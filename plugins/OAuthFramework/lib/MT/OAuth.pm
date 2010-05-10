package MT::OAuth;
use strict;
use warnings;
use MT;
use Net::OAuth;
$Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0A;

{
my $SERVERS;

sub server {
    ## FIXME: get server on proper way
    my $pkg = shift;
    $pkg->servers->{$_[0]};
}

sub servers {
    my $pkg = shift;
    if ( defined $SERVERS ) {
        return wantarray ? values %$SERVERS : $SERVERS;
    }
    $SERVERS = {};

    ## IDEA: add an updated datetime in registry, and, if
    ## multi entry about the same server has found, use newest one.
    ## this could help the old plugin from change somthing by server side.
    my $registry_servers = MT->registry('oauth_servers')
        or return;
    for my $id ( keys %$registry_servers ) {
        $SERVERS->{$id} = MT::OAuth::Server->new(
            id => $id,
            %{ $registry_servers->{$id} },
        );
    }
    return wantarray ? values %$SERVERS : $SERVERS;
}
}

package MT::OAuth::Server;
use base qw( Class::Accessor::Fast MT::ErrorHandler );

__PACKAGE__->mk_accessors(qw(
    id            label                 regist_url
    manage_url    consumer_key          consumer_secret
    update        request_token_url     access_token_url
    authorize_url author_app_manage_url
));

{
my $plugindata;
my $plugindata_terms = {
    plugin => 'core',
    key    => 'oauth_servers',
};

sub new {
    my $pkg = shift;
    my ( %param ) = @_;
    my $id = $param{id};
    my $plugindata_class = MT->model('plugindata');
    unless ( defined $plugindata ) {
        $plugindata = $plugindata_class->load($plugindata_terms);
        unless ( defined $plugindata ) {
            $plugindata = $plugindata_class->new or die "aa";
            $plugindata->set_values($plugindata_terms);
            $plugindata->data({});
        }
    }
    if ( $plugindata ) {
        if ( my $credentials = $plugindata->data->{$id} ) {
            %param = ( %param, %$credentials );
        }
        $param{__plugindata} = $plugindata;
    }
    return bless \%param, $pkg;
}
}

sub registered {
    return $_[0]->consumer_key && $_[0]->consumer_secret;
}

sub save_consumer_info {
    my $self = shift;
    my $pdata = $self->{__plugindata};
    my $data = $pdata->data;
    $data->{$self->id} = {
        consumer_key    => $self->consumer_key,
        consumer_secret => $self->consumer_secret,
    };
    $pdata->data($data);
    $pdata->save or return $self->error( 'failed to save data: ' . $pdata->errstr );
    1;
}

sub callback_url {
    my $self = shift;
    ## FIXME
    MT->config->CGIPath . 'mt.cgi?__mode=oauth_verified&server=' . $self->id;
}

sub oauth_request {
    my $self = shift;
    my ( $request_to, %param ) = @_;
    my $request = Net::OAuth->request($request_to)->new(
        consumer_key     => $self->consumer_key,
        consumer_secret  => $self->consumer_secret,
        callback         => $self->callback_url,
        request_method   => 'POST',
        signature_method => 'HMAC-SHA1',
        timestamp        => time(),
        ## FIXME: what is the nonce?
        nonce            => substr(MT->app->make_magic_token, 0, 8),
        %param,
    );
    $request->sign;
    $request;
}

sub get_temporary_credentials {
    my $self = shift;
    return unless $self->registered;
    my $ua = MT->new_ua;
    my $request = $self->oauth_request(
        'request token',
        request_url => $self->request_token_url,
    );
    my $http_req = HTTP::Request->new('POST', $self->request_token_url);
    $http_req->content($request->to_post_body);
    my $res = $ua->request($http_req);
    die 'somethingwrong' unless $res->is_success;
    my $response = Net::OAuth->response('request token')->from_post_body($res->content);
    return {
        token        => $response->token,
        token_secret => $response->token_secret,
        redirect_url =>
            $self->authorize_url
            . '?oauth_token=' . $response->token
            . '&server='      . $self->id,
    };
}

sub get_access_tokens {
    my $self = shift;
    my ( %param ) = @_;
    return unless $self->registered;

    my $ua = MT->new_ua;
    my $request = $self->oauth_request(
        "access token",
        request_url      => $self->access_token_url,
        callback         => $self->callback_url,
        token            => $param{oauth_token},
        verifier         => $param{oauth_verifier},
        token_secret     => $param{request_token_secret},
    );
    my $http_req = HTTP::Request->new('POST', $self->access_token_url);
    $http_req->content($request->to_post_body);
    my $res = $ua->request($http_req);
    my $response = Net::OAuth->response('access token')->from_post_body($res->content);
    die 'somethingwrong' unless $res->is_success;
    my $token = MT->model('oauth_token')->new;
    $token->set_values({
        server => $self->id,
        token  => $response->token,
        secret => $response->token_secret,
    });
    return $token;
}

sub has_token {
    my $self = shift;
    my ( %param ) = @_;
    return unless $self->registered;
    my $author_id = $param{author_id} || 0;
    my $token = MT->model('oauth_token')->load({
        author_id => $author_id,
        server    => $self->id,
    }) or return;
    $token;
}

sub access {
    my $self = shift;
    my ( %param ) = @_;
    return unless $self->registered;
    my $author_id = $param{author_id} || 0;
    my $token = MT->model('oauth_token')->load({
        author_id => $author_id,
        server    => $self->id,
    });
    if ( !defined $token ) {
        if ( my $retry = $param{retry} ) {
            my $app = MT->app or die 'Need App to retry after OAuth steps.';
            die 'Permission denied for handshake with external resource'
                if $author_id <= 0 && !$app->user->is_superuser;
            my $mode = $app->mode;
            my $sess = MT->model('session')->new;
            $sess->set_values({
                id   => $app->make_magic_token,
                kind => 'OA',
                start => time(),
            });
            $sess->set(mode => $mode);
            $sess->set(post => $param{post});
            $sess->set(param => $retry);
            $sess->save or die $sess->errstr;
            return $app->forward(
                'oauth_handshake',
                server    => $self->id,
                session   => $sess->id,
                author_id => $author_id,
            );
        }
        elsif ( my $redirect = $param{ redirect } ) {
            my $app = MT->app or die 'Need App to redirect after OAuth steps.';
            return $app->forward(
                'oauth_handshake',
                server    => $self->id,
                redirect  => $redirect,
                author_id => $author_id,
            );
        }
        else {
            return $self->error('Unauthorized');
        }
    }
    my $ua = MT->new_ua;
    my $request = $self->oauth_request(
        'protected resource',
        request_url      => $param{end_point},
        token            => $token->token,
        token_secret     => $token->secret,
        extra_params     => $param{post},
    );
    my $http_req = HTTP::Request->new('POST', $param{end_point});
    $http_req->content($request->to_post_body);
    my $res = $ua->request($http_req);
    ## TBD: if user revoked the handshake, retur code is 401. need recovery.
    die 'somethingwrong'
        unless $res->is_success;
    return $param{callback} ? $param{callback}->($self, $res) : $res;
}

1;
