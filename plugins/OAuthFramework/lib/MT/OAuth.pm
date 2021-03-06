package MT::OAuth;
use strict;
use warnings;
use MT;
use Net::OAuth;

$Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0A;

sub client {
    my $pkg = shift;
    my ( $client_id ) = @_;

    ## IDEA: add an updated datetime in registry, and, if
    ## multi entry about the same provider has found, use newest one.
    ## this could help the old plugin from change somthing by provider side.
    my $reg = MT->registry('oauth_service_providers', $client_id)
        or die "Failed tos load OAuth client $client_id";

    my $class = $reg->{class};
    if ( $class ) {
        eval "require $class"
            or die "Failedss to load OAuth client $client_id: $@";
    }
    else {
        $class = "MT::OAuth::Client::$client_id";
        eval 'package ' . $class . '; @' . $class . '::ISA = qw( MT::OAuth::Client ); 1;'
            or die "Failed to load OAuth client $client_id";
    }
    return $class->new( id => $client_id, %$reg );
}

sub clients {
    my $pkg = shift;
    my $registry_providers = MT->registry('oauth_service_providers')
        or return;
    my $clients = {};
    for my $id ( keys %$registry_providers ) {
        $clients->{$id} = $pkg->client($id);
    }
    return wantarray ? values %$clients : $clients;
}

package MT::OAuth::Client;
use strict;
use warnings;
use MT::Util qw( encode_url );
use base qw( Class::Accessor::Fast MT::ErrorHandler );
use HTTP::Request::Common qw(POST);
use JSON;

__PACKAGE__->mk_accessors(qw(
    id            label                 regist_url
    manage_url    consumer_key          consumer_secret
    update        request_token_url     access_token_url
    authorize_url author_app_manage_url protocol_version
    user_info_url fetch_user_info       scope
    callback_url
));

sub new {
    my $pkg = shift;
    my ( %param ) = @_;
    my $obj = bless \%param, $pkg;
    $obj->init or die "Failed to init $pkg: " . $obj->errstr;
    return $obj;
}

{
my $plugindata_terms = {
    plugin => 'core',
    key    => 'oauth_clients',
};

sub init {
    my $self = shift;
    my $plugindata_class = MT->model('plugindata');
    my $plugindata = $plugindata_class->load($plugindata_terms);
    if ( !$plugindata ) {
        $plugindata = $plugindata_class->new
            or die "Failed to init Plugin Data: " . $plugindata_class->errstr;
        $plugindata->set_values($plugindata_terms);
        $plugindata->data({});
    }
    if ( my $credentials = $plugindata->data->{$self->id} ) {
        $self->{$_} = $credentials->{$_} for keys %$credentials;
    }
    $self->{__plugindata} = $plugindata;
    return $self;
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

sub oauth_request {
    my $self = shift;
    my ( $request_to, %param ) = @_;
    my $request = Net::OAuth->request($request_to)->new(
        consumer_key     => $self->consumer_key,
        consumer_secret  => $self->consumer_secret,
        signature_method => 'HMAC-SHA1',
        timestamp        => time(),
        callback         => $self->callback_url,
        nonce            => substr(MT->app->make_magic_token, 0, 8),
        %param,
    );
    $request->sign;
    die "COULDN'T VERIFY! Check OAuth parameters.\n"
        unless $request->verify;
    $request;
}

sub get_temporary_credentials {
    my $self = shift;
    return unless $self->registered;
    local $Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0
        if ( $self->protocol_version || '' ) eq '1_0';
    my $ua = MT->new_ua;
    my $request = $self->oauth_request(
        'request token',
        request_method => 'POST',
        request_url    => $self->request_token_url,
    );
    my $http_req = HTTP::Request->new('POST', $self->request_token_url);
    $http_req->content( $request->to_post_body );
    $http_req->content_type( 'application/x-www-form-urlencoded' );
    my $res = $ua->request( $http_req );
    die 'Failed to get OAuth Temporary Credentials: ' . $res->status_line
        unless $res->is_success;

    my $response = Net::OAuth->response('request token')->from_post_body($res->content);
    return {
        token        => $response->token,
        token_secret => $response->token_secret,
        redirect_url =>
            $self->authorize_url
            . '?oauth_token=' . $response->token
            . '&client='      . $self->id,
    };
}

sub get_access_tokens {
    my $self = shift;
    my ( %param ) = @_;
    return unless $self->registered;
    local $Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0
        if ( $self->protocol_version || '' ) eq '1_0';

    my $ua = MT->new_ua;
    my $request = $self->oauth_request(
        "access token",
        request_method => 'POST',
        request_url    => $self->access_token_url,
        token          => $param{oauth_token},
        verifier       => $param{oauth_verifier},
        token_secret   => $param{request_token_secret},
    );
    my $http_req = HTTP::Request->new('POST', $self->access_token_url);
    $http_req->content($request->to_post_body);
    $http_req->content_type( 'application/x-www-form-urlencoded' );

    my $res = $ua->request($http_req);
    my $response = Net::OAuth->response('access token')->from_post_body($res->content);
    die 'Failed to get OAuth Tokens: ' . $res->status_line
        unless $res->is_success;
    my $token = MT->model('oauth_token')->new;
    $token->set_values({
        provider => $self->id,
        token    => $response->token,
        secret   => $response->token_secret,
    });
    return $token;
}

sub get_access_tokens_v2 {
    my $self = shift;
    my ( %param ) = @_;
    return unless $self->registered;
    my $ua = MT->new_ua;
    my %req_params = (
        grant_type    => 'authorization_code',
        client_id     => $self->consumer_key,
        client_secret => $self->consumer_secret,
        redirect_uri  => $param{redirect},
        code          => $param{code},
    );
    #my $uri = $self->access_token_url . '?';
    #$uri .= join( '&', ( map { $_ . '=' . $req_params{$_} } keys %req_params ) );
    #my $http_req = HTTP::Request->new('GET', $uri);

    my $http_req = POST( $self->access_token_url, [ %req_params ] );
    #$http_req->content_type( 'application/x-www-form-urlencoded' );

    my $res = $ua->request($http_req);
    die 'Failed to get OAuth Tokens: ' . $res->status_line
        unless $res->is_success;
    my $content = $res->content;
    my %content;
    if ( $content =~ /\{/ ) {
        # it's JSON, maybe...
        %content = %{ decode_json( $content ) };
    }
    else {
        # it's form-urlencoded, maybe?
        %content = map { split '=', $_ } split( '&', $content );
    }
    $content{access_token} or die "Token not found";
    my $token = MT->model('oauth_token')->new;
    $token->set_values({
        provider => $self->id,
        token    => $content{access_token},
    });
    return $token;
}

sub user_info {
    my $self = shift;
    my $token = shift
        or die "Token is required";
    my $fetcher = $self->fetch_user_info
        or die "This OAuth provider doesn't support user info";
    if ( 'CODE' ne ref $fetcher ) {
        $fetcher = MT->handler_to_coderef($fetcher);
    }
    my $user = $fetcher->($self, $token);
    return $user;
}

sub has_token {
    my $self = shift;
    my ( %param ) = @_;
    return unless $self->registered;
    my $author_id = $param{author_id} || 0;
    my $token = MT->model('oauth_token')->load({
        author_id => $author_id,
        client    => $self->id,
    }) or return;
    $token;
}

sub access {
    my $self = shift;
    my ( %param ) = @_;
    return unless $self->registered;
    local $Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0
        if ( $self->protocol_version || '' ) eq '1_0';
    my $author_id = $param{author_id} || 0;
    my $token = MT->model('oauth_token')->load({
        author_id => $author_id,
        provider  => $self->id,
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
                client    => $self->id,
                session   => $sess->id,
                author_id => $author_id,
            );
        }
        elsif ( my $redirect = $param{ redirect } ) {
            my $app = MT->app or die 'Need App to redirect after OAuth steps.';
            return $app->forward(
                'oauth_handshake',
                client    => $self->id,
                redirect  => $redirect,
                author_id => $author_id,
            );
        }
        else {
            return $self->error('Unauthorized');
        }
    }
    my $ua     = MT->new_ua;
    my $post   = $param{post};
    my $method = $param{method}   ? $param{method}
               : ( $param{post} ) ? 'POST'
               :                    'GET'
               ;
    my %extra  = $post && ref $post ? ( extra_params => $post ) : ();
    my $request = $self->oauth_request(
        'protected resource',
        request_method   => $method,
        request_url      => $param{end_point},
        token            => $token->token,
        token_secret     => $token->secret,
        %extra,
    );
    my $http_req = HTTP::Request->new( $method, $request->request_url );
    $http_req->content_type( $param{content_type} ) if $param{content_type};
    if ( %extra ) {
        $http_req->content( $request->to_post_body );
    }
    else {
        $http_req->header( 'Authorization', $request->to_authorization_header );
        $http_req->content( $param{content} ) if $param{content};
    }
    $ua->max_redirect(0);
    my $res = $ua->request($http_req);
    ## TBD: if user revoked the handshake, retur code is 401. need recovery.
    die 'Failed to access OAuth Protected resource: ' . $res->status_line
        if $res->is_error;
    return $param{callback} ? $param{callback}->($res) : $res;
}

1;
