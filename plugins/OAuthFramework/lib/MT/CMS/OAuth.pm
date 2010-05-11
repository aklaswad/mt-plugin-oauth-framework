package MT::CMS::OAuth;
use strict;
use warnings;
use MT::OAuth;

sub list_oauth_servers {
    my $app = shift;
    my %param;
    my @servers = MT::OAuth->servers;
    @servers = map {{
        id              => $_->id,
        label           => $_->label,
        consumer_key    => $_->consumer_key,
        consumer_secret => $_->consumer_secret,
        registered      => $_->registered,
        regist_url      => $_->regist_url,
        manage_url      => $_->manage_url,
    }} @servers;
    $param{servers} = \@servers;
    $app->load_tmpl( 'list_oauth_servers.tmpl', \%param );
}

sub save_oauth_consumer_setting {
    my $app = shift;
    my $q = $app->param;
    my ( $server_id ) = $q->param('server');
    my ( $key, $secret ) = map { $q->param("$server_id-$_") } qw(key secret);
    my $server = MT::OAuth->server($server_id);
    $server->consumer_key($key);
    $server->consumer_secret($secret);
    $server->save_consumer_info or return $server->error( $server->errstr );
    $app->forward('list_oauth_servers');
}

sub oauth_handshake {
    my $app = shift;
    my ( %forward_param ) = @_;
    my $server_id = $forward_param{server} || $app->param('server');
    my $server = MT::OAuth->server($server_id)
        or die "Unknown OAuth Server: $server_id";
    my $res = $server->get_temporary_credentials;
    return $app->error( 'failed to start OAuth session: ' . $server->errstr )
        unless $res;
    my $author_id
        = defined $forward_param{author_id} ? $forward_param{author_id}
        :                                     $app->user->id
        ;
    ## FIXME: do expire
    my $cookie = $app->bake_cookie (
        -name => 'mt_oauth_' . $server_id . '_credential',
        -value => {
            author_id    => $author_id,
            session      => $forward_param{session},
            redirect     => $forward_param{redirect},
            token        => $res->{token},
            token_secret => $res->{token_secret},
        },
        -path=>'/',
    );
    $app->redirect(
        $res->{redirect_url},
        UseMeta => 1,
        -cookie => $cookie
    );
}

sub oauth_verified {
    my $app = shift;
    my $q = $app->param;
    my $server_id = $q->param('server');
    my %cookie = $q->cookie('mt_oauth_' . $server_id . '_credential');
    my $server = MT::OAuth->server($server_id)
        or return $app->error("Unknown server $server_id");
    my $token = $server->get_access_tokens(
        request_token        => $cookie{token},
        request_token_secret => $cookie{token_secret},
        oauth_token          => $q->param('oauth_token'),
        oauth_verifier       => $q->param('oauth_verifier'),
    ) or $app->error( 'Failed to get oAuth token: ' . $server->errstr );
    $token->author_id($app->user->id);
    $token->save or return $app->error( $token->errstr );
    if ( my $redirect = $cookie{redirect} ) {
        return $app->redirect($redirect);
    }
    elsif ( my $sess_id = $cookie{session} ) {
        my $sess = MT->model('session')->load($sess_id)
            or die 'Failed to reboot original method';
        my $param = $sess->get('param');
        my $post  = $sess->get('post');
        $sess->remove;
        return $app->forward(
            $sess->get('mode'),
            param => $param,
            post  => $post,
        );
    }
    return $app->return_to_dashboard;
}

1;
