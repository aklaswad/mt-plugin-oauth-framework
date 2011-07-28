package MT::CMS::OAuth;
use strict;
use warnings;
use MT::OAuth;
use MT::Auth::OpenID;
use MT::Util qw( encode_url ts2epoch );

sub list_oauth_providers {
    my $app = shift;
    if ( MT->VERSION > 5 ) {
        $app->can_do('manage_oauth_clients')
            or return $app->return_to_dashboard(
                permission => 1,
            );
    }
    else {
        $app->user->is_superuser
            or return $app->return_to_dashboard(
                permission => 1,
            );
    }
    my %param;
    my @providers = provider_list();
    $param{providers} = \@providers;
    $app->load_tmpl( 'list_oauth_providers.tmpl', \%param );
}

sub save_oauth_consumer_setting {
    my $app = shift;
    if ( MT->VERSION > 5 ) {
        $app->can_do('change_oauth_consumer_setting')
            or return $app->return_to_dashboard(
                permission => 1,
            );
    }
    else {
        $app->user->is_superuser
            or return $app->return_to_dashboard(
                permission => 1,
            );
    }
    my $q = $app->param;
    my ( $client_id ) = $q->param('client');
    my ( $key, $secret ) = map { $q->param("$client_id-$_") } qw(key secret);
    my $client = MT::OAuth->client($client_id);
    $client->consumer_key($key);
    $client->consumer_secret($secret);
    $client->save_consumer_info or return $client->error( $client->errstr );
    $app->forward('list_oauth_providers');
}

sub list_oauth_tokens {
    my $app = shift;
    my (%forward) = @_;
    my $author = $app->user
        or die;
    my %param;
    my @tokens = MT->model('oauth_token')->load({ author_id => $author->id });
    my @providers = grep { $_->{registered} } provider_list();
    for my $provider ( @providers ) {
        my ($token) = grep { $_->provider eq $provider->{id} } @tokens;
        $provider->{token_id} = $token->id if $token;
    }
    $param{providers} = \@providers;
    if ( my $revoked_id = $forward{revoked} ) {
        $param{revoked_provider_label} = MT::OAuth->client($revoked_id)->label;
        $param{revoked} = 1;
    }
    $app->load_tmpl( 'list_oauth_tokens.tmpl', \%param );
}

sub provider_list {
    my @providers = MT::OAuth->clients;
    my @tokens = MT->model('oauth_token')->load({ author_id => 0 });
    for my $provider ( @providers ) {
        my ($token) = grep { $_->provider eq $provider->{id} } @tokens;
        $provider->{sys_token_id} = $token->id if $token;
    }
    map {{
        id              => $_->id,
        label           => $_->label,
        consumer_key    => $_->consumer_key,
        consumer_secret => $_->consumer_secret,
        registered      => $_->registered,
        regist_url      => $_->regist_url,
        manage_url      => $_->manage_url,
        user_manage_url => $_->author_app_manage_url,
        callback_url    => $_->callback_url,
        sys_token_id    => $_->{sys_token_id},
    }} @providers;
}

sub revoke_handshake {
    my $app = shift;
    my $q = $app->param;
    my $id = $q->param('id');
    my $token = MT->model('oauth_token')->load($id)
        or return $app->error('Invalid request');
    if ( MT->VERSION > 5 ) {
        if ( $app->user->id != $token->author_id
            && !$app->can_do('manage_all_handshakes') ) {
            return $app->error('Permission denied');
        }
    }
    else {
        if ( $app->user->id != $token->author_id
                 && !$app->user->is_superuser ) {
            return $app->error('Permission denied');
        }
    }
    $token->remove();
    if ( my $redirect = $q->param('redirect') ) {
        $app->redirect($redirect);
    }
    else {
        $app->forward(
            $q->param('forward') || 'list_oauth_tokens',
            remokedd => $id );
    }
}

sub oauth_login {
    my $app = shift;
    my $login_blog_id = $app->param('blog_id') || 'global';
    oauth_handshake( $app, login => $login_blog_id, @_ );
}

sub oauth_handshake {
    my $app = shift;
    my ( %forward_param ) = @_;
    my $client_id = $forward_param{client}   || $app->param('client');
    my $client = MT::OAuth->client($client_id)
        or die "Unknown OAuth Client: $client_id";
    my $author_id
        = defined $forward_param{author_id} ? $forward_param{author_id}
        : defined $app->param('author_id')  ? $app->param('author_id')
        : $app->user                        ? $app->user->id
        :                                     undef
        ;

    my $login = defined $forward_param{login} ? $forward_param{login} : $app->param('login');
    my $our_endpoint = $forward_param{our_endpoint};
    $our_endpoint ||= $app->base
        . $app->uri( mode => 'oauth_verified', args => { client => $client->id });
    $client->callback_url( $our_endpoint );
    if ( $client->protocol_version eq '2_0') {
        my $redirect  = $forward_param{redirect} || $app->param('redirect');
        my %state = (
            client_id => $client_id,
            author_id => $author_id,
            redirect  => $redirect,
            login     => $login,
        );
        my $state = join( ' ', ( map { join '::', $_, $state{$_} } keys %state ) );
        my $uri = $client->authorize_url
                . "?response_type=code"
                . "&client_id=" . $client->consumer_key
                . "&state="     . encode_url( $state )
                . "&redirect_uri="
                . encode_url( $our_endpoint )
                ;
        my $scope_str;
        if ( my $scope = $client->scope ) {
            delete $scope->{plugin};
            $uri .= '&scope=' . join('+', ( map { encode_url($_) } keys %$scope ) );
        }
        $app->redirect( $uri );
    }
    else {
        my $res = $client->get_temporary_credentials;
        return $app->error( 'failed to start OAuth session: ' . $client->errstr )
            unless $res;
        my $redirect  = $forward_param{redirect} || $app->param('redirect');
        ## FIXME: set cookie expire
        my $cookie = $app->bake_cookie (
            -name => 'mt_oauth_' . $client_id . '_credential',
            -value => {
                author_id    => $author_id,
                session      => $forward_param{session},
                redirect     => $redirect,
                token        => $res->{token},
                token_secret => $res->{token_secret},
                login        => $login,
            },
            -path=>'/',
        );
        $app->redirect(
            $res->{redirect_url},
            UseMeta => 1,
            -cookie => $cookie
        );
    }
}

sub oauth_verified {
    my $app = shift;
    my %param = @_;
    my $q = $app->param;
    my $client_id = $q->param('client');
    my ( $redirect, $author_id, $login );
    unless ($client_id) {
        ## When using OAuth 2.0, some params are serialized in state parameters.
        my $state = $q->param('state')
            or die "Invalid request";
        my %state;
        for ( split ' ', $state ) {
            my ( $k, $v ) = split '::', $_;
            $state{$k} = $v;
        }
        ( $client_id, $author_id, $redirect, $login )
            = @state{qw( client_id author_id redirect login )};
    }

    my $client = MT::OAuth->client($client_id)
        or return $app->error("Unknown client $client_id");
    my $our_endpoint = $param{our_endpoint};
    $our_endpoint ||= $app->base . $app->uri(mode => 'oauth_verified', args => { client => $client->id });
    $client->callback_url( $our_endpoint );
    my $token;
    my %cookie;
    if ( '2_0' eq $client->protocol_version ) {
        $token = $client->get_access_tokens_v2(
            code     => $q->param('code'),
            redirect => $our_endpoint,
        ) or $app->error( 'Failed to get oAuth token: ' . $client->errstr );
    }
    else {
        %cookie = $q->cookie('mt_oauth_' . $client_id . '_credential');
        $token = $client->get_access_tokens(
            request_token        => $cookie{token},
            request_token_secret => $cookie{token_secret},
            oauth_token          => $q->param('oauth_token'),
            oauth_verifier       => $q->param('oauth_verifier'),
        ) or $app->error( 'Failed to get oAuth token: ' . $client->errstr );
        $author_id = defined $cookie{author_id} ? $cookie{author_id} : $app->user->id;
        $redirect  = $cookie{redirect};
        $login     = $cookie{login};
    }

    ## OK, we got access token now. so what to do?
    if ( $login ) {
        my $blog;
        if ( $login ne 'global' ) {
            $blog = MT->model('blog')->load($login);
        }
        login_with_token( $app, $client, $token, $blog );
    }
    else {
        MT->model('oauth_token')->remove({
            author_id => $author_id,
            provider  => $client->id,
        });
        $token->author_id($author_id);
        $token->provider($client->id);
        $token->save or return $app->error( $token->errstr );
    }

    ## Do redirect.
    if ( $redirect ) {
        if ( $login ) {
            $redirect .= '#_login';
        }
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

sub login_with_token {
    my $app = shift;
    my ( $client, $token, $blog ) = @_;
    my $user = $client->user_info($token);
    my $auth_type = 'oauth.' . $client->id;
    my $INTERVAL = 60 * 60 * 24 * 7;
    my $cmntr = MT->model('author')->load(
        {   name      => $user->{name},
            type      => MT->model('author')->COMMENTER(),
            auth_type => $auth_type,
        }
    );

    if ($cmntr) {
        unless (
            (   $cmntr->modified_on
                && ( ts2epoch( $blog, $cmntr->modified_on )
                    > time - $INTERVAL )
            )
            || ($cmntr->created_on
                && ( ts2epoch( $blog, $cmntr->created_on )
                    > time - $INTERVAL )
            )
            )
        {
            # TODO: update nickname and email
            # $class->set_commenter_properties( $cmntr, $vident );
            $cmntr->save or return 0;
        }
    }
    else {
        $cmntr = $app->make_commenter(
            name        => $user->{name},
            email       => $user->{email},
            nickname    => $user->{nickname},
            url         => $user->{url},
            auth_type   => $auth_type,
        );
        if ( my $userpic_url = $user->{userpic_url} ) {
            my $asset = MT::Auth::OpenID::_asset_from_url($userpic_url);
            $cmntr->userpic_asset_id( $asset->id );
        }
        $cmntr->save;
    }

    return unless $cmntr;
    my $session = $app->make_commenter_session($cmntr);
}

1;
