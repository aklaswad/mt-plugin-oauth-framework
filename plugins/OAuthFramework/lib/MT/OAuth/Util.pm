package MT::OAuth::Util;
use strict;
use warnings;
use MT;
use LWP::Simple;
use JSON;

sub fetch_userinfo_google {
    my ( $client, $token ) = @_;
    my $info_url = 'https://www.googleapis.com/oauth2/v1/userinfo?access_token=';
    $info_url .= $token->token;
    my $ua = MT->new_ua;
    my $http_req = HTTP::Request->new('GET', $info_url);
    my $res = $ua->request($http_req);
    die 'Failed to get OAuth Tokens: ' . $res->status_line
        unless $res->is_success;
    my $content = $res->content;
    my $user = decode_json( $content );
    return {
        name        => $user->{id},
        nickname    => $user->{name},
        email       => $user->{email},
        url         => $user->{link},
        userpic_url => $user->{picture},
    }
}

sub fetch_userinfo_github {
    my ( $client, $token ) = @_;
    my $info_url = 'https://api.github.com/user?access_token=';
    $info_url .= $token->token;
    my $ua = MT->new_ua;
    my $http_req = HTTP::Request->new('GET', $info_url);
    my $res = $ua->request($http_req);
    die 'Failed to get OAuth Tokens: ' . $res->status_line
        unless $res->is_success;
    my $content = $res->content;
    my $user = decode_json( $content );
    return {
        name        => $user->{id},
        nickname    => $user->{name},
        email       => $user->{email},
        url         => $user->{link},
        userpic_url => $user->{picture},
    }
}

sub fetch_userinfo_facebook {
    my ( $client, $token ) = @_;
    my $info_url = 'https://graph.facebook.com/me?fields=id,name,email,link,picture&access_token=';
    $info_url .= $token->token;
    my $ua = MT->new_ua;
    my $http_req = HTTP::Request->new('GET', $info_url);
    my $res = $ua->request($http_req);
    die 'Failed to get OAuth Tokens: ' . $res->status_line
        unless $res->is_success;
    my $content = $res->content;
    my $user = decode_json( $content );
    return {
        name        => $user->{id},
        nickname    => $user->{name},
        email       => $user->{email},
        url         => $user->{link},
        userpic_url => $user->{picture},
    }
}

sub fetch_userinfo_twitter {
    my ( $client, $token ) = @_;
    my $end_point = 'http://api.twitter.com/1/account/verify_credentials.json';
    my $ua = MT->new_ua;
    my $request = $client->oauth_request(
        'protected resource',
        request_method   => 'GET',
        request_url      => $end_point,
        token            => $token->token,
        token_secret     => $token->secret,
    );
    my $http_req = HTTP::Request->new( 'GET', $request->request_url );
    $http_req->header( 'Authorization', $request->to_authorization_header );
    my $res = $ua->request($http_req);
    die 'Failed to get OAuth Tokens: ' . $res->status_line
        unless $res->is_success;
    my $content = $res->content;
    my $user = decode_json( $content );
    return {
        name        => $user->{screen_name},
        nickname    => $user->{name},
        ## TBD: No Email in this endpoint. Where?
        #email       => $user->{email},
        url         => $user->{url},
        userpic_url => $user->{profile_image_url},
    }
}

1;
