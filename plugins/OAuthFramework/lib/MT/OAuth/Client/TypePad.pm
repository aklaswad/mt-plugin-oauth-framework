package MT::OAuth::Client::TypePad;
use strict;
use warnings;
use base qw( MT::OAuth::Client );
use MT;
use JSON;

sub get_temporary_credentials {
    my $self = shift;
    my $ua = MT->new_ua;
    my $url = 'http://api.typepad.com/api-keys/' . $self->consumer_key . '.json';
    my $res = $ua->get($url);
    die "Failed to get api-keys" unless $res->is_success;
    my $json = JSON::decode_json( $res->content );
    $self->authorize_url( $json->{owner}{oauthAuthorizationUrl} );
    $self->request_token_url( $json->{owner}{oauthRequestTokenUrl} );
    $self->access_token_url( $json->{owner}{oauthAccessTokenUrl} );
    $self->{api_key} = $json->{apiKey};

    $self->SUPER::get_temporary_credentials(@_);
}

1;
