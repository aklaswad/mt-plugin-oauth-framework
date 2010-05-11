package MT::OAuth::Token;
use strict;
use warnings;
use base qw( MT::Object );
use MT;
use MT::OAuth;

__PACKAGE__->install_properties({
    column_defs => {
        id           => 'integer not null auto_increment',
        provider     => 'string(75)',
        author_id    => 'integer',
        token        => 'string(75)',
        secret       => 'string(75)',
    },
    datasource  => 'oauth_token',
    primary_key => 'id',
});

sub class_label { 'OAuth Token' }

1;
