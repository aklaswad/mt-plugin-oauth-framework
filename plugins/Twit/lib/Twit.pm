package Twit;
use strict;
use warnings;
use MT;
use MT::OAuth;
sub widget {
    my $app = shift;
    my ( $tmpl, $param ) = @_;
}

sub post {
    my ($app) = shift;
    my (%forward) = @_;
    my $twit = $forward{post}{status} || $app->param('twit');
    my $author = $app->user or die;
    my $client = MT::OAuth->client('twitter');
    return $client->access(
        author_id => $author->id,
	       end_point => 'https://api.twitter.com/1/statuses/update.xml',
        post => {
            status => $twit,
        },
        retry => 1,
        callback => sub {
            return $app->return_to_dashboard;
        },
    ) or die "failed";
}

1;
