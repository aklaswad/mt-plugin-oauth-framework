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
    use YAML; print STDERR YAML::Dump \%forward;
    my $twit = $forward{post}{status} || $app->param('twit');
    my $author = $app->user or die;
    my $server = MT::OAuth->server('twitter');
    return $server->access(
        author_id => $author->id,
	       end_point => 'https://twitter.com/statuses/update.xml',
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
