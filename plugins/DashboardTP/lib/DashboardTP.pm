package DashboardTP;
use strict;
use warnings;
use MT;
use MT::OAuth;
use JSON;

sub widget {
    my $app = shift;
    my ( $tmpl, $param ) = @_;
}

my $endpoint = 'https://api.typepad.com/';

sub tp2 {
    my @path = @_;
    my ( $path, $content, $json );
    my $method = 'GET';
    if ( ref $path[-1] ) {
        $method = 'POST';
        $content = pop @path;
        $json = JSON::encode_json( $content );
    }
    $path = join '/', @path;
    my $client = MT::OAuth->client('typepad');
    my $res = $client->access(
        author_id    => MT->app->user->id,
	end_point    => 'https://api.typepad.com/' . $path . '.json',
        content_type => 'application/json',
        retry        => 1,
        method       => $method,
        content      => $json,
    ) or return;
    return JSON::decode_json( $res->content );
}

sub post {
    my $app = shift;
    my (%forward) = @_;
    my $body = $forward{retry}{content} || $app->param('body');
    my $user = tp2(users => '@self') or return;
    my $user_id = $user->{urlId};
    my $blogs = tp2( users => $user_id => 'blogs' )
        or return;

    ## FIXME: but how to select blog to post?
    my $blog_id = $blogs->{entries}[0]{urlId};
    my $res = tp2( blogs => $blog_id => 'post-assets' => {
        content => $body,
    }) or return;
    my $permalink = $res->{permalinkUrl};
    $app->return_to_dashboard( tpsaved => $permalink );
}

1;
