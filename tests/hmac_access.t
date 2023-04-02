#!/usr/bin/perl

# (C) Laurent Georget

# Tests for nginx HMAC access module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http access http_hmac_access/);

my $NGINX = defined $ENV{TEST_NGINX_BINARY} ? $ENV{TEST_NGINX_BINARY}
        : '../nginx/objs/nginx';
my $modules = $ENV{TEST_NGINX_MODULES};
if (!defined $modules) {
	my ($volume, $dir) = File::Spec->splitpath($NGINX);
	$modules = File::Spec->catpath($volume, $dir, '');
}
my $module = File::Spec->rel2abs(File::Spec->canonpath($modules . 'ngx_http_hmac_access_module.so'));

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

load_module $module;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            hmac_access_vars "\$arg_h,\$arg_ts,\$arg_e";
            hmac_access_secret "not_so_secret";
            hmac_access_message "\$uri|\$request_body|\$arg_ts|\$arg_e";
            hmac_access_algorithm sha256;
            hmac_access_requires_body on;

            proxy_pass http://127.0.0.1:8081/;
        }

    }

    server {
        listen       127.0.0.1:8081;

        location / {
            return 200 "OK";
        }
    }
}

EOF

$t->plan(3)->run();

###############################################################################

# test with correct hash

like(http_post_hmac('/foo', 'foobar'), qr/200 OK/, 'HMAC correct');

# test with incorrect hash

like(http_post_incorrect_hmac('/foo', 'foobar'), qr/403 Forbidden/, 'HMAC incorrect');

# test with missing hash

like(http_get('/foo'), qr/403 Forbidden/, 'HMAC_missing');

###############################################################################

sub http_post_hmac {
	my ($url, $body) = @_;
	my $length = length $body;

	use Digest::SHA qw(hmac_sha256_base64);
	use POSIX qw(strftime);

	my $now = time();
	my $key = "not_so_secret";
	my $expire = 60;
	my $tz = strftime("%z", localtime($now));
	$tz =~ s/(\d{2})(\d{2})/$1:$2/;
	my $timestamp = strftime("%Y-%m-%dT%H:%M:%S", localtime($now)) . $tz;


	my $digest = hmac_sha256_base64($url . "|" . $body . "|" . $timestamp . "|" . $expire,  $key);
	$digest =~ tr(+/)(-_);
	$url .= "?h=" . $digest . "&ts=" . $timestamp . "&e=" . $expire;

	return http(<<EOF);
POST $url HTTP/1.1
Host: localhost
Connection: close
Content-Length: $length

$body
EOF
}

sub http_post_incorrect_hmac {
	my ($url, $body) = @_;
	my $length = length $body;

	my $now = time();
	my $expire = 60;
	my $tz = strftime("%z", localtime($now));
	$tz =~ s/(\d{2})(\d{2})/$1:$2/;
	my $timestamp = strftime("%Y-%m-%dT%H:%M:%S", localtime($now)) . $tz;


	$url .= "?h=wrong_hash&ts=" . $timestamp . "&e=" . $expire;

	return http(<<EOF);
POST $url HTTP/1.1
Host: localhost
Connection: close
Content-Length: $length

$body
EOF
}
