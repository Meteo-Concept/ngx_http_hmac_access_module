Nginx HMAC Secure Link Module
=============================

Météo Concept `laurent.georget@meteo-concept`
Copyleft 2023

Description:
============

The Nginx HMAC access module allows limiting the access to a location by use of
a cryptographic hash that can depend on any variable, including the request
body.

Furthermore, the HMAC is computed as described in RFC2104, that is,
`H(secret_key XOR opad,H(secret_key XOR ipad, message))`.


Motivation
==========

We originally made this module for an IoT weather station equipped with a 4G
modem.  Our first design used SSL/TLS with client authentication but we found
that the overhead of SSL/TLS was very large for the very small GET and POST
requests we were doing to upload sensor data to the server.

This module is only viable when the data sent to the web server need to be
**authenticated** and checked for **integrity** but are not **confidential**,
since they will not be encrypted.


Installation:
=============

You'll need to re-compile Nginx from source to include this module.
Modify your compile of Nginx by adding the following directive (modified to suit your path of course):

Static module (built-in nginx binary)

    ./configure --add-module=path/to/ngx_http_hmac_access_module

Dynamic nginx module `ngx_http_hmac_access_module.so` module

    ./configure --add-dynamic-module=path/to/ngx_http_hmac_access_module

Build Nginx

    make
    make install


Usage:
======

The message to be hashed is defined by `hmac_access_message`. It's a string
containing nginx variables and static text which defines the structure of the
cleartext to hash.

The key used to compute the HMAC (the secret shared between client and server)
is given by `hmac_access_secret`, the hashing algorithm H is defined by
`hmac_access_algorithm`.

If the hash includes the body (it always should whenever a body is expected,
like in POST requests for instance), the variable `hmac_access_requires_body`
must be set to `on`.

To prevent message replaying, the hash should include the request timestamp
(and the timestamp should be checked). This module supports two formats:
 ISO 8601 (`2017-12-08T07:54:59+00:00`) and UNIX timestamp.

An optional paramter allows defining a lifetime against which the timestamp
will be checked. If the expiration period is zero or it is not specified, the
timestamp will not be checked by the module.

The `hmac_access_vars` gives the value of the hash, the timestamp, and,
optionally, the expiration time. These are usually `$arg_???` variables to get
the values from the query string.

Server-side configuration example
---------------------------------

```nginx
map $remote_user $my_hmac_secret {
        known_user1     "ezqsdffgqkjrsghsqf23T435TRFG4ATGFS3";
        default         "not_secret_at_all";
}

location ^~ /restricted_area/ {
    # Variable to be passed are secure token, timestamp, expiration period (optional)
    # separated by comma
    hmac_access_vars "$arg_h,$arg_ts,$arg_e";

    # Structure of the message to be verified: here, the hash is computed from
    # the URI (with the query string), the request body, the remote username
    # (passed by Basic auth), the timestamp and the expiration time
    hmac_access_message "$uri|$body|$remote_user|$arg_ts|$arg_e";

    # The hash includes the request body so this variable must be set to on
    # to have the module read the request body in time to compute the hash
    # properly
    hmac_access_requires_body on;

    # Secret key
    hmac_access_secret "$my_hmac_secret";

    # Cryptographic hash function to use
    hmac_access_algorithm sha256;

    # Here for instance if the request is validated, we pass it to an inner
    # server with a special header.
    # If the computed hash is different from the hash passed, or if the
    # request has expired, then the user gets a 403 error instead.
    proxy_set_header X-Authenticated-User "$remote_user";
    proxy_pass http://192.168.40.100:8080;
}
```

Here, we use a map to use a different shared secret for each user.

Client-side usage
-----------------

The client application needs to compute the hash and pass it encoded as
Base64URL in the query.

Example in Bash

```shell
#!/bin/bash

SECRET="my_super_secret"
TIMESTAMP="$(date +%s)"
EXPIRES="3600"; # seconds
URL="/restricted_area/route"
USER=user
BODY="Hello world!"

ST="$URL|$TIME_STAMP|$EXPIRES"
TOKEN="$(echo -n $ST | openssl dgst -sha256 -hmac $SECRET -binary | openssl base64 | tr +/ -_ | tr -d =)"

echo "http://{$USER}@example.com{$URL}?h={$TOKEN}&ts={$TIMESTAMP}&e={$EXPIRES}" -d "$BODY" -H "Content-Type: application/octet-stream"
```

Note that the `ts`, `h`, and `e` arguments in the query string are accessed
by nginx through variables `$arg_ts`, `$arg_h`, and `$arg_e` respectively in
the `hmac_access_vars` variable in the server configuration.


Server configuration
====================

The module is used for access control at server, directory, or location level.
The following variables are used:

* `$hmac_access_vars` - must be a string containing two or three values:
  the hash passed by the client, the timestamp, and optionally the expiration
  time of the request in seconds.
* `$hmac_access_message` - must be a string giving the message to hash.
  For the hash to be secure, it should include all parts that must be checked:
  the URL, the request body if any, the remote username if it's relevant, the
  timestamp, etc.
* `$hmac_access_secret` - must be a string giving the shared secret between
  the server and client. This value must be kept secure, it's essentially the
  client password.
* `$hmac_access_algorithm` - must be a string giving the name of a supported
  OpenSSL hash algorithm. At the time I write this documentation, and on my
  system, this list is : `blake2b512`, `blake2s256`, `md5`, `md5-sha1`,
  `ripemd`, `ripemd160`, `rmd160`, `sha1`, `sha224`, `sha256`, `sha3-224`,
  `sha3-256`, `sha3-384`, `sha3-512`, `sha384`, `sha512`, `sha512-224`,
  `sha512-256`, `shake128`, `shake256`, `sm3`, `ssl3-md5`, `ssl3-sha1`.
  This variable is optional, the default value is `sha256`.
* `$hmac_access_requires_body` - must be an on/off variable telling the module
  whether it needs to fetch the request body before checking access. This must
  be set to `on` if the hash includes the request body, otherwise the
  `$request_body` variable might be not be populated yet at the time the module
  mediates the request. This variable is `off` by default.


Caveats
=======

Nginx might not populate the `$request_body` variable if it's very large (i.e.
cannot be loaded in memory). In that case, SSL/TLS with client authentication
should be used instead.


Credits:
========

This plugin is based on the Nginx HMAC Secure Link Module, by Denis Denisov
(https://github.com/nginx-modules/ngx_http_hmac_secure_link_module). Many
thanks to him.

