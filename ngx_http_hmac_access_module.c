
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#define NGX_DEFAULT_HASH_FUNCTION  "sha256"

typedef struct {
    ngx_http_complex_value_t  *hmac_variable;
    ngx_http_complex_value_t  *hmac_message;
    ngx_http_complex_value_t  *hmac_secret;
    ngx_str_t                  hmac_algorithm;
    ngx_flag_t                 hmac_requires_body;
} ngx_http_hmac_access_conf_t;


typedef struct {
    ngx_str_t   expires;
    unsigned    done:1;
    unsigned    waiting_more_body:1;
} ngx_http_hmac_access_ctx_t;

static void *ngx_http_hmac_access_create_conf(ngx_conf_t *cf);
static char *ngx_http_hmac_access_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_hmac_access_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_hmac_access_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_hmac_access_commands[] = {

    { ngx_string("hmac_access_vars"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hmac_access_conf_t, hmac_variable),
      NULL },

    { ngx_string("hmac_access_message"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hmac_access_conf_t, hmac_message),
      NULL },

    { ngx_string("hmac_access_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hmac_access_conf_t, hmac_secret),
      NULL },

    { ngx_string("hmac_access_algorithm"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hmac_access_conf_t, hmac_algorithm),
      NULL },

    { ngx_string("hmac_access_requires_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hmac_access_conf_t, hmac_requires_body),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_hmac_access_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_hmac_access_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_hmac_access_create_conf,      /* create location configuration */
    ngx_http_hmac_access_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_hmac_access_module = {
    NGX_MODULE_V1,
    &ngx_http_hmac_access_module_ctx,      /* module context */
    ngx_http_hmac_access_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_hmac_access_create_conf(ngx_conf_t *cf)
{
    ngx_http_hmac_access_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hmac_access_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->hmac_variable = NULL;
     *     conf->hmac_message = NULL;
     *     conf->hmac_secret = NULL;
     *     conf->hmac_algorithm = {0,NULL};
     *     conf->hmac_requires_body = NGX_CONF_UNSET,
     */

    conf->hmac_requires_body = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_hmac_access_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_hmac_access_conf_t *prev = parent;
    ngx_http_hmac_access_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->hmac_algorithm, prev->hmac_algorithm, NGX_DEFAULT_HASH_FUNCTION);
    ngx_conf_merge_value(conf->hmac_requires_body, prev->hmac_requires_body, 0);

    if (conf->hmac_variable == NULL) {
        conf->hmac_variable = prev->hmac_variable;
    }

    if (conf->hmac_message == NULL) {
        conf->hmac_message = prev->hmac_message;
    }

    if (conf->hmac_secret == NULL) {
        conf->hmac_secret = prev->hmac_secret;
    }

    return NGX_CONF_OK;
}


static void
ngx_http_hmac_access_post_read(ngx_http_request_t *r)
{
    ngx_http_hmac_access_ctx_t     *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http hmac_access post read request body");

    ctx = ngx_http_get_module_ctx(r, ngx_http_hmac_access_module);
    ctx->done = 1;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "waiting more body: \"%d\"", (int) ctx->waiting_more_body);

    /* waiting_more_body handler */
    if (ctx->waiting_more_body) {
        ctx->waiting_more_body = 0;

        r->preserve_body = 1;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
    }
}


static ngx_int_t
ngx_http_hmac_access_access_handler(ngx_http_request_t *r)
{
    ngx_http_hmac_access_ctx_t   *ctx;
    ngx_http_hmac_access_conf_t  *conf;
    const EVP_MD                 *evp_md;
    u_char                       *p, *last;
    ngx_str_t                     value, hash, key;
    u_char                        hash_buf[EVP_MAX_MD_SIZE], hmac_buf[EVP_MAX_MD_SIZE];
    u_int                         hmac_len;
    time_t                        timestamp, expires, gmtoff;
    unsigned long long            conv_timestamp;
    int                           year, month, mday, hour, min, sec, gmtoff_hour, gmtoff_min;
    char                          gmtoff_sign;
    ngx_int_t                     rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_hmac_access_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_hmac_access_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http hmac_access access handler called");

    if (conf->hmac_variable == NULL || conf->hmac_message == NULL || conf->hmac_secret == NULL) {
        // module not configured, skip
        return NGX_DECLINED;
    }

    if (ctx && ctx->done) {
        // already processed
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http hmac_access access handler has a decision to take");

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_hmac_access_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_hmac_access_module);

    if (conf->hmac_requires_body) {
        rc = ngx_http_read_client_request_body(r, ngx_http_hmac_access_post_read);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        if (rc == NGX_AGAIN) {
            ctx->waiting_more_body = 1;
            return NGX_DONE;
        }

        ngx_http_finalize_request(r, NGX_DONE);
    }

    if (ngx_http_complex_value(r, conf->hmac_variable, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link variable: \"%V\"", &value);

    last = value.data + value.len;

    p = ngx_strlchr(value.data, last, ',');
    timestamp = 0;
    expires = 0;

    if (p) {
        value.len = p++ - value.data;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure link token: \"%V\"", &value);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "secure link timestamp: \"%*s\"",
                        sizeof("1970-01-01T00:00:00+00:00")-1, p);

        /* Parse timestamp in ISO8601 format */
        if (sscanf((char *)p, "%4d-%02d-%02dT%02d:%02d:%02d%c%02i:%02i",
                              (ngx_tm_year_t *) &year, (ngx_tm_mon_t *) &month,
                              (ngx_tm_mday_t *) &mday, (ngx_tm_hour_t *) &hour,
                              (ngx_tm_min_t *) &min, (ngx_tm_sec_t *) &sec,
                              &gmtoff_sign, &gmtoff_hour, &gmtoff_min) == 9) {

            /* Put February last because it has leap day */
            month -= 2;
            if (month <= 0) {
                month += 12;
                year -= 1;
            }

            /* Gauss' formula for Gregorian days since March 1, 1 BC */
            /* Taken from ngx_http_parse_time.c */
            timestamp = (time_t) (
                         /* days in years including leap years since March 1, 1 BC */
                         365 * year + year / 4 - year / 100 + year / 400
                         /* days before the month */
                         + 367 * month / 12 - 30
                         /* days before the day */
                         + mday - 1
                         /*
                          * 719527 days were between March 1, 1 BC and March 1, 1970,
                          * 31 and 28 days were in January and February 1970
                          */
                         - 719527 + 31 + 28) * 86400 + hour * 3600 + min * 60 + sec;

            /* Determine the time offset with respect to GMT */
            gmtoff = 3600 * gmtoff_hour + 60 * gmtoff_min;

            if (gmtoff_sign == '+') {
                timestamp -= gmtoff;
            }

            if (gmtoff_sign == '-') {
                timestamp += gmtoff;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "secure link timestamp: \"%T\"", timestamp);

        } else if (sscanf((char *)p, "%llu", &conv_timestamp) == 1) {
            /* Try if p is UNIX timestamp */

            timestamp = (time_t)conv_timestamp;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "secure link timestamp: \"%T\"", timestamp);

        } else {
            return NGX_HTTP_FORBIDDEN;
        }

        if (timestamp <= 0) {
            return NGX_HTTP_FORBIDDEN;
        }

        /* Parse expiration period in seconds */
        p = ngx_strlchr(p, last, ',');

        if (p) {
            p++;

            expires = ngx_atotm(p, last - p);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "secure link expires: \"%T\"", expires);

            if (expires < 0) {
                return NGX_DECLINED;
            }


            ctx->expires.len = value.len;
            ctx->expires.data = value.data;
        }
    }

    evp_md = EVP_get_digestbyname((const char*) conf->hmac_algorithm.data);
    if (evp_md == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "Unknown cryptographic hash function \"%s\"", conf->hmac_algorithm.data);

        return NGX_ERROR;
    }

    hash.len  = (u_int) EVP_MD_size(evp_md);
    hash.data = hash_buf;

    if (value.len > ngx_base64_encoded_length(hash.len)+2) {
        return NGX_HTTP_FORBIDDEN;
    }

    if (ngx_decode_base64url(&hash, &value) != NGX_OK) {
        return NGX_HTTP_FORBIDDEN;
    }

    if (hash.len != (u_int) EVP_MD_size(evp_md)) {
        return NGX_HTTP_FORBIDDEN;
    }

    if (ngx_http_complex_value(r, conf->hmac_message, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link message: \"%V\"", &value);

    if (ngx_http_complex_value(r, conf->hmac_secret, &key) != NGX_OK) {
        return NGX_ERROR;
    }

    HMAC(evp_md, key.data, key.len, value.data, value.len, hmac_buf, &hmac_len);

    if (CRYPTO_memcmp(hash_buf, hmac_buf, EVP_MD_size(evp_md)) != 0) {
        return NGX_HTTP_FORBIDDEN;
    }

    if (expires && timestamp + expires < ngx_time()) {
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_hmac_access_init(ngx_conf_t *cf)

{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_hmac_access_access_handler;
    return NGX_OK;
}
