/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
 #include "tool_setup.h"

 #include "tool_cfgable.h"
 #include "tool_cb_prg.h"
 #include "tool_filetime.h"
 #include "tool_formparse.h"
 #include "tool_getparam.h"
 #include "tool_helpers.h"
 #include "tool_libinfo.h"
 #include "tool_msgs.h"
 #include "tool_paramhlp.h"
 #include "tool_parsecfg.h"
 #include "tool_main.h"
 #include "tool_stderr.h"
 #include "tool_help.h"
 #include "var.h"
 
 #include "memdebug.h" /* keep this as LAST include */
 
 #define ALLOW_BLANK TRUE
 #define DENY_BLANK FALSE
 
 static ParameterError getstr(char **str, const char *val, bool allowblank)
 {
   if(*str) {
     free(*str);
     *str = NULL;
   }
   DEBUGASSERT(val);
   if(!allowblank && !val[0])
     return PARAM_BLANK_STRING;
 
   *str = strdup(val);
   if(!*str)
     return PARAM_NO_MEM;
 
   return PARAM_OK;
 }
 
 static ParameterError getstrn(char **str, const char *val,
                               size_t len, bool allowblank)
 {
   if(*str) {
     free(*str);
     *str = NULL;
   }
   DEBUGASSERT(val);
   if(!allowblank && !val[0])
     return PARAM_BLANK_STRING;
 
   *str = malloc(len + 1);
   if(!*str)
     return PARAM_NO_MEM;
 
   memcpy(*str, val, len);
   (*str)[len] = 0; /* null-terminate */
 
   return PARAM_OK;
 }
 
 /* this array MUST be alphasorted based on the 'lname' */
 static const struct LongShort aliases[]= {
   {"abstract-unix-socket",       ARG_FILE, ' ', C_ABSTRACT_UNIX_SOCKET},
   {"alpn",                       ARG_BOOL|ARG_NO|ARG_TLS, ' ', C_ALPN},
   {"alt-svc",                    ARG_STRG, ' ', C_ALT_SVC},
   {"anyauth",                    ARG_NONE, ' ', C_ANYAUTH},
   {"append",                     ARG_BOOL, 'a', C_APPEND},
   {"aws-sigv4",                  ARG_STRG, ' ', C_AWS_SIGV4},
   {"basic",                      ARG_BOOL, ' ', C_BASIC},
   {"buffer",                     ARG_BOOL|ARG_NO, 'N', C_BUFFER},
   {"ca-native",                  ARG_BOOL|ARG_TLS, ' ', C_CA_NATIVE},
   {"cacert",                     ARG_FILE|ARG_TLS, ' ', C_CACERT},
   {"capath",                     ARG_FILE|ARG_TLS, ' ', C_CAPATH},
   {"cert",                       ARG_FILE|ARG_TLS|ARG_CLEAR, 'E', C_CERT},
   {"cert-status",                ARG_BOOL|ARG_TLS, ' ', C_CERT_STATUS},
   {"cert-type",                  ARG_STRG|ARG_TLS, ' ', C_CERT_TYPE},
   {"ciphers",                    ARG_STRG|ARG_TLS, ' ', C_CIPHERS},
   {"clobber",                    ARG_BOOL|ARG_NO, ' ', C_CLOBBER},
   {"compressed",                 ARG_BOOL, ' ', C_COMPRESSED},
   {"compressed-ssh",             ARG_BOOL, ' ', C_COMPRESSED_SSH},
   {"config",                     ARG_FILE, 'K', C_CONFIG},
   {"connect-timeout",            ARG_STRG, ' ', C_CONNECT_TIMEOUT},
   {"connect-to",                 ARG_STRG, ' ', C_CONNECT_TO},
   {"continue-at",                ARG_STRG, 'C', C_CONTINUE_AT},
   {"cookie",                     ARG_STRG, 'b', C_COOKIE},
   {"cookie-jar",                 ARG_STRG, 'c', C_COOKIE_JAR},
   {"create-dirs",                ARG_BOOL, ' ', C_CREATE_DIRS},
   {"create-file-mode",           ARG_STRG, ' ', C_CREATE_FILE_MODE},
   {"crlf",                       ARG_BOOL, ' ', C_CRLF},
   {"crlfile",                    ARG_FILE|ARG_TLS, ' ', C_CRLFILE},
   {"curves",                     ARG_STRG|ARG_TLS, ' ', C_CURVES},
   {"data",                       ARG_STRG, 'd', C_DATA},
   {"data-ascii",                 ARG_STRG, ' ', C_DATA_ASCII},
   {"data-binary",                ARG_STRG, ' ', C_DATA_BINARY},
   {"data-raw",                   ARG_STRG, ' ', C_DATA_RAW},
   {"data-urlencode",             ARG_STRG, ' ', C_DATA_URLENCODE},
   {"delegation",                 ARG_STRG, ' ', C_DELEGATION},
   {"digest",                     ARG_BOOL, ' ', C_DIGEST},
   {"disable",                    ARG_BOOL, 'q', C_DISABLE},
   {"disable-eprt",               ARG_BOOL, ' ', C_DISABLE_EPRT},
   {"disable-epsv",               ARG_BOOL, ' ', C_DISABLE_EPSV},
   {"disallow-username-in-url",   ARG_BOOL, ' ', C_DISALLOW_USERNAME_IN_URL},
   {"dns-interface",              ARG_STRG, ' ', C_DNS_INTERFACE},
   {"dns-ipv4-addr",              ARG_STRG, ' ', C_DNS_IPV4_ADDR},
   {"dns-ipv6-addr",              ARG_STRG, ' ', C_DNS_IPV6_ADDR},
   {"dns-servers",                ARG_STRG, ' ', C_DNS_SERVERS},
   {"doh-cert-status",            ARG_BOOL|ARG_TLS, ' ', C_DOH_CERT_STATUS},
   {"doh-insecure",               ARG_BOOL|ARG_TLS, ' ', C_DOH_INSECURE},
   {"doh-url"        ,            ARG_STRG, ' ', C_DOH_URL},
   {"dump-ca-embed",              ARG_NONE|ARG_TLS, ' ', C_DUMP_CA_EMBED},
   {"dump-header",                ARG_FILE, 'D', C_DUMP_HEADER},
   {"ech",                        ARG_STRG|ARG_TLS, ' ', C_ECH},
   {"egd-file",                   ARG_STRG|ARG_DEPR, ' ', C_EGD_FILE},
   {"engine",                     ARG_STRG|ARG_TLS, ' ', C_ENGINE},
   {"eprt",                       ARG_BOOL, ' ', C_EPRT},
   {"epsv",                       ARG_BOOL, ' ', C_EPSV},
   {"etag-compare",               ARG_FILE, ' ', C_ETAG_COMPARE},
   {"expect100-timeout",          ARG_STRG, ' ', C_EXPECT100_TIMEOUT},
   {"fail",                       ARG_BOOL, 'f', C_FAIL},
   {"fail-early",                 ARG_BOOL, ' ', C_FAIL_EARLY},
   {"fail-with-body",             ARG_BOOL, ' ', C_FAIL_WITH_BODY},
   {"false-start",                ARG_BOOL, ' ', C_FALSE_START},
   {"follow",                     ARG_BOOL, ' ', C_FOLLOW},
  {"form",                       ARG_STRG, 'F', C_FORM},
   {"form-escape",                ARG_BOOL, ' ', C_FORM_ESCAPE},
   {"form-string",                ARG_STRG, ' ', C_FORM_STRING},
   {"ftp-account",                ARG_STRG, ' ', C_FTP_ACCOUNT},
   {"ftp-alternative-to-user",    ARG_STRG, ' ', C_FTP_ALTERNATIVE_TO_USER},
   {"ftp-create-dirs",            ARG_BOOL, ' ', C_FTP_CREATE_DIRS},
{{ ... }}
       /* failed, remove time condition */
       config->timecond = CURL_TIMECOND_NONE;
       warnf("Illegal date format for -z, --time-cond (and not "
             "a filename). Disabling time condition. "
             "See curl_getdate(3) for valid date syntax.");
     }
  return err;
}

struct flagmap {
  const char *name;
  size_t len;
  unsigned char flag;
};
 
 static const struct flagmap flag_table[] = {
   {"answered", 8, CURLULFLAG_ANSWERED},
   {"deleted",  7, CURLULFLAG_DELETED},
   {"draft",    5, CURLULFLAG_DRAFT},
{{ ... }}
   else
     *modify &= ~bits;
 }
 
 /* opt_depr is the function that handles ARG_DEPR options */
 static void opt_depr(const struct LongShort *a)
{
  warnf("--%s is deprecated and has no function anymore", a->lname);
}

static ParameterError opt_sslver(struct OperationConfig *config,
                                 unsigned char ver)
{
   if(config->ssl_version_max &&
      (config->ssl_version_max < ver)) {
     errorf("Minimum TLS version set higher than max");
     return PARAM_BAD_USE;
   }
{{ ... }}
   config->ssl_version = ver;
   return PARAM_OK;
 }
 
 /* opt_none is the function that handles ARG_NONE options */
 static ParameterError opt_none(struct OperationConfig *config,
                                const struct LongShort *a)
 {
   ParameterError err = PARAM_OK;
   switch(a->cmd) {
   case C_ANYAUTH: /* --anyauth */
     config->authtype = CURLAUTH_ANY;
     break;
   case C_DUMP_CA_EMBED: /* --dump-ca-embed */
     return PARAM_CA_EMBED_REQUESTED;
   case C_FTP_PASV: /* --ftp-pasv */
     tool_safefree(config->ftpport);
     break;
 
   case C_HTTP1_0: /* --http1.0 */
     /* HTTP version 1.0 */
     sethttpver(config, CURL_HTTP_VERSION_1_0);
     break;
   case C_HTTP1_1: /* --http1.1 */
     /* HTTP version 1.1 */
     sethttpver(config, CURL_HTTP_VERSION_1_1);
     break;
   case C_HTTP2: /* --http2 */
     /* HTTP version 2.0 */
     if(!feature_http2)
       return PARAM_LIBCURL_DOESNT_SUPPORT;
     sethttpver(config, CURL_HTTP_VERSION_2_0);
     break;
   case C_HTTP2_PRIOR_KNOWLEDGE: /* --http2-prior-knowledge */
     /* HTTP version 2.0 over clean TCP */
     if(!feature_http2)
       return PARAM_LIBCURL_DOESNT_SUPPORT;
     sethttpver(config, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
     break;
   case C_HTTP3: /* --http3: */
     /* Try HTTP/3, allow fallback */
     if(!feature_http3)
       return PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       sethttpver(config, CURL_HTTP_VERSION_3);
     break;
   case C_HTTP3_ONLY: /* --http3-only */
     /* Try HTTP/3 without fallback */
     if(!feature_http3)
       return PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       sethttpver(config, CURL_HTTP_VERSION_3ONLY);
     break;
   case C_TLSV1: /* --tlsv1 */
     err = opt_sslver(config, 1);
     break;
   case C_TLSV1_0: /* --tlsv1.0 */
     err = opt_sslver(config, 1);
     break;
   case C_TLSV1_1: /* --tlsv1.1 */
     err = opt_sslver(config, 2);
     break;
   case C_TLSV1_2: /* --tlsv1.2 */
     err = opt_sslver(config, 3);
     break;
   case C_TLSV1_3: /* --tlsv1.3 */
     err = opt_sslver(config, 4);
     break;
   case C_IPV4: /* --ipv4 */
     config->ip_version = CURL_IPRESOLVE_V4;
     break;
   case C_IPV6: /* --ipv6 */
     config->ip_version = CURL_IPRESOLVE_V6;
     break;
   case C_NEXT: /* --next */
     return PARAM_NEXT_OPERATION;
   case C_PROXY_TLSV1: /* --proxy-tlsv1 */
     /* TLS version 1 for proxy */
     config->proxy_ssl_version = CURL_SSLVERSION_TLSv1;
     break;
   }
   return err;
 }
 
 /* opt_bool is the function that handles boolean options */
 static ParameterError opt_bool(struct OperationConfig *config,
                                const struct LongShort *a,
                                bool toggle)
 {
   switch(a->cmd) {
   case C_ALPN: /* --alpn */
     config->noalpn = !toggle;
     break;
   case C_DISABLE_EPSV: /* --disable-epsv */
     config->disable_epsv = toggle;
     break;
   case C_DISALLOW_USERNAME_IN_URL: /* --disallow-username-in-url */
     config->disallow_username_in_url = toggle;
     break;
   case C_EPSV: /* --epsv */
     config->disable_epsv = !toggle;
     break;
   case C_COMPRESSED: /* --compressed */
     if(toggle && !(feature_libz || feature_brotli || feature_zstd))
       return PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       config->encoding = toggle;
     break;
   case C_TR_ENCODING: /* --tr-encoding */
     config->tr_encoding = toggle;
     break;
   case C_DIGEST: /* --digest */
     togglebit(toggle, &config->authtype, CURLAUTH_DIGEST);
     break;
   case C_FTP_CREATE_DIRS: /* --ftp-create-dirs */
     config->ftp_create_dirs = toggle;
     break;
   case C_CREATE_DIRS: /* --create-dirs */
     config->create_dirs = toggle;
     break;
   case C_PROXY_NTLM: /* --proxy-ntlm */
     if(!feature_ntlm)
       return PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       config->proxyntlm = toggle;
     break;
   case C_CRLF: /* --crlf */
     config->crlf = toggle;
     break;
   case C_HAPROXY_PROTOCOL: /* --haproxy-protocol */
     config->haproxy_protocol = toggle;
     break;
   case C_NEGOTIATE: /* --negotiate */
     if(!feature_spnego && toggle)
       return PARAM_LIBCURL_DOESNT_SUPPORT;
     togglebit(toggle, &config->authtype, CURLAUTH_NEGOTIATE);
     break;
   case C_NTLM: /* --ntlm */
     if(!feature_ntlm && toggle)
       return PARAM_LIBCURL_DOESNT_SUPPORT;
     togglebit(toggle, &config->authtype, CURLAUTH_NTLM);
     break;
   case C_OUT_NULL: /* --out-null */
     return parse_output(config, NULL);
   case C_BASIC: /* --basic */
     togglebit(toggle, &config->authtype, CURLAUTH_BASIC);
     break;
 #ifdef USE_WATT32
   case C_WDEBUG: /* --wdebug */
     dbug_init();
     break;
 #endif
   case C_DISABLE_EPRT: /* --disable-eprt */
     config->disable_eprt = toggle;
     break;
   case C_EPRT: /* --eprt */
     config->disable_eprt = !toggle;
     break;
   case C_XATTR: /* --xattr */
     config->xattr = toggle;
     break;
   case C_FTP_SSL: /* --ftp-ssl */
   case C_SSL: /* --ssl */
     config->ftp_ssl = toggle;
     if(config->ftp_ssl)
       warnf("--%s is an insecure option, consider --ssl-reqd instead",
             a->lname);
     break;
   case C_FTP_SSL_CCC: /* --ftp-ssl-ccc */
     config->ftp_ssl_ccc = toggle;
     if(!config->ftp_ssl_ccc_mode)
       config->ftp_ssl_ccc_mode = CURLFTPSSL_CCC_PASSIVE;
     break;
   case C_TCP_NODELAY: /* --tcp-nodelay */
     config->tcp_nodelay = toggle;
     break;
   case C_PROXY_DIGEST: /* --proxy-digest */
     config->proxydigest = toggle;
     break;
   case C_PROXY_BASIC: /* --proxy-basic */
     config->proxybasic = toggle;
     break;
   case C_RETRY_CONNREFUSED: /* --retry-connrefused */
     config->retry_connrefused = toggle;
     break;
   case C_RETRY_ALL_ERRORS: /* --retry-all-errors */
     config->retry_all_errors = toggle;
     break;
   case C_PROXY_NEGOTIATE: /* --proxy-negotiate */
     if(!feature_spnego)
       return PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       config->proxynegotiate = toggle;
     break;
   case C_FORM_ESCAPE: /* --form-escape */
     togglebit(toggle, &config->mime_options, CURLMIMEOPT_FORMESCAPE);
     break;
   case C_PROXY_ANYAUTH: /* --proxy-anyauth */
     config->proxyanyauth = toggle;
     break;
   case C_TRACE_TIME: /* --trace-time */
     global->tracetime = toggle;
     break;
   case C_IGNORE_CONTENT_LENGTH: /* --ignore-content-length */
     config->ignorecl = toggle;
     break;
   case C_FTP_SKIP_PASV_IP: /* --ftp-skip-pasv-ip */
     config->ftp_skip_ip = toggle;
     break;
   case C_FTP_SSL_REQD: /* --ftp-ssl-reqd */
   case C_SSL_REQD: /* --ssl-reqd */
     config->ftp_ssl_reqd = toggle;
     break;
   case C_SESSIONID: /* --sessionid */
     config->disable_sessionid = !toggle;
     break;
   case C_FTP_SSL_CONTROL: /* --ftp-ssl-control */
     config->ftp_ssl_control = toggle;
     break;
   case C_RAW: /* --raw */
     config->raw = toggle;
     break;
   case C_KEEPALIVE: /* --keepalive */
     config->nokeepalive = !toggle;
     break;
   case C_POST301: /* --post301 */
     config->post301 = toggle;
     break;
   case C_POST302: /* --post302 */
     config->post302 = toggle;
     break;
   case C_POST303: /* --post303 */
     config->post303 = toggle;
     break;
   case C_SOCKS5_GSSAPI_NEC: /* --socks5-gssapi-nec */
     config->socks5_gssapi_nec = toggle;
     break;
   case C_FTP_PRET: /* --ftp-pret */
     config->ftp_pret = toggle;
     break;
   case C_SASL_IR: /* --sasl-ir */
     config->sasl_ir = toggle;
     break;
 #ifdef DEBUGBUILD
   case C_TEST_DUPHANDLE: /* --test-duphandle */
     global->test_duphandle = toggle;
     break;
   case C_TEST_EVENT: /* --test-event */
     global->test_event_based = toggle;
     break;
 #endif
   case C_PATH_AS_IS: /* --path-as-is */
     config->path_as_is = toggle;
     break;
   case C_TFTP_NO_OPTIONS: /* --tftp-no-options */
     config->tftp_no_options = toggle;
     break;
   case C_TLS_EARLYDATA: /* --tls-earlydata */
     config->ssl_allow_earlydata = toggle;
     break;
   case C_SUPPRESS_CONNECT_HEADERS: /* --suppress-connect-headers */
     config->suppress_connect_headers = toggle;
     break;
   case C_COMPRESSED_SSH: /* --compressed-ssh */
     config->ssh_compression = toggle;
     break;
   case C_TRACE_IDS: /* --trace-ids */
     global->traceids = toggle;
     break;
   case C_PROGRESS_METER: /* --progress-meter */
     global->noprogress = !toggle;
     break;
   case C_PROGRESS_BAR: /* --progress-bar */
     global->progressmode = toggle ? CURL_PROGRESS_BAR : CURL_PROGRESS_STATS;
     break;
   case C_HTTP0_9: /* --http0.9 */
     config->http09_allowed = toggle;
     break;
   case C_PROXY_HTTP2: /* --proxy-http2 */
     if(!feature_httpsproxy || !feature_http2)
       return PARAM_LIBCURL_DOESNT_SUPPORT;
 
     config->proxyver = toggle ? CURLPROXY_HTTPS2 : CURLPROXY_HTTPS;
     break;
   case C_APPEND: /* --append */
     config->ftp_append = toggle;
     break;
   case C_USE_ASCII: /* --use-ascii */
     config->use_ascii = toggle;
     break;
   case C_CA_NATIVE: /* --ca-native */
     config->native_ca_store = toggle;
     break;
   case C_PROXY_CA_NATIVE: /* --proxy-ca-native */
     config->proxy_native_ca_store = toggle;
     break;
   case C_SSL_ALLOW_BEAST: /* --ssl-allow-beast */
     config->ssl_allow_beast = toggle;
     break;
   case C_SSL_AUTO_CLIENT_CERT: /* --ssl-auto-client-cert */
     config->ssl_auto_client_cert = toggle;
     break;
   case C_PROXY_SSL_AUTO_CLIENT_CERT: /* --proxy-ssl-auto-client-cert */
     config->proxy_ssl_auto_client_cert = toggle;
     break;
   case C_CERT_STATUS: /* --cert-status */
     config->verifystatus = toggle;
     break;
   case C_DOH_CERT_STATUS: /* --doh-cert-status */
     config->doh_verifystatus = toggle;
     break;
   case C_FALSE_START: /* --false-start */
     opt_depr(a);
     break;
   case C_SSL_NO_REVOKE: /* --ssl-no-revoke */
     config->ssl_no_revoke = toggle;
     break;
   case C_SSL_REVOKE_BEST_EFFORT: /* --ssl-revoke-best-effort */
     config->ssl_revoke_best_effort = toggle;
     break;
   case C_TCP_FASTOPEN: /* --tcp-fastopen */
     config->tcp_fastopen = toggle;
     break;
   case C_PROXY_SSL_ALLOW_BEAST: /* --proxy-ssl-allow-beast */
     config->proxy_ssl_allow_beast = toggle;
     break;
   case C_PROXY_INSECURE: /* --proxy-insecure */
     config->proxy_insecure_ok = toggle;
     break;
   case C_SOCKS5_BASIC: /* --socks5-basic */
     togglebit(toggle, &config->socks5_auth, CURLAUTH_BASIC);
     break;
   case C_SOCKS5_GSSAPI: /* --socks5-gssapi */
     togglebit(toggle, &config->socks5_auth, CURLAUTH_GSSAPI);
     break;
   case C_FAIL_EARLY: /* --fail-early */
     global->fail_early = toggle;
     break;
   case C_STYLED_OUTPUT: /* --styled-output */
     global->styled_output = toggle;
     break;
   case C_MAIL_RCPT_ALLOWFAILS: /* --mail-rcpt-allowfails */
     config->mail_rcpt_allowfails = toggle;
     break;
   case C_FAIL_WITH_BODY: /* --fail-with-body */
     config->failwithbody = toggle;
     if(config->failonerror && config->failwithbody) {
       errorf("You must select either --fail or "
              "--fail-with-body, not both.");
       return PARAM_BAD_USE;
     }
     break;
   case C_REMOVE_ON_ERROR: /* --remove-on-error */
     if(config->use_resume && toggle) {
       errorf("--continue-at is mutually exclusive with --remove-on-error");
       return PARAM_BAD_USE;
     }
     config->rm_partial = toggle;
     break;
   case C_FAIL: /* --fail */
     config->failonerror = toggle;
     if(config->failonerror && config->failwithbody) {
       errorf("You must select either --fail or "
              "--fail-with-body, not both.");
       return PARAM_BAD_USE;
     }
     break;
   case C_GLOBOFF: /* --globoff */
     config->globoff = toggle;
     break;
   case C_GET: /* --get */
     config->use_httpget = toggle;
     break;
   case C_INCLUDE: /* --include */
   case C_SHOW_HEADERS: /* --show-headers */
     config->show_headers = toggle;
     break;
   case C_JUNK_SESSION_COOKIES: /* --junk-session-cookies */
     config->cookiesession = toggle;
     break;
   case C_HEAD: /* --head */
     config->no_body = toggle;
     config->show_headers = toggle;
     if(SetHTTPrequest((config->no_body) ? TOOL_HTTPREQ_HEAD :
                       TOOL_HTTPREQ_GET, &config->httpreq))
       return PARAM_BAD_USE;
     break;
   case C_REMOTE_HEADER_NAME: /* --remote-header-name */
     config->content_disposition = toggle;
     break;
   case C_INSECURE: /* --insecure */
     config->insecure_ok = toggle;
     break;
   case C_DOH_INSECURE: /* --doh-insecure */
     config->doh_insecure_ok = toggle;
     break;
   case C_LIST_ONLY: /* --list-only */
     config->dirlistonly = toggle; /* only list the names of the FTP dir */
     break;
   case C_MANUAL: /* --manual */
     if(toggle)   /* --no-manual shows no manual... */
       return PARAM_MANUAL_REQUESTED;
     break;
   case C_NETRC_OPTIONAL: /* --netrc-optional */
     config->netrc_opt = toggle;
     break;
   case C_NETRC: /* --netrc */
     config->netrc = toggle;
     break;
   case C_BUFFER: /* --buffer */
     config->nobuffer = !toggle;
     break;
   case C_REMOTE_NAME_ALL: /* --remote-name-all */
     config->remote_name_all = toggle;
     break;
   case C_CLOBBER: /* --clobber */
     if(config->use_resume && !toggle) {
       errorf("--continue-at is mutually exclusive with --no-clobber");
       return PARAM_BAD_USE;
     }
     config->file_clobber_mode = toggle ? CLOBBER_ALWAYS : CLOBBER_NEVER;
     break;
   case C_REMOTE_NAME: /* --remote-name */
     return parse_remote_name(config, toggle);
     break;
   case C_PROXYTUNNEL: /* --proxytunnel */
     config->proxytunnel = toggle;
     break;
   case C_DISABLE: /* --disable */
     /* if used first, already taken care of, we do it like this so we do not
        cause an error! */
     break;
   case C_REMOTE_TIME: /* --remote-time */
     config->remote_time = toggle;
     break;
   case C_SILENT: /* --silent */
     global->silent = toggle;
     break;
   case C_SKIP_EXISTING: /* --skip-existing */
     config->skip_existing = toggle;
     break;
   case C_SHOW_ERROR: /* --show-error */
     global->showerror = toggle;
     break;
   case C_VERBOSE: /* --verbose */
     return parse_verbose(toggle);
     break;
   case C_VERSION: /* --version */
     if(toggle)    /* --no-version yields no output! */
       return PARAM_VERSION_INFO_REQUESTED;
     break;
   case C_PARALLEL: /* --parallel */
     global->parallel = toggle;
     break;
   case C_PARALLEL_IMMEDIATE:   /* --parallel-immediate */
     global->parallel_connect = toggle;
     break;
   case C_MPTCP: /* --mptcp */
     config->mptcp = toggle;
     break;
   case C_LOCATION_TRUSTED: /* --location-trusted */
     config->unrestricted_auth = toggle;
     FALLTHROUGH();
   case C_LOCATION: /* --location */
     if(config->followlocation == CURLFOLLOW_OBEYCODE)
       warnf("--location overrides --follow");
     config->followlocation = toggle ? CURLFOLLOW_ALL : 0;
     break;
   case C_FOLLOW: /* --follow */
     if(config->followlocation == CURLFOLLOW_ALL)
       warnf("--follow overrides --location");
     config->followlocation = toggle ? CURLFOLLOW_OBEYCODE : 0;
     break;
   default:
     return PARAM_OPTION_UNKNOWN;
   }
   return PARAM_OK;
 }
 
 
 /* opt_filestring handles string and file options */
 static ParameterError opt_filestring(struct OperationConfig *config,
                                      const struct LongShort *a,
                                      const char *nextarg)
 {
   ParameterError err = PARAM_OK;
   curl_off_t value;
   long val;
   static const char *redir_protos[] = {
     "http",
     "https",
     "ftp",
     "ftps",
     NULL
   };
   if(!nextarg)
     nextarg = "";
 
   switch(a->cmd) {
   case C_DNS_IPV4_ADDR: /* --dns-ipv4-addr */
     if(!curlinfo->ares_num) /* c-ares is needed for this */
       return PARAM_LIBCURL_DOESNT_SUPPORT;
     /* addr in dot notation */
     return getstr(&config->dns_ipv4_addr, nextarg, DENY_BLANK);
 
   case C_DNS_IPV6_ADDR: /* --dns-ipv6-addr */
     if(!curlinfo->ares_num) /* c-ares is needed for this */
       return PARAM_LIBCURL_DOESNT_SUPPORT;
     /* addr in dot notation */
     return getstr(&config->dns_ipv6_addr, nextarg, DENY_BLANK);
 
   case C_OAUTH2_BEARER: /* --oauth2-bearer */
     config->authtype |= CURLAUTH_BEARER;
     return getstr(&config->oauth_bearer, nextarg, DENY_BLANK);
 
   case C_CONNECT_TIMEOUT: /* --connect-timeout */
     return secs2ms(&config->connecttimeout_ms, nextarg);
 
   case C_DOH_URL: /* --doh-url */
     err = getstr(&config->doh_url, nextarg, ALLOW_BLANK);
     if(!err && config->doh_url && !config->doh_url[0])
       /* if given a blank string, make it NULL again */
       tool_safefree(config->doh_url);
     break;
 
   case C_CIPHERS: /* -- ciphers */
     err = getstr(&config->cipher_list, nextarg, DENY_BLANK);
     break;
 
   case C_DNS_INTERFACE: /* --dns-interface */
     if(!curlinfo->ares_num) /* c-ares is needed for this */
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       /* interface name */
       err = getstr(&config->dns_interface, nextarg, DENY_BLANK);
     break;
   case C_DNS_SERVERS: /* --dns-servers */
     if(!curlinfo->ares_num) /* c-ares is needed for this */
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       /* IP addrs of DNS servers */
       err = getstr(&config->dns_servers, nextarg, DENY_BLANK);
     break;
   case C_TRACE: /* --trace */
     err = getstr(&global->trace_dump, nextarg, DENY_BLANK);
     if(!err) {
       if(global->tracetype && (global->tracetype != TRACE_BIN))
         warnf("--trace overrides an earlier trace/verbose option");
       global->tracetype = TRACE_BIN;
     }
     break;
   case C_TRACE_ASCII: /* --trace-ascii */
     err = getstr(&global->trace_dump, nextarg, DENY_BLANK);
     if(!err) {
       if(global->tracetype && (global->tracetype != TRACE_ASCII))
         warnf("--trace-ascii overrides an earlier trace/verbose option");
       global->tracetype = TRACE_ASCII;
     }
     break;
   case C_LIMIT_RATE: /* --limit-rate */
     err = GetSizeParameter(nextarg, "rate", &value);
     if(!err) {
       config->recvpersecond = value;
       config->sendpersecond = value;
     }
     break;
   case C_RATE:
     err = set_rate(nextarg);
     break;
   case C_CREATE_FILE_MODE: /* --create-file-mode */
     err = oct2nummax(&config->create_file_mode, nextarg, 0777);
     break;
   case C_MAX_REDIRS: /* --max-redirs */
     /* specified max no of redirects (http(s)), this accepts -1 as a
        special condition */
     err = str2num(&config->maxredirs, nextarg);
     if(!err && (config->maxredirs < -1))
       err = PARAM_BAD_NUMERIC;
     break;
 #ifndef CURL_DISABLE_IPFS
   case C_IPFS_GATEWAY: /* --ipfs-gateway */
     err = getstr(&config->ipfs_gateway, nextarg, DENY_BLANK);
     break;
 #endif /* !CURL_DISABLE_IPFS */
   case C_AWS_SIGV4: /* --aws-sigv4 */
     config->authtype |= CURLAUTH_AWS_SIGV4;
     err = getstr(&config->aws_sigv4, nextarg, ALLOW_BLANK);
     break;
   case C_STDERR: /* --stderr */
     tool_set_stderr_file(nextarg);
     break;
   case C_INTERFACE: /* --interface */
     /* interface */
     err = getstr(&config->iface, nextarg, DENY_BLANK);
     break;
   case C_KRB: /* --krb */
     /* kerberos level string */
     if(!feature_spnego)
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       err = getstr(&config->krblevel, nextarg, DENY_BLANK);
     break;
   case C_HAPROXY_CLIENTIP: /* --haproxy-clientip */
     err = getstr(&config->haproxy_clientip, nextarg, DENY_BLANK);
     break;
   case C_MAX_FILESIZE: /* --max-filesize */
     err = GetSizeParameter(nextarg, "max-filesize", &value);
     if(!err)
       config->max_filesize = value;
     break;
   case C_URL: /* --url */
     err = parse_url(config, nextarg);
     break;
   case C_SOCKS5: /* --socks5 */
     /*  socks5 proxy to use, and resolves the name locally and passes on the
         resolved address */
     err = getstr(&config->proxy, nextarg, DENY_BLANK);
     config->proxyver = CURLPROXY_SOCKS5;
     break;
   case C_SOCKS4: /* --socks4 */
     err = getstr(&config->proxy, nextarg, DENY_BLANK);
     config->proxyver = CURLPROXY_SOCKS4;
     break;
   case C_SOCKS4A: /* --socks4a */
     err = getstr(&config->proxy, nextarg, DENY_BLANK);
     config->proxyver = CURLPROXY_SOCKS4A;
     break;
   case C_SOCKS5_HOSTNAME: /* --socks5-hostname */
     err = getstr(&config->proxy, nextarg, DENY_BLANK);
     config->proxyver = CURLPROXY_SOCKS5_HOSTNAME;
     break;
   case C_IP_TOS: { /* --ip-tos */
     struct TOSEntry find;
     const struct TOSEntry *entry;
     find.name = nextarg;
     entry = bsearch(&find, tos_entries,
                     CURL_ARRAYSIZE(tos_entries),
                     sizeof(*tos_entries), find_tos);
     if(entry)
       config->ip_tos = entry->value;
     else /* numeric tos value */
       err = str2unummax(&config->ip_tos, nextarg, 0xFF);
     break;
   }
   case C_VLAN_PRIORITY: /* --vlan-priority */
     err = str2unummax(&config->vlan_priority, nextarg, 7);
     break;
   case C_RETRY: /* --retry */
     err = str2unum(&config->req_retry, nextarg);
     break;
   case C_RETRY_DELAY: /* --retry-delay */
     err = secs2ms(&config->retry_delay_ms, nextarg);
     break;
   case C_RETRY_MAX_TIME: /* --retry-max-time */
     err = secs2ms(&config->retry_maxtime_ms, nextarg);
     break;
   case C_FTP_ACCOUNT: /* --ftp-account */
     err = getstr(&config->ftp_account, nextarg, DENY_BLANK);
     break;
   case C_FTP_METHOD: /* --ftp-method */
     config->ftp_filemethod = ftpfilemethod(nextarg);
     break;
   case C_LOCAL_PORT: /* --local-port */
     err = parse_localport(config, nextarg);
     break;
   case C_FTP_ALTERNATIVE_TO_USER: /* --ftp-alternative-to-user */
     err = getstr(&config->ftp_alternative_to_user, nextarg, DENY_BLANK);
     break;
   case C_LIBCURL: /* --libcurl */
 #ifdef CURL_DISABLE_LIBCURL_OPTION
     warnf("--libcurl option was disabled at build-time");
     err = PARAM_OPTION_UNKNOWN;
 #else
     err = getstr(&global->libcurl, nextarg, DENY_BLANK);
 #endif
     break;
   case C_KEEPALIVE_TIME: /* --keepalive-time */
     err = str2unum(&config->alivetime, nextarg);
     break;
   case C_KEEPALIVE_CNT: /* --keepalive-cnt */
     err = str2unum(&config->alivecnt, nextarg);
     break;
   case C_NOPROXY: /* --noproxy */
     /* This specifies the noproxy list */
     err = getstr(&config->noproxy, nextarg, ALLOW_BLANK);
     break;
   case C_PROXY1_0: /* --proxy1.0 */
     /* http 1.0 proxy */
     err = getstr(&config->proxy, nextarg, DENY_BLANK);
     config->proxyver = CURLPROXY_HTTP_1_0;
     break;
   case C_TFTP_BLKSIZE: /* --tftp-blksize */
     err = str2unum(&config->tftp_blksize, nextarg);
     break;
   case C_MAIL_FROM: /* --mail-from */
     err = getstr(&config->mail_from, nextarg, DENY_BLANK);
     break;
   case C_MAIL_RCPT: /* --mail-rcpt */
     /* append receiver to a list */
     err = add2list(&config->mail_rcpt, nextarg);
     break;
   case C_PROTO: /* --proto */
     config->proto_present = TRUE;
     err = proto2num(built_in_protos, &config->proto_str, nextarg);
     break;
   case C_PROTO_REDIR: /* --proto-redir */
     config->proto_redir_present = TRUE;
     if(proto2num(redir_protos, &config->proto_redir_str, nextarg))
       err = PARAM_BAD_USE;
     break;
   case C_RESOLVE: /* --resolve */
     err = add2list(&config->resolve, nextarg);
     break;
   case C_DELEGATION: /* --delegation */
     config->gssapi_delegation = delegation(nextarg);
     break;
   case C_MAIL_AUTH: /* --mail-auth */
     err = getstr(&config->mail_auth, nextarg, DENY_BLANK);
     break;
   case C_SASL_AUTHZID: /* --sasl-authzid */
     err = getstr(&config->sasl_authzid, nextarg, DENY_BLANK);
     break;
   case C_UNIX_SOCKET: /* --unix-socket */
     config->abstract_unix_socket = FALSE;
     err = getstr(&config->unix_socket_path, nextarg, DENY_BLANK);
     break;
   case C_PROXY_SERVICE_NAME: /* --proxy-service-name */
     err = getstr(&config->proxy_service_name, nextarg, DENY_BLANK);
     break;
   case C_SERVICE_NAME: /* --service-name */
     err = getstr(&config->service_name, nextarg, DENY_BLANK);
     break;
   case C_PROTO_DEFAULT: /* --proto-default */
     err = getstr(&config->proto_default, nextarg, DENY_BLANK);
     if(!err)
       err = check_protocol(config->proto_default);
     break;
   case C_EXPECT100_TIMEOUT: /* --expect100-timeout */
     err = secs2ms(&config->expect100timeout_ms, nextarg);
     break;
   case C_CONNECT_TO: /* --connect-to */
     err = add2list(&config->connect_to, nextarg);
     break;
   case C_ABSTRACT_UNIX_SOCKET: /* --abstract-unix-socket */
     config->abstract_unix_socket = TRUE;
     err = getstr(&config->unix_socket_path, nextarg, DENY_BLANK);
     break;
   case C_TLS_MAX: /* --tls-max */
     err = str2tls_max(&config->ssl_version_max, nextarg);
     if(!err && (config->ssl_version_max < config->ssl_version)) {
       errorf("--tls-max set lower than minimum accepted version");
       err = PARAM_BAD_USE;
     }
     break;
   case C_HAPPY_EYEBALLS_TIMEOUT_MS: /* --happy-eyeballs-timeout-ms */
     err = str2unum(&config->happy_eyeballs_timeout_ms, nextarg);
     /* 0 is a valid value for this timeout */
     break;
   case C_TRACE_CONFIG: /* --trace-config */
     if(set_trace_config(nextarg))
       err = PARAM_NO_MEM;
     break;
   case C_VARIABLE: /* --variable */
     err = setvariable(nextarg);
     break;
   case C_TLS13_CIPHERS: /* --tls13-ciphers */
     err = getstr(&config->cipher13_list, nextarg, DENY_BLANK);
     break;
   case C_PROXY_TLS13_CIPHERS: /* --proxy-tls13-ciphers */
     err = getstr(&config->proxy_cipher13_list, nextarg, DENY_BLANK);
     break;
   case C_USER_AGENT: /* --user-agent */
     err = getstr(&config->useragent, nextarg, ALLOW_BLANK);
     break;
   case C_ALT_SVC: /* --alt-svc */
     if(!feature_altsvc)
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       err = getstr(&config->altsvc, nextarg, ALLOW_BLANK);
     break;
   case C_HSTS: /* --hsts */
     if(!feature_hsts)
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       err = getstr(&config->hsts, nextarg, ALLOW_BLANK);
     break;
   case C_COOKIE: /* --cookie */
     if(strchr(nextarg, '=')) {
       /* A cookie string must have a =-letter */
       err = add2list(&config->cookies, nextarg);
       break;
     }
     else {
       /* We have a cookie file to read from! */
       err = add2list(&config->cookiefiles, nextarg);
     }
     break;
   case C_COOKIE_JAR: /* --cookie-jar */
     err = getstr(&config->cookiejar, nextarg, DENY_BLANK);
     break;
   case C_CONTINUE_AT: /* --continue-at */
     err = parse_continue_at(config, nextarg);
     break;
   case C_DATA: /* --data */
   case C_DATA_ASCII:  /* --data-ascii */
   case C_DATA_BINARY:  /* --data-binary */
   case C_DATA_URLENCODE:  /* --data-urlencode */
   case C_JSON:  /* --json */
   case C_DATA_RAW:  /* --data-raw */
     err = set_data((cmdline_t)a->cmd, nextarg, config);
     break;
   case C_URL_QUERY:  /* --url-query */
     err = url_query(nextarg, config);
     break;
   case C_DUMP_HEADER: /* --dump-header */
     err = getstr(&config->headerfile, nextarg, DENY_BLANK);
     break;
   case C_REFERER: { /* --referer */
     size_t len = strlen(nextarg);
     /* does it end with ;auto ? */
     if(len >= 5 && !strcmp(";auto", &nextarg[len - 5])) {
       /* Automatic referer requested, this may be combined with a set initial
          one */
       config->autoreferer = TRUE;
       len -= 5;
     }
     else
       config->autoreferer = FALSE;
 
     if(len)
       err = getstrn(&config->referer, nextarg, len, ALLOW_BLANK);
     else
       tool_safefree(config->referer);
   }
     break;
   case C_CERT: /* --cert */
     GetFileAndPassword(nextarg, &config->cert, &config->key_passwd);
     break;
   case C_CACERT: /* --cacert */
     err = getstr(&config->cacert, nextarg, DENY_BLANK);
     break;
   case C_CERT_TYPE: /* --cert-type */
     err = getstr(&config->cert_type, nextarg, DENY_BLANK);
     break;
   case C_KEY: /* --key */
     err = getstr(&config->key, nextarg, DENY_BLANK);
     break;
   case C_KEY_TYPE: /* --key-type */
     err = getstr(&config->key_type, nextarg, DENY_BLANK);
     break;
   case C_PASS: /* --pass */
     err = getstr(&config->key_passwd, nextarg, DENY_BLANK);
     break;
   case C_ENGINE: /* --engine */
     err = getstr(&config->engine, nextarg, DENY_BLANK);
     if(!err &&
        config->engine && !strcmp(config->engine, "list")) {
       err = PARAM_ENGINES_REQUESTED;
     }
     break;
   case C_ECH: /* --ech */
     err = parse_ech(config, nextarg);
     break;
   case C_CAPATH: /* --capath */
     err = getstr(&config->capath, nextarg, DENY_BLANK);
     break;
   case C_PUBKEY: /* --pubkey */
     err = getstr(&config->pubkey, nextarg, DENY_BLANK);
     break;
   case C_HOSTPUBMD5: /* --hostpubmd5 */
     err = getstr(&config->hostpubmd5, nextarg, DENY_BLANK);
     if(!err) {
       if(!config->hostpubmd5 || strlen(config->hostpubmd5) != 32)
         err = PARAM_BAD_USE;
     }
     break;
   case C_HOSTPUBSHA256: /* --hostpubsha256 */
     if(!feature_libssh2)
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       err = getstr(&config->hostpubsha256, nextarg, DENY_BLANK);
     break;
   case C_CRLFILE: /* --crlfile */
     err = getstr(&config->crlfile, nextarg, DENY_BLANK);
     break;
   case C_TLSUSER: /* --tlsuser */
     if(!feature_tls_srp)
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       err = getstr(&config->tls_username, nextarg, DENY_BLANK);
     break;
   case C_TLSPASSWORD: /* --tlspassword */
     if(!feature_tls_srp)
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       err = getstr(&config->tls_password, nextarg, ALLOW_BLANK);
     break;
   case C_TLSAUTHTYPE: /* --tlsauthtype */
     if(!feature_tls_srp)
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     else {
       err = getstr(&config->tls_authtype, nextarg, DENY_BLANK);
       if(!err && config->tls_authtype && strcmp(config->tls_authtype, "SRP"))
         err = PARAM_LIBCURL_DOESNT_SUPPORT; /* only support TLS-SRP */
     }
     break;
   case C_PINNEDPUBKEY: /* --pinnedpubkey */
     err = getstr(&config->pinnedpubkey, nextarg, DENY_BLANK);
     break;
   case C_PROXY_PINNEDPUBKEY: /* --proxy-pinnedpubkey */
     err = getstr(&config->proxy_pinnedpubkey, nextarg, DENY_BLANK);
     break;
   case C_SSL_SESSIONS: /* --ssl-sessions */
     if(feature_ssls_export)
       err = getstr(&global->ssl_sessions, nextarg, DENY_BLANK);
     else
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     break;
   case C_PROXY_TLSUSER: /* --proxy-tlsuser */
     if(!feature_tls_srp)
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       err = getstr(&config->proxy_tls_username, nextarg, ALLOW_BLANK);
     break;
   case C_PROXY_TLSPASSWORD: /* --proxy-tlspassword */
     if(!feature_tls_srp)
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     else
       err = getstr(&config->proxy_tls_password, nextarg, DENY_BLANK);
     break;
   case C_PROXY_TLSAUTHTYPE: /* --proxy-tlsauthtype */
     if(!feature_tls_srp)
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
     else {
       err = getstr(&config->proxy_tls_authtype, nextarg, DENY_BLANK);
       if(!err && config->proxy_tls_authtype &&
          strcmp(config->proxy_tls_authtype, "SRP"))
         err = PARAM_LIBCURL_DOESNT_SUPPORT; /* only support TLS-SRP */
     }
     break;
   case C_PROXY_CERT: /* --proxy-cert */
     GetFileAndPassword(nextarg, &config->proxy_cert,
                        &config->proxy_key_passwd);
     break;
   case C_PROXY_CERT_TYPE: /* --proxy-cert-type */
     err = getstr(&config->proxy_cert_type, nextarg, DENY_BLANK);
     break;
   case C_PROXY_KEY: /* --proxy-key */
     err = getstr(&config->proxy_key, nextarg, ALLOW_BLANK);
     break;
   case C_PROXY_KEY_TYPE: /* --proxy-key-type */
     err = getstr(&config->proxy_key_type, nextarg, DENY_BLANK);
     break;
   case C_PROXY_PASS: /* --proxy-pass */
     err = getstr(&config->proxy_key_passwd, nextarg, ALLOW_BLANK);
     break;
   case C_PROXY_CIPHERS: /* --proxy-ciphers */
     err = getstr(&config->proxy_cipher_list, nextarg, DENY_BLANK);
     break;
   case C_PROXY_CRLFILE: /* --proxy-crlfile */
     err = getstr(&config->proxy_crlfile, nextarg, DENY_BLANK);
     break;
   case C_LOGIN_OPTIONS: /* --login-options */
     err = getstr(&config->login_options, nextarg, ALLOW_BLANK);
     break;
   case C_PROXY_CACERT: /* --proxy-cacert */
     err = getstr(&config->proxy_cacert, nextarg, DENY_BLANK);
     break;
   case C_PROXY_CAPATH: /* --proxy-capath */
     err = getstr(&config->proxy_capath, nextarg, DENY_BLANK);
     break;
   case C_ETAG_SAVE: /* --etag-save */
     if(config->num_urls > 1) {
       errorf("The etag options only work on a single URL");
       err = PARAM_BAD_USE;
     }
     else
       err = getstr(&config->etag_save_file, nextarg, DENY_BLANK);
     break;
   case C_ETAG_COMPARE: /* --etag-compare */
     if(config->num_urls > 1) {
       errorf("The etag options only work on a single URL");
       err = PARAM_BAD_USE;
     }
     else
       err = getstr(&config->etag_compare_file, nextarg, DENY_BLANK);
     break;
   case C_CURVES: /* --curves */
     err = getstr(&config->ssl_ec_curves, nextarg, DENY_BLANK);
     break;
   case C_SIGNATURE_ALGORITHMS: /* --sigalgs */
     err = getstr(&config->ssl_signature_algorithms, nextarg, DENY_BLANK);
     break;
   case C_FORM: /* --form */
   case C_FORM_STRING: /* --form-string */
     /* "form data" simulation, this is a little advanced so lets do our best
        to sort this out slowly and carefully */
     if(formparse(nextarg, &config->mimeroot, &config->mimecurrent,
                  (a->cmd == C_FORM_STRING))) /* literal string */
       err = PARAM_BAD_USE;
     else if(SetHTTPrequest(TOOL_HTTPREQ_MIMEPOST, &config->httpreq))
       err = PARAM_BAD_USE;
     break;
   case C_REQUEST_TARGET: /* --request-target */
     err = getstr(&config->request_target, nextarg, DENY_BLANK);
     break;
   case C_HEADER: /* --header */
   case C_PROXY_HEADER: /* --proxy-header */
     err = parse_header(config, (cmdline_t)a->cmd, nextarg);
     break;
   case C_CONFIG: /* --config */
     if(parseconfig(nextarg)) {
       errorf("cannot read config from '%s'", nextarg);
       err = PARAM_READ_ERROR;
     }
     break;
   case C_MAX_TIME: /* --max-time */
     /* specified max time */
     err = secs2ms(&config->timeout_ms, nextarg);
     break;
   case C_NETRC_FILE: /* --netrc-file */
     err = getstr(&config->netrc_file, nextarg, DENY_BLANK);
     break;
   case C_OUTPUT_DIR: /* --output-dir */
     err = getstr(&config->output_dir, nextarg, DENY_BLANK);
     break;
   case C_OUTPUT: /* --output */
     err = parse_output(config, nextarg);
     break;
   case C_FTP_PORT: /* --ftp-port */
     /* This makes the FTP sessions use PORT instead of PASV */
     /* use <eth0> or <192.168.10.10> style addresses. Anything except
        this will make us try to get the "default" address.
        NOTE: this is a changed behavior since the released 4.1!
     */
     err = getstr(&config->ftpport, nextarg, DENY_BLANK);
     break;
   case C_FTP_SSL_CCC_MODE: /* --ftp-ssl-ccc-mode */
     config->ftp_ssl_ccc = TRUE;
     config->ftp_ssl_ccc_mode = ftpcccmethod(nextarg);
     break;
   case C_QUOTE: /* --quote */
     err = parse_quote(config, nextarg);
     break;
   case C_RANGE: /* --range */
     err = parse_range(config, nextarg);
     break;
   case C_TELNET_OPTION: /* --telnet-option */
     /* Telnet options */
     err = add2list(&config->telnet_options, nextarg);
     break;
   case C_UPLOAD_FILE: /* --upload-file */
     err = parse_upload_file(config, nextarg);
     break;
   case C_USER: /* --user */
     /* user:password  */
     err = getstr(&config->userpwd, nextarg, ALLOW_BLANK);
     break;
   case C_PROXY_USER: /* --proxy-user */
     /* Proxy user:password  */
     err = getstr(&config->proxyuserpwd, nextarg, ALLOW_BLANK);
     break;
   case C_WRITE_OUT: /* --write-out */
     err = parse_writeout(config, nextarg);
     break;
   case C_PREPROXY: /* --preproxy */
     err = getstr(&config->preproxy, nextarg, DENY_BLANK);
     break;
   case C_PROXY: /* --proxy */
     /* --proxy */
     err = getstr(&config->proxy, nextarg, ALLOW_BLANK);
     if(config->proxyver != CURLPROXY_HTTPS2)
       config->proxyver = CURLPROXY_HTTP;
     break;
   case C_REQUEST: /* --request */
     /* set custom request */
     err = getstr(&config->customrequest, nextarg, DENY_BLANK);
     break;
   case C_SPEED_TIME: /* --speed-time */
     /* low speed time */
     err = str2unum(&config->low_speed_time, nextarg);
     if(!err && !config->low_speed_limit)
       config->low_speed_limit = 1;
     break;
   case C_SPEED_LIMIT: /* --speed-limit */
     /* low speed limit */
     err = str2unum(&config->low_speed_limit, nextarg);
     if(!err && !config->low_speed_time)
       config->low_speed_time = 30;
     break;
   case C_PARALLEL_HOST: /* --parallel-max-host */
     err = str2unum(&val, nextarg);
     if(err)
       break;
     if(val > MAX_PARALLEL_HOST)
       global->parallel_host = MAX_PARALLEL_HOST;
     else if(val < 1)
       global->parallel_host = PARALLEL_HOST_DEFAULT;
     else
       global->parallel_host = (unsigned short)val;
     break;
     break;
   case C_PARALLEL_MAX:  /* --parallel-max */
     err = str2unum(&val, nextarg);
     if(err)
       break;
     if(val > MAX_PARALLEL)
       global->parallel_max = MAX_PARALLEL;
     else if(val < 1)
       global->parallel_max = PARALLEL_DEFAULT;
     else
       global->parallel_max = (unsigned short)val;
     break;
   case C_TIME_COND: /* --time-cond */
     err = parse_time_cond(config, nextarg);
     break;
   case C_UPLOAD_FLAGS: /* --upload-flags */
     err = parse_upload_flags(config, nextarg);
     break;
   }
   return err;
 }
 
 /* the longest command line option, excluding the leading -- */
 #define MAX_OPTION_LEN 26
 
 ParameterError getparameter(const char *flag, /* f or -long-flag */
                             const char *nextarg,    /* NULL if unset */
                             bool *usedarg,    /* set to TRUE if the arg
                                                  has been used */
                             struct OperationConfig *config)
 {
   const char *parse = NULL;
   bool longopt = FALSE;
   bool singleopt = FALSE; /* when true means '-o foo' used '-ofoo' */
   ParameterError err = PARAM_OK;
   bool toggle = TRUE; /* how to switch boolean options, on or off. Controlled
                          by using --OPTION or --no-OPTION */
   bool nextalloc = FALSE; /* if nextarg is allocated */
   bool consumearg = TRUE; /* the argument comes separate */
   const struct LongShort *a = NULL;
   verbose_nopts = 0; /* options processed in `flag`*/
 
   *usedarg = FALSE; /* default is that we do not use the arg */
 
   if(('-' != flag[0]) || ('-' == flag[1])) {
     /* this should be a long name */
     const char *word = ('-' == flag[0]) ? flag + 2 : flag;
     bool noflagged = FALSE;
     bool expand = FALSE;
     const char *p;
     struct Curl_str out;
 
     if(!strncmp(word, "no-", 3)) {
       /* disable this option but ignore the "no-" part when looking for it */
       word += 3;
       toggle = FALSE;
       noflagged = TRUE;
     }
     else if(!strncmp(word, "expand-", 7)) {
       /* variable expansions is to be done on the argument */
       word += 7;
       expand = TRUE;
     }
 
     p = word;
     /* is there an '=' ? */
     if(!curlx_str_until(&p, &out, MAX_OPTION_LEN, '=') &&
        !curlx_str_single(&p, '=') ) {
       /* there's an equal sign */
       char tempword[MAX_OPTION_LEN + 1];
       memcpy(tempword, curlx_str(&out), curlx_strlen(&out));
       tempword[curlx_strlen(&out)] = 0;
       a = findlongopt(tempword);
       nextarg = p;
       consumearg = FALSE; /* it is not separate */
     }
     else
       a = findlongopt(word);
 
     if(a) {
       longopt = TRUE;
     }
     else {
       err = PARAM_OPTION_UNKNOWN;
       goto error;
     }
     if(noflagged && (ARGTYPE(a->desc) != ARG_BOOL)) {
       /* --no- prefixed an option that is not boolean! */
       err = PARAM_NO_PREFIX;
       goto error;
     }
     else if(expand && nextarg) {
       struct dynbuf nbuf;
       bool replaced;
 
       if((ARGTYPE(a->desc) != ARG_STRG) &&
          (ARGTYPE(a->desc) != ARG_FILE)) {
         /* --expand on an option that is not a string or a filename */
         err = PARAM_EXPAND_ERROR;
         goto error;
       }
       err = varexpand(nextarg, &nbuf, &replaced);
       if(err) {
         curlx_dyn_free(&nbuf);
         goto error;
       }
       if(replaced) {
         nextarg = curlx_dyn_ptr(&nbuf);
         nextalloc = TRUE;
       }
     }
   }
   else {
     flag++; /* prefixed with one dash, pass it */
     parse = flag;
   }
 
   do {
     /* we can loop here if we have multiple single-letters */
     if(!longopt) {
       a = findshortopt(*parse);
       if(!a) {
         err = PARAM_OPTION_UNKNOWN;
         break;
       }
       toggle = !(a->desc & ARG_NO);
     }
     if((a->desc & ARG_TLS) && !feature_ssl) {
       err = PARAM_LIBCURL_DOESNT_SUPPORT;
       break;
     }
     else if(ARGTYPE(a->desc) >= ARG_STRG) {
       /* this option requires an extra parameter */
       if(!longopt && parse[1]) {
         nextarg = &parse[1]; /* this is the actual extra parameter */
         singleopt = TRUE;   /* do not loop anymore after this */
       }
       else if(a->cmd == C_HELP) {
         /* --help is special */
         tool_help((nextarg && *nextarg) ? nextarg : NULL);
         err = PARAM_HELP_REQUESTED;
         break;
       }
       else if(!nextarg) {
         err = PARAM_REQUIRES_PARAMETER;
         break;
       }
       else {
         *usedarg = consumearg; /* mark it as used */
       }
       if(a->desc & ARG_DEPR) {
         opt_depr(a);
         break;
       }
 
       if((ARGTYPE(a->desc) == ARG_FILE) &&
          (nextarg[0] == '-') && nextarg[1]) {
         /* if the filename looks like a command line option */
         warnf("The filename argument '%s' looks like a flag.",
               nextarg);
       }
       else if(!strncmp("\xe2\x80\x9c", nextarg, 3)) {
         warnf("The argument '%s' starts with a Unicode quote where "
               "maybe an ASCII \" was intended?",
               nextarg);
       }
       /* ARG_FILE | ARG_STRG */
       err = opt_filestring(config, a, nextarg);
       if(a->desc & ARG_CLEAR)
         cleanarg(CURL_UNCONST(nextarg));
     }
     else {
       if(a->desc & ARG_DEPR) {
         opt_depr(a);
         break;
       }
       /* ARG_NONE | ARG_BOOL */
       if(ARGTYPE(a->desc) == ARG_BOOL)
         err = opt_bool(config, a, toggle);
       else
         err = opt_none(config, a);
     }
 
     ++verbose_nopts; /* processed one option from `flag` input, loop for
                         more */
   } while(!longopt && !singleopt && *++parse && !*usedarg && !err);
 
 error:
   if(nextalloc)
     free(CURL_UNCONST(nextarg));
   return err;
 }
 
 ParameterError parse_args(int argc, argv_item_t argv[])
 {
   int i;
   bool stillflags;
   const char *orig_opt = NULL;
   ParameterError result = PARAM_OK;
   struct OperationConfig *config = global->first;
 
   for(i = 1, stillflags = TRUE; i < argc && !result; i++) {
     orig_opt = convert_tchar_to_UTF8(argv[i]);
     if(!orig_opt)
       return PARAM_NO_MEM;
 
     if(stillflags && ('-' == orig_opt[0])) {
       bool passarg;
 
       if(!strcmp("--", orig_opt))
         /* This indicates the end of the flags and thus enables the
            following (URL) argument to start with -. */
         stillflags = FALSE;
       else {
         const char *nextarg = NULL;
         if(i < (argc - 1)) {
           nextarg = convert_tchar_to_UTF8(argv[i + 1]);
           if(!nextarg) {
             unicodefree(orig_opt);
             return PARAM_NO_MEM;
           }
         }
 
         result = getparameter(orig_opt, nextarg, &passarg, config);
 
         unicodefree(nextarg);
         config = global->last;
         if(result == PARAM_NEXT_OPERATION) {
           /* Reset result as PARAM_NEXT_OPERATION is only used here and not
              returned from this function */
           result = PARAM_OK;
 
           if(config->url_list && config->url_list->url) {
             /* Allocate the next config */
             config->next = config_alloc();
             if(config->next) {
               /* Update the last config pointer */
               global->last = config->next;
 
               /* Move onto the new config */
               config->next->prev = config;
               config = config->next;
             }
             else
               result = PARAM_NO_MEM;
           }
           else {
             errorf("missing URL before --next");
             result = PARAM_BAD_USE;
           }
         }
         else if(!result && passarg)
           i++; /* we are supposed to skip this */
       }
     }
     else {
       bool used;
 
       /* Just add the URL please */
       result = getparameter("--url", orig_opt, &used, config);
     }
 
     if(!result) {
       unicodefree(orig_opt);
       orig_opt = NULL;
     }
   }
 
   if(!result && config->content_disposition) {
     if(config->resume_from_current)
       result = PARAM_CONTDISP_RESUME_FROM;
   }
 
   if(result && result != PARAM_HELP_REQUESTED &&
      result != PARAM_MANUAL_REQUESTED &&
      result != PARAM_VERSION_INFO_REQUESTED &&
      result != PARAM_ENGINES_REQUESTED &&
      result != PARAM_CA_EMBED_REQUESTED) {
     const char *reason = param2text(result);
 
     if(orig_opt && strcmp(":", orig_opt))
       helpf("option %s: %s", orig_opt, reason);
     else
       helpf("%s", reason);
   }
 
   unicodefree(orig_opt);
   return result;
 }
 
