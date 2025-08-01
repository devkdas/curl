#ifndef HEADER_CURL_TOOL_GETPARAM_H
#define HEADER_CURL_TOOL_GETPARAM_H
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

/* one enum for every command line option. The name is the verbatim long
   option name, but in uppercase with periods and minuses replaced with
   underscores using a "C_" prefix. */
typedef enum {
  C_ABSTRACT_UNIX_SOCKET,
  C_ALPN,
  C_ALT_SVC,
  C_ANYAUTH,
  C_APPEND,
  C_AWS_SIGV4,
  C_BASIC,
  C_BUFFER,
  C_CA_NATIVE,
  C_CACERT,
  C_CAPATH,
  C_CERT,
  C_CERT_STATUS,
  C_CERT_TYPE,
  C_CIPHERS,
  C_CLOBBER,
  C_COMPRESSED,
  C_COMPRESSED_SSH,
  C_CONFIG,
  C_CONNECT_TIMEOUT,
  C_CONNECT_TO,
  C_CONTINUE_AT,
  C_COOKIE,
  C_COOKIE_JAR,
  C_CREATE_DIRS,
  C_CREATE_FILE_MODE,
  C_CRLF,
  C_CRLFILE,
  C_CURVES,
  C_DATA,
  C_DATA_ASCII,
  C_DATA_BINARY,
  C_DATA_RAW,
  C_DATA_URLENCODE,
  C_DELEGATION,
  C_DIGEST,
  C_DISABLE,
  C_DISABLE_EPRT,
  C_DISABLE_EPSV,
  C_DISALLOW_USERNAME_IN_URL,
  C_DNS_INTERFACE,
  C_DNS_IPV4_ADDR,
  C_DNS_IPV6_ADDR,
  C_DNS_SERVERS,
  C_DOH_CERT_STATUS,
  C_DOH_INSECURE,
  C_DOH_URL,
  C_DUMP_CA_EMBED,
  C_DUMP_HEADER,
  C_ECH,
  C_EGD_FILE,
  C_ENGINE,
  C_EPRT,
  C_EPSV,
  C_ETAG_COMPARE,
  C_ETAG_SAVE,
  C_EXPECT100_TIMEOUT,
  C_FAIL,
  C_FAIL_EARLY,
  C_FAIL_WITH_BODY,
  C_FALSE_START,
  C_FORM,
  C_FORM_ESCAPE,
  C_FORM_STRING,
  C_FTP_ACCOUNT,
  C_FTP_ALTERNATIVE_TO_USER,
  C_FTP_CREATE_DIRS,
  C_FTP_METHOD,
  C_FTP_PASV,
  C_FTP_PORT,
  C_FTP_PRET,
  C_FTP_SKIP_PASV_IP,
  C_FTP_SSL,
  C_FTP_SSL_CCC,
  C_FTP_SSL_CCC_MODE,
  C_FTP_SSL_CONTROL,
  C_FTP_SSL_REQD,
  C_GET,
  C_GLOBOFF,
  C_HAPPY_EYEBALLS_TIMEOUT_MS,
  C_HAPROXY_CLIENTIP,
  C_HAPROXY_PROTOCOL,
  C_HEAD,
  C_HEADER,
  C_HELP,
  C_HOSTPUBMD5,
  C_HOSTPUBSHA256,
  C_HSTS,
  C_HTTP0_9,
  C_HTTP1_0,
  C_HTTP1_1,
  C_HTTP2,
  C_HTTP2_PRIOR_KNOWLEDGE,
  C_HTTP3,
  C_HTTP3_ONLY,
  C_QUIC_V2,
  C_IGNORE_CONTENT_LENGTH,
  C_INCLUDE,
  C_INSECURE,
  C_INTERFACE,
  C_IPFS_GATEWAY,
  C_IPV4,
  C_IPV6,
  C_JSON,
  C_JUNK_SESSION_COOKIES,
  C_KEEPALIVE,
  C_KEEPALIVE_CNT,
  C_KEEPALIVE_TIME,
  C_KEY,
  C_KEY_TYPE,
  C_KRB,
  C_KRB4,
  C_LIBCURL,
  C_LIMIT_RATE,
  C_LIST_ONLY,
  C_LOCAL_PORT,
  C_LOCATION,
  C_LOCATION_TRUSTED,
  C_LOGIN_OPTIONS,
  C_MAIL_AUTH,
  C_MAIL_FROM,
  C_MAIL_RCPT,
  C_MAIL_RCPT_ALLOWFAILS,
  C_MANUAL,
  C_MAX_FILESIZE,
  C_MAX_REDIRS,
  C_MAX_TIME,
  C_METALINK,
  C_MPTCP,
  C_NEGOTIATE,
  C_NETRC,
  C_NETRC_FILE,
  C_NETRC_OPTIONAL,
  C_NEXT,
  C_NOPROXY,
  C_NPN,
  C_NTLM,
  C_NTLM_WB,
  C_OAUTH2_BEARER,
  C_OUT_NULL,
  C_OUTPUT,
  C_OUTPUT_DIR,
  C_PARALLEL,
  C_PARALLEL_IMMEDIATE,
  C_PARALLEL_MAX,
  C_PASS,
  C_PATH_AS_IS,
  C_PINNEDPUBKEY,
  C_POST301,
  C_POST302,
  C_POST303,
  C_PREPROXY,
  C_PROGRESS_BAR,
  C_PROGRESS_METER,
  C_PROTO,
  C_PROTO_DEFAULT,
  C_PROTO_REDIR,
  C_PROXY,
  C_PROXY_ANYAUTH,
  C_PROXY_BASIC,
  C_PROXY_CA_NATIVE,
  C_PROXY_CACERT,
  C_PROXY_CAPATH,
  C_PROXY_CERT,
  C_PROXY_CERT_TYPE,
  C_PROXY_CIPHERS,
  C_PROXY_CRLFILE,
  C_PROXY_DIGEST,
  C_PROXY_HEADER,
  C_PROXY_HTTP2,
  C_PROXY_INSECURE,
  C_PROXY_KEY,
  C_PROXY_KEY_TYPE,
  C_PROXY_NEGOTIATE,
  C_PROXY_NTLM,
  C_PROXY_PASS,
  C_PROXY_PINNEDPUBKEY,
  C_PROXY_SERVICE_NAME,
  C_PROXY_SSL_ALLOW_BEAST,
  C_PROXY_SSL_AUTO_CLIENT_CERT,
  C_PROXY_TLS13_CIPHERS,
  C_PROXY_TLSAUTHTYPE,
  C_PROXY_TLSPASSWORD,
  C_PROXY_TLSUSER,
  C_PROXY_TLSV1,
  C_PROXY_USER,
  C_PROXY1_0,
  C_PROXYTUNNEL,
  C_PUBKEY,
  C_QUOTE,
  C_RANDOM_FILE,
  C_RANGE,
  C_RATE,
  C_RAW,
  C_REFERER,
  C_REMOTE_HEADER_NAME,
  C_REMOTE_NAME,
  C_REMOTE_NAME_ALL,
  C_REMOTE_TIME,
  C_REMOVE_ON_ERROR,
  C_REQUEST,
  C_REQUEST_TARGET,
  C_RESOLVE,
  C_RETRY,
  C_RETRY_ALL_ERRORS,
  C_RETRY_CONNREFUSED,
  C_RETRY_DELAY,
  C_RETRY_MAX_TIME,
  C_SASL_AUTHZID,
  C_SASL_IR,
  C_SERVICE_NAME,
  C_SESSIONID,
  C_SHOW_ERROR,
  C_SHOW_HEADERS,
  C_SILENT,
  C_SIGNATURE_ALGORITHMS,
  C_SKIP_EXISTING,
  C_SOCKS4,
  C_SOCKS4A,
  C_SOCKS5,
  C_SOCKS5_BASIC,
  C_SOCKS5_GSSAPI,
  C_SOCKS5_GSSAPI_NEC,
  C_SOCKS5_GSSAPI_SERVICE,
  C_SOCKS5_HOSTNAME,
  C_SPEED_LIMIT,
  C_SPEED_TIME,
  C_SSL,
  C_SSL_ALLOW_BEAST,
  C_SSL_AUTO_CLIENT_CERT,
  C_SSL_NO_REVOKE,
  C_SSL_REQD,
  C_SSL_REVOKE_BEST_EFFORT,
  C_SSL_SESSIONS,
  C_SSLV2,
  C_SSLV3,
  C_STDERR,
  C_STYLED_OUTPUT,
  C_SUPPRESS_CONNECT_HEADERS,
  C_TCP_FASTOPEN,
  C_TCP_NODELAY,
  C_TELNET_OPTION,
  C_TEST_DUPHANDLE,
  C_TEST_EVENT,
  C_TFTP_BLKSIZE,
  C_TFTP_NO_OPTIONS,
  C_TIME_COND,
  C_TLS_EARLYDATA,
  C_TLS_MAX,
  C_TLS13_CIPHERS,
  C_TLSAUTHTYPE,
  C_TLSPASSWORD,
  C_TLSUSER,
  C_TLSV1,
  C_TLSV1_0,
  C_TLSV1_1,
  C_TLSV1_2,
  C_TLSV1_3,
  C_TR_ENCODING,
  C_TRACE,
  C_TRACE_ASCII,
  C_TRACE_CONFIG,
  C_TRACE_IDS,
  C_TRACE_TIME,
  C_IP_TOS,
  C_UNIX_SOCKET,
  C_UPLOAD_FILE,
  C_UPLOAD_FLAGS,
  C_URL,
  C_URL_QUERY,
  C_USE_ASCII,
  C_USER,
  C_USER_AGENT,
  C_VARIABLE,
  C_VERBOSE,
  C_VERSION,
  C_VLAN_PRIORITY,
  C_WDEBUG,
  C_WRITE_OUT,
  C_XATTR
} cmdline_t;

#define ARG_NONE 0 /* stand-alone but not a boolean */
#define ARG_BOOL 1 /* accepts a --no-[name] prefix */
#define ARG_STRG 2 /* requires an argument */
#define ARG_FILE 3 /* requires an argument, usually a filename */

#define ARG_TYPEMASK 0x03
#define ARGTYPE(x) ((x) & ARG_TYPEMASK)

#define ARG_DEPR 0x10 /* deprecated option */
#define ARG_CLEAR 0x20 /* clear cmdline argument */
#define ARG_TLS 0x40 /* requires TLS support */
#define ARG_NO 0x80 /* set if the option is documented as --no-* */

struct LongShort {
  const char *lname;  /* long name option */
  unsigned char desc; /* type, see ARG_* */
  char letter;  /* short name option or ' ' */
  unsigned short cmd;
};

typedef enum {
  PARAM_OK = 0,
  PARAM_OPTION_AMBIGUOUS,
  PARAM_OPTION_UNKNOWN,
  PARAM_REQUIRES_PARAMETER,
  PARAM_BAD_USE,
  PARAM_HELP_REQUESTED,
  PARAM_MANUAL_REQUESTED,
  PARAM_VERSION_INFO_REQUESTED,
  PARAM_ENGINES_REQUESTED,
  PARAM_CA_EMBED_REQUESTED,
  PARAM_GOT_EXTRA_PARAMETER,
  PARAM_BAD_NUMERIC,
  PARAM_NEGATIVE_NUMERIC,
  PARAM_LIBCURL_DOESNT_SUPPORT,
  PARAM_LIBCURL_UNSUPPORTED_PROTOCOL,
  PARAM_NO_MEM,
  PARAM_NEXT_OPERATION,
  PARAM_NO_PREFIX,
  PARAM_NUMBER_TOO_LARGE,
  PARAM_CONTDISP_RESUME_FROM, /* --continue-at and --remote-header-name */
  PARAM_READ_ERROR,
  PARAM_EXPAND_ERROR, /* --expand problem */
  PARAM_BLANK_STRING,
  PARAM_VAR_SYNTAX, /* --variable syntax error */
  PARAM_LAST
} ParameterError;

struct GlobalConfig;
struct OperationConfig;

const struct LongShort *findlongopt(const char *opt);
const struct LongShort *findshortopt(char letter);

ParameterError getparameter(const char *flag, const char *nextarg,
                            bool *usedarg,
                            struct OperationConfig *config);

#ifdef UNITTESTS
void parse_cert_parameter(const char *cert_parameter,
                          char **certname,
                          char **passphrase);
#endif

ParameterError parse_args(struct GlobalConfig *global, int argc,
                          argv_item_t argv[]);

#if defined(UNICODE) && defined(_WIN32) && !defined(UNDER_CE)

#define convert_UTF8_to_tchar(ptr) curlx_convert_UTF8_to_wchar((ptr))
#define convert_tchar_to_UTF8(ptr) curlx_convert_wchar_to_UTF8((ptr))
#define unicodefree(ptr) curlx_unicodefree(ptr)

#else

#define convert_UTF8_to_tchar(ptr) (const char *)(ptr)
#define convert_tchar_to_UTF8(ptr) (const char *)(ptr)
#define unicodefree(ptr) do {} while(0)

#endif

#endif /* HEADER_CURL_TOOL_GETPARAM_H */
