module ys3ds.curl.typecheck_gcc;

// dear curl devs: what the FUCK is this file's header source code????
// no
// nooooooope
// none of this. -- sink
/+

import core.stdc.config;
import core.stdc.stdio;

import ys3ds.curl;

extern (C):

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

/* wraps curl_easy_setopt() with typechecking */

/* To add a new kind of warning, add an
 *   if(curlcheck_sometype_option(_curl_opt))
 *     if(!curlcheck_sometype(value))
 *       _curl_easy_setopt_err_sometype();
 * block and define curlcheck_sometype_option, curlcheck_sometype and
 * _curl_easy_setopt_err_sometype below
 *
 * NOTE: We use two nested 'if' statements here instead of the && operator, in
 *       order to work around gcc bug #32061.  It affects only gcc 4.3.x/4.4.x
 *       when compiling with -Wlogical-op.
 *
 * To add an option that uses the same type as an existing option, you'll just
 * need to extend the appropriate _curl_*_option macro
 */
alias curl_easy_setopt = curl_easy_setopt;

/* wraps curl_easy_getinfo() with typechecking */
alias curl_easy_getinfo = curl_easy_getinfo;

/*
 * For now, just make sure that the functions are called with three arguments
 */
alias curl_share_setopt = curl_share_setopt;
alias curl_multi_setopt = curl_multi_setopt;

/* the actual warnings, triggered by calling the _curl_easy_setopt_err*
 * functions */

/* To define a new warning, use _CURL_WARNING(identifier, "message") */

void _curl_easy_setopt_err_long ();
void _curl_easy_setopt_err_curl_off_t ();
void _curl_easy_setopt_err_string ();
void _curl_easy_setopt_err_write_callback ();
void _curl_easy_setopt_err_resolver_start_callback ();
void _curl_easy_setopt_err_read_cb ();
void _curl_easy_setopt_err_ioctl_cb ();
void _curl_easy_setopt_err_sockopt_cb ();
void _curl_easy_setopt_err_opensocket_cb ();
void _curl_easy_setopt_err_progress_cb ();
void _curl_easy_setopt_err_debug_cb ();
void _curl_easy_setopt_err_ssl_ctx_cb ();
void _curl_easy_setopt_err_conv_cb ();
void _curl_easy_setopt_err_seek_cb ();
void _curl_easy_setopt_err_cb_data ();
void _curl_easy_setopt_err_error_buffer ();
void _curl_easy_setopt_err_FILE ();
void _curl_easy_setopt_err_postfields ();
void _curl_easy_setopt_err_curl_httpost ();
void _curl_easy_setopt_err_curl_mimepost ();
void _curl_easy_setopt_err_curl_slist ();
void _curl_easy_setopt_err_CURLSH ();

void _curl_easy_getinfo_err_string ();
void _curl_easy_getinfo_err_long ();
void _curl_easy_getinfo_err_double ();
void _curl_easy_getinfo_err_curl_slist ();
void _curl_easy_getinfo_err_curl_tlssesssioninfo ();
void _curl_easy_getinfo_err_curl_certinfo ();
void _curl_easy_getinfo_err_curl_socket ();
void _curl_easy_getinfo_err_curl_off_t ();

/* groups of curl_easy_setops options that take the same type of argument */

/* To add a new option to one of the groups, just add
 *   (option) == CURLOPT_SOMETHING
 * to the or-expression. If the option takes a long or curl_off_t, you don't
 * have to do anything
 */

/* evaluates to true if option takes a long argument */
extern (D) auto curlcheck_long_option(T)(auto ref T option)
{
    return 0 < option && option < CURLOPTTYPE_OBJECTPOINT;
}

extern (D) auto curlcheck_off_t_option(T)(auto ref T option)
{
    return (option > CURLOPTTYPE_OFF_T) && (option < CURLOPTTYPE_BLOB);
}

/* evaluates to true if option takes a char* argument */
extern (D) auto curlcheck_string_option(T)(auto ref T option)
{
    return option == .CURLOPT_ABSTRACT_UNIX_SOCKET || option == .CURLOPT_ACCEPT_ENCODING || option == .CURLOPT_ALTSVC || option == .CURLOPT_CAINFO || option == .CURLOPT_CAPATH || option == .CURLOPT_COOKIE || option == .CURLOPT_COOKIEFILE || option == .CURLOPT_COOKIEJAR || option == .CURLOPT_COOKIELIST || option == .CURLOPT_CRLFILE || option == .CURLOPT_CUSTOMREQUEST || option == .CURLOPT_DEFAULT_PROTOCOL || option == .CURLOPT_DNS_INTERFACE || option == .CURLOPT_DNS_LOCAL_IP4 || option == .CURLOPT_DNS_LOCAL_IP6 || option == .CURLOPT_DNS_SERVERS || option == .CURLOPT_DOH_URL || option == .CURLOPT_EGDSOCKET || option == .CURLOPT_FTP_ACCOUNT || option == .CURLOPT_FTP_ALTERNATIVE_TO_USER || option == .CURLOPT_FTPPORT || option == .CURLOPT_HSTS || option == .CURLOPT_HAPROXY_CLIENT_IP || option == .CURLOPT_INTERFACE || option == .CURLOPT_ISSUERCERT || option == .CURLOPT_KEYPASSWD || option == .CURLOPT_KRBLEVEL || option == .CURLOPT_LOGIN_OPTIONS || option == .CURLOPT_MAIL_AUTH || option == .CURLOPT_MAIL_FROM || option == .CURLOPT_NETRC_FILE || option == .CURLOPT_NOPROXY || option == .CURLOPT_PASSWORD || option == .CURLOPT_PINNEDPUBLICKEY || option == .CURLOPT_PRE_PROXY || option == .CURLOPT_PROTOCOLS_STR || option == .CURLOPT_PROXY || option == .CURLOPT_PROXY_CAINFO || option == .CURLOPT_PROXY_CAPATH || option == .CURLOPT_PROXY_CRLFILE || option == .CURLOPT_PROXY_ISSUERCERT || option == .CURLOPT_PROXY_KEYPASSWD || option == .CURLOPT_PROXY_PINNEDPUBLICKEY || option == .CURLOPT_PROXY_SERVICE_NAME || option == .CURLOPT_PROXY_SSL_CIPHER_LIST || option == .CURLOPT_PROXY_SSLCERT || option == .CURLOPT_PROXY_SSLCERTTYPE || option == .CURLOPT_PROXY_SSLKEY || option == .CURLOPT_PROXY_SSLKEYTYPE || option == .CURLOPT_PROXY_TLS13_CIPHERS || option == .CURLOPT_PROXY_TLSAUTH_PASSWORD || option == .CURLOPT_PROXY_TLSAUTH_TYPE || option == .CURLOPT_PROXY_TLSAUTH_USERNAME || option == .CURLOPT_PROXYPASSWORD || option == .CURLOPT_PROXYUSERNAME || option == .CURLOPT_PROXYUSERPWD || option == .CURLOPT_RANDOM_FILE || option == .CURLOPT_RANGE || option == .CURLOPT_REDIR_PROTOCOLS_STR || option == .CURLOPT_REFERER || option == .CURLOPT_REQUEST_TARGET || option == .CURLOPT_RTSP_SESSION_ID || option == .CURLOPT_RTSP_STREAM_URI || option == .CURLOPT_RTSP_TRANSPORT || option == .CURLOPT_SASL_AUTHZID || option == .CURLOPT_SERVICE_NAME || option == .CURLOPT_SOCKS5_GSSAPI_SERVICE || option == .CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 || option == .CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 || option == .CURLOPT_SSH_KNOWNHOSTS || option == .CURLOPT_SSH_PRIVATE_KEYFILE || option == .CURLOPT_SSH_PUBLIC_KEYFILE || option == .CURLOPT_SSLCERT || option == .CURLOPT_SSLCERTTYPE || option == .CURLOPT_SSLENGINE || option == .CURLOPT_SSLKEY || option == .CURLOPT_SSLKEYTYPE || option == .CURLOPT_SSL_CIPHER_LIST || option == .CURLOPT_TLS13_CIPHERS || option == .CURLOPT_TLSAUTH_PASSWORD || option == .CURLOPT_TLSAUTH_TYPE || option == .CURLOPT_TLSAUTH_USERNAME || option == .CURLOPT_UNIX_SOCKET_PATH || option == .CURLOPT_URL || option == .CURLOPT_USERAGENT || option == .CURLOPT_USERNAME || option == .CURLOPT_AWS_SIGV4 || option == .CURLOPT_USERPWD || option == .CURLOPT_XOAUTH2_BEARER || option == .CURLOPT_SSL_EC_CURVES || 0;
}

/* evaluates to true if option takes a curl_write_callback argument */
extern (D) auto curlcheck_write_cb_option(T)(auto ref T option)
{
    return option == .CURLOPT_HEADERFUNCTION || option == .CURLOPT_WRITEFUNCTION;
}

/* evaluates to true if option takes a curl_conv_callback argument */
extern (D) auto curlcheck_conv_cb_option(T)(auto ref T option)
{
    return option == .CURLOPT_CONV_TO_NETWORK_FUNCTION || option == .CURLOPT_CONV_FROM_NETWORK_FUNCTION || option == .CURLOPT_CONV_FROM_UTF8_FUNCTION;
}

/* evaluates to true if option takes a data argument to pass to a callback */
extern (D) auto curlcheck_cb_data_option(T)(auto ref T option)
{
    return option == .CURLOPT_CHUNK_DATA || option == .CURLOPT_CLOSESOCKETDATA || option == .CURLOPT_DEBUGDATA || option == .CURLOPT_FNMATCH_DATA || option == .CURLOPT_HEADERDATA || option == .CURLOPT_HSTSREADDATA || option == .CURLOPT_HSTSWRITEDATA || option == .CURLOPT_INTERLEAVEDATA || option == .CURLOPT_IOCTLDATA || option == .CURLOPT_OPENSOCKETDATA || option == .CURLOPT_PREREQDATA || option == CURLOPT_PROGRESSDATA || option == .CURLOPT_READDATA || option == .CURLOPT_SEEKDATA || option == .CURLOPT_SOCKOPTDATA || option == .CURLOPT_SSH_KEYDATA || option == .CURLOPT_SSL_CTX_DATA || option == .CURLOPT_WRITEDATA || option == .CURLOPT_RESOLVER_START_DATA || option == .CURLOPT_TRAILERDATA || option == .CURLOPT_SSH_HOSTKEYDATA || 0;
}

/* evaluates to true if option takes a POST data argument (void* or char*) */
extern (D) auto curlcheck_postfields_option(T)(auto ref T option)
{
    return option == .CURLOPT_POSTFIELDS || option == .CURLOPT_COPYPOSTFIELDS || 0;
}

/* evaluates to true if option takes a struct curl_slist * argument */
extern (D) auto curlcheck_slist_option(T)(auto ref T option)
{
    return option == .CURLOPT_HTTP200ALIASES || option == .CURLOPT_HTTPHEADER || option == .CURLOPT_MAIL_RCPT || option == .CURLOPT_POSTQUOTE || option == .CURLOPT_PREQUOTE || option == .CURLOPT_PROXYHEADER || option == .CURLOPT_QUOTE || option == .CURLOPT_RESOLVE || option == .CURLOPT_TELNETOPTIONS || option == .CURLOPT_CONNECT_TO || 0;
}

/* groups of curl_easy_getinfo infos that take the same type of argument */

/* evaluates to true if info expects a pointer to char * argument */
extern (D) auto curlcheck_string_info(T)(auto ref T info)
{
    return CURLINFO_STRING < info && info < CURLINFO_LONG && info != .CURLINFO_PRIVATE;
}

/* evaluates to true if info expects a pointer to long argument */
extern (D) auto curlcheck_long_info(T)(auto ref T info)
{
    return CURLINFO_LONG < info && info < CURLINFO_DOUBLE;
}

/* evaluates to true if info expects a pointer to double argument */
extern (D) auto curlcheck_double_info(T)(auto ref T info)
{
    return CURLINFO_DOUBLE < info && info < CURLINFO_SLIST;
}

/* true if info expects a pointer to struct curl_slist * argument */
extern (D) auto curlcheck_slist_info(T)(auto ref T info)
{
    return (info == .CURLINFO_SSL_ENGINES) || (info == .CURLINFO_COOKIELIST);
}

/* true if info expects a pointer to struct curl_tlssessioninfo * argument */
extern (D) auto curlcheck_tlssessioninfo_info(T)(auto ref T info)
{
    return (info == .CURLINFO_TLS_SSL_PTR) || (info == .CURLINFO_TLS_SESSION);
}

/* true if info expects a pointer to struct curl_certinfo * argument */
extern (D) auto curlcheck_certinfo_info(T)(auto ref T info)
{
    return info == .CURLINFO_CERTINFO;
}

/* true if info expects a pointer to struct curl_socket_t argument */
extern (D) auto curlcheck_socket_info(T)(auto ref T info)
{
    return CURLINFO_SOCKET < info && info < CURLINFO_OFF_T;
}

/* true if info expects a pointer to curl_off_t argument */
extern (D) auto curlcheck_off_t_info(T)(auto ref T info)
{
    return CURLINFO_OFF_T < info;
}

/* typecheck helpers -- check whether given expression has requested type */

/* For pointers, you can use the curlcheck_ptr/curlcheck_arr macros,
 * otherwise define a new macro. Search for __builtin_types_compatible_p
 * in the GCC manual.
 * NOTE: these macros MUST NOT EVALUATE their arguments! The argument is
 * the actual expression passed to the curl_easy_setopt macro. This
 * means that you can only apply the sizeof and __typeof__ operators, no
 * == or whatsoever.
 */

/* XXX: should evaluate to true if expr is a pointer */
extern (D) size_t curlcheck_any_ptr(T)(auto ref T expr)
{
    return expr.sizeof == void*.sizeof;
}

/* evaluates to true if expr is NULL */
/* XXX: must not evaluate expr, so this check is not accurate */

/* evaluates to true if expr is type*, const type* or NULL */

/* evaluates to true if expr is one of type[], type*, NULL or const type* */

/* evaluates to true if expr is a string */
extern (D) auto curlcheck_string(T)(auto ref T expr)
{
    return curlcheck_arr(expr, char) || curlcheck_arr(expr, byte) || curlcheck_arr(expr, ubyte);
}

/* evaluates to true if expr is a long (no matter the signedness)
 * XXX: for now, int is also accepted (and therefore short and char, which
 * are promoted to int when passed to a variadic function) */

/* evaluates to true if expr is of type curl_off_t */

/* evaluates to true if expr is abuffer suitable for CURLOPT_ERRORBUFFER */
/* XXX: also check size of an char[] array? */

/* evaluates to true if expr is of type (const) void* or (const) FILE* */

/* be less strict */
alias curlcheck_cb_data = curlcheck_any_ptr;

/* evaluates to true if expr is of type FILE* */

/* evaluates to true if expr can be passed as POST data (void* or char*) */
extern (D) auto curlcheck_postfields(T)(auto ref T expr)
{
    return curlcheck_ptr(expr, void) || curlcheck_arr(expr, char) || curlcheck_arr(expr, ubyte);
}

/* helper: __builtin_types_compatible_p distinguishes between functions and
 * function pointers, hide it */

/* evaluates to true if expr is of type curl_resolver_start_callback */
extern (D) auto curlcheck_resolver_start_callback(T)(auto ref T expr)
{
    return curlcheck_NULL(expr) || curlcheck_cb_compatible(expr, curl_resolver_start_callback);
}

/* evaluates to true if expr is of type curl_read_callback or "similar" */
alias _curl_read_callback1 = c_ulong function (char*, size_t, size_t, void*);
alias _curl_read_callback2 = c_ulong function (char*, size_t, size_t, const(void)*);
alias _curl_read_callback3 = c_ulong function (char*, size_t, size_t, FILE*);
alias _curl_read_callback4 = c_ulong function (void*, size_t, size_t, void*);
alias _curl_read_callback5 = c_ulong function (void*, size_t, size_t, const(void)*);
alias _curl_read_callback6 = c_ulong function (void*, size_t, size_t, FILE*);

/* evaluates to true if expr is of type curl_write_callback or "similar" */
alias _curl_write_callback1 = c_ulong function (const(char)*, size_t, size_t, void*);
alias _curl_write_callback2 = c_ulong function (
    const(char)*,
    size_t,
    size_t,
    const(void)*);
alias _curl_write_callback3 = c_ulong function (const(char)*, size_t, size_t, FILE*);
alias _curl_write_callback4 = c_ulong function (const(void)*, size_t, size_t, void*);
alias _curl_write_callback5 = c_ulong function (
    const(void)*,
    size_t,
    size_t,
    const(void)*);
alias _curl_write_callback6 = c_ulong function (const(void)*, size_t, size_t, FILE*);

/* evaluates to true if expr is of type curl_ioctl_callback or "similar" */
extern (D) auto curlcheck_ioctl_cb(T)(auto ref T expr)
{
    return curlcheck_NULL(expr) || curlcheck_cb_compatible(expr, curl_ioctl_callback) || curlcheck_cb_compatible(expr, _curl_ioctl_callback1) || curlcheck_cb_compatible(expr, _curl_ioctl_callback2) || curlcheck_cb_compatible(expr, _curl_ioctl_callback3) || curlcheck_cb_compatible(expr, _curl_ioctl_callback4);
}

alias _curl_ioctl_callback1 = _Anonymous_0 function (CURL*, int, void*);
alias _curl_ioctl_callback2 = _Anonymous_0 function (CURL*, int, const(void)*);
alias _curl_ioctl_callback3 = _Anonymous_0 function (CURL*, curliocmd, void*);
alias _curl_ioctl_callback4 = _Anonymous_0 function (CURL*, curliocmd, const(void)*);

/* evaluates to true if expr is of type curl_sockopt_callback or "similar" */
extern (D) auto curlcheck_sockopt_cb(T)(auto ref T expr)
{
    return curlcheck_NULL(expr) || curlcheck_cb_compatible(expr, curl_sockopt_callback) || curlcheck_cb_compatible(expr, _curl_sockopt_callback1) || curlcheck_cb_compatible(expr, _curl_sockopt_callback2);
}

alias _curl_sockopt_callback1 = int function (void*, curl_socket_t, curlsocktype);
alias _curl_sockopt_callback2 = int function (
    const(void)*,
    curl_socket_t,
    curlsocktype);

/* evaluates to true if expr is of type curl_opensocket_callback or
   "similar" */
extern (D) auto curlcheck_opensocket_cb(T)(auto ref T expr)
{
    return curlcheck_NULL(expr) || curlcheck_cb_compatible(expr, curl_opensocket_callback) || curlcheck_cb_compatible(expr, _curl_opensocket_callback1) || curlcheck_cb_compatible(expr, _curl_opensocket_callback2) || curlcheck_cb_compatible(expr, _curl_opensocket_callback3) || curlcheck_cb_compatible(expr, _curl_opensocket_callback4);
}

alias _curl_opensocket_callback1 = int function (
    void*,
    curlsocktype,
    curl_sockaddr*);
alias _curl_opensocket_callback2 = int function (
    void*,
    curlsocktype,
    const(curl_sockaddr)*);
alias _curl_opensocket_callback3 = int function (
    const(void)*,
    curlsocktype,
    curl_sockaddr*);
alias _curl_opensocket_callback4 = int function (
    const(void)*,
    curlsocktype,
    const(curl_sockaddr)*);

/* evaluates to true if expr is of type curl_progress_callback or "similar" */
extern (D) auto curlcheck_progress_cb(T)(auto ref T expr)
{
    return curlcheck_NULL(expr) || curlcheck_cb_compatible(expr, curl_progress_callback) || curlcheck_cb_compatible(expr, _curl_progress_callback1) || curlcheck_cb_compatible(expr, _curl_progress_callback2);
}

alias _curl_progress_callback1 = int function (
    void*,
    double,
    double,
    double,
    double);
alias _curl_progress_callback2 = int function (
    const(void)*,
    double,
    double,
    double,
    double);

/* evaluates to true if expr is of type curl_debug_callback or "similar" */
extern (D) auto curlcheck_debug_cb(T)(auto ref T expr)
{
    return curlcheck_NULL(expr) || curlcheck_cb_compatible(expr, curl_debug_callback) || curlcheck_cb_compatible(expr, _curl_debug_callback1) || curlcheck_cb_compatible(expr, _curl_debug_callback2) || curlcheck_cb_compatible(expr, _curl_debug_callback3) || curlcheck_cb_compatible(expr, _curl_debug_callback4) || curlcheck_cb_compatible(expr, _curl_debug_callback5) || curlcheck_cb_compatible(expr, _curl_debug_callback6) || curlcheck_cb_compatible(expr, _curl_debug_callback7) || curlcheck_cb_compatible(expr, _curl_debug_callback8);
}

alias _curl_debug_callback1 = int function (
    CURL*,
    curl_infotype,
    char*,
    size_t,
    void*);
alias _curl_debug_callback2 = int function (
    CURL*,
    curl_infotype,
    char*,
    size_t,
    const(void)*);
alias _curl_debug_callback3 = int function (
    CURL*,
    curl_infotype,
    const(char)*,
    size_t,
    void*);
alias _curl_debug_callback4 = int function (
    CURL*,
    curl_infotype,
    const(char)*,
    size_t,
    const(void)*);
alias _curl_debug_callback5 = int function (
    CURL*,
    curl_infotype,
    ubyte*,
    size_t,
    void*);
alias _curl_debug_callback6 = int function (
    CURL*,
    curl_infotype,
    ubyte*,
    size_t,
    const(void)*);
alias _curl_debug_callback7 = int function (
    CURL*,
    curl_infotype,
    const(ubyte)*,
    size_t,
    void*);
alias _curl_debug_callback8 = int function (
    CURL*,
    curl_infotype,
    const(ubyte)*,
    size_t,
    const(void)*);

/* evaluates to true if expr is of type curl_ssl_ctx_callback or "similar" */
/* this is getting even messier... */
extern (D) auto curlcheck_ssl_ctx_cb(T)(auto ref T expr)
{
    return curlcheck_NULL(expr) || curlcheck_cb_compatible(expr, curl_ssl_ctx_callback) || curlcheck_cb_compatible(expr, _curl_ssl_ctx_callback1) || curlcheck_cb_compatible(expr, _curl_ssl_ctx_callback2) || curlcheck_cb_compatible(expr, _curl_ssl_ctx_callback3) || curlcheck_cb_compatible(expr, _curl_ssl_ctx_callback4) || curlcheck_cb_compatible(expr, _curl_ssl_ctx_callback5) || curlcheck_cb_compatible(expr, _curl_ssl_ctx_callback6) || curlcheck_cb_compatible(expr, _curl_ssl_ctx_callback7) || curlcheck_cb_compatible(expr, _curl_ssl_ctx_callback8);
}

alias _curl_ssl_ctx_callback1 = _Anonymous_1 function (CURL*, void*, void*);
alias _curl_ssl_ctx_callback2 = _Anonymous_1 function (CURL*, void*, const(void)*);
alias _curl_ssl_ctx_callback3 = _Anonymous_1 function (CURL*, const(void)*, void*);
alias _curl_ssl_ctx_callback4 = _Anonymous_1 function (
    CURL*,
    const(void)*,
    const(void)*);

/* hack: if we included OpenSSL's ssl.h, we know about SSL_CTX
 * this will of course break if we're included before OpenSSL headers...
 */

alias _curl_ssl_ctx_callback5 = _Anonymous_1 function ();
alias _curl_ssl_ctx_callback6 = _Anonymous_1 function ();
alias _curl_ssl_ctx_callback7 = _Anonymous_1 function ();
alias _curl_ssl_ctx_callback8 = _Anonymous_1 function ();

/* evaluates to true if expr is of type curl_conv_callback or "similar" */
extern (D) auto curlcheck_conv_cb(T)(auto ref T expr)
{
    return curlcheck_NULL(expr) || curlcheck_cb_compatible(expr, curl_conv_callback) || curlcheck_cb_compatible(expr, _curl_conv_callback1) || curlcheck_cb_compatible(expr, _curl_conv_callback2) || curlcheck_cb_compatible(expr, _curl_conv_callback3) || curlcheck_cb_compatible(expr, _curl_conv_callback4);
}

alias _curl_conv_callback1 = _Anonymous_1 function (char*, size_t length);
alias _curl_conv_callback2 = _Anonymous_1 function (const(char)*, size_t length);
alias _curl_conv_callback3 = _Anonymous_1 function (void*, size_t length);
alias _curl_conv_callback4 = _Anonymous_1 function (const(void)*, size_t length);

/* evaluates to true if expr is of type curl_seek_callback or "similar" */
extern (D) auto curlcheck_seek_cb(T)(auto ref T expr)
{
    return curlcheck_NULL(expr) || curlcheck_cb_compatible(expr, curl_seek_callback) || curlcheck_cb_compatible(expr, _curl_seek_callback1) || curlcheck_cb_compatible(expr, _curl_seek_callback2);
}

alias _curl_seek_callback1 = _Anonymous_1 function (void*, curl_off_t, int);
alias _curl_seek_callback2 = _Anonymous_1 function (const(void)*, curl_off_t, int);

/* CURLINC_TYPECHECK_GCC_H */
+/
