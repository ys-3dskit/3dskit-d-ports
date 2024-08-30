module ys3ds.curl.urlapi;

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

/* the error codes for the URL API */
enum CURLUcode
{
    CURLUE_OK = 0,
    CURLUE_BAD_HANDLE = 1, /* 1 */
    CURLUE_BAD_PARTPOINTER = 2, /* 2 */
    CURLUE_MALFORMED_INPUT = 3, /* 3 */
    CURLUE_BAD_PORT_NUMBER = 4, /* 4 */
    CURLUE_UNSUPPORTED_SCHEME = 5, /* 5 */
    CURLUE_URLDECODE = 6, /* 6 */
    CURLUE_OUT_OF_MEMORY = 7, /* 7 */
    CURLUE_USER_NOT_ALLOWED = 8, /* 8 */
    CURLUE_UNKNOWN_PART = 9, /* 9 */
    CURLUE_NO_SCHEME = 10, /* 10 */
    CURLUE_NO_USER = 11, /* 11 */
    CURLUE_NO_PASSWORD = 12, /* 12 */
    CURLUE_NO_OPTIONS = 13, /* 13 */
    CURLUE_NO_HOST = 14, /* 14 */
    CURLUE_NO_PORT = 15, /* 15 */
    CURLUE_NO_QUERY = 16, /* 16 */
    CURLUE_NO_FRAGMENT = 17, /* 17 */
    CURLUE_NO_ZONEID = 18, /* 18 */
    CURLUE_BAD_FILE_URL = 19, /* 19 */
    CURLUE_BAD_FRAGMENT = 20, /* 20 */
    CURLUE_BAD_HOSTNAME = 21, /* 21 */
    CURLUE_BAD_IPV6 = 22, /* 22 */
    CURLUE_BAD_LOGIN = 23, /* 23 */
    CURLUE_BAD_PASSWORD = 24, /* 24 */
    CURLUE_BAD_PATH = 25, /* 25 */
    CURLUE_BAD_QUERY = 26, /* 26 */
    CURLUE_BAD_SCHEME = 27, /* 27 */
    CURLUE_BAD_SLASHES = 28, /* 28 */
    CURLUE_BAD_USER = 29, /* 29 */
    CURLUE_LACKS_IDN = 30, /* 30 */
    CURLUE_LAST
}

enum CURLUPart
{
    CURLUPART_URL = 0,
    CURLUPART_SCHEME = 1,
    CURLUPART_USER = 2,
    CURLUPART_PASSWORD = 3,
    CURLUPART_OPTIONS = 4,
    CURLUPART_HOST = 5,
    CURLUPART_PORT = 6,
    CURLUPART_PATH = 7,
    CURLUPART_QUERY = 8,
    CURLUPART_FRAGMENT = 9,
    CURLUPART_ZONEID = 10 /* added in 7.65.0 */
}

enum CURLU_DEFAULT_PORT = 1 << 0; /* return default port number */
enum CURLU_NO_DEFAULT_PORT = 1 << 1; /* act as if no port number was set,
   if the port number matches the
   default for the scheme */
enum CURLU_DEFAULT_SCHEME = 1 << 2; /* return default scheme if
   missing */
enum CURLU_NON_SUPPORT_SCHEME = 1 << 3; /* allow non-supported scheme */
enum CURLU_PATH_AS_IS = 1 << 4; /* leave dot sequences */
enum CURLU_DISALLOW_USER = 1 << 5; /* no user+password allowed */
enum CURLU_URLDECODE = 1 << 6; /* URL decode on get */
enum CURLU_URLENCODE = 1 << 7; /* URL encode on set */
enum CURLU_APPENDQUERY = 1 << 8; /* append a form style part */
enum CURLU_GUESS_SCHEME = 1 << 9; /* legacy curl-style guessing */
enum CURLU_NO_AUTHORITY = 1 << 10; /* Allow empty authority when the
   scheme is unknown. */
enum CURLU_ALLOW_SPACE = 1 << 11; /* Allow spaces in the URL */
enum CURLU_PUNYCODE = 1 << 12; /* get the host name in punycode */
enum CURLU_PUNY2IDN = 1 << 13; /* punycode => IDN conversion */

struct Curl_URL;
alias CURLU = Curl_URL;

/*
 * curl_url() creates a new CURLU handle and returns a pointer to it.
 * Must be freed with curl_url_cleanup().
 */
CURLU* curl_url ();

/*
 * curl_url_cleanup() frees the CURLU handle and related resources used for
 * the URL parsing. It will not free strings previously returned with the URL
 * API.
 */
void curl_url_cleanup (CURLU* handle);

/*
 * curl_url_dup() duplicates a CURLU handle and returns a new copy. The new
 * handle must also be freed with curl_url_cleanup().
 */
CURLU* curl_url_dup (const(CURLU)* in_);

/*
 * curl_url_get() extracts a specific part of the URL from a CURLU
 * handle. Returns error code. The returned pointer MUST be freed with
 * curl_free() afterwards.
 */
CURLUcode curl_url_get (
    const(CURLU)* handle,
    CURLUPart what,
    char** part,
    uint flags);

/*
 * curl_url_set() sets a specific part of the URL in a CURLU handle. Returns
 * error code. The passed in string will be copied. Passing a NULL instead of
 * a part string, clears that part.
 */
CURLUcode curl_url_set (
    CURLU* handle,
    CURLUPart what,
    const(char)* part,
    uint flags);

/*
 * curl_url_strerror() turns a CURLUcode value into the equivalent human
 * readable error string.  This is useful for printing meaningful error
 * messages.
 */
const(char)* curl_url_strerror (CURLUcode);

/* end of extern "C" */

/* CURLINC_URLAPI_H */
