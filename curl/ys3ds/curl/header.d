module ys3ds.curl.header;

import ys3ds.curl;

extern (C) @nogc nothrow:

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

struct curl_header
{
    char* name; /* this might not use the same case */
    char* value;
    size_t amount; /* number of headers using this name  */
    size_t index; /* ... of this instance, 0 or higher */
    uint origin; /* see bits below */
    void* anchor; /* handle privately used by libcurl */
}

/* 'origin' bits */
enum CURLH_HEADER = 1 << 0; /* plain server header */
enum CURLH_TRAILER = 1 << 1; /* trailers */
enum CURLH_CONNECT = 1 << 2; /* CONNECT headers */
enum CURLH_1XX = 1 << 3; /* 1xx headers */
enum CURLH_PSEUDO = 1 << 4; /* pseudo headers */

enum CURLHcode
{
    CURLHE_OK = 0,
    CURLHE_BADINDEX = 1, /* header exists but not with this index */
    CURLHE_MISSING = 2, /* no such header exists */
    CURLHE_NOHEADERS = 3, /* no headers at all exist (yet) */
    CURLHE_NOREQUEST = 4, /* no request with this number was used */
    CURLHE_OUT_OF_MEMORY = 5, /* out of memory while processing */
    CURLHE_BAD_ARGUMENT = 6, /* a function argument was not okay */
    CURLHE_NOT_BUILT_IN = 7 /* if API was disabled in the build */
}

CURLHcode curl_easy_header (
    CURL* easy,
    const(char)* name,
    size_t index,
    uint origin,
    int request,
    curl_header** hout);

curl_header* curl_easy_nextheader (
    CURL* easy,
    uint origin,
    int request,
    curl_header* prev);

/* end of extern "C" */

/* CURLINC_HEADER_H */
