module ys3ds.curl.websockets;

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

struct curl_ws_frame
{
    int age; /* zero */
    int flags; /* See the CURLWS_* defines */
    curl_off_t offset; /* the offset of this data into the frame */
    curl_off_t bytesleft; /* number of pending bytes left of the payload */
    size_t len; /* size of the current data chunk */
}

/* flag bits */
enum CURLWS_TEXT = 1 << 0;
enum CURLWS_BINARY = 1 << 1;
enum CURLWS_CONT = 1 << 2;
enum CURLWS_CLOSE = 1 << 3;
enum CURLWS_PING = 1 << 4;
enum CURLWS_OFFSET = 1 << 5;

/*
 * NAME curl_ws_recv()
 *
 * DESCRIPTION
 *
 * Receives data from the websocket connection. Use after successful
 * curl_easy_perform() with CURLOPT_CONNECT_ONLY option.
 */
CURLcode curl_ws_recv (
    CURL* curl,
    void* buffer,
    size_t buflen,
    size_t* recv,
    const(curl_ws_frame*)* metap);

/* flags for curl_ws_send() */
enum CURLWS_PONG = 1 << 6;

/*
 * NAME curl_ws_send()
 *
 * DESCRIPTION
 *
 * Sends data over the websocket connection. Use after successful
 * curl_easy_perform() with CURLOPT_CONNECT_ONLY option.
 */
CURLcode curl_ws_send (
    CURL* curl,
    const(void)* buffer,
    size_t buflen,
    size_t* sent,
    curl_off_t fragsize,
    uint flags);

/* bits for the CURLOPT_WS_OPTIONS bitmask: */
enum CURLWS_RAW_MODE = 1 << 0;

const(curl_ws_frame)* curl_ws_meta (CURL* curl);

/* CURLINC_WEBSOCKETS_H */
