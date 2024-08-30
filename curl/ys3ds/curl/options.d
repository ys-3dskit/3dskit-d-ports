module ys3ds.curl.options;

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

enum curl_easytype
{
    CURLOT_LONG = 0, /* long (a range of values) */
    CURLOT_VALUES = 1, /*      (a defined set or bitmask) */
    CURLOT_OFF_T = 2, /* curl_off_t (a range of values) */
    CURLOT_OBJECT = 3, /* pointer (void *) */
    CURLOT_STRING = 4, /*         (char * to null-terminated buffer) */
    CURLOT_SLIST = 5, /*         (struct curl_slist *) */
    CURLOT_CBPTR = 6, /*         (void * passed as-is to a callback) */
    CURLOT_BLOB = 7, /* blob (struct curl_blob *) */
    CURLOT_FUNCTION = 8 /* function pointer */
}

/* Flag bits */

/* "alias" means it is provided for old programs to remain functional,
   we prefer another name */
enum CURLOT_FLAG_ALIAS = 1 << 0;

/* The CURLOPTTYPE_* id ranges can still be used to figure out what type/size
   to use for curl_easy_setopt() for the given id */
struct curl_easyoption
{
    const(char)* name;
    CURLoption id;
    curl_easytype type;
    uint flags;
}

const(curl_easyoption)* curl_easy_option_by_name (const(char)* name);

const(curl_easyoption)* curl_easy_option_by_id (CURLoption id);

const(curl_easyoption)* curl_easy_option_next (const(curl_easyoption)* prev);

/* end of extern "C" */

/* CURLINC_OPTIONS_H */
