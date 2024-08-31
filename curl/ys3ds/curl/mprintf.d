module ys3ds.curl.mprintf;

//import ys3ds.curl;

import core.stdc.stdio;
import core.stdc.stdarg : va_list;

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

/* needed for FILE */
/* for CURL_EXTERN */

int curl_mprintf (const(char)* format, ...);
int curl_mfprintf (FILE* fd, const(char)* format, ...);
int curl_msprintf (char* buffer, const(char)* format, ...);
int curl_msnprintf (char* buffer, size_t maxlength, const(char)* format, ...);
int curl_mvprintf (const(char)* format, va_list args);
int curl_mvfprintf (FILE* fd, const(char)* format, va_list args);
int curl_mvsprintf (char* buffer, const(char)* format, va_list args);
int curl_mvsnprintf (
    char* buffer,
    size_t maxlength,
    const(char)* format,
    va_list args);
char* curl_maprintf (const(char)* format, ...);
char* curl_mvaprintf (const(char)* format, va_list args);

/* end of extern "C" */

/* CURLINC_MPRINTF_H */
