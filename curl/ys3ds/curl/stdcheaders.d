module ys3ds.curl.stdcheaders;

import core.stdc.config;
import core.stdc.stdio;

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

c_ulong fread (void*, size_t, size_t, FILE*);
c_ulong fwrite (const(void)*, size_t, size_t, FILE*);

int strcasecmp (const(char)*, const(char)*);
int strncasecmp (const(char)*, const(char)*, size_t);

/* CURLINC_STDCHEADERS_H */
