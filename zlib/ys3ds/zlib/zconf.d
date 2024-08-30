module ys3ds.zlib.zconf;

/* zconf.h -- configuration of the zlib compression library
 * Copyright (C) 1995-2016 Jean-loup Gailly, Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h
 */

import core.stdc.config;
import core.sys.horizon.sys.types;

extern (C):

/*
 * Compile with -DMAXSEG_64K if the alloc function cannot allocate more
 * than 64k bytes at a time (needed on systems with 16-bit int).
 */ /* iSeries (formerly AS/400). */

/* cannot use !defined(STDC) && !defined(const) on Mac */
/* note: need a more gentle solution here */

alias z_longlong = long;

alias z_size_t = c_ulong;

/* Maximum value for memLevel in deflateInit2 */

enum MAX_MEM_LEVEL = 9;

/* Maximum value for windowBits in deflateInit2 and inflateInit2.
 * WARNING: reducing MAX_WBITS makes minigzip unable to extract .gz files
 * created by gzip. (Files created by minigzip can still be extracted by
 * gzip.)
 */

enum MAX_WBITS = 15; /* 32K LZ77 window */

/* The memory requirements for deflate are (in bytes):
            (1 << (windowBits+2)) +  (1 << (memLevel+9))
 that is: 128K for windowBits=15  +  128K for memLevel = 8  (default values)
 plus a few kilobytes for small objects. For example, if you want to reduce
 the default memory requirements from 256K to 128K, compile with
     make CFLAGS="-O -DMAX_WBITS=14 -DMAX_MEM_LEVEL=7"
 Of course this will generally degrade compression (there's no free lunch).

   The memory requirements for inflate are (in bytes) 1 << windowBits
 that is, 32K for windowBits=15 (default value) plus about 7 kilobytes
 for small objects.
*/

/* Type declarations */

// pretty sure this is unnecessary -- sink
/+
/* function prototypes */
extern (D) auto OF(T)(auto ref T args)
{
    return args;
}

/* function prototypes for stdarg */
extern (D) auto Z_ARG(T)(auto ref T args)
{
    return args;
}
+/

alias Byte = ubyte; /* 8 bits */

alias uInt = uint; /* 16 bits or more */
alias uLong = c_ulong; /* 32 bits or more */

/* Borland C/C++ and some old MSC versions ignore FAR inside typedef */

alias Bytef = ubyte;

alias charf = char;
alias intf = int;
alias uIntf = uint;
alias uLongf = c_ulong;

alias voidpc = const(void)*;
alias voidpf = void*;
alias voidp = void*;

alias Z_U4 = uint;

alias z_crc_t = uint;

alias z_off_t = off_t;

alias z_off64_t = z_off_t;

/* ZCONF_H */
