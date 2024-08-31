/* Copyright (c) INRIA and Microsoft Corporation. All rights reserved.
   Licensed under the Apache 2.0 License. */

extern (C):

/******************************************************************************/
/* Implementing C.fst (part 2: endian-ness macros)                            */
/******************************************************************************/

/* ... for Linux */

/* ... for OSX */

/* ... for Solaris */

/* ... for the BSDs */

/* ... for Windows (MSVC)... not targeting XBOX 360! */

/* ... for Windows (GCC-like, e.g. mingw or clang) */

/* ... generic big-endian fallback code */

/* byte swapping code inspired by:
 * https://github.com/rweather/arduinolibs/blob/master/libraries/Crypto/utility/EndianUtil.h
 * */

/* ... generic little-endian fallback code */

/* ... couldn't determine endian-ness of the target platform */

/* defined(__linux__) || ... */

/* Loads and stores. These avoid undefined behavior due to unaligned memory
 * accesses, via memcpy. */

ushort load16 (ubyte* b);

uint load32 (ubyte* b);

ulong load64 (ubyte* b);

void store16 (ubyte* b, ushort i);

void store32 (ubyte* b, uint i);

void store64 (ubyte* b, ulong i);

extern (D) auto load16_le(T)(auto ref T b)
{
    return le16toh(load16(b));
}

extern (D) auto store16_le(T0, T1)(auto ref T0 b, auto ref T1 i)
{
    return store16(b, htole16(i));
}

extern (D) auto load16_be(T)(auto ref T b)
{
    return be16toh(load16(b));
}

extern (D) auto store16_be(T0, T1)(auto ref T0 b, auto ref T1 i)
{
    return store16(b, htobe16(i));
}

extern (D) auto load32_le(T)(auto ref T b)
{
    return le32toh(load32(b));
}

extern (D) auto store32_le(T0, T1)(auto ref T0 b, auto ref T1 i)
{
    return store32(b, htole32(i));
}

extern (D) auto load32_be(T)(auto ref T b)
{
    return be32toh(load32(b));
}

extern (D) auto store32_be(T0, T1)(auto ref T0 b, auto ref T1 i)
{
    return store32(b, htobe32(i));
}

extern (D) auto load64_le(T)(auto ref T b)
{
    return le64toh(load64(b));
}

extern (D) auto store64_le(T0, T1)(auto ref T0 b, auto ref T1 i)
{
    return store64(b, htole64(i));
}

extern (D) auto load64_be(T)(auto ref T b)
{
    return be64toh(load64(b));
}

extern (D) auto store64_be(T0, T1)(auto ref T0 b, auto ref T1 i)
{
    return store64(b, htobe64(i));
}
