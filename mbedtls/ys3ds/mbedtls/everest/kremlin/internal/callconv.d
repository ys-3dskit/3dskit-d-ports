/* Copyright (c) INRIA and Microsoft Corporation. All rights reserved.
   Licensed under the Apache 2.0 License. */

extern (C) @nogc nothrow:

/******************************************************************************/
/* Some macros to ease compatibility                                          */
/******************************************************************************/

/* We want to generate __cdecl safely without worrying about it being undefined.
 * When using MSVC, these are always defined. When using MinGW, these are
 * defined too. They have no meaning for other platforms, so we define them to
 * be empty macros in other situations. */

/* Since KreMLin emits the inline keyword unconditionally, we follow the
 * guidelines at https://gcc.gnu.org/onlinedocs/gcc/Inline.html and make this
 * __inline__ to ensure the code compiles with -std=c90 and earlier. */

/* GCC-specific attribute syntax; everyone else gets the standard C inline
 * attribute. */

