/* Copyright (c) INRIA and Microsoft Corporation. All rights reserved.
   Licensed under the Apache 2.0 License. */

import core.stdc.config;
import core.stdc.stdio;

extern (C):

/* Types which are either abstract, meaning that have to be implemented in C, or
 * which are models, meaning that they are swapped out at compile-time for
 * hand-written C types (in which case they're marked as noextract). */

alias FStar_UInt64_t = c_ulong;
alias FStar_UInt64_t_ = c_ulong;
alias FStar_Int64_t = c_long;
alias FStar_Int64_t_ = c_long;
alias FStar_UInt32_t = uint;
alias FStar_UInt32_t_ = uint;
alias FStar_Int32_t = int;
alias FStar_Int32_t_ = int;
alias FStar_UInt16_t = ushort;
alias FStar_UInt16_t_ = ushort;
alias FStar_Int16_t = short;
alias FStar_Int16_t_ = short;
alias FStar_UInt8_t = ubyte;
alias FStar_UInt8_t_ = ubyte;
alias FStar_Int8_t = byte;
alias FStar_Int8_t_ = byte;

/* Only useful when building Kremlib, because it's in the dependency graph of
 * FStar.Int.Cast. */
alias FStar_UInt63_t = c_ulong;
alias FStar_UInt63_t_ = c_ulong;
alias FStar_Int63_t = c_long;
alias FStar_Int63_t_ = c_long;

alias FStar_Float_float = double;
alias FStar_Char_char = uint;
alias FStar_IO_fd_read = /* _IO_ */FILE*;
alias FStar_IO_fd_write = /* _IO_ */FILE*;

alias FStar_Dyn_dyn = void*;

alias C_String_t = const(char)*;
alias C_String_t_ = const(char)*;

alias exit_code = int;
alias channel = /* _IO_ */FILE*;

alias TestLib_cycles = ulong;

alias FStar_Date_dateTime = c_ulong;
alias FStar_Date_timeSpan = c_ulong;

/* The uint128 type is a special case since we offer several implementations of
 * it, depending on the compiler and whether the user wants the verified
 * implementation or not. */

struct FStar_UInt128_uint128 { ulong low; ulong high; }

alias FStar_UInt128_t = FStar_UInt128_uint128;
alias FStar_UInt128_t_ = FStar_UInt128_uint128;
alias uint128_t = FStar_UInt128_uint128;

