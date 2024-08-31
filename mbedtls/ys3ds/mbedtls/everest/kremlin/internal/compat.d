/* Copyright (c) INRIA and Microsoft Corporation. All rights reserved.
   Licensed under the Apache 2.0 License. */

extern (C) @nogc nothrow:

/* A series of macros that define C implementations of types that are not Low*,
 * to facilitate porting programs to Low*. */

alias Prims_string = const(char)*;

struct FStar_Bytes_bytes
{
    uint length;
    const(char)* data;
}

alias Prims_pos = int;
alias Prims_nat = int;
alias Prims_nonzero = int;
alias Prims_int = int;
alias krml_checked_int_t = int;

