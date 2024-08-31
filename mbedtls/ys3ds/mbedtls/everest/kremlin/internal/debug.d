/* Copyright (c) INRIA and Microsoft Corporation. All rights reserved.
   Licensed under the Apache 2.0 License. */

extern (C):

/******************************************************************************/
/* Debugging helpers - intended only for KreMLin developers                   */
/******************************************************************************/

/* In support of "-wasm -d force-c": we might need this function to be
 * forward-declared, because the dependency on WasmSupport appears very late,
 * after SimplifyWasm, and sadly, after the topological order has been done. */
void WasmSupport_check_buffer_size (uint s);

/* A series of GCC atrocities to trace function calls (kremlin's [-d c-calls]
 * option). Useful when trying to debug, say, Wasm, to compare traces. */
/* clang-format off */

/* clang-format on */

