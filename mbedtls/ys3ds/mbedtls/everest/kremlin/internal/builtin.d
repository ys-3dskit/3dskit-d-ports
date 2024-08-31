/* Copyright (c) INRIA and Microsoft Corporation. All rights reserved.
   Licensed under the Apache 2.0 License. */

extern (C) @nogc nothrow:

/* For alloca, when using KreMLin's -falloca */

/* If some globals need to be initialized before the main, then kremlin will
 * generate and try to link last a function with this type: */
void kremlinit_globals ();

