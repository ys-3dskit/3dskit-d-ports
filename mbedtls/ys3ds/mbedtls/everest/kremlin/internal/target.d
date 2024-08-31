/* Copyright (c) INRIA and Microsoft Corporation. All rights reserved.
   Licensed under the Apache 2.0 License. */

import core.stdc.stdio;
import core.stdc.stdlib;

extern (C):

/******************************************************************************/
/* Macros that KreMLin will generate.                                         */
/******************************************************************************/

/* For "bare" targets that do not have a C stdlib, the user might want to use
 * [-add-early-include '"mydefinitions.h"'] and override these. */

alias KRML_HOST_PRINTF = printf;

alias KRML_HOST_EXIT = exit;

alias KRML_HOST_MALLOC = malloc;

alias KRML_HOST_CALLOC = calloc;

alias KRML_HOST_FREE = free;

/* Prims_nat not yet in scope */
int krml_time ();

alias KRML_HOST_TIME = krml_time;

/* In statement position, exiting is easy. */

/* In expression position, use the comma-operator and a malloc to return an
 * expression of the right size. KreMLin passes t as the parameter to the macro.
 */

/* In FStar.Buffer.fst, the size of arrays is uint32_t, but it's a number of
 * *elements*. Do an ugly, run-time check (some of which KreMLin can eliminate).
 */

//enum _KRML_CHECK_SIZE_PRAGMA = _Pragma("GCC diagnostic ignored \"-Wtype-limits\"");

alias KRML_HOST_SNPRINTF = snprintf;

