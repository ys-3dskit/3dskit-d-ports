module ys3ds.zlib.minizip.mztools;

/*
  Additional tools for Minizip
  Code: Xavier Roche '2004
  License: Same as ZLIB (www.gzip.org)
*/

import ys3ds.zlib.zconf;

extern (C) @nogc nothrow:

/* Repair a ZIP file (missing central directory)
   file: file to recover
   fileOut: output file after recovery
   fileOutTmp: temporary file name used for recovery
*/
int unzRepair (
    const(char)* file,
    const(char)* fileOut,
    const(char)* fileOutTmp,
    uLong* nRecovered,
    uLong* bytesRecovered);

