module ys3ds.zlib.minizip.unzip;

/* unzip.h -- IO for uncompress .zip files using zlib
   Version 1.1, February 14h, 2010
   part of the MiniZip project - ( http://www.winimage.com/zLibDll/minizip.html )

         Copyright (C) 1998-2010 Gilles Vollant (minizip) ( http://www.winimage.com/zLibDll/minizip.html )

         Modifications of Unzip for Zip64
         Copyright (C) 2007-2008 Even Rouault

         Modifications for Zip64 support on both zip and unzip
         Copyright (C) 2009-2010 Mathias Svensson ( http://result42.com )

         For more info read MiniZip_info.txt

         ---------------------------------------------------------------------------------

        Condition of use and distribution are the same than zlib :

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  ---------------------------------------------------------------------------------

        Changes

        See header of unzip64.c

*/

import core.stdc.stdlib;

import ys3ds.zlib;
import ys3ds.zlib.zconf;
import ys3ds.zlib.minizip.ioapi;

extern (C):

enum Z_BZIP2ED = 12;

/* like the STRICT of WIN32, we define a pointer that cannot be converted
    from (void*) without cast */

alias unzFile = void*;

enum UNZ_OK = 0;
enum UNZ_END_OF_LIST_OF_FILE = -100;
enum UNZ_ERRNO = Z_ERRNO;
enum UNZ_EOF = 0;
enum UNZ_PARAMERROR = -102;
enum UNZ_BADZIPFILE = -103;
enum UNZ_INTERNALERROR = -104;
enum UNZ_CRCERROR = -105;

/* tm_unz contain date/time info */
struct tm_unz_s
{
    int tm_sec; /* seconds after the minute - [0,59] */
    int tm_min; /* minutes after the hour - [0,59] */
    int tm_hour; /* hours since midnight - [0,23] */
    int tm_mday; /* day of the month - [1,31] */
    int tm_mon; /* months since January - [0,11] */
    int tm_year; /* years - [1980..2044] */
}

alias tm_unz = tm_unz_s;

/* unz_global_info structure contain global data about the ZIPfile
   These data comes from the end of central dir */
struct unz_global_info64_s
{
    ZPOS64_T number_entry; /* total number of entries in
      the central dir on this disk */
    uLong size_comment; /* size of the global comment of the zipfile */
}

alias unz_global_info64 = unz_global_info64_s;

struct unz_global_info_s
{
    uLong number_entry; /* total number of entries in
         the central dir on this disk */
    uLong size_comment; /* size of the global comment of the zipfile */
}

alias unz_global_info = unz_global_info_s;

/* unz_file_info contain information about a file in the zipfile */
struct unz_file_info64_s
{
    uLong version_; /* version made by                 2 bytes */
    uLong version_needed; /* version needed to extract       2 bytes */
    uLong flag; /* general purpose bit flag        2 bytes */
    uLong compression_method; /* compression method              2 bytes */
    uLong dosDate; /* last mod file date in Dos fmt   4 bytes */
    uLong crc; /* crc-32                          4 bytes */
    ZPOS64_T compressed_size; /* compressed size                 8 bytes */
    ZPOS64_T uncompressed_size; /* uncompressed size               8 bytes */
    uLong size_filename; /* filename length                 2 bytes */
    uLong size_file_extra; /* extra field length              2 bytes */
    uLong size_file_comment; /* file comment length             2 bytes */

    uLong disk_num_start; /* disk number start               2 bytes */
    uLong internal_fa; /* internal file attributes        2 bytes */
    uLong external_fa; /* external file attributes        4 bytes */

    tm_unz tmu_date;
}

alias unz_file_info64 = unz_file_info64_s;

struct unz_file_info_s
{
    uLong version_; /* version made by                 2 bytes */
    uLong version_needed; /* version needed to extract       2 bytes */
    uLong flag; /* general purpose bit flag        2 bytes */
    uLong compression_method; /* compression method              2 bytes */
    uLong dosDate; /* last mod file date in Dos fmt   4 bytes */
    uLong crc; /* crc-32                          4 bytes */
    uLong compressed_size; /* compressed size                 4 bytes */
    uLong uncompressed_size; /* uncompressed size               4 bytes */
    uLong size_filename; /* filename length                 2 bytes */
    uLong size_file_extra; /* extra field length              2 bytes */
    uLong size_file_comment; /* file comment length             2 bytes */

    uLong disk_num_start; /* disk number start               2 bytes */
    uLong internal_fa; /* internal file attributes        2 bytes */
    uLong external_fa; /* external file attributes        4 bytes */

    tm_unz tmu_date;
}

alias unz_file_info = unz_file_info_s;

int unzStringFileNameCompare (
    const(char)* fileName1,
    const(char)* fileName2,
    int iCaseSensitivity);
/*
   Compare two filenames (fileName1,fileName2).
   If iCaseSensitivity = 1, comparison is case sensitive (like strcmp)
   If iCaseSensitivity = 2, comparison is not case sensitive (like strcmpi
                                or strcasecmp)
   If iCaseSensitivity = 0, case sensitivity is default of your operating system
    (like 1 on Unix, 2 on Windows)
*/

unzFile unzOpen (const(char)* path);
unzFile unzOpen64 (const(void)* path);
/*
  Open a Zip file. path contain the full pathname (by example,
     on a Windows XP computer "c:\\zlib\\zlib113.zip" or on an Unix computer
     "zlib/zlib113.zip".
     If the zipfile cannot be opened (file don't exist or in not valid), the
       return value is NULL.
     Else, the return value is a unzFile Handle, usable with other function
       of this unzip package.
     the "64" function take a const void* pointer, because the path is just the
       value passed to the open64_file_func callback.
     Under Windows, if UNICODE is defined, using fill_fopen64_filefunc, the path
       is a pointer to a wide unicode string (LPCTSTR is LPCWSTR), so const char*
       does not describe the reality
*/

unzFile unzOpen2 (const(char)* path, zlib_filefunc_def* pzlib_filefunc_def);
/*
   Open a Zip file, like unzOpen, but provide a set of file low level API
      for read/write the zip file (see ioapi.h)
*/

unzFile unzOpen2_64 (
    const(void)* path,
    zlib_filefunc64_def* pzlib_filefunc_def);
/*
   Open a Zip file, like unz64Open, but provide a set of file low level API
      for read/write the zip file (see ioapi.h)
*/

int unzClose (unzFile file);
/*
  Close a ZipFile opened with unzOpen.
  If there is files inside the .Zip opened with unzOpenCurrentFile (see later),
    these files MUST be closed with unzCloseCurrentFile before call unzClose.
  return UNZ_OK if there is no problem. */

int unzGetGlobalInfo (unzFile file, unz_global_info* pglobal_info);

int unzGetGlobalInfo64 (unzFile file, unz_global_info64* pglobal_info);
/*
  Write info about the ZipFile in the *pglobal_info structure.
  No preparation of the structure is needed
  return UNZ_OK if there is no problem. */

int unzGetGlobalComment (unzFile file, char* szComment, uLong uSizeBuf);
/*
  Get the global comment string of the ZipFile, in the szComment buffer.
  uSizeBuf is the size of the szComment buffer.
  return the number of byte copied or an error code <0
*/

/***************************************************************************/
/* Unzip package allow you browse the directory of the zipfile */

int unzGoToFirstFile (unzFile file);
/*
  Set the current file of the zipfile to the first file.
  return UNZ_OK if there is no problem
*/

int unzGoToNextFile (unzFile file);
/*
  Set the current file of the zipfile to the next file.
  return UNZ_OK if there is no problem
  return UNZ_END_OF_LIST_OF_FILE if the actual file was the latest.
*/

int unzLocateFile (unzFile file, const(char)* szFileName, int iCaseSensitivity);
/*
  Try locate the file szFileName in the zipfile.
  For the iCaseSensitivity signification, see unzStringFileNameCompare

  return value :
  UNZ_OK if the file is found. It becomes the current file.
  UNZ_END_OF_LIST_OF_FILE if the file is not found
*/

/* ****************************************** */
/* Ryan supplied functions */
/* unz_file_info contain information about a file in the zipfile */
struct unz_file_pos_s
{
    uLong pos_in_zip_directory; /* offset in zip file directory */
    uLong num_of_file; /* # of file */
}

alias unz_file_pos = unz_file_pos_s;

int unzGetFilePos (unzFile file, unz_file_pos* file_pos);

int unzGoToFilePos (unzFile file, unz_file_pos* file_pos);

struct unz64_file_pos_s
{
    ZPOS64_T pos_in_zip_directory; /* offset in zip file directory */
    ZPOS64_T num_of_file; /* # of file */
}

alias unz64_file_pos = unz64_file_pos_s;

int unzGetFilePos64 (unzFile file, unz64_file_pos* file_pos);

int unzGoToFilePos64 (unzFile file, const(unz64_file_pos)* file_pos);

/* ****************************************** */

int unzGetCurrentFileInfo64 (
    unzFile file,
    unz_file_info64* pfile_info,
    char* szFileName,
    uLong fileNameBufferSize,
    void* extraField,
    uLong extraFieldBufferSize,
    char* szComment,
    uLong commentBufferSize);

int unzGetCurrentFileInfo (
    unzFile file,
    unz_file_info* pfile_info,
    char* szFileName,
    uLong fileNameBufferSize,
    void* extraField,
    uLong extraFieldBufferSize,
    char* szComment,
    uLong commentBufferSize);
/*
  Get Info about the current file
  if pfile_info!=NULL, the *pfile_info structure will contain some info about
        the current file
  if szFileName!=NULL, the filemane string will be copied in szFileName
            (fileNameBufferSize is the size of the buffer)
  if extraField!=NULL, the extra field information will be copied in extraField
            (extraFieldBufferSize is the size of the buffer).
            This is the Central-header version of the extra field
  if szComment!=NULL, the comment string of the file will be copied in szComment
            (commentBufferSize is the size of the buffer)
*/

/** Addition for GDAL : START */

ZPOS64_T unzGetCurrentFileZStreamPos64 (unzFile file);

/** Addition for GDAL : END */

/***************************************************************************/
/* for reading the content of the current zipfile, you can open it, read data
   from it, and close it (you can close it before reading all the file)
   */

int unzOpenCurrentFile (unzFile file);
/*
  Open for reading data the current file in the zipfile.
  If there is no error, the return value is UNZ_OK.
*/

int unzOpenCurrentFilePassword (unzFile file, const(char)* password);
/*
  Open for reading data the current file in the zipfile.
  password is a crypting password
  If there is no error, the return value is UNZ_OK.
*/

int unzOpenCurrentFile2 (unzFile file, int* method, int* level, int raw);
/*
  Same than unzOpenCurrentFile, but open for read raw the file (not uncompress)
    if raw==1
  *method will receive method of compression, *level will receive level of
     compression
  note : you can set level parameter as NULL (if you did not want known level,
         but you CANNOT set method parameter as NULL
*/

int unzOpenCurrentFile3 (
    unzFile file,
    int* method,
    int* level,
    int raw,
    const(char)* password);
/*
  Same than unzOpenCurrentFile, but open for read raw the file (not uncompress)
    if raw==1
  *method will receive method of compression, *level will receive level of
     compression
  note : you can set level parameter as NULL (if you did not want known level,
         but you CANNOT set method parameter as NULL
*/

int unzCloseCurrentFile (unzFile file);
/*
  Close the file in zip opened with unzOpenCurrentFile
  Return UNZ_CRCERROR if all the file was read but the CRC is not good
*/

int unzReadCurrentFile (unzFile file, voidp buf, uint len);
/*
  Read bytes from the current file (opened by unzOpenCurrentFile)
  buf contain buffer where data must be copied
  len the size of buf.

  return the number of byte copied if some bytes are copied
  return 0 if the end of file was reached
  return <0 with error code if there is an error
    (UNZ_ERRNO for IO error, or zLib error for uncompress error)
*/

z_off_t unztell (unzFile file);

ZPOS64_T unztell64 (unzFile file);
/*
  Give the current position in uncompressed data
*/

int unzeof (unzFile file);
/*
  return 1 if the end of file was reached, 0 elsewhere
*/

int unzGetLocalExtrafield (unzFile file, voidp buf, uint len);
/*
  Read extra field from the current file (opened by unzOpenCurrentFile)
  This is the local-header version of the extra field (sometimes, there is
    more info in the local-header version than in the central-header)

  if buf==NULL, it return the size of the local extra field

  if buf!=NULL, len is the size of the buffer, the extra header is copied in
    buf.
  the return value is the number of bytes copied in buf, or (if <0)
    the error code
*/

/***************************************************************************/

/* Get the current file offset */
ZPOS64_T unzGetOffset64 (unzFile file);
uLong unzGetOffset (unzFile file);

/* Set the current file offset */
int unzSetOffset64 (unzFile file, ZPOS64_T pos);
int unzSetOffset (unzFile file, uLong pos);

/* _unz64_H */
