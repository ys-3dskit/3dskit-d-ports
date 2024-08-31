module ys3ds.zlib.minizip.ioapi;

/* ioapi.h -- IO base function header for compress/uncompress .zip
   part of the MiniZip project - ( http://www.winimage.com/zLibDll/minizip.html )

         Copyright (C) 1998-2010 Gilles Vollant (minizip) ( http://www.winimage.com/zLibDll/minizip.html )

         Modifications for Zip64 support
         Copyright (C) 2009-2010 Mathias Svensson ( http://result42.com )

         For more info read MiniZip_info.txt

         Changes

    Oct-2009 - Defined ZPOS64_T to fpos_t on windows and u_int64_t on linux. (might need to find a better why for this)
    Oct-2009 - Change to fseeko64, ftello64 and fopen64 so large files would work on linux.
               More if/def section may be needed to support other platforms
    Oct-2009 - Defined fxxxx64 calls to normal fopen/ftell/fseek so they would compile on windows.
                          (but you should use iowin32.c for windows instead)

*/

import core.stdc.config;

import ys3ds.zlib.zconf;

extern (C) @nogc nothrow:

// Linux needs this to support file operation on files larger then 4+GB
// But might need better if/def to select just the platforms that needs them.

enum __USE_LARGEFILE64 = 1;

enum _FILE_OFFSET_BIT = 64;

// old MSC

/*
#ifndef ZPOS64_T
  #ifdef _WIN32
                #define ZPOS64_T fpos_t
  #else
    #include <stdint.h>
    #define ZPOS64_T uint64_t
  #endif
#endif
*/

/* a type chosen by DEFINE */

alias ZPOS64_T = ulong;

/* Maximum unsigned 32-bit value used as placeholder for zip64 */

enum MAXU32 = 0xffffffff;

enum ZLIB_FILEFUNC_SEEK_CUR = 1;
enum ZLIB_FILEFUNC_SEEK_END = 2;
enum ZLIB_FILEFUNC_SEEK_SET = 0;

enum ZLIB_FILEFUNC_MODE_READ = 1;
enum ZLIB_FILEFUNC_MODE_WRITE = 2;
enum ZLIB_FILEFUNC_MODE_READWRITEFILTER = 3;

enum ZLIB_FILEFUNC_MODE_EXISTING = 4;
enum ZLIB_FILEFUNC_MODE_CREATE = 8;

alias open_file_func = void* function (voidpf opaque, const(char)* filename, int mode);
alias read_file_func = c_ulong function (voidpf opaque, voidpf stream, void* buf, uLong size);
alias write_file_func = c_ulong function (voidpf opaque, voidpf stream, const(void)* buf, uLong size);
alias close_file_func = int function (voidpf opaque, voidpf stream);
alias testerror_file_func = int function (voidpf opaque, voidpf stream);

alias tell_file_func = c_long function (voidpf opaque, voidpf stream);
alias seek_file_func = c_long function (voidpf opaque, voidpf stream, uLong offset, int origin);

/* here is the "old" 32 bits structure structure */
struct zlib_filefunc_def_s
{
    open_file_func zopen_file;
    read_file_func zread_file;
    write_file_func zwrite_file;
    tell_file_func ztell_file;
    seek_file_func zseek_file;
    close_file_func zclose_file;
    testerror_file_func zerror_file;
    voidpf opaque;
}

alias zlib_filefunc_def = zlib_filefunc_def_s;

alias tell64_file_func = ulong function (voidpf opaque, voidpf stream);
alias seek64_file_func = c_long function (voidpf opaque, voidpf stream, ZPOS64_T offset, int origin);
alias open64_file_func = void* function (voidpf opaque, const(void)* filename, int mode);

struct zlib_filefunc64_def_s
{
    open64_file_func zopen64_file;
    read_file_func zread_file;
    write_file_func zwrite_file;
    tell64_file_func ztell64_file;
    seek64_file_func zseek64_file;
    close_file_func zclose_file;
    testerror_file_func zerror_file;
    voidpf opaque;
}

alias zlib_filefunc64_def = zlib_filefunc64_def_s;

void fill_fopen64_filefunc (zlib_filefunc64_def* pzlib_filefunc_def);
void fill_fopen_filefunc (zlib_filefunc_def* pzlib_filefunc_def);

/* now internal definition, only for zip.c and unzip.h */
struct zlib_filefunc64_32_def_s
{
    zlib_filefunc64_def zfile_func64;
    open_file_func zopen32_file;
    tell_file_func ztell32_file;
    seek_file_func zseek32_file;
}

alias zlib_filefunc64_32_def = zlib_filefunc64_32_def_s;

pragma(inline, true)
extern (D)
{
  auto ZREAD64(T0, T1, T2, T3)(auto ref T0 filefunc, auto ref T1 filestream, auto ref T2 buf, auto ref T3 size)
  {
    return (*filefunc.zfile_func64.zread_file)(filefunc.zfile_func64.opaque, filestream, buf, size);
  }

  auto ZWRITE64(T0, T1, T2, T3)(auto ref T0 filefunc, auto ref T1 filestream, auto ref T2 buf, auto ref T3 size)
  {
    return (*filefunc.zfile_func64.zwrite_file)(filefunc.zfile_func64.opaque, filestream, buf, size);
  }

  //#define ZTELL64(filefunc,filestream)            ((*((filefunc).ztell64_file)) ((filefunc).opaque,filestream))
  //#define ZSEEK64(filefunc,filestream,pos,mode)   ((*((filefunc).zseek64_file)) ((filefunc).opaque,filestream,pos,mode))
  auto ZCLOSE64(T0, T1)(auto ref T0 filefunc, auto ref T1 filestream)
  {
    return (*filefunc.zfile_func64.zclose_file)(filefunc.zfile_func64.opaque, filestream);
  }

  auto ZERROR64(T0, T1)(auto ref T0 filefunc, auto ref T1 filestream)
  {
    return (*filefunc.zfile_func64.zerror_file)(filefunc.zfile_func64.opaque, filestream);
  }
}

voidpf call_zopen64 (const(zlib_filefunc64_32_def)* pfilefunc, const(void)* filename, int mode);
c_long call_zseek64 (const(zlib_filefunc64_32_def)* pfilefunc, voidpf filestream, ZPOS64_T offset, int origin);
ZPOS64_T call_ztell64 (const(zlib_filefunc64_32_def)* pfilefunc, voidpf filestream);

void fill_zlib_filefunc64_32_def_from_filefunc32 (zlib_filefunc64_32_def* p_filefunc64_32, const(zlib_filefunc_def)* p_filefunc32);

pragma(inline, true)
extern (D)
{
  auto ZOPEN64(T0, T1, T2)(auto ref T0 filefunc, auto ref T1 filename, auto ref T2 mode)
  {
      return call_zopen64(&filefunc, filename, mode);
  }

  auto ZTELL64(T0, T1)(auto ref T0 filefunc, auto ref T1 filestream)
  {
      return call_ztell64(&filefunc, filestream);
  }

  auto ZSEEK64(T0, T1, T2, T3)(auto ref T0 filefunc, auto ref T1 filestream, auto ref T2 pos, auto ref T3 mode)
  {
      return call_zseek64(&filefunc, filestream, pos, mode);
  }
}
