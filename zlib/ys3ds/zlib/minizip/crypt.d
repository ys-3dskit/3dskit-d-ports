module ys3ds.zlib.minizip.crypt;

/* crypt.h -- base code for crypt/uncrypt ZIPfile


   Version 1.01e, February 12th, 2005

   Copyright (C) 1998-2005 Gilles Vollant

   This code is a modified version of crypting code in Infozip distribution

   The encryption/decryption parts of this source code (as opposed to the
   non-echoing password parts) were originally written in Europe.  The
   whole source package can be freely distributed, including from the USA.
   (Prior to January 2000, re-export from the US was a violation of US law.)

   This encryption code is a direct transcription of the algorithm from
   Roger Schlafly, described by Phil Katz in the file appnote.txt.  This
   file (appnote.txt) is distributed with the PKZIP program (even in the
   version without encryption capabilities).

   If you don't need crypting in your application, just define symbols
   NOCRYPT and NOUNCRYPT.

   This code support the "Traditional PKWARE Encryption".

   The new AES encryption added on Zip format by Winzip (see the page
   http://www.winzip.com/aes_info.htm ) and PKWare PKZip 5.x Strong
   Encryption is not supported.
*/

import core.stdc.config;

import ys3ds.zlib.zconf;

extern (C):

pragma(inline, true)
extern (D)
{
  auto CRC32(T0, T1)(const(z_crc_t)* pcrc_32_tab, auto ref T0 c, auto ref T1 b)
  {
      return (*(pcrc_32_tab + ((cast(int) c ^ b) & 0xff))) ^ (c >> 8);
  }

  /***********************************************************************
  * Return the next byte in the pseudo-random sequence
  */
  int decrypt_byte (c_ulong* pkeys, const(z_crc_t)* pcrc_32_tab)
  {
    /* POTENTIAL BUG:  temp*(temp^1) may overflow in an
     * unpredictable manner on 16-bit systems; not a problem
     * with any known compiler so far, though */
    uint temp;

    //(void)pcrc_32_tab; // suppresses compiler unused param warning
    temp = (cast(uint)(*(pkeys+2)) & 0xffff) | 2;
    return cast(int) (((temp * (temp ^ 1)) >> 8) & 0xff);
  }

  /***********************************************************************
  * Update the encryption keys with the next byte of plain text
  */
  int update_keys (c_ulong* pkeys, const(z_crc_t)* pcrc_32_tab, int c)
  {
    *(pkeys+0) = CRC32(pcrc_32_tab, *(pkeys+0), c);
    *(pkeys+1) += *(pkeys+0) & 0xff;
    *(pkeys+1) = cast(uint) (*(pkeys+1) * 134_775_813L + 1);

    /* register */ int keyshift = cast(int) ((*(pkeys+1)) >> 24);
    *(pkeys+2) = CRC32(pcrc_32_tab, *(pkeys+2), keyshift);

    return c;
  }

  /***********************************************************************
  * Initialize the encryption keys and the random header according to
  * the given password.
  */
  void init_keys (
      const(char)* passwd,
      c_ulong* pkeys,
      const(z_crc_t)* pcrc_32_tab)
  {
    *(pkeys+0) = 305_419_896L;
    *(pkeys+1) = 591_751_049L;
    *(pkeys+2) = 878_082_192L;

    while (*passwd != '\0')
    {
      update_keys(pkeys, pcrc_32_tab, cast(int) *passwd); // @suppress(dscanner.unused_result)
      passwd++;
    }
  }

  auto zdecode(c_ulong* pkeys, const(z_crc_t)* pcrc_32_tab, int c)
  {
    return update_keys(pkeys, pcrc_32_tab, c ^= decrypt_byte(pkeys, pcrc_32_tab));
  }

  void zencode(c_ulong* pkeys, const(z_crc_t)* pcrc_32_tab, int c, ref int t)
  {
    t = decrypt_byte(pkeys, pcrc_32_tab);
    update_keys(pkeys, pcrc_32_tab, c); // @suppress(dscanner.unused_result)
  }

}
