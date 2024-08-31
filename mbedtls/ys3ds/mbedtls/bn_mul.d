/**
 * \file bn_mul.h
 *
 * \brief Multi-precision integer library
 */

extern (C) @nogc nothrow:

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 *      Multiply source vector [s] with b, add result
 *       to destination vector [d] and set carry c.
 *
 *      Currently supports:
 *
 *         . IA-32 (386+)         . AMD64 / EM64T
 *         . IA-32 (SSE2)         . Motorola 68000
 *         . PowerPC, 32-bit      . MicroBlaze
 *         . PowerPC, 64-bit      . TriCore
 *         . SPARC v8             . ARM v3+
 *         . Alpha                . MIPS32
 *         . C, longlong          . C, generic
 */

/*
 * Conversion macros for embedded constants:
 * build lists of mbedtls_mpi_uint's from lists of unsigned char's grouped by 8, 4 or 2
 */

/* 64-bits */

extern (D) auto MBEDTLS_BYTES_TO_T_UINT_8(T0, T1, T2, T3, T4, T5, T6, T7)(auto ref T0 a, auto ref T1 b, auto ref T2 c, auto ref T3 d, auto ref T4 e, auto ref T5 f, auto ref T6 g, auto ref T7 h)
{
    return (cast(mbedtls_mpi_uint) a << 0) | (cast(mbedtls_mpi_uint) b << 8) | (cast(mbedtls_mpi_uint) c << 16) | (cast(mbedtls_mpi_uint) d << 24) | (cast(mbedtls_mpi_uint) e << 32) | (cast(mbedtls_mpi_uint) f << 40) | (cast(mbedtls_mpi_uint) g << 48) | (cast(mbedtls_mpi_uint) h << 56);
}

extern (D) auto MBEDTLS_BYTES_TO_T_UINT_4(T0, T1, T2, T3)(auto ref T0 a, auto ref T1 b, auto ref T2 c, auto ref T3 d)
{
    return MBEDTLS_BYTES_TO_T_UINT_8(a, b, c, d, 0, 0, 0, 0);
}

extern (D) auto MBEDTLS_BYTES_TO_T_UINT_2(T0, T1)(auto ref T0 a, auto ref T1 b)
{
    return MBEDTLS_BYTES_TO_T_UINT_8(a, b, 0, 0, 0, 0, 0, 0);
}

/* bits in mbedtls_mpi_uint */

/* *INDENT-OFF* */

/* armcc5 --gnu defines __GNUC__ but doesn't support GNU's extended asm */

/*
 * GCC < 5.0 treated the x86 ebx (which is used for the GOT) as a
 * fixed reserved register when building as PIC, leading to errors
 * like: bn_mul.h:46:13: error: PIC register clobbered by 'ebx' in 'asm'
 *
 * This is fixed by an improved register allocator in GCC 5+. From the
 * release notes:
 * Register allocation improvements: Reuse of the PIC hard register,
 * instead of using a fixed register, was implemented on x86/x86-64
 * targets. This improves generated PIC code performance as more hard
 * registers can be used.
 */

/*
 * Disable use of the i386 assembly code below if option -O0, to disable all
 * compiler optimisations, is passed, detected with __OPTIMIZE__
 * This is done as the number of registers used in the assembly code doesn't
 * work with the -O0 option.
 */

/* SSE2 */
/* i386 */

enum MULADDC_CORE = "movq   (%%rsi), %%rax\n" ~ "mulq   %%rbx\n" ~ "addq   $8, %%rsi\n" ~ "addq   %%rcx, %%rax\n" ~ "movq   %%r8, %%rcx\n" ~ "adcq   $0, %%rdx\n" ~ "nop    \n" ~ "addq   %%rax, (%%rdi)\n" ~ "adcq   %%rdx, %%rcx\n" ~ "addq   $8, %%rdi\n";

/* AMD64 */

/* Aarch64 */

/* MC68000 */

/* __MACH__ && __APPLE__ */

/* __MACH__ && __APPLE__ */

/* end PPC64/begin PPC32  */

/* __MACH__ && __APPLE__ */

/* __MACH__ && __APPLE__ */

/* PPC32 */

/*
 * The Sparc(64) assembly is reported to be broken.
 * Disable it for now, until we're able to fix it.
 */

/* __sparc64__ */

/* __sparc64__ */
/* __sparc__ */

/* MicroBlaze */

/* TriCore */

/*
 * Note, gcc -O0 by default uses r7 for the frame pointer, so it complains about
 * our use of r7 below, unless -fomit-frame-pointer is passed.
 *
 * On the other hand, -fomit-frame-pointer is implied by any -Ox options with
 * x !=0, which we can detect using __OPTIMIZE__ (which is also defined by
 * clang and armcc5 under the same conditions).
 *
 * So, only use the optimized assembly below for optimized build, which avoids
 * the build error and is pretty reasonable anyway.
 */

/*
 * Thumb 1 ISA. This code path has only been tested successfully on gcc;
 * it does not compile on clang or armclang.
 *
 * Other compilers which define __GNUC__ may not work. The above macro
 * attempts to exclude these untested compilers.
 */

/* Compiler is gcc */

/* Thumb */

/* ARMv3 */

/* Alpha */

/* MIPS */
/* GNUC */

/* SSE2 */
/* MSVC */

/* MBEDTLS_HAVE_ASM */

/* C (generic)  */
/* C (longlong) */

/* *INDENT-ON* */
/* bn_mul.h */
