/* GLOBAL.H - RSAREF types and constants */

/* Copyright (C) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */

#ifndef _I_GLOBAL_H_
#define _I_GLOBAL_H_ 1

/* PROTOTYPES should be set to one if and only if the compiler supports
     function argument prototyping.
   The following makes PROTOTYPES default to 1 if it has not already been
     defined as 0 with C compiler flags.
 */
#ifndef PROTOTYPES
#define PROTOTYPES 1
#endif

/* POINTER defines a generic pointer type */
#ifndef POINTER_TYPE
#define POINTER_TYPE	1
typedef unsigned char *POINTER;
#endif

#if defined(__MINGW32__)
#   include <basetyps.h>
#endif

#ifdef _WIN32
typedef unsigned __int16 UINT2;	// UINT2 defines a two byte word
typedef unsigned __int32 UINT4;	// UINT4 defines a four byte word
#else
#include <sys/types.h>

#ifdef sun
typedef uint16_t UINT2;
typedef uint32_t UINT4;
#else
typedef u_int16_t UINT2;
typedef u_int32_t UINT4;
#endif /* sun */

#endif

#ifndef NULL_PTR
#define NULL_PTR ((POINTER)0)
#endif

#ifndef UNUSED_ARG
#define UNUSED_ARG(x) x = *(&x);
#endif

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
   If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
     returns an empty list.
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif

#endif /* end _I_GLOBAL_H_ */
