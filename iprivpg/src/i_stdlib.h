/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/


#ifndef __I_STDLIB_H
#define __I_STDLIB_H

#include <stdarg.h>

#if defined(_WIN32_WCE)

#if !defined(_WIN32)
#define _WIN32
#endif /* _WIN32 */

#endif /* _WIN32_WCE */

// data types
#if !defined(_WIN32)

#ifdef __SYMBIAN32__
#include <_ansi.h>
#endif /*__SYMBIAN32__*/

#include <sys/types.h>

#ifdef sun
typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
#else
typedef u_int8_t uint8;
typedef u_int16_t uint16;
typedef u_int32_t uint32;
//typedef u_int64_t uint64;
#endif /* sun */

#else

#if defined(__MINGW32__)
#   include <basetyps.h>
#endif

typedef unsigned __int8 uint8;
typedef unsigned __int16 uint16;
typedef unsigned __int32 uint32;
//typedef unsigned __int64 uint64;

#endif /* _WIN32 */


int rsaref_mpicpy(const unsigned char* src, int nsrc, unsigned char* dst, int ndst);
void rsaref_dump(void *src, int nsrc);

#if defined(_WIN32) && _MSC_VER <= 1600
#define vsnprintf	__vsnprintf
#define snprintf	__snprintf
#else
#define O_BINARY
#endif

// memory management
void* i_malloc(unsigned long len);
void* i_realloc(void* ptr,unsigned long len);
void i_free(void* ptr);

#if defined(__DEBUG) || defined(_DEBUG)

#ifdef __cplusplus
extern "C" {
#endif

long GetMemUsage(void);

#ifdef __cplusplus
}
#endif

#endif


unsigned long atoul(const char* s);

int __vsnprintf(char* dst,int size,const char* fmt,va_list ap);
int __snprintf(char* dst,int size,const char* fmt,...);


class MemBuf
{
protected:
	char* ptr;
	int len;
public:
	MemBuf(int l=0)
	{
		ptr=0;
		len=0;
		if(l>0)
		{
			ptr=(char*)i_malloc(l);
			if(ptr)
				len=l;
		}
	}
	~MemBuf(void)
	{
		done();
	}
	void done(void)
	{
		if(ptr)
		{
			i_free(ptr);
			ptr=0;
		}
	}
	int expand(int l)
	{
		char* p=(char*)i_realloc(ptr,l);
		if(!p)
			return -1;
		ptr=p;
		len=l;
		return 0;
	}
	char* getptr(void)
	{
		return ptr;
	}
	int getlen(void)
	{
		return len;
	}
	operator char*()
	{
		return getptr();
	}
	operator int()
	{
		return getlen();
	}
};



// LE<=>BE
uint16 rotate16 (uint16 s);
uint32 rotate32 (uint32 s);

// exception management
#ifdef __SYMBIAN32__
#include <e32base.h>
#define trap_rc_t	TInt
#define trap_throw(rc)	User::Leave(rc)
#else
#define trap_rc_t	int
#endif /*__SYMBIAN32__*/

#ifndef WITH_EXCEPTIONS

#ifndef __SYMBIAN32__
#include <setjmp.h>

#define TRAP(RC,PROC)			\
	{				\
		Trap::Result=&RC;	\
		if(!setjmp(Trap::Env))	\
			PROC;		\
		Trap::Result=0;		\
	}
	
#define trap_throw(rc)	Trap::Throw(rc)

namespace Trap
{
	extern trap_rc_t* Result;
	extern jmp_buf Env;
	void Throw(trap_rc_t rc);
}
#endif /*__SYMBIAN32__*/

#else

class IprivError
{
public:
	int err;
	IprivError(int e){err=e;}
};

#define TRAP(RC,PROC)			\
	try				\
	{				\
		PROC;			\
	}				\
	catch(IprivError e)		\
	{				\
		RC=e.err;		\
	}

#define trap_throw(rc)	throw(IprivError((int)rc))

	
#endif /* WITH_EXCEPTIONS */

#endif /*__I_STDLIB_H */
