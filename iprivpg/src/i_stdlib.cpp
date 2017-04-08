/*
   Copyright (C) 1998-2011 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/


#include "config.h"

#include <string.h>
#include "i_stdlib.h"
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>


#ifdef __linux
#include <endian.h> 
#if __BYTE_ORDER == __BIG_ENDIAN	// SPARC, Motorola, PowerPC
#define IS_BIGENDIAN	1
#endif
#endif

#if defined(__DEBUG) || defined(_DEBUG)
long memory_usage=0;

void* i_malloc(unsigned long len)
{
	if(len<=0)
		return 0;
	void* p=malloc(len+sizeof(uint32));
	if(!p)
		return 0;
	*((uint32*)p)=len;
	memory_usage+=len;
	return ((char*)p)+sizeof(uint32);
}
void* i_realloc(void* ptr,unsigned long len)
{
	if(!ptr || len<0)
		return 0;
	void* p=((char*)ptr)-sizeof(uint32);
	memory_usage-=*((uint32*)p);
	p=realloc(p,len+sizeof(uint32));
	if(!p)
		return 0;
	*((uint32*)p)=len;
	memory_usage+=len;
	return ((char*)p)+sizeof(uint32);
}
void i_free(void* ptr)
{
	if(!ptr)
		return;
	void* p=((char*)ptr)-sizeof(uint32);
	memory_usage-=*((uint32*)p);
	free(p);
}

long GetMemUsage(void)
{
	return memory_usage;
}

#else
void* i_malloc(unsigned long len)
{
	return malloc(len);
}
void* i_realloc(void* ptr,unsigned long len)
{
	return realloc(ptr,len);
}
void i_free(void* ptr)
{
	free(ptr);
}
#endif

int __vsnprintf(char* dst,int size,const char* fmt,va_list ap)
{
#ifdef __SYMBIAN32__
	return vsprintf(dst,fmt,ap);
#else
	if(size<=0)
		return 0;
#ifdef _WIN32
	int rc=_vsnprintf(dst,size,fmt,ap);
#else
	int rc=vsnprintf(dst,size,fmt,ap);
#endif
	if(rc<0 || rc>=size)
		rc=size-1;
	dst[rc]=0;
	return rc;
#endif /*__SYMBIAN32__*/
}


int __snprintf(char* dst,int size,const char* fmt,...)
{
	va_list ap;
	va_start(ap,fmt);
	int rc=__vsnprintf(dst,size,fmt,ap);
	va_end(ap);
	return rc;
}

unsigned long atoul(const char* s)
{
	unsigned long rc=0;
	while(*s)
	{
		unsigned char c=*((unsigned char*)s);
		if(!isdigit(c))
			return 0;
		rc=rc*10+(c-48);
		s++;
	}
	return rc;
}


uint16 rotate16 (uint16 s)
{
#ifdef IS_BIGENDIAN
    return s;
#else
    return (s>>8) | (s<<8);
#endif
}

uint32 rotate32 (uint32 s)
{
#ifdef IS_BIGENDIAN
    return s;
#else
    return (s>>24) | ((s>>8)&0x0000ff00) | ((s<<8)&0x00ff0000) | (s<<24);
#endif
}

#ifndef WITH_EXCEPTIONS

#ifndef __SYMBIAN32__
namespace Trap
{
	trap_rc_t* Result=0;
	jmp_buf Env;

	void Throw(trap_rc_t rc)
	{
		if(Result)
		{
			*Result=rc;
			longjmp(Env,1);
		}
	}
}
#endif /*__SYMBIAN32__*/

#endif

#ifdef _WIN32_WCE
#include <windows.h>
extern "C" time_t time(time_t* tloc)
{
    FILETIME ftmCur;
    SYSTEMTIME tmCur;

    GetSystemTime(&tmCur);
    SystemTimeToFileTime(&tmCur,&ftmCur);

    LONGLONG tsCur=(LONGLONG)ftmCur.dwLowDateTime|((LONGLONG)ftmCur.dwHighDateTime)<<32;
    time_t rc = ((time_t)(tsCur/10000000L))-3054539008L;

    if(tloc)
        *tloc=rc;
    return rc;
}
#endif

int rsaref_mpicpy(const unsigned char* src, int nsrc, unsigned char* dst, int ndst)
{
	if (nsrc == ndst)
		memcpy(dst,src,nsrc);
	else if (nsrc > ndst) {
		int n = nsrc-ndst;
		memcpy(dst, src+n, ndst);
	} else {
		int n = ndst-nsrc;
		memset(dst, 0, n);
		memcpy(dst+n, src, nsrc);
	}
	return 0;
}

void rsaref_dump(void *s, int nsrc)
{
	unsigned char *src = (unsigned char *) s;
	while (nsrc>0 && !*src) {
		src++;
		nsrc--;
	}
	
	for(int i=0;i<nsrc;i++)
		printf("%.2x ", src[i]);
	printf("\n");
}
