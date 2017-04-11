/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

#include "memfile.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>


MemFile::MemFile(void)
{
	attach(0,0,0);
}
MemFile::MemFile(char* buf,long size,int how)
{
	attach(buf,size,how);
}
void MemFile::attach(char* buf,long size,int how)
{
	m_pBuf=(uint8*)buf;
	m_nOffset=0;
	m_nSize=(how==MF_O_RDONLY)?size:0;
	m_nMaxSize=size;
	m_nHow=how;
}

void MemFile::error(int errcode)
{
	trap_throw(errcode);
}

long MemFile::read(char* dst,long ndst)
{
	if(!(m_nHow&MF_O_RDONLY))
		return 0;
	long n=m_nSize-m_nOffset;
	if(n<ndst)
		ndst=n;
	memcpy(dst,m_pBuf+m_nOffset,ndst);
	m_nOffset+=ndst;
	return ndst;
}
long MemFile::write(const char* src,long nsrc)
{
	if(!(m_nHow&MF_O_WRONLY))
		return 0;
	long n=m_nMaxSize-m_nOffset;
	if(n<nsrc)
		nsrc=n;
	memcpy(m_pBuf+m_nOffset,src,nsrc);
	m_nOffset+=nsrc;
	if(m_nOffset>m_nSize)
		m_nSize=m_nOffset;
	return nsrc;
}
void MemFile::read_n(char* dst,long ndst)
{
	if(!(m_nHow&MF_O_RDONLY))
		error(MF_ERR_EOF);
	if(m_nSize-m_nOffset<ndst)
		error(MF_ERR_NODATAFOUND);
	memcpy(dst,m_pBuf+m_nOffset,ndst);
	m_nOffset+=ndst;
}

void MemFile::write_n(const char* src,long nsrc)
{
	if(!(m_nHow&MF_O_WRONLY))
		error(MF_ERR_EOF);
	if(m_nMaxSize-m_nOffset<nsrc)
		error(MF_ERR_FREESPACE);
	memcpy(m_pBuf+m_nOffset,src,nsrc);
	m_nOffset+=nsrc;
	if(m_nOffset>m_nSize)
		m_nSize=m_nOffset;
}
void MemFile::seek(long offset,int whence)
{
	long tmp = 0;
	switch(whence)
	{
	case MF_SEEK_SET:
		tmp=offset;
		break;
	case MF_SEEK_CUR:
		tmp=m_nOffset+offset;
		break;
	case MF_SEEK_END:
		tmp=m_nSize+offset;
		break;
	default:
		error(MF_ERR_EOF);
	}
	if(tmp<0)
		error(MF_ERR_EOF);
	if(tmp>m_nMaxSize)
		error(MF_ERR_EOF);
	m_nOffset=tmp;
	if(m_nSize<m_nOffset)
		m_nSize=m_nOffset;
}
void MemFile::resize(long size)
{
	if(size<0 || size>m_nMaxSize)
		error(MF_ERR_EOF);
	m_nSize=size;
}
long MemFile::tell(void)
{
	return m_nOffset;
}
long MemFile::length(void)
{
	return m_nSize;
}
char* MemFile::getptr(void)
{
	return (char*)m_pBuf+m_nOffset;
}
int MemFile::checklen(long len)
{
	if(m_nSize-m_nOffset<len)
		return -1;
	return 0;
}
int MemFile::printf(const char* fmt,...)
{
    if(!(m_nHow&MF_O_WRONLY))
	error(MF_ERR_EOF);
    int n=m_nMaxSize-m_nOffset;

    va_list ap;
    va_start(ap,fmt);

    int rc=vsnprintf((char*)m_pBuf+m_nOffset,n,fmt,ap);

    va_end(ap);

    if(rc<0 || rc>=n)
	rc=n;

    m_nOffset+=rc;
    if(m_nOffset>m_nSize)
	m_nSize=m_nOffset;

    return rc;
}
int MemFile::_getc(void)
{
    if(!(m_nHow&MF_O_RDONLY))
	return 0;
    if(m_nOffset>=m_nSize)
	return 0;
    int rc=m_pBuf[m_nOffset];
    m_nOffset++;
    return rc;
}
char* MemFile::fgets(char* dst,int ndst)
{
    ndst--;
    int n=0;
    for(int i=0;;i++)
    {
	uint8 c=_getc();
	if(!c)
	{
	    if(!i)
		error(MF_ERR_EOF);
	    break;
	}
	if(c=='\r')
	    continue;
	if(c=='\n')
	    break;
	if(n<ndst)
	{
	    ((uint8*)dst)[n]=c;
	    n++;
	}
    }
    dst[n]=0;
    return dst;
}
