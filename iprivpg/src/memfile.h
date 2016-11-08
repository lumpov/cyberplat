/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

#ifndef __MEMFILE_H
#define __MEMFILE_H

#include "i_stdlib.h"
#include "libipriv.h"


#define MF_O_WRONLY	0x01
#define MF_O_RDONLY	0x02
#define MF_O_RDWR	0x03

#define MF_SEEK_SET	0
#define MF_SEEK_CUR	1
#define MF_SEEK_END	2

#define MF_ERR_EOF		CRYPT_ERR_NO_DATA_FOUND
#define MF_ERR_NODATAFOUND	CRYPT_ERR_NO_DATA_FOUND
#define MF_ERR_FREESPACE	CRYPT_ERR_OUT_OF_MEMORY

class MemFile
{
private:
	uint8* m_pBuf;
	long m_nOffset;
	long m_nSize;
	long m_nMaxSize;
	int m_nHow;

	int _getc(void);
protected:
	void error(int errcode);
public:
	MemFile(void);
	MemFile(char* buf,long size,int how);
	void attach(char* buf,long size,int how);
	long read(char* dst,long ndst);
	long write(const char* src,long nsrc);
	void read_n(char* dst,long ndst);		// read ndst bytes, exception if no data found
	void write_n(const char* src,long nsrc);	// write nsrc bytes, exception if no data found
	void seek(long offset,int whence);
	void resize(long size);
	long tell(void);
	long length(void);
	char* getptr(void);				// get current pos ptr
	int checklen(long len);				// check for free space

	int printf(const char* fmt,...);

	char* fgets(char* dst,int ndst);
};


#endif
