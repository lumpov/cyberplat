/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/


#ifndef __ARMOR_H
#define __ARMOR_H

#include "libipriv.h"
#include "ipriv.h"

#define MAX_DOCTYPE_LENGTH		2

typedef struct
{
	int version;				// document version
	char type[MAX_DOCTYPE_LENGTH+1];	// document type
	char userid1[MAX_USERID_LENGTH+1];
	unsigned long keyserial1;
	char userid2[MAX_USERID_LENGTH+1];
	unsigned long keyserial2;
	const char* doc;
	long doc_len;
	long strip_doc_len;
	const char* sig;
	long sig_len;
}doc_info;


long ArmorDoc(char *dst, int ndst, doc_info* di);
long DearmorDoc(const char *src, int nsrc,doc_info* di);



#endif /*__ARMOR_H */
