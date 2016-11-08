/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/


#include "armor.h"
#include "memfile.h"
#include "i_stdlib.h"
#include "libipriv.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

unsigned long str2int(const char *src, int nsrc)
{
	unsigned long rc = 0;

	for (int i = 0; i < nsrc; i++) {
		if (!isdigit(src[i]))
			return 0;
		rc = rc * 10 + src[i] - '0';
	}
	return rc;
}


int Dearmor_Internal(MemFile &doc, doc_info* di, long &offset)
{
	MemBuf temp(512);
	if(!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;

	doc.fgets(temp, temp.getlen());					// header
	if (strlen(temp) != 36)
		return CRYPT_ERR_INVALID_FORMAT;
	
	di->version=str2int(temp.getptr() + 8, 2);			// version, doctype
	memcpy(di->type, temp.getptr() + 10, MAX_DOCTYPE_LENGTH);
	di->type[MAX_DOCTYPE_LENGTH]=0;
	
	long rsize = str2int(temp.getptr(), 8);
	long docsize = str2int(temp.getptr() + 12, 8);			// doc size
	long stripdocsize = str2int(temp.getptr() + 20, 8);		// strip doc size
	long sigsize = str2int(temp.getptr() + 28, 8);			// signature size

	if (rsize <= 0 || docsize <= 0 || sigsize < 0)
		return CRYPT_ERR_INVALID_FORMAT;

	doc.fgets(temp, temp.getlen());					// userid, keyserial
	if (strlen(temp) != 28)
		return CRYPT_ERR_INVALID_FORMAT;
	char *p = temp.getptr() + 19;
	while (p >= temp.getptr() && *p == ' ')
	{
		*p = 0;
		p--;
	}
	memcpy(di->userid1, temp, MAX_USERID_LENGTH);
	di->userid1[MAX_USERID_LENGTH]=0;
	di->keyserial1 = str2int(temp.getptr() + 20, 8);

	doc.fgets(temp, temp.getlen());					// userid2, keyserial2
	if (strlen(temp) != 28)
		return CRYPT_ERR_INVALID_FORMAT;
	p = temp.getptr() + 19;
	while (p >= temp.getptr() && *p == ' ')
	{
		*p = 0;
		p--;
	}
	memcpy(di->userid2, temp, MAX_USERID_LENGTH);
	di->userid2[MAX_USERID_LENGTH]=0;
	di->keyserial2 = str2int(temp.getptr() + 20, 8);

	
	doc.fgets(temp, temp.getlen());					// BEGIN tag
	if (strcmp(temp, "BEGIN"))
		return CRYPT_ERR_INVALID_FORMAT;

	long docpos = doc.tell();					// doc position

	doc.seek(docsize, MF_SEEK_CUR);

	doc.fgets(temp, temp.getlen());					// \r\n tag
	if (*temp.getptr())
		return CRYPT_ERR_INVALID_FORMAT;

	doc.fgets(temp, temp.getlen());					// END tag
	if (strcmp(temp, "END"))
		return CRYPT_ERR_INVALID_FORMAT;

	doc.fgets(temp, temp.getlen());					// BEGIN SIGNATURE tag
	if (strcmp(temp, "BEGIN SIGNATURE"))
		return CRYPT_ERR_INVALID_FORMAT;

	long sigpos = doc.tell();					// signature position

	doc.seek(sigsize, MF_SEEK_CUR);
	doc.fgets(temp, temp.getlen());					// \r\n tag
	if (*temp.getptr())
		return CRYPT_ERR_INVALID_FORMAT;
	doc.fgets(temp, temp.getlen());					// END SIGNATURE tag
	if (strncmp(temp, "END SIGNATURE",13))
		return CRYPT_ERR_INVALID_FORMAT;

	offset += doc.tell();

	doc.seek(docpos, MF_SEEK_SET);
	const char *pdocument = doc.getptr();

	doc.seek(sigpos, MF_SEEK_SET);
	const char *psignature = doc.getptr();

	di->doc=pdocument;
	di->doc_len=docsize;
	di->strip_doc_len=stripdocsize;
	di->sig=psignature;
	di->sig_len=sigsize;

	return 0;
}

long DearmorDoc(const char *src, int nsrc, doc_info* di)
{
	if(!nsrc)
		return 0;

	if (!src || !di)
		return CRYPT_ERR_BAD_ARGS;

	if (nsrc < 0)
		nsrc = strlen(src);

	long offset = 0;

	while (*src == ' ' || *src == '\t' || *src == '\n' || *src == '\r') {
		src++;
		nsrc--;
		offset++;
	}

	MemFile doc((char *) src, nsrc, MF_O_RDONLY);

	int n = 0;

	trap_rc_t e = 0;
	TRAP(e, (n = Dearmor_Internal(doc, di, offset)));
	if (e)
		return CRYPT_ERR_INVALID_FORMAT;
	if (n)
		return n;

	return offset > 0 ? offset : CRYPT_ERR_INVALID_FORMAT;
}




void Armor_Internal(MemFile &doc, doc_info* di,long &offset)
{
//	char uid[MAX_USERID_LENGTH+1];
//	int len;

	doc.printf("%08.8ld", 0);					// right size
	doc.printf("%02.2ld", di->version);				// version
	doc.printf("%-2.2s", di->type);					// doc type
	doc.printf("%08.8ld", di->doc_len);				// size of body after armoring
	doc.printf("%08.8ld", di->strip_doc_len);			// size of body
	doc.printf("%08.8ld", di->sig_len);				// size of signature after armoring
	doc.printf("\r\n");

	doc.printf("%-20.20s%08.8ld\r\n",di->userid1,di->keyserial1);	// userid1,keyserial1
	doc.printf("%-20.20s%08.8ld\r\n",di->userid2,di->keyserial2);	// userid2,keyserial2

	doc.printf("BEGIN\r\n");
	doc.write_n(di->doc,di->doc_len);				// message
	doc.printf("\r\nEND\r\n");

	doc.printf("BEGIN SIGNATURE\r\n");
	if (di->sig_len > 0)
		doc.write_n(di->sig,di->sig_len);			// signature
	doc.printf("\r\nEND SIGNATURE");

	offset += doc.tell();

	doc.seek(0, MF_SEEK_SET);
	char tmp[16];
	snprintf(tmp, sizeof(tmp), "%08ld", doc.length() - 8);	// right size

	doc.write_n(tmp, 8);
	doc.seek(0, MF_SEEK_END);
}

long ArmorDoc(char *dst, int ndst, doc_info* di)
{
	if (!dst || !di)
		return CRYPT_ERR_BAD_ARGS;

	MemFile doc(dst, ndst, MF_O_WRONLY);

	long offset=0;
	trap_rc_t e = 0;
	TRAP(e, Armor_Internal(doc, di, offset));
	if (e)
		return CRYPT_ERR_OUT_OF_MEMORY;
	return offset;
}
