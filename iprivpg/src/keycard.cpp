#include <stdlib.h>
#include <string.h>
#include "libipriv.h"
#include <stdio.h>
#include "radix64.h"
#include "keycard.h"

static uint32 crypt_crc_table[256];

void CryptBuildCRCTable(uint32 poly)
{
	int i;
	uint32 t, *p, *q;

	p = q = crypt_crc_table;
	*q++ = 0;
	*q++ = poly;
	for (i = 1; i < 128; i++) {
		t = *++p;
		if (t & CRCHIBIT) {
			t <<= 1;
			*q++ = t ^ poly;
			*q++ = t;
		} else {
			t <<= 1;
			*q++ = t;
			*q++ = t ^ poly;
		}
	}
}

uint32 CryptCRC(unsigned char *buf, unsigned len, uint32 accum)
{
	do {
		accum = accum << 8 ^ crypt_crc_table[(unsigned char) (accum >> CRCSHIFTS) ^ *buf++];
	} while (--len);
	return maskcrc(accum);
}




int CryptReadKeyCard(const char *src, int nsrc, unsigned long *serial, char *userid)
{
	if (!serial || !userid)
		return CRYPT_ERR_BAD_ARGS;
	if (nsrc < 0)
		nsrc = strlen(src);

	MemBuf temp(nsrc + 1);

	if (!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;

	memcpy(temp.getptr(), src, nsrc);
	temp.getptr()[nsrc] = 0;

	char *pos = strrchr(temp.getptr(), '=');

	if (!pos)
		return CRYPT_ERR_INVALID_KEYCARD;
	*pos = 0;
	uint32 crc = CryptCRC((unsigned char *) temp.getptr(), pos - temp.getptr(), CRCINIT);

	crc &= 0xffffffL;
	pos++;

	if (strlen(pos) != 4)
		return CRYPT_ERR_INVALID_KEYCARD;

	char str1[] = "Version: 01\r\nUser ID: ";
	char str2[] = "\r\nUser Key: ";
	char *start = temp.getptr();

	char *s = strstr(start, str1);
	if (s != start)
		return CRYPT_ERR_INVALID_KEYCARD;

	int i;
	s += sizeof(str1)-1;
	for (i=0; i<MAX_USERID_LENGTH; i++) {
		if (s[i] == '\r' || s[i] == '\n' || !s[i]) break;
		userid[i] = s[i];
	}
	userid[i] = 0;

	s = strstr(s, str2);
	if (!s)
		return CRYPT_ERR_INVALID_KEYCARD;
	*serial = atol(s+sizeof(str2)-1);

	uint32 tcrc = 0;
	radix64dec_block(pos, 4, ((char *) &tcrc) + 1);
	tcrc = rotate32(tcrc);
	if (crc != tcrc)
		return CRYPT_ERR_INVALID_KEYCARD;

	return 0;
}

int CryptWriteKeyCard(char *dst, int ndst, unsigned long serial, const char *userid)
{
	int n = __snprintf(dst, ndst, "Version: 01\r\nUser ID: %s\r\nUser Key: %lu\r\n", userid, serial);

	if (n <= 0)
		return 0;

	uint32 crc = CryptCRC((unsigned char *) dst, n, CRCINIT);

	crc = rotate32(crc & 0xffffffL);
	char crcbuf[6];

	radix64enc_block(((char *) &crc) + 1, 3, crcbuf + 1);
	crcbuf[0] = '=';
	crcbuf[5] = 0;

	if (ndst - n < (int) sizeof(crcbuf))
		return 0;

	strcpy(dst + n, crcbuf);
	return n + (sizeof(crcbuf) - 1);
}

/*
// записать карточку ключа
int writeKeyFile(const char *keyfilename, long keySerial, const char *userid)
{
	int rc, len;
	char s[200], crcbuf[6];
	unsigned long crc;
	FILE *f;
	char* how = "w";
#ifdef _WIN32
	how = "wb";
#endif

	if (!keyfilename || !*keyfilename || keySerial<=0 || !userid || !*userid)
		return CRYPT_ERR_BAD_ARGS;

	if ((f = fopen(keyfilename, how)) == NULL){
		return -1;
	}
	len = sprintf(s, "Version: 01\r\nUser ID: %s\r\nUser Key: %ld\r\n", userid, keySerial);

	init_crc();
	crc = crcbytes((byte *) s, len, CRCINIT);
    crc=i_htonl(crc&0xffffffL);
    crcbuf[0] = '=';
    radix64enc_block(((char*) &crc)+1, 3, crcbuf+1);
	crcbuf[5] = 0;
	strcat(s, crcbuf);

	rc = fwrite(s, 1, len+5, f);
	fclose(f);

	if (!rc) 
		return CRYPT_ERR_WRITEFILE;
	else 
		return 0;
}
*/
