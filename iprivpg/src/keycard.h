#ifndef __KEYCARD_H
#define __KEYCARD_H

#include "i_stdlib.h"

#define CRCINIT 0xB704CEL
#define PRZCRC 0x864cfbL
#define CRCBITS 24
#define CRCHIBIT ((uint32) (1L<<(CRCBITS-1)))
#define CRCSHIFTS (CRCBITS-8)

#define maskcrc(crc) ((crc) & 0xffffffL)


#define CryptInitCRC()	CryptBuildCRCTable(PRZCRC)

void CryptBuildCRCTable(uint32 poly);
uint32 CryptCRC(unsigned char* buf,unsigned len,uint32 accum);
int CryptReadKeyCard(const char* src, int nsrc,unsigned long *serial, char *userid);
int CryptWriteKeyCard(char* dst,int ndst,unsigned long serial,const char *userid);



#endif
