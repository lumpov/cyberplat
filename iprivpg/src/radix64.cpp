/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

#include <string.h>
#include "radix64.h"
#include "i_stdlib.h"
#include <stdio.h>


static const unsigned char bin2ascii[65]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char ascii2bin[128]=
{
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x3e, 0x80, 0x80, 0x80, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x80, 0x80, 0x80, 0x80, 0x80
};

uint32 radix_crc24(uint32 crc,const char* src,int nsrc)
{
    for(int j=0;j<nsrc;j++)
    {
        crc^=(((unsigned char*)src)[j])<<16;
        for(int i=0;i<8;i++)
        {
            crc<<=1;
    	    if(crc&0x1000000)
	        crc^=0x1864cfbL;
	}
    }
    return crc;
}

int radix64enc_block(const char* src,int nsrc,char* dst)
{
    unsigned char* s=(unsigned char*)src;

    dst[0]=bin2ascii[(s[0]>>2)&0x3f];
    if(nsrc>2)
    {
	dst[1]=bin2ascii[((s[0]<<4)&0x30)|((s[1]>>4)&0x0f)];
	dst[2]=bin2ascii[((s[1]<<2)&0x3c)|((s[2]>>6)&0x03)];
	dst[3]=bin2ascii[s[2]&0x3f];
    }else if(nsrc>1)
    {
	dst[1]=bin2ascii[((s[0]<<4)&0x30)|((s[1]>>4)&0x0f)];
	dst[2]=bin2ascii[(s[1]<<2)&0x3c];
	dst[3]='=';
    }else if(nsrc>0)
    {
	dst[1]=bin2ascii[(s[0]<<4)&0x30];
	dst[2]='=';
	dst[3]='=';
    }
    return 4;
}


int radix64encode(const char* src,int nsrc,char* dst,int ndst)
{
    uint32 crc=0xb704ceL;

    int rc=ndst;
    *dst=0;

    int l=0;
    for(;;)
    {
	if(nsrc<3)
	    break;
	if(ndst<4)
	    return -1;

	radix64enc_block(src,nsrc,dst);
	crc=radix_crc24(crc,src,3);
	src+=3;
	dst+=4;
	nsrc-=3;
	ndst-=4;

	if((l+=4)==RADIX64_MAX_LINE_LENGTH)
	{
	    if(ndst<2)
		return -1;
	    dst[0]='\r';
	    dst[1]='\n';
	    dst+=2;
	    ndst-=2;
	    l=0;
	}
    }

    if(nsrc>0)
    {
	l+=4;
	radix64enc_block(src,nsrc,dst);
	crc=radix_crc24(crc,src,nsrc);
	src+=3;
	dst+=4;
	nsrc-=3;
	ndst-=4;
    }
    if(l)
    {
	if(ndst<2)
	    return -1;
	dst[0]='\r';
	dst[1]='\n';
	dst+=2;
	ndst-=2;
    }

/*
    if(ndst<8)
*/
    if(ndst<6)
	return -1;

    crc=rotate32(crc&0xffffffL);

    dst[0]='=';
    radix64enc_block(((char*)&crc)+1,3,dst+1);
/*
    dst[5]='\r';
    dst[6]='\n';
    dst[7]=0;
    ndst-=7;
*/
    dst[5]=0;
    ndst-=5;

    return rc-ndst;
}

int radix64dec_block(const char* src,int nsrc,char* dst)
{
    unsigned char* d=(unsigned char*)dst;

    unsigned char b1=ascii2bin[(int) src[0]];
    unsigned char b2=ascii2bin[(int) src[1]];
    unsigned char b3=ascii2bin[(int) src[2]];
    unsigned char b4=ascii2bin[(int) src[3]];

    if(src[2]=='=')
    {
	if(b1&0x80 || b2&0x80)
	    return -1;
	d[0]=((b1<<2)&0xfc)|((b2>>4)&0x03);
	return 1;
    }else if(src[3]=='=')
    {
	if(b1&0x80 || b2&0x80 || b3&0x80)
	    return -1;
	d[0]=((b1<<2)&0xfc)|((b2>>4)&0x03);
	d[1]=((b2<<4)&0xf0)|((b3>>2)&0x0f);
	return 2;
    }

    if(b1&0x80 || b2&0x80 || b3&0x80 || b4&0x80)
	return -1;

    d[0]=((b1<<2)&0xfc)|((b2>>4)&0x03);
    d[1]=((b2<<4)&0xf0)|((b3>>2)&0x0f);
    d[2]=((b3<<6)&0xc0)|(b4&0x3f);

    return 3;
}


int radix64decode(const char* src,int nsrc,char* dst,int ndst)
{
    uint32 crc=0xb704ceL;

    int rc=ndst;

    if(nsrc<0)
	nsrc=strlen(src);

    unsigned char* s=(unsigned char*)src;

    char crcbuf[4];
    int ncrcbuf=0;

    int newline=1;
    int iscrc=0;

    char data[4];
    int ndata=0;

    for(int i=0;i<nsrc;i++)
    {
	if(s[i]&0x80)
	    return -1;

	if(strchr(" \t\r",s[i]))
	    continue;
	if(s[i]=='\n')
	{
	    newline=1;
	    continue;
	}
	if(iscrc)
	{
	    if(newline)
		break;
	    if(ncrcbuf>= (int) sizeof(crcbuf))
		return -1;
	    crcbuf[ncrcbuf++]=s[i];
	    continue;
	}
	if(newline)
	{
	    newline=0;
	    if(s[i]=='=')
	    {
		iscrc=1;
		continue;
	    }
	}

	data[ndata++]=s[i];
	if(ndata >= (int) sizeof(data))
	{
	    if(ndst<3)
		return -1;
	    int n=radix64dec_block(data,sizeof(data),dst);
	    if(n<=0)
		return -1;
	    crc=radix_crc24(crc,dst,n);
	    dst+=n;
	    ndst-=n;
	    ndata=0;
	}
    }
    if(ndata>0)
    {
	if(ndata!=sizeof(data))
	    return -1;

        if(ndst<3)
	    return -1;
	int n=radix64dec_block(data,sizeof(data),dst);
	if(n<=0)
	    return -1;
	crc=radix_crc24(crc,dst,n);
	dst+=n;
	ndst-=n;
    }

    if(ncrcbuf!=sizeof(crcbuf))
	return -1;

    uint32 tcrc=0;
    radix64dec_block(crcbuf,sizeof(crcbuf),((char*)&tcrc)+1);
    if((crc&0xffffffL)!=rotate32(tcrc))
	return -1;

    return rc-ndst;
}
