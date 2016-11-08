/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/


#ifndef __RADIX64_H
#define __RADIX64_H

#define RADIX64_MAX_LINE_LENGTH 64

int radix64enc_block(const char* src,int nsrc,char* dst);
int radix64dec_block(const char* src,int nsrc,char* dst);
int radix64encode(const char* src,int nsrc,char* dst,int ndst);
int radix64decode(const char* src,int nsrc,char* dst,int ndst);


#endif
