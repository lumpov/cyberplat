/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

#include "ipriv.h"
#include "armor.h"
#include "radix64.h"
#include "packet.h"
#include <string.h>
#include <time.h>
#ifndef WITH_OPENSSL
#include "md5.h"
#else
#include <openssl/md5.h>
#endif
#include "sha256.h"

int Crypt_ReadSecretKey(const char* src,int nsrc,const char* passwd,IPRIV_KEY_BODY* key)
{
//	memset((char*)key,0,sizeof(*key));

	doc_info di;
	int rc=DearmorDoc(src,nsrc,&di);
	if(rc<0)
		return rc;

	if(strcmp(di.type,"NM"))
		return CRYPT_ERR_DOCTYPE;
	
	MemBuf temp(2048);
	if(!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;

	int n=radix64decode(di.doc,di.doc_len,temp.getptr(),temp.getlen());
	if(n<=0)
		return CRYPT_ERR_RADIX_DECODE;

	rc=read_packet(temp.getptr(),n,key,passwd,0,0,0,0);
	if(rc<0)
		return rc;
	strcpy(key->userid,di.userid1);
		
	return rc;
}
int Crypt_ReadSecretKey2(const char* src,int nsrc,const char* passwd,IPRIV_KEY_BODY* key)
{
//	memset((char*)key,0,sizeof(*key));

	MemBuf temp(2048);
	if(!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;

	int n=radix64decode(src,nsrc,temp.getptr(),temp.getlen());
	if(n<=0)
		return CRYPT_ERR_RADIX_DECODE;

	int rc=read_packet(temp.getptr(),n,key,passwd,0,key->userid,sizeof(key->userid),0);
	if(rc<0)
		return rc;

	return rc;
}

int Crypt_WriteSecretKey(char* dst,int ndst,const char* passwd,IPRIV_KEY_BODY* key,unsigned char* iv,int niv)
{
	MemBuf temp(2048);
	MemBuf temp2(4096);
	if(!temp.getlen() || !temp2.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;

	int rc=write_packet(temp.getptr(),temp.getlen(),key,passwd,0,key->userid,0,iv,niv);
	if(rc<=0)
		return rc;
		
	int n=radix64encode(temp.getptr(),rc,temp2.getptr(),temp2.getlen());
	if(n<=0)
		return CRYPT_ERR_RADIX_ENCODE;

	doc_info di;
	di.version=1;
	strcpy(di.type,"NM");
	strcpy(di.userid1,key->userid);
	di.keyserial1=key->keyserial;
	*di.userid2=0;
	di.keyserial2=0;
	di.doc=temp2.getptr();
	di.doc_len=n;
	di.strip_doc_len=rc;
	di.sig=0;
	di.sig_len=0;


	rc=ArmorDoc(dst,ndst,&di);
	if(rc<0)
		return rc;

	return rc;
}
int Crypt_ReadPublicKey(const char* src,int nsrc,unsigned long keyserial,IPRIV_KEY_BODY* key,IPRIV_KEY* cakey,IPRIV_ENGINE* eng)
{
//	memset((char*)key,0,sizeof(*key));

	doc_info di;
	
	int rc=CRYPT_ERR_PUB_KEY_NOT_FOUND;
	for(int offset=0;;)
	{	
		int n=DearmorDoc(src+offset,nsrc-offset,&di);
		if(n<=0)
			break;
		if(!strcmp(di.type,"NS")/* && di.keyserial2*/)
		{
			if(!keyserial || di.keyserial1==keyserial)
			{
				rc=0;
				break;
			}
		}
		offset+=n;
	}
	if(rc)
		return rc;

	MemBuf body(2048);
	if(!body.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;

	int blen=radix64decode(di.doc,di.doc_len,body.getptr(),body.getlen());
	if(blen<=0)
		return CRYPT_ERR_RADIX_DECODE;

	IPRIV_POSITION keypos={0,0};
	rc=read_packet(body.getptr(),blen,key,0,0,0,0,&keypos);
	if(rc<0)
		return rc;

	if(cakey)
	{
		if(!di.sig_len)
			return CRYPT_ERR_VERIFY;
		MemBuf sign(2048);
		if(!sign.getlen())
			return CRYPT_ERR_OUT_OF_MEMORY;

		int slen=radix64decode(di.sig,di.sig_len,sign.getptr(),sign.getlen());
		if(slen<=0)
			return CRYPT_ERR_RADIX_DECODE;

		IPRIV_SIGNATURE sig;
		memset((char*)&sig,0,sizeof(sig));

		rc=read_packet(sign.getptr(),slen,0,0,&sig,0,0,0);
		if(rc<0)
			return rc;
		rc=Crypt_VerifyPacket(keypos.ptr,keypos.len,0,0,cakey,di.userid1,&sig,eng);

		if(rc)
			return rc;
	}

	strcpy(key->userid,di.userid1);
		
	return 0;
}
int Crypt_ReadPublicKey2(const char* src,int nsrc,IPRIV_KEY_BODY* key)
{
//	memset((char*)key,0,sizeof(*key));

	MemBuf body(2048);
	if(!body.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;

	int blen=radix64decode(src,nsrc,body.getptr(),body.getlen());
	if(blen<=0)
		return CRYPT_ERR_RADIX_DECODE;

	int rc=read_packet(body.getptr(),blen,key,0,0,key->userid,sizeof(key->userid),0);
	if(rc<0)
		return rc;

	return 0;
}

int Crypt_WritePublicKey(char * dst, int ndst, IPRIV_KEY_BODY * key, IPRIV_KEY * cakey, IPRIV_ENGINE * eng, IPRIV_ENGINE * ca_eng)
{
	MemBuf body(2048);
	MemBuf sign(2048);
	if(!body.getlen() || !sign.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;

	doc_info di;

	MemBuf temp(2048);
	if(!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;
		
	IPRIV_POSITION keypos={0,0};
	int rc=write_packet(temp.getptr(),temp.getlen(),key,0,0,key->userid,&keypos,0,0);
	if(rc<=0)
		return rc;
	di.strip_doc_len=rc;
	
	rc=radix64encode(temp.getptr(),rc,body.getptr(),body.getlen());
	if(rc<=0)
		return CRYPT_ERR_RADIX_ENCODE;
	di.doc=body.getptr();
	di.doc_len=rc;

	IPRIV_SIGNATURE sig;
	memset((char*)&sig,0,sizeof(sig));
	if(cakey)
	{
		rc = Crypt_SignPacket(keypos.ptr, keypos.len, cakey, sign.getptr(), sign.getlen(), key->userid, &sig, ca_eng, IPRIV_ALG_MD5);
		if(rc<0)
			return rc;
		di.sig=sign.getptr();
		di.sig_len=rc;
	}else
	{
		di.sig="";
		di.sig_len=0;
	}

	di.version=1;
	strcpy(di.type,"NS");
	strcpy(di.userid1,key->userid);
	di.keyserial1=key->keyserial;
	if(cakey)
	{
		strcpy(di.userid2,sig.userid);
		di.keyserial2=sig.keyserial;
	}else
	{
		*di.userid2=0;
		di.keyserial2=0;
	}

	return ArmorDoc(dst,ndst,&di);
}

static const unsigned char crypt_md5_asn1_tag[] =
        { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };

static const unsigned char crypt_sha1_asn1_tag[] =
        { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };

static const unsigned char crypt_sha256_asn1_tag[] =
        { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

static const unsigned char crypt_sha384_asn1_tag[] =
        { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };

static const unsigned char crypt_sha512_asn1_tag[] =
        { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

int Crypt_SignPacket(const char* src,int nsrc,IPRIV_KEY* key,char* dst,int ndst,const char* pubuserid,IPRIV_SIGNATURE* sig,IPRIV_ENGINE* eng,int alg)
{
	if(!eng->secret_key_encrypt)
		return CRYPT_ERR_NOT_SUPPORT;

	IPRIV_SIGNATURE temp_sig;
	if(!sig)
		sig=&temp_sig;

	sig->version=PGP_VER_3;
	sig->type=pubuserid ? PGP_SIG_K0 : PGP_SIG_SM;
	sig->keyserial=key->keyserial;
	strcpy(sig->userid,key->userid);
	sig->timestamp = (unsigned long) time(0);
	Packet::build_signature_extra(sig);
	sig->alg=RSA_ALGORITHM_BYTE;

        unsigned char md[256];
        int md_size=0;

        if(alg==IPRIV_ALG_MD5)
        {
            sig->hash_alg=MD5_ALGORITHM_BYTE;

            md_size=sizeof(crypt_md5_asn1_tag)+MD5_DIGEST_SIZE;

            memcpy(md,crypt_md5_asn1_tag,sizeof(crypt_md5_asn1_tag));

            MD5_CTX ctx;
            MD5_Init(&ctx);
            MD5_Update(&ctx, (unsigned char*) src, nsrc);
            if (pubuserid)
                MD5_Update(&ctx, (unsigned char*) pubuserid, strlen(pubuserid));
            MD5_Update(&ctx, sig->extra, sig->extra_len);
            MD5_Final(md + sizeof(crypt_md5_asn1_tag), &ctx);

            memcpy(sig->md_low,md+sizeof(crypt_md5_asn1_tag),MAX_MD_LOW_SIZE);
        }else if(alg==IPRIV_ALG_SHA256)
        {
            sig->hash_alg=SHA256_ALGORITHM_BYTE;

            md_size=sizeof(crypt_sha256_asn1_tag)+SHA256_DIGEST_SIZE;

            memcpy(md,crypt_sha256_asn1_tag,sizeof(crypt_sha256_asn1_tag));

            SHA256_CTX ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, (unsigned char*) src, nsrc);
            if (pubuserid)
                sha256_update(&ctx, (unsigned char*) pubuserid, strlen(pubuserid));
            sha256_update(&ctx, sig->extra, sig->extra_len);
            sha256_final(&ctx, md + sizeof(crypt_sha256_asn1_tag));

            memcpy(sig->md_low,md+sizeof(crypt_sha256_asn1_tag),MAX_MD_LOW_SIZE);
        }else
            return CRYPT_ERR_UNKNOWN_ALG;


	int rc=eng->secret_key_encrypt(md,md_size,sig->mpi,sizeof(sig->mpi),key);
	if(rc)
		return rc;


	sig->bits=Packet::calc_bit_count(sig->mpi,sizeof(sig->mpi));


	if(dst && ndst>0)
	{
		MemBuf temp(2048);
		if(!temp.getlen())
			return CRYPT_ERR_OUT_OF_MEMORY;

		rc=write_packet(temp.getptr(),temp.getlen(),0,0,sig,0,0,0,0);
		if(rc<=0)
			return 0;
	
		rc=radix64encode(temp.getptr(),rc,dst,ndst);
		if(rc<=0)
			return CRYPT_ERR_RADIX_ENCODE;
		return rc;
	}

	return 0;
}
int Crypt_VerifyPacket(const char* src,int nsrc,const char* sigsrc,int nsigsrc,IPRIV_KEY* key,const char* pubuserid,IPRIV_SIGNATURE* sig,IPRIV_ENGINE* eng)
{
	if(!eng->public_key_decrypt_and_verify)
		return CRYPT_ERR_NOT_SUPPORT;

	IPRIV_SIGNATURE temp_sig;
	if(!sig)
	{
		sig=&temp_sig;
		memset((char*)&temp_sig,0,sizeof(temp_sig));
	}
	if(sigsrc && nsigsrc>0)
	{
		MemBuf temp(2048);
		if(!temp.getlen())
			return CRYPT_ERR_OUT_OF_MEMORY;
		int n=radix64decode(sigsrc,nsigsrc,temp.getptr(),temp.getlen());
		if(n<=0)
			return CRYPT_ERR_RADIX_DECODE;

		n=read_packet(temp.getptr(),n,0,0,sig,0,0,0);
		if(n<0)
			return n;
	}
	

        unsigned char md[256];
        int md_size=0;

        if(sig->hash_alg==SHA256_ALGORITHM_BYTE)
        {
            md_size=sizeof(crypt_sha256_asn1_tag)+SHA256_DIGEST_SIZE;

            memcpy(md,crypt_sha256_asn1_tag,sizeof(crypt_sha256_asn1_tag));

            SHA256_CTX ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, (unsigned char*) src, nsrc);
            if (pubuserid)
                sha256_update(&ctx, (unsigned char*) pubuserid, strlen(pubuserid));
            sha256_update(&ctx, sig->extra, sig->extra_len);
            sha256_final(&ctx,md + sizeof(crypt_sha256_asn1_tag));

            if(memcmp(sig->md_low,md+sizeof(crypt_sha256_asn1_tag),MAX_MD_LOW_SIZE))
                return CRYPT_ERR_VERIFY;
        }else if(sig->hash_alg==MD5_ALGORITHM_BYTE)
        {
            md_size=sizeof(crypt_md5_asn1_tag)+MD5_DIGEST_SIZE;

            memcpy(md,crypt_md5_asn1_tag,sizeof(crypt_md5_asn1_tag));

            MD5_CTX ctx;
            MD5_Init(&ctx);
            MD5_Update(&ctx, (unsigned char*) src, nsrc);
            if (pubuserid)
                MD5_Update(&ctx, (unsigned char*) pubuserid, strlen(pubuserid));
            MD5_Update(&ctx, sig->extra, sig->extra_len);
            MD5_Final(md + sizeof(crypt_md5_asn1_tag), &ctx);

            if(memcmp(sig->md_low,md+sizeof(crypt_md5_asn1_tag),MAX_MD_LOW_SIZE))
                return CRYPT_ERR_VERIFY;
        }else
            return CRYPT_ERR_UNKNOWN_ALG;

        return eng->public_key_decrypt_and_verify(sig->mpi,sizeof(sig->mpi),md,md_size,key);
}
