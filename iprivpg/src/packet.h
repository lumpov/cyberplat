/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/


#ifndef __PACKET_H
#define __PACKET_H

#include "memfile.h"
#include "idea.h"
#include "libipriv.h"
#include "ipriv.h"

#define PGP_TAG_SESSION_KEY_PE	1			// Public-Key Encrypted Session Key Packet
#define PGP_TAG_SIGNATURE	2			// Signature Packet
#define PGP_TAG_SESSION_KEY_SE	3			// Symmetric-Key Encrypted Session Key Packet
#define PGP_TAG_SIGNATURE_OP	4			// One-Pass Signature Packet
#define PGP_TAG_SECRET_KEY	IPRIV_KEY_TAG_SECRET	// Secret Key Packet
#define PGP_TAG_PUBLIC_KEY	IPRIV_KEY_TAG_PUBLIC	// Public Key Packet
#define PGP_TAG_COMP_DATA	8			// Compressed Data Packet
#define PGP_TAG_SYM_ENC_DATA	9			// Symmetrically Encrypted Data Packet
#define PGP_TAG_MARKER		10			// Marker Packet
#define PGP_TAG_LITERAL_DATA	11			// Literal Data Packet
#define PGP_TAG_TRUST		12			// Keyring trust packet
#define PGP_TAG_USER_ID		13			// User ID Packet

#define PGP_SIG_SB		0x00			// Signature of a binary msg or doc
#define PGP_SIG_SM		0x01			// Signature of canonical msg or doc
#define PGP_SIG_K0		0x10			// Key certification, generic

#define PGP_VER_2		2
#define PGP_VER_3		3

#define RSA_ALGORITHM_BYTE	1
#define IDEA_ALGORITHM_BYTE	1
#define MD5_ALGORITHM_BYTE	1
#define SHA1_ALGORITHM_BYTE	2
#define SHA256_ALGORITHM_BYTE	8
#define SHA384_ALGORITHM_BYTE	9
#define SHA512_ALGORITHM_BYTE	10
#define SHA224_ALGORITHM_BYTE	11

#define bits2bytes(n) (((n)+7) >> 3)

typedef IPRIV_SIGNATURE pgp_signature;
typedef IPRIV_KEY_BODY pgp_key;

typedef struct
{
	short level;
	short amount;
}pgp_trust;

#define PACKET_ERR_PACKETFORMAT	CRYPT_ERR_INVALID_PACKET_FORMAT
#define PACKET_ERR_PACKETVER	CRYPT_ERR_INVALID_PACKET_FORMAT
#define PACKET_ERR_LENTYPE	CRYPT_ERR_INVALID_PACKET_FORMAT
#define PACKET_ERR_ALG		CRYPT_ERR_UNKNOWN_ALG
#define PACKET_ERR_KEYLEN	CRYPT_ERR_INVALID_KEYLEN
#define PACKET_ERR_PASSWD	CRYPT_ERR_INVALID_PASSWD
#define PACKET_ERR_OUTOFMEM	CRYPT_ERR_OUT_OF_MEMORY

class Packet : public MemFile
{
private:
	int type;

	uint8 read_u1(void);
	uint16 read_u2(void);
	uint32 read_u4(void);
	void write_u1(uint8 v);
	void write_u2(uint16 v);
	void write_u4(uint32 v);
	int read_mpi(unsigned char* dst, int ndst, IdeaCfbContext *cfb, uint16* crc);
	int write_mpi(unsigned char* src, int nsrc,IdeaCfbContext *cfb, uint16* crc);

	uint16 checksum(unsigned char * ptr, int nptr);

	int read_key2(pgp_key* k,IdeaCfbContext* cfb);
	int write_key2(pgp_key* k,IdeaCfbContext* cfb,unsigned char* iv,int niv);
public:
	int get_next_packet(Packet* p);
	int read_signature(pgp_signature* s);		// 2
	int read_key(pgp_key* k,const char* passwd);	// 5,6
	int read_cke(unsigned char *ideakey, unsigned char *dst, int ndst);	// 9
	int read_trust(pgp_trust* t);			// 12
	int read_userid(char* dst,int ndst);		// 13

	int set_next_packet(Packet* p);
	int write_pke(pgp_key *k, unsigned char *idea, int nidea);
	int write_signature(pgp_signature* s);
	int write_key(pgp_key* k,const char* passwd,unsigned char* iv,int niv);
	int write_cke(unsigned char *ideakey, unsigned char *src, int nsrc);
	int write_trust(pgp_trust* t);
	int write_userid(const char* src,int nsrc);


public:
	Packet(void){type=0;}
	Packet(char* p,long l,int h):MemFile(p,l,h){type=0;}
	Packet(MemBuf* m,int h):MemFile(m->getptr(),m->getlen(),h){type=0;}
	
	int get_type(void){return type;}
	void set_type(int t){type=t;}

	static int build_signature_extra(pgp_signature* s);
	static void MD5(const char *src, int nsrc, char *dst);
	static int calc_bit_count(const unsigned char * src, int nsrc);

	void read_packet(pgp_key* key,const char* passwd,pgp_signature* sig,char* userid,int userid_len,IPRIV_POSITION* keypos);
	void write_packet(pgp_key* key,const char* passwd,pgp_signature* sig,char* userid,char* temp,int temp_len,IPRIV_POSITION* keypos,unsigned char* iv,int niv);
};

int read_packet(const char* src,int nsrc,pgp_key* key,const char* passwd,pgp_signature* sig,char* userid,int userid_len,IPRIV_POSITION* keypos);
int write_packet(char* dst,int ndst,pgp_key* key,const char* passwd,pgp_signature* sig,char* userid,IPRIV_POSITION* keypos,unsigned char* iv,int niv);

#endif
