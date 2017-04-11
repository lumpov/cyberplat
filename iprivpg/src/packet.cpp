/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

#include "packet.h"
#include <string.h>
#include <time.h>
#ifndef WITH_OPENSSL
#include "md5.h"
#else
#include <openssl/md5.h>
#endif


uint16 Packet::checksum(unsigned char *ptr, int nptr)
{
	uint16 cs = 0;

	while (nptr--)
		cs += *ptr++;
	return cs;
}

int Packet::calc_bit_count(const unsigned char *src, int nsrc)
{
	int i, j;

	for (i = 0; i < nsrc; i++)
		if (src[i])
			break;

	if (i >= nsrc)
		return 0;

	unsigned char b = src[i];

	for (j = 0; j < 8; j++) {
		if (b & 0x80)
			break;
		b <<= 1;
	}
	int bits = (nsrc - i - 1) * 8 + (8 - j);

	return bits;
}

void Packet::MD5(const char *src, int nsrc, char *dst)
{
	MD5_CTX mdContext;

	MD5_Init(&mdContext);
	MD5_Update(&mdContext, (unsigned char *) src, nsrc);
	MD5_Final((unsigned char *) dst, &mdContext);
}

uint8 Packet::read_u1(void)
{
	uint8 rc;

	read_n((char *) &rc, sizeof(rc));
	return rc;
}

uint16 Packet::read_u2(void)
{
	uint16 rc;

	read_n((char *) &rc, sizeof(rc));
	return rotate16(rc);
}

uint32 Packet::read_u4(void)
{
	uint32 rc;

	read_n((char *) &rc, sizeof(rc));
	return rotate32(rc);
}

void Packet::write_u1(uint8 v)
{
	write_n((char *) &v, sizeof(v));
}

void Packet::write_u2(uint16 v)
{
	uint16 t = rotate16(v);
	write_n((char *) &t, sizeof(t));
}

void Packet::write_u4(uint32 v)
{
	uint32 t = rotate32(v);
	write_n((char *) &t, sizeof(t));
}

int Packet::write_mpi(unsigned char *src, int nsrc, IdeaCfbContext *cfb, uint16 *crc)
{
	uint16 nbits = calc_bit_count(src, nsrc);
	int n = bits2bytes(nbits);

	uint16 _nbits = rotate16(nbits);

	write_n((char *) &_nbits, sizeof(_nbits));

	if (!nbits)
		return nbits;

	unsigned char *mpi = src + nsrc - n;

	if (crc)
		*crc += checksum((unsigned char *) &_nbits, sizeof(_nbits)) + checksum(mpi, n);

	if (cfb) {
		char temp[MAX_MPI_LENGTH];

		ideaCfbSync(cfb);
		ideaCfbEncrypt(cfb, mpi, (unsigned char *) temp, n);
		write_n((char *) temp, n);
	} else
		write_n((char *) mpi, n);

	return nbits;
}

int Packet::read_mpi(unsigned char *dst, int ndst, IdeaCfbContext *cfb, uint16 *crc)
{
	uint16 nbits = 0;

	read_n((char *) &nbits, sizeof(uint16));
	if (crc)
		*crc += checksum((unsigned char *) &nbits, sizeof(uint16));

	nbits = rotate16(nbits);

	int n = bits2bytes(nbits);

	if (!n || n > ndst)
		error(PACKET_ERR_KEYLEN);

	unsigned char *mpi = dst + ndst - n;

	read_n((char *) mpi, n);

	if (cfb) {
		ideaCfbSync(cfb);
		ideaCfbDecrypt(cfb, (unsigned char *) mpi, (unsigned char *) mpi, n);
	}

	if (crc)
		*crc += checksum(mpi, n);

	return nbits;
}

int Packet::set_next_packet(Packet *p)
{
	long pos = tell();

	uint8 ctag = p->get_type();
	uint8 ltype;

	switch (p->get_type()) {
	case PGP_TAG_TRUST:
	case PGP_TAG_USER_ID:
		ltype = 0;
		break;
	default:
		if (p->length() <= 0xffff)
			ltype = 1;
		else
			ltype = 2;
		break;
	}

	uint8 ptag = 0x80 | ((ctag << 2) & 0x3c) | (ltype & 0x03);

	write_u1(ptag);

	switch (ltype) {
	case 0:
		write_u1((uint8) p->length());
		break;
	case 1:
		write_u2((uint16) p->length());
		break;
	case 2:
		write_u4(p->length());
		break;
	}

	p->seek(0, MF_SEEK_SET);
	write_n(p->getptr(), p->length());

	return tell() - pos;
}

int Packet::get_next_packet(Packet *p)
{
	long pos = tell();

	if (length() - pos <= 0)
		return 0;

	uint8 ctag = 0;
	uint32 plen = 0;

	uint8 ptag = read_u1();

	if (!(ptag & 0x80))
		error(PACKET_ERR_PACKETFORMAT);
	if (ptag & 0x40)
		error(PACKET_ERR_PACKETVER);
	ctag = (ptag >> 2) & 0x0f;
	uint8 ltype = ptag & 0x03;

	switch (ltype) {
	case 0:
		plen = read_u1();
		break;
	case 1:
		plen = read_u2();
		break;
	case 2:
		plen = read_u4();
		break;
	default:
		error(PACKET_ERR_LENTYPE);
	}

	if (checklen(plen))
		error(PACKET_ERR_PACKETFORMAT);

	p->attach(getptr(), plen, MF_O_RDONLY);
	p->type = ctag;

	seek(plen, MF_SEEK_CUR);

	return tell() - pos;
}

int Packet::write_userid(const char *src, int nsrc)
{
	if (nsrc < 0)
		nsrc = strlen(src);
	write_n(src, nsrc);
	return nsrc;
}

int Packet::read_userid(char *dst, int ndst)
{
	*dst = 0;
	int len = length();
	int n = len < ndst ? len : ndst - 1;

	memcpy(dst, getptr(), n);
	dst[n] = 0;
	return n;
}

int Packet::build_signature_extra(pgp_signature *s)
{
	if (!s->timestamp)
		s->timestamp = (unsigned long) time(0);
	s->extra_len = sizeof(uint8) + sizeof(uint32) + sizeof(uint32);
	*s->extra = (unsigned char) s->type;

	uint32 tmp = rotate32(s->keyserial);
	memcpy(s->extra + sizeof(uint8), (char *) &tmp, sizeof(tmp));
	tmp = rotate32(s->timestamp);
	memcpy(s->extra + sizeof(uint8) + sizeof(uint32), (char *) &tmp, sizeof(tmp));

	return s->extra_len;
}

int Packet::write_signature(pgp_signature *s)
{
	int pos = tell();

	write_u1((uint8) s->version);

	write_u1((uint8) s->extra_len);
	write_n((char *) s->extra, s->extra_len);

	write_u1((uint8) s->alg);
	write_u1((uint8) s->hash_alg);

	write_n((char *) s->md_low, sizeof(s->md_low));

	write_mpi(s->mpi, MAX_MPI_LENGTH, 0, 0);

	return tell() - pos;
}

int Packet::read_signature(pgp_signature *s)
{
//  memset((char*)s,0,sizeof(*s));

	int pos = tell();

	s->version = read_u1();

//  if (s->version != PGP_VER_2 && s->version != PGP_VER_3)
//      error(PACKET_ERR_PACKETVER);

	s->extra_len = read_u1();

	if (s->extra_len > MAX_EXTRA_DATA_LENGTH)
		error(PACKET_ERR_PACKETFORMAT);

	read_n((char *) s->extra, s->extra_len);

	if (s->extra_len > 0) {
		s->type = *s->extra;
		if (s->extra_len >= (int) (sizeof(uint8) + sizeof(uint32))) {
			memcpy((char *) &s->keyserial, s->extra + sizeof(uint8), sizeof(s->keyserial));
			s->keyserial = rotate32(s->keyserial);
		}
		if (s->extra_len >= (int) (sizeof(uint8) + sizeof(uint32) + sizeof(uint32))) {
			memcpy((char *) &s->timestamp, s->extra + sizeof(uint8) + sizeof(uint32), sizeof(s->timestamp));
			s->timestamp = rotate32(s->timestamp);
		}
	}

	s->alg = read_u1();
	s->hash_alg = read_u1();

//  if (s->alg != RSA_ALGORITHM_BYTE || s->hash_alg != MD5_ALGORITHM_BYTE)
//      error(PACKET_ERR_ALG);

	read_n((char *) s->md_low, sizeof(s->md_low));

	s->bits = read_mpi(s->mpi, MAX_MPI_LENGTH, 0, 0);

	return tell() - pos;
}

int Packet::write_key2(pgp_key *k, IdeaCfbContext *cfb, unsigned char *iv, int niv)
{
	int pos = tell();

	write_u1((uint8) k->version);

	write_u4(k->keyserial);
	write_u4(k->timestamp);
	write_u2(k->validity);
	write_u1((uint8) k->alg);

	write_mpi(k->modulus, MAX_MPI_LENGTH, 0, 0);
	write_mpi(k->publicExponent, MAX_MPI_LENGTH, 0, 0);

	if (type == PGP_TAG_SECRET_KEY) {
		write_u1(cfb ? IDEA_ALGORITHM_BYTE : 0);

		if (cfb) {
			unsigned char _iv[IDEABLOCKSIZE];

			if (niv >= (int) sizeof(_iv))
				memcpy(_iv, iv, sizeof(_iv));
			else {
				uint32 t = (uint32) k->keyserial;
				memcpy(_iv, (char *) &t, sizeof(t));
				t = (uint32) time(0);
				memcpy(_iv + sizeof(t), (char *) &t, sizeof(t));
			}

			ideaCfbSync(cfb);
			ideaCfbEncrypt(cfb, _iv, _iv, sizeof(_iv));
			write_n((char *) _iv, sizeof(_iv));
		}

		uint16 mpi_checksum = 0;

		write_mpi(k->exponent, MAX_MPI_LENGTH, cfb, &mpi_checksum);
		write_mpi(k->prime1, HALF_MPI_LENGTH, cfb, &mpi_checksum);
		write_mpi(k->prime2, HALF_MPI_LENGTH, cfb, &mpi_checksum);
		write_mpi(k->coefficient, MAX_MPI_LENGTH, cfb, &mpi_checksum);

		write_u2(mpi_checksum);
	}

	return tell() - pos;
}

int Packet::write_key(pgp_key *k, const char *passwd, unsigned char *iv, int niv)
{
	if (!passwd || !*passwd)
		return write_key2(k, 0, iv, niv);

	unsigned char pass[MD5_DIGEST_SIZE];
	MD5(passwd, strlen(passwd), (char *) pass);

	IdeaCfbContext cfb;

	ideaCfbInit(&cfb, pass);
	int rc = write_key2(k, &cfb, iv, niv);

	ideaCfbDestroy(&cfb);
	memset(pass, 0, sizeof(pass));

	return rc;
}

int Packet::read_key2(pgp_key *k, IdeaCfbContext *cfb)
{
	int pos = tell();

	k->version = read_u1();
//	if (k->version != PGP_VER_2 && k->version != PGP_VER_3)
//		error(PACKET_ERR_PACKETVER);

	k->keyserial = read_u4();
	k->timestamp = read_u4();
	k->validity = read_u2();
	k->alg = read_u1();
	k->type = type;

	if (k->alg != RSA_ALGORITHM_BYTE)
		error(PACKET_ERR_ALG);

	k->bits = read_mpi(k->modulus, MAX_MPI_LENGTH, 0, 0);
	read_mpi(k->publicExponent, MAX_MPI_LENGTH, 0, 0);

	if (type == PGP_TAG_SECRET_KEY) {
		int alg = read_u1();

		if (alg == IDEA_ALGORITHM_BYTE) {
			if (!cfb)
				error(PACKET_ERR_PASSWD);
		} else if (alg)
			error(PACKET_ERR_ALG);

		if (alg) {
			unsigned char iv[IDEABLOCKSIZE];

			read_n((char *) iv, sizeof(iv));
			ideaCfbDecrypt(cfb, iv, iv, sizeof(iv));
		}

		uint16 mpi_checksum = 0;

		read_mpi(k->exponent, MAX_MPI_LENGTH, cfb, &mpi_checksum);
		read_mpi(k->prime1, HALF_MPI_LENGTH, cfb, &mpi_checksum);
		read_mpi(k->prime2, HALF_MPI_LENGTH, cfb, &mpi_checksum);
		read_mpi(k->coefficient, MAX_MPI_LENGTH, cfb, &mpi_checksum);

		uint16 chksum = read_u2();

		if (chksum != mpi_checksum)
			error(PACKET_ERR_PASSWD);

	}

	return tell() - pos;
}

int Packet::read_key(pgp_key *k, const char *passwd)
{
	if (!passwd || !*passwd)
		return read_key2(k, 0);

	unsigned char pass[MD5_DIGEST_SIZE];

	MD5(passwd, strlen(passwd), (char *) pass);

	IdeaCfbContext cfb;

	ideaCfbInit(&cfb, pass);
	int rc = read_key2(k, &cfb);

	ideaCfbDestroy(&cfb);
	memset(pass, 0, sizeof(pass));

	return rc;
}

int Packet::write_trust(pgp_trust *t)
{
	int pos = tell();

	write_u1((uint8) t->level);
	if (t->level == 1)
		write_u1((uint8) t->amount);

	return tell() - pos;
}

int Packet::read_trust(pgp_trust *t)
{
//  memset((char*)t,0,sizeof(*t));

	int pos = tell();

	t->level = read_u1();
	if (length() > 1 && t->level == 1)
		t->amount = read_u1();

	return tell() - pos;
}

int Packet::write_pke(pgp_key *k, unsigned char *idea, int nidea)
{
	int pos = tell();

	return tell() - pos;
}

int Packet::read_cke(unsigned char *ideakey, unsigned char *dst, int ndst)
{
	int pos = tell();

	return tell() - pos;
}

int Packet::write_cke(unsigned char *ideakey, unsigned char *src, int nsrc)
{
	byte textbuf[IDEAKEYSIZE+2];
	int pos = tell();

	IdeaCfbContext cfb;
	ideaCfbInit(&cfb, ideakey);

	memcpy(textbuf, ideakey+IDEAKEYSIZE, IDEABLOCKSIZE);
	/* key check bytes are simply duplicates of final 2 random bytes */
	textbuf[IDEABLOCKSIZE] = textbuf[IDEABLOCKSIZE-2];
	textbuf[IDEABLOCKSIZE+1] = textbuf[IDEABLOCKSIZE-1];

	ideaCfbEncrypt(&cfb, textbuf, textbuf, IDEABLOCKSIZE+2);
	write_n((char *) textbuf, IDEABLOCKSIZE+2);

	ideaCfbSync(&cfb);

	ideaCfbEncrypt(&cfb, src, src, nsrc);	// destroyng source !!!
	write_n((char *) src, nsrc);

	ideaCfbDestroy(&cfb);
	memset(textbuf, 0, sizeof(textbuf));

	return tell() - pos;
}

void Packet::read_packet(pgp_key *key, const char *passwd, pgp_signature *sig, char *userid, int userid_len,
						 IPRIV_POSITION *keypos)
{
	for (;;) {
		char *ptr = getptr();
		int len;

		Packet p;

		if (!(len = get_next_packet(&p)))
			break;
		switch (p.get_type()) {
		case PGP_TAG_SECRET_KEY:
		case PGP_TAG_PUBLIC_KEY:
			if (keypos) {
				keypos->ptr = ptr;
				keypos->len = len;
			}
			if (key)
				p.read_key(key, passwd);
			break;
		case PGP_TAG_USER_ID:
			if (userid)
				p.read_userid(userid, userid_len);
			break;
		case PGP_TAG_SIGNATURE:
			if (sig)
				p.read_signature(sig);
			break;
		}
	}
}

int read_packet(const char *src, int nsrc, pgp_key *key, const char *passwd, pgp_signature *sig,
				char *userid, int userid_len, IPRIV_POSITION *keypos)
{
	Packet p((char *) src, nsrc, MF_O_RDONLY);
	trap_rc_t rc = 0;

	TRAP(rc, p.read_packet(key, passwd, sig, userid, userid_len, keypos));

	return rc;
}

void Packet::write_packet(pgp_key *key, const char *passwd, pgp_signature *sig, char *userid, char *temp,
					  int temp_len, IPRIV_POSITION *keypos, unsigned char *iv, int niv)
{
	Packet p;

	if (sig) {
		p.attach(temp, temp_len, MF_O_WRONLY);
		p.set_type(PGP_TAG_SIGNATURE);
		p.write_signature(sig);
		set_next_packet(&p);

		p.attach(temp, temp_len, MF_O_WRONLY);
		p.set_type(PGP_TAG_TRUST);
		pgp_trust t = { 0xc7, 0 };
		p.write_trust(&t);
		set_next_packet(&p);

	} else if (key) {
		p.attach(temp, temp_len, MF_O_WRONLY);
		p.set_type(key->type);
		p.write_key(key, passwd, iv, niv);

		char *ptr = getptr();
		int len = set_next_packet(&p);

		if (keypos) {
			keypos->ptr = ptr;
			keypos->len = len;
		}

		if (key->type == PGP_TAG_PUBLIC_KEY) {
			p.attach(temp, temp_len, MF_O_WRONLY);
			p.set_type(PGP_TAG_TRUST);
			pgp_trust t = { 0x87, 0 };
			p.write_trust(&t);
			set_next_packet(&p);
		}

		if (userid) {
			p.attach(temp, temp_len, MF_O_WRONLY);
			p.set_type(PGP_TAG_USER_ID);
			p.write_userid(userid, -1);
			set_next_packet(&p);

			if (key->type == PGP_TAG_PUBLIC_KEY) {
				p.attach(temp, temp_len, MF_O_WRONLY);
				p.set_type(PGP_TAG_TRUST);
				pgp_trust t = { 0x03, 0 };
				p.write_trust(&t);
				set_next_packet(&p);
			}
		}
	}
}

int write_packet(char *dst, int ndst, pgp_key *key, const char *passwd, pgp_signature *sig, char *userid,
				 IPRIV_POSITION *keypos, unsigned char *iv, int niv)
{
	MemBuf temp(ndst + 2048);
	if (!temp.getlen())
		return PACKET_ERR_OUTOFMEM;

	Packet p(dst, ndst, MF_O_WRONLY);
	trap_rc_t rc = 0;

	TRAP(rc, p.write_packet(key, passwd, sig, userid, temp.getptr(), temp.getlen(), keypos, iv, niv));
	if (rc) return rc;

	return p.length();
}
