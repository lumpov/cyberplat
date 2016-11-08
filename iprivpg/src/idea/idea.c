/*
 *    idea.c - C source code for IDEA block cipher.
 *      IDEA (International Data Encryption Algorithm), formerly known as
 *      IPES (Improved Proposed Encryption Standard).
 *      Algorithm developed by Xuejia Lai and James L. Massey, of ETH Zurich.
 *      This implementation modified and derived from original C code
 *      developed by Xuejia Lai.
 *      Zero-based indexing added, names changed from IPES to IDEA.
 *      CFB functions added.  Random number routines added.
 *
 *      Extensively optimized and restructured by Colin Plumb.
 *
 *      There are two adjustments that can be made to this code to
 *      speed it up.  Defaults may be used for PCs.  Only the -DIDEA32
 *      pays off significantly if selectively set or not set.
 *      Experiment to see what works best for your machine.
 *
 *      Multiplication: default is inline, -DAVOID_JUMPS uses a
 *              different version that does not do any conditional
 *              jumps (a few percent worse on a SPARC), while
 *              -DSMALL_CACHE takes it out of line to stay
 *              within a small on-chip code cache.
 *      Variables: normally, 16-bit variables are used, but some
 *              machines (notably RISCs) do not have 16-bit registers,
 *              so they do a great deal of masking.  -DIDEA32 uses "int"
 *              register variables and masks explicitly only where
 *              necessary.  On a SPARC, for example, this boosts
 *              performace by 30%.
 *
 *      The IDEA(tm) block cipher is covered by patents held by ETH and a
 *      Swiss company called Ascom-Tech AG.  The Swiss patent number is
 *      PCT/CH91/00117, the European patent number is EP 0 482 154 B1, and
 *      the U.S. patent number is US005214703.  IDEA(tm) is a trademark of
 *      Ascom-Tech AG.  There is no license fee required for noncommercial
 *      use.  Commercial users may obtain licensing details from Dieter
 *      Profos, Ascom Tech AG, Solothurn Lab, Postfach 151, 4502 Solothurn,
 *      Switzerland, Tel +41 65 242885, Fax +41 65 235761.
 *
 *      The IDEA block cipher uses a 64-bit block size, and a 128-bit key
 *      size.  It breaks the 64-bit cipher block into four 16-bit words
 *      because all of the primitive inner operations are done with 16-bit
 *      arithmetic.  It likewise breaks the 128-bit cipher key into eight
 *      16-bit words.
 *
 *      For further information on the IDEA cipher, see the book:
 *        Xuejia Lai, "On the Design and Security of Block Ciphers",
 *        ETH Series on Information Processing (ed. J.L. Massey) Vol 1,
 *        Hartung-Gorre Verlag, Konstanz, Switzerland, 1992.  ISBN
 *        3-89191-573-X.
 *
 *      This code runs on arrays of bytes by taking pairs in big-endian
 *      order to make the 16-bit words that IDEA uses internally.  This
 *      produces the same result regardless of the byte order of the
 *      native CPU.
 */

#include <string.h>
#include "idea.h"

#ifdef __linux
#include <endian.h> 
#if __BYTE_ORDER == __BIG_ENDIAN	// SPARC, Motorola, PowerPC
#define IS_BIGENDIAN	1
#endif
#endif

#ifdef MACTC5
#include <string.h>
#define IDEA32
#define SMALL_CACHE
#define USE68ASM
void ideaCipher(byte const inbuf[8], byte outbuf[8],
		       word16 const *key);
#endif

#ifdef IDEA32			/* Use >16-bit temporaries */
#define low16(x) ((x) & 0xFFFF)
typedef unsigned int uint16;	/* at LEAST 16 bits, maybe more */
#else
#define low16(x) (x)		/* this is only ever applied to uint16's */
typedef word16 uint16;
#endif

#ifdef _GNUC_
/* __const__ simply means there are no side effects for this function,
 * which is useful info for the gcc optimizer
 */
#define CONST __const__
#else
#define CONST
#endif

/*
 * Multiplication, modulo (2**16)+1
 * Note that this code is structured on the assumption that
 * untaken branches are cheaper than taken branches, and the
 * compiler doesn't schedule branches.
 */
#ifdef SMALL_CACHE

CONST static uint16
 mul(register uint16 a, register uint16 b)
{
    register word32 p;

    p = (word32) a *b;
    if (p) {
	b = low16(p);
	a = p >> 16;
	return (b - a) + (b < a);
    } else if (a) {
	return 1 - a;
    } else {
	return 1 - b;
    }
}				/* mul */
#endif			/* SMALL_CACHE */


/*
 * Expand a 128-bit user key to a working encryption key EK
 */
static void ideaExpandKey(byte const *userkey, word16 * EK)
{
    int i, j;

    for (j = 0; j < 8; j++) {
	EK[j] = (userkey[0] << 8) + userkey[1];
	userkey += 2;
    }
    for (i = 0; j < IDEAKEYLEN; j++) {
	i++;
	EK[i + 7] = EK[i & 7] << 9 | EK[(i + 1) & 7] >> 7;
	EK += i & 8;
	i &= 7;
    }
}				/* ideaExpandKey */


/*
 * MUL(x,y) computes x = x*y, modulo 0x10001.  Requires two temps,
 * t16 and t32.  x is modified, and must be a side-effect-free lvalue.
 * y may be anything, but unlike x, must be strictly less than 65536
 * even if low16() is #defined.
 * All of these are equivalent - see which is faster on your machine
 */
#ifdef SMALL_CACHE
#define MUL(x,y) (x = mul(low16(x),y))
#else				/* !SMALL_CACHE */
#ifdef AVOID_JUMPS
#define MUL(x,y) (x = low16(x-1), t16 = low16((y)-1), \
		t32 = (word32)x*t16 + x + t16, x = low16(t32), \
		t16 = t32>>16, x = (x-t16) + (x<t16) + 1)
#else				/* !AVOID_JUMPS (default) */
#define MUL(x,y) \
	((t16 = (y)) ? \
		(x=low16(x)) ? \
			t32 = (word32)x*t16, \
			x = low16(t32), \
			t16 = t32>>16, \
			x = (x-t16)+(x<t16) \
		: \
			(x = 1-t16) \
	: \
		(x = 1-x))
#endif
#endif

/*      IDEA encryption/decryption algorithm */
/* Note that in and out can be the same buffer */
#ifndef USE68ASM
static void ideaCipher(byte const inbuf[8], byte outbuf[8],
		       word16 const *key)
{
    register uint16 x1, x2, x3, x4, s2, s3;
    word16 *in, *out;
#ifndef SMALL_CACHE
    register uint16 t16;	/* Temporaries needed by MUL macro */
    register word32 t32;
#endif
    int r = IDEAROUNDS;

    in = (word16 *) inbuf;
    x1 = *in++;
    x2 = *in++;
    x3 = *in++;
    x4 = *in;
#ifndef IS_BIGENDIAN
    x1 = (x1 >> 8) | (x1 << 8);
    x2 = (x2 >> 8) | (x2 << 8);
    x3 = (x3 >> 8) | (x3 << 8);
    x4 = (x4 >> 8) | (x4 << 8);
#endif
    do {
	MUL(x1, *key++);
	x2 += *key++;
	x3 += *key++;
	MUL(x4, *key++);

	s3 = x3;
	x3 ^= x1;
	MUL(x3, *key++);
	s2 = x2;
	x2 ^= x4;
	x2 += x3;
	MUL(x2, *key++);
	x3 += x2;

	x1 ^= x2;
	x4 ^= x3;

	x2 ^= s3;
	x3 ^= s2;
    } while (--r);
    MUL(x1, *key++);
    x3 += *key++;
    x2 += *key++;
    MUL(x4, *key);

    out = (word16 *) outbuf;
#ifdef IS_BIGENDIAN
    *out++ = x1;
    *out++ = x3;
    *out++ = x2;
    *out = x4;
#else				/* !IS_BIGENDIAN */
    x1 = low16(x1);
    x2 = low16(x2);
    x3 = low16(x3);
    x4 = low16(x4);
    *out++ = (x1 >> 8) | (x1 << 8);
    *out++ = (x3 >> 8) | (x3 << 8);
    *out++ = (x2 >> 8) | (x2 << 8);
    *out = (x4 >> 8) | (x4 << 8);
#endif
}				/* ideaCipher */
#endif			/* USE68ASM */

/*-------------------------------------------------------------*/



/*************************************************************************/

void ideaCfbReinit(struct IdeaCfbContext *context, byte const *iv)
{
    if (iv)
	memcpy(context->iv, iv, 8);
    else
	fill0(context->iv, 8);
    context->bufleft = 0;
}

void ideaCfbInit(struct IdeaCfbContext *context, byte const key[16])
{
    ideaExpandKey(key, context->key);
    ideaCfbReinit(context, 0);
}

void ideaCfbDestroy(struct IdeaCfbContext *context)
{
    burn(*context);
}

/*
 * Okay, explanation time:
 * Phil invented a unique way of doing CFB that's sensitive to semantic
 * boundaries within the data being encrypted.  One way to phrase
 * CFB en/decryption is to say that you XOR the current 8 bytes with
 * IDEA(previous 8 bytes of ciphertext).  Normally, you repeat this
 * at 8-byte intervals, but Phil decided to resync things on the
 * boundaries between elements in the stream being encrypted.
 *
 * That is, the last 4 bytes of a 12-byte field are en/decrypted using
 * the first 4 bytes of IDEA(previous 8 bytes of ciphertext), but then
 * the last 4 bytes of that IDEA computation are thrown away, and the
 * first 8 bytes of the next field are en/decrypted using
 * IDEA(last 8 bytes of ciphertext).  This is equivalent to using a
 * shorter feedback length (if you're familiar with the general CFB
 * technique) briefly, and doesn't weaken the cipher any (using shorter
 * CFB lengths makes it stronger, actually), it just makes it a bit unusual.
 *
 * Anyway, to accomodate this behaviour, every time we do an IDEA
 * encrpytion of 8 bytes of ciphertext to get 8 bytes of XOR mask,
 * we remember the ciphertext.  Then if we have to resync things
 * after having processed, say, 2 bytes, we refill the iv buffer
 * with the last 6 bytes of the old ciphertext followed by the
 * 2 bytes of new ciphertext stored in the front of the iv buffer.
 */
void ideaCfbSync(struct IdeaCfbContext *context)
{
    int bufleft = context->bufleft;

    if (bufleft) {
	memmove(context->iv + bufleft, context->iv, 8 - bufleft);
	memcpy(context->iv, context->oldcipher + 8 - bufleft, bufleft);
	context->bufleft = 0;
    }
}

/*
 * Encrypt a buffer of data, using IDEA in CFB mode.
 * There are more compact ways of writing this, but this is
 * written for speed.
 */
void ideaCfbEncrypt(struct IdeaCfbContext *context, byte const *src,
		    byte * dest, int count)
{
    int bufleft = context->bufleft;
    byte *bufptr = context->iv + 8 - bufleft;

    /* If there are no more bytes to encrypt that there are bytes
     * in the buffer, XOR them in and return.
     */
    if (count <= bufleft) {
	context->bufleft = bufleft - count;
	while (count--) {
	    *dest++ = *bufptr++ ^= *src++;
	}
	return;
    }
    count -= bufleft;
    /* Encrypt the first bufleft (0 to 7) bytes of the input by XOR
     * with the last bufleft bytes in the iv buffer.
     */
    while (bufleft--) {
	*dest++ = (*bufptr++ ^= *src++);
    }
    /* Encrypt middle blocks of the input by cranking the cipher,
     * XORing 8-byte blocks, and repeating until the count
     * is 8 or less.
     */
    while (count > 8) {
	bufptr = context->iv;
	memcpy(context->oldcipher, bufptr, 8);
	ideaCipher(bufptr, bufptr, context->key);
	bufleft = 8;
	count -= 8;
	do {
	    *dest++ = (*bufptr++ ^= *src++);
	} while (--bufleft);
    }
    /* Do the last 1 to 8 bytes */
    bufptr = context->iv;
    memcpy(context->oldcipher, bufptr, 8);
    ideaCipher(bufptr, bufptr, context->key);
    context->bufleft = 8 - count;
    do {
	*dest++ = (*bufptr++ ^= *src++);
    } while (--count);
}


/*
 * Decrypt a buffer of data, using IDEA in CFB mode.
 * There are more compact ways of writing this, but this is
 * written for speed.
 */
void ideaCfbDecrypt(struct IdeaCfbContext *context, byte const *src,
		    byte * dest, int count)
{
    int bufleft = context->bufleft;
    /*static byte *bufptr;*/	/* NEED FOR SYMBIAN !!!!!!!!!!!! */
    byte *bufptr;		/* NEED FOR SYMBIAN !!!!!!!!!!!! */

    byte t;

    bufptr = context->iv + (8 - bufleft);
    if (count <= bufleft) {
	context->bufleft = bufleft - count;
	while (count--) {
	    t = *bufptr;
	    *dest++ = t ^ (*bufptr++ = *src++);
	}
	return;
    }
    count -= bufleft;
    while (bufleft--) {
	t = *bufptr;
	*dest++ = t ^ (*bufptr++ = *src++);
    }
    while (count > 8) {
	bufptr = context->iv;
	memcpy(context->oldcipher, bufptr, 8);
	ideaCipher(bufptr, bufptr, context->key);
	bufleft = 8;
	count -= 8;
	do {
	    t = *bufptr;
	    *dest++ = t ^ (*bufptr++ = *src++);
	} while (--bufleft);
    }
    bufptr = context->iv;
    memcpy(context->oldcipher, bufptr, 8);
    ideaCipher(bufptr, bufptr, context->key);
    context->bufleft = 8 - count;
    do {
	t = *bufptr;
	*dest++ = t ^ (*bufptr++ = *src++);
    } while (--count);
}

/********************************************************************/

/*
 * Cryptographically strong pseudo-random-number generator.
 * The design is from Appendix C of ANSI X9.17, "Financial
 * Institution Key Management (Wholesale)", with IDEA
 * substituted for the DES.
 */

/*
 * Initialize a cryptographic random-number generator.
 * key and seed should be arbitrary.
 */
void ideaRandInit(struct IdeaRandContext *context, byte const key[16],
		  byte const seed[8])
{
    ideaExpandKey(key, context->key);
    context->bufleft = 0;
    memcpy(context->internalbuf, seed, 8);
}


/*
 * Read out the RNG's state.
 */
void ideaRandState(struct IdeaRandContext *context, byte key[16], byte seed[8])
{
    int i;

    memcpy(seed, context->internalbuf, 8);
    for (i = 0; i < 8; i++) {
	key[2 * i] = context->key[i] >> 8;
	key[2 * i + 1] = (byte) context->key[i];
    }

}

/*
 * Encrypt the RNG's state with the given CFB encryptor.
 */
void ideaRandWash(struct IdeaRandContext *context, struct IdeaCfbContext *cfb)
{
    byte keyseed[16 + 8];

    ideaRandState(context, keyseed, keyseed + 16);
    ideaCfbEncrypt(cfb, keyseed, keyseed, 16 + 8);
    ideaRandInit(context, keyseed, keyseed + 16);

    memset(keyseed, 0, 16 + 8);
}


/* end of idea.c */
