#include "isaac_encryption.h"

/* Code borrowed from Rosetta Code (http://rosettacode.org/wiki/The_ISAAC_Cipher) */

/* internal state */
static    ub4 mm[256];
static    ub4 aa=0, bb=0, cc=0;
void isaac()
{
	register ub4 i,x,y;
 
	cc = cc + 1;    /* cc just gets incremented once per 256 results */
	bb = bb + cc;   /* then combined with bb */
 
	for (i=0; i<256; ++i)
	{
		x = mm[i];
		switch (i%4)
		{
			case 0: aa = aa^(aa<<13); break;
			case 1: aa = aa^(aa>>6); break;
			case 2: aa = aa^(aa<<2); break;
			case 3: aa = aa^(aa>>16); break;
		}
		aa              = mm[(i+128)%256] + aa;
		mm[i]      = y  = mm[(x>>2)%256] + aa + bb;
		randrsl[i] = bb = mm[(y>>10)%256] + x;
	}
	// not in original readable.c
	randcnt = 0;
}

ub4 iRandom()
{
	ub4 r = randrsl[randcnt];
	++randcnt;
	if (randcnt >255) {
		isaac();
		randcnt = 0;
	}
	return r;
}
 
 
// Get a random character in printable ASCII range
char iRandA()
{	
	return iRandom() % 95 + 32;
}

// Caesar-shift a printable character
char Caesar(enum ciphermode m, char ch, char shift, char modulo, char start)
{
	register int n;
	if (m == mDecipher) shift = -shift;
	n = (ch-start) + shift;
	n = n % modulo;
	if (n<0) n += modulo;
	return start+n;
}
 
// Caesar-shift a string on a pseudo-random stream
char c[MAXMSG];
char* DecryptCaesar(enum ciphermode m, char *msg, char modulo, char start)
{
	register ub4 i,l;
	l = strlen(msg);
	// zeroise c
	memset(c,'\0',l+1);
	// Caesar-shift message
	for (i=0; i<l; i++) 
		c[i] = Caesar(m, msg[i], iRandA(), modulo, start);
	return c;
}