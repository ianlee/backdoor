#include "isaac_encryption.h"

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

void randinit(int flag)
{
	register int i;
	ub4 a,b,c,d,e,f,g,h;
	aa=bb=cc=0;
	a=b=c=d=e=f=g=h=0x9e3779b9;  /* the golden ratio */
	 
	for (i=0; i<4; ++i)          /* scramble it */
	{
		mix(a,b,c,d,e,f,g,h);
	}
	 
	for (i=0; i<256; i+=8)   /* fill in mm[] with messy stuff */
	{
		if (flag)                  /* use all the information in the seed */
		{
		       a+=randrsl[i  ]; b+=randrsl[i+1]; c+=randrsl[i+2]; d+=randrsl[i+3];
		       e+=randrsl[i+4]; f+=randrsl[i+5]; g+=randrsl[i+6]; h+=randrsl[i+7];
		}
		mix(a,b,c,d,e,f,g,h);
		mm[i  ]=a; mm[i+1]=b; mm[i+2]=c; mm[i+3]=d;
		mm[i+4]=e; mm[i+5]=f; mm[i+6]=g; mm[i+7]=h;
	}
	 
	if (flag)
	{       /* do a second pass to make all of the seed affect all of mm */
		for (i=0; i<256; i+=8)
	     	{
		       	a+=mm[i  ]; b+=mm[i+1]; c+=mm[i+2]; d+=mm[i+3];
		       	e+=mm[i+4]; f+=mm[i+5]; g+=mm[i+6]; h+=mm[i+7];
		       	mix(a,b,c,d,e,f,g,h);
		       	mm[i  ]=a; mm[i+1]=b; mm[i+2]=c; mm[i+3]=d;
		       	mm[i+4]=e; mm[i+5]=f; mm[i+6]=g; mm[i+7]=h;
	     	}
	}
	 
	isaac();            /* fill in the first set of results */
	randcnt=0;        /* prepare to use the first set of results */
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
 
 
// Seed ISAAC with a string
void iSeed(char *seed, int flag)
{
	register ub4 i,m;
	for (i=0; i<256; i++) mm[i]=0;
	m = strlen(seed);
	for (i=0; i<256; i++)
	{
		// in case seed has less than 256 elements
        	if (i>m) randrsl[i]=0;  else randrsl[i] = seed[i];
	}
	// initialize ISAAC with seed
	randinit(flag);
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