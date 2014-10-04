#ifndef ISAAC_ENCRYPTION_H
#define ISAAC_ENCRYPTION_H

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#ifdef _MSC_VER
  typedef unsigned __int32 uint32_t;
#else
  #include <stdint.h>
#endif
 
/* a ub4 is an unsigned 4-byte quantity */
typedef  uint32_t  ub4;
 
/* external results */
ub4 randrsl[256], randcnt;
 
/* internal state */
static    ub4 mm[256];
static    ub4 aa=0, bb=0, cc=0;

/* if (flag!=0), then use the contents of randrsl[] to initialize mm[]. */
#define mix(a,b,c,d,e,f,g,h) \
{ \
   	a^=b<<11; d+=a; b+=c; \
   	b^=c>>2;  e+=b; c+=d; \
   	c^=d<<8;  f+=c; d+=e; \
   	d^=e>>16; g+=d; e+=f; \
   	e^=f<<10; h+=e; f+=g; \
   	f^=g>>4;  a+=f; g+=h; \
   	g^=h<<8;  b+=g; h+=a; \
   	h^=a>>9;  c+=h; a+=b; \
}
#define MAXMSG 4096
#define MOD 95
#define START 32
// cipher modes for Caesar
enum ciphermode {
	mEncipher, mDecipher, mNone 
};

void isaac();
void randinit(int flag);
ub4 iRandom();
char iRandA();
void iSeed(char *seed, int flag);
char Caesar(enum ciphermode m, char ch, char shift, char modulo, char start);
char* DecryptCaesar(enum ciphermode m, char *msg, char modulo, char start);


#endif