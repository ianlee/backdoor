#ifndef UTILS_H
#define UTILS_H

#include "main.h"

/** 
* get_line
* utility to safely read from a stream into a buffer with a max size
*
* taken from http://home.datacomm.ch/t_wolf/tw/c/getting_input.html 
*/
char *get_line (char *s, size_t n, FILE *f);
void usage();

#endif
