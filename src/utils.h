#ifndef UTILS_H
#define UTILS_H

#include "main.h"
#define SERVER_MODE 0
#define CLIENT_MODE 1
/** 
* get_line
* utility to safely read from a stream into a buffer with a max size
*
* taken from http://home.datacomm.ch/t_wolf/tw/c/getting_input.html 
*/
char *get_line (char *s, size_t n, FILE *f);
void usage(char * program_name, int mode);

#endif
