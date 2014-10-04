#ifndef BACKDOOR_CLIENT_H
#define BACKDOOR_CLIENT_H

#include "pktcap.h"

#define BUF_LENGTH 300
#define TRUE 1
#define FALSE 0
#define DEFAULT_PORT 8080
#define USER_ROOT 0

struct options
{
	char command[BUF_LENGTH];
	char host[80];
	int port;

} user_options;

int startClient( char* host, int port, char* command);

#endif
