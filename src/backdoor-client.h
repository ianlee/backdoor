#ifndef BACKDOOR_CLIENT_H
#define BACKDOOR_CLIENT_H

#include "pktcap.h"
#include "utils.h"
#include "lib/isaac_encryption.h"

#define BUF_LENGTH 512
#define TRUE 1
#define FALSE 0
#define DEFAULT_PORT 8080
#define USER_ROOT 0

struct client
{
	char * 	server_host;
	int	dst_port;
	char * 	command;
	char *	password;

} client;

int startClient();
int parse_options(int argc, char **argv);
void print_client_info();
void * process_user (void * arg);


#endif
