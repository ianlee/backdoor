#ifndef BACKDOOR_CLIENT_H
#define BACKDOOR_CLIENT_H

#include "main.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>



#define BUF_LENGTH 300


int startClient( char* host, int port, char* command);

#endif
