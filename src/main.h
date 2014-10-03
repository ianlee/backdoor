#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <time.h> 


#include "backdoor-client.h"
#include "backdoor-server.h"
#include "utils.h"
#include "pktcap.h"

//remove on production
#ifndef DEBUG
#define DEBUG
#endif
