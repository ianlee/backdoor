#ifndef PKTCAP_H
#define PKTCAP_H

#include "utils.h"

#define NETWORK_INT "em1"
#define PKT_SIZE 1500
#define BUFFER 100

int startPacketCapture();
int stopPacketCapture();

#endif
