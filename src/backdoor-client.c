#include "backdoor-client.h"




int startPacketCapture(){
	//start libpcap and pass in callback function
	return 0;
}
int stopPacketCapture(){
	//stop libpcap?
	return 0;
}
int sendPacket(char* host, int port, char* command){
	#ifdef DEBUG
		printf("host:%s \nport: %d \ncommand: %s\n",host, port, command);
	#endif
	//encode
	
	//send on raw socket
	return 0;
}


int startClient( char* host, int port, char* command){
	//char s[BUF_LENGTH];
	//char *command;
	//int quit = 0;
	
	//start libpcap to display results
	startPacketCapture();
	//while(!quit){
		//read input
		//command = get_line (s, BUF_LENGTH, stdin);
	//	if(strcmp( command, "quit") == 0){
	//		quit = 1;
	//	}
		//send packet
		sendPacket(host, port, command);
		
	//}
	//stopPacketCapture();
	return 0;
}
