#include "main.h"


int main (int argc, char **argv){
	char c;
	int port=0, server=0, daemon=0;
	char host[80];
	char command[BUF_LENGTH];
	int b_command = 0, b_host = 0;
	
	while ((c = getopt (argc, argv, "dsa:p:c:")) != -1){
		switch (c){
			//client switches
			case 'p':
				port= atoi(optarg);
			break;
			case 'a':
				strncpy(host, optarg,79); 
				b_host = 1;
			break;
			case 'c':
				strncpy(command, optarg, BUF_LENGTH -1); 
				b_command = 1;
			break;
			//server switches
			case 's':
				server = 1;
			break;
			case 'd':
				daemon = 1;
			break;
			
			case '?':
			default:
				usage();
				return 1;
		}
	}
	
	if(server == 0){
		if(b_command==0 || b_host == 0){
			usage();
		}
		if(port ==0){
			srand (time(NULL));
			port = rand()%1000+1025 ;
		}
		startClient(host, port, command);
		
	} else {
		//rename program
		//rename(argv);
		//initServer();
		//startServer();
	}
	return 0;
}
