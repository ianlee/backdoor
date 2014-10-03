#include "main.h"

int main (int argc, char **argv){
	char c;
	int port = DEFAULT_PORT, server = FALSE, daemon = FALSE;
	char host[80];
	char command[BUF_LENGTH];
	int b_command = 0, b_host = 0;
	
	while ((c = getopt (argc, argv, "dsa:p")) != -1){
		switch (c){
			//client switches
			case 'p':
				port= atoi(optarg);
			break;
			case 'a':
				strncpy(host, optarg, 79); 
				b_host = 1;
			break;
			//case 'c':
			//	strncpy(command, optarg, BUF_LENGTH - 1); 
			//	b_command = 1;
			//break;
			//server switches
			case 's':
				server = TRUE;
			break;
			case 'd':
				daemon = TRUE;
			break;			
			case '?':
			default:
				usage(argv[0]);
				return 1;
		}
	}
	
	if(server == FALSE){
		if(b_command == FALSE || b_host == FALSE){
			usage(argv[0]);
		}
		//if(port == 0){
			//srand (time(NULL));
			//port = rand() % 1000 + 1025;
		//}
		startClient(host, port, command);
		
	} 
	else 
	{
		//rename program
		//rename(argv);
		//initServer();
		//startServer();
	}
	return 0;
}
