#include "main.h"


int main (int argc, char **argv){
	int port=0, server=0;
	char host[80];
	
	while ((c = getopt (argc, argv, "s:a:p:")) != -1){
		switch (c){
			case 'p':
				port= atoi(optarg);
			break;
			case 'a':
				host = optarg;
			break;
			case 's':
				server = 1;
			break;
			
			case '?':
			default:
				fprintf(stderr, "Usage: %s \n", argv[0]);
				return 1;
		}
	}
	
	if(server == 0){
		//initClient();
		startClient(host, port);
		
	} else {
		//initServer();
		//startServer();
	}
	return 0;
}
