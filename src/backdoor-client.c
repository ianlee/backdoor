#include "backdoor-client.h"


int main(int argc, char **argv)
{
	user_options.port  =DEFAULT_PORT;
	/* Check to see if user is root */
	if (geteuid() != USER_ROOT)
	{
		printf("\nYou need to be root to run this.\n\n");
    		exit(0);
	}
	if(parse_options(argc, argv) < 0){
		exit(-1);
	}
	print_client_info();
	startClient();

	return 0;
}
int sendClientPacket(char* host, int port, char* command){
	#ifdef DEBUG
		printf("host:%s \nport: %d \ncommand: %s\n", host, port, command);
	#endif
	//encode command
	
	//send on raw socket
	return 0;
}
int startClient(){
	pcap_t * nic_handle = NULL;
	struct bpf_program fp;
	//char s[BUF_LENGTH];
	//char *command;
	//int quit = 0;
	
	//start libpcap to display results
	startPacketCapture(nic_handle, fp, user_options.port);
	//while(!quit){
		//read input
		//command = get_line (s, BUF_LENGTH, stdin);
	//	if(strcmp( command, "quit") == 0){
	//		quit = 1;
	//	}
		//send packet
		sendClientPacket(user_options.host, user_options.port, user_options.command);
		
	//}
	//stopPacketCapture();
	return 0;
}

int parse_options(int argc, char **argv)
{
	int b_command = FALSE, b_host = FALSE;
	char c;
	while ((c = getopt (argc, argv, "p:a:c:")) != -1)
	{
		switch (c)
		{
			case 'p':
				user_options.port= atoi(optarg);
			break;
			case 'a':
				strncpy(user_options.host, optarg, 79); 
				b_host = TRUE;
			break;
			case 'c':
				strncpy(user_options.command, optarg, BUF_LENGTH - 1); 
				b_command = TRUE;
			break;
			case '?':
			default:
				usage(argv[0], CLIENT_MODE);
				return -1;
		}
		if(b_command == FALSE || b_host == FALSE){
			usage(argv[0], CLIENT_MODE);
			return -1;
		}
	}
	return 0;
}
void print_client_info()
{
	fprintf(stderr, "Host: %s.\n", user_options.host);
	fprintf(stderr, "Port: %d\n", user_options.port);
	fprintf(stderr, "Command: %s\n", user_options.command);
}
