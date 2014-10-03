#include "backdoor-server.h"

int main(int argc, char **argv)
{
	/* Check to see if user is root */
	if (geteuid() != USER_ROOT)
	{
		printf("\nYou need to be root to run this.\n\n");
		exit(-1);
	}

	if(parse_options(argc, argv) < 0)
	{
		printf("\nInvalid options.\n\n");
		exit(-1);
	}

	printf("Process name masked as: %s\n", MASK_NAME);

	return 0;
}

void usage(char * prgm_name)
{
	printf("Usage: %s [options]\n", prgm_name);
	printf("Options:\n");
	printf("-d or --daemon - run the process in the background");
	printf("-h or --help - print this screen");
}

int parse_options(int argc, char **argv)
{

}

int print_server_info()
{

}
