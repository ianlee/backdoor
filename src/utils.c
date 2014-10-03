#include "utils.h"

char *get_line (char *s, size_t n, FILE *f)
{
  	char *p = fgets (s, n, f);

  	if (p != NULL) {
    		size_t last = strlen (s) - 1;
    		if (s[last] == '\n') s[last] = '\0';
  	}
  	return p;
}

void usage(char * program_name, int mode){
	if(mode == SERVER_MODE)
	{
		fprintf(stderr, "Usage: %s [-d daemon mode]\n", program_name);
		fprintf(stderr, "-d 	- Daemon mode (run the server process in the background)\n");
		fprintf(stderr, " 	- IF NOT SPECIFIED, default is running server in foreground with messages displayed\n");
	}
	if(mode == CLIENT_MODE)
	{
		fprintf(stderr, "Usage: %s -a host [-p port]\n", program_name);
		fprintf(stderr, "-a 	- Server host to send commands to\n\n");
		fprintf(stderr, "-p 	- Destination port to send commands to (port must be the same as server capturing on that port\n");
		fprintf(stderr, " 	- IF NOT SPECIFIED, default is port 8080\n");
	}
	exit(1);
}
