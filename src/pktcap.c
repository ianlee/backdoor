#include "pktcap.h"

int startPacketCapture(pcap_t * nic_descr, struct bpf_program fp){
	
	char nic_dev[BUFFER];
	pcap_if_t *alldevs, *temp; 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    bpf_u_int32 maskp;          // subnet mask               
    bpf_u_int32 netp;           // ip 
    char filter_exp[BUFFER];
	
    
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
	
	/*Compiling the filter expression */
	sprintf(filter_exp, "tcp and dst port %d", port);
	if(pcap_compile(nic_descr, &fp, filter_exp, 0, netp))
	{
		fprintf(stderr, "Cannot parse expression filter\n");
		exit(1);
	}
	if(pcap_setfilter(nic_descr, &fp) < 0)
	{
		fprintf(stderr, "Cannot set filter\n");
		exit(1);
	}
	pcap_loop(nic_descr, -1, pkt_callback, NULL);
	return 0;
}
int stopPacketCapture(pcap_t * nic_descr, struct bpf_program fp){
	pcap_freecode(&fp);
	pcap_close(nic_descr);
	return 0;
}