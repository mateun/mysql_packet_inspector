#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define PCAP_BUFFER_SIZE 65535
#define SNAP_LEN 65535
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)

void got_packet(u_char* args, const struct pcap_pkthdr* header,
								const u_char* packet) {

	printf("got packet!\n");

	const struct sniff_ethernet* ethernet;
	const struct sniff_ip* ip;

	ethernet = (struct sniff_ethernet*) (packet);
	ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
		

}

int main(int argc, char** args) {

	char* dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("starting mysql packet inspection\n");

	dev = pcap_lookupdev(errbuf);

	if (dev == NULL) {
		printf("could not detect device\n");
		return 1;
	}

	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	struct in_addr addr;

	// when trying to capture mysql traffic from a local
	// client we need to listen on the loopback interface.
	// for production, we might want to listen on the "real"
	// device given by pcap_lookupdev!
	dev = "lo";
	
	int ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

	if (ret == -1) {
		printf("%s\n", errbuf);
		return 1;
	}

	addr.s_addr = netp;
	char* net = inet_ntoa(addr);

	printf("device: %s \n", dev);
	printf("NET: %s\n", net);

	pcap_t* handle = pcap_open_live(dev, 65535, 0, -1, errbuf);
	if (handle == NULL) {
		printf("could not open pcap: %s\n", errbuf);
		return 1;
	}

	const u_char* packet;
	struct pcap_pkthdr header;
	struct ether_header *eptr;

	u_char* ptr;

	struct bpf_program fp;
	char filter_exp[] = "port 3306";
	if(pcap_compile(handle, &fp, filter_exp, 0, netp) == -1) {
		printf("could not parse filter %s %s\n", filter_exp, pcap_geterr(handle));
		return 2;			
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		printf("could not install filter %s %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}

	pcap_loop(handle, -1, got_packet, NULL);


	/*packet = pcap_next(handle, &header);
	if (packet == NULL) {
		printf("did not grab packet\n");
		return 1;
	} else { 
		printf("grabbed packet!\n");
	}*/
	

	return 0;
	
}
