#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <libnet.h>

void usage() {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");
}

typedef struct {
        char* dev_;
} Param;

Param param  = {
        .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
        if (argc != 2) {
                usage();
                return false;
        }
        param->dev_ = argv[1];
        return true;
}

int main(int argc, char* argv[]) {
        if (!parse(&param, argc, argv))
                return -1;

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
        if (pcap == NULL) {
                fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
                return -1;
        }

        while (true) {
                struct pcap_pkthdr* header;
                const u_char* packet;
                struct libnet_ethernet_hdr* eth_h;
                struct libnet_ipv4_hdr* ip_h;
                struct libnet_tcp_hdr* tcp_h;

                int res = pcap_next_ex(pcap, &header, &packet);

                if (res == 0) continue;
                if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                        break;
                }

                // Ethernet Header
                eth_h = (struct libnet_ethernet_hdr *) packet;
                uint8_t src_mac[6], dest_mac[6];

                // IP Header
                int eth_len = sizeof(struct libnet_ethernet_hdr);
                ip_h = (struct libnet_ipv4_hdr *)(packet + eth_len);

                if (ip_h->ip_p == 6){

                    // TCP Header
                        int ip_len = sizeof(struct libnet_ipv4_hdr);
                        tcp_h = (struct libnet_tcp_hdr *)(packet + ip_len + eth_len );
                        int tcp_hlen = (tcp_h->th_off) * 4;
                        int total_plen = ntohs(ip_h->ip_len);
                        int ip_hlen = (ip_h->ip_hl) * 4;

                        memcpy(dest_mac,eth_h->ether_dhost,6);
                        memcpy(src_mac,eth_h->ether_shost,6);

                        printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", dest_mac[0],dest_mac[1],dest_mac[2],dest_mac[3],dest_mac[4],dest_mac[5]);
                        printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);

                        printf("Src IP: %s\n",inet_ntoa(ip_h->ip_src));
                        printf("Dest IP: %s\n",inet_ntoa(ip_h->ip_dst));

                        printf("Src Port: %d\n",ntohs(tcp_h->th_sport));
                        printf("Dest Port: %d\n",ntohs(tcp_h->th_dport));

                        if (total_plen != ip_hlen + tcp_hlen){
                                int data_st = ip_hlen + tcp_hlen + eth_len;

                                for (int i=0;i<10;i++){
                                        printf("%02x ",packet[data_st+i]);
                                }
                                printf("\n");

                        }

                        printf("\n");
                }

        }

        pcap_close(pcap);
}
