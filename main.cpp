#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <arpa/inet.h>
#include <fstream>

using namespace std;

struct ether_header{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
};

struct ipv4_header{
    uint8_t h_len:4;
    uint8_t ip_v:4;
    uint8_t tos;
    uint16_t ip_len;
    uint16_t iden;
    uint16_t flag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t sip[4];
    uint8_t dip[4];
};

struct tcp_header{
    uint8_t sport[2];
    uint8_t dport[2];
    uint8_t seq[4];
    uint8_t ack[4];
    uint8_t h_len:4;
    uint8_t flag;
    uint16_t wid_size;
    uint16_t checksum;
    uint16_t urgent_p;
};

void print_eth(uint8_t *p_ether)
{
    for(int i=0 ; i<6 ; i++)
    {
        if(i==5)
        {
            printf("%02x\n",p_ether[i]);
            break;
        }
        printf("%02x:",p_ether[i]);
    }
}

void print_ip(uint8_t *p_ip)
{
    for(int i=0 ; i<4 ; i++)
    {
        if(i==3)
        {
            printf("%d \n", p_ip[i]);
            break;
        }
        printf("%d.",p_ip[i]);
    }
}

void print_port(uint8_t *p_port)
{
    printf("%d \n", (p_port[0]<<8)+p_port[1]);
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);

    struct ether_header* eth = (struct ether_header*) packet;

    cout << " --------------------ethernet----------------- " << endl;
    printf("source mac:");
    print_eth(eth->smac);
    printf("Des mac:");
    print_eth(eth->dmac);

    short ether_type =ntohs(eth->type);
    if(ether_type == 0x0800)
    {

        packet += sizeof (struct ether_header);
        struct ipv4_header* iph = (struct ipv4_header*) packet;
        cout << "------------------------ip---------------------" << endl;
        printf("source ip:");
        print_ip(iph->sip);
        printf("Des ip:");
        print_ip(iph->dip);

        if(iph->protocol == 6)
        {
            packet += sizeof (struct ipv4_header);
            struct tcp_header* tcph = (struct tcp_header*) packet;
            cout << "-----------------------tcp---------------------" << endl;
            printf("source port:");
            print_port(tcph->sport);
            printf("Des port:");
            print_port(tcph->dport);

            cout << "----------------------http---------------------" << endl;
            packet += sizeof (struct tcp_header);
            for(int i=0 ; i<16 ; i++)
                cout << packet[i];

            cout << endl;
        }
    }
  }

  pcap_close(handle);
  return 0;
}
