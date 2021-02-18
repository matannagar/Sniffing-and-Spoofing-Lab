#include <netdb.h>
#include <pcap.h>
#include <netinet/in.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include<netinet/tcp.h>
#include <stdlib.h>
#include  <ctype.h>

/* Ethernet header */
struct ethheader {
    u_char ether_dhost[6]; /* destination host address */
    u_char ether_shost[6]; /* source host address */
    u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};
/* IP Header */
struct ipheader {
    unsigned char iph_ihl: 4, //IP header length
    iph_ver: 4; //IP version
    unsigned char iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag: 3, //Fragmentation flags
    iph_offset: 13; //Flags offset
    unsigned char iph_ttl; //Time to Live
    unsigned char iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct in_addr iph_sourceip; //Source IP address
    struct in_addr iph_destip;   //Destination IP address
};
struct tcpheader {
    unsigned short th_sport; /* source port */
    unsigned short th_dport; /* destination port */
    unsigned char th_offx2;  /* data offset, rsvd */
    unsigned short th_win; /* window */
    unsigned short th_sum; /* checksum */
    unsigned short th_urp; /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *) packet;
    if (ntohs(eth->ether_type) ==
        0x800) { // 0x0800 is IP typ4.
        struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct ethheader));
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)
                    (packet + sizeof(struct ethheader) + sizeof(struct ipheader));
            printf("   Protocol: TCP\n");
            printf("         From: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("         To: %s\n", inet_ntoa(ip->iph_destip));
            printf("         source port: %hu\n", htons(tcp->th_sport));
            printf("         destination port: %hu\n", htons(tcp->th_dport));

            char *data = (u_char *) packet + sizeof(struct ethheader)+ sizeof(struct ipheader) +sizeof(struct tcpheader);
            int size_data = ntohs(ip->iph_len) -(sizeof(struct ipheader) + sizeof(struct tcpheader));
            if (size_data > 0) {
                int i = 0;
                while(i < size_data){
                    if ((*data >='a' && *data <='z') || (*data >='A' && *data <='Z')|| (*data >= 0 && *data <= 9))
                        printf("%c", *data);
                    else
                        printf(".");
                    data++;
                    i++;
                }
            }
        }
        return;
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "proto TCP and dst portrange 10-100";
    bpf_u_int32 net;
    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);   //Close the handle
    return 0;
}

