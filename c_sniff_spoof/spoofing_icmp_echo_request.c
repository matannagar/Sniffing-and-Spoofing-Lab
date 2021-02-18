#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>

#define IP4_HDRLEN 20
#define ICMP_HDRLEN 8

unsigned short calculate_checksum(unsigned short *paddress, int len);

#define SOURCE_IP "10.0.2.4"
#define DESTINATION_IP "8.8.8.8"

int main() {
    struct ip iphdr; // IPv4 header  
    struct icmp icmphdr; // ICMP-header  
    char data[IP_MAXPACKET] = "This is the ping.\n";
    int datalen = strlen(data) + 1;
    iphdr.ip_v = 4;
    iphdr.ip_hl = IP4_HDRLEN / 4; // not the most correct  
    iphdr.ip_tos = 0;
    iphdr.ip_len = htons(IP4_HDRLEN + ICMP_HDRLEN + datalen);
    iphdr.ip_id = 0;
    int ip_flags[4];
    ip_flags[0] = 0;
    ip_flags[1] = 0;
    ip_flags[2] = 0;
    ip_flags[3] = 0;

    iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14)+ (ip_flags[2] << 13) + ip_flags[3]);
    iphdr.ip_ttl = 128;
    iphdr.ip_p = IPPROTO_ICMP;
    if (inet_pton(AF_INET, SOURCE_IP, &(iphdr.ip_src)) <= 0) {
        fprintf(stderr, "inet_pton() failed for source-ip with error: %d", errno);
        return -1;
    }
    if (inet_pton(AF_INET, DESTINATION_IP, &(iphdr.ip_dst)) <= 0) {
        fprintf(stderr, "inet_pton() failed for destination-ip with error: %d", errno);
        return -1;
    }
    iphdr.ip_sum = 0;
    iphdr.ip_sum = calculate_checksum((unsigned short *) &iphdr, IP4_HDRLEN);
    icmphdr.icmp_type = ICMP_ECHO;
    icmphdr.icmp_code = 0;
    icmphdr.icmp_id = 18;
    icmphdr.icmp_seq = 0;
    icmphdr.icmp_cksum = 0;
    char packet[IP_MAXPACKET];
    memcpy(packet, &iphdr, IP4_HDRLEN);
    memcpy((packet + ip4_hdrlen), &icmphdr, icmp_hdrlen);
    memcpy(packet + ip4_hdrlen + icmp_hdrlen, data, datalen);
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet + ip4_hdrlen),icmp_hdrlen + datalen);
    memcpy((packet + ip4_hdrlen), &icmphdr, icmp_hdrlen);
    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;
    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        fprintf(stderr, "socket() failed with error: %d", errno);
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }
    const int flagOne = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &flagOne, sizeof(flagOne)) == -1) {
        fprintf(stderr, "setsockopt() failed with error: %d", errno);
        return -1;
    }

    if (sendto(sock, packet, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof(dest_in)) ==
        -1) {
        fprintf(stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
    printf("send ICMP packet from: %s to: %s\n", SOURCE_IP, DESTINATION_IP);
    close(sock);
    return 0;
}

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
    sum += (sum >> 16);                 // add carry  
    answer = ~sum;                      // truncate to 16 bits  

    return answer;
}  

