1.	# include <stdio.h>  
2.	# include <stdlib.h>  
3.	# include <unistd.h>  
4.	# include <string.h>  
5.	# include <sys/types.h>  
6.	# include <sys/socket.h>  
7.	# include <netinet/in.h>  
8.	# include <netinet/ip.h>  
9.	# include <netinet/ip_icmp.h>  
10.	# include <arpa/inet.h>  
11.	# include <errno.h>  
12.	# define IP4_HDRLEN 20  
13.	# define ICMP_HDRLEN 8  
14.	  
15.	unsigned short calculate_checksum(unsigned short * paddress, int len) {  
16.	    int nleft = len;  
17.	    int sum = 0;  
18.	    unsigned short * w = paddress;  
19.	    unsigned short answer = 0;  
20.	  
21.	    while (nleft > 1) {  
22.	    sum += * w++;  
23.	    nleft -= 2;  
24.	    }  
25.	    if (nleft == 1) {  
26.	    * ((unsigned char * ) & answer) = * ((unsigned char * ) w);  
27.	    sum += answer;}  
28.	    sum = (sum >> 16) + (sum & 0xffff);  
29.	    sum += (sum >> 16);  
30.	    answer = ~sum;  
31.	    return answer;  
32.	}  
33.	
34.	# define SOURCE_IP "10.0.2.4"  
35.	# define DESTINATION_IP "8.8.8.8"  
36.	  
37.	int main(){  
38.	    struct icmp icmphdr; // ICMP - header  
39.	    char data[IP_MAXPACKET] = "Matan and Reut";  
40.	    int datalen = strlen(data) + 1;  
41.	      
42.	    //= == == == == == == == == ==  
43.	    // ICMP header  
44.	    //= == == == == == == == == ==  
45.	    icmphdr.icmp_type = ICMP_ECHO;  
46.	    icmphdr.icmp_code = 0;  
47.	    icmphdr.icmp_id = 18;   
48.	    icmphdr.icmp_seq = 0;  
49.	    icmphdr.icmp_cksum = 0;  
50.	    memcpy((packet), & icmphdr, ICMP_HDRLEN);  
51.	    memcpy(packet + ICMP_HDRLEN, data, datalen);  
52.	    icmphdr.icmp_cksum = 
	calculate_checksum((unsigned short *)(packet), ICMP_HDRLEN + datalen);  
53.	    memcpy((packet), & icmphdr, ICMP_HDRLEN);    
1.	    struct sockaddr_in dest_in;  
2.	    memset( & dest_in, 0, sizeof(struct sockaddr_in));  
3.	    dest_in.sin_family = AF_INET;  
4.	    dest_in.sin_addr.s_addr = inet_addr(DESTINATION_IP);  
5.	      
6.	    int sock = -1;  
7.	    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {  
8.	        fprintf(stderr, "socket() failed with error: %d", errno);  
9.	        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");  
10.	        return -1;  
11.	    }  
12.	      
13.	    if (sendto(sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *) & dest_in, sizeof(dest_in)) == -1) {  
14.	        fprintf(stderr, "sendto() failed with error: %d", errno);  
15.	        return -1;  
16.	    }  
17.	      
18.	    printf("\n(%s): echo, ", SOURCE_IP);  
19.	    printf("data: %s\n", (packet + ICMP_HDRLEN));  
20.	      
21.	    close(sock);  
22.	    return 0;  
23.	}  
