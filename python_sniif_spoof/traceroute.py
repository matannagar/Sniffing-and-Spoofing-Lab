1.	from scapy.all import *  
2.	hostname=”google.com”  
3.	i=0  
4.	while(True):  
5.	    i=i+1  
6.	    pkt = IP(dst=hostname, ttl=i) / ICMP()  
7.	    reply = sr1(pkt, verbose=0)  
8.	    if reply is None:  
9.	        break  
10.	    elif reply.src == '172.217.171.206':  
11.	        print("Done!", reply.src)  
12.	        break  
13.	    else:  
14.	        print("%d hops away: " % i, reply.src, reply.time)  
