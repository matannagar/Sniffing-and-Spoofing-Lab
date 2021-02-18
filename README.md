# Packet Sniffing and Spoofing Lab

![](https://seedsecuritylabs.org/Labs_20.04/Networking/Sniffing_Spoofing/sniffing_spoofing.png)
Packet sniffing and spoofing are the two important concepts in network security; they are two major threats in network communication. Being able to understand these two threats is essential for understanding security measures in networking. There are many packet sniffing and spoofing tools, such as Wireshark, Tcpdump, Netwox, etc. Some of these tools are widely used by security experts, as well as by attackers. Being able to use these tools is important for students, but what is more important for students in a network security course is to understand how these tools work, i.e., how packet sniffing and spoofing are implemented in software.

The objective of this lab is for students to master the technologies underlying most of the sniffing and spoofing tools. Students will play with some simple sniffer and spoofing programs, read their source code, modify them, and eventually gain an in-depth understanding on the technical aspects of these programs. At the end of this lab, students should be able to write their own sniffing and spoofing programs.

For more information regarding this lab: [Seed Lab](https://seedsecuritylabs.org/Labs_20.04/Networking/Sniffing_Spoofing/ "Seed Lab")

**Before starting this task, please set up Virtual Machines as instructed [in this link](https://github.com/seed-labs/seed-labs/blob/master/manuals/vm/seedvm-manual.md "in this link").**

## General Purpose
- We will set up two virtual machines, each will hold its own IP adressed as depicted below. 
- The host will be "the regular user", sending and receiving packets.
- The attacker will be the other VM which will use sniffing and spoofing programs in order to "listen" to network activity on the host side.
- Attacker will then sniff packets (that were not meant for him)
- He will then forge ICMP- Echo -Reply packets to "trick" the host into thinking that it is the destination that is responding to him.

![](https://i.ibb.co/HBQb7JC/image.jpg)



### Programming Languages

- Java
- Python







####Javascript　

```javascript
function test(){
	console.log("Hello world!");
}
 
(function(){
    var box = function(){
        return box.fn.init();
    };

    box.prototype = box.fn = {
        init : function(){
            console.log('box.init()');

			return this;
        },

		add : function(str){
			alert("add", str);

			return this;
		},

		remove : function(str){
			alert("remove", str);

			return this;
		}
    };
    
    box.fn.init.prototype = box.fn;
    
    window.box =box;
})();

var testBox = box();
testBox.add("jQuery").remove("jQuery");
```


