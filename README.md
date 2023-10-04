# reflector
Project Description:
This reflector assignment uses the scapy library 
to easily create packets.
The main function creates the variables for the 
command line dictated in the requirements:

./reflector --interface eth0 --victim-ip 192.168.1.10  
--victim-ethernet 31:16:A9:63:FF:83 --reflector-ip 192.168.1.20 
--reflector-ethernet 38:45:E3:89:B5:56

It uses a try to get those arguments and assigns them to
the correct variables.

There are three functions to handle the packets.
The first packethandler1 checks if the destintion is 
the victim's ip. If so, it changes the packet dest to 
the packet source and the source to the reflecor ip. 
There are checks to handle if it is TCP or UDP and alters
the check sum
The second packethandler2 checks if the destintation is 
the reflector's ip. If so, it changes the dest to the 
source ip and the source to the victim's ip. 
It checks if TCP or UDP and alters the checksum 
accordingly.
The third handles ARP cases and changes the ip's to reflect
accordingly.

There are more functions to sniff the packes and define 
whether they are the victim ip, reflector ip, or arp.

While loop to make it run continuosly.

