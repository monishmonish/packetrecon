#!usr/bin/python3
from scapy.all import *
import sys

RI="\033[91m"
RF="\033[00m"
GI="\033[92m"
GF="\033[00m"
YI="\033[93m"
YF="\033[00m"
interface="wlp2s0"
def customPacket():
	source=str(input(YI+"[+]Enter the source of the packet :"+YF))
	destination=str(input(YI+"[+]Enter the destination of the packet :"+YF))
	ttl_value=int(input(YI+"[+]Enter the TTL value (Default=64) :"+YF))
	a=IP(ttl=ttl_value)
	a.src=source
	a.dst=destination
	a
	send(a,iface=interface)

def fakeTCPFlooder():
	choice=input(YI+"[+]Do you want spoofed MAC In packets(y/n) :"+YF)
	if choice=="y":
		countvalue=int(input(YI+"[+]Enter the number of packets to be flooded:"+YF))
		spoofedmac=str(input(YI+"[+]Enter the spoofed source MAC :"+YF))
		source=str(input(YI+"[+]Enter the source of the packet :"+YF))
		destination=str(input(YI+"[+]Enter the destination of the packet :"+YF))
		sourceport=int(input(YI+"[+]Enter the source port :"+YF))
		destinationport=int(input(YI+"[+]Enter the destination port :"+YF))
		sendp(Ether(src=spoofedmac)/IP(src=source, dst=destination)/TCP(sport=sourceport,dport=destinationport), count=countvalue)
	if choice=="n":
		countvalue=int(input(YI+"[+]Enter the number of packets to be flooded:"+YF))
		source=str(input(YI+"[+]Enter the source of the packet :"+YF))
		destination=str(input(YI+"[+]Enter the destination of the packet :"+YF))
		sourceport=int(input(YI+"[+]Enter the source port :"+YF))
		destinationport=int(input(YI+"[+]Enter the destination port :"+YF))
		send(IP(src=source, dst=destination)/TCP(sport=sourceport,dport=destinationport), count=countvalue)


def sniffLimtd():
	countvalue=int(input(YI+"[+]Enter the number of packets to be sniffed :"+YF))
	a=sniff(iface=interface,count=countvalue)
	a.nsummary()
	choice=input(YI+"[+]Want to see in detail(y/n) : "+YF)
	if choice=="y":
		for pkt in a:
			print(RI+"*"*60+RF)
			pkt.show()
			print(RI+"*"*60+RF)
	if choice=="n":
		sys.exit()
	

def ttlchecker():
	def packets(pkt):
		if IP in pkt:
			src_ip=pkt[IP].src
			dst_ip=pkt[IP].dst
			ttl_value=pkt[IP].ttl
			print(RI+"[SRC]:"+RF+YI+str(src_ip)+YF+GI+" >>>>> "+GF+RI+"[DST]:"+RF+YI+str(dst_ip)+YF+RI+" | TTL:"+RF+YI+str(ttl_value)+YF)
	sniff(prn=packets,iface=interface)
def ipv6Router():
	def packets(pkt):
		if IPv6 in pkt:
			src_ip=pkt[IPv6].src
			dst_ip=pkt[IPv6].dst
			print(RI+"[SRC]:"+RF+YI+str(src_ip)+YF+GI+" >>>>> "+GF+RI+"[DST]:"+RF+YI+str(dst_ip)+YF)
	sniff(prn=packets,iface=interface)
def ipv4Router():
	def packets(pkt):
		if IP in pkt:
			src_ip=pkt[IP].src
			dst_ip=pkt[IP].dst
			print(RI+"[SRC]:"+RF+YI+str(src_ip)+YF+GI+" >>>>> "+GF+RI+"[DST]:"+RF+YI+str(dst_ip)+YF)
	sniff(prn=packets,iface=interface)
def MACRouter():
	def packets(pkt):
		if Ether in pkt:
			src_mac=pkt[Ether].src
			dst_mac=pkt[Ether].dst
			print(RI+"[SRC]:"+RF+YI+str(src_mac)+YF+GI+" >>>>> "+GF+RI+"[DST]:"+RF+YI+str(dst_mac)+YF)
	sniff(prn=packets,iface=interface)




