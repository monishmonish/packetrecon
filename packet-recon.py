#!usr/bin/python3
from scapy.all import *
import sys
sys.path.append('/functions/')
from functions import *




__banner__='''

 ____   _    ____ _  _______ _____     ____  _____ ____ ___  _   _ 
|  _ \ / \  / ___| |/ / ____|_   _|   |  _ \| ____/ ___/ _ \| \ | |
| |_) / _ \| |   | ' /|  _|   | |_____| |_) |  _|| |  | | | |  \| |
|  __/ ___ \ |___| . \| |___  | |_____|  _ <| |__| |__| |_| | |\  |
|_| /_/   \_\____|_|\_\_____| |_|     |_| \_\_____\____\___/|_| \_|

   DEVELOPED BY MONISH KUMAR R | CONTACT : monish937@gmail.com

'''

__choice__='''

	[1]Create And Send Custom Packet
	[2]Sniff Limited Packets
	[3]Fake TCP Flooder
	[4]TTL(Time To Live) Checker For Packets
	[5]List Live MAC Connections
	[6]List Live IPv4 Connections
	[7]List Live IPv6 Connections
	[8]DOS Attack on IP

'''

def callFunction(choice):
	if choice==1:
		customPacket()
	if choice==2:
		sniffLimtd()
	if choice==3:
		fakeTCPFlooder()
	if choice==4:
		ttlchecker()
	if choice==5:
		MACRouter()
	if choice==6:
		ipv4Router()
	if choice==7:
		ipv6Router()
	if choice==8:
		dosattack()


if __name__ == "__main__":
	print(YI+__banner__+YF)
	print(GI+__choice__+GF)
	choice=int(input(YI+"[+]Enter Your Choice :"+YF))
	try:
		callFunction(choice)
	except KeyboardInterrupt:
		print(RI+">>>>>USER REQUESTED SHUTDOWN<<<<<"+RF)
	
