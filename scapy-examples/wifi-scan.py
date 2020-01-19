#!/usr/bin/python

import sys
from scapy.all import *

file = open("wifi.txt", "w")

ssids = set()
def Packet(pkt):
	if pkt.haslayer(Dot11Beacon):
		if (pkt.info not in ssids) and pkt.info:
			print len(ssids),pkt.addr2 , pkt.info
			ssids.add(pkt.info)
			file.write(pkt.info + " " + pkt.addr2 + "\n")

sniff(iface = "wlan1", count = 500, prn = Packet)