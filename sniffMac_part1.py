#!/usr/bin/env python
# Authors : Miguel Gouveia et Doriane Tedongmo
# SWI Labo1 part1

from scapy.all import *
import sys

# get the mac address in parameter
mac = sys.argv[1]

def handle_packet(packet):
	# verify if it's a wifi packet
	if packet.haslayer(Dot11):

		# verify type annd subtype
		if packet.type == 0 and packet.subtype in (0,2,4):

			# verify if the MAC is the same than that in parameter
			if mac == packet.addr2:

				# print if the MAC is found
				print("The MAC : %s is found!" %(packet.addr2.upper()))
				exit(0)
# start to sniff on wlan0mon
sniff(iface="wlan0mon", prn=handle_packet)
