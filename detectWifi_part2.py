#!/usr/bin/env python
# Authors : Miguel Lopes Gouveia et Doriane Tedongmo
# SWI Labo1 part2

from scapy.all import *
import requests
import json

# dictionary with the captured customers
clients = dict()



def handle_packet(packet):
	# verify if it's a wifi packet
	if packet.haslayer(Dot11):

		#type and subtype for probe request
		if packet.type == 0 and packet.subtype == 4:

			# drop empty SSID
			if packet.info != "":

				# add new MAC in clients
				if packet.addr2 not in clients:
					clients[packet.addr2] = {packet.info}

				# add new SSID to a know MAC
				elif packet.info not in clients[packet.addr2]:
					clients[packet.addr2].add(packet.info)

				# get the vendor information for the print
				responseClient = requests.get('https://macvendors.co/api/%s' %(packet.addr2))
				jsonClient = responseClient.json()
				try:
					company = jsonClient['result']['company']
				except:
					company = "unknown"

				# print the information in the terminal
				print("{} ({}) - {}".format(packet.addr2, company, ", ".join(clients[packet.addr2])))
# start to sniff on wlan0mon
sniff(iface="wlan0mon", prn=handle_packet)
