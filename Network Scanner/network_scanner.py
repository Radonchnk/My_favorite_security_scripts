 #!usr/bin/env python

import scapy.all as scapy 
import optparse

def get_arguments():
	parser = optparse.OptionParser()
	parser.add_option("-t", "--target", dest="ip", help="Diapason of IP to scan")
	(options, arguments) = parser.parse_args()
	if not options.ip:
		parser.error("[-] Please specify an IP diapason , use --help for more info.")
	return options.ip

def scan(ip):
	arp_request = scapy.ARP(pdst = ip)
	brodcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
	arp_request_brodcast = brodcast/arp_request
	answered_list = scapy.srp(arp_request_brodcast, timeout=1, verbose=False)[0]
	
	clients_list = []
	for element in answered_list:
		client_dict = {"IP":element[1].psrc, "MAC":element[1].hwsrc}
		clients_list.append(client_dict)
		
	return(clients_list)
	
def print_clients_IP_MAC(results_list):
	print("IP\t\t\t MAC ADDRESS\n------------------------------------------	")
	
	for client in results_list:
		print(client["IP"] + "\t\t " + client["MAC"])
	
ip = get_arguments()
scan_results = scan(ip)
print_clients_IP_MAC(scan_results)
