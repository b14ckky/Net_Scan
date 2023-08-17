#!/usr/bin/env python
import sys
import threading
import random
import scapy.all as scapy
import argparse

from colorama import Fore
from termcolor import colored

rainbow = ['red', 'green', 'green', 'blue', 'magenta', 'cyan']
r0 = random.randint(0, 5)
r1 = random.randint(0, 5)
r2 = random.randint(0, 5)
r3 = random.randint(0, 5)
r4 = random.randint(0, 5)

print(colored("\t┌────────────────────────┐", rainbow[r0]))
print(colored("\t│╔╗╔┌─┐┌┬┐   ╔═╗┌─┐┌─┐┌┐┌│", rainbow[r1]))
print(colored("\t│║║║├┤  │    ╚═╗│  ├─┤││││", rainbow[r2]))
print(colored("\t│╝╚╝└─┘ ┴    ╚═╝└─┘┴ ┴┘└┘│", rainbow[r3]))
print(colored("\t└────────0xb14cky────────┘\n", rainbow[r4]))

parser = argparse.ArgumentParser(
    description="A Simple Host Discovery Tool !!",
    formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=47)
)


def get_arguments():
    parser.add_argument("-t", "--target", dest="target", help="Specify target ip or ip range")
    options = parser.parse_args()
    return options


client_list = []


def scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet / arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    print(Fore.RED+"IP\t\t\tMAC\n----------------------------------------"+Fore.RESET)
    for client in client_list:
        print(client["ip"] + "\t\t" + client["mac"])
    return client_list


options = get_arguments()

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

t = threading.Thread(target=scan, args=(options.target,))
t.start()
