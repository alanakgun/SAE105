import argparse
from scapy.all import ARP, Ether, srp

def scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def passive_scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    srp(arp_request_broadcast, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="Discovery script for network hosts.")
    parser.add_argument("-a", "--active", dest="active_scan", metavar="IP", help="Trigger active discovery with the specified IP address.")
    parser.add_argument("-p", "--passive", dest="passive_scan", metavar="IP", help="Trigger passive discovery with the specified IP address.")
    args = parser.parse_args()

    if args.active_scan:
        result = scan(args.active_scan)
        print("Active Discovery Results:")
        print(result)

    if args.passive_scan:
        print("Passive Discovery Results:")
        passive_scan(args.passive_scan)

if __name__ == "__main__":
    main()
