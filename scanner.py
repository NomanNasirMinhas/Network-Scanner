import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
import argparse
#pipe install scapy-python3

def getArgs():
    parser = argparse.ArgumentParser(description="A simple Network Scanner built upon Scapy")
    parser.add_argument("-a", "--addr", dest="ip", help="IP Range to Scan", required=True)
    parser.add_argument("-i", "--iface", dest="iface", help="Network Interface to Use", required=False)
    parser.add_argument("-t", "--timeout", dest="timeout", help="Timeout for broadcasting ARP request", required=False)
    options = parser.parse_args()
    return options


def scan_network(ip, timeout=3):
    arp_req = scapy.ARP(pdst=ip)
    # print(arp_req.summary())
    # scapy.ls(scapy.ARP())
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast / arp_req
    # arp_broadcast.show()
    answered = scapy.srp(arp_broadcast, timeout=timeout, verbose=False)[0]
    return answered


def display_res(result):
    print("Following Responses were captured")
    print("==============================================")
    print("IP\t\t\tMAC Address")
    print("==============================================")
    for response in result:
        print(response[1].psrc + "\t\t" + response[1].hwsrc)
        print("----------------------------------------------")


opts = getArgs()
res = scan_network(opts.ip, opts.timeout)
display_res(res)
