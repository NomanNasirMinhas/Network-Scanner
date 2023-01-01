import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
import argparse
#pipe install scapy-python3
import pyfiglet
ascii_banner = pyfiglet.figlet_format("Network Scanner",font="banner3-D")
print(ascii_banner)
def getArgs():
    parser = argparse.ArgumentParser(description="A simple Network Scanner built upon Scapy")
    parser.add_argument("-a", "--addr", dest="ip", help="IP Range to Scan", required=True)
    parser.add_argument("-i", "--iface", dest="iface", help="Network Interface to Use", required=False)
    parser.add_argument("-t", "--timeout", dest="timeout", type=int, help="Timeout for broadcasting ARP request", required=False)
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
    if len(result) == 0:
        print("No Devices were found in \"" + opts.ip + "\" Network")
        return
    print("Following Devices were found in \"" + opts.ip + "\" Network")
    print("==============================================")
    print("  IP\t\t\t  MAC Address")
    print("==============================================")
    for idx, response in enumerate(result):
        print(response[1].psrc + "\t|\t" + response[1].hwsrc)
        print("----------------------------------------------")


opts = getArgs()
res = scan_network(opts.ip, opts.timeout)
display_res(res)
