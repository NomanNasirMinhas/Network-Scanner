# Network Scanner
### This is a simple Network Scanner written in Python using the scapy library. It can be used to scan a network and return a list of hosts that are currently online.

### Requirements
- Python 3
- scapy library
To install scapy, run the following command:


    pip install scapy

### Usage
To use the Network Scanner, run the following command:


    sudo python3 scanner.py -a IP -i IFACE -t TIMEOUT


#### optional arguments:
  

    -h,         --help              Show this help message and exit
    -a IP,      --addr IP           IP Range to Scan
    -i IFACE,   --iface IFACE       Network Interface to Use
    -t TIMEOUT, --timeout TIMEOUT   Timeout for broadcasting ARP request



### Notes
The script may take a few minutes to run, depending on the size of the network.
The script requires root privileges to run, as it uses scapy's srp() function to send packets at the Ethernet layer.
### Credits
This script was written by `Noman Nasir Minhas` using the scapy library.