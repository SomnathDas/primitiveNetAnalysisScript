from scapy.all import *

pcap_p = rdpcap("hp_challenge.pcap")

print(pcap_p[0].summary())
