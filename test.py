import sys
sys.path.append('/home/kamada/searchVersion/modules')
from scapy.all import rdpcap, Raw

import version
import cipher
import option

args = option.get_option()

pcap_file = str(args.file)
pcap = rdpcap(pcap_file)
ip = str(args.address)

for packet in pcap:
    if packet.haslayer('SSH'):
        print("成功")