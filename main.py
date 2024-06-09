import sys
sys.path.append('/home/kamada/searchVersion/modules')
from scapy.all import rdpcap, Raw

import version
import encryption
import option

args = option.get_option()

pcap_file = str(args.file)
pcap = rdpcap(pcap_file)

version.search_version(pcap)
algorithms_list = encryption.output_string(pcap)
for i, algorithms in enumerate(algorithms_list):
    algorithms_list[i] = encryption.remove_duplicates_preserve_order(algorithms)
encryption.search_algorithm(algorithms_list[0],algorithms_list[1])