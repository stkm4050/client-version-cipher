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

version_list=version.search_version(pcap,ip)
cipher_list=cipher.output_string(pcap,ip)

for i,version in enumerate(version_list):
    print(f"Version:{version_list[i]}\nCipher:{cipher_list[i]}")