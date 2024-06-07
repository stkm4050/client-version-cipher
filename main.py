import sys
sys.path.append('/home/kamada/searchVersion/modules')
from scapy.all import rdpcap, Raw

import version
import encryption

pcap_file = '/home/kamada/capture_libssh/libssh-0.10.0-1.0.1u-install/sshd9.0-1.0.1u.dump'
pcap = rdpcap(pcap_file)

version.search_version(pcap)
algorithms_list = encryption.output_string(pcap)
for i, algorithms in enumerate(algorithms_list):
    algorithms_list[i] = encryption.remove_duplicates_preserve_order(algorithms)
encryption.search_algorithm(algorithms_list[0],algorithms_list[1])