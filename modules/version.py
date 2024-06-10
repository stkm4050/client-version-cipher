from scapy.all import rdpcap, Raw
import pyshark, codecs

#pcapファイルをscapyをもとに分析するプログラム
#pcap = rdpcap('/home/kamada/capture_libssh/libssh-0.10.0-1.0.1u-install/sshd9.0-1.0.1u.dump')

#バージョンを取得する関数
def search_version(pcap,ip):
    version_list = []
    i = 0
    for packet in pcap:
        if packet.haslayer('TCP'):
            src_ip = packet['IP'].src
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                if payload.startswith(b'SSH-'):  
                    banner = payload.decode('utf-8').strip() 
                    if src_ip != ip:
                        version_info = banner.split('-')[2]
                        version_list.append(version_info)
                        i = i + 1
    return version_list



# version(pcap)