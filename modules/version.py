from scapy.all import rdpcap, Raw
import pyshark, codecs

#pcapファイルをscapyをもとに分析するプログラム
#pcap = rdpcap('/home/kamada/capture_libssh/libssh-0.10.0-1.0.1u-install/sshd9.0-1.0.1u.dump')

#バージョンを取得する関数
def search_version(pcap):
    for packet in pcap:
        if packet.haslayer('TCP'):
            src_ip = packet['IP'].src
            if packet.haslayer(Raw):
                payload = packet[Raw].load
            
                if payload.startswith(b'SSH-'):  
                    banner = payload.decode('utf-8').strip() 
                    if src_ip != "10.1.152.2":
                        version_info = banner.split('-')[2]
                        print(f"SSHバージョン：{version_info}")



# version(pcap)