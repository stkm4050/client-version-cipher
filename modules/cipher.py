from scapy.all import rdpcap, Raw
import re

# PCAPファイルを読み込む
# pcap_file = '/home/kamada/capture_libssh/libssh-0.10.0-1.0.1u-install/sshd9.0-1.0.1u.dump'  # PCAPファイルのパスを適宜変更してください
# packets = rdpcap(pcap_file)

# 暗号化方式を出力する関数
def output_unencrypted(payload):
    # 正規表現パターンを定義
    pattern = rb'(3des-cbc|chacha20-poly1305@openssh\.com|aes256-gcm@openssh\.com|aes128-gcm@openssh\.com|aes256-ctr|aes192-ctr|aes128-ctr|aes256-cbc|aes192-cbc|aes128-cbc)'
    # 正規表現を使って抽出
    unencrypted_algorithms = re.findall(pattern, payload)
    return [algorithm.decode() for algorithm in unencrypted_algorithms]

# 各パケットの暗号化アルゴリズムを抽出して2次元配列に格納する関数
def output_string(packets,ip):
    server_algorithms_list = []
    client_algorithms_list = []
    cipher_list = []
    for packet in packets:
        if packet.haslayer('TCP'):
            src_ip = packet['IP'].src
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                # 暗号化されていない文字列を抽出
                unencrypted_algorithms = output_unencrypted(payload)
                if src_ip != ip:
                    client_algorithms_list.append(unencrypted_algorithms)
                else:
                    server_algorithms_list.append(unencrypted_algorithms)
    client_algorithms_list = [algorithms for algorithms in client_algorithms_list if algorithms]
    server_algorithms_list = [algorithms for algorithms in server_algorithms_list if algorithms]
    
    for i, algorithms in enumerate(client_algorithms_list):
        client_algorithms_list[i] = remove_duplicates_preserve_order(algorithms)
        server_algorithms_list[i] = remove_duplicates_preserve_order(algorithms)
        cipher_list.append(search_algorithm(client_algorithms_list[i],server_algorithms_list[i]))
    return cipher_list


# 重複を除去しつつ順序を保持する関数
def remove_duplicates_preserve_order(lst):
    seen = set()
    result = []
    for item in lst:
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result

#配列の要素同士で被っているものがあればそれを抽出する関数
def search_algorithm(client,server):
    for item in client:
        if item in server:
            cipher = item
            break
    return cipher
  

# 各パケットごとの暗号化されていないアルゴリズムを2次元配列に格納
# algorithms_list = output_string(packets)

# # 各配列内の重複要素を削除（順序を保持）
# for i, algorithms in enumerate(algorithms_list):
#     algorithms_list[i] = remove_duplicates_preserve_order(algorithms)

# cipher = search_algorithm(algorithms_list[0],algorithms_list[1])
