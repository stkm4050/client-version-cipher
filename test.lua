-- Usage: tshark  -o "ssh.tcp.port:<port>" -X lua_script:get_ip_client.lua -X lua_script1:<capture file> -X lua_script1:<port> -X lua_script1:<save file>  -r <capture file> -q
local args = { ... }
local pcap_file = args[1]
local ssh_port = tonumber(args[2])
local file_name = args[3] or "list.csv"
local version = Field.new("ssh.protocol")
local src_ip = Field.new("ip.src")
local dst_port_field = Field.new("tcp.dstport")
local src_port_field = Field.new("tcp.srcport")
local client_cipher_field = Field.new("ssh.encryption_algorithms_client_to_server")
local server_cipher_field = Field.new("ssh.encryption_algorithms_server_to_client")




local tap = Listener.new(nil, "tcp.port =="..ssh_port ) 

local ip_table = {}
local version_table = {}
local client_version_counts = {}
local client_cipher_counts = {}
local packet_info = {}
local cipher_table = {}
local totatl_version_count = 0
local total_cipher_count = 0

local output_file = io.open(file_name, "w")
output_file:write("SSHversion,Percentage,Cipher,Percentage\n")

function tap.packet(pinfo, tvb, tapdata) --1packet毎に行われる処理

end

function tap.reset()
    print("Tap reset or finished")
end