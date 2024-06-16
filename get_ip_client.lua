-- Usage: tshark -X lua_script:search_client.lua -X lua_script1:<capture file> -r <capture file>
-- Example: ls *.dump | xargs -I {} -P 1 sh -c "tshark -X lua_script:get_reset.lua -X lua_script1:{} -r {} -q"
local args = { ... }
local pcap_file = args[1]
local ssh_port = tonumber(args[2])
local version_file_name = args[3] or "version_list.csv"
local cipher_file_name = args[4] or "cipher_list.csv"
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

local version_file = io.open(version_file_name, "w")
local cipher_file = io.open(cipher_file_name, "w")

version_file:write("SSHVersion,Percentage\n")
cipher_file:write("Cipher,Percentage\n")

--２つのcipherが記述された配列を比較して合致するものを抽出する関数
local function search_algorithm(client,server)
	local found_match = false

	for i = 3, #client do
        for j = 3, #server do
            if client[i] == server[j] then
                table.insert(cipher_table,client[i])
				total_cipher_count = total_cipher_count + 1
				if not client_cipher_counts[client[i]] then
					client_cipher_counts[client[i]] = 1
				else
					client_cipher_counts[client[i]] = client_cipher_counts[client[i]] + 1
				end
				found_match = true
				break
            end
        end
		if found_match then
			break
		end
    end
end

--sshバージョンを取得する関数
local function get_client_version()
	local src_ip_str = tostring(src_ip())
	local dst_port_str = tostring(dst_port_field())
	-- if src_ip_str does not start with 10.
	-- if not string.starts(src_ip_str, "10.") then
		if version() then
			if dst_port_str == tostring(ssh_port) then
				local client_version = tostring(version())
				--クライアントIPによる重複チェック
				if not version_table[src_ip_str] then
					version_table[src_ip_str] = {}
					table.insert(version_table[src_ip_str], tostring(version()))
					totatl_version_count = totatl_version_count + 1
				else
					table.insert(version_table[src_ip_str], tostring(version()))
					totatl_version_count = totatl_version_count + 1
				end

				if not client_version_counts[client_version] then
					client_version_counts[client_version] = 1
				else
					client_version_counts[client_version] = client_version_counts[client_version] + 1
				end
			end
		end
	-- end
end

--パケット事のsrcIP,dstIP,cipherを一つの配列にまとめる関数
local function get_packet_info()
	local client_cipher = client_cipher_field()
	local dst_port = dst_port_field()
	local src_port = src_port_field()

	if client_cipher then
		packet_info[#packet_info + 1] ={src_port(),dst_port(),client_cipher()}
	end
end

--cipherを取得する関数
local function get_cipher()
	
	for _, packet in ipairs(packet_info) do
		for cipher in packet[3]:gmatch("[^,]+") do
			table.insert(packet,cipher)
		end
		table.remove(packet,3)
	end

	for _, client_cipher_list in ipairs(packet_info) do
		if client_cipher_list[2] == ssh_port then
			for _, server_cipher_list in ipairs(packet_info) do
				if client_cipher_list[1] == server_cipher_list[2] then
					search_algorithm(client_cipher_list,server_cipher_list)
				end
			end
		end
	end
end

--各バージョン，cipherの割合を出力する関数
local function calculate_percentages(index,allCount)
	local percentages = {}
	for version, count in pairs(index) do
		percentages[version] = (count / allCount) * 100
	end
	return percentages
end

function tap.packet(pinfo, tvb, tapdata) --1packet毎に行われる処理
	get_client_version()
	get_packet_info()
end
-- function tap.draw() end
function tap.reset()
	--cipherリストの出力
	get_cipher()

	-- クライアントデータの集計後に割合を表示
	local client_version_percentages = calculate_percentages(client_version_counts,totatl_version_count)
	for version, percentage in pairs(client_version_percentages) do
		version_file:write(string.format("%s,%.2f\n",version,percentage))
	end
	local client_cipher_percentegaes = calculate_percentages(client_cipher_counts,total_cipher_count)
	for cipher, percentage in pairs(client_cipher_percentegaes) do
		cipher_file:write(string.format("%s,%.2f\n",cipher,percentage))
	end

	cipher_file:close()
	version_file:close()
end