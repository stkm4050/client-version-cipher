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
local client_version_counts = {}
local client_cipher_counts = {}
local packet_info = {}
local cipher_table = {}
local totatl_version_count = 0
local total_cipher_count = 0

--クライアントバージョンごとのCipher割合のための変数
local version_list = {}
local cipher_list = {}
local version_cipher_counts = {}
local version_counts = {}

local output_file = io.open(file_name, "w")
output_file:write("SSHversion-Cipher,percentage\n")

--sshバージョンを取得する関数
local function get_client_version()
	local dst_port_str = tostring(dst_port_field())
	-- if src_ip_str does not start with 10.
	-- if not string.starts(src_ip_str, "10.") then
		if version() then
			if dst_port_str == tostring(ssh_port) then
				local client_version = tostring(version())
				totatl_version_count = totatl_version_count + 1
				if not client_version_counts[client_version] then
					client_version_counts[client_version] = 1
				else
					client_version_counts[client_version] = client_version_counts[client_version] + 1
				end
				version_list[#version_list+1] ={ tostring(src_ip()),tostring(src_port_field()),tostring(version())}
				
			end
		end
	-- end
end

--２つのcipherが記述された配列を比較して合致するものを抽出する関数
local function search_algorithm(client,server)
	local found_match = false

	for i = 4, #client do
        for j = 4, #server do
            if client[i] == server[j] then
                table.insert(cipher_table,client[i])
				total_cipher_count = total_cipher_count + 1
				if not client_cipher_counts[client[i]] then
					client_cipher_counts[client[i]] = 1
				else
					client_cipher_counts[client[i]] = client_cipher_counts[client[i]] + 1
				end
				cipher_list[#cipher_list+1] ={client[1],client[2],client[i]}
				found_match = true
				break
            end
        end
		if found_match then
			break
		end
    end
end

--パケット事のsrcIP,dstIP,cipherを一つの配列にまとめる関数
local function get_packet_info()
	local client_cipher = client_cipher_field()
	local dst_port = dst_port_field()
	local src_port = src_port_field()

	if client_cipher then
		packet_info[#packet_info + 1] ={tostring(src_ip()),src_port(),dst_port(),client_cipher()}
	end
end

--cipherを取得する関数
local function get_cipher()
	
	for _, packet in ipairs(packet_info) do
		for cipher in packet[4]:gmatch("[^,]+") do
			table.insert(packet,cipher)
		end
		table.remove(packet,4)
	end

	for i, client_cipher_list in ipairs(packet_info) do
		if client_cipher_list[3] == ssh_port then
			for j, server_cipher_list in ipairs(packet_info) do
				if client_cipher_list[2] == server_cipher_list[3] then
					search_algorithm(client_cipher_list,server_cipher_list)
					table.remove(packet_info,i)
					table.remove(packet_info,j)
					break
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

--割合の多い順に並び替える関数
local function sort_percentages(percentages_table)
	local sorted_percentages_table = {}
	for key, percentage in pairs(percentages_table) do
		table.insert(sorted_percentages_table, {key=key,percentage=percentage})
	end
	table.sort(sorted_percentages_table, function(a,b) return a.percentage > b.percentage end)
	return sorted_percentages_table
end

--クライアントバージョン毎のCipherの割合調査
local function version_cipher_parcent()
	local percentages = {}
	for versions_key, cipher_data in pairs(version_cipher_counts) do
        for cipher_key, counts in pairs(cipher_data) do
			for version_key, count in pairs(version_counts) do
				if versions_key == version_key then
					percentages[version_key.."-"..cipher_key] = (counts/count)*100
				end
			end
        end
    end
	local newpercentages = sort_percentages(percentages)
	for _, data in pairs(newpercentages) do
		-- print(string.format("Version-cipher: %s, percent: %.2f\n",version,percent))
		output_file:write(string.format("%s,%.2f\n",data.key,data.percentage))
	end

end

--クライアントバージョン毎のCipherを算出
local function set_version_cipher()
	local k = 1
	for i in ipairs(version_list) do
		for j in ipairs(cipher_list) do
			if version_list[i][1] == cipher_list[j][1] then
				if version_list[i][2] == tostring(cipher_list[j][2]) then

					local version_key = version_list[i][3]
					if not version_cipher_counts[version_key] then
						version_cipher_counts[version_key] = {}
						version_counts[version_key] = 1
					else
						version_counts[version_key] = version_counts[version_key] + 1
					end

					local cipher_key = cipher_list[j][3]
					if not version_cipher_counts[version_key][cipher_key] then
						version_cipher_counts[version_key][cipher_key] = 1
					else
						version_cipher_counts[version_key][cipher_key] = version_cipher_counts[version_key][cipher_key] + 1
					end
			
					-- print(version_key)
					-- print(cipher_key)
					-- print(version_cipher_counts[version_key][cipher_key])

					version_list[i][1]=("No Version")
					version_list[i][2]=("No Version port")
					cipher_list[j][1]=("No Cipher")
					cipher_list[j][2]=("No Cipher port")
				end
			end
		end
	end
	version_cipher_parcent()
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
	local client_cipher_percentegaes = calculate_percentages(client_cipher_counts,total_cipher_count)

	set_version_cipher()
	output_file:close()
end