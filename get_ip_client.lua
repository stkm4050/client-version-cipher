-- Usage: tshark -X lua_script:stream.lua -X lua_script1:<capture file> -r <capture file>
-- Example: ls *.dump | xargs -I {} -P 1 sh -c "tshark -X lua_script:get_reset.lua -X lua_script1:{} -r {} -q"
local args = { ... }
local pcap_file = args[1]
local client = Field.new("ssh.protocol")
local src_ip = Field.new("ip.src")
local dst_port_field = Field.new("tcp.dstport")
local src_port_field = Field.new("tcp.srcport")
local client_cipher_field = Field.new("ssh.encryption_algorithms_client_to_server")
local server_cipher_field = Field.new("ssh.encryption_algorithms_server_to_client")

-- local tap = Listener.new(nil, "ssh") --port 22を見る設定←ここを特定のものに変更する必要がる
local tap = Listener.new(nil, "tcp.port == 49538 or tcp.port == 10000 or tcp.port == 22") --変更のテスト中
function string.starts(String, Start)
	return string.sub(String, 1, string.len(Start)) == Start
end

local ip_table = {}
local client_table = {}
local client_version_counts = {}
local cipher_info = {}
local cipher_table = {}
local total_count = 0
local function unique(t)
	local uniqueElements = {}
	if type(t) == "table" then
		for k, v in pairs(t) do
			if not uniqueElements[v] then
				uniqueElements[v] = true
			end
		end
	elseif type(t) == "userdata" and t:dim() == 1 then
		for i = 1, t:size(1) do
			uniqueElements[t[i]] = true
		end
	elseif type(t) == "userdata" and t:dim() == 2 then
		for r = 1, t:size(1) do
			for c = 1, t:size(2) do
				uniqueElements[t[r][c]] = true
			end
		end
	else
		error("bad type or dim for t; type(t) = " .. type(t))
	end
	local result = {}
	for k, v in pairs(uniqueElements) do
		table.insert(result, k)
	end

	return result
end

local function get_client()
	local src_ip_str = tostring(src_ip())
	local dst_port_str = tostring(dst_port_field())
	-- if src_ip_str does not start with 10.
	-- if not string.starts(src_ip_str, "10.") then
		if client() then
			if dst_port_str == "49538" then
				local client_version = tostring(client())
				--クライアントIPによる重複チェック
				if not client_table[src_ip_str] then
					client_table[src_ip_str] = {}
					table.insert(client_table[src_ip_str], tostring(client()))
					total_count = total_count + 1
				else
					table.insert(client_table[src_ip_str], tostring(client()))
					total_count = total_count + 1
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

local function get_cipher_info()
	local client_cipher = client_cipher_field()
	local dst_port = dst_port_field()
	local src_port = src_port_field()

	if client_cipher then
		cipher_info[#cipher_info + 1] ={src_port(),dst_port(),client_cipher()}
	end
end

local function get_cipher()
	for _, packet_info in ipairs(cipher_info) do
		local server_port = packet_info[1]
		local client_port = packet_info[0]
		if server_port == "49538" then
			for _, search_packet in ipairs(cipher_info) do
				if search_packet[1] == client_port then
					if not cipher_table[src_ip_str] then
						client_table[src_ip_str] = {}
						table.insert(client_table[src_ip_str], tostring(client()))
						total_count = total_count + 1
					else
						table.insert(client_table[src_ip_str], tostring(client()))
						total_count = total_count + 1
					end
					break
				end
			end
		end
	end

local function calculate_percentages()
	local percentages = {}
	for version, count in pairs(client_version_counts) do
		percentages[version] = (count / total_count) * 100
	end
	return percentages
end

function tap.packet(pinfo, tvb, tapdata) --1packet毎に行われる処理
	get_client()
	get_cipher_info()
end
function tap.draw() end
function tap.reset()
	for k, v in pairs(client_table) do
		local unique_v = unique(v)
		print(k .. "," .. table.concat(unique_v, ","))
	end
	-- クライアントデータの集計後に割合を表示
	local client_percentages = calculate_percentages()
		for version, percentage in pairs(client_percentages) do
			print(string.format("Version: %s, Percentage: %.2f%%", version, percentage))
		end
end
