#!/bin/bash

for ago in 1 2 3 4 5 6 7;
do
	month=$(date -d "-${ago} day" +%m)
    day=$(date -d "-${ago} day"  +%d)

	mkdir -p /home/kamada/packet/csv/${month}

	scp honey:/home/koba/Research/dump/port22-2024${month}${day}0000.dump /home/kamada/packet/honey
	tshark -o "ssh.tcp.port:22" -X lua_script:get_ip_client.lua -X lua_script1:/home/kamada/packet/honey/port22-2024${month}${day}0000.dump -X lua_script1:22 -X lua_script1:/home/kamada/packet/csv/${month}/${month}${day}.csv -r /home/kamada/packet/honey/port22-2024${month}${day}0000.dump -q
	scp honey:/home/koba/Research/dump-cririn/port22-2024${month}${day}0000.dump /home/kamada/packet/cririn
	tshark -o "ssh.tcp.port:22" -X lua_script:get_ip_client.lua -X lua_script1:/home/kamada/packet/cririn/port22-2024${month}${day}0000.dump -X lua_script1:22 -X lua_script1:/home/kamada/packet/csv/${month}/${month}${day}_cririn.csv -r /home/kamada/packet/cririn/port22-2024${month}${day}0000.dump -q
	tshark -o "ssh.tcp.port:22" -X lua_script:version_cipher.lua -X lua_script1:/home/kamada/packet/honey/port22-2024${month}${day}0000.dump -X lua_script1:22 -X lua_script1:/home/kamada/packet/csv/version-cipher/${month}/${month}${day}.csv -r /home/kamada/packet/honey/port22-2024${month}${day}0000.dump -q
	tshark -o "ssh.tcp.port:22" -X lua_script:version_cipher.lua -X lua_script1:/home/kamada/packet/cririn/port22-2024${month}${day}0000.dump -X lua_script1:22 -X lua_script1:/home/kamada/packet/csv/version-cipher/${month}/${month}${day}_cririn.csv -r /home/kamada/packet/cririn/port22-2024${month}${day}0000.dump -q
	
done
