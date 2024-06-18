#!/bin/bash

for date in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31;
do
	tshark -o "ssh.tcp.port:22" -X lua_script:get_ip_client.lua -X lua_script1:/home/kamada/packet/honey/port22-202405${date}0000.dump -X lua_script1:22 -X lua_script1:/home/kamada/searchVersion/csv/05${date}.csv -r /home/kamada/packet/honey/port22-202405${date}0000.dump -q
	tshark -o "ssh.tcp.port:22" -X lua_script:get_ip_client.lua -X lua_script1:/home/kamada/packet/cririn/port22-202405${date}0000.dump -X lua_script1:22 -X lua_script1:/home/kamada/searchVersion/csv/05${date}_cririn.csv -r /home/kamada/packet/cririn/port22-202405${date}0000.dump -q
done
