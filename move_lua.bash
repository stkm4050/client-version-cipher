#!/bin/bash

#for date in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31;
for date in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16;
do
	scp honey:/home/koba/Research/dump/port22-202406${date}0000.dump /home/kamada/packet/honey
	tshark -o "ssh.tcp.port:22" -X lua_script:get_ip_client.lua -X lua_script1:/home/kamada/packet/honey/port22-202406${date}0000.dump -X lua_script1:22 -X lua_script1:/home/kamada/searchVersion/csv/6/06${date}.csv -r /home/kamada/packet/honey/port22-202406${date}0000.dump -q
	scp honey:/home/koba/Research/dump-cririn/port22-202406${date}0000.dump /home/kamada/packet/cririn
	tshark -o "ssh.tcp.port:22" -X lua_script:get_ip_client.lua -X lua_script1:/home/kamada/packet/cririn/port22-202406${date}0000.dump -X lua_script1:22 -X lua_script1:/home/kamada/searchVersion/csv/6/06${date}_cririn.csv -r /home/kamada/packet/cririn/port22-202406${date}0000.dump -q
done
