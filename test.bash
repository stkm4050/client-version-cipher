#!/bin/bash


for ago in 1 2 3 4 5 6 7; 
do
	month=$(date -d "-${ago} day" +%m)
	day=$(date -d "-${ago} day"  +%d)

	echo $month	
	echo $day
done
