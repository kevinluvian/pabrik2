#!/bin/sh

app_name="opc_ua_app_53"

while true
do
	ps -ef | grep $app_name | grep -v "grep"
	if [ "$?" -eq 1 ]
	then
		#printf "restart %s at %s\n" $app_name $(date +%Y-%m-%d_%H:%M:%S) >> appRestart.txt
		sleep 13
		cd /home/root/OPC_UA/
		./$app_name &
	else
		PID=$(ps -e | grep $app_name | awk '{printf $1}')
		CPU=$(top -b -n1 | grep $PID | awk '{print $9}' | awk -F. '{print $1}')  
		if [ $CPU -gt 60 ]
		then
			#printf "killApp at Date=%s, PID=%s, CPU=%s\n" $(date +%Y-%m-%d_%H:%M:%S) $PID $CPU >> appKill.txt
			kill -9 $PID
		fi	
	fi
	sleep 10
done