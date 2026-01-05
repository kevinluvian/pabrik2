#!/bin/bash

rm /etc/network/interfaces
cp /home/root/OPC_UA/interfaces  /etc/network/
ls -l /etc/network
sleep 1
rm  /etc/init.d/opc_ua.sh
cp /home/root/OPC_UA/opc_ua.sh  /etc/init.d/
sleep 1
rm /etc/rc5.d/S99opc_ua.sh
ln -s /etc/init.d/opc_ua.sh /etc/rc5.d/S99opc_ua.sh
sync
sleep 1
sync
sleep 1
sync

