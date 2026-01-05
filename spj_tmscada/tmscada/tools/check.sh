#! /bin/sh

#echo -e "\e[45m 运行环境检测进行中... \e[0m"
echo -e "运行环境检测进行中..."

if [[ $0 =~ ^\/.* ]]; then    									#判断当前脚本是否为绝对路径，匹配以/开头下的所有
	SCRIPT=$0
else
	SCRIPT=$(pwd)/$0
fi
SCRIPT_PATH=$(cd $(dirname $0); pwd)  						#获取脚本的真实路径
SCRIPT_DIR_PATH=$(cd $(dirname $0) && pwd)   				#获取脚本所在目录的真实路径
UPDATE_PATH=$(cd $(dirname $SCRIPT_DIR_PATH) && pwd)   		#获取脚本所在目录的父目录的真实路径

sudo ifconfig #>/dev/null 2>&1
if [ $? -eq 0 ]; then
	IF_ETH0_IP=$(sudo ifconfig | grep -A1 "eth0" | grep 'inet addr' | awk -F ':' '{print $2}' | awk '{print $1}')
    IF_ETH1_IP=$(sudo ifconfig | grep -A1 "eth1" | grep 'inet addr' | awk -F '--' '{printf $1}' | awk -F 'eth1:1' '{printf $1}' | awk -F ':' '{print $2}' | awk '{print $1}')
	IF_ETH1_S1_IP=$(sudo ifconfig | grep -A1 "eth1:1" | grep 'inet addr' | awk -F ':' '{print $2}' | awk '{print $1}')
fi
sudo sync

INTERFACES_PATH=/etc/network/interfaces
IN_ETH0_IP=$(sudo grep -A1 "iface eth0 inet static" $INTERFACES_PATH | grep -v "iface eth0 inet static" | awk -F 'address' '{print $2}' | awk '{print $1}')
IN_ETH1_IP=$(sudo grep -A1 "iface eth1 inet static" $INTERFACES_PATH | grep -v "iface eth1 inet static" | awk -F 'address' '{print $2}' | awk '{print $1}')
IN_ETH1_S1_IP=$(sudo grep -A1 "iface eth1:1 inet static" $INTERFACES_PATH | grep -v "iface eth1:1 inet static" | awk -F 'address' '{print $2}' | awk '{print $1}')

if [ $IF_ETH0_IP != $IN_ETH0_IP ]; then
	#echo -e "\e[41m eth0 IP配置错误... \e[0m"
	echo -e "eth0 IP配置错误..."
	#echo -e "\e[41m 运行环境检测结果：异常 \e[0m"
	echo -e "运行环境检测结果：异常"
	exit
elif [ $IF_ETH1_IP != $IN_ETH1_IP ]; then
	#echo -e "\e[41m eth1 IP配置错误... \e[0m"
	echo -e "\e[41m eth1 IP配置错误... \e[0m"
	#echo -e "\e[41m 运行环境检测结果：异常 \e[0m"
	echo -e "运行环境检测结果：异常"
	exit
elif [ $IF_ETH1_S1_IP != $IN_ETH1_S1_IP ]; then
	#echo -e "\e[41m eth1:1 IP配置错误... \e[0m"
	echo -e "eth1:1 IP配置错误..."
	#echo -e "\e[41m 运行环境检测结果：异常 \e[0m"
	echo -e "运行环境检测结果：异常"
	exit
else
	#echo -e "\e[46m 网络配置结果：正常 \e[0m"
	echo -e "网络配置结果：正常"
fi

if [ ! -f "$UPDATE_PATH/myconfig.ini" ]; then
	#echo -e "\e[41m OPC_UA应用程式运行结果：异常 \e[0m"
	echo -e "OPC_UA应用程式运行结果：异常"
	#echo -e "\e[41m 运行环境检测结果：异常 \e[0m"
	echo -e "运行环境检测结果：异常"
	exit
fi
MY_CONFIG=$(sudo awk -F '=' '/\[54_55_FLAG\]/{a=1}a==1&&$1~/54_55_value/{print $2;exit}' $UPDATE_PATH/myconfig.ini) 
if [[ $MY_CONFIG =~ "52" ]]; then
	sudo ps -ef | grep opc_ua_app_52 | grep -v grep | grep -v ps #>/dev/null 2>&1
elif [[ $MY_CONFIG =~ "53" ]]; then
	sudo ps -ef | grep opc_ua_app_53 | grep -v grep | grep -v ps #>/dev/null 2>&1
elif [[ $MY_CONFIG =~ "54" ]]; then
	sudo ps -ef | grep opc_ua_app_54 | grep -v grep | grep -v ps #>/dev/null 2>&1
elif [[ $MY_CONFIG =~ "55" ]]; then
	sudo ps -ef | grep opc_ua_app_55 | grep -v grep | grep -v ps #>/dev/null 2>&1
elif [[ $MY_CONFIG =~ "56" ]]; then
	sudo ps -ef | grep opc_ua_app_56 | grep -v grep | grep -v ps #>/dev/null 2>&1
elif [[ $MY_CONFIG =~ "57" ]]; then
	sudo ps -ef | grep opc_ua_app_57 | grep -v grep | grep -v ps #>/dev/null 2>&1
else
	sudo ps -ef | grep $MY_CONFIG | grep -v grep | grep -v ps #>/dev/null 2>&1
fi
if [ $? -ne 0 ]; then
	#echo -e "\e[41m OPC_UA应用程式运行结果：异常 \e[0m"
	echo -e "OPC_UA应用程式运行结果：异常"
	#echo -e "\e[41m 运行环境检测结果：异常 \e[0m"
	echo -e "运行环境检测结果：异常"
	exit
else
	#echo -e "\e[46m OPC_UA应用程式运行结果：正常 \e[0m"
	echo -e "OPC_UA应用程式运行结果：正常"
	OPC_UA="OPC_UA_"$MY_CONFIG
	VERSION_PATH=$UPDATE_PATH/version.txt
	OPC_UA_VERSION=$(sudo grep $OPC_UA $VERSION_PATH | awk '{print $2}')
	#echo -e "\e[46m 当前OPC_UA应用程式：$OPC_UA，版本：$OPC_UA_VERSION\e[0m"
	echo -e "当前OPC_UA应用程式：$OPC_UA，版本：$OPC_UA_VERSION"
fi
sudo sync
sleep 1
sudo sync
#echo -e "\e[46m 运行环境检测结果：正常 \e[0m"
echo -e "运行环境检测结果：正常"
exit
