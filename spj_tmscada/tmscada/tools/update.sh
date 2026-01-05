#! /bin/sh

#echo -e "\e[45m 运行环境配置进行中... \e[0m"
echo -e "运行环境配置进行中..."

if [[ $0 =~ ^\/.* ]]; then    									#判断当前脚本是否为绝对路径，匹配以/开头下的所有
	SCRIPT=$0
else
	SCRIPT=$(pwd)/$0
fi
SCRIPT_PATH=$(cd $(dirname $0); pwd)  						#获取脚本的真实路径
SCRIPT_DIR_PATH=$(cd $(dirname $0) && pwd)   				#获取脚本所在目录的真实路径
UPDATE_PATH=$(cd $(dirname $SCRIPT_DIR_PATH) && pwd)   		#获取脚本所在目录的父目录的真实路径

sudo rm -rf /etc/network/interfaces #>/dev/null 2>&1
sudo sync
sudo cp -rf $UPDATE_PATH/interfaces /etc/network/ #>/dev/null 2>&1
if [ $? -ne 0 ]; then
    #echo -e "\e[41m interfaces文件不存在... \e[0m"
	echo -e "interfaces文件不存在..."
	#echo -e "\e[41m 运行环境配置失败！！！ \e[0m"
	echo -e "运行环境配置失败！！"
	exit
fi
sudo sync
# sudo ifconfig #>/dev/null 2>&1
# sudo sync
sudo ls -l /etc/network #>/dev/null 2>&1
sleep 1
sudo sync
sudo rm -rf /etc/init.d/opc_ua.sh #>/dev/null 2>&1
sudo sync
sudo cp -rf $UPDATE_PATH/opc_ua.sh /etc/init.d/ #>/dev/null 2>&1
if [ $? -ne 0 ]; then
    #echo -e "\e[41m opc_ua.sh文件不存在... \e[0m"
	echo -e "opc_ua.sh文件不存在..."
	#echo -e "\e[41m 运行环境配置失败！！！ \e[0m"
	echo -e "运行环境配置失败！！！"
	exit
fi
sudo sync
sleep 1
sudo sync
sudo rm -rf /etc/rc5.d/S99opc_ua.sh #>/dev/null 2>&1
sudo sync
sudo ln -s /etc/init.d/opc_ua.sh /etc/rc5.d/S99opc_ua.sh #>/dev/null 2>&1
sudo sync
sleep 1
sudo sync
sleep 1
sudo sync
sleep 1
sudo sync
#echo -e "\e[46m 运行环境配置成功！！！ \e[0m"
echo -e "运行环境配置成功！！！"
exit
