#! /bin/sh

#echo -e "\e[45m 运行环境恢复出厂进行中... \e[0m"
echo -e "运行环境恢复出厂进行中..."

if [[ $0 =~ ^\/.* ]]; then    									#判断当前脚本是否为绝对路径，匹配以/开头下的所有
	SCRIPT=$0
else
	SCRIPT=$(pwd)/$0
fi
SCRIPT_PATH=$(cd $(dirname $0); pwd)  						#获取脚本的真实路径
SCRIPT_DIR_PATH=$(cd $(dirname $0) && pwd)   				#获取脚本所在目录的真实路径
UPDATE_PATH=$(cd $(dirname $SCRIPT_DIR_PATH) && pwd)   		#获取脚本所在目录的父目录的真实路径

sudo rm -rf $UPDATE_PATH #>/dev/null 2>&1
sudo sync
sudo rm -rf /etc/network/interfaces #>/dev/null 2>&1
sudo sync
sudo cp -rf /etc/network/interfaces.default /etc/network/interfaces #>/dev/null 2>&1
sudo sync
sudo rm -rf /etc/init.d/opc_ua.sh #>/dev/null 2>&1
sudo sync
sudo rm -rf /etc/rc5.d/S99opc_ua.sh #>/dev/null 2>&1
sudo sync
sleep 1
sudo sync
#echo -e "\e[45m 运行环境恢复出厂成功！！！ \e[0m"
echo root:root | chpasswd #>/dev/null 2>&1
echo -e "运行环境恢复出厂成功！！！"
exit
