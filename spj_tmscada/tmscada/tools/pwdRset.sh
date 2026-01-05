#! /bin/sh
# 修改初始密码&卸载webmin服务
#echo -e "\e[45m 设备重启进行中... \e[0m"
#echo -e "设备重启进行中..."

if [[ $0 =~ ^\/.* ]]; then    									#判断当前脚本是否为绝对路径，匹配以/开头下的所有
	SCRIPT=$0
else
	SCRIPT=$(pwd)/$0
fi
SCRIPT_PATH=$(cd $(dirname $0); pwd)  						#获取脚本的真实路径
SCRIPT_DIR_PATH=$(cd $(dirname $0) && pwd)   				#获取脚本所在目录的真实路径
UPDATE_PATH=$(cd $(dirname $SCRIPT_DIR_PATH) && pwd)   		#获取脚本所在目录的父目录的真实路径 iD201*2023

echo root:iD201*2023 | chpasswd #>/dev/null 2>&1
echo "root default password has changed"

ps -ef | grep webmin | grep -v grep
if [ $? -eq 0 ]
then
apt-get remove -y webmin #>/dev/null 2>&1
echo "removed Webmin success"
else
echo "Webmin has removed"
fi
exit
