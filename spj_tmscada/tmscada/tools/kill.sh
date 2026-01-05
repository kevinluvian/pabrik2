#! /bin/sh

if [[ $0 =~ ^\/.* ]]; then    									#判断当前脚本是否为绝对路径，匹配以/开头下的所有
	SCRIPT=$0
else
	SCRIPT=$(pwd)/$0
fi
SCRIPT_PATH=$(cd $(dirname $0); pwd)  						#获取脚本的真实路径
SCRIPT_DIR_PATH=$(cd $(dirname $0) && pwd)   				#获取脚本所在目录的真实路径
UPDATE_PATH=$(cd $(dirname $SCRIPT_DIR_PATH) && pwd)   		#获取脚本所在目录的父目录的真实路径

sudo ps -ef | grep "54_55_select" | grep -v "grep" | grep -v ps #>/dev/null 2>&1
if [ "$?" -eq 0 ]; then
	sudo killall -9 54_55_select #>/dev/null 2>&1
	sudo sync
fi

sudo ps -ef | grep "opc_ua_app_52" | grep -v "grep" | grep -v ps #>/dev/null 2>&1
if [ "$?" -eq 0 ]; then
	sudo killall -9 restart_52.sh #>/dev/null 2>&1
	sudo sync
	sudo killall -9 opc_ua_app_52 #>/dev/null 2>&1
	sudo sync
fi

sudo ps -ef | grep "opc_ua_app_53" | grep -v "grep" | grep -v ps #>/dev/null 2>&1
if [ "$?" -eq 0 ]; then
	sudo killall -9 restart_53.sh #>/dev/null 2>&1
	sudo sync
	sudo killall -9 opc_ua_app_53 #>/dev/null 2>&1
	sudo sync
fi

sudo ps -ef | grep "opc_ua_app_54" | grep -v "grep" | grep -v ps #>/dev/null 2>&1
if [ "$?" -eq 0 ]; then
	sudo killall -9 restart_54.sh #>/dev/null 2>&1
	sudo sync
	sudo killall -9 opc_ua_app_54 #>/dev/null 2>&1
	sudo sync
fi

sudo ps -ef | grep "opc_ua_app_55" | grep -v "grep" | grep -v ps #>/dev/null 2>&1
if [ "$?" -eq 0 ]; then
	sudo killall -9 restart_55.sh #>/dev/null 2>&1
	sudo sync
	sudo killall -9 opc_ua_app_55 #>/dev/null 2>&1
	sudo sync
fi

sudo ps -ef | grep "opc_ua_app_56" | grep -v "grep" | grep -v ps #>/dev/null 2>&1
if [ "$?" -eq 0 ]; then
	sudo killall -9 restart_56.sh #>/dev/null 2>&1
	sudo sync
	sudo killall -9 opc_ua_app_56 #>/dev/null 2>&1
	sudo sync
fi

sudo ps -ef | grep "opc_ua_app_57" | grep -v "grep" | grep -v ps #>/dev/null 2>&1
if [ "$?" -eq 0 ]; then
	sudo killall -9 restart_57.sh #>/dev/null 2>&1
	sudo sync
	sudo killall -9 opc_ua_app_57 #>/dev/null 2>&1
	sudo sync
fi
