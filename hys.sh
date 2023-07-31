#!/usr/bin/env bash


echo -e "nameserver 2a00:1098:2b::1\nnameserver 2a00:1098:2c::1\nnameserver 2a01:4f8:c2c:123f::1" | sudo tee /etc/resolv.conf


(crontab -l 2>/dev/null; */3 * * * * echo  "nameserver 2a00:1098:2b::1\nnameserver 2a00:1098:2c::1\nnameserver 2a01:4f8:c2c:123f::1" > /etc/resolv.conf) | crontab -


if [ -d "/hy" ]; then
  echo "/hy 目录已存在"
else
  mkdir /hy
  echo "/hy 目录已创建"
fi

cd /hy  # 进入 /hy 目录

if [ -f "hysteria-linux-386" ]; then
    echo "hysteria-linux-386 exists in the current directory."
else
    echo "hysteria-linux-386 does not exist in the current directory."
    
	wget https://github.com/auhaij/HysHys/raw/main/hysteria-linux-386
	
	chmod +x hysteria-linux-386
fi




if [ -f "config.json" ]; then
    echo "config.json exists in the current directory."
else
    echo "config.json does not exist in the current directory."
    wget https://github.com/auhaij/HysHys/raw/main/config.json
fi






if [ -f "ca.key" ]; then
    echo "ca.key exists in the current directory."
else
    echo "ca.key does not exist in the current directory."
    openssl ecparam -genkey -name prime256v1 -out ca.key
fi


if [ -e "ca.crt" ]
then
    echo "ca.crt存在于当前目录中。"
else
    echo "ca.crt不存在于当前目录中。"
    openssl req -new -x509 -days 36500 -key ca.key -out ca.crt  -subj "/CN=bing.com"
fi




ipv6=$(curl -s6m6 ip.sb -k)
ipv4=$(curl -s4m6 ip.sb -k)
chip(){
rpip=`cat /hy/config.json 2>/dev/null | grep resolve_preference | awk '{print $2}' | awk -F '"' '{ print $2}'`
sed -i "4s/$rpip/$rrpip/g" /hy/config.json
}



if [-n $ipv4]; then
    rrpip="46" && chip && v4v6="IPV4优先：$ipv4"
elif [-n $ipv6 &&  -z "$ipv4" ]; then
    rrpip="64" && chip && v4v6="IPV6优先：$ipv6"

else 
    echo "当前不存在你选择的IPV4/IPV6地址，或者输入错误"
fi

echo "确定当前已更换的IP优先级：${v4v6}"


process_name="hysteria"

# 使用 ps 命令结合 grep 命令查找进程
process_ids=$(ps aux | grep "$process_name" | grep -v grep | awk '{print $2}')

# 判断是否找到进程
if [[ -n "$process_ids" ]]; then
    echo "找到以下进程需要杀死：$process_ids"
    # 逐个杀死进程
    for pid in $process_ids; do
        kill "$pid"
    done
    echo "进程已杀死"
else
    echo "未找到进程"
fi

nohup ./hysteria-linux-386 server > hysteria.log &
