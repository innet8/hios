package constant

const installBase = string(`#!/bin/bash
#fonts color
Green="\033[32m"
Red="\033[31m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

#notification information
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

source '/etc/os-release' > /dev/null

if [ -f "/usr/bin/yum" ] && [ -d "/etc/yum.repos.d" ]; then
    PM="yum"
elif [ -f "/usr/bin/apt-get" ] && [ -f "/usr/bin/dpkg" ]; then
    PM="apt-get"        
else
    echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font}"
    exit 1
fi

judge() {
    if [[ 0 -eq $? ]]; then
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 失败 ${Font}"
        exit 1
    fi
}

check_system() {
    sudo $PM update -y
    sudo $PM install -y curl wget socat
    judge "安装脚本依赖"
    #
    if [ "${PM}" = "yum" ]; then
        sudo yum install -y epel-release
    fi
}

check_docker() {
    docker --version &> /dev/null
    if [ $? -ne  0 ]; then
        echo -e "安装docker环境..."
        curl -sSL https://get.daocloud.io/docker | sh
        echo -e "${OK} Docker环境安装完成!"
    fi
    systemctl start docker
    judge "Docker 启动"
    #
    docker-compose --version &> /dev/null
    if [ $? -ne  0 ]; then
        echo -e "安装docker-compose..."
        curl -s -L "https://get.daocloud.io/docker/compose/releases/download/v2.7.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
        echo -e "${OK} Docker-compose安装完成!"
        service docker restart
    fi
}

add_swap() {
    local swap=$(echo "$1"| awk '{print int($0)}')
    if [ "$swap" -gt "0" ]; then
        if [ -z "$(swapon --show | grep 'hicloudswap')" ] || [ "$(cat /.hicloudswap_size)" != "$swap" ]; then
            [ -n "$(swapon --show | grep 'hicloudswap')" ] && swapoff /hicloudswap;
            dd if=/dev/zero of=/hicloudswap bs=1M count="$swap"
            chmod 600 /hicloudswap
            mkswap /hicloudswap
            swapon /hicloudswap
            echo "$swap" > /.hicloudswap_size
            [ -z "$(cat /etc/fstab | grep '/hicloudswap')" ] && echo "/hicloudswap swap swap defaults 0 0" >> /etc/fstab
        fi
    fi
}

add_supervisor() {
    if [ "${PM}" = "yum" ]; then
        sudo yum install -y supervisor
        sudo systemctl enable supervisord
        sudo systemctl start supervisord
    elif [ "${PM}" = "apt-get" ]; then
        sudo apt-get install -y supervisor
        sudo systemctl start supervisor
    fi
    #
    touch /var/.hicloud/hios.sh
    cat > /var/.hicloud/hios.sh <<-EOF
#!/bin/bash
if [ -f "/var/.hicloud/hios" ]; then
    chmod +x /var/.hicloud/hios
    host=\$(echo "\$SERVER_URL" | awk -F "/" '{print \$3}')
    exi=\$(echo "\$SERVER_URL" | grep 'https://')
    if [ -n "\$exi" ]; then
        url="wss://\${host}/ws"
    else
        url="ws://\${host}/ws"
    fi
    /var/.hicloud/hios work --server="\${url}?action=nodework&nodemode=\${NODE_MODE}&nodename=\${NODE_NAME}&nodetoken=\${NODE_TOKEN}&hostname=\${HOSTNAME}"
else
    echo "hios file does not exist"
    sleep 5
    exit 1
fi
EOF
    chmod +x /var/.hicloud/hios.sh
    #
    local superfile=/etc/supervisor/conf.d/hicloud.conf
    if [ -f /etc/supervisord.conf ]; then
        superfile=/etc/supervisord.d/hicloud.ini
    fi
    touch $superfile
    cat > $superfile <<-EOF
[program:hicloud]
directory=/var/.hicloud
command=/bin/bash -c /var/.hicloud/hios.sh
numprocs=1
autostart=true
autorestart=true
startretries=100
user=root
redirect_stderr=true
environment=SERVER_URL={{.SERVER_URL}},NODE_NAME={{.NODE_NAME}},NODE_TOKEN={{.NODE_TOKEN}},NODE_MODE=host
stdout_logfile=/var/log/supervisor/%(program_name)s.log
EOF
    #
    supervisorctl update hicloud >/dev/null
    supervisorctl restart hicloud
}

remove_supervisor() {
    rm -f /etc/supervisor/conf.d/hicloud.conf
    rm -f /etc/supervisord.d/hicloud.ini
    supervisorctl stop hicloud >/dev/null 2>&1
    supervisorctl update >/dev/null 2>&1
}

echo "error" > /tmp/.hicloud_installed

if [ "$1" = "install" ]; then
    check_system
    check_docker
    add_supervisor
    add_swap "{{.SWAP_FILE}}"
elif [ "$1" = "remove" ]; then
    docker --version &> /dev/null
    if [ $? -eq  0 ]; then
        ll=$(docker ps -a --format "table {{"{{"}}.Names{{"}}"}}\t{{"{{"}}.ID{{"}}"}}" | grep -E "^hicloud\-" | awk '{print $2}')
        ii=$(docker images --format "table {{"{{"}}.Repository{{"}}"}}\t{{"{{"}}.ID{{"}}"}}" | grep -E "^kuaifan\/hicloud" | awk '{print $2}')
        [ -n "$ll" ] && docker rm -f $ll &> /dev/null
        [ -n "$ii" ] && docker rmi -f $ii &> /dev/null
    fi
    remove_supervisor
fi

echo "success" > /tmp/.hicloud_installed
`)
