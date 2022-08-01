#!/bin/bash

binDir="/usr/lib/hicloud/bin"

load_init() {
    if [ -f ${binDir}/hios ]; then
        chmod +x ${binDir}/hios
    fi

    if [ -f ${binDir}/xray ]; then
        chmod +x ${binDir}/xray
    fi

    exist=`ps -ef | grep "${binDir}/hios work" | grep -v "grep"`
    if [ -z "$exist" ]; then
        nohup ${binDir}/hios work > /dev/null 2>&1 &
    fi

    if [ -n "${HI_NETIP}" ] && [ -n "${HI_NETGW}" ]; then
        expect <<EOF
set timeout 300
spawn su vyos
expect "vyos@" { send "configure\n" }
expect "#" { send "set system name-server 8.8.8.8\n" }
expect "#" { send "set protocols static route 0.0.0.0/0 next-hop ${HI_NETGW}\n" }
expect "#" { send "set interfaces ethernet eth0 address ${HI_NETIP}/24\n" }
expect "#" { send "set interfaces ethernet eth0 ipv6 address no-default-link-local\n" }
expect "#" { send "commit\n" }
expect "#" { send "save\n" }
expect "#" { send "exit\n" } expect eof
interact
EOF
    fi

    cat > /etc/dnsmasq.conf <<EOF
user=dnsmasq
all-servers
cache-size=150
clear-on-reload
resolv-file=/etc/resolv.dnsmasq.conf
conf-dir=/etc/dnsmasq.d
EOF
    echo "nameserver 127.0.0.11" > /etc/resolv.dnsmasq.conf
}

load_boot() {
    file=$1
    if [ -f "${file}" ]; then
        expect <<EOF
set timeout 300
spawn su vyos
expect "vyos@" { send "configure\n" }
expect "#" { send "load ${file}\n" }
expect "#" { send "commit\n" }
expect "#" { send "save\n" }
expect "#" { send "exit\n" } expect eof
interact
EOF
    fi
}

########################################################################
########################################################################
########################################################################

if [ "$1" = "load" ]; then
    # 加载配置文件：文件路径
    load_boot $2
else
    # 初始化并启动hios
    load_init
fi