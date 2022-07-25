#!/bin/bash

binDir="/usr/lib/hicloud/bin"

_wsurl() {
    local host=$(echo "$SERVER_URL" | awk -F "/" '{print $3}')
    local exi=$(echo "$SERVER_URL" | grep 'https://')
    if [ -n "$exi" ]; then
        echo "wss://${host}/ws"
    else
        echo "ws://${host}/ws"
    fi
}

_network() {
    local target=$SERVER_URL
    local ret_code=`curl -I -s --connect-timeout 1 -m 5 ${target} -w %{http_code} | tail -n1`
    if [ "x$ret_code" = "x200" ] || [ "x$ret_code" = "x301" ] || [ "x$ret_code" = "x302" ]; then
        return 1
    else
        return 0
    fi
    return 0
}

check_work() {
    local url=`_wsurl`
    local exist=`ps -ef | grep "${binDir}/hios work" | grep -v "grep"`
    [ -n "$url" ] && [ -z "$exist" ] && {
        _network
        if [ $? -eq 0 ]; then
            echo "network is blocked, try again 10 seconds"
        else
            echo "${url}?action=nodework&nodemode=${NODE_MODE}&nodename=${NODE_NAME}&nodetoken=${NODE_TOKEN}&hostname=${HOSTNAME}" > ${binDir}/.work-server
            nohup ${binDir}/hios work > /dev/null 2>&1 &
        fi
    }
}

if [ -f ${binDir}/hios ]; then
    chmod +x ${binDir}/hios
fi

if [ -f ${binDir}/xray ]; then
    chmod +x ${binDir}/xray
fi

while true; do
    sleep 10
    check_work > /dev/null 2>&1 &
done
