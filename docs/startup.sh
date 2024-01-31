#! /bin/bash

nohup java -jar RemoteKeyInjectServer.jar > /dev/null 2>&1 &
tpid=$!
echo ${tpid} > tpid
echo "Service has started. ${tpid}"
