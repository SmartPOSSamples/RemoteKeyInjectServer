#! /bin/bash

tpid=`cat tpid`
kill -9 ${tpid}
echo "Service has started. ${tpid}"

