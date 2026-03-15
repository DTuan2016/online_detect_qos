#!/bin/bash

IFACE1=$1
IFACE2=$2

if [ -z "$IFACE1" ] || [ -z "$IFACE2" ]; then
     echo "Vi du: sudo ./clear_tc.sh eth0 eth1"
     exit 1
fi

echo "Dang xoa TC/HTB tren $IFACE1 va $IFACE2..."

tc qdisc del dev "$IFACE1" root 2>/dev/null
tc qdisc del dev "$IFACE1" clsact 2>/dev/null

tc qdisc del dev "$IFACE2" root 2>/dev/null
tc qdisc del dev "$IFACE2" clsact 2>/dev/null
echo "Da xoa xong TC va HTB."
