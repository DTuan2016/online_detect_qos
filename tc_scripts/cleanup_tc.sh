#!/usr/bin/env bash

IFACE=${1:-eth0}

echo "Removing TC configuration on $IFACE"

sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true

echo "Done"
