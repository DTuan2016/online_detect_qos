#!/usr/bin/env bash

set -e

IFACE=${1:-eth0}
BPF_OBJ=${2:-tc_prog.o}

echo "Interface: $IFACE"
echo "BPF object: $BPF_OBJ"

echo "-----------------------------"
echo "1. Remove existing qdisc"
sudo tc qdisc del dev $IFACE clsact 2>/dev/null || true

echo "-----------------------------"
echo "2. Add clsact qdisc"
sudo tc qdisc add dev $IFACE clsact

echo "-----------------------------"
echo "3. Attach TC egress program"
sudo tc filter add dev $IFACE egress \
    bpf da obj $BPF_OBJ sec tc

echo "-----------------------------"
echo "4. Show qdisc"
tc qdisc show dev $IFACE

echo "-----------------------------"
echo "5. Show filters"
#tc filter show dev $IFACE ingress
tc filter show dev $IFACE egress

echo "-----------------------------"
echo "TC setup complete"
