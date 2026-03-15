#!/bin/bash

IFACE=$1
if [ -z "$IFACE" ]; then
    echo "Loi: Thieu ten interface. Vi du: sudo ./test.sh eth1"
    exit 1
fi

# Xoa cau hinh cu
tc qdisc del dev "$IFACE" root 2>/dev/null
tc qdisc del dev "$IFACE" clsact 2>/dev/null

echo "--- Dang thiet lap QoS cho $IFACE ---"

tc qdisc add dev "$IFACE" root handle 1: htb default 50
if [ $? -ne 0 ]; then echo "Loi khi tao Root HTB"; exit 1; fi

# 2. Tao Class Cha
tc class add dev "$IFACE" parent 1: classid 1:1 htb rate 100mbit ceil 100mbit

#3. Tao cac Class con (Dinh nghia Service)
tc class add dev "$IFACE" parent 1:1 classid 1:10 htb rate 5mbit ceil 20mbit prio 0
tc class add dev "$IFACE" parent 1:1 classid 1:20 htb rate 40mbit ceil 80mbit prio 1
tc class add dev "$IFACE" parent 1:1 classid 1:30 htb rate 20mbit ceil 50mbit prio 2
tc class add dev "$IFACE" parent 1:1 classid 1:40 htb rate 10mbit ceil 30mbit prio 3
tc class add dev "$IFACE" parent 1:1 classid 1:50 htb rate 5mbit ceil 100mbit prio 4

#4. Gan FQ_CoDel cho tung class de toi uu do tre
tc qdisc add dev "$IFACE" parent 1:10 handle 10: fq_codel
tc qdisc add dev "$IFACE" parent 1:20 handle 20: fq_codel
tc qdisc add dev "$IFACE" parent 1:30 handle 30: fq_codel
tc qdisc add dev "$IFACE" parent 1:40 handle 40: fq_codel
tc qdisc add dev "$IFACE" parent 1:50 handle 50: fq_codel

BPF_OBJ="/home/dtuan/online_detect_qos/build/tc_prog.o"

#5. Gan BPF Filter (Kiem tra file .o truoc khi chay)
if [ -f "$BPF_OBJ" ]; then
    tc qdisc del dev "$IFACE" clsact 2>/dev/null
    tc qdisc add dev "$IFACE" clsact
    tc filter add dev "$IFACE" ingress bpf obj "$BPF_OBJ" sec tc da
    echo "Done: Da attach BPF Filter."
else
    echo "Canh bao: Khong tim thay file "$BPF_OBJ", bo qua buoc filter."
fi

echo "--- Hoan thanh cau hinh ---"
