IFACE=$1
REDIRECT_IF=$2

if [ -z "$IFACE" ]; then
    echo "Loi: Thieu interface vao"
    exit 1
fi

if [ -z "$REDIRECT_IF" ]; then
    echo "Loi: Thieu interface redirect"
    exit 1
fi

echo "--- Setup QoS tren $REDIRECT_IF ---"

# Xoa config cu
tc qdisc del dev "$REDIRECT_IF" root 2>/dev/null
tc qdisc del dev "$IFACE" clsact 2>/dev/null

# =============================
# HTB tren NIC redirect
# =============================

tc qdisc add dev "$REDIRECT_IF" root handle 1: htb default 50

tc class add dev "$REDIRECT_IF" parent 1: classid 1:1 htb rate 100mbit ceil 100mbit

tc class add dev "$REDIRECT_IF" parent 1:1 classid 1:10 htb rate 5mbit ceil 20mbit prio 0
tc class add dev "$REDIRECT_IF" parent 1:1 classid 1:20 htb rate 40mbit ceil 80mbit prio 1
tc class add dev "$REDIRECT_IF" parent 1:1 classid 1:30 htb rate 20mbit ceil 50mbit prio 2
tc class add dev "$REDIRECT_IF" parent 1:1 classid 1:40 htb rate 10mbit ceil 30mbit prio 3
tc class add dev "$REDIRECT_IF" parent 1:1 classid 1:50 htb rate 5mbit ceil 100mbit prio 4

tc qdisc add dev "$REDIRECT_IF" parent 1:10 handle 10: fq_codel
tc qdisc add dev "$REDIRECT_IF" parent 1:20 handle 20: fq_codel
tc qdisc add dev "$REDIRECT_IF" parent 1:30 handle 30: fq_codel
tc qdisc add dev "$REDIRECT_IF" parent 1:40 handle 40: fq_codel
tc qdisc add dev "$REDIRECT_IF" parent 1:50 handle 50: fq_codel

# =============================
# TC ingress tren NIC input
# =============================

echo "--- Setup TC ingress tren $IFACE ---"

tc qdisc add dev "$IFACE" clsact

BPF_OBJ="/home/dtuan/online_detect_qos/build/tc_prog.o"

if [ -f "$BPF_OBJ" ]; then
    tc filter add dev "$IFACE" ingress \
    prio 1 \
    bpf obj "$BPF_OBJ" sec tc
    echo "Done: Attach BPF classifier"
else
    echo "Khong tim thay BPF program"
fi

# =============================
# Redirect sang NIC HTB
# =============================

    tc filter add dev "$IFACE" ingress \
    protocol all \
    prio 100 \
    flower \
    action mirred egress redirect dev "$REDIRECT_IF"

echo "Done: Redirect $IFACE -> $REDIRECT_IF"
