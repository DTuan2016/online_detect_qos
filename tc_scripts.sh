tc qdisc add dev eth0 root handle 1: htb default 30

# Lớp tổng
tc class add dev eth0 parent 1: classid 1:1 htb rate 100mbit

# Phân chia chi tiết
tc class add dev eth0 parent 1:1 classid 1:10 htb rate 5mbit ceil 10mbit prio 0
tc class add dev eth0 parent 1:1 classid 1:20 htb rate 40mbit ceil 90mbit prio 1
tc class add dev eth0 parent 1:1 classid 1:30 htb rate 30mbit ceil 100mbit prio 2
tc class add dev eth0 parent 1:1 classid 1:40 htb rate 10mbit ceil 50mbit prio 3

tc qdisc add dev eth0 parent 1:10 handle 10: fq_codel
tc qdisc add dev eth0 parent 1:20 handle 20: fq_codel
tc qdisc add dev eth0 parent 1:30 handle 30: fq_codel
tc qdisc add dev eth0 parent 1:40 handle 40: fq_codel

# VOIP (Label 40) vào làn 1:10
tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip tos 40 0xff flowid 1:10

# STREAMING (Label 32) và CHAT (Label 8) vào làn 1:20
tc filter add dev eth0 protocol ip parent 1:0 prio 2 u32 match ip tos 32 0xff flowid 1:20
tc filter add dev eth0 protocol ip parent 1:0 prio 2 u32 match ip tos 8 0xff flowid 1:20

# P2P (Label 24) và FT (Label 16) vào làn 1:40
tc filter add dev eth0 protocol ip parent 1:0 prio 4 u32 match ip tos 24 0xff flowid 1:40
tc filter add dev eth0 protocol ip parent 1:0 prio 4 u32 match ip tos 16 0xff flowid 1:40