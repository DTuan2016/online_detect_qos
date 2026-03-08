# Enhancing QoS with XDP DSCP Classification and TC eBPF

## 1. Overview
This project implements a **QoS scheduling system using eBPF and Linux Traffic Control (TC)**. The system workflow:

1. **Traffic classification in XDP**
2. **Rewrite DSCP values in IPv4 header**
3. **TC eBPF program reads DSCP and assigns packet priority**
4. **HTB scheduler enforces QoS policies**

- **This design combines:**
    - **Low-latency packet processing (XDP)**
    - **Flexible traffic shaping (TC HTB)**

## 2. System Architecture
```bash
NIC RX
│
▼
XDP Program
├── Flow detection / ML classification
├── Rewrite DSCP field
▼
Kernel Network Stack
▼
TC egress eBPF
├── Read DSCP
├── Set skb->priority
▼
HTB QoS Scheduler
├── Real-time traffic
├── Interactive traffic
├── Default traffic
├── Bulk traffic
▼
NIC TX
```

### 2.1. Flow Detection / ML Classification:

The system performs **per-flow traffic analysis and machine learning classification directly in the XDP datapath**.

#### Flow Identification
- Each packet is parsed at the XDP layer to extract the **5-tuple flow key**:
    - Source IP
    - Destination IP
    - Source Port
    - Destination Port
    - Transport Protocol

- This information is stored in a `flow_key` structure and used as the key of the `xdp_flow_tracking` map.
    + BPF_MAP_TYPE_HASH: xdp_flow_tracking
    + key : struct flow_key
    + value : data_point
- Each entry (`data_point`) maintains statistics for a single network flow.
#### Flow Statistics Collection: 
- **Packet counters**
    - Total packets
    - Total bytes

- **Packet length statistics**
    - Minimum packet length
    - Maximum packet length
    - Sum of packet lengths
    - Mean packet length

- **Inter-arrival time (IAT) statistics**
    - Minimum IAT
    - Maximum IAT
    - Sum of IAT
    - Mean IAT
- The timestamp is obtained using: `bpf_ktime_get_ns()`

These statistics are continuously updated in the `update_stats()` function.
#### Feature Vector Construction
- The collected statistics are converted into a **fixed-point feature vector** used by the ML model.
- The following features are computed:

| Feature | Description |
|-------|-------------|
| Current packet length | Size of the current packet |
| Min IAT | Minimum inter-arrival time |
| Max IAT | Maximum inter-arrival time |
| Sum IAT | Total inter-arrival time |
| Mean IAT | Average inter-arrival time |
| Min packet length | Minimum packet size |
| Max packet length | Maximum packet size |
| Sum packet length | Total packet size |
| Mean packet length | Average packet size |

- All features are stored in: `dp->features[MAX_FEATURES]`
- Values are converted to **fixed-point representation** to allow arithmetic operations inside eBPF.
#### Detection Trigger
Classification is triggered after observing a fixed number of packets per flow: `NUM_PACKET` When: `total_pkts == NUM_PACKET`
### 2.2. Rewrite DSCP Field:

### 2.3. Traffic Classes
Traffic is grouped into **4 QoS classes** based on DSCP.

| Class | Traffic Type | DSCP | QoS Strategy |
|------|-------------|------|-------------|
| Real-time | VoIP | 40 | Ultra-low latency |
| Interactive | Chat, Streaming | 8, 32 | High priority |
| Default | Browsing, Mail | 0, 48 | Fair bandwidth |
| Bulk | File Transfer, P2P | 16, 24 | Lowest priority |

### 2.4. Priority Mapping

The TC program maps DSCP to `skb->priority`.

| skb->priority | Traffic Class |
|---------------|---------------|
| 3 | Real-time |
| 2 | Interactive |
| 1 | Default |
| 0 | Bulk |


## 3. Installation Guide

This section describes how to install dependencies, compile the eBPF programs, and deploy the **XDP + TC QoS system**.

### 3.1 Install Dependencies
- **Install dependencies:**
```bash
sudo apt update

sudo apt install -y \
clang \
llvm \
libelf-dev \
libbpf-dev \
gcc \
make \
iproute2 \
linux-tools-common \
linux-tools-generic \
linux-headers-$(uname -r)
```
- **Install bpftool:**
```bash
sudo apt install bpftool
```
- **Clone this repository:**
```bash
git clone --recurse-submodules https://github.com/DTuan2016/online_detect_qos.git
cd online_detect_qos
```
- **Compile libbpf, xdp-tools:**
```bash
cd external/libbpf
make
sudo make install

cd ../xdp-tools
make
sudo make install

cd ~/online_detect_qos
mkdir build
cd build
cmake ..
make
```

- **Attack XDP program:**
```bash 
cd ../src
sudo -E python3 rf2qs.py --model ../classification_model/vpn_<nb_packet>.pkl --iface <your_interface> --nb_packet <nb_packet>
```
- **Note:**
    + In this repository, I use model RF with 300 trees. If you want to attach another parameters of model RF, you might implement tail call in XDP program.
    + We use VPN dataset: [ISCXVPN2016 Dataset](https://www.scitepress.org/Link.aspx?doi=10.5220/0005740704070414)