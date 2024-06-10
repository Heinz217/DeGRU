import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict
import numpy as np
from scapy.utils import rdpcap
from decimal import Decimal
import os
import time

import csv


# 定义数据结构来存储流的数据包
class Flow:
    def __init__(self):
        self.forward_packets = []  # 上行数据包
        self.backward_packets = []  # 下行数据包
        self.packet_count = 0  # 流中的数据包数量
        self.proto = 6  # TCP=6,UDP=17
        self.flow_name = None

    def add_packet(self, packet, is_upstream):
        if is_upstream:
            self.forward_packets.append(packet)
        else:
            self.backward_packets.append(packet)
        self.packet_count += 1

    def add_proto(self,flow_key):
        self.proto = flow_key[4]
        self.flow_key = flow_key

    def calculate_flow(self):


        # 1.inbound
        if len(self.forward_packets) < len(self.backward_packets):
            inbound = 1
        else:
            inbound = 0

        # 2. flow duration
        if self.packet_count > 0:
            start_time = min(pkt.time for pkt in self.forward_packets + self.backward_packets)
            end_time = max(pkt.time for pkt in self.forward_packets + self.backward_packets)
            flow_duration = end_time - start_time
        else:
            flow_duration = 0

        # 3. min packet length
        # 4. packet length std
        # 5. average packet size
        packet_lengths = [len(pkt) for pkt in self.forward_packets + self.backward_packets]
        if packet_lengths:
            min_packet_length = min(packet_lengths)
            packet_length_std = np.std(packet_lengths)
            average_packet_size = np.mean(packet_lengths)
        else:
            min_packet_length = 0
            packet_length_std = 0
            average_packet_size = 0

        # 6. Flow Packets/s
        if flow_duration > 0:
            flow_packets_per_second = self.packet_count / flow_duration
        else:
            flow_packets_per_second = 0

        # 7. active mean
        # 8. active max
        # 9. active min
        def active_times(packets):
            if len(packets) < 2:
                return []
            return [packets[i + 1].time - packets[i].time for i in range(len(packets) - 1)]

        forward_active_times = active_times(self.forward_packets)
        backward_active_times = active_times(self.backward_packets)
        active_times_all = forward_active_times + backward_active_times
        print(forward_active_times)
        print(backward_active_times)
        print(active_times_all)

        if active_times_all:
            active_mean = np.mean(np.float64(active_times_all))
            active_max = np.max(np.float64(active_times_all))
            active_min = np.min(np.float64(active_times_all))
            print(active_mean)
            print(active_max)
            print(active_min)
            # active_mean = np.mean(active_times_all)
            # active_max = np.max(active_times_all)
            # active_min = np.min(active_times_all)
        else:
            active_mean = 0
            active_max = 0
            active_min = 0

        # 10.Flow IAT Max
        if active_times_all:
            flow_iat_max = max(active_times_all)
        else:
            flow_iat_max = 0
        # 11.-14. RST, ACK, URG, CWE flag counts
        rst_flag_count = 0
        ack_flag_count = 0
        urg_flag_count = 0
        cwe_flag_count = 0

        for pkt in self.forward_packets + self.backward_packets:
            if TCP in pkt:
                flags = pkt[TCP].flags
                if flags & 0x04:  # RST flag
                    rst_flag_count += 1
                if flags & 0x10:  # ACK flag
                    ack_flag_count += 1
                if flags & 0x20:  # URG flag
                    urg_flag_count += 1
                if flags & 0x80:  # CWE flag (not standard, typically reserved)
                    cwe_flag_count += 1

        # 15.-29. Calculate features for forward packets
        total_fwd_packets = len(self.forward_packets)
        fwd_packet_lengths = [len(pkt) for pkt in self.forward_packets]

        if fwd_packet_lengths:
            fwd_packet_length_max = max(fwd_packet_lengths)
            fwd_packet_length_min = min(fwd_packet_lengths)
            fwd_packet_length_mean = np.mean(fwd_packet_lengths)
            fwd_packet_length_std = np.std(fwd_packet_lengths)
        else:
            fwd_packet_length_max = 0
            fwd_packet_length_min = 0
            fwd_packet_length_mean = 0
            fwd_packet_length_std = 0

        avg_fwd_segment_size = fwd_packet_length_mean

        fwd_header_lengths = [pkt[IP].ihl * 4 for pkt in self.forward_packets if IP in pkt]

        if fwd_header_lengths:
            fwd_header_length = sum(fwd_header_lengths)
        else:
            fwd_header_length = 0

        fwd_psh_flags = sum(1 for pkt in self.forward_packets if TCP in pkt and pkt[TCP].flags & 0x08)  # PSH flag
        init_win_bytes_forward = self.forward_packets[0][TCP].window if self.forward_packets and TCP in \
                                                                        self.forward_packets[0] else 0
        act_data_pkt_fwd = sum(1 for pkt in self.forward_packets if TCP in pkt and pkt[TCP].payload)

        fwd_iat_total = sum(np.float64(forward_active_times))
        fwd_iat_max = max(np.float64(forward_active_times)) if forward_active_times else 0
        fwd_iat_min = min(np.float64(forward_active_times)) if forward_active_times else 0
        fwd_iat_mean = np.mean(np.float64(forward_active_times)) if forward_active_times else 0
        fwd_iat_std = np.std(np.float64(forward_active_times)) if forward_active_times else 0

        # 30.-44.Calculate features for backward packets

        total_bwd_packets = len(self.backward_packets)
        bwd_packet_lengths = [len(pkt) for pkt in self.backward_packets]

        if bwd_packet_lengths:
            bwd_packet_length_max = max(bwd_packet_lengths)
            bwd_packet_length_min = min(bwd_packet_lengths)
            bwd_packet_length_mean = np.mean(bwd_packet_lengths)
            bwd_packet_length_std = np.std(bwd_packet_lengths)
        else:
            bwd_packet_length_max = 0
            bwd_packet_length_min = 0
            bwd_packet_length_mean = 0
            bwd_packet_length_std = 0

        avg_bwd_segment_size = bwd_packet_length_mean

        bwd_header_lengths = [pkt[IP].ihl * 4 for pkt in self.backward_packets if IP in pkt]

        if bwd_header_lengths:
            bwd_header_length = sum(bwd_header_lengths)
        else:
            bwd_header_length = 0

        bwd_psh_flags = sum(1 for pkt in self.backward_packets if TCP in pkt and pkt[TCP].flags & 0x08)  # PSH flag
        init_win_bytes_backward = self.backward_packets[0][TCP].window if self.backward_packets and TCP in \
                                                                        self.backward_packets[0] else 0
        act_data_pkt_bwd = sum(1 for pkt in self.backward_packets if TCP in pkt and pkt[TCP].payload)

        bwd_iat_total = sum(backward_active_times)
        bwd_iat_max = max(np.float64(backward_active_times)) if backward_active_times else 0
        bwd_iat_min = min(np.float64(backward_active_times)) if backward_active_times else 0
        print('backward',backward_active_times)
        bwd_iat_mean = np.mean(np.float64(backward_active_times)) if backward_active_times else 0
        bwd_iat_std = np.std(np.float64(backward_active_times)) if backward_active_times else 0
        print(bwd_iat_std)
        flow_key = None
        proto = 0
        for packet in self.forward_packets:
            if IP in packet:
                if TCP in packet:
                    proto = 6
                    flow_key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport, proto)
                    break
                elif UDP in packet:
                    proto = 17
                    flow_key = (packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, proto)
                    break
                else:
                    flow_key = None
                    break

        b= {
            'flow_key': flow_key,
            'proto': proto,
            'inbound': inbound,
            'flow_duration': flow_duration,
            'min_packet_length': min_packet_length,
            'packet_length_std': packet_length_std,
            'average_packet_size': average_packet_size,
            'flow_packets_per_second': flow_packets_per_second,
            'active_mean': active_mean,
            'active_max': active_max,
            'active_min': active_min,
            'flow_iat_max': flow_iat_max,
            'rst_flag_count': rst_flag_count,
            'ack_flag_count': ack_flag_count,
            'urg_flag_count': urg_flag_count,
            'cwe_flag_count': cwe_flag_count,
            'total_fwd_packets': total_fwd_packets,
            'fwd_packet_length_max': fwd_packet_length_max,
            'fwd_packet_length_min': fwd_packet_length_min,
            'fwd_packet_length_mean': fwd_packet_length_mean,
            'fwd_packet_length_std': fwd_packet_length_std,
            'avg_fwd_segment_size': avg_fwd_segment_size,
            'fwd_header_length': fwd_header_length,
            'fwd_psh_flags': fwd_psh_flags,
            'init_win_bytes_forward': init_win_bytes_forward,
            'act_data_pkt_fwd': act_data_pkt_fwd,
            'fwd_iat_total': fwd_iat_total,
            'fwd_iat_max': fwd_iat_max,
            'fwd_iat_min': fwd_iat_min,
            'fwd_iat_mean': fwd_iat_mean,
            'fwd_iat_std': fwd_iat_std,
            'total_bwd_packets': total_bwd_packets,
            'bwd_packet_length_max': bwd_packet_length_max,
            'bwd_packet_length_min': bwd_packet_length_min,
            'bwd_packet_length_mean': bwd_packet_length_mean,
            'bwd_packet_length_std': bwd_packet_length_std,
            'avg_bwd_segment_size': avg_bwd_segment_size,
            'bwd_header_length': bwd_header_length,
            'bwd_psh_flags': bwd_psh_flags,
            'init_win_bytes_backward': init_win_bytes_backward,
            'act_data_pkt_bwd': act_data_pkt_bwd,
            'bwd_iat_total': bwd_iat_total,
            'bwd_iat_max': bwd_iat_max,
            'bwd_iat_min': bwd_iat_min,
            'bwd_iat_mean': bwd_iat_mean,
            'bwd_iat_std': bwd_iat_std,
        }
        print(flow_key, flow_duration)
        return {
            'Flow ID': flow_key,
            ' Protocol': proto,
            ' Flow Duration': flow_duration,
            ' Total Fwd Packets': total_fwd_packets,
            ' Total Backward Packets': total_bwd_packets,
            ' Fwd Packet Length Max': fwd_packet_length_max,
            ' Fwd Packet Length Min': fwd_packet_length_min,
            ' Fwd Packet Length Mean': fwd_packet_length_mean,
            ' Fwd Packet Length Std': fwd_packet_length_std,
            'Bwd Packet Length Max': bwd_packet_length_max,
            ' Bwd Packet Length Min': bwd_packet_length_min,
            ' Bwd Packet Length Mean': bwd_packet_length_mean,
            ' Bwd Packet Length Std': bwd_packet_length_std,
            ' Flow Packets/s': flow_packets_per_second,
            ' Flow IAT Max': flow_iat_max,
            'Fwd IAT Total': fwd_iat_total,
            ' Fwd IAT Mean': fwd_iat_mean,
            ' Fwd IAT Std': fwd_iat_std,
            ' Fwd IAT Max': fwd_iat_max,
            ' Fwd IAT Min': fwd_iat_min,
            'Bwd IAT Total': bwd_iat_total,
            ' Bwd IAT Mean': bwd_iat_mean,
            ' Bwd IAT Std': bwd_iat_std,
            ' Bwd IAT Max': bwd_iat_max,
            ' Bwd IAT Min': bwd_iat_min,
            'Fwd PSH Flags': fwd_psh_flags,
            ' Bwd PSH Flags': bwd_psh_flags,
            ' Fwd Header Length': fwd_header_length,
            ' Bwd Header Length': bwd_header_length,
            ' Min Packet Length': min_packet_length,
            ' Packet Length Std': packet_length_std,
            ' RST Flag Count': rst_flag_count,
            ' ACK Flag Count': ack_flag_count,
            ' URG Flag Count': urg_flag_count,
            ' CWE Flag Count': cwe_flag_count,
            ' Average Packet Size': average_packet_size,
            ' Avg Fwd Segment Size': avg_fwd_segment_size,
            ' Avg Bwd Segment Size': avg_bwd_segment_size,
            'Init_Win_bytes_forward': init_win_bytes_forward,
            ' Init_Win_bytes_backward': init_win_bytes_backward,
            ' act_data_pkt_fwd': act_data_pkt_fwd,
            'Active Mean': active_mean,
            ' Active Max': active_max,
            ' Active Min': active_min,
            ' Inbound': inbound,
            # 'act_data_pkt_bwd': act_data_pkt_bwd,
        }


# 将数据包按流分类
def classify_packets(packet, flows, server_ip):
    if IP in packet:
        # 对于TCP还是UDP，进行属性赋值，防止之后处理流程不同
        if TCP in packet:
            proto = 6
            flow_key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport, proto)
        elif UDP in packet:
            proto = 17
            flow_key = (packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, proto)
        else:
            return

        # 判断数据包方向,上行还是下行
        if packet[IP].src == server_ip:
            is_upstream = False
        elif packet[IP].dst == server_ip:
            is_upstream = True
        else:
            is_upstream = True

        # 查找流是否已存在
        if flow_key in flows:
            flows[flow_key].add_packet(packet, is_upstream)
            flows[flow_key].add_proto(flow_key)
        else:
            new_flow = Flow()
            new_flow.add_packet(packet, is_upstream)
            new_flow.add_proto(flow_key)
            flows[flow_key] = new_flow

# 示例用法
def analyze_pcap(pcap_file, server_ip):
    flows = defaultdict(Flow)

    # 只捕获ip数据包，其余的都忽略
    packets = rdpcap(pcap_file)
    # packets = sniff(offline=pcap_file, filter="ip")
    for packet in packets:
        classify_packets(packet, flows, server_ip)

    flow_features = []
    # 对每个流进行特征计算
    for flow_key, flow in flows.items():
        a=flow.calculate_flow()
        flow_features.append(a)

        # 在这里可以打印或处理每个流的特征
    return flow_features

