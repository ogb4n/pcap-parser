import threading
from scapy.all import sniff, wrpcap, rdpcap, IP

def capture_traffic(interface, pcap_file, duration):
    packets = sniff(iface=interface, timeout=duration)
    wrpcap(pcap_file, packets)

def start_parallel_capture(interfaces, duration):
    threads = []
    pcap_files = []
    for interface in interfaces:
        pcap_file = f'{interface}_capture.pcap'
        pcap_files.append(pcap_file)
        thread = threading.Thread(target=capture_traffic, args=(interface, pcap_file, duration))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return pcap_files

def merge_pcaps(pcap1_file, pcap2_file, output_file):
    pcap1 = rdpcap(pcap1_file)
    pcap2 = rdpcap(pcap2_file)

    max_len = min(len(pcap1), len(pcap2))

    merged_packets = []

    for i in range(max_len):
        pkt1 = pcap1[i]
        pkt2 = pcap2[i]

        if IP in pkt1 and IP in pkt2:
            merged_pkt = pkt1.copy()
            merged_pkt[IP].src = pkt1[IP].src
            merged_pkt[IP].dst = pkt2[IP].dst
            merged_packets.append(merged_pkt)
        else:
            continue  

    wrpcap(output_file, merged_packets)

interfaces = ['Ethernet', 'Mullvad']  # INTERFACE NAMES 
capture_duration = 20  # SCAN TIME
output_merged_file = 'output.pcap'

pcap_files = start_parallel_capture(interfaces, capture_duration)

if len(pcap_files) != 2:
    raise ValueError("Le nombre de fichiers pcap capturés est incorrect. Assurez-vous de capturer sur exactement deux interfaces.")

merge_pcaps(pcap_files[0], pcap_files[1], output_merged_file)