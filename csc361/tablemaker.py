import socket
import struct
import argparse
import pandas as pd
import matplotlib.pyplot as plt

class ICMP_Packet:
    def __init__(self):
        self.source_address = None
        self.destination_address = None
        self.type = 0
        self.timestamp = None
        self.count = 0

class TracerouteInfo:
    def __init__(self):
        self.source_address = None
        self.destination_address = None
        self.ICMP_packets = []
        self.intermediate_addresses = []
        self.start_time = None
        self.end_time = None
        self.protocol_values = []
        self.fragment_count = 0
        self.last_fragment_offset = 0
        self.rtt_values = {}
        self.sd_values = {}
        self.sent_packets = []
        self.packets = []

def stdev(data):
    n = len(data)
    mean = sum(data) / n
    return (sum((x - mean) ** 2 for x in data) / n) ** 0.5

def parse_tcp_packet(data):
    ethernet_header_size = 14  # Ethernet header is 14 bytes
    ip_header_size = 20  # IP header is typically 20 bytes (without options)
    
    # Unpack Ethernet header
    ethernet_header = struct.unpack('!6s6sH', data[:ethernet_header_size])
    
    # Unpack IP header
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[ethernet_header_size:ethernet_header_size + ip_header_size])
    
    # Extract source and destination addresses
    source_address = socket.inet_ntoa(ip_header[8])
    destination_address = socket.inet_ntoa(ip_header[9])
    
    # Calculate the start of the TCP header
    tcp_header_start = ethernet_header_size + ip_header_size
    
    # Unpack TCP header
    tcp_header = struct.unpack('!HHLLBBHHH', data[tcp_header_start:tcp_header_start + 20])
    
    return source_address, destination_address

def parse_packet_header(data):
    packet_header_format = 'IIII'
    packet_header_size = struct.calcsize(packet_header_format)
    packet_header = struct.unpack(packet_header_format, data[:packet_header_size])
    return packet_header, data[packet_header_size:]

def read_tracefile(filename):
    with open(filename, 'rb') as file:
        data = file.read()
        print(f"Read {len(data)} bytes from {filename}")
        #print("Data:", data)
        return data
    
def extract_timestamp(data, offset):
    # Unpack 8 bytes (seconds and microseconds)
    try:
        packet_header = parse_packet_header(data[offset:offset + 16])[0]
        #print("Packet header:", packet_header)
        seconds, microseconds = packet_header[0], packet_header[1]
        # Convert to milliseconds
        return seconds
    except struct.error:
        print(f"Failed to extract timestamp at offset {offset}.")
        return None

def align_data(data, info):
    accepted_protocols = [1, 6, 17]
    start = 0
    packet_number = 1
    fragments = {}
    print("Data length:", len(data))

    i = 0
    while start < len(data):
        #print("Packet number:", packet_number)
        # Skip packets with protocols not in accepted_protocols
        if start + 20 >= len(data):
            break

        while start < len(data) and data[start + 9] not in accepted_protocols:
            start += 1
            if start + 20 >= len(data):
                break
        
        if start + 20 >= len(data):
            break

        if info.protocol_values.count(data[start + 9]) == 0:
            info.protocol_values.append(data[start + 9])
        
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[start:start + 20])
        timestamp = extract_timestamp(data, start - 16)

        # Check if the first 4 bits indicate IPv4
        version_and_ihl = data[start]
        ip_version = version_and_ihl >> 4
        if ip_version != 4:
            start += 1
            if start + 20 >= len(data):
                break  
            # Not IPv4, skip a byte
            continue
        
        # Check if the packet size is valid
        #or (info.start_time != None and timestamp < info.start_time)
        if 5000 < ip_header[2] or ip_header[2] < 20 or ip_header[6] > 255 or ip_header[6] < 0: 
            start += 1
            if start + 20 >= len(data):
                break
            continue

        if info.source_address is None:
            info.source_address = socket.inet_ntoa(ip_header[8])
            info.start_time = extract_timestamp(data, start - 16)
            info.destination_address = socket.inet_ntoa(ip_header[9])
            print("Start time:", info.start_time)

        flags_fragment_offset = ip_header[4]
        id = ip_header[3]
        ttl = ip_header[5]
        protocol = ip_header[6]
        source_address = socket.inet_ntoa(ip_header[8])
        destination_address = socket.inet_ntoa(ip_header[9])

        i += 1
        #print(data[start:start + 20])
        if protocol == 1:
            print(i, ": Source:", source_address)
            print(i, ": Destination:", destination_address)
            #print(i, ": Protocol:", protocol)
            #print(i, ": TTL:", ttl)
            #print(i, ": ID:", id)
            #print(i, ": Flags:", flags_fragment_offset)
            print(i, ": Timestamp:", timestamp - info.start_time)
        info.packets.append({"packetNum": i, "source": source_address, "dest": destination_address, "protocol": protocol, "ttl": ttl, "id": id, "flags": flags_fragment_offset, "timestamp": timestamp})
        '''
        if (source_address != info.source_address and source_address != info.destination_address) and source_address not in info.intermediate_addresses:
            info.intermediate_addresses.append(source_address)

        if (destination_address != info.source_address and destination_address != info.destination_address) and destination_address not in info.intermediate_addresses:
            info.intermediate_addresses.append(destination_address)
        '''

        if protocol == 17:
            info.sent_packets.append({"ttl": ttl, "timestamp": timestamp, "dest": destination_address})

        mf_flag = (flags_fragment_offset & 0x2000) >> 13
        fragment_offset = flags_fragment_offset & 0x1FFF

        if id not in fragments:
            fragments[id] = {"count": 0, "last_offset": 0}

        fragments[id]["count"] += 1
        fragments[id]["last_offset"] = max(fragments[id]["last_offset"], fragment_offset)
        
        #print("Packet size:", ip_header[2])
        #print("Source:", socket.inet_ntoa(ip_header[8]))
        #print("Destination:", socket.inet_ntoa(ip_header[9]))
        if(ip_header[6] == 1):
            #print("Protocol: ICMP")
            parse_ICMP_packet(data[start - 16:], info)

        
        start += 50  # Move to the next packet based on the IP header's total length
        if start + 20 >= len(data):
            break
        packet_number += 1

    for id, fragment_data in fragments.items():
        info.fragment_count += fragment_data["count"]
        info.last_fragment_offset = max(info.last_fragment_offset, fragment_data["last_offset"] * 8)

    print(f"Final offset: {start}, File length: {len(data)}")

def parse_ICMP_packet(data, info):
    # Unpack IP header
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[16:36])
    # Extract source and destination addresses
    source_address = socket.inet_ntoa(ip_header[8])
    destination_address = socket.inet_ntoa(ip_header[9])
    # Calculate the start of the ICMP header
    icmp_header_start = 20
    # Unpack ICMP header
    icmp_header = struct.unpack('!BBHHH', data[icmp_header_start:icmp_header_start + 8])
    # Extract ICMP type and code
    icmp_type = icmp_header[0]
    icmp_code = icmp_header[1]
    # Extract ICMP timestamp
    timestamp = extract_timestamp(data, 0)
    print("Timestamp:", timestamp)
    # Extract ICMP count
    count = struct.unpack('!H', data[icmp_header_start + 16:icmp_header_start + 18])[0]
    # Create ICMP packet object
    icmp_packet = ICMP_Packet()
    icmp_packet.source_address = source_address
    icmp_packet.destination_address = destination_address
    icmp_packet.timestamp = timestamp
    icmp_packet.count = count
    icmp_packet.type = icmp_type


    info.ICMP_packets.append(icmp_packet)
    if(icmp_packet.source_address not in info.intermediate_addresses and icmp_packet.source_address != info.source_address and icmp_packet.source_address != info.destination_address): 
        info.intermediate_addresses.append(icmp_packet.source_address)
        
    rtt = info.start_time - timestamp
    print(f"RTT = {info.start_time} - {timestamp} = {rtt:.2f}")
    print(f"RTT: {rtt:.2f}")
    #print("ICMP Packet:" + icmp_packet.source_address)
    rtt = timestamp - info.start_time
    print("----------------------", source_address)
    if source_address not in info.rtt_values:
        info.rtt_values[source_address] = []
    info.rtt_values[source_address].append(rtt)

def print_info(info):

    print('The IP address of the source node: {}'.format(info.source_address))
    print('The IP address of ultimate destination node: {}'.format(info.destination_address))
    print('The IP addresses of the intermediate destination nodes:')
    for address in info.intermediate_addresses:
        print("    " + address)
    print('The values in the protocol field of IP headers:')
    for protocol in info.protocol_values:
        print("    " + str(protocol))
    print('The number of fragments created from the original datagram is: {}'.format(info.fragment_count))
    print('The offset of the last fragment: {}'.format(info.last_fragment_offset))
    print('\n')
    avg_rtt = 0
    for address in info.rtt_values:
        rtts = info.rtt_values[address]
        sd_rtt = stdev(rtts)
        avg_rtt = sum(rtts) / len(rtts)
        print(f"    The avg RTT between {info.source_address} and {address} is: {avg_rtt:2f} ms, the s.d. is: {sd_rtt:2f} ms")

def print_info(info):
    for address, rtts in info.rtt_values.items():
        avg_rtt = sum(rtts) / len(rtts)
        std_dev_rtt = stdev(rtts)
        info.sd_values[address] = std_dev_rtt

    probes_per_ttl = {}
    for packet in info.sent_packets:
        if packet["ttl"] not in probes_per_ttl:
            probes_per_ttl[packet["ttl"]] = 0
        probes_per_ttl[packet["ttl"]] += 1
    
    answer_second_question = "Yes"
    answer_third_question = "No"

    # Print the table with horizontal line dividers
    print(f"{'Row':<5} {'Components':<60} {'Details'}")
    print("=" * 90)

    # Display each rubric component with row numbers and horizontal dividers
    print(f"{'1':<5} {'The IP address of the source node (R1)':<60} {info.source_address}")
    print("-" * 90)
    print(f"{'2':<5} {'The IP address of ultimate destination node (R1)':<60} {info.destination_address}")
    print("-" * 90)
    print(f"{'3':<5} {'The IP addresses of the intermediate destination nodes (R1)':<60} {', '.join(info.intermediate_addresses)}")
    print("-" * 90)
    print(f"{'4':<5} {'The correct order of the intermediate destination nodes (R1)':<60} {', '.join(info.intermediate_addresses)}")
    print("-" * 90)

    # Protocol values
    protocol_details = ", ".join(f"{p}: {'ICMP' if p == 1 else 'UDP' if p == 17 else 'Unknown'}" for p in info.protocol_values)
    print(f"{'5':<5} {'The values in the protocol field of IP headers (R1)':<60} {protocol_details}")
    print("-" * 90)

    # Fragmentation details for single datagram
    print(f"{'6':<5} {'The number of fragments created from the original datagram (R1)':<60} {info.fragment_count}")
    print("-" * 90)
    print(f"{'7':<5} {'The offset of the last fragment (R1)':<60} {info.last_fragment_offset}")
    print("-" * 90)

    # RTT details
    if(info.rtt_values.get(info.destination_address) != None):
        print(f"{'8':<5} {'The avg RTT to ultimate destination node (R1)':<60} {sum(info.rtt_values[info.destination_address])/len(info.rtt_values[info.destination_address]):.2f} ms")
    else:
        print(f"{'8':<5} {'The avg RTT to ultimate destination node (R1)':<60} {0:.2f} ms")
    for address, rtts in info.rtt_values.items():
        avg_rtt = sum(rtts) / len(rtts)
        print(f"{'8':<5} {'The avg RTT between ' + info.source_address + ' and ' + address:<60} {avg_rtt:.2f} ms")
    print("-" * 90)
    if(info.sd_values.get(info.destination_address) != None):
        print(f"{'9':<5} {'The std deviation of RTT to ultimate destination node (R1)':<60} {info.sd_values[info.destination_address]:.2f} ms")
    else:
        print(f"{'9':<5} {'The std deviation of RTT to ultimate destination node (R1)':<60} {0:.2f} ms")
    for address, rtts in info.rtt_values.items():
        avg_rtt = sum(rtts) / len(rtts)
        print(f"{'8':<5} {'The avg std between ' + info.source_address + ' and ' + address:<60} {info.sd_values[address]:.2f} ms")
    print("-" * 90)

    # Probes and question answers
    print(f"{'10':<5} {'The number of probes per TTL (R2)':<60} {', '.join(f'TTL {ttl}: {probes}' for ttl, probes in probes_per_ttl.items())}")
    print("-" * 90)
    print(f"{'11':<5} {'Right answer to the second question (R2)':<60} {answer_second_question}")
    print("-" * 90)
    print(f"{'12':<5} {'Right answer to the third/or fourth question (R2)':<60} {answer_third_question}")
    print("=" * 90)

def generate_ttl_rtt_table(filenames):
    ttl_rtt = {}
    for filename in filenames:
        traceroute_data = read_tracefile(filename)
        info = TracerouteInfo()
        align_data(traceroute_data, info)
        
        for packet in info.packets:
            ttl = packet["ttl"]
            rtt = packet["timestamp"]
            if ttl not in ttl_rtt:
                ttl_rtt[ttl] = {}
            if filename not in ttl_rtt[ttl]:
                ttl_rtt[ttl][filename] = []
            ttl_rtt[ttl][filename].append(rtt)
    
    ttl_avg_rtt = {ttl: {filename: sum(rtts) / len(rtts) for filename, rtts in files.items()} for ttl, files in ttl_rtt.items()}
    df = pd.DataFrame(ttl_avg_rtt).T.fillna(0)
    df.columns = [f"Average RTT ({filename})" for filename in filenames]
    df = df.sort_index(ascending=True)
    
    fig, ax = plt.subplots(figsize=(12, 8))
    ax.axis('tight')
    ax.axis('off')
    table = ax.table(cellText=df.values, colLabels=df.columns, rowLabels=df.index, cellLoc='center', loc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 1.2)
    plt.title("Average RTT by TTL and Filename")
    plt.savefig("average_rtt_table.png")
    plt.show()

if __name__ == '__main__':
    filenames = ["group1-trace1.pcap", "group1-trace2.pcap", "group1-trace3.pcap", "group1-trace4.pcap", "group1-trace5.pcap"]
    generate_ttl_rtt_table(filenames)