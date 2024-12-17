"""
The goal of this assignment it to simply parse a trace file and print out:
1. The number of unique TCP connections
2. Most importantly, for each TCP connection we need:
    a. The state of the connection (e.g., S0F0, S1F0, etc. indicating the
    number of SYN and FIN packets seen so far)
    b. The starting time, ending time, and duration of each connection
    c. The number of packets sent in each direction on each complete
    connection as well as the total number of packets sent in both directions
    d. The number of bytes sent in each direction on each complete connection
    as well as the total number of bytes sent in both directions.
3. The number of reset TCP connections observed in the trace
4. The number of TCP connections that were still open when the trace ended
5. The number of TCP connections that were established before the trace started
6. The number of TCP connections that were observed during the trace
7. For each TCP connection observed during the trace:
    a. The minumum, mean, and maximum time durations of the complete TCP connections
    b. The minimum, mean, and maximum RTT values of the complete TCP connections
    c. The minimum, mean, and maximum number of packets sent in each direction
    d. The minimum, mean, and maximum recieve window sizes (both sides) of the complete TCP connections

Output Format: 

    TOTAL CONNECTIONS

    Total number of connections: N

    CONNECTION INFORMATION

    Connection 1:
    Source Address:
    Destination address:
    Source Port:
    Destination Port:
    Status:
    (Only if the connection is complete provide the following information)
    Start time:
    End Time:
    Duration:
    Number of packets sent from Source to Destination:
    Number of packets sent from Destination to Source:
    Total number of packets:
    Number of data bytes sent from Source to Destination:
    Number of data bytes sent from Destination to Source:
    Total number of data bytes:
    END
    +++++++++++++++++++++++++++++++++
    .
    .
    .
    +++++++++++++++++++++++++++++++++
    Connection N:
    Source Address:
    Destination address:
    Source Port:
    Destination Port:
    Status:
    Duration:
    (Only if the connection is complete provide the following information)
    Start time:
    End Time:
    Number of packets sent from Source to Destination:
    Number of packets sent from Destination to Source:
    Total number of packets:
    Number of data bytes sent from Source to Destination:
    Number of data bytes sent from Destination to Source:
    Total number of data bytes:
    END

    GENERAL INFORMATION

    The total number of complete TCP connections:
    The number of reset TCP connections:
    The number of TCP connections that were still open when the trace capture ended:
    The number of TCP connections established before the capture started:

    COMPLETE TCP CONNECTIONS

    Minimum time duration:
    Mean time duration:
    Maximum time duration:
    Minimum RTT value:
    Mean RTT value:
    Maximum RTT value:
    Minimum number of packets including both send/received:
    Mean number of packets including both send/received:
    Maximum number of packets including both send/received:
    Minimum receive window size including both send/received:
    Mean receive window size including both send/received:
    Maximum receive window size including both send/received:
    END
"""

import struct
import socket

class Connection:
    def __init__(self, source_address, destination_address, source_port, destination_port):
        self.source_address = source_address
        self.destination_address = destination_address
        self.source_port = source_port
        self.destination_port = destination_port
        self.status = None
        self.start_time = None
        self.end_time = None
        self.duration = None
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.first_seg_syn = False

    def calculate_duration(self):
        if self.start_time and self.end_time:
            self.duration = self.end_time - self.start_time

    def determine_status(self):
        self.status = f"S{self.syn_count}F{self.fin_count}"

    def change_times(self, dif):
        self.start_time -= dif
        self.end_time -= dif

def read_capture_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def parse_global_header(data):
    global_header_format = 'IHHIIII'
    global_header_size = struct.calcsize(global_header_format)
    global_header = struct.unpack(global_header_format, data[:global_header_size])
    return global_header, data[global_header_size:]

def parse_packet_header(data):
    packet_header_format = 'IIII'
    packet_header_size = struct.calcsize(packet_header_format)
    packet_header = struct.unpack(packet_header_format, data[:packet_header_size])
    return packet_header, data[packet_header_size:]

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
    
    # Extract source and destination ports using bitwise operations
    source_port = (data[tcp_header_start] << 8) | data[tcp_header_start + 1]
    destination_port = (data[tcp_header_start + 2] << 8) | data[tcp_header_start + 3]
    
    # Extract TCP flags
    flags = tcp_header[5]
    
    return source_address, destination_address, source_port, destination_port, flags

def normalize_connection_key(source_address, destination_address, source_port, destination_port):
    if (source_address, source_port) < (destination_address, destination_port):
        return (source_address, destination_address, source_port, destination_port)
    else:
        return (destination_address, source_address, destination_port, source_port)

def parse_capture_data(data):
    connections = {}
    global_header, data = parse_global_header(data)
    
    while data:
        packet_header, data = parse_packet_header(data)
        packet_data = data[:packet_header[2]]
        data = data[packet_header[2]:]
        
        source_address, destination_address, source_port, destination_port, flags = parse_tcp_packet(packet_data)
        timestamp = packet_header[0]
        timestampus = packet_header[1]
        
        connection_key = normalize_connection_key(source_address, destination_address, source_port, destination_port)
        
        if connection_key not in connections:
            connections[connection_key] = Connection(source_address, destination_address, source_port, destination_port)
            connections[connection_key].start_time = timestamp + timestampus / 1000000
            # Check if the first segment is a SYN
            if flags & 0x02:
                connections[connection_key].first_segment_syn = True
        
        connection = connections[connection_key]
        connection.end_time = timestamp + timestampus / 1000000

        
        # Check for SYN flag (0x02)
        if flags & 0x02:
            connection.syn_count += 1
        """# Check for ACK flag (0x10)
        elif flags & 0x10:
            connection.packets_received += 1"""
        # Check for FIN flag (0x01)
        if flags & 0x01:
            connection.fin_count += 1
        # Check for RST flag (0x04)
        if flags & 0x04:
            connection.rst_count += 1

        if source_address == connection.source_address and source_port == connection.source_port:
            connection.packets_sent += 1
            # Update byte counts (assuming the entire packet is data for simplicity)
            connection.bytes_sent += len(packet_data)
        else:
            connection.packets_received += 1
            # Update byte counts (assuming the entire packet is data for simplicity)
            connection.bytes_received += len(packet_data)
    
    ## Find start time of first connection
    first_start_time = min([conn.start_time for conn in connections.values()])

    for conn in connections.values():
        conn.calculate_duration()
        conn.determine_status()
        conn.change_times(first_start_time)
    
    return list(connections.values())

def print_results(connections):
    print(f"A) Total number of connections: {len(connections)}")
    print("_________________________________________________________")
    print("B) Connection Details")
    for i, conn in enumerate(connections, 1):
        print(f"Connection {i}:")
        print(f"Source Address: {conn.source_address}")
        print(f"Destination address: {conn.destination_address}")
        print(f"Source Port: {conn.source_port}")
        print(f"Destination Port: {conn.destination_port}")
        print(f"Status: {conn.status}")
        if conn.duration:
            print(f"Start time: {conn.start_time:.4f}s")
            print(f"End Time: {conn.end_time:.4f}s")
            print(f"Duration: {conn.duration:.4f}s")
            print(f"Number of packets sent from Source to Destination: {conn.packets_sent}")
            print(f"Number of packets sent from Destination to Source: {conn.packets_received}")
            print(f"Total number of packets: {conn.packets_sent + conn.packets_received}")
            print(f"Number of data bytes sent from Source to Destination: {conn.bytes_sent}")
            print(f"Number of data bytes sent from Destination to Source: {conn.bytes_received}")
            print(f"Total number of data bytes: {conn.bytes_sent + conn.bytes_received}")
        print("END")
        print("+++++++++++++++++++++++++++++++++")

    print("_________________________________________________________")
    print("C) General Information")
    print(f"Total number of complete TCP connections: {len([conn for conn in connections if conn.fin_count >= 1])}")
    print(f"Number of reset TCP connections: {len([conn for conn in connections if conn.rst_count >= 1])}")
    print(f"Number of TCP connections that were still open when the trace capture ended: {len([conn for conn in connections if conn.fin_count == 0])}")
    print(f"Number of TCP connections established before the capture started: {len([conn for conn in connections if not conn.first_segment_syn])}")
    print("_________________________________________________________")
    print("D) Complete TCP Connections")
    durations = [conn.duration for conn in connections if conn.fin_count >= 1]
    rtts = [conn.duration for conn in connections if conn.fin_count >= 1]
    packets = [conn.packets_sent + conn.packets_received for conn in connections if conn.fin_count >= 1]
    receive_window_sizes = [0 for conn in connections if conn.fin_count >= 1]
    print(f"Minimum time duration: {min(durations):.4f}")
    print(f"Mean time duration: {sum(durations) / len(durations):.4f}")
    print(f"Maximum time duration: {max(durations):.4f}")
    print(f"Minimum RTT value: {min(rtts):.4f}")
    print(f"Mean RTT value: {sum(rtts) / len(rtts):.4f}")
    print(f"Maximum RTT value: {max(rtts):.4f}")
    print(f"Minimum number of packets including both send/received: {min(packets)}")
    print(f"Mean number of packets including both send/received: {sum(packets) / len(packets):.0f}")
    print(f"Maximum number of packets including both send/received: {max(packets)}")

if __name__ == "__main__":
    capture_data = read_capture_file('sample-capture-file.cap')
    connections = parse_capture_data(capture_data)
    print_results(connections)
