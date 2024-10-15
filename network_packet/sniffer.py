import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.utils import PcapWriter


# Define a function to capture packets
def capture_packets(iface, count):
    """
    Capture packets on the specified interface.

    Parameters:
    iface (str): The network interface to capture packets on.
    count (int): The number of packets to capture.

    Returns:
    list: A list of captured packets.
    """
    print(f"Capturing {count} packets on interface {iface}...")
    packets = scapy.sniff(iface=iface, count=count)
    print(f"Captured {len(packets)} packets.")
    return packets


# Define a function to analyze packets
def analyze_packets(packets):
    """
    Analyze captured packets and print relevant information.

    Parameters:
    packets (list): A list of captured packets.
    """
    for packet in packets:
        # Check if the packet is an IP packet
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print(f"IP Packet: {src_ip} -> {dst_ip}")

            # Check if the packet is a TCP packet
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

                # Check if the packet is an HTTP request
                if packet.haslayer(HTTPRequest):
                    method = packet[HTTPRequest].Method.decode()
                    path = packet[HTTPRequest].Path.decode()
                    print(f"HTTP Request: {method} {path}")

                # Check if the packet is an HTTP response
                if packet.haslayer(HTTPResponse):
                    status_code = packet[HTTPResponse].Status_Code
                    reason = packet[HTTPResponse].Reason.decode()
                    print(f"HTTP Response: {status_code} {reason}")

            # Check if the packet is a UDP packet
            if packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

            # Check if the packet is an ICMP packet
            if packet.haslayer(ICMP):
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                print(f"ICMP Packet: Type {icmp_type}, Code {icmp_code}")


# Define a function to save packets to a PCAP file
def save_packets(packets, filename):
    """
    Save captured packets to a PCAP file.

    Parameters:
    packets (list): A list of captured packets.
    filename (str): The name of the file to save packets to.
    """
    print(f"Saving packets to {filename}...")
    writer = PcapWriter(filename, append=True)
    writer.write(packets)
    writer.close()
    print("Packets saved successfully.")


# Define a function to filter packets based on protocol
def filter_packets(packets, protocol):
    """
    Filter packets based on protocol.

    Parameters:
    packets (list): A list of captured packets.
    protocol (str): The protocol to filter by (e.g., TCP, UDP, ICMP).

    """
    filtered_packets = []
    for packet in packets:
        if packet.haslayer(protocol):
            filtered_packets.append(packet)
    return filtered_packets

# Define a function to filter packets based on source IP
def filter_packets_by_src_ip(packets, src_ip):
    
    filtered_packets = []
    for packet in packets:
        if packet.haslayer(IP) and packet[IP]. src == src_ip:
            filtered_packets.append(packet)
    return filtered_packets


# Main function
def main():
    """
    Main function to run the network sniffer.
    """
    iface = "eth0"  # Change this to your network interface
    count = 100     # Number of packets to capture

    # Capture packets
    packets = capture_packets(iface, count)

    # Analyze captured packets
    analyze_packets(packets)

    # Save captured packets to a PCAP file
    save_packets(packets, "packets.pcap")

    # Filter packets by protocol (e.g., TCP)
    tcp_packets = filter_packets(packets, TCP)
    print("TCP Packets:")
    analyze_packets(tcp_packets)

    # Filter packets by source IP
    src_ip_packets = filter_packets_by_src_ip(packets, "192.168.1.100")
    print("Packets from 192.168.1.100:")
    analyze_packets(src_ip_packets)



if __name__ == "__main__":
    main()