import scapy.all as sa
from prettytable import PrettyTable

def analyzeProtocol(capturefile, protocol):
    """
    Extract and summarize traffic for a specific protocol from a PCAP file.

    Args:
        capturefile (str): The path to the PCAP file to analyze.
        protocol (str): The protocol to filter and analyze (e.g., "TCP", "UDP", "DNS").

    Returns:
        None: Displays a summary of the filtered traffic and details in a tabular format.
    """
    packets = sa.rdpcap(capturefile)
    filteredPackets = [pkt for pkt in packets if pkt.haslayer(protocol)]

    # dictionary to store overall and detailed information
    summary = {
        "protocol": protocol,
        "packet count": len(filteredPackets),
        "total size": sum(len(pkt) for pkt in filteredPackets),
        "details": []
    }

    for pkt in filteredPackets:
        detail = {
            "src_ip": pkt["IP"].src if pkt.haslayer("IP") else "N/A",
            "dst_ip": pkt["IP"].dst if pkt.haslayer("IP") else "N/A",
            "src_port": pkt[protocol].sport if pkt.haslayer(protocol) and hasattr(pkt[protocol], "sport") else "N/A",
            "dst_port": pkt[protocol].dport if pkt.haslayer(protocol) and hasattr(pkt[protocol], "dport") else "N/A",
            "length": len(pkt),
            "timestamp": pkt.time
        }
        summary["details"].append(detail)
    
    print(f"\n{'='*40}")
    print(f"Protocol Analysis: {summary['protocol']}")
    print(f"Total Packets: {summary['packet count']}")
    print(f"Total Size: {summary['total size']} bytes")
    print(f"{'='*40}")

    table = PrettyTable()
    table.field_names = ["Source IP", "Destination IP", "Source Port", "Destination Port", "Length", "Timestamp"]
    for detail in summary["details"]:
        table.add_row([detail["src_ip"], detail["dst_ip"], detail["src_port"], detail["dst_port"], detail["length"], detail["timestamp"]])

    print(table)


def synDetect(capturefile):
    """
    Detect potential SYN flood attacks by analyzing a PCAP file.

    Args:
        capturefile (str): The path to the PCAP file to analyze.

    Returns:
        None: Displays the detection results, including the total SYN packets, 
              the detection threshold, and any IPs suspected of being targets of a SYN flood attack.
    """
    packets = sa.rdpcap(capturefile)
    threshold = 100
    synPackets = []

    for pkt in packets:
        if pkt.haslayer("TCP") and pkt["TCP"].flags == "S":
            synPackets.append(pkt)
    
    synCount = {}
    for pkt in synPackets:
        if pkt.haslayer("IP"):
            dstIp = pkt["IP"].dst
            synCount[dstIp] = synCount.get(dstIp, 0) + 1
    
    potentialAttacks = {ip: count for ip,count in synCount.items() if count>threshold}

    print(f"\n{'='*40}")
    print("SYN Flood Detection")
    print(f"{'='*40}")
    print(f"Total SYN Packets: {len(synPackets)}")
    print(f"Threshold: {threshold} SYN packets per IP\n")

    if potentialAttacks:
        print("Potential SYN flood attacks:")
        for ip,count in potentialAttacks.items():
            print(f"Target IP: {ip}, SYN Packet Count: {count}")
    else:
        print("No SYN flood attack detected.")


def payloadExtract(capturefile):
    """
    Extract HTTP payloads and display their details.

    Args:
        capturefile (str): The path to the PCAP file to analyze.

    Returns:
        None: Displays the extracted HTTP payloads along with their source/destination 
              IPs, MAC addresses, and the payload content.
    """
    packets = sa.rdpcap(capturefile)
    httpDetails = []

    for pkt in packets:
        if pkt.haslayer("Ether") and pkt.haslayer("IP") and pkt.haslayer("TCP") and pkt.haslayer("Raw"):
            payload = pkt["Raw"].load.decode("utf-8", errors="ignore")
            if "HTTP" in payload or payload.startswith(("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD")):
                detail = {
                    "src_ip": pkt["IP"].src,
                    "dst_ip": pkt["IP"].dst,
                    "src_mac": pkt["Ether"].src,
                    "dst_mac": pkt["Ether"].dst,
                    "payload": payload
                }

                httpDetails.append(detail)
    
    print(f"\nExtracted {len(httpDetails)} HTTP packet(s)\n")
    
    for detail in httpDetails:
        print(f"\n{'-'*40}")
        print(f"Source IP: {detail['src_ip']}")
        print(f"Destination IP: {detail['dst_ip']}")
        print(f"Source MAC: {detail['src_mac']}")
        print(f"Destination MAC: {detail['dst_mac']}")
        print("Payload:")
        print(detail["payload"])
        print("-"*40)

def convSum(capturefile):
    """
    Provide a summary of conversations from a PCAP file.

    Args:
        capturefile (str): The path to the PCAP file to analyze.

    Returns:
        None: Displays a summary of conversations including source/destination IPs, 
              ports, protocol, packet count, and total bytes transferred.
    """
    packets = sa.rdpcap(capturefile)
    conversations = {}

    for pkt in packets:
        if pkt.haslayer("IP") and (pkt.haslayer("TCP") or pkt.haslayer("UDP")):
            src_ip = pkt["IP"].src
            dst_ip = pkt["IP"].dst
            src_port = pkt["TCP"].sport if pkt.haslayer("TCP") else pkt["UDP"].sport
            dst_port = pkt["TCP"].dport if pkt.haslayer("TCP") else pkt["UDP"].dport
            protocol = "TCP" if pkt.haslayer("TCP") else "UDP"

            convKey = (src_ip, src_port, dst_ip, dst_port, protocol)

            if convKey not in conversations:
                conversations[convKey] = {
                    "packet_count": 0,
                    "total_bytes": 0
                }

            conversations[convKey]["packet_count"] += 1
            conversations[convKey]["total_bytes"] += len(pkt)
    
    print(f"\n{'='*40}")
    print("Conversation Summary")
    print(f"{'='*40}\n")
    for key, details in conversations.items():
        src_ip, src_port, dst_ip, dst_port, protocol = key
        print(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})")
        print(f"  Packets: {details['packet_count']}")
        print(f"  Total Bytes: {details['total_bytes']} bytes")
        print(f"{'-'*40}")
