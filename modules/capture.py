import scapy.all as sa
from datetime import datetime 

def _getFilename():
    """
    Generate a filename for the PCAP file based on the current timestamp.

    Returns:
        str: A string representing the filename in the format 'sniff_YYYY-MM-DD_HH-MM-SS.pcap'.
    """
    currTime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"sniff_{currTime}.pcap"

outFile = _getFilename()

def _processPackets(packet):
    """
    Process a single captured packet: print its summary and save it to the PCAP file.

    Args:
        packet (scapy.packet.Packet): The packet captured by Scapy.
    """
    print(packet.summary())
    sa.wrpcap(outFile, packet, append=True)

def sniffAllPackets(interface):
    """
    Capture all packets on a given network interface.

    Args:
        interface (str): The name of the network interface to sniff packets from.

    Note:
        Runs in promiscuous mode, capturing all packets visible to the interface.
        Press Ctrl+C to stop sniffing.
    """
    try:
        sa.sniff(iface=interface, prn=lambda packet: _processPackets(packet), promisc=True)
        print(f"packets saved in {outFile}")
    except KeyboardInterrupt:
        print("\nStopping sniffing...")

def sniffProtocol(interface, userFilter):
    """
    Capture packets on a given network interface that match a specified protocol filter.

    Args:
        interface (str): The name of the network interface to sniff packets from.
        userFilter (str): A filter string ("tcp", "udp") to capture specific protocols.

    Note:
        Runs in promiscuous mode and uses the specified filter to limit captured packets.
        Press Ctrl+C to stop sniffing.
    """
    try:
        sa.sniff(iface=interface, prn=lambda packet: _processPackets(packet), promisc=True, filter=userFilter)
        print(f"packets saved in {outFile}")
    except KeyboardInterrupt:
        print("\nStopping sniffing...")