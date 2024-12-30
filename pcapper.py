import sys
from modules import capture, analyze

def showBanner():
    '''
    displays a banner
    '''
    banner = '''

        ██████╗  ██████╗ █████╗ ██████╗ ██████╗ ███████╗██████╗ 
        ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
        ██████╔╝██║     ███████║██████╔╝██████╔╝█████╗  ██████╔╝
        ██╔═══╝ ██║     ██╔══██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
        ██║     ╚██████╗██║  ██║██║     ██║     ███████╗██║  ██║
        ╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
        
                        By:- https://github.com/RIZZZIOM
    '''
    return banner

def packetCapture():
    """
    Capture and filter packets from the network and save them in a PCAP file.

    Args:
        None: User input is required during execution to select options.

    Returns:
        None: Captures and saves packets based on user choices, either all packets or specific protocol traffic.
    """
    capOptions = {
        1 : "Capture all packets",
        2 : "Capture specific protocol"
    }

    protocols = {
        1 : "tcp",
        2 : "udp"
    }

    interface = input("interface [Wi-Fi]: ")
    print()
    if not interface:
        interface = "Wi-Fi"
    print("\n--- SNIFF TYPE ---\n")
    for num, val in capOptions.items():
        print(f"[{num}] - {val}")
    capChoice = int(input("\nChoose an option: "))
    if capChoice == 1:
        print("\nSniffing started...")
        capture.sniffAllPackets(interface=interface)
        print("Sniffing stopped...\n")
    elif capChoice == 2:
        print("\n--- PROTOCOLS ---\n")
        for num,val in protocols.items():
            print(f"[{num}] - {val}")
        capProtocol = int(input("\nChoose protocol: "))
        capPort = input("Enter service port (optional): ")
        if capPort:
            try:
                capPort = int(capPort)
                filter = f"{protocols[capProtocol]} port {capPort}"
            except:
                print("Invalid port number. Skipping service filter...")
                filter = protocols[capProtocol]
        else:
            filter = protocols[capProtocol]
        print("\nSniffing started...")
        capture.sniffProtocol(interface=interface, userFilter=filter)
        print("Sniffing stopped...\n")

def analyzeCapture():
    """
    Analyze the captured Wireshark packets from a PCAP or PCAPNG file.

    Args:
        None: User input is required during execution to provide the file name and select analysis options.

    Returns:
        None: Performs the selected analysis action on the provided capture file.
    """
    fileTypes = {
        1 : "pcap",
        2 : "pcapng"
    }
    actions = {
        1 : "Extract and summarize traffic for specific protocol",
        2 : "Detect SYN flood",
        3 : "Extract http payload",
        4 : "TCP/UDP conversation summary"
    }
    capFile = input("Enter pcap/pcapng file: ")
    print()
    
    if not capFile.endswith(".pcap") and not capFile.endswith(".pcapng"):
        print("\n--- FILE TYPES ---\n")
        for key,val in fileTypes.items():
            print(f"[{key}] - {val}")    
        userType = int(input("\nSelect file type: "))
        if userType == 1:
            capFile = capFile.strip() + ".pcap"
        elif userType == 2:
            capFile = capFile.strip() + ".pcapng"
        else:
            print("Invalid file type.")
    print("\n--- ANALYSIS OPERATIONS ---\n")
    for num,act in actions.items():
        print(f"[{num}] - {act}")
    userAct = int(input("\nChoose an action: "))
    if userAct == 1:
        prot = input("Enter protocol / service: ").upper()
        analyze.analyzeProtocol(capFile, prot)
    elif userAct == 2:
        analyze.synDetect(capFile)
    elif userAct == 3:
        analyze.payloadExtract(capFile)
    elif userAct == 4:
        analyze.convSum(capFile)
    else:
        print("Invalid option")

def main():
    """
    Display the main menu and handle user actions for the network tool.

    Args:
        None: User input is required during execution to select menu options.

    Returns:
        None: Executes the selected action (packet capture, analysis, or program exit).
    """
    netOptions = {
        1 : "Capture and filter network packets",
        2 : "Analyze PCAP/PCAPNG file",
        0 : "Exit the program"
    }

    myBanner = showBanner()
    print(myBanner)

    while True:
        print("\n--- MAIN MENU ---\n")
        for num,val in netOptions.items():
            print(f"[{num}] - {val}")
        userAction = int(input("\nchoose an action: "))
        if userAction == 1:
            packetCapture()
        if userAction == 2:
            analyzeCapture()
        if userAction == 0:
            print(f"Goodbye!")
            sys.exit(0)

if __name__ == '__main__':
    main()