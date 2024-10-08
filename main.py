import sys
import warnings
import argparse
from scapy.all import sniff, conf

# Suppress specific warning
warnings.filterwarnings("ignore", message=".*cannot read manuf.*")

# Function to processes each captured packet
def process_packet(packet):
    print(packet.summary())  # Prints a brief summary of the packet

def main():
    # Argparse automatically creates the help section with these variables
    parser = argparse.ArgumentParser(
        description="A simple packet sniffer written in Python.",
        epilog="Author: Lucas Caetano <https://github.com/LucasRibeiroCaetano>"
    )

    # -f for filter; this option allows the user to specify a packet filter
    parser.add_argument(
        '-f',  # Short option
        '--filter',  # Long option
        type=str,
        help="Filter for sniffing (e.g., 'tcp', 'udp', 'icmp')",
        default="ip"  # captures all IP traffic by default
    )

    # -n for the number of packets to capture
    parser.add_argument(
        '-n',  # Short option
        '--num',  # Long option
        type=int,
        help="Number of packets to capture",
        default=0  # 0 means capture indefinitely
    )

    # -i for specifying the network interface to sniff on
    parser.add_argument(
        '-i',  # Short option
        '--interface',  # Long option
        type=str,
        help="Network interface to sniff on (e.g., 'eth0', 'wlan0')",
        default=None  # None means all available interfaces
    )

    # Parse the command-line arguments provided by the user
    args = parser.parse_args()

    # Start packet sniffing
    try:
        # Print the starting configuration for the user
        print(f"Starting packet capture with filter: {args.filter} on interface: {args.interface}")

        # Call the sniff function to start capturing packets
        # - filter=args.filter: Use the filter string provided by the user
        # - iface=args.interface: Use the specified network interface
        # - prn=process_packet: Specify the function to process each captured packet
        # - count=args.num: Limit the number of packets captured based on user input
        sniff(filter=args.filter, iface=args.interface, prn=process_packet, count=args.num)

    # Handle a keyboard interrupt (Ctrl+C) to stop the sniffing process
    except KeyboardInterrupt:
        print("\nPacket capture interrupted by user.")

    # Handle permission errors, which may occur if the script is not run with sufficient privileges
    except PermissionError:
        print("Permission denied: Please run the script as root.")

# Checks if the script is being run directly (as opposed to being imported as a module)
if __name__ == "__main__":
    main()  # Call the main function to execute the packet sniffer
