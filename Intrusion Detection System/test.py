import pyshark
import re
from urllib.parse import unquote
import signal
import sys

# Global variable to control the packet capture loop
capture_running = True

def signal_handler(sig, frame):
    global capture_running
    print('Interrupt received, stopping capture...')
    capture_running = False

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

# Function to process packets
def process_packet(pkt, log_file):
    try:
        if 'TCP' in pkt and 'Raw' in pkt:
            raw_data = pkt.tcp.payload.binary_value.decode('utf-8', errors='ignore')

            # Hypothetical traffic pattern for WhatsApp
            if 'whatsapp' in raw_data.lower():  # Replace with actual pattern if known
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport

                # Log the packet details to the log file
                log_file.write(f"Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
                log_file.write(f"Data: {raw_data}\n")
                log_file.write("="*50 + "\n")
                log_file.flush()
    except AttributeError as e:
        print(f"Error processing packet: {e}")

# Start packet sniffing
def start_packet_sniffing(interface, log_filename):
    global capture_running
    with open(log_filename, 'w') as log_file:
        capture = pyshark.LiveCapture(interface=interface, bpf_filter='tcp')
        try:
            for packet in capture:
                if not capture_running:
                    break
                process_packet(packet, log_file)
        except EOFError:
            print('Capture ended.')

# Main function
if __name__ == "__main__":
    interface = 'Ethernet 2'  # Use the name of your primary network interface
    log_filename = 'captured_packets.log'
    start_packet_sniffing(interface, log_filename)
