from scapy.all import sniff, IP
from scapy.layers.http import HTTPRequest
import logging
import re
import platform
import sys
from threading import Thread

# Configure logging
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s - %(message)s')
file_handler = logging.FileHandler('ids.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logging.getLogger().addHandler(file_handler)

# Function to handle HTTP packets
def http_monitor_callback(pkt):
    if pkt.haslayer(HTTPRequest):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        method = pkt[HTTPRequest].Method.decode("utf-8")
        url = pkt[HTTPRequest].Path.decode("utf-8", errors='ignore')

        # Check for suspicious HTTP activity
        if re.search(r'\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP)\b', url, re.IGNORECASE):
            logging.warning(f"Potential SQL Injection Attempt: {src_ip} -> {dst_ip}, URL: {url}")
        elif 'maliciousdomain.com' in url:
            logging.warning(f"Access to Known Malicious Domain: {src_ip} -> {dst_ip}, URL: {url}")

# Function to handle process creation events (Windows only)
def process_creation_callback(process):
    logging.info(f"Process Launched: {process.Name}")

    # Check for suspicious processes
    if process.Name.lower() == 'cmd.exe':
        logging.warning(f"Command Prompt Launched: {process.Name}")

# Function to simulate chat message monitoring
def chat_message_monitor_callback(message):
    logging.info(f"Chat Message: {message}")

# Function to start HTTP monitoring
def start_http_monitoring():
    try:
        sniff(filter="tcp port 80", prn=http_monitor_callback, store=0)
    except Exception as e:
        logging.error(f"Error in HTTP monitoring: {e}")

# Function to start process monitoring
def start_process_monitoring():
    if platform.system() == "Windows":
        try:
            import wmi
            c = wmi.WMI()
            watcher = c.Win32_Process.watch_for("creation")
            while True:
                process = watcher()
                process_creation_callback(process)
        except ImportError as e:
            logging.error(f"wmi module not found: {e}")
        except Exception as e:
            logging.error(f"Error in process monitoring: {e}")
    else:
        logging.warning("Process monitoring is only supported on Windows.")

# Main function
if __name__ == "__main__":
    http_thread = Thread(target=start_http_monitoring)
    process_thread = Thread(target=start_process_monitoring)
    # chat_thread = Thread(target=start_chat_message_monitoring)

    http_thread.start()
    process_thread.start()
    # chat_thread.start()

    http_thread.join()
    process_thread.join()
    # chat_thread.join()
