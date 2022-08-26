"""Main Module of the Controller (Subscriber). Defines the processflow and security controls."""

import sys
from cryptography.fernet import Fernet
import log
import energy_meter
import json

## CONFIG ##
with open("./config/config.json", "r") as config_f:
    CONFIG = json.load(config_f)

# Functions #
def retrieve_key():
    '''Function to retrieve the Fernet Encryption Key from the config folder.'''
    try: # try retrieving the Fernet encryption key from bin file
        with open("./config/key.bin", "rb") as key_file:
            retrieved_key = key_file.read()
    except OSError: # if file not found
        print("Error retrieving key.")
        return None
    return retrieved_key

def fetch_credentials():
    '''Function to decrypt credentials from config/credentials.bin file'''
    try: # try to open and retrieve encrypted credentials.bin
        with open("./config/credentials.bin", "rb") as login_f:
            retrieved_cred = login_f.read()
    except OSError: # file not found
        return False
    cipher = Fernet(retrieve_key()) # fetch Fernet decryption key
    credential = cipher.decrypt(retrieved_cred) # decrypt credentials using key
    credential = credential.decode('utf-8') # decode output into utf-8 format
    return credential.split(":") # split string into list using ":" as seperator

# Main Code Execution #
if __name__ == "__main__": # only run code if main.py is executed and not imported
    # Set Credentials #
    credentials = fetch_credentials() # attempt to fetch and decypt the connection credentials
    if credentials is False:
        print("Error: Unable to decrypt Credentials to connect to Broker.")
        sys.exit() # exit execution if credentials could not be retrieved
    host, port, user, password = credentials # assign credentials list to individual variables

    # Menu Choice #
    user_choice = input("""Overview:\n1. Energy Meter Overview
2. Broker Logs\n\nInput Choice: """)

    # redirect to Module where appropriate
    if user_choice == "1":
        energy_meter.reading_loop(user, password, CONFIG["broker"], CONFIG["port"]) # redirect to temperatures module
    elif user_choice == "2":
        log.log_loop(user, password, CONFIG["broker"], CONFIG["port"]) # redirect to log module
    else:
        print("Error: Invalid Input. Please try again.")
        sys.exit() # exit execution if invalid input was given for menu choice
