"""Main Module of the Energy Meter Device (Publisher). Defines the processflow and controls."""

import sys
import time
from random import randint
import paho.mqtt.client as mqtt
import certifi
from cryptography.fernet import Fernet
import json
import numpy
import bfv_python
import rsa
import datetime
from os.path import exists
from Pyfhel import Pyfhel, PyCtxt

### Config ###
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

def label_validation(check_label:str):
    '''
    Checks if a given device label is conform to the system's standards.
    This is done to prevent any sort of malicious user inputs and injection attacks.
    Validation: min. 3 characters max. 20 characters and at least 1 Letter.
    May only contain letters, numbers, spaces and '-'.
    Returns: True if conform and False if not.
    '''
    valid_char = (' ','-')
    min_len = 3
    max_len = 20
    min_1_letter = False # string has at least 1 letter
    if len(check_label) < min_len or len(check_label) > max_len: # checks the len of the given label
        return False # returns False if label length is less than 3 or more than 20
    for char in check_label: # checks each character of given label string
        if char.isalpha() and min_1_letter is not True:
            min_1_letter = True # set True that string has at least 1 letter
        if char.isalnum():
            continue
        if char in valid_char:
            continue
        return False # returns False if a character does not meet validation rules
    if min_1_letter is True:
        return True # returns True if all validation rules are met
    return False # returns False if label does not at least include 1 letter


# Main Class #
class Meter:
    '''Class for Energy Meter Object. Includes the PoC functionality and attributes.'''
    def __init__(self, label):
        self.label = label
        self.reading = 0
        self.client = mqtt.Client("Meter/"+str(self.label)) # set MQTT client incl. label
        self.topic = f"Meters/{CONFIG['scheme']}/kw/"
        self.prefix = self.label+": "

    def publish_reading(self):
        '''Publishes object's current kw reading to its MQTT Topic including its label prefix.'''
        result = self.client.publish(self.topic, self.reading) # publish call
        status = result[0]
        if status == 0:
            print(f'[{datetime.datetime.now()}] Sent "{self.prefix}Reading" to topic "{self.topic}"') # print confirm.
        else:
            print(f'Failed to send message to topic "{self.topic}"') # print error if unsuccessful
        return True

    def encrypt_reading(self, message):
        '''Encrypts energy reading with specified scheme in Config'''
        if CONFIG["scheme"] == "bfv_python":
            n = 4096
            q = 2**54
            t = 40961
            std_dev = 3.2
            p = 2
            std_dev2 = 1.6
            poly_mod = numpy.array([1]+[0]*(n-1)+[1])
            if not exists('config/priv.bfv.npz') or not exists('config/pub.bfv.npz') or not exists('config/rlk.bfv.npz'):
                priv, pub = bfv_python.key_pair_gen(n, q, poly_mod, std_dev)
                numpy.savez_compressed('config/priv.bfv', priv)
                numpy.savez_compressed('config/pub.bfv', pub)
                rlk = bfv_python.rlk_gen(n, q, p, poly_mod, priv, std_dev2)
                numpy.savez_compressed('config/rlk.bfv', rlk)
            else:
                priv = numpy.load('config/priv.bfv.npz')['arr_0']
                pub = numpy.load('config/pub.bfv.npz')['arr_0']
                rlk = numpy.load('config/rlk.bfv.npz')['arr_0']
            enc_mess = bfv_python.encrypt_message(message, pub, n, q, t, poly_mod, std_dev)
            c1 = json.dumps(enc_mess[0].tolist())
            c2 = json.dumps(enc_mess[1].tolist())
            self.reading = (c1+"|"+c2).replace(" ", "")
        
        elif CONFIG["scheme"] == "RSA":
            if not exists('config/pub.rsa.pem') or not exists('config/priv.rsa.pem'):
                (pubkey, privkey) = rsa.newkeys(256)
                with open('config/priv.rsa.pem', mode='wb') as priv_f:
                    priv_f.write(privkey.save_pkcs1("PEM"))
                with open('config/pub.rsa.pem', mode='wb') as pub_f:
                    pub_f.write(pubkey.save_pkcs1("PEM"))
            else:
                with open('config/priv.rsa.pem', mode='rb') as priv_f:
                    privkey = rsa.PrivateKey.load_pkcs1(priv_f.read())
                with open('config/pub.rsa.pem', mode='rb') as pub_f:
                    pubkey = rsa.PublicKey.load_pkcs1(pub_f.read())
            self.reading = rsa.encrypt(str(message).encode('utf8'), pubkey)

        elif CONFIG["scheme"] == "pyfhel-bfv":
            BFV = Pyfhel()
            BFV.contextGen(scheme='bfv', n=4096, t_bits=16, q=2**54)
            if not exists('config/pub.pyfhel-bfv.bin') or not exists('config/priv.pyfhel-bfv.bin') or not exists('config/rlk.pyfhel-bfv.bin'):
                BFV.keyGen()
                BFV.relinKeyGen()
                BFV.save_public_key("config/pub.pyfhel-bfv.bin")
                BFV.save_secret_key("config/priv.pyfhel-bfv.bin")
                BFV.save_relin_key("config/rlk.pyfhel-bfv.bin")
            else:
                BFV.load_public_key("config/pub.pyfhel-bfv.bin")
                BFV.load_secret_key("config/priv.pyfhel-bfv.bin")
                BFV.load_relin_key("config/rlk.pyfhel-bfv.bin")
            message_array = numpy.array([message], dtype=numpy.int64)
            enc_mess = BFV.encryptInt(message_array)
            self.reading = enc_mess.to_bytes()

        elif CONFIG["scheme"] == "pyfhel-ckks":
            CKKS = Pyfhel()
            CKKS.contextGen(scheme='CKKS', n=2**14, scale=2**30, qi=[60, 30, 30, 30, 60])
            if not exists('config/pub.pyfhel-ckks.bin') or not exists('config/priv.pyfhel-ckks.bin') or not exists('config/rlk.pyfhel-ckks.bin'):
                CKKS.keyGen()
                CKKS.relinKeyGen()
                CKKS.save_public_key("config/pub.pyfhel-ckks.bin")
                CKKS.save_secret_key("config/priv.pyfhel-ckks.bin")
                CKKS.save_relin_key("config/rlk.pyfhel-ckks.bin")
            else:
                CKKS.load_public_key("config/pub.pyfhel-ckks.bin")
                CKKS.load_secret_key("config/priv.pyfhel-ckks.bin")
                CKKS.load_relin_key("config/rlk.pyfhel-ckks.bin")
            message_array = numpy.array([float(message)], dtype=numpy.float64)
            mess = CKKS.encodeFrac(message_array)
            enc_mess = CKKS.encryptPtxt(mess)
            self.reading = enc_mess.to_bytes()
        

# Set Credentials #
credentials = fetch_credentials() # attempt to fetch and decypt the connection credentials
if credentials is False:
    print("Error: Unable to decrypt Credentials to connect to Broker.")
    sys.exit() # exit execution if credentials could not be retrieved
host, port, user, password = credentials # assign credentials list to individual variables

# Set Device Label and Object #
u_label = input("Where is this Energy Meter located? ")
if label_validation(u_label) is False:
    print("Error: Invalid device label given. Please make sure to ",
        "at least use 3 characters and only use letters, numbers, spaces and hyphens.")
    sys.exit() # exit execution if inputted device label does not conform to validation rules
energymeter = Meter(u_label)
energymeter.client.username_pw_set(username=user,password=password) # set user and pass in client
if CONFIG["tls"] == True:
    energymeter.client.tls_set(certifi.where()) # use certifi library to set TLS cert of host
energymeter.client.connect(CONFIG["broker"], port=int(CONFIG["port"])) # connect to host and port specified in credentials

# Main Loop #
while True:
    energymeter.encrypt_reading(randint(0, 10)) # assign random integer value between 0 and 10 as kw and encrypt
    energymeter.publish_reading() # publish the energy consumption to the MQTT topic
    time.sleep(CONFIG["freq"])