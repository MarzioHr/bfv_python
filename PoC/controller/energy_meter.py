"""Energy Meter Module of the Controller (Subscriber) to display all devices temp to User."""

import sys
import time
from queue import Queue
import certifi
import paho.mqtt.client as mqtt
import bfv_python
import json
import numpy
import rsa
from Pyfhel import Pyfhel, PyCtxt

# CONSTANTS #
with open("./config/config.json", "r") as config_f:
    CONFIG = json.load(config_f)
TOPIC = f"Meters/{CONFIG['scheme']}/kw/" # topic to subscribe to



# Set Message Queue #
q=Queue() # initialise queue

def decrypt(message):
    '''Function to handle decryption of incoming messages'''
    if CONFIG["scheme"] == "bfv_python":
        message = message.decode('utf8')
        n = 4096
        q = 2**54
        t = 40961
        poly_mod = numpy.array([1]+[0]*(n-1)+[1])
        priv = numpy.load('config/priv.bfv.npz')['arr_0']
        enc_mess = message.split("|")
        c1 = numpy.array(json.loads(enc_mess[0]))
        c2 = numpy.array(json.loads(enc_mess[1]))
        return bfv_python.decrypt_cipher((c1,c2),priv,q,t,poly_mod)
    
    elif CONFIG["scheme"] == "RSA":
        with open('config/priv.rsa.pem', mode='rb') as priv_f:
            privkey = rsa.PrivateKey.load_pkcs1(priv_f.read())
        return rsa.decrypt(message, privkey).decode('utf8')
    
    elif CONFIG["scheme"] == "pyfhel-bfv":
        BFV = Pyfhel()
        BFV.contextGen(scheme='bfv', n=4096, t_bits=16, q=2**54)
        BFV.load_public_key("config/pub.pyfhel-bfv.bin")
        BFV.load_secret_key("config/priv.pyfhel-bfv.bin")
        BFV.load_relin_key("config/rlk.pyfhel-bfv.bin")
        enc_mess = PyCtxt(pyfhel=BFV, bytestring=message)
        return BFV.decryptInt(enc_mess)[0]

    elif CONFIG["scheme"] == "pyfhel-ckks":
        CKKS = Pyfhel()
        CKKS.contextGen(scheme='CKKS', n=2**14, scale=2**30, qi=[60, 30, 30, 30, 60])
        CKKS.load_public_key("config/pub.pyfhel-ckks.bin")
        CKKS.load_secret_key("config/priv.pyfhel-ckks.bin")
        CKKS.load_relin_key("config/rlk.pyfhel-ckks.bin")
        enc_mess = PyCtxt(pyfhel=CKKS, bytestring=message)
        return int(round(CKKS.decryptFrac(enc_mess)[0],0))

def on_message(client, userdata, message):
    '''Function to handle what to do once a message is received.'''
    q.put(message) # add message to queue

def reading_loop(user,password,host,port):
    '''
    Main Function to handle incoming energy meter values and print messages.
    Subscribes to the temp topic of the broker in a new thread and
    ensures all received messages are added to the queue.
    Loops through all messages in the queue and updates temp values displayed to user.
    '''
    client = mqtt.Client(f"Meters/{CONFIG['scheme']}/kw/") # set client id
    print("\nConnecting to Broker..")
    client.username_pw_set(username=user,password=password) # set username and password as per args
    if CONFIG["tls"] == True:
        client.tls_set(certifi.where()) # use certifi library to set TLS cert of host
    client.connect(CONFIG["broker"], port=int(CONFIG["port"])) # connect to host and port as per args
    client.on_message = on_message # bind custom on_message function to MQTT client
    print("Subscribing to topic",f"Meters/{CONFIG['scheme']}/kw/")
    client.subscribe(TOPIC)
    # client Loop
    client.loop_start() # start subscribe loop in new thread
    readings = [] # initialise empty dict
    lines = 0 # variable to count how many lines to overwrite
    print("\nSmart Meter Readings\n____________________")
    while True:
        if not q.empty(): # if queue is not empty
            message = q.get() # get the latest message
            if message is not None:
                readings.append(decrypt(message.payload)) # add reading data for specified room (prefix) to dict
            for _ in range(lines): # for number of lines
                sys.stdout.write("\x1b[1A\x1b[2K") # move up cursor and delete whole line in stdout
            lines = 0 # reset line count
            for entry in readings: # for all room+temp pairs in dict
                lines += 1 # increment line count to remove upon update
                print(f"{entry} kw") # print formatted meter and energy data
        else:
            time.sleep(1) # if queue is empty sleep 1 second and try again
