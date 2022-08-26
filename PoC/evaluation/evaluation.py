"""Energy Meter Module of the Controller (Subscriber) to display all devices temp to User."""

import time
from queue import Queue
import certifi
import paho.mqtt.client as mqtt
import bfv_python
import json
import numpy
import rsa
from Pyfhel import Pyfhel, PyCtxt
from os.path import exists


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

def encrypt(message):
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
        return (c1+"|"+c2).replace(" ", "")
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
        return rsa.encrypt(str(message).encode('utf8'), pubkey)
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
        return enc_mess.to_bytes()
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
        return enc_mess.to_bytes()

def eval_add(m1, m2):
    if CONFIG["scheme"] == "bfv_python":
        m1 = m1.decode('utf8')
        m2 = m2.decode('utf8')
        q = 2**54
        n = 4096
        poly_mod = numpy.array([1]+[0]*(n-1)+[1])
        m1_split = m1.split("|")
        m1_c1 = numpy.array(json.loads(m1_split[0]))
        m1_c2 = numpy.array(json.loads(m1_split[1]))
        enc_m1 = (m1_c1, m1_c2)
        m2_split = m2.split("|")
        m2_c1 = numpy.array(json.loads(m2_split[0]))
        m2_c2 = numpy.array(json.loads(m2_split[1]))
        enc_m2 = (m2_c1, m2_c2)
        enc_sum = bfv_python.eval_add(enc_m1, enc_m2, q, poly_mod)
        c1 = json.dumps(enc_sum[0].tolist())
        c2 = json.dumps(enc_sum[1].tolist())
        return (c1+"|"+c2).replace(" ", "")
    elif CONFIG["scheme"] == "pyfhel-bfv":
        BFV = Pyfhel()
        BFV.contextGen(scheme='bfv', n=4096, t_bits=16, q=2**54)
        BFV.load_public_key("config/pub.pyfhel-bfv.bin")
        BFV.load_secret_key("config/priv.pyfhel-bfv.bin")
        BFV.load_relin_key("config/rlk.pyfhel-bfv.bin")
        enc_m1 = PyCtxt(pyfhel=BFV, bytestring=m1)
        enc_m2 = PyCtxt(pyfhel=BFV, bytestring=m2)
        enc_sum = enc_m1 + enc_m2
        return enc_sum.to_bytes()
    elif CONFIG["scheme"] == "pyfhel-ckks":
        CKKS = Pyfhel()
        CKKS.contextGen(scheme='CKKS', n=2**14, scale=2**30, qi=[60, 30, 30, 30, 60])
        CKKS.load_public_key("config/pub.pyfhel-ckks.bin")
        CKKS.load_secret_key("config/priv.pyfhel-ckks.bin")
        CKKS.load_relin_key("config/rlk.pyfhel-ckks.bin")
        enc_m1 = PyCtxt(pyfhel=CKKS, bytestring=m1)
        enc_m2 = PyCtxt(pyfhel=CKKS, bytestring=m2)
        enc_sum = enc_m1 + enc_m2
        return enc_sum.to_bytes()

def eval_mult(m1, m2):
    if CONFIG["scheme"] == "bfv_python":
        m1 = m1.decode('utf8')
        m2 = m2.decode('utf8')
        q = 2**54
        n = 4096
        t = 40961
        p = 2
        poly_mod = numpy.array([1]+[0]*(n-1)+[1])
        rlk = numpy.load('config/rlk.bfv.npz')['arr_0']
        m1_split = m1.split("|")
        m1_c1 = numpy.array(json.loads(m1_split[0]))
        m1_c2 = numpy.array(json.loads(m1_split[1]))
        enc_m1 = (m1_c1, m1_c2)
        m2_split = m2.split("|")
        m2_c1 = numpy.array(json.loads(m2_split[0]))
        m2_c2 = numpy.array(json.loads(m2_split[1]))
        enc_m2 = (m2_c1, m2_c2)
        enc_prod = bfv_python.eval_mult(enc_m1, enc_m2, q, t, p, poly_mod, rlk)
        c1 = json.dumps(enc_prod[0].tolist())
        c2 = json.dumps(enc_prod[1].tolist())
        return (c1+"|"+c2).replace(" ", "")
    elif CONFIG["scheme"] == "pyfhel-bfv":
        BFV = Pyfhel()
        BFV.contextGen(scheme='bfv', n=4096, t_bits=16, q=2**54)
        BFV.load_public_key("config/pub.pyfhel-bfv.bin")
        BFV.load_secret_key("config/priv.pyfhel-bfv.bin")
        BFV.load_relin_key("config/rlk.pyfhel-bfv.bin")
        enc_m1 = PyCtxt(pyfhel=BFV, bytestring=m1)
        enc_m2 = PyCtxt(pyfhel=BFV, bytestring=m2)
        enc_prod = enc_m1 * enc_m2
        return enc_prod.to_bytes()
    elif CONFIG["scheme"] == "pyfhel-ckks":
        CKKS = Pyfhel()
        CKKS.contextGen(scheme='CKKS', n=2**14, scale=2**30, qi=[60, 30, 30, 30, 60])
        CKKS.load_public_key("config/pub.pyfhel-ckks.bin")
        CKKS.load_secret_key("config/priv.pyfhel-ckks.bin")
        CKKS.load_relin_key("config/rlk.pyfhel-ckks.bin")
        enc_m1 = PyCtxt(pyfhel=CKKS, bytestring=m1)
        enc_m2 = PyCtxt(pyfhel=CKKS, bytestring=m2)
        enc_prod = enc_m1 * enc_m2
        return enc_prod.to_bytes()


def publish(client, message, topic):
    result = client.publish(topic, message) # publish call
    status = result[0]
    if status != 0:
        print(f'Failed to send message to topic "{topic}"') # print error if unsuccessful
    return True

def on_message(client, userdata, message):
    '''Function to handle what to do once a message is received.'''
    q.put(message) # add message to queue

def reading_loop(user,password,host,port,evaluation):
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
    last_message = ""
    while True:
        if not q.empty(): # if queue is not empty
            message = q.get() # get the latest message
            if message is not None and last_message != "":
                if evaluation == "add":
                    result = eval_add(message.payload, last_message)
                elif evaluation == "mult":
                    result = eval_mult(message.payload, last_message)
                publish(client, result, f"{TOPIC}{evaluation}/")
                print(f"[{CONFIG['scheme']}] Published {evaluation} result to '{TOPIC}{evaluation}/'")
            last_message = message.payload
        else:
            time.sleep(1) # if queue is empty sleep 1 second and try again
