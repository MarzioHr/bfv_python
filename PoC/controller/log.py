"""Log Module of the Controller (Subscriber) to display Logs from Broker back to User."""

import time
from queue import Queue
import certifi
import paho.mqtt.client as mqtt

# CONSTANTS #
LOG_TOPIC = "$SYS/broker/log/#" # log topic to subscribe to

# Set Message Queue #
q=Queue() # initialise queue

def on_message(client, userdata, message):
    '''Function to handle what to do once a message is received.'''
    q.put(message) # add message to queue

def log_loop(user:str,password:str,host:str,port:str):
    '''
    Main Function to handle log and print messages.
    Subsbcribes to the log topic of the broker in a new thread
    and ensures all received messages are added to the queue.
    Loops through all messages in the queue and prints them back to the user.
    '''
    log_client = mqtt.Client("Controller/Logs") # set client id
    print("\nConnecting to Broker..")
    log_client.username_pw_set(username=user,password=password) # set user and pass as per args
    log_client.tls_set(certifi.where()) # use certifi library to set TLS cert of host
    log_client.connect(host, port=int(port)) # connect to host and port as per args
    log_client.on_message = on_message # bind custom on_message function to MQTT client
    print("Subscribing to topic",LOG_TOPIC)
    log_client.subscribe(LOG_TOPIC)
    # client Loop
    log_client.loop_start() # start subscribe loop in new thread
    print("\nBroker Logs\n____________________")
    while True:
        if not q.empty(): # if queue is not empty
            message = q.get() # get the latest message
            if message is not None:
                print(str(message.payload.decode("utf-8"))) # print decoded message content
        else:
            time.sleep(1) # if queue is empty sleep 1 second and try again
