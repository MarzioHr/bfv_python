'''Main Script used for benchmarking the individual functionalities and byte sizes.'''

import sys
from random import randint
import json
import numpy
import bfv_python
import rsa
import datetime
from os.path import exists
from Pyfhel import Pyfhel, PyCtxt

CONFIG = {"scheme": "pyfhel-ckks"}

# Benchmarking Functions
def get_byte_size(input_obj) -> int:
    '''
    Takes as input any native data object and returns
    the size of the object in bytes.
    '''
    bytes = sys.getsizeof(input_obj)
    return bytes

def execution_time(input_func, *args) -> float:
    '''
    Takes as input a function and any arguments to be passed 
    and returns the function's execution time in milliseconds.
    '''
    start_time = datetime.datetime.now()
    # execute function to time
    input_func(*args)
    end_time = datetime.datetime.now()
    time_diff = (end_time - start_time)
    ms = time_diff.total_seconds() * 1000
    return ms

# Encryption Functions
def key_gen_test():
    if CONFIG["scheme"] == "bfv_python":
        n = 4096
        q = 2**54
        t = 40961
        std_dev = 3.2
        p = 2
        std_dev2 = 1.6
        poly_mod = numpy.array([1]+[0]*(n-1)+[1]) 
        priv, pub = bfv_python.key_pair_gen(n, q, poly_mod, std_dev)
        rlk = bfv_python.rlk_gen(n, q, p, poly_mod, priv, std_dev2)
        numpy.savez_compressed('keys/priv.bfv', priv)
        numpy.savez_compressed('keys/pub.bfv', pub)
        numpy.savez_compressed('keys/rlk.bfv', rlk)
    
    elif CONFIG["scheme"] == "RSA":
        (pubkey, privkey) = rsa.newkeys(256)
        with open('keys/priv.rsa.pem', mode='wb') as priv_f:
            priv_f.write(privkey.save_pkcs1("PEM"))
        with open('keys/pub.rsa.pem', mode='wb') as pub_f:
            pub_f.write(pubkey.save_pkcs1("PEM"))

    elif CONFIG["scheme"] == "pyfhel-bfv":
            BFV = Pyfhel()
            BFV.contextGen(scheme='bfv', n=4096, t_bits=16, q=2**54)
            BFV.keyGen()
            BFV.relinKeyGen()
            BFV.save_public_key("keys/pub.pyfhel-bfv.bin")
            BFV.save_secret_key("keys/priv.pyfhel-bfv.bin")
            BFV.save_relin_key("keys/rlk.pyfhel-bfv.bin")

    elif CONFIG["scheme"] == "pyfhel-ckks":
            CKKS = Pyfhel()
            CKKS.contextGen(scheme='CKKS', n=2**14, scale=2**30, qi=[60, 30, 30, 30, 60])
            CKKS.keyGen()
            CKKS.relinKeyGen()
            CKKS.save_public_key("keys/pub.pyfhel-ckks.bin")
            CKKS.save_secret_key("keys/priv.pyfhel-ckks.bin")
            CKKS.save_relin_key("keys/rlk.pyfhel-ckks.bin")

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
        if not exists('keys/priv.bfv.npz') or not exists('keys/pub.bfv.npz') or not exists('keys/rlk.bfv.npz'):
            priv, pub = bfv_python.key_pair_gen(n, q, poly_mod, std_dev)
            numpy.savez_compressed('keys/priv.bfv', priv)
            numpy.savez_compressed('keys/pub.bfv', pub)
            rlk = bfv_python.rlk_gen(n, q, p, poly_mod, priv, std_dev2)
            numpy.savez_compressed('keys/rlk.bfv', rlk)
        else:
            priv = numpy.load('keys/priv.bfv.npz')['arr_0']
            pub = numpy.load('keys/pub.bfv.npz')['arr_0']
            rlk = numpy.load('keys/rlk.bfv.npz')['arr_0']
        enc_mess = bfv_python.encrypt_message(message, pub, n, q, t, poly_mod, std_dev)
        c1 = json.dumps(enc_mess[0].tolist())
        c2 = json.dumps(enc_mess[1].tolist())
        return (c1+"|"+c2).replace(" ", "")
    elif CONFIG["scheme"] == "RSA":
        if not exists('keys/pub.rsa.pem') or not exists('keys/priv.rsa.pem'):
            (pubkey, privkey) = rsa.newkeys(256)
            with open('keys/priv.rsa.pem', mode='wb') as priv_f:
                priv_f.write(privkey.save_pkcs1("PEM"))
            with open('keys/pub.rsa.pem', mode='wb') as pub_f:
                pub_f.write(pubkey.save_pkcs1("PEM"))
        else:
            with open('keys/priv.rsa.pem', mode='rb') as priv_f:
                privkey = rsa.PrivateKey.load_pkcs1(priv_f.read())
            with open('keys/pub.rsa.pem', mode='rb') as pub_f:
                pubkey = rsa.PublicKey.load_pkcs1(pub_f.read())
        return rsa.encrypt(str(message).encode('utf8'), pubkey)
    elif CONFIG["scheme"] == "pyfhel-bfv":
        BFV = Pyfhel()
        BFV.contextGen(scheme='bfv', n=4096, t_bits=16, q=2**54)
        if not exists('keys/pub.pyfhel-bfv.bin') or not exists('keys/priv.pyfhel-bfv.bin') or not exists('keys/rlk.pyfhel-bfv.bin'):
            BFV.keyGen()
            BFV.relinKeyGen()
            BFV.save_public_key("keys/pub.pyfhel-bfv.bin")
            BFV.save_secret_key("keys/priv.pyfhel-bfv.bin")
            BFV.save_relin_key("keys/rlk.pyfhel-bfv.bin")
        else:
            BFV.load_public_key("keys/pub.pyfhel-bfv.bin")
            BFV.load_secret_key("keys/priv.pyfhel-bfv.bin")
            BFV.load_relin_key("keys/rlk.pyfhel-bfv.bin")
        message_array = numpy.array([message], dtype=numpy.int64)
        enc_mess = BFV.encryptInt(message_array)
        return enc_mess.to_bytes()
    elif CONFIG["scheme"] == "pyfhel-ckks":
        CKKS = Pyfhel()
        CKKS.contextGen(scheme='CKKS', n=2**14, scale=2**30, qi=[60, 30, 30, 30, 60])
        if not exists('keys/pub.pyfhel-ckks.bin') or not exists('keys/priv.pyfhel-ckks.bin') or not exists('keys/rlk.pyfhel-ckks.bin'):
            CKKS.keyGen()
            CKKS.relinKeyGen()
            CKKS.save_public_key("keys/pub.pyfhel-ckks.bin")
            CKKS.save_secret_key("keys/priv.pyfhel-ckks.bin")
            CKKS.save_relin_key("keys/rlk.pyfhel-ckks.bin")
        else:
            CKKS.load_public_key("keys/pub.pyfhel-ckks.bin")
            CKKS.load_secret_key("keys/priv.pyfhel-ckks.bin")
            CKKS.load_relin_key("keys/rlk.pyfhel-ckks.bin")
        message_array = numpy.array([float(message)], dtype=numpy.float64)
        mess = CKKS.encodeFrac(message_array)
        enc_mess = CKKS.encryptPtxt(mess)
        return enc_mess.to_bytes()

def decrypt(message):
    '''Function to handle decryption of incoming messages'''
    if CONFIG["scheme"] == "bfv_python":
        n = 4096
        q = 2**54
        t = 40961
        poly_mod = numpy.array([1]+[0]*(n-1)+[1])
        priv = numpy.load('keys/priv.bfv.npz')['arr_0']
        enc_mess = message.split("|")
        c1 = numpy.array(json.loads(enc_mess[0]))
        c2 = numpy.array(json.loads(enc_mess[1]))
        return bfv_python.decrypt_cipher((c1,c2),priv,q,t,poly_mod)
    elif CONFIG["scheme"] == "RSA":
        with open('keys/priv.rsa.pem', mode='rb') as priv_f:
            privkey = rsa.PrivateKey.load_pkcs1(priv_f.read())
        return rsa.decrypt(message, privkey).decode('utf8')
    elif CONFIG["scheme"] == "pyfhel-bfv":
        BFV = Pyfhel()
        BFV.contextGen(scheme='bfv', n=4096, t_bits=16, q=2**54)
        BFV.load_public_key("keys/pub.pyfhel-bfv.bin")
        BFV.load_secret_key("keys/priv.pyfhel-bfv.bin")
        BFV.load_relin_key("keys/rlk.pyfhel-bfv.bin")
        enc_mess = PyCtxt(pyfhel=BFV, bytestring=message)
        return BFV.decryptInt(enc_mess)[0]
    elif CONFIG["scheme"] == "pyfhel-ckks":
        CKKS = Pyfhel()
        CKKS.contextGen(scheme='CKKS', n=2**14, scale=2**30, qi=[60, 30, 30, 30, 60])
        CKKS.load_public_key("keys/pub.pyfhel-ckks.bin")
        CKKS.load_secret_key("keys/priv.pyfhel-ckks.bin")
        CKKS.load_relin_key("keys/rlk.pyfhel-ckks.bin")
        enc_mess = PyCtxt(pyfhel=CKKS, bytestring=message)
        return CKKS.decryptFrac(enc_mess)[0]

def eval_add(m1, m2):
    if CONFIG["scheme"] == "bfv_python":
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
        BFV.load_public_key("keys/pub.pyfhel-bfv.bin")
        BFV.load_secret_key("keys/priv.pyfhel-bfv.bin")
        BFV.load_relin_key("keys/rlk.pyfhel-bfv.bin")
        enc_m1 = PyCtxt(pyfhel=BFV, bytestring=m1)
        enc_m2 = PyCtxt(pyfhel=BFV, bytestring=m2)
        enc_sum = enc_m1 + enc_m2
        return enc_sum.to_bytes()
    elif CONFIG["scheme"] == "pyfhel-ckks":
        CKKS = Pyfhel()
        CKKS.contextGen(scheme='CKKS', n=2**14, scale=2**30, qi=[60, 30, 30, 30, 60])
        CKKS.load_public_key("keys/pub.pyfhel-ckks.bin")
        CKKS.load_secret_key("keys/priv.pyfhel-ckks.bin")
        CKKS.load_relin_key("keys/rlk.pyfhel-ckks.bin")
        enc_m1 = PyCtxt(pyfhel=CKKS, bytestring=m1)
        enc_m2 = PyCtxt(pyfhel=CKKS, bytestring=m2)
        enc_sum = enc_m1 + enc_m2
        return enc_sum.to_bytes()

def eval_mult(m1, m2):
    if CONFIG["scheme"] == "bfv_python":
        q = 2**54
        n = 4096
        t = 40961
        p = 2
        poly_mod = numpy.array([1]+[0]*(n-1)+[1])
        rlk = numpy.load('keys/rlk.bfv.npz')['arr_0']
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
        BFV.load_public_key("keys/pub.pyfhel-bfv.bin")
        BFV.load_secret_key("keys/priv.pyfhel-bfv.bin")
        BFV.load_relin_key("keys/rlk.pyfhel-bfv.bin")
        enc_m1 = PyCtxt(pyfhel=BFV, bytestring=m1)
        enc_m2 = PyCtxt(pyfhel=BFV, bytestring=m2)
        enc_prod = enc_m1 * enc_m2
        return enc_prod.to_bytes()
    elif CONFIG["scheme"] == "pyfhel-ckks":
        CKKS = Pyfhel()
        CKKS.contextGen(scheme='CKKS', n=2**14, scale=2**30, qi=[60, 30, 30, 30, 60])
        CKKS.load_public_key("keys/pub.pyfhel-ckks.bin")
        CKKS.load_secret_key("keys/priv.pyfhel-ckks.bin")
        CKKS.load_relin_key("keys/rlk.pyfhel-ckks.bin")
        enc_m1 = PyCtxt(pyfhel=CKKS, bytestring=m1)
        enc_m2 = PyCtxt(pyfhel=CKKS, bytestring=m2)
        enc_prod = enc_m1 * enc_m2
        return enc_prod.to_bytes()

# Testcases
print(f"Running Test Cases for {CONFIG['scheme']}")

## Key Gen ##
## Single Key Generation
# key_gen_test()
## Batch Run for Execution Timing
# gen_time = []
# for i in range(0,1000):
#     print(f"Run {i+1}..")
#     gen_time.append(execution_time(key_gen_test))
# print(f"Avg. Key Generation Execution Time for scheme '{CONFIG['scheme']}': {round(sum(gen_time)/len(gen_time),4)} ms")

## Encryption and Decryption ##
## Single Encryption and Decryption
# m = randint(0, 5)
# print(f"m: {m}")
# enc_m = encrypt(m)
# print(f"enc m: {enc_m}")
# dec_m = decrypt(enc_m)
# print(f"dec m: {dec_m}")
# print(f"ciphertext size: {get_byte_size(enc_m)} bytes")
## Batch Encryption for Execution Timing
# enc_time = []
# for i in range(0,1000):
#     print(f"Run {i+1}..")
#     m = randint(0, 5)
#     enc_time.append(execution_time(encrypt,m))
# print(f"Avg. Encryption Execution Time for scheme '{CONFIG['scheme']}': {round(sum(enc_time)/len(enc_time),4)} ms")
# Batch Decryption for Execution Timing  
# dec_time = []
# for i in range(0,1000):
#     print(f"Run {i+1}..")
#     m = randint(0, 5)
#     enc_m = encrypt(m)
#     dec_time.append(execution_time(decrypt,enc_m))
# print(f"Avg. Decryption Execution Time for scheme '{CONFIG['scheme']}': {round(sum(dec_time)/len(dec_time),4)} ms")

## Eval Add ##
## Single Eval Add
# m1 = randint(0,10)
# m2 = randint(0,10)
# enc_m1 = encrypt(m1)
# enc_m2 = encrypt(m2)
# enc_sum = eval_add(enc_m1, enc_m2)
# dec_sum = decrypt(enc_sum)
# print(f"Decrypted Sum: {dec_sum}")
# print(f"Plaintext Sum: {m1+m2}")
## Batch Eval Add for Execution Timing  
# eval_add_time = []
# for i in range(0,1000):
#     print(f"Run {i+1}..")
#     m1 = randint(0,10)
#     m2 = randint(0,10)
#     enc_m1 = encrypt(m1)
#     enc_m2 = encrypt(m2)
#     eval_add_time.append(execution_time(eval_add, enc_m1, enc_m2))
# print(f"Avg. Addition Evaluation Execution Time for scheme '{CONFIG['scheme']}': {round(sum(eval_add_time)/len(eval_add_time),4)} ms")

## Eval Mult ##
## Single Eval Mult
m1 = randint(0,5)
m2 = randint(0,5)
enc_m1 = encrypt(m1)
enc_m2 = encrypt(m2)
enc_prod = eval_mult(enc_m1, enc_m2)
dec_prod = decrypt(enc_prod)
print(f"Decrypted Sum: {dec_prod}")
print(f"Plaintext Sum: {m1*m2}")
## Batch Eval Mult for Execution Timing  
eval_mult_time = []
for i in range(0,1000):
    print(f"Run {i+1}..")
    m1 = randint(0,10)
    m2 = randint(0,10)
    enc_m1 = encrypt(m1)
    enc_m2 = encrypt(m2)
    eval_mult_time.append(execution_time(eval_mult, enc_m1, enc_m2))
print(f"Avg. Multiplication Evaluation Execution Time for scheme '{CONFIG['scheme']}': {round(sum(eval_mult_time)/len(eval_mult_time),4)} ms")