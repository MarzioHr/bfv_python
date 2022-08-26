'''Main script for unit testing the bfv_python library. Comment/uncomment test cases as needed.'''

import bfv_python
import numpy

## Test Case: Key Generation ##
print("Key Generation Testcase:")
# Set Ciphertext Modulus q
q=2**16
# Set polynomial length (number of coefficients)
n=2**2
# Set the standard deviation for error distribution
std_dev=1
# Set the polynomial modulus using n
polynom_modulus = numpy.array([1]+[0]*(n-1)+[1])
priv_key, pub_key = bfv_python.key_pair_gen(n,q,polynom_modulus,std_dev)
print(f"SK: {priv_key}")
print(f"PK1: {pub_key[0]}") 
print(f"PK2: {pub_key[1]}") 


## Test Case: Encryption and Decryption ##
print("\nEncryption and Decryption Testcase:")
# Set plaintext modulus
t = 16
# Set messages
m1 = 2
m2 = 3
# Encrypt the messages
c1 = bfv_python.encrypt_message(m1, pub_key, n, q, t, polynom_modulus, std_dev)
c2 = bfv_python.encrypt_message(m2, pub_key, n, q, t, polynom_modulus, std_dev)
print("Ciphertexts:")
print(f"c1: {c1[0]} | {c1[1]}")
print(f"c2: {c2[0]} | {c2[1]}")
dec1 = bfv_python.decrypt_cipher(c1, priv_key, q, t, polynom_modulus)
dec2 = bfv_python.decrypt_cipher(c2, priv_key, q, t, polynom_modulus)
print("Decrypted Ciphertexts:")
print(f"c1': {dec1}")
print(f"c2': {dec2}")


## Test Case: Addition Evaluation ##
print("\nAddition Evaluation Testcase:")
# Set messages
m1 = 6
m2 = 3
# Encrypt the messages
c1 = bfv_python.encrypt_message(m1, pub_key, n, q, t, polynom_modulus, std_dev)
c2 = bfv_python.encrypt_message(m2, pub_key, n, q, t, polynom_modulus, std_dev)
# Add the two ciphertexts and decrypt result
c_sum = bfv_python.eval_add(c1, c2, q, polynom_modulus)
dec_sum = bfv_python.decrypt_cipher(c_sum, priv_key, q, t, polynom_modulus)
print("Decrypted sum of c1+c2:")
print(f"dec_sum: {dec_sum}")
# Calculate plaintext sum
m_sum = m1+m2
print("Plaintext sum of m1+m2:")
print(f"m_sum: {m_sum}")


## Test Case: Multiplication Evaluation ##
print("\nMultiplication Evaluation Testcase:")
# Set parameters and generate rlk
p = 2**8
std_dev2 = 2
rlk = bfv_python.rlk_gen(n, q, p, polynom_modulus, priv_key, std_dev2)
# Set messages
m1 = 2
m2 = 3
# Encrypt the messages
c1 = bfv_python.encrypt_message(m1, pub_key, n, q, t, polynom_modulus, std_dev)
c2 = bfv_python.encrypt_message(m2, pub_key, n, q, t, polynom_modulus, std_dev)
# Multiply the two ciphertexts and decrypt result
c_prod = bfv_python.eval_mult(c1 , c2, q, t, p, polynom_modulus, rlk)
dec_prod = bfv_python.decrypt_cipher(c_prod, priv_key, q, t, polynom_modulus)
print("Decrypted product of c1*c2:")
print(f"dec_prod: {dec_prod}")
# Calculate plaintext product
m_prod = m1*m2
print("Plaintext product of m1*m2:")
print(f"m_prod: {m_prod}")