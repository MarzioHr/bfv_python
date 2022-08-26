'''Main module for the bfv_python homomorphic encryption library.'''

import numpy
from numpy.polynomial import polynomial

# Operations for Polynomials within Polynomial Ring R_q
def add_polys(poly1:list, poly2:list, mod_q:int, poly_mod:int) -> list:
    '''
    Adds two polynomials together.
    Takes as input:
        poly1: first polynomial to take as base.
        poly2: second polynomial to add to base.
        mod_q: the ciphertext modulus.
        poly_mod: the polynomial modulus (given as x^len_n+1).
    Returns:
        The sum as a polynomial within the polynomial ring R_q.
    '''
    poly_sum = polynomial.polydiv(polynomial.polyadd(poly1, poly2) % mod_q, poly_mod)[1] % mod_q
    return numpy.int64(numpy.round(poly_sum))


def mult_polys(poly1:list, poly2:list, mod_q:int, poly_mod:int) -> list:
    '''
    Multiplies two polynomials.
    Takes as input:
        poly1: first polynomial to take as base.
        poly2: second polynomial to multiply with base.
        mod_q: the ciphertext modulus.
        poly_mod: the polynomial modulus (given as x^len_n+1).
    Returns:
        The product as a polynomial within the polynomial ring R_q.
    '''
    product = polynomial.polydiv(polynomial.polymul(poly1, poly2) % mod_q, poly_mod)[1] % mod_q
    return numpy.int64(numpy.round(product))


# Operations for Polynomials mod poly_mod only
def add_mod_poly(poly1:list, poly2:list, poly_mod:int) -> list:
    '''
    Add two polynomials without applying modulus mod_q (mod poly_mod only).
    Takes as input:
        poly1: first polynomial to take as base.
        poly2: second polynomial to add to base.
        poly_mod: the polynomial modulus (given as x^len_n+1).
    Returns:
        The sum as a polynomial within the polynomial ring without applying mod_q.
    '''
    summed = polynomial.polydiv(polynomial.polyadd(poly1, poly2), poly_mod)
    return summed[1]

def mult_mod_poly(poly1:list, poly2:list, poly_mod:int) -> list:
    '''
    Multiply two polynomials without applying modulus mod_q (mod poly_mod only).
    Takes as input:
        poly1: first polynomial to take as base.
        poly2: second polynomial to multiply with base.
        poly_mod: the polynomial modulus (given as x^len_n+1).
    Returns:
        The product as a polynomial within the polynomial ring without applying mod_q.
    '''
    product = polynomial.polydiv(polynomial.polymul(poly1, poly2), poly_mod)[1]
    return product


# Generation of differing types of Polynomials
def ternary_poly_gen(len_n:int) -> list:
    '''
    Generates a ternary polynomial with coefficients being either {-1, 0, 1}.
    Takes as input:
        len_n: the number of coefficients within the polynomial
           (the degree of the polynomial amounts to len_n+1).
    Returns:
        A coefficient array, where array[i] denotes the polynomial coefficient at position i.
    '''
    array = numpy.random.randint(-1, 2, len_n)
    return array

def uni_poly_gen(len_n:int, mod_q:int) -> list:
    '''
    Generates a polynomial with coeffecients within Z_q {0,1,..,mod_q-1},
    i.e. is part of the polynomial ring R_q.
    Takes as input:
        len_n: the number of coefficients within the polynomial
           (the degree of the polynomial amounts to len_n+1).
        mod_q: the modulus for the given polynomial ring.
    Returns:
        A coefficient array, where array[i] denotes the polynomial coefficient at position i.
    '''
    array = numpy.random.randint(0, mod_q, len_n)
    return array

def gauss_poly_gen(len_n:int, std_dev:float) -> list:
    '''
    Generates a polynomial with coefficients that are part of the error distribution χ
    (discrete Gaussian distribution). Uses standard deviation and mean of 0 to
    transform the normal distribution to a discrete one (discretization).
    Takes as input:
        len_n: the number of coefficients within the polynomial
           (the degree of the polynomial amounts to len_n+1).
        std_dev: the standard deviation to be used for discretization.
    Returns:
        A coefficient array, where array[i] denotes the polynomial coefficient at position i.
    '''
    array = numpy.int64(numpy.random.normal(0, std_dev, size=len_n))
    return array

# Generate Private and Public Key Pair #
def key_pair_gen(len_n:int, mod_q:int, poly_mod:int, std_dev:float):
    '''
    Generates the private/public key pair to be used for the HE process.
    Takes as input:
        len_n: the length of polynomials to be used as priv/pub keys.
        mod_q: the ciphertext modulus.
        poly_mod: the polynomial modulus (given as x^len_n+1).
        std_dev: the standard deviation to be used for the error distribution.
    Returns:
        priv_key, pub_key
    '''
    priv_key = ternary_poly_gen(len_n)
    poly_a = uni_poly_gen(len_n, mod_q)
    poly_e = gauss_poly_gen(len_n,std_dev)
    pub_key_1 = add_polys(mult_polys(-poly_a, priv_key, mod_q, poly_mod), -poly_e, mod_q, poly_mod)
    pub_key_2 = poly_a
    pub_key = (pub_key_1, pub_key_2)
    return priv_key, pub_key

# Encryption
def encrypt_message(mess:int, pub_key:tuple, len_n:int, mod_q:int, mod_t:int,
    poly_mod:int, std_dev:float) -> tuple:
    '''
    Encrypt a given integer message mess using the given public key.
    Takes as input:
        mess: plaintext integer message.
        pub_key: public key generated via key_pair_gen().
        mod_q: the modulus used for ciphertext (as per BFV).
        mod_t: the modulus used for plaintext (as per BFV).
        poly_mod: the modulus used for polynomials (given as x^len_n+1).
    Returns:
        The encrypted ciphertext polynomial C=(C1,C2) as a tuple containing two arrays.
    '''
    encoded_m = numpy.array([mess] +[0]*(len_n-1)) % mod_t
    moduli_quotient = mod_q//mod_t
    scale = moduli_quotient * encoded_m
    u_poly = ternary_poly_gen(len_n)
    error1_poly = gauss_poly_gen(len_n, std_dev)
    error2_poly = gauss_poly_gen(len_n, std_dev)
    c_1 = add_polys(
            add_polys(
                mult_polys(pub_key[0], u_poly, mod_q, poly_mod),
                error1_poly, mod_q, poly_mod),
            scale, mod_q, poly_mod
    )
    c_2 = add_polys(
        mult_polys(pub_key[1], u_poly, mod_q, poly_mod),
        error2_poly, mod_q, poly_mod
    )
    return (c_1, c_2)


# Decryption
def decrypt_cipher(cipher:tuple, priv_key:list, mod_q:int, mod_t:int, poly_mod:int) -> int:
    '''
    Decrypt a given ciphertext using the passed private/secret key.
    Takes as input:
        c: ciphertext tuple containing c1 and c2.
        priv_key: private key generated via key_pair_gen().
        mod_q: the modulus used for ciphertext (as per BFV).
        mod_t: the modulus used for plaintext (as per BFV).
        poly_mod: the modulus used for polynomials (given as x^len_n+1).
    Returns:
        The decrypted ciphertext polynomial as an integer.
    '''
    scaled_m = add_polys(mult_polys(cipher[1], priv_key, mod_q, poly_mod),
                cipher[0], mod_q, poly_mod)
    decrypted_res = numpy.int64((numpy.round(mod_t * scaled_m / mod_q) % mod_t)[0])
    return decrypted_res


#Evaluation
def eval_add(c_1:tuple, c_2:tuple, mod_q:int, poly_mod:int) -> tuple:
    '''
    Adds two ciphertexts and returns the sum as a ciphertext.
    Takes as input:
        c1: first ciphertext to take as base.
        c2: second ciphertext to add to base.
        mod_q: the ciphertext modulus.
        poly_mod: the polynomial modulus (given as x^len_n+1).
    Returns:
        The encrypted ciphertext c_sum=(c_sum1,c_sum2) as a tuple containing two arrays.
    '''
    c_sum1 = add_polys(c_1[0], c_2[0], mod_q, poly_mod)
    c_sum2 = add_polys(c_1[1], c_2[1], mod_q, poly_mod)
    return (c_sum1, c_sum2)

def eval_mult(c_1:tuple, c_2:tuple, mod_q:int, mod_t:int, mod_p:int,
    poly_mod:int, rlk:tuple) -> tuple:
    '''
    Multiplies two ciphertexts and returns the product as a ciphertext.
    Utilises the rlk key to reduce the result from a degree 2 polynomial
    to a degree 1 polynomial.
    Employs the concept of modulus switching to reduce generated noise.
    Takes as input:
        c1: first ciphertext to take as base.
        c2: second ciphertext to add to base.
        mod_q: the modulus used for ciphertext (as per BFV).
        mod_t: the modulus used for plaintext (as per BFV).
        mod_p: an extra integer mod_p to generate the masked version modulo mod_p*mod_q.
        poly_mod: the modulus used for polynomials (given as x^len_n+1).
        rlk: the relinearization key rlk.
    Returns:
        The encrypted ciphertext new_c_prod=(new_c_prod1, new_c_prod2)
        as a tuple containing two arrays.
    '''
    # Calculate degree 2 polynomial c_prod = (c_prod1, c_prod2, c_prod3)
    c_prod1 = numpy.int64(numpy.round(mult_mod_poly(c_1[0],c_2[0],poly_mod) * mod_t / mod_q))%mod_q
    c_prod2 = numpy.int64(numpy.round(add_mod_poly(
                mult_mod_poly(c_1[0], c_2[1], poly_mod),
                mult_mod_poly(c_1[1], c_2[0], poly_mod), poly_mod)
            * mod_t / mod_q)) % mod_q
    c_prod3 = numpy.int64(numpy.round(mult_mod_poly(c_1[1],c_2[1],poly_mod) * mod_t / mod_q))%mod_q
    # Calculate the approximation for c_prod3 * sk^2 mod mod_q
    c_prod2_0 = numpy.int64(numpy.round(mult_mod_poly(c_prod3, rlk[0], poly_mod) / mod_p)) % mod_q
    c_prod2_1 = numpy.int64(numpy.round(mult_mod_poly(c_prod3, rlk[1], poly_mod) / mod_p)) % mod_q
    # Calculate new_c_prod using the approximation
    new_c_prod1 = numpy.int64(add_mod_poly(c_prod1, c_prod2_0, poly_mod)) % mod_q
    new_c_prod2 = numpy.int64(add_mod_poly(c_prod2, c_prod2_1, poly_mod)) % mod_q
    return (new_c_prod1, new_c_prod2)

# Generate Relinearisation Key rlk
def rlk_gen(len_n:int, mod_q:int, mod_p:int, poly_mod:int, priv_key:list, std_dev2:float) -> tuple:
    '''
    Follows relinearization variant 2 within BFV.
    Utilises an approach that incorporates the concept of modulus switching
    to approximate c_prod3 * sk^2 mod mod_q.
    Takes as input:
        len_n: the length of the polynomials to be used.
        mod_q: the modulus used for ciphertext (as per BFV).
        poly_mod: the modulus used for polynomials (given as x^len_n+1).
        priv_key: private key generated via key_pair_gen().
        mod_p: an extra integer mod_p to generate the masked version modulo mod_p*mod_q.
        std_dev2: the standard deviation to be used for the error distribution X'.
    Returns:
        Relinearization key rlk as tuple containing (rlk1, rlk2).
    '''
    mod_switch = mod_q*mod_p
    poly_a = uni_poly_gen(len_n, mod_switch)
    poly_e = gauss_poly_gen(len_n, std_dev2)
    masked_secret = mod_p*polynomial.polymul(priv_key, priv_key)
    rlk_1 = numpy.int64(add_mod_poly(
            mult_mod_poly(-poly_a, priv_key, poly_mod),
            add_mod_poly(-poly_e, masked_secret, poly_mod), poly_mod)
        ) % mod_switch
    rlk_2 = poly_a
    return (rlk_1, rlk_2)
