import hashlib
import base64
from random import randrange

def miller_rabin(n, num_trials=4):
    if n in [2,3,5,7]:
        return True
    if n<=10 or n%2 == 0:
        return False
    s = 0
    d = n - 1
    while True:
        q, r = divmod(d, 2)
        if r == 1:
            break
        s += 1
        d = q
    for i in range(num_trials):
        a = randrange(2, n)
        apow = pow(a, d, n)
        if not (apow in [1, n-1]):
            some_minus_one = False
            for r in range(s-1):
                apow = (apow**2)%n
                if apow == n-1:
                    some_minus_one = True
                    break;
        if (apow not in [1, n-1]) and not some_minus_one:
            return False
    return True

# FIXME: Add check for response too? >= q

def verify_cp_proof(triple, g, p, q, commitment, challenge, response):
    X = triple[0]
    Y = triple[1]
    Z = triple[2]
    A = commitment[0]
    B = commitment[1]

    if challenge>=q:
        return False

    gresponse = pow(g, response, p)
    alpha_y_c = (pow(Y, challenge, p) * A) % p
    if gresponse != alpha_y_c:
        return False

    xresponse = pow(X, response, p)
    beta_z_c  = (pow(Z, challenge, p) * B) % p
    if xresponse != beta_z_c:
        return False

    return True

def verify_schnorr_proof(X, g, p, q, commitment, challenge, response):
    if challenge >= q:
        return False
    gresponse = pow(g, response, p)
    alpha_x_c = (pow(X, challenge, p) * commitment) % p
    if gresponse != alpha_x_c:
        return False
    return True

def int_sha1(string):
    return int(hashlib.sha1(string.encode()).hexdigest(),16)

def b64_sha256(string):
    out = hashlib.sha256(string.encode()).digest()
    return base64.b64encode(out)[:-1].decode()
