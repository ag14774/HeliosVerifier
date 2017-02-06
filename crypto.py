import hashlib
import base64

"""
def xgcd(a, b):
    rprev, r = a, b
    sprev, s = 1, 0
    tprev, t = 0, 1
    while True:
        q = rprev // r
        rnext = rprev - q*r #Remainder calculations
        rprev = r
        r = rnext
        snext = sprev - q*s #First Bezout coefficient
        sprev = s
        s = snext
        tnext = tprev - q*t #Second Bezout coefficient
        tprev = t
        t = tnext
        if r==0: return (rprev,sprev,tprev)

inverse_cache = {}
def modinverse(a ,b):
    '''Find a^(-1) mod b'''
    try:
        return inverse_cache[(a,b)]
    except Exception:
        (r,s,t) = xgcd(a, b)
        if r!=1:
            raise ValueError("remainder not equal to 1")
        result = s%b
        inverse_cache[(a,b)] = result
        return result
"""

def verify_cp_proof(triple, g, p, commitment, challenge, response):
    X = triple[0]
    Y = triple[1]
    Z = triple[2]
    A = commitment[0]
    B = commitment[1]

    gresponse = pow(g, response, p)
    alpha_y_c = (pow(Y, challenge, p) * A) % p
    if gresponse != alpha_y_c:
        return False

    xresponse = pow(X, response, p)
    beta_z_c  = (pow(Z, challenge, p) * B) % p
    if xresponse != beta_z_c:
        return False

    return True

def verify_schnorr_proof(X, g, p, commitment, challenge, response):
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
