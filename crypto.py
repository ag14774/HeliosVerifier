"""Contains useful functions related to cryptography."""
import base64
import hashlib
from random import randrange


def xgcd(a, b):
    """Extended GCD of (a, b)."""
    rprev, r = a, b
    sprev, s = 1, 0
    tprev, t = 0, 1
    while True:
        q = rprev // r
        rnext = rprev - q * r  # Remainder calculations
        rprev = r
        r = rnext
        snext = sprev - q * s  # First Bezout coefficient
        sprev = s
        s = snext
        tnext = tprev - q * t  # Second Bezout coefficient
        tprev = t
        t = tnext
        if r == 0:
            return (rprev, sprev, tprev)


def modinverse(a, b):
    """Find a^(-1) mod b."""
    (r, s, t) = xgcd(a, b)
    if r != 1:
        raise ValueError("remainder not equal to 1")
    return s % b


def miller_rabin(n, num_trials=4):
    """Check if n is prime."""
    if n in [2, 3, 5, 7]:
        return True
    if n <= 10 or n % 2 == 0:
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
        if not (apow in [1, n - 1]):
            some_minus_one = False
            for r in range(s - 1):
                apow = (apow**2) % n
                if apow == n - 1:
                    some_minus_one = True
                    break
        if (apow not in [1, n - 1]) and not some_minus_one:
            return False
    return True


def verify_cp_proof(triple, g, p, q, commitment, challenge, response):
    """
    Verify knowledge of a Diffie-Hellman triple.

    Use Chaum-Pederson zero-knowledge proof to verify knowledge of
    a Diffie-Hellman triple
    """
    X = triple[0]
    Y = triple[1]
    Z = triple[2]
    A = commitment[0]
    B = commitment[1]

    if not (1 < challenge < q):
        return False

    if pow(A, q, p) != 1:
        return False

    if pow(B, q, p) != 1:
        return False

    gresponse = pow(g, response, p)
    alpha_y_c = (pow(Y, challenge, p) * A) % p
    if gresponse != alpha_y_c:
        return False

    xresponse = pow(X, response, p)
    beta_z_c = (pow(Z, challenge, p) * B) % p
    if xresponse != beta_z_c:
        return False

    return True


def verify_schnorr_proof(X, g, p, q, commitment, challenge, response):
    """Verify knowledge of a discrete logarithm."""
    if not (1 < challenge < q):
        return False

    if pow(commitment, q, p) != 1:
        return False

    gresponse = pow(g, response, p)
    alpha_x_c = (pow(X, challenge, p) * commitment) % p
    if gresponse != alpha_x_c:
        return False
    return True


def int_sha1(string):
    """Hash a string using SHA1 and return it as an integer."""
    return int(hashlib.sha1(string.encode()).hexdigest(), 16)


def b64_sha256(string):
    """Hash a string using SHA256 and return is as a base64 encoding."""
    out = hashlib.sha256(string.encode()).digest()
    return base64.b64encode(out)[:-1].decode()
