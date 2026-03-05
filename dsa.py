import random
import hashlib

# fungsi modular inverse
def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


# Key Generation
def generate_keys():

    # contoh bilangan kecil agar mudah dihitung
    p = 23
    q = 11
    g = 2

    x = random.randint(1, q-1)   # private key
    y = pow(g, x, p)             # public key

    return (p, q, g, y, x)


# Hash function
def hash_message(message):
    h = hashlib.sha1(message.encode()).hexdigest()
    return int(h, 16)


# Signing
def sign(message, p, q, g, x):

    H = hash_message(message)

    while True:
        k = random.randint(1, q-1)

        r = pow(g, k, p) % q
        if r == 0:
            continue

        k_inv = mod_inverse(k, q)

        s = (k_inv * (H + x*r)) % q
        if s == 0:
            continue

        return (r, s)


# Verification
def verify(message, r, s, p, q, g, y):

    if not (0 < r < q and 0 < s < q):
        return False

    H = hash_message(message)

    w = mod_inverse(s, q)

    u1 = (H * w) % q
    u2 = (r * w) % q

    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

    return v == r


# Demo
p, q, g, y, x = generate_keys()

message = "Hello DSA"

r, s = sign(message, p, q, g, x)

print("Message:", message)
print("Signature:", r, s)

valid = verify(message, r, s, p, q, g, y)

print("Valid Signature:", valid)