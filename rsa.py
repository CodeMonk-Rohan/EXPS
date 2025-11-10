import random

class RSA:
    """RSA Encryption/Decryption Implementation"""

    def __init__(self, key_size=64):
        # Small key for demo - NEVER use in production!
        self.key_size = key_size

    @staticmethod
    def is_prime(n, k=5):
        """Miller-Rabin primality test"""
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, s, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_prime(self, bits):
        """Generate a prime number with specified number of bits"""
        while True:
            n = random.getrandbits(bits)
            n |= ((1 << (bits - 1)) | 1)   # Ensure highest bit and odd
            if self.is_prime(n):
                return n

    @staticmethod
    def gcd(a, b):
        """Calculate Greatest Common Divisor"""
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def extended_gcd(a, b):
        """Extended Euclidean Algorithm"""
        if a == 0:
            return (b, 0, 1)
        gcd, x1, y1 = RSA.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return (gcd, x, y)

    def mod_inverse(self, e, phi):
        """Calculate modular multiplicative inverse"""
        gcd, x, _ = RSA.extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return x % phi

    def generate_keypair(self):
        """Generate RSA public and private key pair"""
        print(f"Generating {self.key_size}-bit RSA keys...")
        p = self.generate_prime(self.key_size // 2)
        q = self.generate_prime(self.key_size // 2)
        while p == q:
            q = self.generate_prime(self.key_size // 2)

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537  # Common public exponent
        if self.gcd(e, phi) != 1:
            e = 3
        d = self.mod_inverse(e, phi)

        return {
            'public': (e, n),
            'private': (d, n),
            'p': p,
            'q': q,
            'phi': phi
        }

    @staticmethod
    def encrypt(message, public_key):
        """Encrypt message using public key"""
        e, n = public_key
        message_int = int.from_bytes(message.encode('utf-8'), 'big')
        if message_int >= n:
            raise ValueError("Message too long for key size")
        cipher_int = pow(message_int, e, n)
        return cipher_int

    @staticmethod
    def decrypt(cipher_int, private_key):
        """Decrypt ciphertext using private key"""
        d, n = private_key
        message_int = pow(cipher_int, d, n)
        byte_length = (message_int.bit_length() + 7) // 8
        message_bytes = message_int.to_bytes(byte_length, 'big')
        return message_bytes.decode('utf-8')


class User:
    """Represents a user with RSA keys"""

    def __init__(self, name, key_size=64):
        self.name = name
        self.rsa = RSA(key_size)
        self.keys = None

    def generate_keys(self):
        print(f"\n{self.name} is generating RSA keys...")
        print("=" * 60)
        self.keys = self.rsa.generate_keypair()
        e, n = self.keys['public']
        d, _ = self.keys['private']
        print(f"Prime p = {self.keys['p']}")
        print(f"Prime q = {self.keys['q']}")
        print(f"{self.name}'s PUBLIC KEY (e, n): ({e}, {n})")
        print(f"{self.name}'s PRIVATE KEY (d, n): ({d}, {n})")
        print("=" * 60)

    def get_public_key(self):
        return self.keys['public']

    def encrypt_message(self, message, recipient_public_key):
        print(f"\n{self.name} encrypting message...")
        print(f"Original message: '{message}'")
        cipher_int = RSA.encrypt(message, recipient_public_key)
        print(f"Encrypted (as integer): {cipher_int}")
        return cipher_int

    def decrypt_message(self, cipher_int):
        print(f"\n{self.name} decrypting message...")
        plaintext = RSA.decrypt(cipher_int, self.keys['private'])
        print(f"Decrypted: '{plaintext}'")
        return plaintext


def demonstrate_rsa_communication():
    alice = User("Alice", key_size=64)
    bob = User("Bob", key_size=64)
    alice.generate_keys()
    bob.generate_keys()

    cipher = alice.encrypt_message("Hi Bob!", bob.get_public_key())
    bob.decrypt_message(cipher)

    cipher2 = bob.encrypt_message("Got it!", alice.get_public_key())
    alice.decrypt_message(cipher2)


if __name__ == "__main__":
    demonstrate_rsa_communication()
