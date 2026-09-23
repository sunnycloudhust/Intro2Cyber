from nacl.secret import SecretBox
from nacl.utils import random as random_bytes

M1 = b"Send the final report to the dean before Friday noon."
M2 = b"The exam for the course starts at eight in room D9."


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def G(key: bytes, nonce: bytes, n: int) -> bytes:
    result = SecretBox(key).encrypt(bytes(n), nonce).ciphertext
    return result[SecretBox.MACBYTES:]


def encrypt(key: bytes, message: bytes, nonce=None) -> bytes:
    nonce = nonce or random_bytes(SecretBox.NONCE_SIZE)
    return nonce + xor_bytes(message, G(key, nonce, len(message)))


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    nonce = ciphertext[:SecretBox.NONCE_SIZE]
    body = ciphertext[SecretBox.NONCE_SIZE:]
    return xor_bytes(body, G(key, nonce, len(body)))


def main():
    key = random_bytes(SecretBox.KEY_SIZE)
    nonce = random_bytes(SecretBox.NONCE_SIZE)
    print("Key:", key.hex())
    print("Nonce:", nonce.hex())
    print("G(k, nonce, 64):", G(key, nonce, 64).hex())

    c1 = encrypt(key, M1)
    c2 = encrypt(key, M1)
    print("M1 ciphertext 1:", c1.hex())
    print("M1 ciphertext 2:", c2.hex())
    print("Ciphertexts differ:", c1 != c2)
    print("Decrypted M1:", decrypt(key, c1).decode())

    c1 = encrypt(key, M1, nonce)
    c2 = encrypt(key, M2, nonce)
    body1 = c1[SecretBox.NONCE_SIZE:]
    body2 = c2[SecretBox.NONCE_SIZE:]
    print("Same-nonce M1 ciphertext:", c1.hex())
    print("Same-nonce M2 ciphertext:", c2.hex())
    print("c1 XOR c2 == M1 XOR M2:", xor_bytes(body1, body2) == xor_bytes(M1, M2))


if __name__ == "__main__":
    main()
