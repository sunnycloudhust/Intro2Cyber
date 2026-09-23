from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from nacl.utils import random as random_bytes

from task3 import decrypt, encrypt, xor_bytes

ORIGINAL = b"PAY BOB 0100 USD"
TARGET = b"PAY BOB 9900 USD"


def forge(ciphertext: bytes, offset: int) -> bytes:
    delta = xor_bytes(ORIGINAL, TARGET)
    return ciphertext[:offset] + xor_bytes(ciphertext[offset:], delta)


def main():
    key = random_bytes(SecretBox.KEY_SIZE)
    ciphertext = encrypt(key, ORIGINAL)
    forged = forge(ciphertext, SecretBox.NONCE_SIZE)
    print("Key:", key.hex())
    print("Task 3 ciphertext:", ciphertext.hex())
    print("Task 3 forged ciphertext:", forged.hex())
    print("Task 3 forged plaintext:", decrypt(key, forged).decode())

    box = SecretBox(key)
    authenticated = bytes(box.encrypt(ORIGINAL))
    offset = SecretBox.NONCE_SIZE + SecretBox.MACBYTES
    forged_authenticated = forge(authenticated, offset)
    print("SecretBox ciphertext:", authenticated.hex())
    print("SecretBox forged ciphertext:", forged_authenticated.hex())
    try:
        print("SecretBox forged plaintext:", box.decrypt(forged_authenticated).decode())
    except CryptoError as error:
        print("SecretBox decrypt result:", type(error).__name__, "-", error)


if __name__ == "__main__":
    main()
