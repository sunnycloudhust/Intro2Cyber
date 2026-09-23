import os

M1 = "Send the final report to the dean before Friday noon."
M2 = "The exam for the course starts at eight in room D9."
M3 = "Lunch will be served in the main hall at half past twelve."
MSGS = [M1, M2, M3]

def random(size=16):
    return os.urandom(size)

def strxor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def encrypt_original(key, msg):
    if isinstance(msg, str):
        msg_bytes = msg.encode('utf-8')
    else:
        msg_bytes = msg
        
    c = strxor(key, msg_bytes)
    return c

# new encrypt that refuses a message longer than the key
def encrypt(key, msg):
    if isinstance(msg, str):
        msg_bytes = msg.encode('utf-8')
    else:
        msg_bytes = msg
        
    if len(msg_bytes) > len(key):
        raise ValueError(f"Error: message ({len(msg_bytes)} bytes) longer than key ({len(key)} bytes)!")
        
    c = strxor(key, msg_bytes)
    return c

def decrypt(key, c):
    m_bytes = strxor(key, c)
    return m_bytes.decode('utf-8')

def main():
    key = random(1024)

    ciphertexts = []
    for i, msg in enumerate(MSGS):
        print(f"--- Encrypting M{i+1} ---")
        c = encrypt(key, msg)
        print(f"Ciphertext (hex): {c.hex()}")
        ciphertexts.append(c)
    print()
    
    print("--- Decrypting ---")
    for i, c in enumerate(ciphertexts):
        plaintext = decrypt(key, c)
        print(f"Decrypted M{i+1}: {plaintext}")
    print()

    with open("ciphertexts.txt", "w") as f:
        for c in ciphertexts:
            f.write(c.hex() + "\n")
    print("Save in file 'ciphertexts.txt'.\n")
    
    msg_1500 = b'A' * 1500 
    
   # Testing encrypt_original
    print("1. Testing encrypt_original:")
    c_1500_old = encrypt_original(key, msg_1500)
    print(f"Received ciphertext length: {len(c_1500_old)} bytes")

    decrypted_1500_old = decrypt(key, c_1500_old)
    print(f"Decrypted message length: {len(decrypted_1500_old)} bytes")
    lost_bytes = len(msg_1500) - len(decrypted_1500_old)
    print(f"{lost_bytes} bytes at the end of the message were lost\n")
    
    # Testing modified encrypt 
    print("2. Testing modified encrypt function:")
    try:
        encrypt(key, msg_1500)
    except ValueError as e:
        print(f"{e}")

if __name__ == "__main__":
    main()