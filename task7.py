def strxor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def lfsr_step(state, taps, n):
    # bit 0
    out_bit = state & 1
    
    # XOR of the bits at the taps
    xor_res = 0
    for t in taps:
        xor_res ^= (state >> t) & 1
        
    # Shift one place to the right and insert XOR on the left
    next_state = (state >> 1) | (xor_res << (n - 1))
    
    return next_state, out_bit

def generate_keystream(seed, taps, n, num_bytes):
    state = seed
    keystream = bytearray()
    
    for _ in range(num_bytes):
        current_byte = 0
        for bit_idx in range(8):
            state, out_bit = lfsr_step(state, taps, n)
            current_byte |= (out_bit << bit_idx)
        keystream.append(current_byte)
        
    return bytes(keystream)

def main():
    
    ciphertext_hex = (
        "3d5cae3331120fe78d2359b8998d846d5230dc78741f3880d0e36e3fb4659796"
        "4a5841c015c4e29f25bbdcb0f946993cd2af3984176325a9688ab8ab6d07dfda"
        "f2f680eee88923ccc31738ce4c3c9962a5b92873b3064e64a69054def9c71331"
    )
    ciphertext = bytes.fromhex(ciphertext_hex)
    
    # RECOVER SEED FROM KNOWN PLAINTEXT

    # first 8 bytes plaintext
    known_plaintext = b"From: ex"

    # first 8 bytes ciphertext
    c_first_8 = ciphertext[:8]
    
    # XOR the first 8 bytes of ciphertext and plaintext -> keystream
    keystream_first_8 = strxor(c_first_8, known_plaintext)
    
    # pack first 4 bytes into a 32-bit integer 
    seed_bytes = keystream_first_8[:4]
    seed = int.from_bytes(seed_bytes, byteorder='little')
    
    print(f"Recovered seed: {seed:08x}\n")
    
    # DECRYPT THE ENTIRE MESSAGE 

    n = 32
    taps = [0, 10, 30, 31]
    
    # generate a full keystream matching the length of the ciphertext
    full_keystream = generate_keystream(seed, taps, n, len(ciphertext))
    
    # XOR ciphertext with the generated keystream -> decrypt the full message 
    full_plaintext = strxor(ciphertext, full_keystream)
    
    print("--- DECRYPTED MESSAGE ---")
    print(full_plaintext.decode('utf-8', errors='replace'))

if __name__ == "__main__":
    main()