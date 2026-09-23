def strxor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def lfsr_step(state, taps, n):
    out_bit = state & 1
    xor_res = 0
    for t in taps:
        xor_res ^= (state >> t) & 1
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

def find_taps_via_gaussian_elimination(keystream_bytes, n=32):
    # extract 64 bits from the 8 bytes of keystream 
    bits = []
    for byte in keystream_bytes[:8]:
        for i in range(8):
            bits.append((byte >> i) & 1)
            
    # augmented matrix (32x33) for the system of linear equations
    matrix = []
    for t in range(n):
        # coefficients c_i corresponding to bits k_t to k_{t+31}
        row = [bits[t + i] for i in range(n)]
        # equation result is the generated bit at k_{t+32}
        row.append(bits[t + n])
        matrix.append(row)
        
    # Gaussian Elimination 
    for i in range(n):
        # find pivot
        pivot = i
        while pivot < n and matrix[pivot][i] == 0:
            pivot += 1
            
        if pivot == n:
            raise ValueError("Matrix is not full rank; cannot solve for taps uniquely.")
            
        # swap rows
        matrix[i], matrix[pivot] = matrix[pivot], matrix[i]
        
        # eliminate other rows 
        for j in range(n):
            if i != j and matrix[j][i] == 1:
                for k in range(n + 1):
                    matrix[j][k] ^= matrix[i][k]
                    
    # extract the tap positions from the solved matrix
    recovered_taps = []
    for i in range(n):
        if matrix[i][n] == 1:
            recovered_taps.append(i)
            
    return recovered_taps

def main():
    
    ciphertext_hex = (
        "3d5cae3331120fe78d2359b8998d846d5230dc78741f3880d0e36e3fb4659796"
        "4a5841c015c4e29f25bbdcb0f946993cd2af3984176325a9688ab8ab6d07dfda"
        "f2f680eee88923ccc31738ce4c3c9962a5b92873b3064e64a69054def9c71331"
    )
    ciphertext = bytes.fromhex(ciphertext_hex)
    
    known_plaintext = b"From: ex"
    keystream_first_8 = strxor(ciphertext[:8], known_plaintext)
    
    seed = int.from_bytes(keystream_first_8[:4], byteorder='little')
    print(f"Recovered seed: {seed:08x}")
    
    # solve the linear system to find taps 
    recovered_taps = find_taps_via_gaussian_elimination(keystream_first_8, n=32)
    print(f"Recovered taps mathematically: {recovered_taps}\n")
    
    # decrypt the full message using the recovered taps
    full_keystream = generate_keystream(seed, recovered_taps, 32, len(ciphertext))
    full_plaintext = strxor(ciphertext, full_keystream)
    
    print("--- DECRYPTED MESSAGE ---")
    print(full_plaintext.decode('utf-8', errors='replace'))

if __name__ == "__main__":
    main()