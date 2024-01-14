# AES pamata konstantes un tabulas
Nb = 4
Nk = 4
Nr = 10

# AES S-box
s_box = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82,
         0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
         0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96,
         0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
         0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
         0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
         0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
         0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
         0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
         0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
         0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
         0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
         0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
         0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
         0xb0, 0x54, 0xbb, 0x16]

# AES inversā S-box
inv_s_box = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3,
             0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
             0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9,
             0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
             0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
             0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
             0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13,
             0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
             0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1,
             0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
             0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
             0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
             0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb,
             0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
             0x55, 0x21, 0x0c, 0x7d]

# Rijndael key schedule rcon
rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]


def sub_bytes(state, inv=False):
    """Byte substitūcija, izmantojot S-box."""
    if inv:
        box = inv_s_box
    else:
        box = s_box
    for i in range(4):
        for j in range(Nb):
            state[i][j] = box[state[i][j]]


def shift_rows(state, inv=False):
    """Rindu nobīde."""
    count = 1 if not inv else 3
    for i in range(1, 4):
        state[i] = state[i][count:] + state[i][:count]
        count = (count + 1) % 4 if not inv else (count - 1) % 4


def mix_columns(state, inv=False):
    """Kolonnu maisīšana."""
    if not inv:  # MixColumns
        for i in range(4):
            a = state[0][i]
            b = state[1][i]
            c = state[2][i]
            d = state[3][i]

            state[0][i] = galois_mult(a, 2) ^ galois_mult(b, 3) ^ c ^ d
            state[1][i] = a ^ galois_mult(b, 2) ^ galois_mult(c, 3) ^ d
            state[2][i] = a ^ b ^ galois_mult(c, 2) ^ galois_mult(d, 3)
            state[3][i] = galois_mult(a, 3) ^ b ^ c ^ galois_mult(d, 2)
    else:  # Inverse MixColumns
        for i in range(4):
            a = state[0][i]
            b = state[1][i]
            c = state[2][i]
            d = state[3][i]

            state[0][i] = galois_mult(a, 14) ^ galois_mult(b, 11) ^ galois_mult(c, 13) ^ galois_mult(d, 9)
            state[1][i] =galois_mult(a, 9) ^ galois_mult(b, 14) ^ galois_mult(c, 11) ^ galois_mult(d, 13)
            state[2][i] = galois_mult(a, 13) ^ galois_mult(b, 9) ^ galois_mult(c, 14) ^ galois_mult(d, 11)
            state[3][i] = galois_mult(a, 11) ^ galois_mult(b, 13) ^ galois_mult(c, 9) ^ galois_mult(d, 14)


def add_round_key(state, w, round=0):
    """Pievieno raunda atslēgu."""
    for c in range(4):
        for r in range(4):
            # Calculate the correct index for w
            index = round * Nb * 4 + c * 4 + r
            state[r][c] ^= w[index]


def key_expansion(key):
    """Key expansion for AES algorithm."""
    key_schedule = [0] * (Nb * (Nr + 1) * 4)

    # Copying the initial key
    for i in range(Nk * 4):  # 4 bytes for each key word
        key_schedule[i] = key[i]

    # Key expansion
    for i in range(Nk, Nb * (Nr + 1)):
        temp = key_schedule[(i - 1) * 4:i * 4]  # temp is now a 32-bit word (4 bytes)

        if i % Nk == 0:
            # RotWord and SubWord operations
            temp = sub_word(rot_word(temp))  # Ensure these functions handle 4-byte words
            # XOR with round constant
            temp[0] = temp[0] ^ rcon[i // Nk]

        # XOR with the word Nk positions before
        for j in range(4):
            key_schedule[i * 4 + j] = key_schedule[(i - Nk) * 4 + j] ^ temp[j]

    return key_schedule


def sub_word(word):
    """Vārda aizstāšana, izmantojot S-box."""
    return [s_box[b] for b in word]


def rot_word(word):
    """Vārda rotācija pa vienu pozīciju pa kreisi."""
    return word[1:] + word[:1]


def aes_encrypt(input_bytes, key):
    """AES šifrēšana."""
    state = [list(input_bytes[i:i + 4]) for i in range(0, len(input_bytes), 4)]
    key_schedule = key_expansion(key)

    add_round_key(state, key_schedule[:Nb * 4])

    for round in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule[round * Nb * 4:(round + 1) * Nb * 4])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule[Nr * Nb * 4:])

    return [byte for row in state for byte in row]


def aes_decrypt(input_bytes, key):
    """AES atšifrēšana."""
    state = [list(input_bytes[i:i + 4]) for i in range(0, len(input_bytes), 4)]
    key_schedule = key_expansion(key)

    add_round_key(state, key_schedule[Nr * Nb:])

    for round in range(Nr - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, key_schedule[round * Nb:(round + 1) * Nb])
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, key_schedule[:Nb])

    return [byte for row in state for byte in row]


def inv_shift_rows(state):
    """Inversā rindu nobīde."""
    for i in range(1, 4):
        state[i] = state[i][-i:] + state[i][:-i]


def inv_sub_bytes(state):
    """Inversā byte substitūcija, izmantojot inverso S-box."""
    for i in range(4):
        for j in range(Nb):
            state[i][j] = inv_s_box[state[i][j]]


def galois_mult(a, b):
    """Reālizē Galois reizināšanu."""
    p = 0
    for counter in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x11b  # x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p % 256


def inv_mix_columns(state):
    """Inversā kolonnu maisīšana AES atšifrēšanai."""
    for i in range(4):
        a = state[0][i]
        b = state[1][i]
        c = state[2][i]
        d = state[3][i]

        state[0][i] = galois_mult(a, 0x0e) ^ galois_mult(b, 0x0b) ^ galois_mult(c, 0x0d) ^ galois_mult(d, 0x09)
        state[1][i] = galois_mult(a, 0x09) ^ galois_mult(b, 0x0e) ^ galois_mult(c, 0x0b) ^ galois_mult(d, 0x0d)
        state[2][i] = galois_mult(a, 0x0d) ^ galois_mult(b, 0x09) ^ galois_mult(c, 0x0e) ^ galois_mult(d, 0x0b)
        state[3][i] = galois_mult(a, 0x0b) ^ galois_mult(b, 0x0d) ^ galois_mult(c, 0x09) ^ galois_mult(d, 0x0e)

def xor_bytes(a, b):
    """Veic XOR operāciju starp divām baitu virknēm."""
    return bytes(i ^ j for i, j in zip(a, b))


def ofb_encrypt(plaintext, key, iv):
    """OFB šifrēšanas režīms izmantojot AES."""
    assert len(iv) == 16

    encrypted = b''
    next_iv = iv

    for i in range(0, len(plaintext), 16):
        next_iv = aes_encrypt(next_iv, key)
        block = plaintext[i:i + 16]
        block = block + b'\x00' * (16 - len(block))  # Pievieno nulles, ja bloks ir par īsu
        encrypted += xor_bytes(block, next_iv)

    return encrypted


def get_hex_input(prompt, length):
    """Iegūst hex ievadi no lietotāja."""
    while True:
        hex_input = input(prompt)
        if len(hex_input) == length:
            return hex_input
        else:
            print(f"Ievadiet pareizu {length} zīmju garumu.")


def main():
    action = input("Ievadiet darbību (encrypt vai decrypt): ").lower()
    if action not in ['encrypt', 'decrypt']:
        raise ValueError("Nepareiza darbība. Ievadiet 'encrypt' vai 'decrypt'.")

    # Ievadīt faila ceļu
    file_path = input("Ievadiet faila ceļu: ")

    # Ievadīt šifrēšanas atslēgu
    key_hex = input("Ievadiet 32 zīmju garu heksadecimālo atslēgu: ")
    key = bytes.fromhex(key_hex)

    # Ievadīt inicializācijas vektoru
    iv_hex = input("Ievadiet 32 zīmju garu heksadecimālo inicializācijas vektoru (IV): ")
    iv = bytes.fromhex(iv_hex)

    # Determine the action
    if action == 'encrypt':
        with open(file_path, 'rb') as file:
            plaintext = file.read()
            encrypted = ofb_encrypt(plaintext, key, iv)

            # Save the encrypted file
            encrypted_file_path = f"{file_path}_encrypted.bin"
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted)
            print(f"Encrypted file saved as {encrypted_file_path}")

    elif action == 'decrypt':
        with open(file_path, 'rb') as file:
            encrypted = file.read()
            decrypted = ofb_encrypt(encrypted, key, iv)  # OFB is symmetric

            # Save the decrypted file
            decrypted_file_path = f"{file_path}_decrypted.docx"
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted)
            print(f"Decrypted file saved as {decrypted_file_path}")


if __name__ == "__main__":
    main()
