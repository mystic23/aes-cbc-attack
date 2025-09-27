from Crypto.Util.Padding import unpad
from v_server import VulnerableServer



BLOCK = 16

def recover_block(oracle, C_prev, C_curr):
    BLOCK = 16
    I = [0] * BLOCK
    M = [0] * BLOCK

    def try_padding(p, t, I, M):
        c_prev_mod = bytearray(C_prev)

        for j in range(t + 1, BLOCK):
            c_prev_mod[j] = I[j] ^ p

        valid_candidates = []
        for g in range(256):
            c_prev_mod[t] = g
            payload = bytes(c_prev_mod) + C_curr
            if oracle(payload):
                valid_candidates.append(g)

        if len(valid_candidates) == 0:
            return False

        for g in valid_candidates:
            I_copy = I[:]
            M_copy = M[:]
            I_copy[t] = g ^ p
            M_copy[t] = I_copy[t] ^ C_prev[t]

            if p == BLOCK or try_padding(p + 1, t - 1, I_copy, M_copy):
                I[:] = I_copy
                M[:] = M_copy
                return True

        return False

    if not try_padding(1, BLOCK - 1, I, M):
        raise Exception("Fallo la recuperación de bloque")

    return bytes(M)


def recover_message(oracle, ct):
    blocks = [ct[i:i + BLOCK] for i in range(0, len(ct), BLOCK)]
    plaintext = b""

    for i in range(1, len(blocks)):
        C_prev = blocks[i - 1]
        C_curr = blocks[i]
        M = recover_block(oracle, C_prev, C_curr)
        plaintext += M
        print(f"Block {i}:", M)


    try:
        return unpad(plaintext, BLOCK)
    except ValueError:
        return plaintext

if __name__ == "__main__":
    server = VulnerableServer()

    original_message = b"Amo el Helado de vainilla"

    ciphertext = server.encrypt(original_message)

    oracle = lambda data: server.decrypt(data)

    global_counter = 0
    def oracle_counting(data):
        global global_counter
        global_counter += 1
        return server.decrypt(data)

    # Recuperación
    recovered = recover_message(oracle_counting, ciphertext)

    # Resultados
    print("Mensaje original:", original_message)
    print("Mensaje recuperado:", recovered)
    print("Total de consultas al oracle:", global_counter)
    print("Len original:", len(original_message))
    print("Len recuperado:", len(recovered))
    
    ciphertext = server.encrypt(original_message)
    print("Ciphertext (hex):", ciphertext.hex())
