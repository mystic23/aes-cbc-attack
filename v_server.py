from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK = 16

class VulnerableServer:
    """
    Simula un servicio que:
    - encrypt (m) -> IV || C
    - decrypt (data) -> True/False segun padding PKCS#7. Este comportamiento es vulnerable y NO debe usarse en produccion
    """
    def __init__(self):
        self.key = get_random_bytes(BLOCK)

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = get_random_bytes(BLOCK)
        padded = pad(plaintext, BLOCK)
        c = AES.new(self.key, AES.MODE_CBC, iv).encrypt(padded)
        return iv + c  # IV || C

    def decrypt(self, data: bytes) -> bool:
        """
        Devuelve True si el padding del ultimo bloque descifrado es valido;
        False de lo contrario. data debe tener >= 2 bloques y longitud multiplo de 16.
        """
        try:
            if len(data) < 2 * BLOCK or (len(data) % BLOCK != 0):
                return False
            blocks = [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]
            iv, cblocks = blocks[0], blocks[1:]
            pt = AES.new(self.key, AES.MODE_CBC, iv).decrypt(b"".join(cblocks))
            _ = unpad(pt, BLOCK)  # ValueError si padding incorrecto
            return True
        except ValueError:
            return False

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