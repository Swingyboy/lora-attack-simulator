from __future__ import annotations

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()


def aes_decrypt_block(key: bytes, block: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(block) + decryptor.finalize()


def aes_cmac_4(key: bytes, payload: bytes) -> bytes:
    signer = cmac.CMAC(algorithms.AES(key))
    signer.update(payload)
    return signer.finalize()[:4]


def lorawan_payload_cipher(
    key: bytes,
    dev_addr_le: bytes,
    fcnt_up: int,
    direction: int,
    payload: bytes,
) -> bytes:
    out = bytearray()
    blocks = (len(payload) + 15) // 16
    for i in range(1, blocks + 1):
        a = bytearray(16)
        a[0] = 0x01
        a[5] = direction & 0x01
        a[6:10] = dev_addr_le
        a[10:14] = fcnt_up.to_bytes(4, "little")
        a[15] = i
        s = aes_encrypt_block(key, bytes(a))
        chunk = payload[(i - 1) * 16 : i * 16]
        out.extend(bytes(x ^ y for x, y in zip(chunk, s)))
    return bytes(out)


def data_mic(
    nwk_s_key: bytes,
    dev_addr_le: bytes,
    fcnt_up: int,
    direction: int,
    msg: bytes,
) -> bytes:
    b0 = bytearray(16)
    b0[0] = 0x49
    b0[5] = direction & 0x01
    b0[6:10] = dev_addr_le
    b0[10:14] = fcnt_up.to_bytes(4, "little")
    b0[15] = len(msg)
    return aes_cmac_4(nwk_s_key, bytes(b0) + msg)


def derive_session_key(
    app_key: bytes,
    key_type: int,
    app_nonce: bytes,
    net_id: bytes,
    dev_nonce: bytes,
) -> bytes:
    material = bytes([key_type]) + app_nonce + net_id + dev_nonce + bytes(7)
    return aes_encrypt_block(app_key, material)
