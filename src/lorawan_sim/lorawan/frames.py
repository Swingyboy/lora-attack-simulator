from __future__ import annotations

from dataclasses import dataclass

from lorawan_sim.lorawan.crypto_v103 import aes_cmac_4, data_mic, derive_session_key, lorawan_payload_cipher

MHDR_JOIN_REQUEST = 0x00
MHDR_JOIN_ACCEPT = 0x20
MHDR_UNCONFIRMED_DATA_UP = 0x40
MHDR_CONFIRMED_DATA_UP = 0x80


@dataclass(frozen=True)
class JoinAcceptData:
    app_nonce: bytes
    net_id: bytes
    dev_addr_le: bytes


def build_join_request(join_eui: bytes, dev_eui: bytes, dev_nonce: bytes, app_key: bytes) -> bytes:
    payload = join_eui[::-1] + dev_eui[::-1] + dev_nonce
    msg = bytes([MHDR_JOIN_REQUEST]) + payload
    mic = aes_cmac_4(app_key, msg)
    return msg + mic


def decode_join_accept(phy_payload: bytes, app_key: bytes) -> JoinAcceptData:
    if not phy_payload or phy_payload[0] != MHDR_JOIN_ACCEPT:
        raise ValueError("invalid join-accept MHDR")
    encrypted = phy_payload[1:]
    if len(encrypted) % 16 != 0:
        raise ValueError("invalid join-accept size")

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    cipher = Cipher(algorithms.AES(app_key), modes.ECB())
    encryptor = cipher.encryptor()
    plain = encryptor.update(encrypted) + encryptor.finalize()
    if len(plain) < 16:
        raise ValueError("join-accept payload too short")
    app_nonce = plain[0:3]
    net_id = plain[3:6]
    dev_addr_le = plain[6:10]
    mic = plain[-4:]
    signed = bytes([MHDR_JOIN_ACCEPT]) + plain[:-4]
    expected_mic = aes_cmac_4(app_key, signed)
    if mic != expected_mic:
        raise ValueError("join-accept MIC mismatch")
    return JoinAcceptData(app_nonce=app_nonce, net_id=net_id, dev_addr_le=dev_addr_le)


def build_unconfirmed_data_up(
    dev_addr_le: bytes,
    fcnt_up: int,
    f_port: int,
    frm_payload: bytes,
    app_s_key: bytes,
    nwk_s_key: bytes,
    confirmed: bool,
) -> bytes:
    mhdr = MHDR_CONFIRMED_DATA_UP if confirmed else MHDR_UNCONFIRMED_DATA_UP
    fctrl = 0x00
    fcnt_le = (fcnt_up & 0xFFFF).to_bytes(2, "little")
    fhdr = dev_addr_le + bytes([fctrl]) + fcnt_le
    encrypted = lorawan_payload_cipher(app_s_key, dev_addr_le, fcnt_up, direction=0, payload=frm_payload)
    msg = bytes([mhdr]) + fhdr + bytes([f_port]) + encrypted
    mic = data_mic(nwk_s_key, dev_addr_le, fcnt_up, direction=0, msg=msg)
    return msg + mic


def derive_session_keys(app_key: bytes, app_nonce: bytes, net_id: bytes, dev_nonce: bytes) -> tuple[bytes, bytes]:
    nwk_s_key = derive_session_key(app_key, 0x01, app_nonce, net_id, dev_nonce)
    app_s_key = derive_session_key(app_key, 0x02, app_nonce, net_id, dev_nonce)
    return nwk_s_key, app_s_key
