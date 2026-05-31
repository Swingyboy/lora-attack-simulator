from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

PROTOCOL_VERSION = 2

PUSH_DATA = 0x00
PUSH_ACK = 0x01
PULL_DATA = 0x02
PULL_RESP = 0x03
PULL_ACK = 0x04
TX_ACK = 0x05


@dataclass(frozen=True)
class SemtechPacket:
    packet_type: int
    token: bytes
    gateway_eui: bytes | None
    json_body: dict | None


def _new_token() -> bytes:
    return secrets.token_bytes(2)


def encode_pull_data(gateway_eui_hex: str) -> bytes:
    gateway_eui = bytes.fromhex(gateway_eui_hex)
    token = _new_token()
    return bytes([PROTOCOL_VERSION]) + token + bytes([PULL_DATA]) + gateway_eui


def encode_push_data(gateway_eui_hex: str, body: dict) -> bytes:
    gateway_eui = bytes.fromhex(gateway_eui_hex)
    token = _new_token()
    return bytes([PROTOCOL_VERSION]) + token + bytes([PUSH_DATA]) + gateway_eui + json.dumps(body).encode("utf-8")


def encode_tx_ack(token: bytes, gateway_eui_hex: str) -> bytes:
    gateway_eui = bytes.fromhex(gateway_eui_hex)
    return bytes([PROTOCOL_VERSION]) + token + bytes([TX_ACK]) + gateway_eui + b"{}"


def decode_packet(packet: bytes) -> SemtechPacket:
    if len(packet) < 4:
        raise ValueError("Semtech packet too short")
    if packet[0] != PROTOCOL_VERSION:
        raise ValueError("Semtech protocol version mismatch")

    token = packet[1:3]
    packet_type = packet[3]
    gateway_eui = packet[4:12] if len(packet) >= 12 and packet_type in (PUSH_DATA, PULL_DATA, TX_ACK) else None
    payload = packet[12:] if gateway_eui is not None else packet[4:]
    json_body = json.loads(payload.decode("utf-8")) if payload else None
    return SemtechPacket(packet_type=packet_type, token=token, gateway_eui=gateway_eui, json_body=json_body)
