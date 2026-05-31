from __future__ import annotations

import secrets
from dataclasses import dataclass

from lorawan_sim.lorawan.frames import (
    build_join_request,
    build_unconfirmed_data_up,
    decode_join_accept,
    derive_session_keys,
)


@dataclass
class DeviceRuntime:
    joined: bool = False
    dev_nonce: bytes = b""
    dev_addr_le: bytes = b""
    nwk_s_key: bytes = b""
    app_s_key: bytes = b""
    fcnt_up: int = 0

    @property
    def dev_addr_hex(self) -> str:
        return self.dev_addr_le[::-1].hex() if self.dev_addr_le else ""


class SimulatedDevice:
    def __init__(self, dev_eui: str, join_eui: str, app_key: str) -> None:
        self._dev_eui = bytes.fromhex(dev_eui)
        self._join_eui = bytes.fromhex(join_eui)
        self._app_key = bytes.fromhex(app_key)
        self.runtime = DeviceRuntime()

    def build_join_request(self) -> bytes:
        self.runtime.dev_nonce = secrets.token_bytes(2)
        return build_join_request(
            join_eui=self._join_eui,
            dev_eui=self._dev_eui,
            dev_nonce=self.runtime.dev_nonce,
            app_key=self._app_key,
        )

    def apply_join_accept(self, phy_payload: bytes) -> None:
        if not self.runtime.dev_nonce:
            raise RuntimeError("join request must be sent before join accept")
        parsed = decode_join_accept(phy_payload, self._app_key)
        nwk_s_key, app_s_key = derive_session_keys(
            app_key=self._app_key,
            app_nonce=parsed.app_nonce,
            net_id=parsed.net_id,
            dev_nonce=self.runtime.dev_nonce,
        )
        self.runtime.dev_addr_le = parsed.dev_addr_le
        self.runtime.nwk_s_key = nwk_s_key
        self.runtime.app_s_key = app_s_key
        self.runtime.joined = True
        self.runtime.fcnt_up = 0

    def build_data_uplink(self, payload: bytes, f_port: int, confirmed: bool) -> bytes:
        if not self.runtime.joined:
            raise RuntimeError("device is not joined")
        frame = build_unconfirmed_data_up(
            dev_addr_le=self.runtime.dev_addr_le,
            fcnt_up=self.runtime.fcnt_up,
            f_port=f_port,
            frm_payload=payload,
            app_s_key=self.runtime.app_s_key,
            nwk_s_key=self.runtime.nwk_s_key,
            confirmed=confirmed,
        )
        self.runtime.fcnt_up += 1
        return frame
