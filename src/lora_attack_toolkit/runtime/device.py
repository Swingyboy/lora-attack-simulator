from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from logging import Logger
from typing import TYPE_CHECKING, Any

from lora_attack_toolkit.config import DeviceConfig
from lora_attack_toolkit.lorawan.frames import (
    build_join_request,
    build_unconfirmed_data_up,
    decode_join_accept,
    derive_session_keys,
)
from lora_attack_toolkit.lorawan.mac_commands import (
    CID_DEV_STATUS_ANS,
    CID_DEV_STATUS_REQ,
    CID_DEVICE_TIME_ANS,
    CID_DUTY_CYCLE_ANS,
    CID_DUTY_CYCLE_REQ,
    CID_LINK_ADR_ANS,
    CID_LINK_ADR_REQ,
    CID_NEW_CHANNEL_ANS,
    CID_NEW_CHANNEL_REQ,
    CID_RX_PARAM_SETUP_ANS,
    CID_RX_PARAM_SETUP_REQ,
    CID_RX_TIMING_SETUP_ANS,
    CID_RX_TIMING_SETUP_REQ,
    MACCommand,
)
from lora_attack_toolkit.lorawan.radio import EU868RegionProfile, Radio, RegionProfile

if TYPE_CHECKING:
    from lora_attack_toolkit.config import RadioMetadata


@dataclass
class DeviceRadioState:
    """Device radio parameters and ADR state.

    Tracks current radio configuration that can be modified by
    Network Server via MAC commands (LinkADRReq, etc.).
    """

    data_rate: int = 5  # DR5 = SF7/BW125 in EU868 (LoRaWAN 1.0.3 Regional Parameters §2.2.3)
    tx_power: int = 14  # EU868 maximum TX power in dBm (index 0 in the regional power table)
    ch_mask: int = 0x00FF  # Enabled channels (16-bit mask)
    nb_trans: int = 1  # Number of transmissions per uplink
    rx1_dr_offset: int = 0  # RX1 data rate offset
    rx2_data_rate: int = 0  # RX2 data rate
    rx1_delay: int = 1  # RX1 delay in seconds
    duty_cycle: int = 0  # Duty cycle limitation (0 = no limit)

    def to_dict(self) -> dict[str, Any]:
        """Convert radio state to dict for logging."""
        return {
            "data_rate": self.data_rate,
            "tx_power": self.tx_power,
            "ch_mask": f"0x{self.ch_mask:04x}",
            "nb_trans": self.nb_trans,
            "rx1_dr_offset": self.rx1_dr_offset,
            "rx2_data_rate": self.rx2_data_rate,
            "rx1_delay": self.rx1_delay,
            "duty_cycle": self.duty_cycle,
        }


@dataclass
class DeviceRuntime:
    joined: bool = False
    dev_nonce: bytes = b""
    dev_addr_le: bytes = b""
    nwk_s_key: bytes = b""
    app_s_key: bytes = b""
    fcnt_up: int = 0
    fcnt_down: int = 0
    adr: DeviceRadioState = field(default_factory=DeviceRadioState)
    radio: "Radio | None" = None  # Owns channel selection, CFList, duty-cycle, DR/power
    join_attempt_index: int = 0
    uplink_index: int = 0

    @property
    def dev_addr_hex(self) -> str:
        return self.dev_addr_le[::-1].hex() if self.dev_addr_le else ""


class SimulatedDevice:
    def __init__(
        self,
        dev_eui: str,
        join_eui: str,
        app_key: str,
        logger: Logger | None = None,
    ) -> None:
        self._dev_eui = bytes.fromhex(dev_eui)
        self._join_eui = bytes.fromhex(join_eui)
        self._app_key = bytes.fromhex(app_key)
        self._logger = logger
        self.runtime = DeviceRuntime()

    def new_dev_nonce(self) -> bytes:
        """Generate a fresh DevNonce, store it in runtime state, and return it."""
        self.runtime.dev_nonce = secrets.token_bytes(2)
        return self.runtime.dev_nonce

    def build_join_request(self, dev_nonce: bytes | None = None) -> bytes:
        """Build a JoinRequest frame.

        Args:
            dev_nonce: DevNonce to use.  When ``None`` (the default) the
                stored ``runtime.dev_nonce`` is used.  Pass an explicit value
                only when replaying a specific nonce (e.g. in devnonce attacks).
                Call :meth:`new_dev_nonce` first to generate and store a fresh
                nonce before calling this method without an argument.
        """
        nonce = dev_nonce if dev_nonce is not None else self.runtime.dev_nonce
        return build_join_request(
            join_eui=self._join_eui,
            dev_eui=self._dev_eui,
            dev_nonce=nonce,
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
        self.runtime.fcnt_down = 0

        # Apply CFList channel updates via Radio
        if parsed.cflist is not None and self.runtime.radio is not None:
            self.runtime.radio.apply_cflist(parsed.cflist)
            if self._logger:
                self._logger.info(
                    "Applied CFList; active uplink channels: %s",
                    self.runtime.radio.get_active_uplink_channels(),
                )

    def build_data_uplink(
        self, payload: bytes, f_port: int, confirmed: bool, f_opts: bytes = b""
    ) -> bytes:
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
            f_opts=f_opts,
        )
        self.runtime.fcnt_up += 1
        return frame

    def select_uplink_radio(
        self,
        uplink_index: int,
        fallback: "RadioMetadata",
    ) -> "RadioMetadata":
        """Return :class:`~lora_attack_toolkit.config.RadioMetadata` for an uplink.

        Delegates channel selection to the device's :class:`Radio` when one is
        configured (EU868 or other region-aware scenario), so CFList channels
        are used in round-robin.  Falls back to *fallback* for fixed-frequency
        scenarios (no Radio configured, legacy configs, or unit-test mocks).

        RSSI and SNR are always taken from *fallback* (gateway-side values).

        Args:
            uplink_index: Zero-based uplink counter used for round-robin channel
                selection.  Typically ``device.runtime.fcnt_up`` before the
                uplink is sent, or any monotonically increasing integer.
            fallback: Gateway-side :class:`RadioMetadata` used when the device
                has no radio or as the source of RSSI/SNR.

        Returns:
            :class:`RadioMetadata` with the selected frequency and data-rate.
        """
        if self.runtime.radio is None:
            return fallback
        tx = self.runtime.radio.select_uplink_channel(uplink_index)
        from lora_attack_toolkit.config import RadioMetadata

        return RadioMetadata(
            frequency=tx.frequency_hz,
            data_rate=tx.data_rate,
            rssi=fallback.rssi,
            snr=fallback.snr,
        )

    def validate_downlink(self, phy_payload: bytes) -> dict[str, Any]:
        """Validate a received downlink frame without mutating device state.

        Checks, in order:
        1. Minimum frame length.
        2. Supported MType (must be a downlink: 0b011 = UnconfirmedDataDown, 0b101 = ConfirmedDataDown).
        3. DevAddr matches the session's DevAddr.
        4. MIC is valid.
        5. FCntDown is not stale (frame counter is ≥ the expected next downlink counter).

        Args:
            phy_payload: Raw PHYPayload bytes.

        Returns:
            Dict with validation results::

                {
                    "valid": bool,              # True only when ALL checks pass
                    "reject_reason": str | None, # First failure reason or None
                    "mtype": int,
                    "dev_addr_match": bool,
                    "valid_mic": bool,
                    "fcnt_ok": bool,
                    "fcnt": int,                # 16-bit FCntDown from frame
                }
        """
        result: dict[str, Any] = {
            "valid": False,
            "reject_reason": None,
            "mtype": -1,
            "dev_addr_match": False,
            "valid_mic": False,
            "fcnt_ok": False,
            "fcnt": -1,
        }

        if len(phy_payload) < 12:
            result["reject_reason"] = f"frame_too_short:{len(phy_payload)}"
            return result

        mhdr = phy_payload[0]
        mtype = (mhdr >> 5) & 0x07
        result["mtype"] = mtype

        # Supported downlink MTypes: 3 = UnconfirmedDataDown, 5 = ConfirmedDataDown
        if mtype not in (3, 5):
            result["reject_reason"] = f"unsupported_mtype:{mtype}"
            return result

        # DevAddr check (bytes 1-4 little-endian)
        frame_dev_addr_le = phy_payload[1:5]
        dev_addr_match = frame_dev_addr_le == self.runtime.dev_addr_le
        result["dev_addr_match"] = dev_addr_match
        if not dev_addr_match:
            result["reject_reason"] = "devaddr_mismatch"
            return result

        # FCntDown (16-bit, bytes 6-7)
        fcnt = int.from_bytes(phy_payload[6:8], "little")
        result["fcnt"] = fcnt

        # MIC validation
        from lora_attack_toolkit.lorawan.crypto import data_mic

        mic_start = len(phy_payload) - 4
        expected_mic = data_mic(
            nwk_s_key=self.runtime.nwk_s_key,
            msg=phy_payload[:mic_start],
            direction=1,
            dev_addr_le=self.runtime.dev_addr_le,
            fcnt_up=fcnt,
        )
        valid_mic = expected_mic == phy_payload[mic_start:]
        result["valid_mic"] = valid_mic
        if not valid_mic:
            result["reject_reason"] = "invalid_mic"
            return result

        # FCntDown freshness (must be ≥ expected)
        expected_fcnt_down = self.runtime.fcnt_down
        fcnt_ok = fcnt >= expected_fcnt_down
        result["fcnt_ok"] = fcnt_ok
        if not fcnt_ok:
            result["reject_reason"] = f"stale_fcnt:got={fcnt},expected>={expected_fcnt_down}"
            return result

        result["valid"] = True
        return result

    def parse_downlink(self, phy_payload: bytes) -> dict[str, Any]:
        """
        Parse a downlink frame and extract MAC commands.

        Args:
            phy_payload: Raw PHYPayload bytes

        Returns:
            Dict with parsed downlink information:
            {
                "mtype": int,
                "dev_addr": str,
                "fcnt": int,
                "f_port": int | None,
                "frm_payload": bytes,
                "mac_commands": list[MACCommand],
                "valid_mic": bool,
            }

        Raises:
            ValueError: If frame cannot be parsed or MIC is invalid
        """
        if not self.runtime.joined:
            raise RuntimeError("Device must be joined to parse downlinks")

        if len(phy_payload) < 12:  # Minimum: MHDR(1) + FHDR(7) + MIC(4)
            raise ValueError(f"Downlink too short: {len(phy_payload)} bytes")

        # Parse MHDR
        mhdr = phy_payload[0]
        mtype = (mhdr >> 5) & 0x07

        # Parse FHDR
        dev_addr_le = phy_payload[1:5]
        fctrl = phy_payload[5]
        fcnt_bytes = phy_payload[6:8]
        fcnt = int.from_bytes(fcnt_bytes, byteorder="little")

        # FOpts length
        f_opts_len = fctrl & 0x0F
        f_opts = phy_payload[8 : 8 + f_opts_len]

        # FPort and FRMPayload
        payload_start = 8 + f_opts_len
        mic_start = len(phy_payload) - 4

        f_port = None
        frm_payload = b""
        mac_commands_in_payload = []

        if payload_start < mic_start:
            f_port = phy_payload[payload_start]
            frm_payload = phy_payload[payload_start + 1 : mic_start]

        # Verify MIC
        from lora_attack_toolkit.lorawan.crypto import data_mic

        expected_mic = data_mic(
            nwk_s_key=self.runtime.nwk_s_key,
            msg=phy_payload[:mic_start],
            direction=1,  # Downlink
            dev_addr_le=self.runtime.dev_addr_le,
            fcnt_up=fcnt,
        )

        actual_mic = phy_payload[mic_start:]
        valid_mic = expected_mic == actual_mic

        # Extract MAC commands from FOpts
        mac_commands_in_fopts = self._parse_mac_commands(f_opts)

        # If FPort == 0, FRMPayload contains MAC commands
        if f_port == 0 and frm_payload:
            # Decrypt with NwkSKey
            from lora_attack_toolkit.lorawan.crypto import lorawan_payload_cipher

            decrypted = lorawan_payload_cipher(
                key=self.runtime.nwk_s_key,
                payload=frm_payload,
                direction=1,  # Downlink
                dev_addr_le=self.runtime.dev_addr_le,
                fcnt_up=fcnt,
            )
            mac_commands_in_payload = self._parse_mac_commands(decrypted)

        all_mac_commands = mac_commands_in_fopts + mac_commands_in_payload

        return {
            "mtype": mtype,
            "dev_addr": dev_addr_le[::-1].hex(),
            "fcnt": fcnt,
            "f_port": f_port,
            "frm_payload": frm_payload,
            "mac_commands": all_mac_commands,
            "valid_mic": valid_mic,
        }

    def _parse_mac_commands(self, data: bytes) -> list[MACCommand]:
        """Parse MAC commands from byte stream."""
        commands = []
        offset = 0

        while offset < len(data):
            if offset >= len(data):
                break

            cid = data[offset]
            offset += 1

            # Determine payload length based on CID
            # These lengths are for downlink commands (NS → Device)
            payload_lengths = {
                CID_LINK_ADR_REQ: 4,
                CID_DUTY_CYCLE_REQ: 1,
                CID_RX_PARAM_SETUP_REQ: 4,
                CID_DEV_STATUS_REQ: 0,
                CID_NEW_CHANNEL_REQ: 5,
                CID_RX_TIMING_SETUP_REQ: 1,
                CID_DEVICE_TIME_ANS: 5,  # DeviceTimeAns: 4-byte GPS seconds + 1-byte fractional
            }

            payload_len = payload_lengths.get(cid, 0)

            if offset + payload_len > len(data):
                if self._logger:
                    self._logger.warning(
                        "Truncated MAC command: CID=0x%02x, expected %d bytes, got %d",
                        cid,
                        payload_len,
                        len(data) - offset,
                    )
                break

            payload = data[offset : offset + payload_len]
            offset += payload_len

            commands.append(MACCommand(cid=cid, payload=payload))

        return commands

    def apply_mac_commands(self, commands: list[MACCommand]) -> list[MACCommand]:
        """
        Apply MAC commands from Network Server and generate responses.

        Args:
            commands: List of MAC commands to process

        Returns:
            List of MAC command responses to include in next uplink
        """
        responses = []

        for cmd in commands:
            if cmd.cid == CID_LINK_ADR_REQ:
                response = self._apply_link_adr_req(cmd)
                responses.append(response)

            elif cmd.cid == CID_RX_PARAM_SETUP_REQ:
                response = self._apply_rx_param_setup_req(cmd)
                responses.append(response)

            elif cmd.cid == CID_DEV_STATUS_REQ:
                response = self._apply_dev_status_req(cmd)
                responses.append(response)

            elif cmd.cid == CID_NEW_CHANNEL_REQ:
                response = self._apply_new_channel_req(cmd)
                responses.append(response)

            elif cmd.cid == CID_DUTY_CYCLE_REQ:
                response = self._apply_duty_cycle_req(cmd)
                responses.append(response)

            elif cmd.cid == CID_RX_TIMING_SETUP_REQ:
                response = self._apply_rx_timing_setup_req(cmd)
                responses.append(response)

            elif cmd.cid == CID_DEVICE_TIME_ANS:
                # DeviceTimeAns is the NS's response to our DeviceTimeReq; no reply needed.
                pass

            else:
                if self._logger:
                    self._logger.warning("Unknown MAC command CID: 0x%02x", cmd.cid)

        return responses

    def _apply_link_adr_req(self, cmd: MACCommand) -> MACCommand:
        """Apply LinkADRReq: delegates to Radio for validation, returns LinkADRAns."""
        radio = self.runtime.radio
        if radio is not None:
            status = radio.apply_link_adr_req(cmd.payload)
            if status == 0x07:
                # Mirror accepted state into DeviceRuntime.adr for legacy consumers
                if len(cmd.payload) >= 4:
                    dr_tx = cmd.payload[0]
                    ch_mask = int.from_bytes(cmd.payload[1:3], "little")
                    redundancy = cmd.payload[3]
                    dr_idx = (dr_tx >> 4) & 0x0F
                    tp_idx = dr_tx & 0x0F
                    nb_trans = redundancy & 0x0F
                    if dr_idx != 0x0F:
                        self.runtime.adr.data_rate = dr_idx
                    if tp_idx != 0x0F:
                        self.runtime.adr.tx_power = tp_idx
                    self.runtime.adr.ch_mask = ch_mask
                    if nb_trans > 0:
                        self.runtime.adr.nb_trans = nb_trans
        else:
            # No Radio object — fall back to legacy direct-mutation behaviour
            if len(cmd.payload) < 4:
                return MACCommand(cid=CID_LINK_ADR_ANS, payload=bytes([0x00]))
            dr_tx = cmd.payload[0]
            ch_mask = int.from_bytes(cmd.payload[1:3], "little")
            redundancy = cmd.payload[3]
            self.runtime.adr.data_rate = (dr_tx >> 4) & 0x0F
            self.runtime.adr.tx_power = dr_tx & 0x0F
            self.runtime.adr.ch_mask = ch_mask
            self.runtime.adr.nb_trans = redundancy & 0x0F
            status = 0x07
        if self._logger:
            self._logger.info(
                "LinkADRReq status=0x%02x dr=%d tx_power=%d ch_mask=0x%04x",
                status,
                self.runtime.adr.data_rate,
                self.runtime.adr.tx_power,
                self.runtime.adr.ch_mask,
            )
        return MACCommand(cid=CID_LINK_ADR_ANS, payload=bytes([status]))

    def _apply_rx_param_setup_req(self, cmd: MACCommand) -> MACCommand:
        """Apply RXParamSetupReq: delegates to Radio, returns RXParamSetupAns."""
        radio = self.runtime.radio
        if radio is not None:
            status = radio.apply_rx_param_setup_req(cmd.payload)
            if status == 0x07 and len(cmd.payload) >= 4:
                dl_settings = cmd.payload[0]
                self.runtime.adr.rx1_dr_offset = (dl_settings >> 4) & 0x07
                self.runtime.adr.rx2_data_rate = dl_settings & 0x0F
        else:
            if len(cmd.payload) < 4:
                return MACCommand(cid=CID_RX_PARAM_SETUP_ANS, payload=bytes([0x00]))
            dl_settings = cmd.payload[0]
            self.runtime.adr.rx1_dr_offset = (dl_settings >> 4) & 0x07
            self.runtime.adr.rx2_data_rate = dl_settings & 0x0F
            status = 0x07
        return MACCommand(cid=CID_RX_PARAM_SETUP_ANS, payload=bytes([status]))

    def _apply_dev_status_req(self, cmd: MACCommand) -> MACCommand:
        """Apply DevStatusReq and return DevStatusAns."""
        # DevStatusAns: 2 bytes (battery, margin)
        battery = 255  # External power
        margin = 20  # Link margin in dB (dummy value)

        if self._logger:
            self._logger.debug("Responding to DevStatusReq")

        return MACCommand(cid=CID_DEV_STATUS_ANS, payload=bytes([battery, margin]))

    def _apply_new_channel_req(self, cmd: MACCommand) -> MACCommand:
        """Apply NewChannelReq: delegates to Radio, returns NewChannelAns."""
        radio = self.runtime.radio
        if radio is not None:
            status = radio.apply_new_channel_req(cmd.payload)
        else:
            if len(cmd.payload) < 5:
                return MACCommand(cid=CID_NEW_CHANNEL_ANS, payload=bytes([0x00]))
            status = 0x03
        return MACCommand(cid=CID_NEW_CHANNEL_ANS, payload=bytes([status]))

    def _apply_duty_cycle_req(self, cmd: MACCommand) -> MACCommand:
        """Apply DutyCycleReq: delegates to Radio, returns DutyCycleAns."""
        radio = self.runtime.radio
        if radio is not None:
            radio.apply_duty_cycle_req(cmd.payload)
        if len(cmd.payload) >= 1:
            self.runtime.adr.duty_cycle = cmd.payload[0] & 0x0F
        return MACCommand(cid=CID_DUTY_CYCLE_ANS, payload=b"")

    def _apply_rx_timing_setup_req(self, cmd: MACCommand) -> MACCommand:
        """Apply RXTimingSetupReq: delegates to Radio, returns RXTimingSetupAns."""
        radio = self.runtime.radio
        if radio is not None:
            radio.apply_rx_timing_setup_req(cmd.payload)
        if len(cmd.payload) >= 1:
            delay = cmd.payload[0] & 0x0F
            self.runtime.adr.rx1_delay = delay if delay > 0 else 1
        return MACCommand(cid=CID_RX_TIMING_SETUP_ANS, payload=b"")


# --- factory ---

_REGION_PROFILES: dict[str, type[RegionProfile]] = {
    "EU868": EU868RegionProfile,
}


def create_device(config: DeviceConfig, logger: Logger | None = None) -> SimulatedDevice:
    device = SimulatedDevice(
        dev_eui=config.activation.dev_eui,
        join_eui=config.activation.join_eui,
        app_key=config.activation.app_key,
        logger=logger,
    )
    profile_cls = _REGION_PROFILES.get(config.region)
    if profile_cls is not None:
        device.runtime.radio = Radio(
            profile_cls(),
            duty_cycle_enforcement=config.duty_cycle_enforcement,
            logger=logger,
        )
    return device
