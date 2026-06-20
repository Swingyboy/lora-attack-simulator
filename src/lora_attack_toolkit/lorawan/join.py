"""OTAA join lifecycle helper for reliable join operations."""

from __future__ import annotations

import struct
import time
from logging import Logger

from lora_attack_toolkit.config import RadioMetadata
from lora_attack_toolkit.lorawan.radio import AirtimeCalculator, Radio
from lora_attack_toolkit.runtime.device import SimulatedDevice
from lora_attack_toolkit.runtime.gateway import GatewaySimulator


def perform_otaa_join(
    device: SimulatedDevice,
    gateway: GatewaySimulator,
    radio: RadioMetadata,
    timeout_sec: float = 5.0,
    logger: Logger | None = None,
) -> bool:
    """
    Perform OTAA join and wait for JoinAccept from Network Server.

    Steps:
    1. Device generates JoinRequest with new DevNonce
    2. Gateway forwards JoinRequest to NS
    3. Wait for PULL_RESP containing JoinAccept
    4. Parse JoinAccept and derive session keys
    5. Device is now in joined state

    Args:
        device: Simulated device to perform join
        gateway: Gateway to forward packets through
        radio: Radio metadata for uplink
        timeout_sec: How long to wait for JoinAccept
        logger: Optional logger for diagnostics

    Returns:
        True if join succeeded (JoinAccept received and applied)
        False if join failed (timeout or invalid JoinAccept)
    """
    if logger:
        logger.info("Attempting OTAA join...")

    # 1. Build and send JoinRequest
    dev_nonce = device.new_dev_nonce()
    join_request = device.build_join_request()

    if logger:
        logger.info("Sending JoinRequest with DevNonce=%s", dev_nonce.hex())

    gateway.forward_uplink(join_request, radio)

    # 2. Wait for JoinAccept from Network Server
    if logger:
        logger.info("Waiting for JoinAccept (timeout=%.1fs)...", timeout_sec)

    join_accept = gateway.await_downlink(timeout_sec=timeout_sec)

    if join_accept is None:
        if logger:
            logger.warning("OTAA join failed: No JoinAccept received from NS")
        return False

    # 3. Parse and apply JoinAccept to device
    try:
        device.apply_join_accept(join_accept)

        if logger:
            logger.info(
                "OTAA join succeeded: DevAddr=%s",
                device.runtime.dev_addr_hex,
                extra={"dev_addr": device.runtime.dev_addr_hex},
            )

        return True

    except (ValueError, KeyError, struct.error) as e:
        if logger:
            logger.error("OTAA join failed: Could not apply JoinAccept: %s", e)
        return False


def perform_otaa_join_via_radio(
    device: SimulatedDevice,
    gateway: GatewaySimulator,
    radio_obj: Radio,
    base_radio: RadioMetadata,
    *,
    seed: int | None = None,
    timeout_sec: float = 5.0,
    logger: Logger | None = None,
) -> bool:
    """Perform OTAA join using the :class:`Radio` object for channel selection.

    Unlike :func:`perform_otaa_join` (which uses a fixed :class:`RadioMetadata`),
    this function selects the JoinRequest channel through ``radio_obj``, enabling:

    * Pseudo-random channel rotation across the region's join channels.
    * Duty-cycle enforcement per ETSI sub-band.
    * Deterministic behavior when a ``seed`` is supplied (for tests).
    * Automatic CFList application from the JoinAccept.

    Args:
        device: Simulated end-device.
        gateway: Gateway used to forward packets and receive downlinks.
        radio_obj: :class:`Radio` instance — provides channel selection and
            will have :meth:`~Radio.apply_cflist` called on JoinAccept.
        base_radio: Used for RSSI/SNR metadata and as a fallback for the
            downlink-listener configuration.
        seed: Optional seed for pseudo-random channel selection.  When set
            the function uses ``seed + attempt`` as the index, producing a
            deterministic hop pattern without global RNG side-effects.
        timeout_sec: How long to wait for a JoinAccept per attempt.
        logger: Optional logger.

    Returns:
        ``True`` if the join succeeded; ``False`` otherwise.
    """
    import time as _time

    if logger:
        logger.info("perform_otaa_join_via_radio: starting")

    dev_nonce = device.new_dev_nonce()
    join_request = device.build_join_request()

    now = _time.monotonic()
    attempt_index = seed if seed is not None else 0
    tx = radio_obj.select_join_channel(attempt_index, now=now)
    join_radio = RadioMetadata(
        frequency=tx.frequency_hz,
        data_rate=tx.data_rate,
        rssi=base_radio.rssi,
        snr=base_radio.snr,
    )
    if logger:
        logger.info(
            "perform_otaa_join_via_radio: sending JoinRequest DevNonce=%s freq=%d dr=%s",
            dev_nonce.hex(),
            tx.frequency_hz,
            tx.data_rate,
        )

    gateway.forward_uplink(join_request, join_radio)
    airtime = AirtimeCalculator.calculate(tx.data_rate, len(join_request))
    radio_obj.record_transmission(tx.frequency_hz, airtime, now)

    join_accept = gateway.await_downlink(timeout_sec=timeout_sec)
    if join_accept is None:
        if logger:
            logger.warning("perform_otaa_join_via_radio: no JoinAccept received")
        return False

    try:
        device.apply_join_accept(join_accept)
        # Mirror CFList into Radio so channel plan is up to date.
        cflist = getattr(device.runtime, "cflist", None)
        if cflist:
            radio_obj.apply_cflist(cflist)
        if logger:
            logger.info(
                "perform_otaa_join_via_radio: joined DevAddr=%s",
                device.runtime.dev_addr_hex,
            )
        return True
    except (ValueError, KeyError, struct.error) as e:
        if logger:
            logger.error("perform_otaa_join_via_radio: could not apply JoinAccept: %s", e)
        return False


def send_periodic_uplinks(
    device: SimulatedDevice,
    gateway: GatewaySimulator,
    radio: RadioMetadata,
    count: int,
    interval_sec: float,
    f_port: int = 10,
    confirmed: bool = False,
    logger: Logger | None = None,
) -> int:
    """
    Send periodic uplinks with specified interval.

    The radio frequency for each uplink is selected from the device's active
    channel plan (if configured) via round-robin rotation, falling back to the
    provided ``radio`` metadata when no channel plan is set.

    Args:
        device: Device to send uplinks from
        gateway: Gateway to forward packets through
        radio: Base radio metadata (rssi/snr reused; frequency overridden by channel plan)
        count: Number of uplinks to send
        interval_sec: Time to wait between uplinks
        f_port: FPort for data uplinks
        confirmed: Whether to request confirmation
        logger: Optional logger for diagnostics

    Returns:
        Number of uplinks successfully sent
    """
    sent_count = 0

    for i in range(count):
        try:
            now = time.monotonic()
            uplink_radio = _select_uplink_radio(device, radio, now=now)

            payload = bytes([i % 256])
            uplink = device.build_data_uplink(
                payload=payload,
                f_port=f_port,
                confirmed=confirmed,
            )

            gateway.forward_uplink(uplink, uplink_radio)

            # Record actual airtime so Radio can enforce duty-cycle correctly.
            if (
                isinstance(device.runtime.radio, Radio)
                and device.runtime.radio.supports_duty_cycle()
            ):
                airtime = AirtimeCalculator.calculate(uplink_radio.data_rate, len(uplink))
                device.runtime.radio.record_transmission(uplink_radio.frequency, airtime, now)

            device.runtime.uplink_index += 1
            sent_count += 1

            if logger:
                logger.info(
                    "Sent uplink %d/%d FCnt=%d frequency=%d",
                    i + 1,
                    count,
                    device.runtime.fcnt_up - 1,
                    uplink_radio.frequency,
                )

            if i < count - 1:
                time.sleep(interval_sec)

        except (OSError, ValueError) as e:
            if logger:
                logger.error("Failed to send uplink %d: %s", i + 1, e)

    return sent_count


def _select_uplink_radio(
    device: SimulatedDevice, base_radio: RadioMetadata, now: float | None = None
) -> RadioMetadata:
    """Return RadioMetadata for the next uplink.

    Uses ``device.runtime.radio`` (the :class:`~lora_attack_toolkit.lorawan.radio.Radio`
    abstraction) when available, otherwise falls back to *base_radio*.
    """
    radio = device.runtime.radio
    if isinstance(radio, Radio):
        tx = radio.select_uplink_channel(device.runtime.uplink_index, now=now)
        return RadioMetadata(
            frequency=tx.frequency_hz,
            data_rate=tx.data_rate,
            rssi=base_radio.rssi,
            snr=base_radio.snr,
        )
    return base_radio
