"""OTAA join lifecycle helper for reliable join operations."""

from __future__ import annotations

from logging import Logger

from lorawan.device.model import SimulatedDevice
from lorawan.gateway.model import GatewaySimulator
from lorawan.scenario.schema import RadioMetadata


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
    join_request = device.build_join_request()
    dev_nonce = device.runtime.dev_nonce
    
    if logger:
        logger.info(f"Sending JoinRequest with DevNonce={dev_nonce.hex()}")
    
    gateway.forward_uplink(join_request, radio)
    
    # 2. Wait for JoinAccept from Network Server
    if logger:
        logger.info(f"Waiting for JoinAccept (timeout={timeout_sec}s)...")
    
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
                f"OTAA join succeeded: DevAddr={device.runtime.dev_addr_hex}",
                extra={"dev_addr": device.runtime.dev_addr_hex},
            )
        
        return True
        
    except Exception as e:
        if logger:
            logger.error(f"OTAA join failed: Could not apply JoinAccept: {e}")
        return False


def perform_otaa_join_with_devnonce(
    device: SimulatedDevice,
    gateway: GatewaySimulator,
    radio: RadioMetadata,
    dev_nonce: bytes,
    timeout_sec: float = 5.0,
    logger: Logger | None = None,
) -> tuple[bool, bool]:
    """
    Perform OTAA join with a specific DevNonce (for replay attacks).
    
    Similar to perform_otaa_join, but allows specifying the DevNonce
    instead of generating a random one. Used for testing DevNonce
    validation by replaying previous values.
    
    Args:
        device: Simulated device to perform join
        gateway: Gateway to forward packets through
        radio: Radio metadata for uplink
        dev_nonce: Specific DevNonce value to use
        timeout_sec: How long to wait for JoinAccept
        logger: Optional logger for diagnostics
        
    Returns:
        Tuple of (ns_responded, join_succeeded):
        - ns_responded: True if NS sent any downlink (even if malformed)
        - join_succeeded: True if JoinAccept was valid and applied successfully
    """
    if logger:
        logger.info(f"Attempting OTAA join with DevNonce={dev_nonce.hex()}")
    
    # Manually set DevNonce before building JoinRequest
    device.runtime.dev_nonce = dev_nonce
    
    # Build JoinRequest with specified DevNonce
    from lorawan.protocol.frames import build_join_request
    
    join_request = build_join_request(
        join_eui=device._join_eui,
        dev_eui=device._dev_eui,
        dev_nonce=dev_nonce,
        app_key=device._app_key,
    )
    
    if logger:
        logger.info(f"Sending JoinRequest with DevNonce={dev_nonce.hex()}")
    
    gateway.forward_uplink(join_request, radio)
    
    # Wait for JoinAccept
    if logger:
        logger.info(f"Waiting for JoinAccept (timeout={timeout_sec}s)...")
    
    join_accept = gateway.await_downlink(timeout_sec=timeout_sec)
    
    if join_accept is None:
        if logger:
            logger.info("No JoinAccept received (NS rejected or timeout)")
        return (False, False)  # NS did not respond
    
    # NS responded with something
    if logger:
        logger.info("downlink_received")
        logger.debug(f"Raw downlink PHYPayload: {join_accept.hex()}")
        logger.debug(f"Downlink size: {len(join_accept)} bytes")
    
    # Parse MHDR to check message type
    if len(join_accept) == 0:
        if logger:
            logger.error("Empty downlink received from NS")
        return (True, False)  # NS responded but empty
    
    mhdr = join_accept[0]
    mtype = (mhdr >> 5) & 0x07  # Extract MType from bits 7-5
    
    # Import MHDR constants
    from lorawan.protocol.frames import (
        MHDR_JOIN_ACCEPT,
        MHDR_UNCONFIRMED_DATA_UP,
        MHDR_CONFIRMED_DATA_UP,
    )
    
    # Map MType to human-readable name
    mtype_names = {
        0x00: "JoinRequest",
        0x01: "JoinAccept",
        0x02: "UnconfirmedDataUp",
        0x03: "UnconfirmedDataDown",
        0x04: "ConfirmedDataUp",
        0x05: "ConfirmedDataDown",
        0x06: "RFU",
        0x07: "Proprietary",
    }
    
    mtype_name = mtype_names.get(mtype, f"Unknown({mtype})")
    
    if logger:
        logger.debug(f"Downlink MHDR: 0x{mhdr:02x}, MType: {mtype} ({mtype_name})")
    
    # Check if it's actually a JoinAccept
    if mhdr != MHDR_JOIN_ACCEPT:
        if logger:
            logger.warning(
                f"NS sent {mtype_name} instead of JoinAccept (MHDR=0x{mhdr:02x})"
            )
            logger.warning(
                "This indicates NS accepted the request but responded with wrong message type"
            )
        return (True, False)  # NS responded but wrong message type
    
    # Try to apply JoinAccept
    try:
        device.apply_join_accept(join_accept)
        
        if logger:
            logger.info(
                f"JoinAccept received: DevAddr={device.runtime.dev_addr_hex}",
                extra={"dev_addr": device.runtime.dev_addr_hex},
            )
        
        return (True, True)  # NS responded and JoinAccept valid
        
    except Exception as e:
        # NS responded with JoinAccept but it's malformed
        if logger:
            logger.error(f"Could not parse JoinAccept: {e}")
            logger.debug(f"Exception type: {type(e).__name__}")
            logger.debug(f"Exception details: {str(e)}")
            
            # Try to provide more context
            if "MIC" in str(e):
                logger.debug("MIC verification failed - NS may have used wrong AppKey")
            elif "size" in str(e):
                logger.debug(f"Invalid size - expected multiple of 16, got {len(join_accept)-1} encrypted bytes")
            elif "too short" in str(e):
                logger.debug("Payload too short after decryption")
        
        return (True, False)  # NS responded but JoinAccept invalid


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
    
    Args:
        device: Device to send uplinks from
        gateway: Gateway to forward packets through
        radio: Radio metadata for uplinks
        count: Number of uplinks to send
        interval_sec: Time to wait between uplinks
        f_port: FPort for data uplinks
        confirmed: Whether to request confirmation
        logger: Optional logger for diagnostics
        
    Returns:
        Number of uplinks successfully sent
    """
    import time
    
    sent_count = 0
    
    for i in range(count):
        try:
            # Build data uplink with simple incrementing payload
            payload = bytes([i % 256])
            uplink = device.build_data_uplink(
                payload=payload,
                f_port=f_port,
                confirmed=confirmed
            )
            
            gateway.forward_uplink(uplink, radio)
            sent_count += 1
            
            if logger:
                logger.info(f"Sent uplink {i+1}/{count} with FCnt={device.runtime.fcnt_up - 1}")
            
            # Wait before next uplink (except after last one)
            if i < count - 1:
                time.sleep(interval_sec)
                
        except Exception as e:
            if logger:
                logger.error(f"Failed to send uplink {i+1}: {e}")
    
    return sent_count


def capture_downlinks(
    gateway: GatewaySimulator,
    timeout_sec: float,
    max_count: int = 10,
    logger: Logger | None = None,
) -> list[bytes]:
    """
    Capture downlinks from Network Server.
    
    Polls for PULL_RESP packets containing downlinks.
    
    Args:
        gateway: Gateway to receive downlinks from
        timeout_sec: How long to wait for downlinks
        max_count: Maximum number of downlinks to capture
        logger: Optional logger for diagnostics
        
    Returns:
        List of captured PHYPayload bytes
    """
    import time
    
    captured = []
    start_time = time.time()
    
    while len(captured) < max_count:
        elapsed = time.time() - start_time
        if elapsed >= timeout_sec:
            break
        
        remaining = timeout_sec - elapsed
        downlink = gateway.await_downlink(timeout_sec=min(remaining, 1.0))
        
        if downlink:
            captured.append(downlink)
            if logger:
                logger.info(f"Captured downlink {len(captured)}/{max_count}")
        else:
            # Short sleep before retry
            time.sleep(0.1)
    
    if logger:
        logger.info(f"Captured {len(captured)} downlink(s) in {timeout_sec}s")
    
    return captured

