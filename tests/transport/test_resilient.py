"""Tests for ResilientTransport retry/recovery wrapper."""

from __future__ import annotations

import logging
import unittest
from unittest.mock import MagicMock

import pytest

from lora_attack_toolkit.transport.errors import (
    DnsResolutionError,
    TemporaryNetworkError,
    TransportPermanentError,
)
from lora_attack_toolkit.transport.resilient import ResilientTransport
from lora_attack_toolkit.transport.retry import RetryPolicy

pytestmark = pytest.mark.unit


def _make_transport(**kwargs):
    """Create a ResilientTransport wrapping a MagicMock inner transport."""
    inner = MagicMock()
    policy = RetryPolicy(**kwargs)
    logger = logging.getLogger("test")
    return ResilientTransport(inner, policy=policy, logger=logger), inner


class TestResilientTransportSend(unittest.TestCase):
    def test_send_succeeds_immediately(self) -> None:
        rt, inner = _make_transport()
        rt.connect()
        rt.send(b"hello")
        inner.send.assert_called_once_with(b"hello")

    def test_send_retries_on_temporary_error(self) -> None:
        rt, inner = _make_transport(initial_delay_sec=0.0)
        inner.send.side_effect = [TemporaryNetworkError("blip"), None]
        rt.connect()
        rt.send(b"data")
        self.assertEqual(inner.send.call_count, 2)

    def test_send_retries_up_to_max_attempts(self) -> None:
        max_attempts = 3
        rt, inner = _make_transport(max_attempts=max_attempts, initial_delay_sec=0.0)
        inner.send.side_effect = TemporaryNetworkError("always fail")
        rt.connect()
        with self.assertRaises(TemporaryNetworkError):
            rt.send(b"data")
        # initial attempt + max_attempts retries
        self.assertEqual(inner.send.call_count, max_attempts + 1)

    def test_send_does_not_retry_permanent_error(self) -> None:
        rt, inner = _make_transport()
        inner.send.side_effect = TransportPermanentError("bad config")
        rt.connect()
        with self.assertRaises(TransportPermanentError):
            rt.send(b"data")
        inner.send.assert_called_once()

    def test_send_attempts_reconnect_between_retries(self) -> None:
        rt, inner = _make_transport(max_attempts=2, initial_delay_sec=0.0)
        inner.send.side_effect = [TemporaryNetworkError("blip"), None]
        rt.connect()
        rt.send(b"data")
        inner.reconnect.assert_called_once()

    def test_send_does_not_retry_when_policy_disabled(self) -> None:
        rt, inner = _make_transport(enabled=False)
        inner.send.side_effect = TemporaryNetworkError("blip")
        rt.connect()
        with self.assertRaises(TemporaryNetworkError):
            rt.send(b"data")
        inner.send.assert_called_once()

    def test_continues_after_failed_reconnect(self) -> None:
        """A failed reconnect should not prevent the next send attempt."""
        rt, inner = _make_transport(max_attempts=2, initial_delay_sec=0.0)
        inner.reconnect.side_effect = TemporaryNetworkError("reconnect failed")
        inner.send.side_effect = [TemporaryNetworkError("blip"), None]
        rt.connect()
        # Should not raise even though reconnect itself fails
        rt.send(b"data")
        self.assertEqual(inner.send.call_count, 2)


class TestResilientTransportConnect(unittest.TestCase):
    def test_connect_retries_on_temporary_error(self) -> None:
        rt, inner = _make_transport(initial_delay_sec=0.0)
        inner.connect.side_effect = [DnsResolutionError("nxdomain"), None]
        rt.connect()
        self.assertEqual(inner.connect.call_count, 2)

    def test_connect_raises_permanent_error_immediately(self) -> None:
        rt, inner = _make_transport()
        inner.connect.side_effect = TransportPermanentError("bad cert")
        with self.assertRaises(TransportPermanentError):
            rt.connect()
        inner.connect.assert_called_once()


class TestResilientTransportReceive(unittest.TestCase):
    def test_receive_returns_data(self) -> None:
        rt, inner = _make_transport()
        inner.receive.return_value = b"payload"
        rt.connect()
        result = rt.receive(1.0)
        self.assertEqual(result, b"payload")

    def test_receive_returns_none_on_timeout(self) -> None:
        rt, inner = _make_transport()
        inner.receive.return_value = None
        rt.connect()
        self.assertIsNone(rt.receive(1.0))

    def test_receive_attempts_reconnect_on_temporary_error(self) -> None:
        rt, inner = _make_transport()
        inner.receive.side_effect = TemporaryNetworkError("socket error")
        rt.connect()
        result = rt.receive(1.0)
        inner.reconnect.assert_called_once()
        self.assertIsNone(result)

    def test_receive_propagates_permanent_error(self) -> None:
        rt, inner = _make_transport()
        inner.receive.side_effect = TransportPermanentError("auth")
        rt.connect()
        with self.assertRaises(TransportPermanentError):
            rt.receive(1.0)


class TestResilientTransportPassThrough(unittest.TestCase):
    def test_disconnect_delegates(self) -> None:
        rt, inner = _make_transport()
        rt.disconnect()
        inner.disconnect.assert_called_once()

    def test_reconnect_delegates(self) -> None:
        rt, inner = _make_transport()
        rt.reconnect()
        inner.reconnect.assert_called_once()
