"""Tests for the transport exception hierarchy."""

from __future__ import annotations

import unittest

from lora_attack_toolkit.transport.errors import (

    DnsResolutionError,
    RemoteResetError,
    TemporaryNetworkError,
    TransportError,
    TransportPermanentError,
    TransportTemporaryError,
    TransportUnavailableError,
)
import pytest

pytestmark = pytest.mark.unit


class TestExceptionHierarchy(unittest.TestCase):
    def test_temporary_errors_are_transport_errors(self) -> None:
        for cls in (
            TransportTemporaryError,
            DnsResolutionError,
            RemoteResetError,
            TemporaryNetworkError,
            TransportUnavailableError,
        ):
            with self.subTest(cls=cls):
                exc = cls("msg")
                self.assertIsInstance(exc, TransportError)
                self.assertIsInstance(exc, TransportTemporaryError)

    def test_permanent_error_is_transport_error(self) -> None:
        exc = TransportPermanentError("bad config")
        self.assertIsInstance(exc, TransportError)
        self.assertNotIsInstance(exc, TransportTemporaryError)

    def test_dns_resolution_error_is_catchable_as_temporary(self) -> None:
        with self.assertRaises(TransportTemporaryError):
            raise DnsResolutionError("no address")

    def test_permanent_error_is_not_catchable_as_temporary(self) -> None:
        with self.assertRaises(TransportPermanentError):
            raise TransportPermanentError("auth failed")
        # Must NOT be caught by TransportTemporaryError handler
        caught_as_temporary = False
        try:
            raise TransportPermanentError("auth failed")
        except TransportTemporaryError:
            caught_as_temporary = True
        except TransportPermanentError:
            pass
        self.assertFalse(caught_as_temporary)
