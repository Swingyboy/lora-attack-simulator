"""Tests for UdpTransport DNS caching and exception mapping."""

from __future__ import annotations

import socket
import unittest
from unittest.mock import MagicMock, call, patch

from lora_attack_toolkit.transport.errors import (
    DnsResolutionError,
    TemporaryNetworkError,
    TransportUnavailableError,
)
from lora_attack_toolkit.transport.udp import UdpTransport


_FAKE_ADDR_INFO = [(socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("1.2.3.4", 1700))]


class TestUdpTransportConnect(unittest.TestCase):
    @patch("lora_attack_toolkit.transport.udp.socket.getaddrinfo", return_value=_FAKE_ADDR_INFO)
    @patch("lora_attack_toolkit.transport.udp.socket.socket")
    def test_connect_caches_resolved_address(self, mock_sock_cls, mock_getaddr) -> None:
        t = UdpTransport("ns.example.com", 1700)
        t.connect()
        self.assertEqual(t._resolved_addr, ("1.2.3.4", 1700))
        mock_getaddr.assert_called_once()

    @patch(
        "lora_attack_toolkit.transport.udp.socket.getaddrinfo",
        side_effect=socket.gaierror(-5, "No address associated with hostname"),
    )
    def test_connect_raises_dns_error_on_gaierror(self, _) -> None:
        t = UdpTransport("bad.host", 1700)
        with self.assertRaises(DnsResolutionError):
            t.connect()

    @patch("lora_attack_toolkit.transport.udp.socket.getaddrinfo", return_value=_FAKE_ADDR_INFO)
    @patch("lora_attack_toolkit.transport.udp.socket.socket")
    def test_reconnect_re_resolves_hostname(self, mock_sock_cls, mock_getaddr) -> None:
        t = UdpTransport("ns.example.com", 1700)
        t.connect()
        t.reconnect()
        # getaddrinfo called once per connect (2 total after reconnect)
        self.assertEqual(mock_getaddr.call_count, 2)


class TestUdpTransportDisconnect(unittest.TestCase):
    @patch("lora_attack_toolkit.transport.udp.socket.getaddrinfo", return_value=_FAKE_ADDR_INFO)
    @patch("lora_attack_toolkit.transport.udp.socket.socket")
    def test_disconnect_clears_socket_and_address(self, mock_sock_cls, mock_getaddr) -> None:
        t = UdpTransport("ns.example.com", 1700)
        t.connect()
        t.disconnect()
        self.assertIsNone(t._socket)
        self.assertIsNone(t._resolved_addr)


class TestUdpTransportSend(unittest.TestCase):
    def _connected_transport(self):
        with patch(
            "lora_attack_toolkit.transport.udp.socket.getaddrinfo", return_value=_FAKE_ADDR_INFO
        ):
            with patch("lora_attack_toolkit.transport.udp.socket.socket") as mock_sock_cls:
                mock_sock = MagicMock()
                mock_sock_cls.return_value = mock_sock
                t = UdpTransport("ns.example.com", 1700)
                t.connect()
                return t, mock_sock

    def test_send_raises_unavailable_when_not_connected(self) -> None:
        t = UdpTransport("ns.example.com", 1700)
        with self.assertRaises(TransportUnavailableError):
            t.send(b"data")

    def test_send_uses_cached_resolved_address(self) -> None:
        t, mock_sock = self._connected_transport()
        t.send(b"hello")
        mock_sock.sendto.assert_called_once_with(b"hello", ("1.2.3.4", 1700))

    def test_send_raises_temporary_error_on_oserror(self) -> None:
        t, mock_sock = self._connected_transport()
        mock_sock.sendto.side_effect = OSError("broken pipe")
        with self.assertRaises(TemporaryNetworkError):
            t.send(b"hello")


class TestUdpTransportReceive(unittest.TestCase):
    def _connected_transport(self):
        with patch(
            "lora_attack_toolkit.transport.udp.socket.getaddrinfo", return_value=_FAKE_ADDR_INFO
        ):
            with patch("lora_attack_toolkit.transport.udp.socket.socket") as mock_sock_cls:
                mock_sock = MagicMock()
                mock_sock_cls.return_value = mock_sock
                t = UdpTransport("ns.example.com", 1700)
                t.connect()
                return t, mock_sock

    def test_receive_raises_unavailable_when_not_connected(self) -> None:
        t = UdpTransport("ns.example.com", 1700)
        with self.assertRaises(TransportUnavailableError):
            t.receive(1.0)

    def test_receive_returns_data(self) -> None:
        t, mock_sock = self._connected_transport()
        mock_sock.recvfrom.return_value = (b"payload", ("1.2.3.4", 1700))
        result = t.receive(1.0)
        self.assertEqual(result, b"payload")

    def test_receive_returns_none_on_timeout(self) -> None:
        t, mock_sock = self._connected_transport()
        mock_sock.recvfrom.side_effect = socket.timeout
        self.assertIsNone(t.receive(0.1))

    def test_receive_raises_temporary_error_on_oserror(self) -> None:
        t, mock_sock = self._connected_transport()
        mock_sock.recvfrom.side_effect = OSError("network error")
        with self.assertRaises(TemporaryNetworkError):
            t.receive(1.0)
