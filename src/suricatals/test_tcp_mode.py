"""
Unit tests for TCP socket mode in suricata-language-server.

Tests the TCP server functionality including:
- TCP server initialization
- LSP communication over TCP
- Initialize/shutdown handshake

Copyright(C) 2026 Stamus Networks SAS
"""

# pylint: disable=W0212  # Allow testing protected methods

import socket
import json
import time
import threading
from unittest.mock import Mock, patch
import pytest

from suricatals.langserver import LangServer


def send_lsp_message(sock, message):
    """Send an LSP message over the socket."""
    content = json.dumps(message)
    header = f"Content-Length: {len(content)}\r\n\r\n"
    full_message = header + content
    sock.sendall(full_message.encode("utf-8"))


def receive_lsp_message(sock, timeout=5.0):
    """Receive an LSP message from the socket with timeout."""
    sock.settimeout(timeout)

    # Read headers
    headers = b""
    while b"\r\n\r\n" not in headers:
        chunk = sock.recv(1)
        if not chunk:
            return None
        headers += chunk

    # Parse Content-Length
    header_str = headers.decode("utf-8")
    content_length = None
    for line in header_str.split("\r\n"):
        if line.startswith("Content-Length:"):
            content_length = int(line.split(":")[1].strip())
            break

    if content_length is None:
        return None

    # Read content
    content = b""
    while len(content) < content_length:
        chunk = sock.recv(content_length - len(content))
        if not chunk:
            return None
        content += chunk

    return json.loads(content.decode("utf-8"))


class TestTCPMode:
    """Test TCP socket mode functionality."""

    @patch("suricatals.langserver.LanguageServer")
    def test_run_tcp_method_exists(self, _mock_ls):
        """Test that run_tcp method exists and has correct signature."""
        server = LangServer()
        assert hasattr(server, "run_tcp")
        assert callable(server.run_tcp)

    @patch("suricatals.langserver.LanguageServer")
    def test_run_tcp_calls_start_tcp(self, mock_ls_class):
        """Test that run_tcp calls server.start_tcp with correct parameters."""
        mock_server_instance = Mock()
        mock_ls_class.return_value = mock_server_instance

        server = LangServer()
        server.server = mock_server_instance

        # Call run_tcp
        test_host = "127.0.0.1"
        test_port = 9999

        # Mock start_tcp to avoid actually starting server
        mock_server_instance.start_tcp = Mock()

        server.run_tcp(host=test_host, port=test_port)

        # Verify start_tcp was called with correct args
        mock_server_instance.start_tcp.assert_called_once_with(test_host, test_port)

    @patch("suricatals.langserver.LanguageServer")
    def test_run_tcp_default_parameters(self, mock_ls_class):
        """Test that run_tcp uses default host and port."""
        mock_server_instance = Mock()
        mock_ls_class.return_value = mock_server_instance

        server = LangServer()
        server.server = mock_server_instance
        mock_server_instance.start_tcp = Mock()

        server.run_tcp()

        # Verify defaults are used
        mock_server_instance.start_tcp.assert_called_once_with("127.0.0.1", 2087)

    def test_tcp_server_integration(self):
        """Integration test: Start TCP server and connect with a client."""
        # Find an available port
        test_port = 15087

        # Create server in a separate thread
        server_ready = threading.Event()
        server_error = []

        def run_server():
            try:
                # Create a minimal mock configuration
                settings = {
                    "docker_mode": False,
                    "suricata_binary": "suricata",
                }

                # Patch SignaturesTester to avoid needing actual Suricata
                with patch(
                    "suricatals.langserver.SignaturesTester"
                ) as mock_tester_class:
                    mock_tester = Mock()
                    mock_tester.suricata_version = "7.0.0"
                    mock_tester.build_keywords_list.return_value = []
                    mock_tester.build_app_layer_list.return_value = []
                    mock_tester.ACTIONS_ITEMS = []
                    mock_tester_class.return_value = mock_tester

                    server = LangServer(settings=settings, batch_mode=False)

                    # Signal that server is about to start
                    server_ready.set()

                    # Start TCP server (this will block)
                    server.run_tcp(host="127.0.0.1", port=test_port)

            # pylint: disable=W0718
            except Exception as e:
                server_error.append(str(e))
                server_ready.set()

        # Start server thread
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()

        # Wait for server to be ready
        assert server_ready.wait(timeout=5.0), "Server failed to start"

        # Check for server errors
        if server_error:
            pytest.fail(f"Server error: {server_error[0]}")

        # Give server a moment to bind to port
        time.sleep(0.5)

        # Connect client
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5.0)
            client_socket.connect(("127.0.0.1", test_port))

            # Send initialize request
            initialize_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "processId": None,
                    "clientInfo": {"name": "test-client", "version": "1.0.0"},
                    "rootUri": None,
                    "capabilities": {},
                },
            }

            send_lsp_message(client_socket, initialize_request)

            # Receive response
            response = receive_lsp_message(client_socket, timeout=5.0)

            # Verify response
            assert response is not None, "No response received from server"
            assert "result" in response, "Response missing 'result' field"
            assert "serverInfo" in response["result"], "Response missing serverInfo"
            assert (
                response["result"]["serverInfo"]["name"] == "Suricata Language Server"
            )

            # Send shutdown request
            shutdown_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "shutdown",
                "params": None,
            }
            send_lsp_message(client_socket, shutdown_request)

            # Wait for shutdown response
            response = receive_lsp_message(client_socket, timeout=5.0)
            assert response is not None, "No shutdown response received"

            client_socket.close()

        except ConnectionRefusedError:
            pytest.fail(
                f"Could not connect to TCP server on port {test_port}. "
                "Is the server running?"
            )
        # pylint: disable=W0718
        except Exception as e:
            pytest.fail(f"TCP integration test failed: {e}")


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-s"])
