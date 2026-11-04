"""Tests for OmaDeck local CA and TLS certificate generation."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from omarchy_voice.mobile_bridge import (
    _ensure_tls,
    _ca_valid,
    _cert_valid,
)


class TlsCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl command not available")

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_ca_and_leaf_generation_with_name_constraints_verifies_ok(self):
        with mock.patch("omarchy_voice.mobile_bridge.CONFIG_DIR", self.config_dir), \
             mock.patch("omarchy_voice.mobile_bridge.CA_CERT_FILE", self.config_dir / "ca.pem"), \
             mock.patch("omarchy_voice.mobile_bridge.CA_KEY_FILE", self.config_dir / "ca.key"), \
             mock.patch("omarchy_voice.mobile_bridge.CA_DER_FILE", self.config_dir / "ca.der"), \
             mock.patch("omarchy_voice.mobile_bridge.CERT_FILE", self.config_dir / "mobile.pem"), \
             mock.patch("omarchy_voice.mobile_bridge.KEY_FILE", self.config_dir / "mobile.key"), \
             mock.patch("omarchy_voice.mobile_bridge.CERT_HOST_FILE", self.config_dir / "mobile.host"):

            # Issue for private IPv4
            tls = _ensure_tls("192.168.1.50")
            self.assertIsNotNone(tls)
            cert_file, key_file = tls
            self.assertTrue(cert_file.exists())
            self.assertTrue(key_file.exists())

            ca_file = self.config_dir / "ca.pem"
            self.assertTrue(ca_file.exists())
            self.assertTrue(_ca_valid(ca_file))

            # Verify leaf against CA using OpenSSL
            res = subprocess.run(
                ["openssl", "verify", "-CAfile", str(ca_file), str(cert_file)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"OpenSSL verify failed: {res.stderr}")
            self.assertIn("OK", res.stdout)

            # Check SAN contents
            res_text = subprocess.run(
                ["openssl", "x509", "-text", "-noout", "-in", str(cert_file)],
                capture_output=True,
                text=True,
            )
            self.assertIn("DNS:localhost", res_text.stdout)
            self.assertIn("IP Address:127.0.0.1", res_text.stdout)
            self.assertIn("IP Address:192.168.1.50", res_text.stdout)

    def test_leaf_generation_for_tailscale_dns_and_ipv6(self):
        with mock.patch("omarchy_voice.mobile_bridge.CONFIG_DIR", self.config_dir), \
             mock.patch("omarchy_voice.mobile_bridge.CA_CERT_FILE", self.config_dir / "ca.pem"), \
             mock.patch("omarchy_voice.mobile_bridge.CA_KEY_FILE", self.config_dir / "ca.key"), \
             mock.patch("omarchy_voice.mobile_bridge.CA_DER_FILE", self.config_dir / "ca.der"), \
             mock.patch("omarchy_voice.mobile_bridge.CERT_FILE", self.config_dir / "mobile.pem"), \
             mock.patch("omarchy_voice.mobile_bridge.KEY_FILE", self.config_dir / "mobile.key"), \
             mock.patch("omarchy_voice.mobile_bridge.CERT_HOST_FILE", self.config_dir / "mobile.host"):

            ca_file = self.config_dir / "ca.pem"

            # Issue for tailscale host
            tls_ts = _ensure_tls("mydevice.ts.net")
            self.assertIsNotNone(tls_ts)
            res_ts = subprocess.run(
                ["openssl", "verify", "-CAfile", str(ca_file), str(tls_ts[0])],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_ts.returncode, 0)
            self.assertIn("OK", res_ts.stdout)

            # Issue for IPv6 loopback
            tls_v6 = _ensure_tls("::1")
            self.assertIsNotNone(tls_v6)
            res_v6 = subprocess.run(
                ["openssl", "verify", "-CAfile", str(ca_file), str(tls_v6[0])],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_v6.returncode, 0)
            self.assertIn("OK", res_v6.stdout)


if __name__ == "__main__":
    unittest.main()
