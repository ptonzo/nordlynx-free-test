import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import build_subscription as b

class EndToEndParserTests(unittest.TestCase):
    def test_vless_tls_uri_builds_sing_box_outbound(self):
        uri = "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=%2Fvpn#node"
        out, host, port = b.outbound_from_uri(uri)
        self.assertEqual((host, port), ("example.com", 443))
        self.assertEqual(out["type"], "vless")
        self.assertEqual(out["tls"]["server_name"], "example.com")
        self.assertEqual(out["transport"]["type"], "ws")

    def test_vless_reality_requires_public_key(self):
        uri = "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=reality&sni=example.com#node"
        with self.assertRaisesRegex(ValueError, "public key"):
            b.outbound_from_uri(uri)

    def test_trojan_tls_uri(self):
        out, host, port = b.outbound_from_uri("trojan://secret@example.com:443?sni=example.com#node")
        self.assertEqual((host, port), ("example.com", 443))
        self.assertEqual(out["type"], "trojan")
        self.assertTrue(out["tls"]["enabled"])

    def test_shadowsocks_uri(self):
        out, host, port = b.outbound_from_uri("ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388#node")
        self.assertEqual((host, port), ("example.com", 8388))
        self.assertEqual(out["type"], "shadowsocks")
        self.assertEqual(out["method"], "aes-256-gcm")

    def test_vmess_base64_uri(self):
        payload = base64.b64encode(json.dumps({
            "add":"vmess.example","port":"8443","id":"11111111-1111-4111-8111-111111111111",
            "scy":"auto","net":"tcp","tls":"tls","host":"vmess.example"
        }).encode()).decode().rstrip("=")
        out, host, port = b.outbound_from_uri("vmess://" + payload)
        self.assertEqual((host, port), ("vmess.example", 8443))
        self.assertEqual(out["type"], "vmess")
        self.assertTrue(out["tls"]["enabled"])

    def test_base64_feed_decode(self):
        raw = "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls#node\n"
        self.assertIn("vless://", b.decode_feed(base64.b64encode(raw.encode()).decode()))

if __name__ == "__main__":
    unittest.main()
