import base64
import json
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import build_subscription as b

class ParserTests(unittest.TestCase):
    def test_vless_host_port(self):
        self.assertEqual(b.parse_host_port("vless://abc@example.com:443?security=tls#🇩🇪 Germany"), ("example.com", 443))
    def test_vmess_host_port(self):
        payload = base64.b64encode(json.dumps({"add":"vmess.example","port":"8443","id":"x"}).encode()).decode().rstrip("=")
        self.assertEqual(b.parse_host_port("vmess://" + payload), ("vmess.example", 8443))
    def test_country_flag(self):
        self.assertEqual(b.country_from_uri("vless://a@x:443#🇯🇵 Japan 01"), "Japan")
    def test_decode_base64_feed(self):
        raw = "vless://a@example.com:443#🇩🇪 Germany\n"
        self.assertIn("vless://", b.decode_feed(base64.b64encode(raw.encode()).decode()))

if __name__ == "__main__":
    unittest.main()
