"""
Integration Tests for Flask Web Application & Steganography Endpoints
---------------------------------------------------------------------
Tests:
1. GET / -> Status 200, renders the secure-message workspace
2. GET /api/stego/generate-key -> Status 200, returns 256-bit keys
3. POST /api/stego/capacity -> Status 200, returns image capacity info
4. POST /api/stego/hide (text) -> Status 200, returns stego URL and PSNR metrics
5. POST /api/stego/extract (text, valid key) -> Status 200, verified plaintext
6. POST /api/stego/extract (wrong key) -> Status 400, rejected with authentication error
7. POST /api/stego/analyze -> Status 200, returns PSNR/MSE metrics & diff image
"""

import os
import io
import json
import unittest
from PIL import Image

from app import app


class TestFlaskRoutes(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

        # Create synthetic cover image in memory
        self.cover_io = io.BytesIO()
        img = Image.new("RGB", (200, 200), color=(50, 100, 150))
        img.save(self.cover_io, format="PNG")
        self.cover_io.seek(0)

    def test_index_route(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Encrypt & Hide", response.data)
        self.assertIn(b"Secure Message Workspace", response.data)
        self.assertIn(b"background-color: #fff", response.data)
        self.assertIn(b'nav-link active" id="tab-hide-btn"', response.data)
        self.assertNotIn(b"Project Abstract", response.data)
        self.assertNotIn(b"tab-overview", response.data)

    def test_api_generate_key(self):
        response = self.client.get("/api/stego/generate-key")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(data["hex_key"]), 64)
        self.assertEqual(len(data["base64_key"]), 44)

    def test_api_capacity(self):
        self.cover_io.seek(0)
        data = {
            "cover_image": (self.cover_io, "cover.png")
        }
        response = self.client.post("/api/stego/capacity", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        res_json = json.loads(response.data)
        self.assertEqual(res_json["width"], 200)
        self.assertEqual(res_json["height"], 200)
        self.assertGreater(res_json["usable_capacity_bytes"], 14000)

    def test_api_hide_and_extract_lifecycle(self):
        self.cover_io.seek(0)
        secret_msg = "Top Secret: Autonomous Cybersecurity Protocol 2026"
        secret_key = "DefenseGradePassphrase2026!#"

        # 1. Hide Text
        data = {
            "cover_image": (self.cover_io, "cover.png"),
            "payload_type": "text",
            "secret_text": secret_msg,
            "key": secret_key
        }
        hide_resp = self.client.post("/api/stego/hide", data=data, content_type="multipart/form-data")
        self.assertEqual(hide_resp.status_code, 200)
        hide_json = json.loads(hide_resp.data)
        self.assertEqual(hide_json["status"], "success")
        self.assertIn("stego_image_url", hide_json)
        self.assertGreater(hide_json["metrics"]["overall_psnr_db"], 50.0)

        # 2. Extract with Valid Key
        stego_filename = hide_json["filename"]
        stego_path = os.path.join(app.config["UPLOAD_FOLDER"], stego_filename)

        with open(stego_path, "rb") as f:
            stego_bytes = io.BytesIO(f.read())

        extract_data = {
            "stego_image": (stego_bytes, "stego.png"),
            "key": secret_key
        }
        ext_resp = self.client.post("/api/stego/extract", data=extract_data, content_type="multipart/form-data")
        self.assertEqual(ext_resp.status_code, 200)
        ext_json = json.loads(ext_resp.data)
        self.assertEqual(ext_json["status"], "success")
        self.assertEqual(ext_json["text"], secret_msg)
        self.assertTrue(ext_json["verified"])

        # 3. Extract with Invalid Key -> MUST Fail
        with open(stego_path, "rb") as f:
            bad_stego_bytes = io.BytesIO(f.read())

        bad_extract_data = {
            "stego_image": (bad_stego_bytes, "stego.png"),
            "key": "WrongPassword999"
        }
        bad_resp = self.client.post("/api/stego/extract", data=bad_extract_data, content_type="multipart/form-data")
        self.assertEqual(bad_resp.status_code, 400)
        bad_json = json.loads(bad_resp.data)
        self.assertIn("error", bad_json)

    def test_api_analyze(self):
        self.cover_io.seek(0)
        # Create stego image
        cover_img = Image.open(self.cover_io)
        from crypto_stego import LSBSteganography
        stego_img, _ = LSBSteganography.hide_text(cover_img, "Test Message", "Pass123")

        cover_bytes = io.BytesIO()
        cover_img.save(cover_bytes, format="PNG")
        cover_bytes.seek(0)

        stego_bytes = io.BytesIO()
        stego_img.save(stego_bytes, format="PNG")
        stego_bytes.seek(0)

        data = {
            "cover_image": (cover_bytes, "cover.png"),
            "stego_image": (stego_bytes, "stego.png"),
            "amplification": 100
        }
        res = self.client.post("/api/stego/analyze", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 200)
        res_json = json.loads(res.data)
        self.assertEqual(res_json["status"], "success")
        self.assertIn("diff_image_url", res_json)
        self.assertGreater(res_json["metrics"]["overall_psnr_db"], 50.0)


if __name__ == "__main__":
    unittest.main()
