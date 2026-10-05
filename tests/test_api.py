import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import create_app  # noqa: E402
from app.analyzer import Intel, analyze, brand_lookalike  # noqa: E402
from app.demo import demo_email  # noqa: E402


def make_app(**extra):
    d = tempfile.mkdtemp()
    cfg = {"DATABASE_PATH": os.path.join(d, "t.db"), "SEED_DEMO": False, "TESTING": True,
           "THREAT_INTEL_FILE": os.path.join(d, "none.json")}
    cfg.update(extra)
    return create_app(cfg)


class EngineTests(unittest.TestCase):
    def test_lookalike(self):
        self.assertEqual(brand_lookalike("paypa1-support.com")["kind"], "homoglyph")
        self.assertIsNone(brand_lookalike("paypal.com"))
        self.assertIsNone(brand_lookalike("mail.google.com"))
        self.assertEqual(brand_lookalike("paypal-support.com")["kind"], "brand_keyword")

    def test_scores_and_levels(self):
        i = Intel()
        self.assertEqual(analyze(demo_email("bec"), i)["risk"]["level"], "high")
        self.assertEqual(analyze(demo_email("ceo"), i)["risk"]["level"], "high")
        self.assertEqual(analyze(demo_email("credential"), i)["risk"]["level"], "high")
        self.assertEqual(analyze(demo_email("invoice"), i)["risk"]["level"], "medium")
        legit = analyze(demo_email("legit"), i)
        self.assertEqual(legit["risk"]["level"], "low")
        self.assertEqual(legit["reasons"], [])

    def test_distribution_sums_to_100(self):
        for k in ("bec", "ceo", "credential", "invoice", "legit"):
            r = analyze(demo_email(k), Intel())
            self.assertEqual(sum(r["distribution"].values()), 100, k)

    def test_garbage_input_never_raises(self):
        for blob in (b"\x00\xff\xfe" * 500, b"hello world", b"From: \n\n", b"Subject: x\n\n" + b"A" * 300000,
                     b"From: =?bogus?=<<>>\nReply-To: a@@b\nReceived: from [[[ by\n\n<a href=\"http://[::1\">x</a>"):
            r = analyze(blob, Intel())
            self.assertIn(r["risk"]["level"], {"low", "medium", "high"})

    def test_group_address_header_regression(self):
        # stdlib's strict parser used to raise AttributeError on this; the engine must not crash
        r = analyze(b"To: a: b@c, d:;\nFrom: x@y.z\n\nhi", Intel())
        self.assertIn(r["risk"]["level"], {"low", "medium", "high"})

    def test_fuzz_never_crashes(self):
        import random
        rnd = random.Random(11)
        frag = [b"From: ", b"To: ", b"Reply-To: ", b"Received: from ", b" by ", b"[1.2.3.4]", b"=?utf-8?B?", b"\n\n", b"<a href=\"",
                b"http://", b"@", b"Content-Type: multipart/mixed; boundary=X\n", b"--X\n", b"\x00", b"\xff\xfe", b"a: b@c, d:;",
                b"Content-Disposition: attachment; filename=\"a.exe\"\n", b"http://[::1", b"urgent wire transfer"]
        for _ in range(800):
            blob = b"".join(rnd.choice(frag) if rnd.random() < .5 else rnd.randbytes(rnd.randint(0, 10)) for _ in range(rnd.randint(1, 50)))
            r = analyze(blob, Intel())
            self.assertTrue(0 <= r["risk"]["score"] <= 100)
            self.assertEqual(sum(r["distribution"].values()), 100)

    def test_untrusted_content_is_data_only(self):
        raw = b"From: <script>alert(1)</script>@evil.com\nSubject: <img src=x onerror=alert(1)>\n\nhi"
        r = analyze(raw, Intel())
        self.assertIsInstance(r["identity"]["subject"], str)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.app = make_app()
        self.c = self.app.test_client()

    def test_health(self):
        self.assertEqual(self.c.get("/healthz").status_code, 200)
        self.assertEqual(self.c.get("/api/health").get_json()["status"], "ok")

    def test_index_and_headers(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")

    def test_analyze_json_and_file(self):
        r = self.c.post("/api/analyze", json={"raw": demo_email("bec").decode()})
        self.assertEqual(r.status_code, 201)
        res = r.get_json()
        self.assertEqual(res["risk"]["level"], "high")
        r2 = self.c.post("/api/analyze", data={"file": (io.BytesIO(demo_email("legit")), "x.eml")},
                         content_type="multipart/form-data")
        self.assertEqual(r2.status_code, 201)
        self.assertEqual(self.c.get(f"/api/analyses/{res['id']}").get_json()["id"], res["id"])
        self.assertEqual(len(self.c.get("/api/analyses").get_json()), 2)

    def test_validation_errors(self):
        self.assertEqual(self.c.post("/api/analyze", json={"raw": ""}).status_code, 400)
        self.assertEqual(self.c.post("/api/analyze", json={"raw": 5}).status_code, 400)
        self.assertEqual(self.c.post("/api/analyze", data="x", content_type="text/plain").status_code, 400)
        self.assertEqual(self.c.get("/api/analyses/nope").status_code, 404)
        self.assertEqual(self.c.get("/api/analyses/ST-0000000000").status_code, 404)
        self.assertEqual(self.c.post("/api/demo?kind=zzz").status_code, 400)
        self.assertEqual(self.c.get("/api/nothing").status_code, 404)
        self.assertEqual(self.c.get("/api/cases/abc").status_code, 404)
        self.assertEqual(self.c.get("/api/cases/CASE-9999").status_code, 404)

    def test_upload_limit(self):
        app = make_app(MAX_UPLOAD_MB=1, MAX_CONTENT_LENGTH=1024 * 1024 + 4096)
        c = app.test_client()
        r = c.post("/api/analyze", data={"file": (io.BytesIO(b"A" * (2 * 1024 * 1024)), "big.eml")},
                   content_type="multipart/form-data")
        self.assertEqual(r.status_code, 413)
        self.assertIn("error", r.get_json())

    def test_stats_cases_evidence_report(self):
        a = self.c.post("/api/demo?kind=bec").get_json()
        self.c.post("/api/demo?kind=legit")
        st = self.c.get("/api/stats").get_json()
        self.assertEqual((st["emails_analyzed"], st["threats_detected"], st["high_risk"]), (2, 1, 1))
        case = self.c.post(f"/api/analyses/{a['id']}/case", json={}).get_json()
        again = self.c.post(f"/api/analyses/{a['id']}/case", json={}).get_json()
        self.assertEqual(case["id"], again["id"])  # idempotent
        self.assertEqual(self.c.post(f"/api/cases/{case['id']}/notes", json={"note": "Blocked domain"}).status_code, 201)
        self.assertEqual(self.c.post(f"/api/cases/{case['id']}/notes", json={"note": " "}).status_code, 400)
        self.assertEqual(self.c.patch(f"/api/cases/{case['id']}", json={"status": "Resolved"}).get_json()["status"], "Resolved")
        self.assertEqual(self.c.patch(f"/api/cases/{case['id']}", json={"status": "bogus"}).status_code, 400)
        ev = self.c.get("/api/evidence").get_json()
        self.assertTrue(all(e["verified"] for e in ev))
        rep = self.c.get(f"/api/analyses/{a['id']}/report")
        self.assertEqual(rep.status_code, 200)
        self.assertIn(b"Forensic Investigation Report", rep.data)
        self.assertNotIn(b"<script", rep.data)
        self.assertEqual(self.c.get(f"/api/analyses/{a['id']}/report?format=json").status_code, 200)
        eml = self.c.get(f"/api/analyses/{a['id']}/eml")
        import hashlib
        self.assertEqual(hashlib.sha256(eml.data).hexdigest(), a["evidence"]["sha256"])
        self.assertGreater(len(self.c.get("/api/audit").get_json()), 3)

    def test_report_escapes_html(self):
        raw = b"From: x <a@evil.test>\nSubject: <script>alert(1)</script>\nTo: b@c.test\n\nurgent payment invoice"
        a = self.c.post("/api/analyze", json={"raw": raw.decode()}).get_json()
        rep = self.c.get(f"/api/analyses/{a['id']}/report").data
        self.assertNotIn(b"<script>alert(1)</script>", rep)

    def test_evidence_tamper_detection(self):
        a = self.c.post("/api/demo?kind=bec").get_json()
        import sqlite3
        conn = sqlite3.connect(self.app.config["DATABASE_PATH"])
        conn.execute("UPDATE analyses SET raw=? WHERE id=?", (b"tampered", a["id"]))
        conn.commit()
        conn.close()
        ev = self.c.get("/api/evidence").get_json()
        self.assertFalse(ev[0]["verified"])

    def test_campaign_clustering(self):
        self.c.post("/api/demo?kind=bec")
        self.c.post("/api/demo?kind=bec")
        self.c.post("/api/demo?kind=ceo")
        camps = self.c.get("/api/campaigns").get_json()
        self.assertEqual(len(camps), 1)
        self.assertEqual(camps[0]["emails"], 2)

    def test_api_key_and_rate_limit(self):
        app = make_app(API_KEY="s3cret", RATE_LIMIT_PER_MIN=3)
        c = app.test_client()
        self.assertEqual(c.get("/api/stats").status_code, 401)
        self.assertEqual(c.get("/api/stats", headers={"X-API-Key": "wrong"}).status_code, 401)
        self.assertEqual(c.get("/api/health").status_code, 200)
        self.assertTrue(c.get("/api/config").get_json()["auth_required"])
        h = {"X-API-Key": "s3cret"}
        codes = [c.post("/api/demo?kind=legit", headers=h).status_code for _ in range(5)]
        self.assertEqual(codes, [201, 201, 201, 429, 429])

    def test_seed(self):
        app = make_app(SEED_DEMO=True)
        c = app.test_client()
        st = c.get("/api/stats").get_json()
        self.assertEqual(st["emails_analyzed"], 6)
        self.assertGreaterEqual(st["active_campaigns"], 1)
        self.assertTrue(c.get("/api/config").get_json()["demo_data"])

    def test_search(self):
        self.c.post("/api/demo?kind=bec")
        self.assertEqual(len(self.c.get("/api/analyses?q=paypa1").get_json()), 1)
        self.assertEqual(len(self.c.get("/api/analyses?q=zzzz").get_json()), 0)


if __name__ == "__main__":
    unittest.main()
