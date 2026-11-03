#!/usr/bin/env python3
"""Unit test for win10_results.py with a fabricated log. Run: python3 tools/test_win10_results.py"""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import win10_results as W

LOG = """boot noise
WS2T begin modes=adm,std exes=4 timeout=60
WS2T os build=19045 version=10.0.19045 sku=48 arch=64-bit
WS2T mode adm
WS2T start ws2_probe
WS2T out ws2_probe | PROBE loopback=ok
WS2T rc ws2_probe 0 0.3
WS2T start a
WS2T out a | RUN  t1
WS2T out a | OK   t1
WS2T out a |   FAIL x.c:3: CHECK(x) (got 1)
WS2T out a | FAIL t2
WS2T out a | SKIP t3
WS2T out a |   SKIP no touch
WS2T out a | SUMMARY tests=3 failed=1 skipped=1 checks_pass=5 checks_fail=1
WS2T rc a 1 1.5
WS2T start b
WS2T out b | OK   u1
WS2T rc b 0xc0000005 0.2
WS2T start c
WS2T rc c TIMEOUT 60
WS2T mode std
WS2T stdkind real-user
WS2T start d
WS2T out d | OK   v1
"""
class T(unittest.TestCase):
    def test_parse(self):
        r = W.parse(LOG); runs = {(x["mode"], x["exe"]): x for x in r["runs"]}
        self.assertFalse(r["done"])
        a = runs[("adm", "a")]
        self.assertEqual((a["tests"], a["failed"], a["skipped"], a["checks_fail"], a["status"]), (3, 1, 1, 1, "OK"))
        self.assertEqual(a["results"], [("OK", "t1"), ("FAIL", "t2"), ("SKIP", "t3")])
        self.assertEqual(runs[("adm", "b")]["status"], "NOSUMMARY")
        self.assertEqual(runs[("adm", "c")]["status"], "TIMEOUT")
        self.assertEqual(runs[("std", "d")]["status"], "HANG")
        self.assertEqual(runs[("adm", "ws2_probe")]["probe"], ["loopback=ok"])
        self.assertEqual(runs[("adm", "ws2_probe")]["status"], "OUT")
        self.assertEqual(r["info"]["stdkind"], "real-user")
if __name__ == "__main__": unittest.main()
