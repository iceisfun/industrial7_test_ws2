/* Address <-> string conversion of the Winsock helper DLLs (WSHAddressToString / WSHStringToAddress).
 * Measures: the text produced for IPv4, IPv6 (ports, scope ids, mapped and unspecified forms) and Bluetooth
 * addresses, the required-size protocol (the call fails with WSAEFAULT and reports the size that fits, the size
 * counts the terminator), the family and length rules, and the parser's accepted and rejected spellings with the
 * exact bytes it builds. Only loopback-style or invented addresses are used; nothing is resolved or contacted. */
#include "anc.h"

static SOCKADDR_IN mk4(ULONG a, unsigned port) { SOCKADDR_IN s; memset(&s, 0, sizeof s); s.sin_family = AF_INET; s.sin_addr.s_addr = a; s.sin_port = htons(port); return s; }
static SOCKADDR_IN6 mk6(const BYTE *a16, unsigned port, ULONG scope) { SOCKADDR_IN6 s; memset(&s, 0, sizeof s); s.sin6_family = AF_INET6; s.sin6_port = htons(port); s.sin6_scope_id = scope; if (a16) memcpy(&s.sin6_addr, a16, 16); return s; }

/* Format one address; also verifies the size protocol around it. */
static void a2s(const anc_wsh *h, const char *who, const void *sa, INT salen, const WCHAR *want, int exact_size_reported) {
    WCHAR out[128]; DWORD len; INT r;
    DWORD need = (DWORD)wcslen(want) + 1;
    wmemset(out, L'Z', 128); len = 100;
    r = h->AddressToString((LPSOCKADDR)sa, salen, NULL, out, &len);
    CHECKF(r == 0, "%s '%ls': rc %d", who, want, r);
    CHECKF(!wcscmp(out, want), "%s: '%ls' want '%ls'", who, out, want);
    CHECKF(len == need, "%s '%ls': length %lu want %lu", who, want, len, need);
    /* exact fit works, one short fails and reports the fitting size */
    wmemset(out, L'Z', 128); len = need;
    r = h->AddressToString((LPSOCKADDR)sa, salen, NULL, out, &len);
    CHECKF(r == 0 && !wcscmp(out, want) && len == need, "%s '%ls': exact-size buffer rc %d len %lu", who, want, r, len);
    wmemset(out, L'Z', 128); len = need - 1;
    r = h->AddressToString((LPSOCKADDR)sa, salen, NULL, out, &len);
    CHECKF(r == E_FAULT, "%s '%ls': short buffer rc %d", who, want, r);
    if (exact_size_reported) CHECKF(len == need, "%s '%ls': short buffer reported %lu want %lu", who, want, len, need);
    else CHECKF(len == 0, "%s '%ls': short buffer reported %lu want 0", who, want, len);
    wmemset(out, L'Z', 128); len = 0;
    r = h->AddressToString((LPSOCKADDR)sa, salen, NULL, out, &len);
    CHECKF(r == E_FAULT, "%s '%ls': empty buffer rc %d", who, want, r);
}

static void a2s_ip(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    if (hi->af != 32) {
        SOCKADDR_IN a = mk4(0x0100007f, 80); a2s(&h, hi->tag, &a, 16, L"127.0.0.1:80", 1);
        a = mk4(0x0100007f, 0);             a2s(&h, hi->tag, &a, 16, L"127.0.0.1", 1);
        a = mk4(0, 0);                      a2s(&h, hi->tag, &a, 16, L"0.0.0.0", 1);
        a = mk4(0xffffffff, 65535);         a2s(&h, hi->tag, &a, 16, L"255.255.255.255:65535", 1);
        a = mk4(0x04030201, 1);             a2s(&h, hi->tag, &a, 16, L"1.2.3.4:1", 1);
        a = mk4(0x04030201, 1); a.sin_zero[3] = 9; a2s(&h, hi->tag, &a, 16, L"1.2.3.4:1", 1);
        SOCKADDR_STORAGE ss; memset(&ss, 0, sizeof ss); a = mk4(0x0100007f, 443); memcpy(&ss, &a, sizeof a);
        a2s(&h, hi->tag, &ss, 128, L"127.0.0.1:443", 1);
        BYTE loop[16] = { 0 }; loop[15] = 1;
        BYTE mapped[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4 };
        BYTE ll[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        BYTE full[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xcd };
        SOCKADDR_IN6 s = mk6(loop, 80, 0);  a2s(&h, hi->tag, &s, 28, L"[::1]:80", 1);
        s = mk6(loop, 0, 0);                a2s(&h, hi->tag, &s, 28, L"::1", 1);
        s = mk6(loop, 0, 7);                a2s(&h, hi->tag, &s, 28, L"::1%7", 1);
        s = mk6(loop, 80, 7);               a2s(&h, hi->tag, &s, 28, L"[::1%7]:80", 1);
        s = mk6(NULL, 0, 0);                a2s(&h, hi->tag, &s, 28, L"::", 1);
        s = mk6(mapped, 0, 0);              a2s(&h, hi->tag, &s, 28, L"::ffff:1.2.3.4", 1);
        s = mk6(ll, 0, 5);                  a2s(&h, hi->tag, &s, 28, L"fe80::1%5", 1);
        s = mk6(full, 8080, 0);             a2s(&h, hi->tag, &s, 28, L"[2001:db8::abcd]:8080", 1);
        s = mk6(loop, 80, 0);               a2s(&h, hi->tag, &s, 128, L"[::1]:80", 1);
        s.sin6_flowinfo = 0x11223344;       a2s(&h, hi->tag, &s, 28, L"[::1]:80", 1);
    }
}
TEST(a2s_ipv4_and_ipv6_text_wshtcpip) { a2s_ip(&anc_tcp); }
TEST(a2s_ipv4_and_ipv6_text_wship6) { a2s_ip(&anc_ip6); }

TEST(a2s_bluetooth_text) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    anc_sockaddr_bth b; memset(&b, 0, sizeof b); b.family = 32;
    b.bt_addr = 0x665544332211ULL; a2s(&h, "wshbth", &b, 30, L"(66:55:44:33:22:11)", 0);
    b.port = 9;                                a2s(&h, "wshbth", &b, 30, L"(66:55:44:33:22:11):9", 0);
    b.port = 12345;                            a2s(&h, "wshbth", &b, 30, L"(66:55:44:33:22:11):12345", 0);
    b.bt_addr = 0; b.port = 0;                 a2s(&h, "wshbth", &b, 30, L"(00:00:00:00:00:00)", 0);
    b.bt_addr = 0x0a0b0c0d0e0fULL;             a2s(&h, "wshbth", &b, 30, L"(0A:0B:0C:0D:0E:0F)", 0);
    b.bt_addr = 0xffff665544332211ULL;         a2s(&h, "wshbth", &b, 30, L"(66:55:44:33:22:11)", 0);   /* only the low six bytes print */
    BYTE big[64]; memset(big, 0, sizeof big); memcpy(big, &b, 30); a2s(&h, "wshbth", big, 64, L"(66:55:44:33:22:11)", 0);
}

/* Family and length rules of the formatter. */
static void a2s_rules(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    WCHAR out[64]; DWORD len; SOCKADDR_STORAGE ss;
    /* a family the helper does not format */
    static const int fams[] = { 0, 1, 6, 17, 18, 21, 22, 24, 31, 33, 0xffff };
    for (size_t i = 0; i < ANC_N(fams); i++) {
        memset(&ss, 0, sizeof ss); ss.ss_family = (ADDRESS_FAMILY)fams[i]; len = 64; wmemset(out, L'Z', 64);
        INT r = h.AddressToString((LPSOCKADDR)&ss, 32, NULL, out, &len);
        CHECKF(r == E_INVAL || r == E_FAULT, "%s family %d: rc %d", hi->tag, fams[i], r);
    }
    /* sockaddr too short for its family */
    if (hi->af != 32) {
        SOCKADDR_IN a = mk4(0x0100007f, 80);
        for (INT l = 0; l < 16; l += 3) { len = 64; CHECKF(h.AddressToString((LPSOCKADDR)&a, l, NULL, out, &len) == E_FAULT, "%s v4 salen %d", hi->tag, l); }
        CHECKF((len = 64, h.AddressToString((LPSOCKADDR)&a, 15, NULL, out, &len) == E_FAULT), "%s v4 salen 15", hi->tag);
        SOCKADDR_IN6 s = mk6(NULL, 80, 0);
        for (INT l = 0; l < 28; l += 3) { len = 64; CHECKF(h.AddressToString((LPSOCKADDR)&s, l, NULL, out, &len) == E_FAULT, "%s v6 salen %d", hi->tag, l); }
        CHECKF((len = 64, h.AddressToString((LPSOCKADDR)&s, 27, NULL, out, &len) == E_FAULT), "%s v6 salen 27", hi->tag);
    } else {
        anc_sockaddr_bth b; memset(&b, 0, sizeof b); b.family = 32;
        for (INT l = 0; l < 30; l += 4) { len = 64; CHECKF(h.AddressToString((LPSOCKADDR)&b, l, NULL, out, &len) == E_FAULT, "wshbth salen %d", l); }
        CHECKF((len = 64, h.AddressToString((LPSOCKADDR)&b, 29, NULL, out, &len) == E_FAULT), "wshbth salen 29");
    }
}
H3(a2s_family_and_length_rules, a2s_rules)

/* NULL arguments are reported as WSAEFAULT instead of faulting. */
static void a2s_nulls(const anc_hinfo *hi) {
    anc_wsh h; if (!anc_begin(&h, hi)) return;
    SOCKADDR_IN a = mk4(0x0100007f, 80); WCHAR out[32]; DWORD len;
    len = 32; CHECK(h.AddressToString(NULL, 16, NULL, out, &len) == E_FAULT);
    if (hi->af != 32) CHECK(h.AddressToString((LPSOCKADDR)&a, 16, NULL, out, NULL) == E_FAULT);   /* the Bluetooth helper writes the length back without a check */
    len = 0; CHECK(h.AddressToString((LPSOCKADDR)&a, 16, NULL, NULL, &len) == E_FAULT);
    len = 5; CHECK(h.AddressToString((LPSOCKADDR)&a, 16, NULL, NULL, &len) == E_FAULT);
}
H3(a2s_null_arguments, a2s_nulls)

/* ---- parsing ---- */
static void s2a_ok(const anc_wsh *h, const char *who, const WCHAR *s, int fam, DWORD inlen, const void *want, DWORD want_len) {
    BYTE buf[64]; DWORD len = inlen; memset(buf, ANC_FILL, sizeof buf);
    INT r = h->StringToAddress((LPWSTR)s, fam, NULL, (LPSOCKADDR)buf, &len);
    CHECKF(r == 0, "%s '%ls' fam %d: rc %d", who, s, fam, r);
    CHECKF(len == want_len, "%s '%ls': length %lu want %lu", who, s, len, want_len);
    CHECKF(!memcmp(buf, want, want_len), "%s '%ls': bytes differ", who, s);
    for (DWORD i = want_len; i < sizeof buf; i++) if (buf[i] != ANC_FILL) { CHECKF(0, "%s '%ls': byte %lu beyond the result changed", who, s, i); break; }
}
static void s2a_bad(const anc_wsh *h, const char *who, const WCHAR *s, int fam, INT want_rc) {
    BYTE buf[64]; DWORD len = 40; memset(buf, ANC_FILL, sizeof buf);
    INT r = h->StringToAddress((LPWSTR)s, fam, NULL, (LPSOCKADDR)buf, &len);
    CHECKF(r == want_rc, "%s '%ls' fam %d: rc %d want %d", who, s, fam, r, want_rc);
}

TEST(s2a_ipv4_spellings_wshtcpip) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    SOCKADDR_IN w;
    w = mk4(0x0100007f, 0);  s2a_ok(&h, "tcp", L"127.0.0.1", 2, 40, &w, 16);
    w = mk4(0x0100007f, 80); s2a_ok(&h, "tcp", L"127.0.0.1:80", 2, 40, &w, 16);
    w = mk4(0, 0);           s2a_ok(&h, "tcp", L"0.0.0.0", 2, 40, &w, 16);
    w = mk4(0xffffffff, 65535); s2a_ok(&h, "tcp", L"255.255.255.255:65535", 2, 40, &w, 16);
    w = mk4(0x03020100 | 0, 0); w.sin_addr.S_un.S_un_b.s_b1 = 1; w.sin_addr.S_un.S_un_b.s_b2 = 2; w.sin_addr.S_un.S_un_b.s_b3 = 0; w.sin_addr.S_un.S_un_b.s_b4 = 3;
    s2a_ok(&h, "tcp", L"1.2.3", 2, 40, &w, 16);          /* three parts: the last one fills the low 16 bits */
    w = mk4(0x0100007f, 0);  s2a_ok(&h, "tcp", L"127.0.0.1", 2, 16, &w, 16);
    w = mk4(0x0100007f, 0);  s2a_ok(&h, "tcp", L"127.0.0.1", 2, 100, &w, 16);
}

TEST(s2a_ipv4_rejected_spellings_wshtcpip) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    static const WCHAR *bad[] = { L"", L"abc", L"256.1.1.1", L"1.2.3.4.5", L"::1", L"[::1]:80", L"::1:", L"fe80::1%5", L"::ffff:1.2.3.4", L"(11:22:33:44:55:66)",
        L"11:22:33:44:55:66", L"112233445566", L"1:2:3:4:5:6:7:8", L"1::2::3", L"[::1]:99999", L"127.0.0.1:99999", L"127.0.0.1:", L" 127.0.0.1", L"127.0.0.1 " };
    for (size_t i = 0; i < ANC_N(bad); i++) s2a_bad(&h, "tcp", bad[i], 2, E_INVAL);
}

TEST(s2a_foreign_family_wshtcpip) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    static const int fams[] = { 0, 6, 17, 23, 32, 1, 0xffff };
    static const WCHAR *strs[] = { L"127.0.0.1", L"127.0.0.1:80", L"::1", L"[::1]:80", L"(11:22:33:44:55:66)" };
    for (size_t i = 0; i < ANC_N(fams); i++) for (size_t j = 0; j < ANC_N(strs); j++) s2a_bad(&h, "tcp", strs[j], fams[i], E_INVAL);
}

TEST(s2a_buffer_length_rules_wshtcpip) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    BYTE buf[64]; DWORD len;
    for (DWORD l = 0; l < 16; l++) { len = l; memset(buf, ANC_FILL, sizeof buf); CHECKF(h.StringToAddress(L"127.0.0.1", 2, NULL, (LPSOCKADDR)buf, &len) == E_FAULT, "len %lu", l); CHECKF(len == l, "len %lu changed to %lu", l, len); }
    for (DWORD l = 16; l <= 40; l += 8) { len = l; CHECK(h.StringToAddress(L"127.0.0.1", 2, NULL, (LPSOCKADDR)buf, &len) == 0); CHECK(len == 16); }
}

TEST(s2a_null_arguments_wshtcpip) {
    anc_wsh h; if (!anc_begin(&h, &anc_tcp)) return;
    BYTE buf[64]; DWORD len = 40;
    CHECK(h.StringToAddress(NULL, 2, NULL, (LPSOCKADDR)buf, &len) == E_FAULT);
    CHECK(h.StringToAddress(L"127.0.0.1", 2, NULL, NULL, &len) == E_FAULT);
    CHECK(h.StringToAddress(L"127.0.0.1", 2, NULL, (LPSOCKADDR)buf, NULL) == E_FAULT);
}

TEST(s2a_ipv6_spellings_wship6) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    BYTE loop[16] = { 0 }; loop[15] = 1;
    BYTE ll[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    BYTE mapped[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4 };
    BYTE eight[16] = { 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8 };
    SOCKADDR_IN6 w;
    w = mk6(loop, 0, 0);  s2a_ok(&h, "ip6", L"::1", 23, 40, &w, 28);
    w = mk6(loop, 0, 0);  s2a_ok(&h, "ip6", L"[::1]", 23, 40, &w, 28);
    w = mk6(loop, 80, 0); s2a_ok(&h, "ip6", L"[::1]:80", 23, 40, &w, 28);
    w = mk6(ll, 0, 5);    s2a_ok(&h, "ip6", L"fe80::1%5", 23, 40, &w, 28);
    w = mk6(ll, 80, 5);   s2a_ok(&h, "ip6", L"[fe80::1%5]:80", 23, 40, &w, 28);
    w = mk6(mapped, 0, 0); s2a_ok(&h, "ip6", L"::ffff:1.2.3.4", 23, 40, &w, 28);
    w = mk6(eight, 0, 0); s2a_ok(&h, "ip6", L"1:2:3:4:5:6:7:8", 23, 40, &w, 28);
    w = mk6(NULL, 0, 0);  s2a_ok(&h, "ip6", L"::", 23, 40, &w, 28);
    w = mk6(loop, 0, 0);  s2a_ok(&h, "ip6", L"::1", 23, 28, &w, 28);
    w = mk6(loop, 0, 0);  s2a_ok(&h, "ip6", L"::1", 23, 500, &w, 28);
}

TEST(s2a_ipv6_rejected_spellings_wship6) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    static const WCHAR *bad[] = { L"", L"abc", L"127.0.0.1", L"127.0.0.1:80", L"1.2.3", L"256.1.1.1", L"::1:", L"1::2::3", L"[::1]:99999", L"(11:22:33:44:55:66)",
        L"11:22:33:44:55:66", L"112233445566", L"[::1", L"::1]", L"1:2:3:4:5:6:7:8:9", L"g::1", L":::1" };
    for (size_t i = 0; i < ANC_N(bad); i++) s2a_bad(&h, "ip6", bad[i], 23, E_INVAL);
}

TEST(s2a_foreign_family_and_buffer_rules_wship6) {
    anc_wsh h; if (!anc_begin(&h, &anc_ip6)) return;
    static const int fams[] = { 0, 2, 6, 17, 32, 1, 0xffff };
    for (size_t i = 0; i < ANC_N(fams); i++) { s2a_bad(&h, "ip6", L"::1", fams[i], E_INVAL); s2a_bad(&h, "ip6", L"[::1]:80", fams[i], E_INVAL); s2a_bad(&h, "ip6", L"127.0.0.1", fams[i], E_INVAL); }
    /* with the right family the argument checks report WSAEFAULT */
    BYTE buf[64]; DWORD len;
    for (DWORD l = 0; l < 28; l += 3) { len = l; CHECKF(h.StringToAddress(L"::1", 23, NULL, (LPSOCKADDR)buf, &len) == E_FAULT, "len %lu", l); }
    len = 27; CHECK(h.StringToAddress(L"::1", 23, NULL, (LPSOCKADDR)buf, &len) == E_FAULT);
    len = 40; CHECK(h.StringToAddress(NULL, 23, NULL, (LPSOCKADDR)buf, &len) == E_FAULT);
    len = 40; CHECK(h.StringToAddress(L"::1", 23, NULL, NULL, &len) == E_FAULT);
    CHECK(h.StringToAddress(L"::1", 23, NULL, (LPSOCKADDR)buf, NULL) == E_FAULT);
}

TEST(s2a_bluetooth_forms_wshbth) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    anc_sockaddr_bth w; memset(&w, 0, sizeof w); w.family = 32; w.bt_addr = 0x112233445566ULL;
    s2a_ok(&h, "bth", L"(11:22:33:44:55:66)", 32, 40, &w, 30);
    s2a_ok(&h, "bth", L"11:22:33:44:55:66", 32, 40, &w, 30);
    s2a_ok(&h, "bth", L"(11:22:33:44:55:66)", 32, 30, &w, 30);
    s2a_ok(&h, "bth", L"(11:22:33:44:55:66)", 32, 200, &w, 30);
    anc_sockaddr_bth z; memset(&z, 0, sizeof z); z.family = 32;
    s2a_ok(&h, "bth", L"", 32, 40, &z, 30);
    w.bt_addr = 0x0a0b0c0d0e0fULL; s2a_ok(&h, "bth", L"(0a:0b:0c:0d:0e:0f)", 32, 40, &w, 30);
    s2a_ok(&h, "bth", L"(0A:0B:0C:0D:0E:0F)", 32, 40, &w, 30);
}

TEST(s2a_bluetooth_rejections_wshbth) {
    anc_wsh h; if (!anc_begin(&h, &anc_bth)) return;
    static const WCHAR *bad[] = { L"abc", L"127.0.0.1", L"127.0.0.1:80", L"[::1]:80", L"112233445566", L"256.1.1.1", L"1.2.3" };
    for (size_t i = 0; i < ANC_N(bad); i++) s2a_bad(&h, "bth", bad[i], 32, E_INVAL);
    static const int fams[] = { 0, 2, 6, 17, 23, 31, 33, 0xffff };
    for (size_t i = 0; i < ANC_N(fams); i++) s2a_bad(&h, "bth", L"(11:22:33:44:55:66)", fams[i], E_INVAL);
    BYTE buf[64]; DWORD len;
    for (DWORD l = 0; l < 30; l += 3) { len = l; memset(buf, ANC_FILL, sizeof buf); CHECKF(h.StringToAddress(L"(11:22:33:44:55:66)", 32, NULL, (LPSOCKADDR)buf, &len) == E_INVAL, "len %lu", l); CHECKF(len == 30, "len %lu reported %lu", l, len); }
    len = 29; CHECK(h.StringToAddress(L"(11:22:33:44:55:66)", 32, NULL, (LPSOCKADDR)buf, &len) == E_INVAL); CHECK(len == 30);
}

/* The two directions agree: format then parse returns the original bytes. */
TEST(a2s_s2a_roundtrip_ipv4_and_ipv6) {
    anc_wsh t, v; WCHAR out[64]; DWORD len; BYTE back[64];
    if (anc_load_wsh(&t, "wshtcpip.dll")) {
        static const ULONG addrs[] = { 0x0100007f, 0x04030201, 0, 0xffffffff, 0x0200a8c0 };
        static const unsigned ports[] = { 0, 80, 2000, 65535 };
        for (size_t i = 0; i < ANC_N(addrs); i++) for (size_t j = 0; j < ANC_N(ports); j++) {
            SOCKADDR_IN a = mk4(addrs[i], ports[j]); len = 64;
            CHECK(t.AddressToString((LPSOCKADDR)&a, 16, NULL, out, &len) == 0);
            DWORD bl = 64; memset(back, 0, sizeof back);
            CHECKF(t.StringToAddress(out, 2, NULL, (LPSOCKADDR)back, &bl) == 0 && bl == 16 && !memcmp(back, &a, 16), "roundtrip %ls", out);
        }
    }
    if (anc_load_wsh(&v, "wship6.dll")) {
        BYTE addrs[3][16] = { { 0 }, { 0 }, { 0x20, 1, 0x0d, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 } }; addrs[1][15] = 1;
        static const unsigned ports[] = { 0, 80, 65535 };
        for (int i = 0; i < 3; i++) for (size_t j = 0; j < ANC_N(ports); j++) {
            SOCKADDR_IN6 a = mk6(addrs[i], ports[j], 0); len = 64;
            CHECK(v.AddressToString((LPSOCKADDR)&a, 28, NULL, out, &len) == 0);
            DWORD bl = 64; memset(back, 0, sizeof back);
            CHECKF(v.StringToAddress(out, 23, NULL, (LPSOCKADDR)back, &bl) == 0 && bl == 28 && !memcmp(back, &a, 28), "roundtrip %ls", out);
        }
    }
}
