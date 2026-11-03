/* The wsock32-only exports (all forwarded to mswsock): BSD-era stubs, DNS name expansion, the
 * Winsock 1.1 name-service helpers and the protocol/namespace enumerations.
 *
 * Measures:
 *  - the fixed-answer stubs: getnetbyname, rcmd, rexec, rresvport, sethostname (a failure value and a fixed
 *    WSA error, no Winsock startup needed), the three rcmd-family names sharing one body;
 *  - dn_expand on hand-built DNS messages: label joining, '.' escaping, compression pointers, bounds, the
 *    consumed-length return value;
 *  - EnumProtocolsA/W: buffer protocol (ERROR_INSUFFICIENT_BUFFER, not a WSA code), struct contents against
 *    WSAEnumProtocols, filter list, works without WSAStartup;
 *  - GetTypeByName / GetNameByType service-id mapping for TCP and UDP ports, error codes;
 *  - GetAddressByName / GetService / SetService argument validation and fixed error codes;
 *  - NPLoadNameSpaces layout; WSApSetPostRoutine; s_perror output; WEP; __WSAFDIsSet. */
#include "wf.h"

#define E_NOT_SUPPORTED  50
#define E_INVALID_PARAM  87
#define E_INSUFFICIENT   122
#define E_SVC_NOT_EXIST  1060

static const GUID k_unknown_guid = { 0x4d3a7c91, 0x6b22, 0x4e0f, { 0x8a, 0x11, 0x5c, 0x9e, 0x01, 0x77, 0xd3, 0x2b } };

/* ---------------------------------------------------------------- stubs */
TEST(stub_getnetbyname_returns_null_with_fixed_error) {
    p_getnetbyname f = WS(getnetbyname); void *r;
    REQUIRE(f);
    wf_seterr(0);
    r = f("loopback");
    CHECK(r == NULL);
    WEQ(wf_err(), WSA_ERR_VERNOTSUPPORTED);
}
TEST(stub_getnetbyname_ignores_its_argument) {
    p_getnetbyname f = WS(getnetbyname); void *r;
    static const char *names[] = { "", "x", "loopback", "localnet", "arpanet" };
    unsigned i;
    REQUIRE(f);
    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        wf_seterr(0);
        r = f(names[i]);
        CHECK(r == NULL);
        CHECKF(wf_err() == WSA_ERR_VERNOTSUPPORTED, "%s -> %d", names[i], wf_err());
    }
}
TEST(stub_getnetbyname_with_null_name) {
    p_getnetbyname f = WS(getnetbyname);
    REQUIRE(f);
    wf_seterr(0);
    CHECK(f(NULL) == NULL);
    WEQ(wf_err(), WSA_ERR_VERNOTSUPPORTED);
}
TEST(stub_getnetbyname_with_winsock_started) {
    p_getnetbyname f = WS(getnetbyname);
    REQUIRE(f);
    WF_UP();
    wf_seterr(0);
    CHECK(f("loopback") == NULL);
    WEQ(wf_err(), WSA_ERR_VERNOTSUPPORTED);
    wf_down();
}
TEST(stub_rcmd_fails_with_fixed_error) {
    p_rcmd f = WS(rcmd); INT_PTR r;
    REQUIRE(f);
    wf_seterr(0);
    r = f(NULL, 0, NULL, NULL, NULL, NULL);
    WEQ((int)r, -1);
    WEQ(wf_err(), WSA_ERR_VERNOTSUPPORTED);
}
TEST(stub_rexec_fails_with_fixed_error) {
    p_rexec f = WS(rexec); INT_PTR r;
    REQUIRE(f);
    wf_seterr(0);
    r = f(NULL, 0, NULL, NULL, NULL, NULL);
    WEQ((int)r, -1);
    WEQ(wf_err(), WSA_ERR_VERNOTSUPPORTED);
}
TEST(stub_rresvport_fails_with_fixed_error) {
    p_rresvport f = WS(rresvport); INT_PTR r;
    REQUIRE(f);
    wf_seterr(0);
    r = f(NULL);
    WEQ((int)r, -1);
    WEQ(wf_err(), WSA_ERR_VERNOTSUPPORTED);
}
TEST(stub_rcmd_family_return_is_full_width_minus_one) {
    p_rcmd f = WS(rcmd); INT_PTR r;
    REQUIRE(f);
    r = f(NULL, 0, NULL, NULL, NULL, NULL);
    CHECK(r == (INT_PTR)-1);       /* a SOCKET-width failure: INVALID_SOCKET */
}
TEST(stub_rcmd_family_no_startup_needed_and_error_is_wsa_slot) {
    p_rcmd f = WS(rcmd);
    REQUIRE(f);
    SetLastError(0);
    f(NULL, 0, NULL, NULL, NULL, NULL);
    WEQ(GetLastError(), WSA_ERR_VERNOTSUPPORTED);     /* WSAGetLastError and GetLastError share the slot */
}
TEST(stub_sethostname_fails_with_fixed_error) {
    p_sethostname f = WS(sethostname); int r;
    REQUIRE(f);
    wf_seterr(0);
    r = f("whatever", 8);
    WEQ(r, -1);
    WEQ(wf_err(), WSA_ERR_VERNOTSUPPORTED);
}
TEST(stub_sethostname_does_not_change_the_host_name) {
    p_sethostname f = WS(sethostname); p_gethostname g = W2(gethostname);
    char before[256], after[256];
    REQUIRE(f); REQUIRE(g);
    WF_UP();
    CHECK(g(before, sizeof before) == 0);
    f("renamed-by-test", 15);
    CHECK(g(after, sizeof after) == 0);
    EXPECT_STR(after, before);
    wf_down();
}
TEST(stub_sethostname_with_null_name) {
    p_sethostname f = WS(sethostname);
    REQUIRE(f);
    wf_seterr(0);
    WEQ(f(NULL, 0), -1);
    WEQ(wf_err(), WSA_ERR_VERNOTSUPPORTED);
}

/* ---------------------------------------------------------------- dn_expand */
typedef struct { const char *name; const unsigned char *msg; int msglen; int off; int outlen; int want_ret; const char *want_str; } dn_case;

static int run_dn(const unsigned char *msg, int msglen, int off, char *out, int outlen, int *ret) {
    p_dn_expand f = WS(dn_expand);
    if (!f) return 0;
    memset(out, 0x5A, (size_t)outlen);
    *ret = f(msg, msg + msglen, msg + off, (unsigned char *)out, outlen);
    return 1;
}

#define DN(nm, bytes, off, outlen, wret, wstr) \
TEST(dn_expand_##nm) { \
    static const unsigned char m[] = bytes; char out[512]; int r; \
    REQUIRE(WS(dn_expand)); \
    run_dn(m, (int)sizeof m - 1, off, out, outlen, &r); \
    WEQ(r, wret); \
    if ((wret) >= 0) EXPECT_STR(out, wstr); \
}

DN(single_label,       "\x03" "www\x00", 0, 64, 5, "www")
DN(two_labels,         "\x03" "www\x07" "example\x00", 0, 64, 13, "www.example")
DN(three_labels,       "\x03" "www\x07" "example\x03" "com\x00", 0, 64, 17, "www.example.com")
DN(root_name,          "\x00", 0, 8, 1, "")
DN(one_char_label,     "\x01" "a\x00", 0, 8, 3, "a")
DN(max_length_label,   "\x3f" "0123456789012345678901234567890123456789012345678901234567890AB\x00", 0, 128, 65, "0123456789012345678901234567890123456789012345678901234567890AB")
DN(second_name_in_message, "\x01" "x\x00" "\x02" "ab\x01" "c\x00", 3, 64, 6, "ab.c")
DN(escape_dot_in_label, "\x03" "a.b\x00", 0, 64, 5, "a\\.b")
DN(escape_dot_leading,  "\x02" ".x\x00", 0, 64, 4, "\\.x")
DN(escape_dot_two_labels, "\x03" "a.b\x01" "c\x00", 0, 64, 7, "a\\.b.c")
DN(digits_and_hyphen,   "\x05" "a-b_9\x02" "z1\x00", 0, 64, 10, "a-b_9.z1")
DN(high_bytes_copied_raw, "\x03" "\x80\xfe\xff\x00", 0, 64, 5, "\x80\xfe\xff")
DN(uppercase_kept,      "\x04" "AbCd\x00", 0, 64, 6, "AbCd")

/* compression pointers */
DN(pointer_to_earlier_name,  "\x07" "example\x03" "com\x00" "\x03" "www\xc0\x00", 13, 64, 6, "www.example.com")
DN(pointer_only,        "\x03" "foo\x00" "\xc0\x00", 5, 64, 2, "foo")
DN(pointer_to_suffix,   "\x03" "foo\x03" "bar\x00" "\x01" "x\xc0\x04", 9, 64, 4, "x.bar")
DN(pointer_chain,       "\x03" "abc\x00" "\xc0\x00" "\xc0\x05", 7, 64, 2, "abc")
DN(pointer_return_counts_only_up_to_pointer, "\x02" "hi\x00" "\x01" "a\x01" "b\xc0\x00", 4, 64, 6, "a.b.hi")

/* failures */
DN(label_flag_01_rejected, "\x41" "abcd\x00", 0, 64, -1, "")
DN(label_flag_10_rejected, "\x81" "a\x00", 0, 64, -1, "")
DN(pointer_at_end_of_message, "\x03" "abc\x00" "\xc0", 5, 64, -1, "")
DN(pointer_past_message,  "\xc0\x30", 0, 64, -1, "")
DN(unterminated_name_hits_end, "\x03" "abc", 0, 64, -1, "")
DN(label_longer_than_message, "\x09" "abc", 0, 64, -1, "")
DN(self_pointer_loop,     "\xc0\x00", 0, 64, -1, "")
DN(two_pointer_loop,      "\xc0\x02\xc0\x00", 0, 64, -1, "")
DN(output_exact_minimum_ok, "\x01" "a\x00", 0, 2, 3, "a")
DN(output_one_short_fails, "\x01" "a\x00", 0, 1, -1, "")
DN(output_zero_length_fails, "\x01" "a\x00", 0, 0, -1, "")
DN(output_too_small_for_second_label, "\x01" "a\x01" "b\x00", 0, 3, -1, "")
DN(output_just_fits_two_labels, "\x01" "a\x01" "b\x00", 0, 4, 5, "a.b")

TEST(dn_expand_terminator_always_written) {
    static const unsigned char m[] = "\x02" "ab\x00";
    char out[16];
    int r;
    REQUIRE(WS(dn_expand));
    run_dn(m, (int)sizeof m - 1, 0, out, sizeof out, &r);
    WEQ(r, 4);
    WEQ(out[2], 0);
    EXPECT_STR(out, "ab");
}
TEST(dn_expand_does_not_write_past_requested_length) {
    static const unsigned char m[] = "\x03" "abc\x00";
    char out[16];
    int r;
    REQUIRE(WS(dn_expand));
    memset(out, 0x77, sizeof out);
    r = WS(dn_expand)(m, m + sizeof m - 1, m, (unsigned char *)out, 3);
    WEQ(r, -1);                          /* "abc" plus its terminator needs 4 */
    memset(out, 0x77, sizeof out);
    r = WS(dn_expand)(m, m + sizeof m - 1, m, (unsigned char *)out, 4);
    WEQ(r, 5);                           /* 5 bytes of the message consumed */
    WEQ(out[3], 0);
    WEQ(out[4], 0x77);                   /* byte after the buffer untouched */
}
TEST(dn_expand_needs_no_winsock_startup) {
    static const unsigned char m[] = "\x01" "q\x00";
    char out[8];
    int r;
    REQUIRE(WS(dn_expand));
    run_dn(m, (int)sizeof m - 1, 0, out, sizeof out, &r);
    WEQ(r, 3);
}
TEST(dn_expand_name_ending_exactly_at_message_end) {
    /* the terminating zero must lie inside the message */
    static const unsigned char m[] = "\x01" "q\x00";
    char out[8];
    int r;
    REQUIRE(WS(dn_expand));
    run_dn(m, 3, 0, out, sizeof out, &r);
    WEQ(r, 3);
    run_dn(m, 2, 0, out, sizeof out, &r);
    WEQ(r, -1);
}

/* ---------------------------------------------------------------- EnumProtocols */
static int enum_wide(LPINT filter, WSAPROTOCOL_INFOW **out, int *n_out) {
    DWORD len = 0; int n;
    wf_seterr(0);
    typedef int (WSAAPI *p_wep)(LPINT, LPWSAPROTOCOL_INFOW, LPDWORD);
    p_wep f = (p_wep)t_proc_in("ws2_32.dll", "WSAEnumProtocolsW");
    if (!f) return 0;
    f(filter, NULL, &len);
    *out = (WSAPROTOCOL_INFOW *)HeapAlloc(GetProcessHeap(), 0, len);
    if (!*out) return 0;
    n = f(filter, *out, &len);
    if (n < 0) { HeapFree(GetProcessHeap(), 0, *out); return 0; }
    *n_out = n;
    return 1;
}

typedef struct { DWORD flags; int af, maxsa, minsa, type, proto; DWORD msgsize; void *name; } penum; /* 32-byte head used by both widths */

TEST(enumprotocols_w_size_query_fails_insufficient_buffer) {
    p_EnumProtocolsW f = WS(EnumProtocolsW); DWORD len = 0; INT r;
    REQUIRE(f);
    SET_ERR(0);
    r = f(NULL, NULL, &len);
    WEQ(r, -1);
    WEQ(GetLastError(), E_INSUFFICIENT);
    CHECK(len >= sizeof(penum) + 8);
}
TEST(enumprotocols_a_size_query_fails_insufficient_buffer) {
    p_EnumProtocolsA f = WS(EnumProtocolsA); DWORD len = 0; INT r;
    REQUIRE(f);
    SET_ERR(0);
    r = f(NULL, NULL, &len);
    WEQ(r, -1);
    WEQ(GetLastError(), E_INSUFFICIENT);
    CHECK(len > 0);
}
TEST(enumprotocols_error_is_not_a_wsa_code) {
    p_EnumProtocolsW f = WS(EnumProtocolsW); DWORD len = 0;
    REQUIRE(f);
    SET_ERR(0);
    f(NULL, NULL, &len);
    CHECK(GetLastError() != WSAENOBUFS);
    CHECK(GetLastError() < 10000);
}
TEST(enumprotocols_w_works_without_startup) {
    p_EnumProtocolsW f = WS(EnumProtocolsW); DWORD len = 0, need; INT n; void *buf;
    REQUIRE(f);
    f(NULL, NULL, &len);
    need = len;
    buf = HeapAlloc(GetProcessHeap(), 0, need);
    n = f(NULL, buf, &len);
    CHECK(n > 0);
    CHECK(len <= need);
    HeapFree(GetProcessHeap(), 0, buf);
}
CHILD(wf_enumprotocols_nostartup) {
    HMODULE m = LoadLibraryA("wsock32.dll");
    p_EnumProtocolsA fa; p_EnumProtocolsW fw; DWORD len = 0; INT n; void *buf;
    if (!m) return 1;
    fa = (p_EnumProtocolsA)GetProcAddress(m, "EnumProtocolsA"); fw = (p_EnumProtocolsW)GetProcAddress(m, "EnumProtocolsW");
    if (!fa || !fw) return 2;
    if (fw(NULL, NULL, &len) != -1 || len == 0) return 3;
    buf = HeapAlloc(GetProcessHeap(), 0, len);
    n = fw(NULL, buf, &len);
    if (n <= 0) return 4;
    /* it started and stopped Winsock on its own: a bare socket call is still refused */
    {
        p_socket sk = (p_socket)GetProcAddress(LoadLibraryA("wsock32.dll"), "socket");
        p_WSAGetLastError e = (p_WSAGetLastError)GetProcAddress(LoadLibraryA("wsock32.dll"), "WSAGetLastError");
        if (sk(AF_INET, SOCK_STREAM, 0) != INVALID_SOCKET) return 5;
        if (e() != WSANOTINITIALISED) return 6;
    }
    return 0;
}
TEST(enumprotocols_leaves_winsock_not_started) { WF_RUN_CHILD("wf_enumprotocols_nostartup", ""); }

TEST(enumprotocols_w_entries_well_formed) {
    p_EnumProtocolsW f = WS(EnumProtocolsW); DWORD len = 0, cap; INT n, i; BYTE *buf; DWORD bad = 0;
    REQUIRE(f);
    f(NULL, NULL, &len);
    cap = len;
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, cap);
    n = f(NULL, buf, &len);
    CHECK(n > 0);
    for (i = 0; i < n; i++) {
        penum *e = (penum *)(buf + (size_t)i * 40);
        const WCHAR *name = (const WCHAR *)e->name;
        if (!name || (const BYTE *)name < buf + (size_t)n * 40 || (const BYTE *)name >= buf + cap) { bad++; continue; }
        if (!name[0]) bad++;
        if (e->af == 0 && e->type == 0 && e->proto == 0) bad++;
    }
    WEQ(bad, 0);
    HeapFree(GetProcessHeap(), 0, buf);
}
TEST(enumprotocols_w_entries_versus_catalog_noted) {
    p_EnumProtocolsW f = WS(EnumProtocolsW); DWORD len = 0; INT n, i, j, wn = 0, missing = 0; BYTE *buf; WSAPROTOCOL_INFOW *wp = NULL;
    REQUIRE(f);
    WF_UP();
    f(NULL, NULL, &len);
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, len);
    n = f(NULL, buf, &len);
    if (n <= 0 || !enum_wide(NULL, &wp, &wn)) { CHECK(0); wf_down(); return; }
    for (i = 0; i < n; i++) {
        penum *e = (penum *)(buf + (size_t)i * 40);
        int found = 0;
        for (j = 0; j < wn; j++)
            if (wp[j].iAddressFamily == e->af && wp[j].iSocketType == e->type && wp[j].iProtocol == e->proto &&
                !lstrcmpW(wp[j].szProtocol, (const WCHAR *)e->name)) found = 1;
        if (!found) missing++;
    }
    t_note("EnumProtocolsW entries without a catalog twin: %d of %d", missing, n);   /* helper-supplied entries come first */
    HeapFree(GetProcessHeap(), 0, wp); HeapFree(GetProcessHeap(), 0, buf);
    wf_down();
}
TEST(enumprotocols_w_covers_every_family_type_proto_triple) {
    p_EnumProtocolsW f = WS(EnumProtocolsW); DWORD len = 0; INT n, i, j, wn = 0, missing = 0; BYTE *buf; WSAPROTOCOL_INFOW *wp = NULL;
    REQUIRE(f);
    WF_UP();
    f(NULL, NULL, &len);
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, len);
    n = f(NULL, buf, &len);
    if (n <= 0 || !enum_wide(NULL, &wp, &wn)) { CHECK(0); wf_down(); return; }
    for (j = 0; j < wn; j++) {
        int found = 0;
        for (i = 0; i < n; i++) {
            penum *e = (penum *)(buf + (size_t)i * 40);
            if (wp[j].iAddressFamily == e->af && wp[j].iSocketType == e->type && wp[j].iProtocol == e->proto) found = 1;
        }
        if (!found) missing++;
    }
    WEQ(missing, 0);
    HeapFree(GetProcessHeap(), 0, wp); HeapFree(GetProcessHeap(), 0, buf);
    wf_down();
}
TEST(enumprotocols_w_tcp_udp_fixed_fields) {
    p_EnumProtocolsW f = WS(EnumProtocolsW); DWORD len = 0; INT n, i, tcp4 = 0, udp4 = 0; BYTE *buf;
    REQUIRE(f);
    f(NULL, NULL, &len);
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, len);
    n = f(NULL, buf, &len);
    for (i = 0; i < n; i++) {
        penum *e = (penum *)(buf + (size_t)i * 40);
        if (e->af == AF_INET && e->type == SOCK_STREAM && e->proto == IPPROTO_TCP) {
            tcp4++;
            WEQ(e->maxsa, sizeof(struct sockaddr_in));
            WEQ(e->minsa, sizeof(struct sockaddr_in));
            WEQ(e->msgsize, 0);
        }
        if (e->af == AF_INET && e->type == SOCK_DGRAM && e->proto == IPPROTO_UDP) {
            udp4++;
            WEQ(e->maxsa, sizeof(struct sockaddr_in));
            WEQ(e->minsa, sizeof(struct sockaddr_in));
            WEQ(e->msgsize, 65527);        /* the helper's datagram size, not the 65467 of the catalog */
        }
    }
    CHECK(tcp4 >= 1);
    CHECK(udp4 >= 1);
    HeapFree(GetProcessHeap(), 0, buf);
}
TEST(enumprotocols_w_filter_tcp_only) {
    p_EnumProtocolsW f = WS(EnumProtocolsW); INT filter[] = { IPPROTO_TCP, 0 }; DWORD len = 0; INT n, i; BYTE *buf; int other = 0;
    REQUIRE(f);
    f(filter, NULL, &len);
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, len);
    n = f(filter, buf, &len);
    CHECK(n >= 1);
    for (i = 0; i < n; i++) if (((penum *)(buf + (size_t)i * 40))->proto != IPPROTO_TCP) other++;
    t_note("filter {TCP}: %d entries, %d of other protocols", n, other);   /* the helper part is not filtered */
    HeapFree(GetProcessHeap(), 0, buf);
}
TEST(enumprotocols_w_filter_unknown_protocol_yields_nothing_or_error) {
    p_EnumProtocolsW f = WS(EnumProtocolsW); INT filter[] = { 0x7777, 0 }; DWORD len = 0; INT n; BYTE *buf;
    REQUIRE(f);
    f(filter, NULL, &len);
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, len + 64);
    len += 64;
    n = f(filter, buf, &len);
    t_note("filter {0x7777}: count %d", n);
    HeapFree(GetProcessHeap(), 0, buf);
}
TEST(enumprotocols_a_matches_w) {
    p_EnumProtocolsA fa = WS(EnumProtocolsA); p_EnumProtocolsW fw = WS(EnumProtocolsW);
    DWORD la = 0, lw = 0; INT na, nw, i, diff = 0; BYTE *ba, *bw;
    REQUIRE(fa); REQUIRE(fw);
    fa(NULL, NULL, &la); fw(NULL, NULL, &lw);
    ba = (BYTE *)HeapAlloc(GetProcessHeap(), 0, la); bw = (BYTE *)HeapAlloc(GetProcessHeap(), 0, lw);
    na = fa(NULL, ba, &la); nw = fw(NULL, bw, &lw);
    WEQ(na, nw);
    for (i = 0; i < na && i < nw; i++) {
        penum *a = (penum *)(ba + (size_t)i * 40), *w = (penum *)(bw + (size_t)i * 40);
        char conv[256];
        if (a->flags != w->flags || a->af != w->af || a->type != w->type || a->proto != w->proto || a->maxsa != w->maxsa) diff++;
        WideCharToMultiByte(CP_ACP, 0, (const WCHAR *)w->name, -1, conv, sizeof conv, NULL, NULL);
        if (strcmp(conv, (const char *)a->name)) diff++;
    }
    WEQ(diff, 0);
    HeapFree(GetProcessHeap(), 0, ba); HeapFree(GetProcessHeap(), 0, bw);
}
TEST(enumprotocols_w_exact_size_buffer_succeeds) {
    p_EnumProtocolsW f = WS(EnumProtocolsW); DWORD len = 0, need; INT n; BYTE *buf;
    REQUIRE(f);
    f(NULL, NULL, &len);
    need = len;
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, need);
    n = f(NULL, buf, &len);
    CHECK(n > 0);
    CHECK(len <= need);
    HeapFree(GetProcessHeap(), 0, buf);
}
TEST(enumprotocols_w_small_buffer_reports_required_size) {
    p_EnumProtocolsW f = WS(EnumProtocolsW); DWORD len = 0, need; INT n; BYTE buf[16];
    REQUIRE(f);
    f(NULL, NULL, &len);
    need = len;
    len = sizeof buf;
    SET_ERR(0);
    n = f(NULL, buf, &len);
    WEQ(n, -1);
    WEQ(GetLastError(), E_INSUFFICIENT);
    WEQ(len, need);
}
TEST(enumprotocols_entry_names_live_inside_buffer_after_array) {
    p_EnumProtocolsW f = WS(EnumProtocolsW); DWORD len = 0, cap; INT n, i, out = 0; BYTE *buf;
    REQUIRE(f);
    f(NULL, NULL, &len);
    cap = len;
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, cap);
    n = f(NULL, buf, &len);
    for (i = 0; i < n; i++) {
        const BYTE *nm = (const BYTE *)((penum *)(buf + (size_t)i * 40))->name;
        if (nm < buf + (size_t)n * 40 || nm >= buf + cap) out++;
    }
    WEQ(out, 0);
    HeapFree(GetProcessHeap(), 0, buf);
}

/* ---------------------------------------------------------------- GetTypeByName / GetNameByType */

static int svc_port(const char *name, const char *proto, int *port_host) {
    struct servent *se;
    if (!W2(getservbyname)) return 0;
    se = W2(getservbyname)(name, proto);
    if (!se) return 0;
    *port_host = wf_sw16((unsigned short)se->s_port);
    return 1;
}
static void expect_svcid(const GUID *g, unsigned tag, int port) {
    WEQ(g->Data1, (tag << 16) | (unsigned)port);
    WEQ(g->Data2, 0);
    WEQ(g->Data3, 0);
    WEQ(g->Data4[0], 0xC0);
    WEQ(g->Data4[1], 0); WEQ(g->Data4[2], 0); WEQ(g->Data4[3], 0);
    WEQ(g->Data4[4], 0); WEQ(g->Data4[5], 0); WEQ(g->Data4[6], 0);
    WEQ(g->Data4[7], 0x46);
}

TEST(gettypebyname_a_tcp_service_gives_svcid_tcp) {
    p_GetTypeByNameA f = WS(GetTypeByNameA); GUID g; int port;
    REQUIRE(f);
    WF_UP();
    if (!svc_port("http", "tcp", &port)) { wf_down(); t_skip("no http service entry"); return; }
    memset(&g, 0xEE, sizeof g);
    WEQ(f("http", &g), 0);
    expect_svcid(&g, 0x9, port);
    wf_down();
}
TEST(gettypebyname_w_tcp_service_gives_svcid_tcp) {
    p_GetTypeByNameW f = WS(GetTypeByNameW); GUID g; int port;
    REQUIRE(f);
    WF_UP();
    if (!svc_port("ftp", "tcp", &port)) { wf_down(); t_skip("no ftp service entry"); return; }
    memset(&g, 0xEE, sizeof g);
    WEQ(f(L"ftp", &g), 0);
    expect_svcid(&g, 0x9, port);
    wf_down();
}
TEST(gettypebyname_tcp_services_table) {
    static const char *names[] = { "echo", "ftp", "telnet", "smtp", "http", "pop3", "https" };
    p_GetTypeByNameA f = WS(GetTypeByNameA); unsigned i;
    REQUIRE(f);
    WF_UP();
    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        GUID g; int port;
        if (!svc_port(names[i], "tcp", &port)) continue;
        memset(&g, 0, sizeof g);
        CHECKF(f((LPSTR)names[i], &g) == 0, "%s", names[i]);
        expect_svcid(&g, 0x9, port);
    }
    wf_down();
}
TEST(gettypebyname_udp_only_service_gives_svcid_udp) {
    static const char *names[] = { "tftp", "ntp", "snmp", "bootps", "syslog" };
    p_GetTypeByNameA f = WS(GetTypeByNameA); unsigned i; int tested = 0;
    REQUIRE(f);
    WF_UP();
    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        GUID g; int port, dummy;
        if (svc_port(names[i], "tcp", &dummy) || !svc_port(names[i], "udp", &port)) continue;
        memset(&g, 0, sizeof g);
        CHECKF(f((LPSTR)names[i], &g) == 0, "%s", names[i]);
        expect_svcid(&g, 0xA, port);
        tested++;
    }
    if (!tested) t_note("no udp-only service names present in the services database");
    wf_down();
}
TEST(gettypebyname_tcp_wins_over_udp_for_dual_service) {
    p_GetTypeByNameA f = WS(GetTypeByNameA); GUID g; int pt, pu;
    REQUIRE(f);
    WF_UP();
    if (!svc_port("domain", "tcp", &pt) || !svc_port("domain", "udp", &pu)) { wf_down(); t_skip("domain not in both tables"); return; }
    memset(&g, 0, sizeof g);
    WEQ(f("domain", &g), 0);
    expect_svcid(&g, 0x9, pt);
    wf_down();
}
TEST(gettypebyname_unknown_name_fails_service_not_exist) {
    p_GetTypeByNameA fa = WS(GetTypeByNameA); p_GetTypeByNameW fw = WS(GetTypeByNameW); GUID g;
    REQUIRE(fa); REQUIRE(fw);
    WF_UP();
    SET_ERR(0);
    WEQ(fa("no_such_service_name_q7", &g), -1);
    WEQ(GetLastError(), E_SVC_NOT_EXIST);
    SET_ERR(0);
    WEQ(fw(L"no_such_service_name_q7", &g), -1);
    WEQ(GetLastError(), E_SVC_NOT_EXIST);
    wf_down();
}
TEST(gettypebyname_empty_name_fails) {
    p_GetTypeByNameW f = WS(GetTypeByNameW); GUID g;
    REQUIRE(f);
    WF_UP();
    SET_ERR(0);
    WEQ(f(L"", &g), -1);
    t_note("empty service name -> %lu", GetLastError());
    wf_down();
}
TEST(gettypebyname_failure_leaves_guid_untouched) {
    p_GetTypeByNameA f = WS(GetTypeByNameA); GUID g;
    REQUIRE(f);
    WF_UP();
    memset(&g, 0xEE, sizeof g);
    WEQ(f("no_such_service_name_q7", &g), -1);
    CHECK(g.Data1 == 0xEEEEEEEEu && g.Data4[7] == 0xEE);
    wf_down();
}
CHILD(wf_gettypebyname_nostartup) {
    HMODULE m = LoadLibraryA("wsock32.dll"); p_GetTypeByNameA f; GUID g;
    if (!m) return 1;
    f = (p_GetTypeByNameA)GetProcAddress(m, "GetTypeByNameA");
    if (!f) return 2;
    SetLastError(0);
    /* the service database lookup needs a running stack; without it the name is simply unknown */
    if (f("http", &g) != -1) return 3;
    if (GetLastError() != E_SVC_NOT_EXIST) return 4;
    return 0;
}
TEST(gettypebyname_service_lookup_needs_startup) { WF_RUN_CHILD("wf_gettypebyname_nostartup", ""); }

TEST(getnamebytype_w_tcp_svcid_gives_service_name) {
    p_GetNameByTypeW f = WS(GetNameByTypeW); GUID g; WCHAR name[64]; int port; struct servent *se; WCHAR want[64];
    REQUIRE(f);
    WF_UP();
    if (!svc_port("http", "tcp", &port)) { wf_down(); t_skip("no http service entry"); return; }
    memset(&g, 0, sizeof g);
    g.Data1 = 0x90000u | (unsigned)port; g.Data4[0] = 0xC0; g.Data4[7] = 0x46;
    se = W2(getservbyport)(wf_sw16((unsigned short)port), "tcp");
    CHECK(se != NULL);
    MultiByteToWideChar(CP_ACP, 0, se ? se->s_name : "", -1, want, 64);
    memset(name, 0, sizeof name);
    WEQ(f(&g, name, sizeof name), 0);
    EXPECT_WSTR(name, want);
    wf_down();
}
TEST(getnamebytype_a_tcp_svcid_gives_service_name) {
    p_GetNameByTypeA f = WS(GetNameByTypeA); GUID g; char name[64]; int port; struct servent *se;
    REQUIRE(f);
    WF_UP();
    if (!svc_port("smtp", "tcp", &port)) { wf_down(); t_skip("no smtp service entry"); return; }
    memset(&g, 0, sizeof g);
    g.Data1 = 0x90000u | (unsigned)port; g.Data4[0] = 0xC0; g.Data4[7] = 0x46;
    se = W2(getservbyport)(wf_sw16((unsigned short)port), "tcp");
    memset(name, 0, sizeof name);
    WEQ(f(&g, name, sizeof name), 0);
    CHECK(se != NULL);
    if (se) EXPECT_STR(name, se->s_name);
    wf_down();
}
TEST(getnamebytype_udp_svcid_gives_service_name) {
    p_GetNameByTypeA f = WS(GetNameByTypeA); GUID g; char name[64]; int port; struct servent *se;
    REQUIRE(f);
    WF_UP();
    if (!svc_port("tftp", "udp", &port)) { wf_down(); t_skip("no tftp service entry"); return; }
    memset(&g, 0, sizeof g);
    g.Data1 = 0xA0000u | (unsigned)port; g.Data4[0] = 0xC0; g.Data4[7] = 0x46;
    se = W2(getservbyport)(wf_sw16((unsigned short)port), "udp");
    memset(name, 0, sizeof name);
    WEQ(f(&g, name, sizeof name), 0);
    CHECK(se != NULL);
    if (se) EXPECT_STR(name, se->s_name);
    wf_down();
}
TEST(getnamebytype_roundtrip_through_gettypebyname) {
    p_GetTypeByNameA ft = WS(GetTypeByNameA); p_GetNameByTypeA fn = WS(GetNameByTypeA); GUID g; char name[64]; int port;
    REQUIRE(ft); REQUIRE(fn);
    WF_UP();
    if (!svc_port("pop3", "tcp", &port)) { wf_down(); t_skip("no pop3 service entry"); return; }
    WEQ(ft("pop3", &g), 0);
    memset(name, 0, sizeof name);
    WEQ(fn(&g, name, sizeof name), 0);
    EXPECT_STR(name, "pop3");
    wf_down();
}
TEST(getnamebytype_unknown_guid_fails_service_not_exist) {
    p_GetNameByTypeA fa = WS(GetNameByTypeA); p_GetNameByTypeW fw = WS(GetNameByTypeW); GUID g = k_unknown_guid; char na[64]; WCHAR nw[64];
    REQUIRE(fa); REQUIRE(fw);
    WF_UP();
    SET_ERR(0);
    WEQ(fw(&g, nw, sizeof nw), -1);
    WEQ(GetLastError(), E_SVC_NOT_EXIST);
    SET_ERR(0);
    WEQ(fa(&g, na, sizeof na), -1);
    WEQ(GetLastError(), E_SVC_NOT_EXIST);
    wf_down();
}
TEST(getnamebytype_tiny_buffer_is_insufficient) {
    p_GetNameByTypeW fw = WS(GetNameByTypeW); p_GetNameByTypeA fa = WS(GetNameByTypeA); GUID g; WCHAR nw[8]; char na[8]; int port;
    REQUIRE(fw); REQUIRE(fa);
    WF_UP();
    if (!svc_port("http", "tcp", &port)) { wf_down(); t_skip("no http service entry"); return; }
    memset(&g, 0, sizeof g);
    g.Data1 = 0x90000u | (unsigned)port; g.Data4[0] = 0xC0; g.Data4[7] = 0x46;
    SET_ERR(0);
    WEQ(fw(&g, nw, 2), -1);
    WEQ(GetLastError(), E_INSUFFICIENT);
    SET_ERR(0);
    WEQ(fa(&g, na, 1), -1);
    WEQ(GetLastError(), E_INSUFFICIENT);
    wf_down();
}
TEST(getnamebytype_known_tcp_guid_with_wrong_tail_is_unknown) {
    p_GetNameByTypeW f = WS(GetNameByTypeW); GUID g; WCHAR nw[64];
    REQUIRE(f);
    WF_UP();
    memset(&g, 0, sizeof g);
    g.Data1 = 0x90050; g.Data4[0] = 0xC0; g.Data4[7] = 0x47;     /* last byte differs from the service-id pattern */
    SET_ERR(0);
    WEQ(f(&g, nw, sizeof nw), -1);
    WEQ(GetLastError(), E_SVC_NOT_EXIST);
    wf_down();
}

/* ---------------------------------------------------------------- GetAddressByName */
TEST(getaddressbyname_a_async_info_not_supported) {
    p_GetAddressByNameA f = WS(GetAddressByNameA); SERVICE_ASYNC_INFO ai; GUID g = k_unknown_guid; char buf[256]; DWORD len = sizeof buf;
    REQUIRE(f);
    memset(&ai, 0, sizeof ai);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, &g, (LPSTR)"localhost", NULL, 0, &ai, buf, &len, NULL, NULL), -1);
    WEQ(GetLastError(), E_NOT_SUPPORTED);
}
TEST(getaddressbyname_w_async_info_not_supported) {
    p_GetAddressByNameW f = WS(GetAddressByNameW); SERVICE_ASYNC_INFO ai; GUID g = k_unknown_guid; char buf[256]; DWORD len = sizeof buf;
    REQUIRE(f);
    memset(&ai, 0, sizeof ai);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, &g, L"localhost", NULL, 0, &ai, buf, &len, NULL, NULL), -1);
    WEQ(GetLastError(), E_NOT_SUPPORTED);
}
TEST(getaddressbyname_async_rejected_for_every_namespace) {
    p_GetAddressByNameW f = WS(GetAddressByNameW); SERVICE_ASYNC_INFO ai; GUID g = k_unknown_guid; char buf[64]; DWORD len;
    static const DWORD ns[] = { NS_ALL, NS_DNS, NS_TCPIP_HOSTS, NS_TCPIP_LOCAL, NS_NETBT, 0x7fff };
    unsigned i;
    REQUIRE(f);
    memset(&ai, 0, sizeof ai);
    for (i = 0; i < sizeof ns / sizeof ns[0]; i++) {
        len = sizeof buf;
        SET_ERR(0);
        CHECKF(f(ns[i], &g, L"h", NULL, 0, &ai, buf, &len, NULL, NULL) == -1 && GetLastError() == E_NOT_SUPPORTED, "namespace %lu", ns[i]);
    }
}
TEST(getaddressbyname_async_check_happens_before_name_use) {
    p_GetAddressByNameW f = WS(GetAddressByNameW); SERVICE_ASYNC_INFO ai; GUID g = k_unknown_guid; DWORD len = 0;
    REQUIRE(f);
    memset(&ai, 0, sizeof ai);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, &g, L"", NULL, 0, &ai, NULL, &len, NULL, NULL), -1);
    WEQ(GetLastError(), E_NOT_SUPPORTED);
}

/* ---------------------------------------------------------------- GetService / SetService */
TEST(getservice_w_async_info_not_supported) {
    p_GetServiceW f = WS(GetServiceW); SERVICE_ASYNC_INFO ai; GUID g = k_unknown_guid; char buf[64]; DWORD len = sizeof buf;
    REQUIRE(f);
    memset(&ai, 0, sizeof ai);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, &g, L"svc", 0, buf, &len, &ai), -1);
    WEQ(GetLastError(), E_NOT_SUPPORTED);
}
TEST(getservice_a_async_info_not_supported) {
    p_GetServiceA f = WS(GetServiceA); SERVICE_ASYNC_INFO ai; GUID g = k_unknown_guid; char buf[64]; DWORD len = sizeof buf;
    REQUIRE(f);
    memset(&ai, 0, sizeof ai);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, &g, (LPSTR)"svc", 0, buf, &len, &ai), -1);
    WEQ(GetLastError(), E_NOT_SUPPORTED);
}
TEST(getservice_w_null_guid_invalid_parameter) {
    p_GetServiceW f = WS(GetServiceW); char buf[64]; DWORD len = sizeof buf;
    REQUIRE(f);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, NULL, L"svc", 0, buf, &len, NULL), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
}
TEST(getservice_w_null_name_invalid_parameter) {
    p_GetServiceW f = WS(GetServiceW); GUID g = k_unknown_guid; char buf[64]; DWORD len = sizeof buf;
    REQUIRE(f);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, &g, NULL, 0, buf, &len, NULL), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
}
TEST(getservice_w_null_size_pointer_invalid_parameter) {
    p_GetServiceW f = WS(GetServiceW); GUID g = k_unknown_guid; char buf[64];
    REQUIRE(f);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, &g, L"svc", 0, buf, NULL, NULL), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
}
TEST(getservice_a_null_guid_invalid_parameter) {
    p_GetServiceA f = WS(GetServiceA); char buf[64]; DWORD len = sizeof buf;
    REQUIRE(f);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, NULL, (LPSTR)"svc", 0, buf, &len, NULL), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
}
TEST(getservice_a_null_name_invalid_parameter) {
    p_GetServiceA f = WS(GetServiceA); GUID g = k_unknown_guid; char buf[64]; DWORD len = sizeof buf;
    REQUIRE(f);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, &g, NULL, 0, buf, &len, NULL), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
}
TEST(getservice_async_beats_other_argument_errors) {
    p_GetServiceW f = WS(GetServiceW); SERVICE_ASYNC_INFO ai;
    REQUIRE(f);
    memset(&ai, 0, sizeof ai);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, NULL, NULL, 0, NULL, NULL, &ai), -1);
    WEQ(GetLastError(), E_NOT_SUPPORTED);
}

static void setsvc_info_w(SERVICE_INFOW *si, SERVICE_TYPE_INFO_ABSW *ti, GUID *g) {
    memset(si, 0, sizeof *si); memset(ti, 0, sizeof *ti);
    si->lpServiceType = g;
    si->lpServiceName = (LPWSTR)L"wf-test-type";
    ti->lpTypeName = (LPWSTR)L"";
    ti->dwValueCount = 0;
    si->ServiceSpecificInfo.cbSize = sizeof *ti;
    si->ServiceSpecificInfo.pBlobData = (BYTE *)ti;
}
TEST(setservice_w_null_info_invalid_parameter) {
    p_SetServiceW f = WS(SetServiceW); DWORD st = 0;
    REQUIRE(f);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_REGISTER, 0, NULL, NULL, &st), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
}
TEST(setservice_a_null_info_invalid_parameter) {
    p_SetServiceA f = WS(SetServiceA); DWORD st = 0;
    REQUIRE(f);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_REGISTER, 0, NULL, NULL, &st), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
}
TEST(setservice_w_async_info_not_supported) {
    p_SetServiceW f = WS(SetServiceW); SERVICE_INFOW si; SERVICE_TYPE_INFO_ABSW ti; GUID g = k_unknown_guid; SERVICE_ASYNC_INFO ai; DWORD st = 0;
    REQUIRE(f);
    setsvc_info_w(&si, &ti, &g);
    memset(&ai, 0, sizeof ai);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_ADD_TYPE, 0, &si, &ai, &st), -1);
    WEQ(GetLastError(), E_NOT_SUPPORTED);
}
TEST(setservice_w_null_status_pointer_invalid_parameter) {
    p_SetServiceW f = WS(SetServiceW); SERVICE_INFOW si; SERVICE_TYPE_INFO_ABSW ti; GUID g = k_unknown_guid;
    REQUIRE(f);
    setsvc_info_w(&si, &ti, &g);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_ADD_TYPE, 0, &si, NULL, NULL), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
}
TEST(setservice_w_add_type_empty_type_name_invalid_parameter) {
    p_SetServiceW f = WS(SetServiceW); SERVICE_INFOW si; SERVICE_TYPE_INFO_ABSW ti; GUID g = k_unknown_guid; DWORD st = 0xDEADBEEF;
    REQUIRE(f);
    setsvc_info_w(&si, &ti, &g);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_ADD_TYPE, 0, &si, NULL, &st), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
    WEQ(st, 0);                      /* the status word is cleared up front */
}
TEST(setservice_w_delete_type_empty_type_name_invalid_parameter) {
    p_SetServiceW f = WS(SetServiceW); SERVICE_INFOW si; SERVICE_TYPE_INFO_ABSW ti; GUID g = k_unknown_guid; DWORD st = 0xDEADBEEF;
    REQUIRE(f);
    setsvc_info_w(&si, &ti, &g);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_DELETE_TYPE, 0, &si, NULL, &st), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
    WEQ(st, 0);
}
TEST(setservice_w_add_type_null_type_name_invalid_parameter) {
    p_SetServiceW f = WS(SetServiceW); SERVICE_INFOW si; SERVICE_TYPE_INFO_ABSW ti; GUID g = k_unknown_guid; DWORD st = 1;
    REQUIRE(f);
    setsvc_info_w(&si, &ti, &g);
    ti.lpTypeName = NULL;
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_ADD_TYPE, 0, &si, NULL, &st), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
}
TEST(setservice_w_add_type_without_blob_invalid_parameter) {
    p_SetServiceW f = WS(SetServiceW); SERVICE_INFOW si; SERVICE_TYPE_INFO_ABSW ti; GUID g = k_unknown_guid; DWORD st = 1;
    REQUIRE(f);
    setsvc_info_w(&si, &ti, &g);
    si.ServiceSpecificInfo.cbSize = 0;
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_ADD_TYPE, 0, &si, NULL, &st), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
    setsvc_info_w(&si, &ti, &g);
    si.ServiceSpecificInfo.pBlobData = NULL;
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_ADD_TYPE, 0, &si, NULL, &st), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
}
TEST(setservice_a_add_type_empty_type_name_invalid_parameter) {
    p_SetServiceA f = WS(SetServiceA); SERVICE_INFOA si; SERVICE_TYPE_INFO_ABSA ti; GUID g = k_unknown_guid; DWORD st = 0xDEADBEEF;
    REQUIRE(f);
    memset(&si, 0, sizeof si); memset(&ti, 0, sizeof ti);
    si.lpServiceType = &g; si.lpServiceName = (LPSTR)"wf-test-type";
    ti.lpTypeName = (LPSTR)"";
    si.ServiceSpecificInfo.cbSize = sizeof ti; si.ServiceSpecificInfo.pBlobData = (BYTE *)&ti;
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_ADD_TYPE, 0, &si, NULL, &st), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
    WEQ(st, 0);
}
TEST(setservice_a_async_info_not_supported) {
    p_SetServiceA f = WS(SetServiceA); SERVICE_INFOA si; SERVICE_TYPE_INFO_ABSA ti; GUID g = k_unknown_guid; SERVICE_ASYNC_INFO ai; DWORD st = 0;
    REQUIRE(f);
    memset(&si, 0, sizeof si); memset(&ti, 0, sizeof ti); memset(&ai, 0, sizeof ai);
    si.lpServiceType = &g; si.lpServiceName = (LPSTR)"wf-test-type";
    ti.lpTypeName = (LPSTR)"x";
    si.ServiceSpecificInfo.cbSize = sizeof ti; si.ServiceSpecificInfo.pBlobData = (BYTE *)&ti;
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_ADD_TYPE, 0, &si, &ai, &st), -1);
    WEQ(GetLastError(), E_NOT_SUPPORTED);
}
TEST(setservice_a_null_info_beats_async_info) {
    p_SetServiceA f = WS(SetServiceA); SERVICE_ASYNC_INFO ai; DWORD st = 0;
    REQUIRE(f);
    memset(&ai, 0, sizeof ai);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_REGISTER, 0, NULL, &ai, &st), -1);
    WEQ(GetLastError(), E_INVALID_PARAM);
}
TEST(setservice_w_null_info_beats_async_info) {
    p_SetServiceW f = WS(SetServiceW); SERVICE_ASYNC_INFO ai; DWORD st = 0;
    REQUIRE(f);
    memset(&ai, 0, sizeof ai);
    SET_ERR(0);
    WEQ(f(NS_DEFAULT, SERVICE_REGISTER, 0, NULL, &ai, &st), -1);
    t_note("W form with NULL info and async info -> %lu", GetLastError());
}

/* ---------------------------------------------------------------- NPLoadNameSpaces */
typedef struct { DWORD count; DWORD pad; void **fns; DWORD ns; DWORD prio; } nsr_t;
TEST(npload_small_buffer_reports_required_size) {
    p_NPLoadNameSpaces f = WS(NPLoadNameSpaces); DWORD ver = 0, len = 16; BYTE buf[16];
    REQUIRE(f);
    SET_ERR(0);
    WEQ(f(&ver, buf, &len), -1);
    WEQ(GetLastError(), E_INSUFFICIENT);
    WEQ(len, 0xe0);
}
TEST(npload_zero_buffer_reports_required_size) {
    p_NPLoadNameSpaces f = WS(NPLoadNameSpaces); DWORD ver = 0, len = 0;
    REQUIRE(f);
    SET_ERR(0);
    WEQ(f(&ver, NULL, &len), -1);
    WEQ(GetLastError(), E_INSUFFICIENT);
    WEQ(len, 0xe0);
}
TEST(npload_one_byte_short_fails) {
    p_NPLoadNameSpaces f = WS(NPLoadNameSpaces); DWORD ver = 0, len = 0xdf; BYTE buf[0x100];
    REQUIRE(f);
    SET_ERR(0);
    WEQ(f(&ver, buf, &len), -1);
    WEQ(GetLastError(), E_INSUFFICIENT);
    WEQ(len, 0xe0);
}
TEST(npload_fills_four_namespace_routines) {
    p_NPLoadNameSpaces f = WS(NPLoadNameSpaces); DWORD ver = 0, len = 0xe0; BYTE buf[0x100]; nsr_t *r; int i;
    static const DWORD ns[4] = { NS_TCPIP_LOCAL, NS_TCPIP_HOSTS, NS_DNS, NS_NETBT };
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    WEQ(f(&ver, buf, &len), 4);
    WEQ(ver, 1);
    r = (nsr_t *)buf;
    for (i = 0; i < 4; i++) {
        CHECKF(r[i].count == 4, "entry %d count %lu", i, r[i].count);
        CHECKF(r[i].ns == ns[i], "entry %d namespace %lu", i, r[i].ns);
        CHECKF(r[i].fns != NULL && (BYTE *)r[i].fns >= buf && (BYTE *)r[i].fns < buf + 0xe0, "entry %d table pointer", i);
        if (r[i].fns) CHECKF(r[i].fns[0] != NULL, "entry %d has no lookup routine", i);
    }
}
TEST(npload_only_local_namespace_has_set_service) {
    p_NPLoadNameSpaces f = WS(NPLoadNameSpaces); DWORD ver = 0, len = 0xe0; BYTE buf[0x100]; nsr_t *r;
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    WEQ(f(&ver, buf, &len), 4);
    r = (nsr_t *)buf;
    if (!r[0].fns || !r[1].fns || !r[2].fns || !r[3].fns) { CHECK(0); return; }
    CHECK(r[0].fns[1] == NULL);
    CHECK(r[0].fns[2] != NULL);
    CHECK(r[0].fns[3] == NULL);
    CHECK(r[1].fns[1] == NULL && r[1].fns[2] == NULL && r[1].fns[3] == NULL);
    CHECK(r[2].fns[1] == NULL && r[2].fns[2] == NULL && r[2].fns[3] == NULL);
    CHECK(r[3].fns[1] == NULL && r[3].fns[2] == NULL && r[3].fns[3] == NULL);
}
TEST(npload_larger_buffer_same_result) {
    p_NPLoadNameSpaces f = WS(NPLoadNameSpaces); DWORD ver = 0, len = 0x400; BYTE buf[0x400];
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    WEQ(f(&ver, buf, &len), 4);
    WEQ(len, 0x400);               /* not rewritten on success */
}
TEST(npload_routines_are_distinct_code) {
    p_NPLoadNameSpaces f = WS(NPLoadNameSpaces); DWORD ver = 0, len = 0xe0; BYTE buf[0x100]; nsr_t *r;
    REQUIRE(f);
    memset(buf, 0, sizeof buf);
    WEQ(f(&ver, buf, &len), 4);
    r = (nsr_t *)buf;
    if (!r[0].fns) { CHECK(0); return; }
    CHECK(r[0].fns[0] != r[1].fns[0]);
    CHECK(r[1].fns[0] != r[2].fns[0]);
    CHECK(r[2].fns[0] != r[3].fns[0]);
    CHECK(r[0].fns[0] != r[0].fns[2]);
}

/* ---------------------------------------------------------------- WSApSetPostRoutine / WEP / FDIsSet / s_perror */
TEST(postroutine_null_returns_zero) {
    p_WSApSetPostRoutine f = WS(WSApSetPostRoutine);
    REQUIRE(f);
    WEQ(f(NULL), 0);
    WEQ(f(NULL), 0);
}
TEST(postroutine_is_same_function_as_ws2_32) {
    CHECK(t_proc_in("wsock32.dll", "WSApSetPostRoutine") == t_proc_in("ws2_32.dll", "WSApSetPostRoutine"));
}
TEST(postroutine_works_with_winsock_started) {
    p_WSApSetPostRoutine f = WS(WSApSetPostRoutine);
    REQUIRE(f);
    WF_UP();
    WEQ(f(NULL), 0);
    wf_down();
}
TEST(wep_is_callable_and_harmless) {
    p_WEP f = WS(WEP);
    REQUIRE(f);
    if (t_is_wine()) { t_skip("emulator lacks WEP"); return; }
    f();                                  /* no arguments; the result is not specified */
    f();
}
TEST(fdisset_membership) {
    p___WSAFDIsSet f = WS(__WSAFDIsSet); fd_set set; SOCKET a, b, c;
    REQUIRE(f);
    WF_UP();
    a = W2(socket)(AF_INET, SOCK_DGRAM, 0); b = W2(socket)(AF_INET, SOCK_DGRAM, 0); c = W2(socket)(AF_INET, SOCK_DGRAM, 0);
    memset(&set, 0, sizeof set);
    set.fd_array[0] = a; set.fd_array[1] = b; set.fd_count = 2;
    WEQ(f(a, &set), 1);
    WEQ(f(b, &set), 1);
    WEQ(f(c, &set), 0);
    set.fd_count = 1;
    WEQ(f(b, &set), 0);              /* only the first fd_count entries are looked at */
    set.fd_count = 0;
    WEQ(f(a, &set), 0);
    W2(closesocket)(a); W2(closesocket)(b); W2(closesocket)(c);
    wf_down();
}
TEST(fdisset_full_set_last_slot) {
    p___WSAFDIsSet f = WS(__WSAFDIsSet); fd_set set; unsigned i;
    REQUIRE(f);
    memset(&set, 0, sizeof set);
    for (i = 0; i < FD_SETSIZE; i++) set.fd_array[i] = (SOCKET)(0x1000 + i * 4);
    set.fd_count = FD_SETSIZE;
    WEQ(f((SOCKET)(0x1000 + (FD_SETSIZE - 1) * 4), &set), 1);
    WEQ(f((SOCKET)0x2, &set), 0);
}

/* s_perror writes "> <text>:<message>" to the standard error handle; the text of the message is
 * locale-dependent, so only the framing is looked at. */
CHILD(wf_s_perror) {
    p_s_perror f = (p_s_perror)GetProcAddress(LoadLibraryA("wsock32.dll"), "s_perror");
    if (!f) return 1;
    f("wftag", argc > 1 ? atoi(argv[1]) : 7);
    return 0;
}
static int run_perror(int code, char *out, int cap) {
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    HANDLE rd, wr; PROCESS_INFORMATION pi; DWORD got = 0, total = 0; char arg[16]; HANDLE h;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    snprintf(arg, sizeof arg, "%d", code);
    h = t_spawn_child("wf_s_perror", arg, 0, NULL, NULL, wr, TRUE, NULL, &pi);
    CloseHandle(wr);
    if (!h) { CloseHandle(rd); return -1; }
    if (WaitForSingleObject(pi.hProcess, 20000) != WAIT_OBJECT_0) { TerminateProcess(pi.hProcess, 99); }
    while (total < (DWORD)cap - 1 && ReadFile(rd, out + total, (DWORD)cap - 1 - total, &got, NULL) && got) total += got;
    out[total] = 0;
    CloseHandle(rd); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return (int)total;
}
TEST(s_perror_child_runs_to_completion) {
    char out[512];
    REQUIRE(WS(s_perror));
    EXPECT_NE(run_perror(7, out, sizeof out), -1);
}
TEST(s_perror_output_framing) {
    char out[512]; int n;
    REQUIRE(WS(s_perror));
    n = run_perror(7, out, sizeof out);
    CHECK(n > 8);
    if (n > 8) {
        CHECK(!strncmp(out, "> wftag:", 8));
        CHECK(out[n - 1] == '\n');
    }
}
TEST(s_perror_unmapped_code_still_frames_output) {
    char out[512]; int n;
    REQUIRE(WS(s_perror));
    n = run_perror(0x7fff0000, out, sizeof out);
    CHECK(n > 8);
    if (n > 8) {
        CHECK(!strncmp(out, "> wftag:", 8));
        CHECK(out[n - 1] == '\n');
    }
}
TEST(s_perror_codes_differ_in_message) {
    char a[512], b[512]; int na, nb;
    REQUIRE(WS(s_perror));
    na = run_perror(1, a, sizeof a);
    nb = run_perror(13, b, sizeof b);
    CHECK(na > 8 && nb > 8);
    CHECK(na != nb || strcmp(a, b) != 0);
}
