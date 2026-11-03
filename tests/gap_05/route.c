/* Routing and address-list control codes reached straight at the device:
 *   0x120ab ROUTING_INTERFACE_QUERY   0x120ac ROUTING_INTERFACE_CHANGE
 *   0x120b3 ADDRESS_LIST_QUERY        0x120b4 ADDRESS_LIST_CHANGE
 * The two queries answer at once; the two change requests pend until the system changes, so the tests
 * either refuse them on size grounds or cancel them. Loopback only: the query target is always 127.0.0.1
 * (or ::1 when the stack has it) and no route or address is ever changed. */
#include "g5.h"

/* A transport address record: count, then { length, type, bytes... } with the length excluding the type. */
typedef struct { ULONG count; USHORT len; USHORT type; UCHAR body[26]; } TA_REC;
static ULONG ta4(TA_REC *t, ULONG host)
{
    memset(t, 0, sizeof *t);
    t->count = 1; t->len = 14; t->type = AF_INET;
    ((struct sockaddr_in *)&t->type)->sin_addr.s_addr = BE32(host);   /* type is the first field of a socket address */
    return 8 + 14;
}
static int have_v6(void)
{
    static int have = -1;
    if (have < 0) {
        SOCKET s = W.WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
        have = 0;
        if (s != INVALID_SOCKET) {
            struct sockaddr_in6 a; memset(&a, 0, sizeof a);
            a.sin6_family = AF_INET6; a.sin6_addr.u.Byte[15] = 1;
            have = W.bind(s, (struct sockaddr *)&a, sizeof a) == 0;
            W.closesocket(s);
        }
    }
    return have;
}

/* ---- ROUTING_INTERFACE_QUERY 0x120ab ------------------------------------------------------------------ */
TEST(gap5_routeq_input_shorter_than_12_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 0, 1, 4, 8, 11 };
    SOCKET s = g5_udp(); TA_REC t; unsigned char o[32]; ta4(&t, 0x7f000001);
    for (int i = 0; i < 5; i++) {
        IO_STATUS_BLOCK io;
        EXPECT_NTS(g5_ctl(S(s), 0x120ab, lens[i] ? &t : NULL, lens[i], o, sizeof o, &io, NULL), ST_INVALID_PARAMETER);
        EXPECT_EQ(io.Information, 0);
    }
    g5_close(s);
}
TEST(gap5_routeq_loopback_v4_answers_loopback)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); TA_REC t; struct sockaddr_in o; IO_STATUS_BLOCK io; ULONG n = ta4(&t, 0x7f000001);
    memset(&o, 0xcc, sizeof o);
    EXPECT_NTS(g5_ctl(S(s), 0x120ab, &t, n, &o, sizeof o, &io, NULL), ST_SUCCESS);
    EXPECT_EQ(io.Information, 16);
    EXPECT_EQ(o.sin_family, AF_INET);
    EXPECT_EQ(o.sin_addr.s_addr, BE32(0x7f000001UL));
    g5_close(s);
}
TEST(gap5_routeq_matches_winsock_ioctl)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); TA_REC t; struct sockaddr_in o, d, w; DWORD got = 0; ULONG n = ta4(&t, 0x7f000001);
    memset(&o, 0, sizeof o); memset(&w, 0, sizeof w);
    d = g5_lo4(0);
    EXPECT_NTS(g5_ctl(S(s), 0x120ab, &t, n, &o, sizeof o, NULL, NULL), ST_SUCCESS);
    CHECK(W.WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, &d, sizeof d, &w, sizeof w, &got, NULL, NULL) == 0);
    EXPECT_EQ(got, sizeof w);
    EXPECT_EQ(w.sin_addr.s_addr, o.sin_addr.s_addr);
    g5_close(s);
}
TEST(gap5_routeq_same_answer_on_any_endpoint_kind)
{
    G5_BEGIN();
    TA_REC t; ULONG n = ta4(&t, 0x7f000001); SOCKET p, k[3];
    k[0] = g5_tcp(); k[1] = g5_bound(SOCK_STREAM, NULL); g5_pair(&k[2], &p);
    for (int i = 0; i < 3; i++) {
        struct sockaddr_in o; memset(&o, 0, sizeof o);
        EXPECT_NTS(g5_ctl(S(k[i]), 0x120ab, &t, n, &o, sizeof o, NULL, NULL), ST_SUCCESS);
        EXPECT_EQ(o.sin_addr.s_addr, BE32(0x7f000001UL));
        g5_close(k[i]);
    }
    g5_close(p);
}
TEST(gap5_routeq_output_too_small_reports_needed_size)
{
    G5_BEGIN();
    static const ULONG outs[] = { 0, 2, 8, 15 };
    SOCKET s = g5_udp(); TA_REC t; unsigned char o[32]; ULONG n = ta4(&t, 0x7f000001);
    for (int i = 0; i < 4; i++) {
        IO_STATUS_BLOCK io;
        EXPECT_NTSV(g5_ctl(S(s), 0x120ab, &t, n, outs[i] ? o : NULL, outs[i], &io, NULL), ST_BUFFER_OVERFLOW, "short output");
        EXPECT_EQ(io.Information, 16);
    }
    EXPECT_NTS(g5_ctl(S(s), 0x120ab, &t, n, o, 16, NULL, NULL), ST_SUCCESS);     /* exactly enough */
    g5_close(s);
}
TEST(gap5_routeq_larger_input_record_accepted)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); TA_REC t; unsigned char in[64]; struct sockaddr_in o; ULONG n = ta4(&t, 0x7f000001);
    memset(in, 0, sizeof in); memcpy(in, &t, n);
    memset(&o, 0, sizeof o);
    EXPECT_NTS(g5_ctl(S(s), 0x120ab, in, sizeof in, &o, sizeof o, NULL, NULL), ST_SUCCESS);
    EXPECT_EQ(o.sin_addr.s_addr, BE32(0x7f000001UL));
    g5_close(s);
}
TEST(gap5_routeq_unknown_address_type_not_supported)
{
    G5_BEGIN();
    static const USHORT types[] = { 0, 1, 99, 0x1234 };
    SOCKET s = g5_udp(); TA_REC t; unsigned char o[32]; ULONG n = ta4(&t, 0x7f000001);
    for (int i = 0; i < 4; i++) {
        t.type = types[i];
        EXPECT_NTSV(g5_ctl(S(s), 0x120ab, &t, n, o, sizeof o, NULL, NULL), ST_NOT_SUPPORTED, "family");
    }
    g5_close(s);
}
TEST(gap5_routeq_loopback_v6_answers_loopback)
{
    G5_BEGIN();
    if (!have_v6()) { t_skip("no IPv6 loopback"); return; }
    SOCKET s = g5_udp(); TA_REC t; struct sockaddr_in6 o; IO_STATUS_BLOCK io;
    memset(&t, 0, sizeof t); memset(&o, 0, sizeof o);
    t.count = 1; t.len = 26; t.type = AF_INET6;
    t.body[6 + 15] = 1;          /* ::1; the body is a v6 socket address without its family: port, flow, address */
    EXPECT_NTS(g5_ctl(S(s), 0x120ab, &t, 8 + 26, &o, sizeof o, &io, NULL), ST_SUCCESS);
    EXPECT_EQ(io.Information, 28);
    EXPECT_EQ(o.sin6_family, AF_INET6);
    EXPECT_EQ(o.sin6_addr.u.Byte[15], 1);
    g5_close(s);
}

/* ---- ROUTING_INTERFACE_CHANGE 0x120ac ----------------------------------------------------------------- */
/* request (0x20 bytes or more): reserved qword, pointer to a transport address record, its length @0x10,
 * flags @0x18 (bit 1 = overlapped caller) */
static LONG chg(SOCKET s, ULONG code, void *addr, ULONG alen, ULONG flags, ULONG reqlen, IO_STATUS_BLOCK *io, HANDLE ev)
{
    unsigned char r[0x28]; memset(r, 0, sizeof r);
    *(void **)(r + 8) = addr; *(ULONG *)(r + 0x10) = alen; *(ULONG *)(r + 0x18) = flags;
    return g5_submit(S(s), ev, code, r, reqlen, NULL, 0, io);
}
/* submit; an answer given at once is returned, a pended request is cancelled and reported as ST_PENDING */
static LONG chg_wait(SOCKET s, ULONG code, void *addr, ULONG alen, ULONG flags, ULONG reqlen)
{
    IO_STATUS_BLOCK io; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    LONG st = chg(s, code, addr, alen, flags, reqlen, &io, ev);
    if (st == ST_PENDING) {
        W.cancel(S(s), &io);
        WaitForSingleObject(ev, WAIT_MS);
    }
    CloseHandle(ev);
    return st;
}
TEST(gap5_routechg_request_shorter_than_0x20_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 0, 8, 0x18, 0x1f };
    SOCKET s = g5_udp(); TA_REC t; ta4(&t, 0x7f000001);
    for (int i = 0; i < 4; i++) EXPECT_NTS(chg_wait(s, 0x120ac, &t, 22, 2, lens[i]), ST_INVALID_PARAMETER);
    g5_close(s);
}
TEST(gap5_routechg_address_length_below_minimum_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 0, 4, 11, 21 };      /* below 12, and below the 8 + address length the record states */
    SOCKET s = g5_udp(); TA_REC t; ta4(&t, 0x7f000001);
    for (int i = 0; i < 4; i++) EXPECT_NTSV(chg_wait(s, 0x120ac, &t, lens[i], 2, 0x20), ST_INVALID_PARAMETER, "address length");
    g5_close(s);
}
TEST(gap5_routechg_address_record_too_short_for_family_refused)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); TA_REC t; ULONG n = ta4(&t, 0x7f000001);
    t.len = 13;                                          /* a v4 address needs at least 14 */
    EXPECT_NTS(chg_wait(s, 0x120ac, &t, n, 2, 0x20), ST_INVALID_PARAMETER);
    t.type = AF_INET6; t.len = 25;                       /* a v6 address needs at least 26 */
    EXPECT_NTS(chg_wait(s, 0x120ac, &t, 8 + 25, 2, 0x20), ST_INVALID_PARAMETER);
    g5_close(s);
}
TEST(gap5_routechg_unknown_family_not_supported)
{
    G5_BEGIN();
    static const USHORT types[] = { 0, 1, 99 };
    SOCKET s = g5_udp(); TA_REC t; ULONG n = ta4(&t, 0x7f000001);
    for (int i = 0; i < 3; i++) { t.type = types[i]; EXPECT_NTSV(chg_wait(s, 0x120ac, &t, n, 2, 0x20), ST_NOT_SUPPORTED, "family"); }
    g5_close(s);
}
TEST(gap5_routechg_valid_request_pends_until_cancelled)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); TA_REC t; IO_STATUS_BLOCK io; ULONG n = ta4(&t, 0x7f000001); HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_NTS(chg(s, 0x120ac, &t, n, 2, 0x20, &io, ev), ST_PENDING);
    CHECK(WaitForSingleObject(ev, 300) == WAIT_TIMEOUT);
    { IO_STATUS_BLOCK cio; W.cancel(S(s), &cio); }
    CHECK(WaitForSingleObject(ev, WAIT_MS) == WAIT_OBJECT_0);
    EXPECT_NTS(io.Status, ST_CANCELLED);
    CloseHandle(ev); g5_close(s);
}
TEST(gap5_routechg_closing_the_endpoint_completes_the_request)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); TA_REC t; IO_STATUS_BLOCK io; ULONG n = ta4(&t, 0x7f000001); HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    EXPECT_NTS(chg(s, 0x120ac, &t, n, 2, 0x20, &io, ev), ST_PENDING);
    g5_close(s);
    CHECK(WaitForSingleObject(ev, WAIT_MS) == WAIT_OBJECT_0);
    EXPECT_NTS(io.Status, ST_CANCELLED);
    CloseHandle(ev);
}
TEST(gap5_routechg_non_blocking_endpoint_needs_overlapped_flag)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); TA_REC t; ULONG n = ta4(&t, 0x7f000001), on = 1;
    W.ioctlsocket(s, FIONBIO, &on);
    EXPECT_NTS(chg_wait(s, 0x120ac, &t, n, 0, 0x20), ST_DEVICE_NOT_READY);
    g5_close(s);
}

/* ---- ADDRESS_LIST_QUERY 0x120b3 ----------------------------------------------------------------------- */
static LONG addrlist(SOCKET s, USHORT fam, void *out, ULONG outl, IO_STATUS_BLOCK *io)
{
    return g5_ctl(S(s), 0x120b3, &fam, sizeof fam, out, outl, io, NULL);
}
/* checks the structure of a returned list and returns the byte length it occupies */
static ULONG walk(const unsigned char *p, ULONG avail, USHORT fam, ULONG *cnt)
{
    ULONG n = *(const ULONG *)p, off = 4;
    if (n > 64) { CHECKF(0, "implausible address count %lu", (unsigned long)n); *cnt = 0; return 4; }
    for (ULONG i = 0; i < n; i++) {
        USHORT len = *(const USHORT *)(p + off), type = *(const USHORT *)(p + off + 2);
        if (off + 4u + len > avail) { CHECK(0); break; }
        CHECK(type == fam);
        CHECK(len == (fam == AF_INET ? 14 : 26));
        off += 4 + len;
    }
    *cnt = n;
    return off;
}
TEST(gap5_addrlq_input_shorter_than_2_refused)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); unsigned char o[64];
    EXPECT_NTS(g5_ctl(S(s), 0x120b3, NULL, 0, o, sizeof o, NULL, NULL), ST_INVALID_PARAMETER);
    unsigned char one = 2;
    EXPECT_NTS(g5_ctl(S(s), 0x120b3, &one, 1, o, sizeof o, NULL, NULL), ST_INVALID_PARAMETER);
    g5_close(s);
}
TEST(gap5_addrlq_output_shorter_than_4_refused)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); unsigned char o[8];
    for (ULONG n = 0; n < 4; n++) EXPECT_NTSV(addrlist(s, AF_INET, n ? o : NULL, n, NULL), ST_INVALID_PARAMETER, "short output");
    g5_close(s);
}
TEST(gap5_addrlq_v4_list_is_well_formed)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); static unsigned char o[2048]; IO_STATUS_BLOCK io; ULONG cnt = 0;
    memset(o, 0xcc, sizeof o);
    EXPECT_NTS(addrlist(s, AF_INET, o, sizeof o, &io), ST_SUCCESS);
    ULONG used = walk(o, sizeof o, AF_INET, &cnt);
    EXPECT_EQ(io.Information, used);
    int loop = 0;
    for (ULONG i = 0, off = 4; i < cnt; i++) {
        USHORT len = *(USHORT *)(o + off);
        if (!memcmp(o + off + 6, "\x7f\x00\x00\x01", 4)) loop = 1;        /* bytes: type(2) then port(2) then address */
        off += 4 + len;
    }
    t_note("v4 address list: entries=%lu holds the loopback address=%d", (unsigned long)cnt, loop);
    g5_close(s);
}
TEST(gap5_addrlq_matches_winsock_ioctl)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); static unsigned char o[2048], w[4096]; ULONG cnt = 0; DWORD got = 0;
    EXPECT_NTS(addrlist(s, AF_INET, o, sizeof o, NULL), ST_SUCCESS);
    walk(o, sizeof o, AF_INET, &cnt);
    CHECK(W.WSAIoctl(s, SIO_ADDRESS_LIST_QUERY, NULL, 0, w, sizeof w, &got, NULL, NULL) == 0);
    EXPECT_EQ(*(int *)w, cnt);
    g5_close(s);
}
TEST(gap5_addrlq_overflow_reports_required_size_and_count)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); static unsigned char big[2048], o[2048]; IO_STATUS_BLOCK io; ULONG cnt = 0;
    EXPECT_NTS(addrlist(s, AF_INET, big, sizeof big, &io), ST_SUCCESS);
    ULONG need = (ULONG)io.Information; walk(big, sizeof big, AF_INET, &cnt);
    if (need <= 4) { t_skip("no IPv4 addresses to overflow with"); g5_close(s); return; }
    memset(o, 0, sizeof o);
    EXPECT_NTS(addrlist(s, AF_INET, o, need - 1, &io), ST_BUFFER_OVERFLOW);
    EXPECT_EQ(io.Information, need);
    EXPECT_EQ(*(ULONG *)o, cnt);                      /* the count is complete even though the entries are not */
    EXPECT_NTS(addrlist(s, AF_INET, o, need, &io), ST_SUCCESS);
    EXPECT_EQ(io.Information, need);
    EXPECT_NTS(addrlist(s, AF_INET, o, 4, &io), ST_BUFFER_OVERFLOW);
    EXPECT_EQ(io.Information, need);
    g5_close(s);
}
TEST(gap5_addrlq_v6_list_is_well_formed)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); static unsigned char o[4096]; IO_STATUS_BLOCK io; ULONG cnt = 0;
    LONG st = addrlist(s, AF_INET6, o, sizeof o, &io);
    EXPECT_NTS(st, ST_SUCCESS);
    if (st == ST_SUCCESS) { ULONG used = walk(o, sizeof o, AF_INET6, &cnt); EXPECT_EQ(io.Information, used); }
    g5_close(s);
}
TEST(gap5_addrlq_unknown_family_yields_empty_list)
{
    G5_BEGIN();
    static const USHORT fams[] = { 0x1234, 99 };
    SOCKET s = g5_udp(); unsigned char o[64]; IO_STATUS_BLOCK io;
    for (int i = 0; i < 2; i++) {
        memset(o, 0xcc, sizeof o);
        EXPECT_NTS(addrlist(s, fams[i], o, sizeof o, &io), ST_SUCCESS);
        EXPECT_EQ(io.Information, 4);
        EXPECT_EQ(*(ULONG *)o, 0);
    }
    g5_close(s);
}
TEST(gap5_addrlq_longer_input_uses_leading_family)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); static unsigned char o[2048], o2[2048]; unsigned char in[16] = { 0 }; IO_STATUS_BLOCK io;
    in[0] = AF_INET;
    EXPECT_NTS(g5_ctl(S(s), 0x120b3, in, sizeof in, o, sizeof o, &io, NULL), ST_SUCCESS);
    EXPECT_NTS(addrlist(s, AF_INET, o2, sizeof o2, NULL), ST_SUCCESS);
    EXPECT_EQ(*(ULONG *)o, *(ULONG *)o2);
    g5_close(s);
}
TEST(gap5_addrlq_same_on_tcp_and_udp_endpoints)
{
    G5_BEGIN();
    SOCKET u = g5_udp(), t = g5_tcp(); static unsigned char a[2048], b[2048]; IO_STATUS_BLOCK ia, ib;
    EXPECT_NTS(addrlist(u, AF_INET, a, sizeof a, &ia), ST_SUCCESS);
    EXPECT_NTS(addrlist(t, AF_INET, b, sizeof b, &ib), ST_SUCCESS);
    EXPECT_EQ(ia.Information, ib.Information);
    EXPECT_EQ(*(ULONG *)a, *(ULONG *)b);
    g5_close(u); g5_close(t);
}

/* ---- ADDRESS_LIST_CHANGE 0x120b4 ---------------------------------------------------------------------- */
/* request: reserved qword, pointer to a family value, its length, flags (bit 1 = overlapped) */
static LONG achg(SOCKET s, USHORT *fam, ULONG flen, ULONG flags, ULONG reqlen, IO_STATUS_BLOCK *io, HANDLE ev)
{
    unsigned char r[0x28]; memset(r, 0, sizeof r);
    *(void **)(r + 8) = fam; *(ULONG *)(r + 0x10) = flen; *(ULONG *)(r + 0x18) = flags;
    return g5_submit(S(s), ev, 0x120b4, r, reqlen, NULL, 0, io);
}
TEST(gap5_addrlchg_request_shorter_than_0x20_refused)
{
    G5_BEGIN();
    static const ULONG lens[] = { 0, 8, 0x18, 0x1f };
    SOCKET s = g5_udp(); USHORT fam = AF_INET;
    for (int i = 0; i < 4; i++) {
        IO_STATUS_BLOCK io; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        EXPECT_NTS(achg(s, &fam, 2, 2, lens[i], &io, ev), ST_INVALID_PARAMETER);
        CloseHandle(ev);
    }
    g5_close(s);
}
TEST(gap5_addrlchg_family_record_shorter_than_2_refused)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); USHORT fam = AF_INET;
    for (ULONG n = 0; n < 2; n++) {
        IO_STATUS_BLOCK io; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        EXPECT_NTSV(achg(s, &fam, n, 2, 0x20, &io, ev), ST_INVALID_PARAMETER, "family record");
        CloseHandle(ev);
    }
    g5_close(s);
}
TEST(gap5_addrlchg_valid_request_pends_until_cancelled)
{
    G5_BEGIN();
    static const USHORT fams[] = { AF_INET, AF_INET6 };
    for (int i = 0; i < 2; i++) {
        SOCKET s = g5_udp(); USHORT fam = fams[i]; IO_STATUS_BLOCK io; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        EXPECT_NTS(achg(s, &fam, 2, 2, 0x20, &io, ev), ST_PENDING);
        CHECK(WaitForSingleObject(ev, 300) == WAIT_TIMEOUT);
        { IO_STATUS_BLOCK cio; W.cancel(S(s), &cio); }
        CHECK(WaitForSingleObject(ev, WAIT_MS) == WAIT_OBJECT_0);
        EXPECT_NTS(io.Status, ST_CANCELLED);
        CloseHandle(ev); g5_close(s);
    }
}
TEST(gap5_addrlchg_several_requests_may_be_pended)
{
    G5_BEGIN();
    SOCKET s = g5_udp(); USHORT fam = AF_INET; IO_STATUS_BLOCK io[3]; HANDLE ev[3];
    for (int i = 0; i < 3; i++) { ev[i] = CreateEventW(NULL, TRUE, FALSE, NULL); EXPECT_NTS(achg(s, &fam, 2, 2, 0x20, &io[i], ev[i]), ST_PENDING); }
    { IO_STATUS_BLOCK cio; W.cancel(S(s), &cio); }
    for (int i = 0; i < 3; i++) { CHECK(WaitForSingleObject(ev[i], WAIT_MS) == WAIT_OBJECT_0); EXPECT_NTS(io[i].Status, ST_CANCELLED); CloseHandle(ev[i]); }
    g5_close(s);
}
