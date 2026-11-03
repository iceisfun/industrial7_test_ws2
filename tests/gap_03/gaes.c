/* GetAcceptExSockaddrs depth: the pure pointer/length arithmetic on hand-built buffers (receive-data offset,
 * which slot is parsed, untouched outputs for a zero-length slot, 16-bit little-endian length at the end of each
 * slot), and the real thing: addresses produced by an actual AcceptEx completion with and without received
 * data, through the looked-up pointer and the mswsock export. */
#include "g3.h"

typedef void (WSAAPI *gaes_fn)(PVOID, DWORD, DWORD, DWORD, struct sockaddr **, LPINT, struct sockaddr **, LPINT);
typedef BOOL (WSAAPI *aex_fn)(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD, LPDWORD, LPOVERLAPPED);

static gaes_fn gaes_ptr(void)
{
    SOCKET s; void *p;
    if (!g3_up()) return NULL;
    s = g3_tcp(); if (s == INVALID_SOCKET) return NULL;
    p = g3_ext(s, (GUID)WSAID_GETACCEPTEXSOCKADDRS);
    g3_closesocket(s);
    return (gaes_fn)p;
}
static aex_fn aex_ptr(void)
{
    SOCKET s; void *p;
    if (!g3_up()) return NULL;
    s = g3_tcp(); if (s == INVALID_SOCKET) return NULL;
    p = g3_ext(s, (GUID)WSAID_ACCEPTEX);
    g3_closesocket(s);
    return (aex_fn)p;
}
/* Initialise the export's cached copy of the provider function: a failing AcceptEx call is enough. */
static gaes_fn gaes_export(void)
{
    gaes_fn e = (gaes_fn)t_proc_in("mswsock.dll", "GetAcceptExSockaddrs");
    aex_fn x = (aex_fn)t_proc_in("mswsock.dll", "AcceptEx");
    struct sockaddr_in a; SOCKET l; unsigned char buf[128]; OVERLAPPED ov; DWORD n = 0;
    if (!e || !x || !gaes_ptr()) return NULL;
    l = g3_listener(&a); if (l == INVALID_SOCKET) return NULL;
    memset(&ov, 0, sizeof ov);
    x(l, INVALID_SOCKET, buf, 0, 32, 32, &n, &ov);
    g3_closesocket(l);
    return e;
}

#define NEED_PTR() gaes_fn fn = gaes_ptr(); do { if (!fn) { t_skip("extension pointer unavailable"); return; } } while (0)

TEST(gap3_gaes_pointer_is_a_mswsock_function)
{
    HMODULE h = NULL;
    NEED_PTR();
    CHECK(GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)fn, &h));
    CHECK(h == t_module("mswsock.dll"));
}

TEST(gap3_gaes_local_slot_starts_at_receive_length_and_length_comes_from_slot_end)
{
    static const DWORD recv[] = { 0, 1, 4, 16, 100, 255 };
    unsigned i;
    NEED_PTR();
    for (i = 0; i < sizeof recv / sizeof *recv; i++) {
        unsigned char buf[800]; struct sockaddr *l = NULL, *r = NULL; int ll = -1, rl = -1;
        memset(buf, 0xEE, sizeof buf);
        buf[recv[i] + 30] = 0x10; buf[recv[i] + 31] = 0x00;       /* local slot [recv, recv+32): length 16 */
        buf[recv[i] + 62] = 0x1C; buf[recv[i] + 63] = 0x00;       /* remote slot [recv+32, recv+64): length 28 */
        fn(buf, recv[i], 32, 32, &l, &ll, &r, &rl);
        CHECKF(l == (struct sockaddr *)(buf + recv[i]), "recv %lu local pointer", recv[i]);
        CHECKF(r == (struct sockaddr *)(buf + recv[i] + 32), "recv %lu remote pointer", recv[i]);
        CHECKF(ll == 16 && rl == 28, "recv %lu lengths %d/%d", recv[i], ll, rl);
    }
}

TEST(gap3_gaes_slot_sizes_need_not_match_and_are_used_as_given)
{
    static const struct { DWORD ls, rs; } rows[] = { { 2, 2 }, { 3, 40 }, { 16, 16 }, { 28, 44 }, { 60, 4 }, { 128, 128 } };
    unsigned i;
    NEED_PTR();
    for (i = 0; i < sizeof rows / sizeof *rows; i++) {
        unsigned char buf[600]; struct sockaddr *l = NULL, *r = NULL; int ll = -1, rl = -1;
        DWORD ls = rows[i].ls, rs = rows[i].rs;
        memset(buf, 0, sizeof buf);
        buf[7 + ls - 2] = 0x11; buf[7 + ls - 1] = 0x01;           /* 0x0111 */
        buf[7 + ls + rs - 2] = 0x22; buf[7 + ls + rs - 1] = 0x02; /* 0x0222 */
        fn(buf, 7, ls, rs, &l, &ll, &r, &rl);
        CHECKF(l == (struct sockaddr *)(buf + 7) && r == (struct sockaddr *)(buf + 7 + ls), "row %u pointers", i);
        CHECKF(ll == 0x111 && rl == 0x222, "row %u lengths %d/%d", i, ll, rl);
    }
}

TEST(gap3_gaes_length_is_unsigned_sixteen_bit)
{
    unsigned char buf[100]; struct sockaddr *l = NULL, *r = NULL; int ll = -1, rl = -1;
    NEED_PTR();
    memset(buf, 0, sizeof buf);
    buf[30] = 0xFF; buf[31] = 0xFF; buf[62] = 0x00; buf[63] = 0x80;
    fn(buf, 0, 32, 32, &l, &ll, &r, &rl);
    G3_EQ(ll, 0xFFFF); G3_EQ(rl, 0x8000);
}

TEST(gap3_gaes_only_the_two_length_bytes_matter_not_the_address_contents)
{
    unsigned char buf[100]; struct sockaddr *l = NULL, *r = NULL; int ll = -1, rl = -1;
    NEED_PTR();
    memset(buf, 0x5A, sizeof buf);
    buf[30] = 9; buf[31] = 0; buf[62] = 5; buf[63] = 0;
    fn(buf, 0, 32, 32, &l, &ll, &r, &rl);
    G3_EQ(ll, 9); G3_EQ(rl, 5);
    CHECK(buf[0] == 0x5A && buf[40] == 0x5A);        /* the buffer is read, never written */
}

TEST(gap3_gaes_buffer_is_not_modified)
{
    unsigned char buf[200], copy[200]; struct sockaddr *l, *r; int ll, rl; unsigned i;
    NEED_PTR();
    for (i = 0; i < sizeof buf; i++) buf[i] = (unsigned char)(i * 5 + 1);
    memcpy(copy, buf, sizeof buf);
    fn(buf, 12, 40, 40, &l, &ll, &r, &rl);
    CHECK(!memcmp(buf, copy, sizeof buf));
}

TEST(gap3_gaes_zero_local_slot_leaves_local_outputs_untouched)
{
    unsigned char buf[100]; struct sockaddr *l = (void *)(ULONG_PTR)0x1111, *r = NULL; int ll = 0x2222, rl = -1;
    NEED_PTR();
    memset(buf, 0, sizeof buf);
    buf[3 + 30] = 0; buf[3 + 31] = 0;
    buf[3 + 14] = 0x1C;                       /* remote slot [3, 19): length from bytes 17..18 */
    buf[3 + 16 - 2] = 0x1C; buf[3 + 16 - 1] = 0;
    fn(buf, 3, 0, 16, &l, &ll, &r, &rl);
    G3_EQ(l, 0x1111); G3_EQ(ll, 0x2222);
    G3_EQ(r, (ULONG_PTR)(buf + 3)); G3_EQ(rl, 0x1C);
}

TEST(gap3_gaes_zero_remote_slot_leaves_remote_outputs_untouched)
{
    unsigned char buf[100]; struct sockaddr *l = NULL, *r = (void *)(ULONG_PTR)0x3333; int ll = -1, rl = 0x4444;
    NEED_PTR();
    memset(buf, 0, sizeof buf);
    buf[20 + 14] = 0x10;
    fn(buf, 20, 16, 0, &l, &ll, &r, &rl);
    G3_EQ(l, (ULONG_PTR)(buf + 20)); G3_EQ(ll, 0x10);
    G3_EQ(r, 0x3333); G3_EQ(rl, 0x4444);
}

TEST(gap3_gaes_both_slots_zero_touches_nothing)
{
    unsigned char buf[16] = {0}; struct sockaddr *l = (void *)(ULONG_PTR)1, *r = (void *)(ULONG_PTR)2; int ll = 3, rl = 4;
    NEED_PTR();
    fn(buf, 8, 0, 0, &l, &ll, &r, &rl);
    G3_EQ(l, 1); G3_EQ(r, 2); G3_EQ(ll, 3); G3_EQ(rl, 4);
}

TEST(gap3_gaes_receive_length_only_shifts_the_slots)
{
    unsigned char buf[300]; struct sockaddr *l1, *r1, *l2, *r2; int a, b, c, d;
    NEED_PTR();
    memset(buf, 0, sizeof buf);
    buf[30] = 7; buf[62] = 9;
    fn(buf, 0, 32, 32, &l1, &a, &r1, &b);
    memmove(buf + 100, buf, 64); memset(buf, 0, 64);
    fn(buf, 100, 32, 32, &l2, &c, &r2, &d);
    G3_EQ((unsigned char *)l2 - (unsigned char *)l1, 100);
    G3_EQ((unsigned char *)r2 - (unsigned char *)r1, 100);
    G3_EQ(a, c); G3_EQ(b, d);
}

TEST(gap3_gaes_export_matches_pointer_after_priming)
{
    gaes_fn ex = gaes_export(); gaes_fn pt = gaes_ptr();
    unsigned char buf[300]; unsigned i;
    if (!ex || !pt) { t_skip("export/pointer unavailable"); return; }
    for (i = 0; i < sizeof buf; i++) buf[i] = (unsigned char)(i + 1);
    for (i = 0; i < 6; i++) {
        static const DWORD rl[] = { 0, 3, 40, 64, 100, 5 };
        struct sockaddr *l1 = NULL, *r1 = NULL, *l2 = NULL, *r2 = NULL; int a = -1, b = -1, c = -1, d = -1;
        ex(buf, rl[i], 32, 24, &l1, &a, &r1, &b);
        pt(buf, rl[i], 32, 24, &l2, &c, &r2, &d);
        CHECKF(l1 == l2 && r1 == r2 && a == c && b == d, "row %u", i);
    }
}

/* ---- real AcceptEx completions ---- */
struct acc { SOCKET l, c, a; struct sockaddr_in laddr, caddr; unsigned char buf[2048]; DWORD rl; };

static int acc_run(struct acc *x, DWORD recvlen, const char *payload, int plen, DWORD slot)
{
    aex_fn ax = aex_ptr(); OVERLAPPED ov; DWORD n = 0; int len = sizeof x->caddr;
    memset(x, 0, sizeof *x);
    x->l = x->c = x->a = INVALID_SOCKET;
    if (!ax) return 0;
    x->l = g3_listener(&x->laddr); x->a = g3_tcp(); x->c = g3_tcp();
    if (x->l == INVALID_SOCKET || x->a == INVALID_SOCKET || x->c == INVALID_SOCKET) return 0;
    memset(&ov, 0, sizeof ov); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    memset(x->buf, 0xCD, sizeof x->buf);
    if (!ax(x->l, x->a, x->buf, recvlen, slot, slot, &n, &ov) && g3_WSAGetLastError() != ERROR_IO_PENDING) { CloseHandle(ov.hEvent); return 0; }
    if (g3_connect(x->c, (struct sockaddr *)&x->laddr, sizeof x->laddr)) { CloseHandle(ov.hEvent); return 0; }
    if (plen) g3_send(x->c, payload, plen, 0);
    if (WaitForSingleObject(ov.hEvent, 8000) != WAIT_OBJECT_0) { CloseHandle(ov.hEvent); return 0; }
    CloseHandle(ov.hEvent);
    g3_getsockname(x->c, (struct sockaddr *)&x->caddr, &len);
    x->rl = recvlen;
    return 1;
}
static void acc_done(struct acc *x)
{
    if (x->l != INVALID_SOCKET) g3_closesocket(x->l);
    if (x->c != INVALID_SOCKET) g3_closesocket(x->c);
    if (x->a != INVALID_SOCKET) g3_closesocket(x->a);
}

static void real_case(gaes_fn fn, DWORD recvlen, const char *payload, int plen)
{
    struct acc x; struct sockaddr *l = NULL, *r = NULL; int ll = -1, rl = -1; DWORD slot = sizeof(struct sockaddr_in) + 16;
    if (!acc_run(&x, recvlen, payload, plen, slot)) { acc_done(&x); t_skip("AcceptEx fixture unavailable"); return; }
    fn(x.buf, recvlen, slot, slot, &l, &ll, &r, &rl);
    CHECK(l == (struct sockaddr *)(x.buf + recvlen));
    CHECK(r == (struct sockaddr *)(x.buf + recvlen + slot));
    G3_EQ(ll, sizeof(struct sockaddr_in)); G3_EQ(rl, sizeof(struct sockaddr_in));
    if (l && ll == sizeof(struct sockaddr_in)) {
        struct sockaddr_in *li = (struct sockaddr_in *)l;
        G3_EQ(li->sin_family, AF_INET); CHECK(li->sin_port == x.laddr.sin_port); CHECK(li->sin_addr.s_addr == x.laddr.sin_addr.s_addr);
    }
    if (r && rl == sizeof(struct sockaddr_in)) {
        struct sockaddr_in *ri = (struct sockaddr_in *)r;
        G3_EQ(ri->sin_family, AF_INET); CHECK(ri->sin_port == x.caddr.sin_port); CHECK(ri->sin_addr.s_addr == x.caddr.sin_addr.s_addr);
    }
    if (plen && recvlen >= (DWORD)plen) CHECK(!memcmp(x.buf, payload, plen));
    acc_done(&x);
}

TEST(gap3_gaes_real_accept_without_data)
{
    NEED_PTR();
    real_case(fn, 0, NULL, 0);
}
TEST(gap3_gaes_real_accept_with_data_in_the_buffer)
{
    NEED_PTR();
    real_case(fn, 5, "hello", 5);
}
TEST(gap3_gaes_real_accept_with_a_larger_receive_area_than_data)
{
    NEED_PTR();
    real_case(fn, 64, "abc", 3);
}
TEST(gap3_gaes_real_accept_through_the_export)
{
    gaes_fn ex = gaes_export();
    if (!ex) { t_skip("export unavailable"); return; }
    real_case(ex, 0, NULL, 0);
    real_case(ex, 8, "12345678", 8);
}
