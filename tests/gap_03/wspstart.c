/* mswsock WSPStartup depth, driven directly: version contract table (only 2.2 accepted, error is the return
 * value, outputs untouched on rejection), exactly what a successful start writes (versions, description text,
 * terminator, nothing beyond it), the 30-entry procedure table, repeatability, and that the provider does not
 * insist on a known ProviderId in the protocol info. Each test balances every successful start with the
 * provider's own cleanup entry so the process-wide count returns to where it was. The upcall table handed in is
 * never exercised (no socket is created through the provider here), so its entries are NULL. */
#include "g3.h"

typedef int (WSPAPI *wspstart_fn)(WORD, LPWSPDATA, LPWSAPROTOCOL_INFOW, WSPUPCALLTABLE, LPWSPPROC_TABLE);
#define WS() ((wspstart_fn)t_proc_in("mswsock.dll", "WSPStartup"))

static const GUID throwaway = { 0x7c3b1e52, 0x9a44, 0x4d0f, { 0x8e, 0x21, 0xb6, 0x5a, 0x03, 0xd9, 0x4c, 0x17 } };

static int start(WORD v, WSPDATA *d, WSAPROTOCOL_INFOW *pi, WSPPROC_TABLE *t)
{
    WSPUPCALLTABLE u;
    memset(&u, 0, sizeof u);
    return WS()(v, d, pi, u, t);
}
static void stop(WSPPROC_TABLE *t) { int e = 0; if (t->lpWSPCleanup) t->lpWSPCleanup(&e); }
static void tcp_info(WSAPROTOCOL_INFOW *pi)
{
    memset(pi, 0, sizeof *pi);
    pi->iAddressFamily = AF_INET; pi->iSocketType = SOCK_STREAM; pi->iProtocol = IPPROTO_TCP;
    pi->ProviderId = (GUID){ 0xE70F1AA0, 0xAB8B, 0x11CF, { 0x8C, 0xA3, 0x00, 0x80, 0x5F, 0x48, 0xA1, 0x92 } };
}

TEST(gap3_wspstartup_rejects_every_version_but_2_2_with_vernotsupported)
{
    static const WORD bad[] = { 0x0000, 0x0001, 0x0002, 0x0100, 0x0101, 0x0102, 0x0200, 0x0201, 0x0203, 0x0300, 0x0302, 0x0A02, 0x0222, 0x2202, 0xFFFF, 0x0402 };
    unsigned i;
    REQUIRE(WS());
    for (i = 0; i < sizeof bad / sizeof *bad; i++) {
        WSPDATA d; WSPPROC_TABLE t; WSAPROTOCOL_INFOW pi; int r;
        tcp_info(&pi);
        memset(&d, 0x5A, sizeof d); memset(&t, 0x5A, sizeof t);
        r = start(bad[i], &d, &pi, &t);
        CHECKF(r == WSAVERNOTSUPPORTED, "version 0x%04x returned %d", bad[i], r);
        CHECKF(d.wVersion == 0x5A5A && d.wHighVersion == 0x5A5A, "version 0x%04x touched WSPDATA", bad[i]);
        CHECKF(((unsigned char *)&t)[0] == 0x5A && ((unsigned char *)&t)[sizeof t - 1] == 0x5A, "version 0x%04x touched the table", bad[i]);
        if (r == 0) stop(&t);
    }
}

TEST(gap3_wspstartup_version_error_is_the_return_value_not_last_error)
{
    WSPDATA d; WSPPROC_TABLE t; WSAPROTOCOL_INFOW pi;
    REQUIRE(WS());
    tcp_info(&pi);
    SET_ERR(0x4242);
    G3_EQ(start(0x0101, &d, &pi, &t), WSAVERNOTSUPPORTED);
    CHECK(GetLastError() == 0x4242 || GetLastError() == 0);
}

TEST(gap3_wspstartup_accepts_2_2_and_fills_versions)
{
    WSPDATA d; WSPPROC_TABLE t; WSAPROTOCOL_INFOW pi;
    REQUIRE(WS());
    tcp_info(&pi);
    memset(&d, 0, sizeof d); memset(&t, 0, sizeof t);
    G3_EQ(start(MAKEWORD(2, 2), &d, &pi, &t), 0);
    G3_EQ(d.wVersion, 0x0202); G3_EQ(d.wHighVersion, 0x0202);
    stop(&t);
}

TEST(gap3_wspstartup_description_is_terminated_and_leaves_the_rest_alone)
{
    WSPDATA d; WSPPROC_TABLE t; WSAPROTOCOL_INFOW pi; unsigned i;
    REQUIRE(WS());
    tcp_info(&pi);
    for (i = 0; i < 256; i++) d.szDescription[i] = 0x7777;
    memset(&t, 0, sizeof t);
    G3_EQ(start(MAKEWORD(2, 2), &d, &pi, &t), 0);
    EXPECT_WSTR(d.szDescription, L"Microsoft Windows Sockets Version 2.");
    G3_EQ(d.szDescription[36], 0);
    G3_EQ(d.szDescription[37], 0x7777);        /* only the characters and one terminator are written */
    G3_EQ(d.szDescription[255], 0x7777);
    stop(&t);
}

TEST(gap3_wspstartup_table_has_thirty_nonnull_distinct_entries)
{
    WSPDATA d; WSPPROC_TABLE t; WSAPROTOCOL_INFOW pi; void **p = (void **)&t; int i, j;
    REQUIRE(WS());
    tcp_info(&pi);
    memset(&t, 0, sizeof t);
    G3_EQ(start(MAKEWORD(2, 2), &d, &pi, &t), 0);
    for (i = 0; i < 30; i++) CHECKF(p[i] != NULL, "entry %d NULL", i);
    for (i = 0; i < 30; i++) for (j = i + 1; j < 30; j++) CHECKF(p[i] != p[j], "entries %d,%d equal", i, j);
    stop(&t);
}

TEST(gap3_wspstartup_table_slot_order_follows_the_spi_declaration)
{
    /* The table is positional: the entry named lpWSPCleanup must be the one that balances the start, and
     * lpWSPSocket must be a different, mswsock-resident function. */
    WSPDATA d; WSPPROC_TABLE t; WSAPROTOCOL_INFOW pi; HMODULE h = NULL;
    REQUIRE(WS());
    tcp_info(&pi);
    memset(&t, 0, sizeof t);
    G3_EQ(start(MAKEWORD(2, 2), &d, &pi, &t), 0);
    CHECK(t.lpWSPSocket != NULL && t.lpWSPSocket != (void *)t.lpWSPCleanup);
    CHECK(GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)t.lpWSPSocket, &h) && h == t_module("mswsock.dll"));
    {
        int e = -1;
        G3_EQ(t.lpWSPCleanup(&e), 0);
    }
}

TEST(gap3_wspstartup_repeated_starts_return_the_same_table)
{
    WSPDATA d1, d2; WSPPROC_TABLE t1, t2; WSAPROTOCOL_INFOW pi;
    REQUIRE(WS());
    tcp_info(&pi);
    memset(&t1, 0, sizeof t1); memset(&t2, 0, sizeof t2);
    G3_EQ(start(MAKEWORD(2, 2), &d1, &pi, &t1), 0);
    G3_EQ(start(MAKEWORD(2, 2), &d2, &pi, &t2), 0);
    CHECK(!memcmp(&t1, &t2, sizeof t1));
    CHECK(d1.wVersion == d2.wVersion && d1.wHighVersion == d2.wHighVersion && !wcscmp(d1.szDescription, d2.szDescription));
    stop(&t2); stop(&t1);
}

TEST(gap3_wspstartup_accepts_an_unrelated_provider_id)
{
    /* The base provider does not refuse a protocol info carrying a GUID it does not own. */
    WSPDATA d; WSPPROC_TABLE t; WSAPROTOCOL_INFOW pi;
    REQUIRE(WS());
    tcp_info(&pi); pi.ProviderId = throwaway;
    memset(&t, 0, sizeof t);
    G3_EQ(start(MAKEWORD(2, 2), &d, &pi, &t), 0);
    CHECK(t.lpWSPSocket != NULL);
    stop(&t);
}

TEST(gap3_wspstartup_accepts_an_all_zero_protocol_info)
{
    WSPDATA d; WSPPROC_TABLE t; WSAPROTOCOL_INFOW pi;
    REQUIRE(WS());
    memset(&pi, 0, sizeof pi); memset(&t, 0, sizeof t);
    G3_EQ(start(MAKEWORD(2, 2), &d, &pi, &t), 0);
    stop(&t);
}

TEST(gap3_wspstartup_accepts_the_udp_and_ipv6_catalog_shapes)
{
    static const struct { int af, ty, pr; } c[] = { { AF_INET, SOCK_DGRAM, IPPROTO_UDP }, { AF_INET6, SOCK_STREAM, IPPROTO_TCP }, { AF_INET6, SOCK_DGRAM, IPPROTO_UDP }, { AF_INET, SOCK_RAW, 0 } };
    unsigned i;
    REQUIRE(WS());
    for (i = 0; i < 4; i++) {
        WSPDATA d; WSPPROC_TABLE t; WSAPROTOCOL_INFOW pi;
        tcp_info(&pi); pi.iAddressFamily = c[i].af; pi.iSocketType = c[i].ty; pi.iProtocol = c[i].pr;
        memset(&t, 0, sizeof t);
        G3_EQ(start(MAKEWORD(2, 2), &d, &pi, &t), 0);
        stop(&t);
    }
}

TEST(gap3_wspstartup_table_entries_are_the_same_across_different_protocol_infos)
{
    WSPDATA d; WSPPROC_TABLE t1, t2; WSAPROTOCOL_INFOW p1, p2;
    REQUIRE(WS());
    tcp_info(&p1); tcp_info(&p2); p2.iAddressFamily = AF_INET6; p2.iSocketType = SOCK_DGRAM; p2.iProtocol = IPPROTO_UDP;
    memset(&t1, 0, sizeof t1); memset(&t2, 0, sizeof t2);
    G3_EQ(start(MAKEWORD(2, 2), &d, &p1, &t1), 0);
    G3_EQ(start(MAKEWORD(2, 2), &d, &p2, &t2), 0);
    CHECK(!memcmp(&t1, &t2, sizeof t1));
    stop(&t2); stop(&t1);
}

TEST(gap3_wspstartup_cleanup_entry_balances_and_reports_success_repeatedly)
{
    WSPDATA d; WSPPROC_TABLE t; WSAPROTOCOL_INFOW pi; int e, i;
    REQUIRE(WS());
    tcp_info(&pi);
    memset(&t, 0, sizeof t);
    for (i = 0; i < 4; i++) G3_EQ(start(MAKEWORD(2, 2), &d, &pi, &t), 0);
    for (i = 0; i < 4; i++) { e = -1; G3_EQ(t.lpWSPCleanup(&e), 0); }
}

TEST(gap3_wspstartup_start_stop_cycles_in_a_clean_process_are_repeatable)
{
    G3_EQ(t_run_child("wspstart_cycles", "", 30000), 0);
}
CHILD(wspstart_cycles)
{
    int i;
    if (!WS()) return 2;
    for (i = 0; i < 5; i++) {
        WSPDATA d; WSPPROC_TABLE t; WSAPROTOCOL_INFOW pi; int e = -1;
        tcp_info(&pi); memset(&t, 0, sizeof t);
        if (start(MAKEWORD(2, 2), &d, &pi, &t) != 0) return 3;
        if (d.wVersion != 0x0202) return 4;
        if (t.lpWSPCleanup(&e) != 0) return 5;
    }
    return 0;
}

TEST(gap3_wspstartup_is_not_a_ws2_32_export)
{
    CHECK(t_proc_in("ws2_32.dll", "WSPStartup") == NULL);
    CHECK(t_proc_in("mswsock.dll", "WSPStartup") != NULL);
}
