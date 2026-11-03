/* Measures the data-carrying and state-changing WSAIoctl controls: SIO_BASE_HANDLE and the BSP handle queries,
 * SIO_GET_BROADCAST_ADDRESS, SIO_GET_QOS / SIO_SET_QOS and the group variants, SIO_ENABLE_CIRCULAR_QUEUEING,
 * SIO_MULTIPOINT_LOOPBACK, SIO_MULTICAST_SCOPE, SIO_KEEPALIVE_VALS, SIO_LOOPBACK_FAST_PATH,
 * SIO_TCP_INITIAL_RTO, SIO_SET_COMPATIBILITY_MODE, SIO_QUERY_RSS_PROCESSOR_INFO and the controls that this
 * stack answers with a fixed "not supported" error.  The buffer-length protocol of each control is covered in
 * matrix.c; here the concern is the values returned and written. */
#include "ib.h"

/* ---- handle queries ---------------------------------------------------------------------------- */
static const DWORD ib_handle_codes[] = {IB_BASE_HANDLE, IB_BSP_HANDLE, IB_BSP_HANDLE_SELECT, IB_BSP_HANDLE_POLL};
static const char *const ib_handle_names[] = {"BASE_HANDLE", "BSP_HANDLE", "BSP_HANDLE_SELECT", "BSP_HANDLE_POLL"};
static const int ib_handle_kinds[] = {K_TCP4, K_UDP4, K_TCP6, K_UDP6, K_UNIX, K_LISTEN4};

IBTEST(ib_handles_report_the_socket_itself)
{
    /* No layered providers are installed in the test environment, so the base/BSP handle is the handle given. */
    unsigned i, j;
    for (i = 0; i < 4; ++i)
        for (j = 0; j < 6; ++j) {
            SOCKET s = ib_mk(ib_handle_kinds[j]);
            SOCKET out = 0;
            ib_res x;
            if (s == INVALID_SOCKET) continue;
            x = ib_io(s, ib_handle_codes[i], NULL, 0, &out, sizeof out, 1);
            CHECKF(IB_OK(x) && x.n == sizeof(SOCKET) && out == s, "%s kind %d: r=%d err=%d n=%lu same=%d", ib_handle_names[i],
                   ib_handle_kinds[j], x.r, x.err, x.n, out == s);
            ib_close(s);
        }
}

IBTEST(ib_handles_large_output_writes_eight_bytes_only)
{
    unsigned i;
    for (i = 0; i < 4; ++i) {
        SOCKET s = ib_mk(K_TCP4);
        unsigned char out[24];
        ib_res x;
        REQUIRE(s != INVALID_SOCKET);
        memset(out, 0xcc, sizeof out);
        x = ib_io(s, ib_handle_codes[i], NULL, 0, out, sizeof out, 1);
        CHECKF(IB_OK(x) && x.n == 8, "%s: r=%d err=%d n=%lu", ib_handle_names[i], x.r, x.err, x.n);
        CHECKF(out[8] == 0xcc && out[23] == 0xcc, "%s wrote past eight bytes", ib_handle_names[i]);
        ib_close(s);
    }
}

IBTEST(ib_handles_short_output_is_fault_and_count_untouched)
{
    unsigned i;
    unsigned lens[] = {0, 1, 4, 7};
    for (i = 0; i < 4; ++i) {
        unsigned k;
        SOCKET s = ib_mk(K_TCP4);
        REQUIRE(s != INVALID_SOCKET);
        for (k = 0; k < 4; ++k) {
            unsigned char out[8] = {0};
            ib_res x = ib_io(s, ib_handle_codes[i], NULL, 0, out, lens[k], 1);
            CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == IB_UNSET, "%s len %u: r=%d err=%d n=%lu", ib_handle_names[i], lens[k], x.r,
                   x.err, x.n);
        }
        ib_close(s);
    }
}

IBTEST(ib_handles_input_buffer_is_ignored)
{
    SOCKET s = ib_mk(K_TCP4);
    char in[64];
    SOCKET out = 0;
    ib_res x;
    REQUIRE(s != INVALID_SOCKET);
    memset(in, 0x5a, sizeof in);
    x = ib_io(s, IB_BASE_HANDLE, in, sizeof in, &out, sizeof out, 1);
    CHECKF(IB_OK(x) && out == s, "r=%d err=%d", x.r, x.err);
    ib_close(s);
}

/* ---- SIO_GET_BROADCAST_ADDRESS ---------------------------------------------------------------- */
IBTEST(ib_bcast_datagram_reports_limited_broadcast)
{
    IB_SOCK(u, K_UDP4);
    struct sockaddr_in a;
    ib_res x;
    memset(&a, 0xcc, sizeof a);
    x = ib_io(u, IB_GET_BCAST, NULL, 0, &a, sizeof a, 1);
    CHECKF(IB_OK(x) && x.n == sizeof a, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    CHECK(a.sin_family == AF_INET);
    CHECK(a.sin_port == 0);
    CHECK(a.sin_addr.s_addr == 0xffffffffu);
    ib_close(u);
}

IBTEST(ib_bcast_large_buffer_writes_sixteen_bytes)
{
    IB_SOCK(u, K_UDP4);
    unsigned char b[40];
    ib_res x;
    memset(b, 0xcc, sizeof b);
    x = ib_io(u, IB_GET_BCAST, NULL, 0, b, sizeof b, 1);
    CHECKF(IB_OK(x) && x.n == 16, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    CHECK(b[16] == 0xcc && b[39] == 0xcc);
    ib_close(u);
}

IBTEST(ib_bcast_short_buffer_is_fault)
{
    IB_SOCK(u, K_UDP4);
    unsigned char b[16];
    unsigned len;
    for (len = 0; len < 16; len += 5) {
        ib_res x = ib_io(u, IB_GET_BCAST, NULL, 0, b, len, 1);
        CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == IB_UNSET, "len %u: r=%d err=%d n=%lu", len, x.r, x.err, x.n);
    }
    {
        ib_res x = ib_io(u, IB_GET_BCAST, NULL, 0, b, 15, 1);
        CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == IB_UNSET, "len 15: r=%d err=%d", x.r, x.err);
    }
    ib_close(u);
}

IBTEST(ib_bcast_stream_socket_is_invalid)
{
    static const int kinds[] = {K_TCP4, K_LISTEN4, K_CONN4};
    unsigned i;
    for (i = 0; i < 3; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        struct sockaddr_in a;
        ib_res x;
        if (s == INVALID_SOCKET) continue;
        x = ib_io(s, IB_GET_BCAST, NULL, 0, &a, sizeof a, 1);
        CHECKF(IB_FAILS(x, WSAEINVAL), "kind %d: r=%d err=%d", kinds[i], x.r, x.err);
        ib_close(s);
    }
}

IBTEST(ib_bcast_ipv6_datagram_has_no_broadcast_control)
{
    IB_SOCK(u, K_UDP6);
    unsigned char b[28];
    ib_res x = ib_io(u, IB_GET_BCAST, NULL, 0, b, sizeof b, 1);
    CHECKF(IB_FAILS(x, WSAENOPROTOOPT), "r=%d err=%d", x.r, x.err);
    ib_close(u);
}

/* ---- QOS ---------------------------------------------------------------------------------------- */
static void ib_check_default_qos(const unsigned char *b, const char *what)
{
    /* First flowspec: every rate/size field is "not specified" (all ones); service type is best effort. */
    const DWORD *d = (const DWORD *)b;
    unsigned i;
    for (i = 0; i < 5; ++i) CHECKF(d[i] == 0xffffffffu, "%s: field %u = %#lx", what, i, d[i]);
    CHECKF(d[5] == 1, "%s: service type %lu", what, d[5]);
}

IBTEST(ib_qos_get_returns_eighty_byte_default)
{
    static const int kinds[] = {K_UDP4, K_TCP4, K_CONN4};
    unsigned i;
    for (i = 0; i < 3; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        unsigned char b[200];
        ib_res x;
        if (s == INVALID_SOCKET) continue;
        memset(b, 0xcc, sizeof b);
        x = ib_io(s, IB_GET_QOS, NULL, 0, b, sizeof b, 1);
        CHECKF(IB_OK(x) && x.n == 80, "kind %d: r=%d err=%d n=%lu", kinds[i], x.r, x.err, x.n);
        CHECK(b[80] == 0xcc && b[199] == 0xcc);
        ib_check_default_qos(b, "GET_QOS");
        ib_close(s);
    }
}

IBTEST(ib_qos_group_get_matches_plain_get)
{
    IB_SOCK(u, K_UDP4);
    unsigned char a[96], g[96];
    ib_res x, y;
    memset(a, 0xcc, sizeof a); memset(g, 0xcc, sizeof g);
    x = ib_io(u, IB_GET_QOS, NULL, 0, a, sizeof a, 1);
    y = ib_io(u, IB_GET_GROUP_QOS, NULL, 0, g, sizeof g, 1);
    CHECKF(IB_OK(x) && IB_OK(y) && x.n == 80 && y.n == 80, "r=%d/%d n=%lu/%lu", x.r, y.r, x.n, y.n);
    CHECK(memcmp(a, g, 24) == 0);
    ib_check_default_qos(g, "GET_GROUP_QOS");
    ib_close(u);
}

IBTEST(ib_qos_get_short_buffer_reports_required_size)
{
    static const DWORD codes[] = {IB_GET_QOS, IB_GET_GROUP_QOS};
    unsigned i, len;
    IB_SOCK(u, K_UDP4);
    for (i = 0; i < 2; ++i)
        for (len = 0; len <= 79; len += (len < 8 ? 4 : 71)) {
            unsigned char b[96];
            ib_res x = ib_io(u, codes[i], NULL, 0, b, len, 1);
            CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == 80, "code %#lx len %u: r=%d err=%d n=%lu", codes[i], len, x.r, x.err, x.n);
        }
    ib_close(u);
}

IBTEST(ib_qos_set_accepts_a_zeroed_structure)
{
    static const DWORD codes[] = {IB_SET_QOS, IB_SET_GROUP_QOS};
    static const int kinds[] = {K_UDP4, K_TCP4};
    unsigned i, j;
    for (j = 0; j < 2; ++j) {
        SOCKET s = ib_mk(kinds[j]);
        REQUIRE(s != INVALID_SOCKET);
        for (i = 0; i < 2; ++i) {
            unsigned char q[96];
            ib_res x;
            memset(q, 0, sizeof q);
            x = ib_io(s, codes[i], q, 80, NULL, 0, 1);
            CHECKF(IB_OK(x) && x.n == 0, "code %#lx kind %d: r=%d err=%d n=%lu", codes[i], kinds[j], x.r, x.err, x.n);
        }
        ib_close(s);
    }
}

IBTEST(ib_qos_set_without_input_is_fault)
{
    static const DWORD codes[] = {IB_SET_QOS, IB_SET_GROUP_QOS};
    unsigned i;
    IB_SOCK(u, K_UDP4);
    for (i = 0; i < 2; ++i) {
        unsigned char q[8] = {0};
        ib_res x = ib_io(u, codes[i], q, 0, NULL, 0, 1);
        CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == IB_UNSET, "code %#lx: r=%d err=%d n=%lu", codes[i], x.r, x.err, x.n);
    }
    ib_close(u);
}

/* ---- the fixed-answer controls ---------------------------------------------------------------- */
IBTEST(ib_fixed_answer_unsupported_controls)
{
    /* code, expected error: controls this stack answers identically for every socket kind used. */
    static const struct { DWORD code; int err; const char *name; } t[] = {
        {IB_FLUSH, WSAEOPNOTSUPP, "SIO_FLUSH"},
        {IB_FIND_ROUTE, WSAEOPNOTSUPP, "SIO_FIND_ROUTE"},
        {IB_QUERY_PNP, WSAEOPNOTSUPP, "SIO_QUERY_TARGET_PNP_HANDLE"},
        {IB_RSS_INFO, WSAEOPNOTSUPP, "SIO_QUERY_RSS_PROCESSOR_INFO"},
        {IB_ABSORB_RTRALERT, WSAEOPNOTSUPP, "SIO_ABSORB_RTRALERT"},
        {IB_UCAST_IF, WSAEOPNOTSUPP, "SIO_UCAST_IF"},
        {IB_LIMIT_BCAST, WSAEOPNOTSUPP, "SIO_LIMIT_BROADCASTS"},
        {IB_NSP_NOTIFY, WSAEOPNOTSUPP, "SIO_NSP_NOTIFY_CHANGE"},
        {IB_ASSOCIATE_HANDLE, WSAENOPROTOOPT, "SIO_ASSOCIATE_HANDLE"},
        {IB_TRANSLATE_HANDLE, WSAENOPROTOOPT, "SIO_TRANSLATE_HANDLE"},
    };
    static const int kinds[] = {K_TCP4, K_UDP4, K_CONN4};
    unsigned i, j;
    for (j = 0; j < 3; ++j) {
        SOCKET s = ib_mk(kinds[j]);
        REQUIRE(s != INVALID_SOCKET);
        for (i = 0; i < sizeof t / sizeof *t; ++i) {
            DWORD in[4] = {0, 0, 0, 0}, out[8];
            ib_res x = ib_io(s, t[i].code, in, 16, out, sizeof out, 1);
            CHECKF(IB_FAILS(x, t[i].err), "%s kind %d: r=%d err=%d", t[i].name, kinds[j], x.r, x.err);
        }
        ib_close(s);
    }
}

/* ---- SIO_ENABLE_CIRCULAR_QUEUEING --------------------------------------------------------------- */
IBTEST(ib_circq_succeeds_on_datagram_without_touching_count)
{
    static const int kinds[] = {K_UDP4, K_UDP6};
    unsigned i;
    for (i = 0; i < 2; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        ib_res x;
        if (s == INVALID_SOCKET) continue;
        x = ib_io(s, IB_ENABLE_CIRCQ, NULL, 0, NULL, 0, 1);
        CHECKF(IB_OK(x), "kind %d: r=%d err=%d", kinds[i], x.r, x.err);
        CHECKF(x.n == IB_UNSET, "kind %d: byte count written (%lu)", kinds[i], x.n);
        ib_close(s);
    }
}

IBTEST(ib_circq_is_invalid_on_streams)
{
    static const int kinds[] = {K_TCP4, K_LISTEN4, K_TCP6};
    unsigned i;
    for (i = 0; i < 3; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        ib_res x;
        if (s == INVALID_SOCKET) continue;
        x = ib_io(s, IB_ENABLE_CIRCQ, NULL, 0, NULL, 0, 1);
        CHECKF(IB_FAILS(x, WSAEINVAL), "kind %d: r=%d err=%d", kinds[i], x.r, x.err);
        ib_close(s);
    }
}

/* ---- multipoint loopback / multicast scope ------------------------------------------------------ */
IBTEST(ib_multipoint_loopback_accepts_flags_on_datagrams)
{
    static const int kinds[] = {K_UDP4, K_UDP6};
    static const DWORD vals[] = {0, 1, 2, 0xffffffffu};
    unsigned i, j;
    for (i = 0; i < 2; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        if (s == INVALID_SOCKET) continue;
        for (j = 0; j < 4; ++j) {
            DWORD v = vals[j];
            ib_res x = ib_io(s, IB_MP_LOOPBACK, &v, 4, NULL, 0, 1);
            CHECKF(IB_OK(x) && x.n == 0, "kind %d value %#lx: r=%d err=%d n=%lu", kinds[i], vals[j], x.r, x.err, x.n);
        }
        ib_close(s);
    }
}

IBTEST(ib_multipoint_loopback_rejected_on_streams)
{
    static const int kinds[] = {K_TCP4, K_LISTEN4, K_CONN4};
    unsigned i;
    for (i = 0; i < 3; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        DWORD v = 1;
        ib_res x;
        if (s == INVALID_SOCKET) continue;
        x = ib_io(s, IB_MP_LOOPBACK, &v, 4, NULL, 0, 1);
        CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "kind %d: r=%d err=%d n=%lu", kinds[i], x.r, x.err, x.n);
        ib_close(s);
    }
}

IBTEST(ib_multicast_scope_range)
{
    /* The scope (time-to-live) is limited to 255. */
    static const struct { DWORD v; int ok; } t[] = {{0, 1}, {1, 1}, {2, 1}, {64, 1}, {255, 1}, {256, 0}, {1000, 0}, {0x80000000u, 0}};
    unsigned i;
    IB_SOCK(u, K_UDP4);
    for (i = 0; i < sizeof t / sizeof *t; ++i) {
        DWORD v = t[i].v;
        ib_res x = ib_io(u, IB_MC_SCOPE, &v, 4, NULL, 0, 1);
        if (t[i].ok) CHECKF(IB_OK(x) && x.n == 0, "scope %lu: r=%d err=%d n=%lu", t[i].v, x.r, x.err, x.n);
        else CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "scope %lu: r=%d err=%d n=%lu", t[i].v, x.r, x.err, x.n);
    }
    ib_close(u);
}

IBTEST(ib_multicast_scope_rejected_on_streams)
{
    static const int kinds[] = {K_TCP4, K_CONN4};
    unsigned i;
    for (i = 0; i < 2; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        DWORD v = 1;
        ib_res x;
        if (s == INVALID_SOCKET) continue;
        x = ib_io(s, IB_MC_SCOPE, &v, 4, NULL, 0, 1);
        CHECKF(IB_FAILS(x, WSAEINVAL), "kind %d: r=%d err=%d", kinds[i], x.r, x.err);
        ib_close(s);
    }
}

/* ---- SIO_KEEPALIVE_VALS -------------------------------------------------------------------------- */
static int ib_keepalive_enabled(SOCKET s)
{
    int v = -1, len = sizeof v;
    if (U(getsockopt)(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&v, &len)) return -1;
    return v & 0xff;       /* only the low byte is written for this option */
}

IBTEST(ib_keepalive_vals_toggle_so_keepalive)
{
    SOCKET s = ib_mk(K_TCP4);
    struct tcp_keepalive k;
    ib_res x;
    REQUIRE(s != INVALID_SOCKET);
    CHECK(ib_keepalive_enabled(s) == 0);
    k.onoff = 1; k.keepalivetime = 60000; k.keepaliveinterval = 1000;
    x = ib_io(s, IB_KEEPALIVE, &k, sizeof k, NULL, 0, 1);
    CHECKF(IB_OK(x) && x.n == 0, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    CHECK(ib_keepalive_enabled(s) == 1);
    k.onoff = 0;
    x = ib_io(s, IB_KEEPALIVE, &k, sizeof k, NULL, 0, 1);
    CHECK(IB_OK(x));
    CHECK(ib_keepalive_enabled(s) == 0);
    ib_close(s);
}

IBTEST(ib_keepalive_vals_onoff_other_than_one_disables)
{
    SOCKET s = ib_mk(K_TCP4);
    struct tcp_keepalive k;
    ib_res x;
    REQUIRE(s != INVALID_SOCKET);
    k.onoff = 2; k.keepalivetime = 60000; k.keepaliveinterval = 1000;
    x = ib_io(s, IB_KEEPALIVE, &k, sizeof k, NULL, 0, 1);
    CHECKF(IB_OK(x), "r=%d err=%d", x.r, x.err);
    CHECK(ib_keepalive_enabled(s) == 0);    /* only exactly 1 turns keep-alive on */
    k.onoff = 1;
    ib_io(s, IB_KEEPALIVE, &k, sizeof k, NULL, 0, 1);
    CHECK(ib_keepalive_enabled(s) == 1);
    k.onoff = 2;
    ib_io(s, IB_KEEPALIVE, &k, sizeof k, NULL, 0, 1);
    CHECK(ib_keepalive_enabled(s) == 0);    /* and any other value turns it off again */
    k.onoff = 0xffffffffu;
    ib_io(s, IB_KEEPALIVE, &k, sizeof k, NULL, 0, 1);
    CHECK(ib_keepalive_enabled(s) == 0);
    ib_close(s);
}

IBTEST(ib_keepalive_vals_extreme_timings_are_accepted)
{
    static const struct { DWORD t, i; } t[] = {{0, 0}, {1, 0}, {0, 1}, {5, 5}, {0xffffffffu, 0xffffffffu}, {1000, 1000}};
    unsigned j;
    SOCKET s = ib_mk(K_TCP4);
    REQUIRE(s != INVALID_SOCKET);
    for (j = 0; j < sizeof t / sizeof *t; ++j) {
        struct tcp_keepalive k;
        ib_res x;
        k.onoff = 1; k.keepalivetime = t[j].t; k.keepaliveinterval = t[j].i;
        x = ib_io(s, IB_KEEPALIVE, &k, sizeof k, NULL, 0, 1);
        CHECKF(IB_OK(x), "time %lu interval %lu: r=%d err=%d", t[j].t, t[j].i, x.r, x.err);
    }
    ib_close(s);
}

IBTEST(ib_keepalive_vals_input_length_rules)
{
    /* At least the 12-byte structure must be supplied; extra bytes are ignored; output buffers are ignored. */
    SOCKET s = ib_mk(K_TCP4);
    unsigned char in[32] = {1, 0, 0, 0, 0x60, 0xea, 0, 0, 0xe8, 3, 0, 0};
    static const struct { unsigned len; int ok; } t[] = {{11, 0}, {12, 1}, {13, 1}, {16, 1}, {32, 1}, {8, 0}, {4, 0}, {0, 0}};
    unsigned j;
    REQUIRE(s != INVALID_SOCKET);
    for (j = 0; j < sizeof t / sizeof *t; ++j) {
        ib_res x = ib_io(s, IB_KEEPALIVE, in, t[j].len, NULL, 0, 1);
        if (t[j].ok) CHECKF(IB_OK(x), "len %u: r=%d err=%d", t[j].len, x.r, x.err);
        else CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == 0, "len %u: r=%d err=%d n=%lu", t[j].len, x.r, x.err, x.n);
    }
    {
        DWORD out[2] = {0xcccccccc, 0xcccccccc};
        ib_res x = ib_io(s, IB_KEEPALIVE, in, 12, out, sizeof out, 1);
        CHECKF(IB_OK(x) && x.n == 0 && out[0] == 0xcccccccc, "with output: r=%d err=%d n=%lu", x.r, x.err, x.n);
    }
    ib_close(s);
}

IBTEST(ib_keepalive_vals_unsupported_on_datagram_and_unix)
{
    static const int kinds[] = {K_UDP4, K_UDP6, K_UNIX};
    unsigned i;
    for (i = 0; i < 3; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        struct tcp_keepalive k = {1, 1000, 1000};
        ib_res x;
        if (s == INVALID_SOCKET) continue;
        x = ib_io(s, IB_KEEPALIVE, &k, sizeof k, NULL, 0, 1);
        CHECKF(IB_FAILS(x, WSAEOPNOTSUPP) && x.n == 0, "kind %d: r=%d err=%d n=%lu", kinds[i], x.r, x.err, x.n);
        ib_close(s);
    }
}

IBTEST(ib_keepalive_vals_on_connected_and_closed_peer)
{
    IB_PAIR(c, s);
    struct tcp_keepalive k = {1, 7200000, 1000};
    ib_res x = ib_io(c, IB_KEEPALIVE, &k, sizeof k, NULL, 0, 1);
    CHECKF(IB_OK(x), "connected: r=%d err=%d", x.r, x.err);
    ib_close(s);
    x = ib_io(c, IB_KEEPALIVE, &k, sizeof k, NULL, 0, 1);
    CHECKF(IB_OK(x), "peer closed: r=%d err=%d", x.r, x.err);
    ib_close(c);
}

IBTEST(ib_keepalive_vals_keepalive_idle_and_interval_options)
{
    /* The timing fields are stored per socket; they are observable through the TCP-level options, in seconds. */
    SOCKET s = ib_mk(K_TCP4);
    struct tcp_keepalive k = {1, 120000, 5000};
    int idle = -1, intv = -1, len = sizeof idle, r;
    ib_res x;
    REQUIRE(s != INVALID_SOCKET);
    x = ib_io(s, IB_KEEPALIVE, &k, sizeof k, NULL, 0, 1);
    CHECK(IB_OK(x));
    r = U(getsockopt)(s, IPPROTO_TCP, 3 /* TCP_KEEPIDLE */, (char *)&idle, &len);
    CHECKF(r == 0 && idle == 120, "TCP_KEEPIDLE r=%d idle=%d", r, idle);
    len = sizeof intv;
    r = U(getsockopt)(s, IPPROTO_TCP, 17 /* TCP_KEEPINTVL */, (char *)&intv, &len);
    CHECKF(r == 0 && intv == 5, "TCP_KEEPINTVL r=%d interval=%d", r, intv);
    ib_close(s);
}

/* ---- SIO_LOOPBACK_FAST_PATH --------------------------------------------------------------------- */
IBTEST(ib_loopback_fast_path_stream_only)
{
    SOCKET t = ib_mk(K_TCP4), u = ib_mk(K_UDP4);
    DWORD v = 1;
    ib_res x;
    REQUIRE(t != INVALID_SOCKET && u != INVALID_SOCKET);
    x = ib_io(t, IB_LOOPBACK_FAST, &v, 4, NULL, 0, 1);
    CHECKF(IB_OK(x) && x.n == 0, "tcp on: r=%d err=%d n=%lu", x.r, x.err, x.n);
    v = 0;
    x = ib_io(t, IB_LOOPBACK_FAST, &v, 4, NULL, 0, 1);
    CHECKF(IB_OK(x), "tcp off: r=%d err=%d", x.r, x.err);
    v = 1;
    x = ib_io(u, IB_LOOPBACK_FAST, &v, 4, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEOPNOTSUPP) && x.n == 0, "udp: r=%d err=%d", x.r, x.err);
    ib_close(t); ib_close(u);
}

IBTEST(ib_loopback_fast_path_connected_socket_not_supported)
{
    IB_PAIR(c, s);
    DWORD v = 1;
    ib_res x = ib_io(c, IB_LOOPBACK_FAST, &v, 4, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEOPNOTSUPP), "r=%d err=%d", x.r, x.err);
    ib_close(c); ib_close(s);
}

IBTEST(ib_loopback_fast_path_input_length_rules)
{
    SOCKET t = ib_mk(K_TCP4);
    DWORD v[4] = {1, 0, 0, 0};
    static const struct { unsigned len; int ok; } tt[] = {{0, 0}, {1, 1}, {2, 1}, {4, 1}, {8, 1}, {16, 1}};
    unsigned i;
    REQUIRE(t != INVALID_SOCKET);
    for (i = 0; i < sizeof tt / sizeof *tt; ++i) {
        ib_res x = ib_io(t, IB_LOOPBACK_FAST, v, tt[i].len, NULL, 0, 1);
        if (tt[i].ok) CHECKF(IB_OK(x), "len %u: r=%d err=%d", tt[i].len, x.r, x.err);
        else CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == 0, "len %u: r=%d err=%d n=%lu", tt[i].len, x.r, x.err, x.n);
    }
    ib_close(t);
}

IBTEST(ib_loopback_fast_path_connection_still_works)
{
    SOCKET l = ib_mk(K_LISTEN4), c = ib_mk(K_TCP4), a = INVALID_SOCKET;
    struct sockaddr_in addr;
    int len = sizeof addr;
    DWORD v = 1;
    char b[4];
    REQUIRE(l != INVALID_SOCKET && c != INVALID_SOCKET);
    CHECK(IB_OK(ib_io(l, IB_LOOPBACK_FAST, &v, 4, NULL, 0, 1)) || 1);
    CHECK(IB_OK(ib_io(c, IB_LOOPBACK_FAST, &v, 4, NULL, 0, 1)));
    U(getsockname)(l, (struct sockaddr *)&addr, &len);
    CHECK(U(connect)(c, (struct sockaddr *)&addr, sizeof addr) == 0);
    a = U(accept)(l, NULL, NULL);
    CHECK(a != INVALID_SOCKET);
    CHECK(U(send)(c, "ping", 4, 0) == 4);
    CHECK(U(recv)(a, b, 4, 0) == 4 && !memcmp(b, "ping", 4));
    if (a != INVALID_SOCKET) ib_close(a);
    ib_close(c); ib_close(l);
}

/* ---- SIO_TCP_INITIAL_RTO ------------------------------------------------------------------------- */
typedef struct { USHORT rtt; UCHAR max; } ib_rto;

IBTEST(ib_initial_rto_accepts_any_values_before_connect)
{
    static const ib_rto t[] = {{3000, 2}, {0xffff, 0xff}, {0, 0}, {3000, 0xfe}, {300, 0}, {1000, 100}, {0xfffe, 1}};
    unsigned i;
    SOCKET s = ib_mk(K_TCP4);
    REQUIRE(s != INVALID_SOCKET);
    for (i = 0; i < sizeof t / sizeof *t; ++i) {
        unsigned char in[4] = {0};
        ib_res x;
        memcpy(in, &t[i].rtt, 2);
        in[2] = t[i].max;
        x = ib_io(s, IB_TCP_INITIAL_RTO, in, 4, NULL, 0, 1);
        CHECKF(IB_OK(x) && x.n == 0, "rtt %u max %u: r=%d err=%d n=%lu", t[i].rtt, t[i].max, x.r, x.err, x.n);
    }
    ib_close(s);
}

IBTEST(ib_initial_rto_input_length_rules)
{
    SOCKET s = ib_mk(K_TCP4);
    unsigned char in[16] = {0xb8, 0x0b, 2, 0};
    static const struct { unsigned len; int ok; } t[] = {{0, 0}, {1, 0}, {3, 0}, {4, 1}, {8, 1}, {16, 1}};
    unsigned i;
    REQUIRE(s != INVALID_SOCKET);
    for (i = 0; i < sizeof t / sizeof *t; ++i) {
        ib_res x = ib_io(s, IB_TCP_INITIAL_RTO, in, t[i].len, NULL, 0, 1);
        if (t[i].ok) CHECKF(IB_OK(x), "len %u: r=%d err=%d", t[i].len, x.r, x.err);
        else CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == 0, "len %u: r=%d err=%d n=%lu", t[i].len, x.r, x.err, x.n);
    }
    ib_close(s);
}

IBTEST(ib_initial_rto_wrong_socket_states)
{
    SOCKET u = ib_mk(K_UDP4), un = ib_mk(K_UNIX);
    IB_PAIR(c, s);
    unsigned char in[4] = {0xb8, 0x0b, 2, 0};
    ib_res x;
    REQUIRE(u != INVALID_SOCKET);
    x = ib_io(u, IB_TCP_INITIAL_RTO, in, 4, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEOPNOTSUPP) && x.n == 0, "udp: r=%d err=%d n=%lu", x.r, x.err, x.n);
    x = ib_io(c, IB_TCP_INITIAL_RTO, in, 4, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL) && x.n == 0, "connected: r=%d err=%d n=%lu", x.r, x.err, x.n);
    if (un != INVALID_SOCKET) {
        x = ib_io(un, IB_TCP_INITIAL_RTO, in, 4, NULL, 0, 1);
        CHECKF(IB_FAILS(x, WSAEOPNOTSUPP), "unix: r=%d err=%d", x.r, x.err);
        ib_close(un);
    }
    ib_close(u); ib_close(c); ib_close(s);
}

IBTEST(ib_initial_rto_refused_connect_still_fails_fast)
{
    /* Reduced SYN retransmissions must not change the outcome against a port nobody listens on:
     * loopback answers with a reset straight away. */
    SOCKET dead = ib_mk(K_LISTEN4), c = ib_mk(K_TCP4);
    struct sockaddr_in a;
    int len = sizeof a, r;
    unsigned char in[4] = {0xb8, 0x0b, 0xfe, 0};
    REQUIRE(dead != INVALID_SOCKET && c != INVALID_SOCKET);
    U(getsockname)(dead, (struct sockaddr *)&a, &len);
    ib_close(dead);
    CHECK(IB_OK(ib_io(c, IB_TCP_INITIAL_RTO, in, 4, NULL, 0, 1)));
    r = U(connect)(c, (struct sockaddr *)&a, sizeof a);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSAECONNREFUSED, "r=%d err=%d", r, ib_err());
    ib_close(c);
}

/* ---- SIO_SET_COMPATIBILITY_MODE --------------------------------------------------------------- */
IBTEST(ib_compat_mode_behavior_ids)
{
    static const struct { DWORD id, os; int ok; } t[] = {
        {0, 0, 1}, {1, 0, 1}, {2, 0, 1}, {3, 0, 0}, {0, 0x0a000000, 1}, {0, 0x06010000, 1}, {0, 0xffffffff, 1}, {100, 0, 0},
    };
    unsigned i;
    SOCKET s = ib_mk(K_TCP4);
    REQUIRE(s != INVALID_SOCKET);
    for (i = 0; i < sizeof t / sizeof *t; ++i) {
        DWORD in[2];
        ib_res x;
        in[0] = t[i].id; in[1] = t[i].os;
        x = ib_io(s, IB_COMPAT_MODE, in, 8, NULL, 0, 1);
        if (t[i].ok) CHECKF(IB_OK(x) && x.n == 0, "id %lu os %#lx: r=%d err=%d n=%lu", t[i].id, t[i].os, x.r, x.err, x.n);
        else CHECKF(IB_FAILS(x, WSAEOPNOTSUPP) && x.n == 0, "id %lu os %#lx: r=%d err=%d n=%lu", t[i].id, t[i].os, x.r, x.err, x.n);
    }
    ib_close(s);
}

IBTEST(ib_compat_mode_input_length_rules)
{
    SOCKET s = ib_mk(K_TCP4);
    DWORD in[4] = {0, 0, 0, 0};
    static const struct { unsigned len; int ok; } t[] = {{0, 0}, {4, 0}, {7, 0}, {8, 1}, {12, 1}, {16, 1}};
    unsigned i;
    REQUIRE(s != INVALID_SOCKET);
    for (i = 0; i < sizeof t / sizeof *t; ++i) {
        ib_res x = ib_io(s, IB_COMPAT_MODE, in, t[i].len, NULL, 0, 1);
        if (t[i].ok) CHECKF(IB_OK(x), "len %u: r=%d err=%d", t[i].len, x.r, x.err);
        else CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == 0, "len %u: r=%d err=%d n=%lu", t[i].len, x.r, x.err, x.n);
    }
    ib_close(s);
}

IBTEST(ib_compat_mode_not_supported_on_datagram_or_unix)
{
    static const int kinds[] = {K_UDP4, K_UDP6, K_UNIX};
    unsigned i;
    for (i = 0; i < 3; ++i) {
        SOCKET s = ib_mk(kinds[i]);
        DWORD in[2] = {0, 0};
        ib_res x;
        if (s == INVALID_SOCKET) continue;
        x = ib_io(s, IB_COMPAT_MODE, in, 8, NULL, 0, 1);
        CHECKF(IB_FAILS(x, WSAEOPNOTSUPP), "kind %d: r=%d err=%d", kinds[i], x.r, x.err);
        ib_close(s);
    }
}

/* ---- SIO_APPLY / QUERY_TRANSPORT_SETTING --------------------------------------------------------- */
IBTEST(ib_transport_setting_calls_without_arguments)
{
    SOCKET t = ib_mk(K_TCP4);
    unsigned char in[64] = {0}, out[64];
    ib_res x;
    REQUIRE(t != INVALID_SOCKET);
    x = ib_io(t, IB_APPLY_TRANSPORT, in, 0, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == 0, "apply none: r=%d err=%d n=%lu", x.r, x.err, x.n);
    x = ib_io(t, IB_APPLY_TRANSPORT, in, 16, NULL, 0, 1);
    CHECKF(IB_FAILS(x, WSAEFAULT) && x.n == 0, "apply 16: r=%d err=%d n=%lu", x.r, x.err, x.n);
    x = ib_io(t, IB_QUERY_TRANSPORT, in, 16, out, sizeof out, 1);
    CHECKF(IB_FAILS(x, WSAEOPNOTSUPP) && x.n == 0, "query: r=%d err=%d n=%lu", x.r, x.err, x.n);
    ib_close(t);
}
