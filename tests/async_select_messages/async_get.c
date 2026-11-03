/* WSAAsyncGetProtoBy* / WSAAsyncGetServBy* / WSAAsyncGetHostBy* completion messages: the task handle
 * returned and echoed in wParam, the packed lParam (low word: bytes needed or used, high word: error),
 * the buffer-size protocol, not-found and invalid-argument encodings, delivery to windows of other
 * threads and kinds, windows that no longer exist, and request ordering.
 * Only data that exists on every installation is looked up: the protocol and service databases and the
 * IPv4 loopback literal. */
#include "asm.h"

static int in_buf(const void *p, const char *buf, int len)
{
    return p && (const char *)p >= buf && (const char *)p < buf + len;
}

static int err_of(LPARAM lp) { return (int)HIWORD(lp); }
static int len_of(LPARAM lp) { return (int)LOWORD(lp); }

static int finish(HANDLE h, UINT msg, LPARAM *lp) { return a_take((WPARAM)h, msg, -1, 8000, lp); }

#define W_OR_SKIP(w) HWND w = a_win(ASM_WIN_MSGONLY); NEED(w)

/* ---- protocols ------------------------------------------------------------------------------- */

static const struct { const char *name; int number; const char *canonical; } k_protos[] = {
    { "tcp", 6, "tcp" }, { "TCP", 6, "tcp" }, { "udp", 17, "udp" }, { "Udp", 17, "udp" },
    { "icmp", 1, "icmp" }, { "ICMP", 1, "icmp" }, { "ip", 0, "ip" },
};

ATEST(asm_get_protobyname_table)
{
    size_t i;
    W_OR_SKIP(w);
    for (i = 0; i < sizeof k_protos / sizeof k_protos[0]; ++i) {
        char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h;
        struct protoent *pe = (struct protoent *)buf;
        memset(buf, 0xCC, sizeof buf);
        h = U(WSAAsyncGetProtoByName)(w, ASM_WM, k_protos[i].name, buf, sizeof buf);
        CHECKF(h != NULL, "%s: no handle", k_protos[i].name);
        if (!h) continue;
        CHECKF(finish(h, ASM_WM, &lp), "%s: no completion", k_protos[i].name);
        CHECKF(err_of(lp) == 0, "%s: error %d", k_protos[i].name, err_of(lp));
        CHECKF(len_of(lp) > 0 && len_of(lp) <= (int)sizeof buf, "%s: length %d", k_protos[i].name, len_of(lp));
        if (err_of(lp) != 0) continue;
        CHECKF(in_buf(pe->p_name, buf, sizeof buf), "%s: name pointer outside buffer", k_protos[i].name);
        CHECKF(in_buf(pe->p_aliases, buf, sizeof buf), "%s: alias list outside buffer", k_protos[i].name);
        if (in_buf(pe->p_name, buf, sizeof buf)) CHECKF(!strcmp(pe->p_name, k_protos[i].canonical), "%s: name '%s'", k_protos[i].name, pe->p_name);
        CHECKF(pe->p_proto == k_protos[i].number, "%s: number %d", k_protos[i].name, pe->p_proto);
    }
}

ATEST(asm_get_protobynumber_table)
{
    size_t i;
    W_OR_SKIP(w);
    for (i = 0; i < sizeof k_protos / sizeof k_protos[0]; i += 2) {
        char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h;
        struct protoent *pe = (struct protoent *)buf;
        h = U(WSAAsyncGetProtoByNumber)(w, ASM_WM, k_protos[i].number, buf, sizeof buf);
        CHECKF(h != NULL, "%d: no handle", k_protos[i].number);
        if (!h) continue;
        CHECKF(finish(h, ASM_WM, &lp), "%d: no completion", k_protos[i].number);
        CHECKF(err_of(lp) == 0, "%d: error %d", k_protos[i].number, err_of(lp));
        if (err_of(lp) != 0) continue;
        CHECKF(in_buf(pe->p_name, buf, sizeof buf), "%d: name pointer", k_protos[i].number);
        if (in_buf(pe->p_name, buf, sizeof buf)) CHECKF(!strcmp(pe->p_name, k_protos[i].canonical), "%d: name '%s'", k_protos[i].number, pe->p_name);
        CHECKF(pe->p_proto == k_protos[i].number, "%d: number %d", k_protos[i].number, pe->p_proto);
    }
}

/* A name that is not in the database completes with WSANO_DATA in the high word and a zero length. */
ATEST(asm_get_protobyname_unknown_name)
{
    char buf[ASM_BUF]; LPARAM lp = 1; HANDLE h;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetProtoByName)(w, ASM_WM, "asm_no_such_protocol", buf, sizeof buf);
    CHECK(h != NULL);
    if (!h) return;
    CHECK(finish(h, ASM_WM, &lp));
    EQ(err_of(lp), WSANO_DATA);
    EQ(len_of(lp), 0);
}

ATEST(asm_get_protobynumber_unknown_numbers)
{
    static const int nums[] = { 200, 254, -1, 100000 };
    size_t i;
    W_OR_SKIP(w);
    for (i = 0; i < sizeof nums / sizeof nums[0]; ++i) {
        char buf[ASM_BUF]; LPARAM lp = 1; HANDLE h = U(WSAAsyncGetProtoByNumber)(w, ASM_WM, nums[i], buf, sizeof buf);
        CHECKF(h != NULL, "%d: no handle", nums[i]);
        if (!h) continue;
        CHECKF(finish(h, ASM_WM, &lp), "%d: no completion", nums[i]);
        CHECKF(err_of(lp) == WSANO_DATA && len_of(lp) == 0, "%d: error %d length %d", nums[i], err_of(lp), len_of(lp));
    }
}

/* Needed size R is reported in the low word; a buffer of exactly R succeeds, R-1 reports WSAENOBUFS. */
static void size_protocol_proto(HWND w, int by_number)
{
    char big[ASM_BUF]; LPARAM lp = 0; HANDLE h; int R;
    h = by_number ? U(WSAAsyncGetProtoByNumber)(w, ASM_WM, 6, big, sizeof big)
                  : U(WSAAsyncGetProtoByName)(w, ASM_WM, "tcp", big, sizeof big);
    CHECK(h != NULL);
    if (!h || !finish(h, ASM_WM, &lp)) { CHECK(0); return; }
    EQ(err_of(lp), 0);
    R = len_of(lp);
    CHECK(R > 0 && R < (int)sizeof big);
    if (R <= 0) return;
    {
        char exact[ASM_BUF]; LPARAM lp2 = 0; HANDLE h2;
        h2 = by_number ? U(WSAAsyncGetProtoByNumber)(w, ASM_WM, 6, exact, R) : U(WSAAsyncGetProtoByName)(w, ASM_WM, "tcp", exact, R);
        CHECK(h2 && finish(h2, ASM_WM, &lp2));
        EQ(err_of(lp2), 0);
        EQ(len_of(lp2), R);
        h2 = by_number ? U(WSAAsyncGetProtoByNumber)(w, ASM_WM, 6, exact, R - 1) : U(WSAAsyncGetProtoByName)(w, ASM_WM, "tcp", exact, R - 1);
        CHECK(h2 && finish(h2, ASM_WM, &lp2));
        EQ(err_of(lp2), WSAENOBUFS);
        EQ(len_of(lp2), R);
    }
}

ATEST(asm_get_protobyname_buffer_size_protocol) { W_OR_SKIP(w); size_protocol_proto(w, 0); }
ATEST(asm_get_protobynumber_buffer_size_protocol) { W_OR_SKIP(w); size_protocol_proto(w, 1); }

/* Both lookups of the same entry need the same space. */
ATEST(asm_get_proto_name_and_number_need_same_size)
{
    LPARAM l1 = 0, l2 = 0; HANDLE h1, h2;
    W_OR_SKIP(w);
    h1 = U(WSAAsyncGetProtoByName)(w, ASM_WM, "udp", NULL, 0);
    h2 = U(WSAAsyncGetProtoByNumber)(w, ASM_WM, 17, NULL, 0);
    CHECK(h1 && h2 && finish(h1, ASM_WM, &l1) && finish(h2, ASM_WM, &l2));
    EQ(err_of(l1), WSAENOBUFS);
    EQ(err_of(l2), WSAENOBUFS);
    CHECK(len_of(l1) > 0);
    EQ(len_of(l1), len_of(l2));
}

ATEST(asm_get_proto_null_buffer_zero_length_reports_nobufs)
{
    LPARAM lp = 0; HANDLE h;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetProtoByName)(w, ASM_WM, "tcp", NULL, 0);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), WSAENOBUFS);
    CHECK(len_of(lp) > 0);
}

/* A failed lookup needs no space, so even a zero-length buffer yields the lookup error, not WSAENOBUFS. */
ATEST(asm_get_proto_unknown_with_zero_buffer_reports_lookup_error)
{
    LPARAM lp = 0; HANDLE h;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetProtoByName)(w, ASM_WM, "asm_no_such_protocol", NULL, 0);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), WSANO_DATA);
    EQ(len_of(lp), 0);
}

/* With a too-small length nothing past that length is written. */
ATEST(asm_get_proto_short_buffer_leaves_tail_untouched)
{
    unsigned char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h; size_t i, bad = 0;
    W_OR_SKIP(w);
    memset(buf, 0xCC, sizeof buf);
    h = U(WSAAsyncGetProtoByName)(w, ASM_WM, "tcp", (char *)buf, 8);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), WSAENOBUFS);
    for (i = 8; i < sizeof buf; ++i) if (buf[i] != 0xCC) ++bad;
    EQ(bad, 0);
}

/* ---- services --------------------------------------------------------------------------------- */

static const struct { const char *name; const char *proto; int port; } k_servs[] = {
    { "http", "tcp", 80 }, { "echo", "tcp", 7 }, { "echo", "udp", 7 }, { "domain", "udp", 53 },
    { "domain", "tcp", 53 }, { "ftp", "tcp", 21 }, { "smtp", "tcp", 25 }, { "telnet", "tcp", 23 },
};

ATEST(asm_get_servbyname_table)
{
    size_t i;
    W_OR_SKIP(w);
    for (i = 0; i < sizeof k_servs / sizeof k_servs[0]; ++i) {
        char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h; struct servent *se = (struct servent *)buf;
        h = U(WSAAsyncGetServByName)(w, ASM_WM, k_servs[i].name, k_servs[i].proto, buf, sizeof buf);
        CHECKF(h != NULL, "%s/%s: no handle", k_servs[i].name, k_servs[i].proto);
        if (!h) continue;
        CHECKF(finish(h, ASM_WM, &lp), "%s/%s: no completion", k_servs[i].name, k_servs[i].proto);
        CHECKF(err_of(lp) == 0, "%s/%s: error %d", k_servs[i].name, k_servs[i].proto, err_of(lp));
        if (err_of(lp) != 0) continue;
        CHECKF(in_buf(se->s_name, buf, sizeof buf) && in_buf(se->s_proto, buf, sizeof buf), "%s/%s: pointers", k_servs[i].name, k_servs[i].proto);
        CHECKF((unsigned short)se->s_port == (unsigned short)U(htons)(k_servs[i].port), "%s/%s: port 0x%x", k_servs[i].name, k_servs[i].proto, (unsigned short)se->s_port);
        if (in_buf(se->s_proto, buf, sizeof buf)) CHECKF(!strcmp(se->s_proto, k_servs[i].proto), "%s/%s: proto '%s'", k_servs[i].name, k_servs[i].proto, se->s_proto);
        if (in_buf(se->s_name, buf, sizeof buf)) CHECKF(!strcmp(se->s_name, k_servs[i].name), "%s/%s: name '%s'", k_servs[i].name, k_servs[i].proto, se->s_name);
    }
}

ATEST(asm_get_servbyport_table)
{
    size_t i;
    W_OR_SKIP(w);
    for (i = 0; i < sizeof k_servs / sizeof k_servs[0]; ++i) {
        char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h; struct servent *se = (struct servent *)buf;
        h = U(WSAAsyncGetServByPort)(w, ASM_WM, U(htons)(k_servs[i].port), k_servs[i].proto, buf, sizeof buf);
        CHECKF(h != NULL, "%d/%s: no handle", k_servs[i].port, k_servs[i].proto);
        if (!h) continue;
        CHECKF(finish(h, ASM_WM, &lp), "%d/%s: no completion", k_servs[i].port, k_servs[i].proto);
        CHECKF(err_of(lp) == 0, "%d/%s: error %d", k_servs[i].port, k_servs[i].proto, err_of(lp));
        if (err_of(lp) != 0) continue;
        CHECKF(in_buf(se->s_name, buf, sizeof buf) && in_buf(se->s_proto, buf, sizeof buf), "%d/%s: pointers", k_servs[i].port, k_servs[i].proto);
        if (in_buf(se->s_name, buf, sizeof buf)) CHECKF(!strcmp(se->s_name, k_servs[i].name), "%d/%s: name '%s'", k_servs[i].port, k_servs[i].proto, se->s_name);
        if (in_buf(se->s_proto, buf, sizeof buf)) CHECKF(!strcmp(se->s_proto, k_servs[i].proto), "%d/%s: proto '%s'", k_servs[i].port, k_servs[i].proto, se->s_proto);
    }
}

/* A NULL protocol matches either protocol. */
ATEST(asm_get_servbyname_null_protocol_matches_any)
{
    char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h; struct servent *se = (struct servent *)buf;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetServByName)(w, ASM_WM, "echo", NULL, buf, sizeof buf);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), 0);
    if (err_of(lp) == 0) EQ((unsigned short)se->s_port, (unsigned short)U(htons)(7));
}

ATEST(asm_get_servbyport_null_protocol_matches_any)
{
    char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h; struct servent *se = (struct servent *)buf;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetServByPort)(w, ASM_WM, U(htons)(7), NULL, buf, sizeof buf);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), 0);
    if (err_of(lp) == 0 && in_buf(se->s_name, buf, sizeof buf)) CHECK(!strcmp(se->s_name, "echo"));
}

ATEST(asm_get_servbyname_unknown)
{
    char buf[ASM_BUF]; LPARAM lp = 1; HANDLE h;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetServByName)(w, ASM_WM, "asm_no_such_service", "tcp", buf, sizeof buf);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), WSANO_DATA);
    EQ(len_of(lp), 0);
}

/* The right name with the wrong protocol is a miss too. */
ATEST(asm_get_servbyname_protocol_mismatch)
{
    char buf[ASM_BUF]; LPARAM lp = 1; HANDLE h;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetServByName)(w, ASM_WM, "http", "asm_no_such_proto", buf, sizeof buf);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), WSANO_DATA);
    EQ(len_of(lp), 0);
}

ATEST(asm_get_servbyport_unknown_port)
{
    char buf[ASM_BUF]; LPARAM lp = 1; HANDLE h;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetServByPort)(w, ASM_WM, U(htons)(61234), "tcp", buf, sizeof buf);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), WSANO_DATA);
    EQ(len_of(lp), 0);
}

/* The port argument is in network byte order: the host-order value 80 names port 20480. */
ATEST(asm_get_servbyport_host_order_value_is_a_different_port)
{
    char buf[ASM_BUF]; LPARAM lp = 1; HANDLE h;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetServByPort)(w, ASM_WM, 80, "tcp", buf, sizeof buf);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), WSANO_DATA);
}

static void size_protocol_serv(HWND w, int by_port)
{
    char big[ASM_BUF], tmp[ASM_BUF]; LPARAM lp = 0, lp2 = 0; HANDLE h, h2; int R;
    h = by_port ? U(WSAAsyncGetServByPort)(w, ASM_WM, U(htons)(80), "tcp", big, sizeof big)
                : U(WSAAsyncGetServByName)(w, ASM_WM, "http", "tcp", big, sizeof big);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), 0);
    R = len_of(lp);
    CHECK(R > 0 && R < (int)sizeof big);
    if (R <= 0) return;
    h2 = by_port ? U(WSAAsyncGetServByPort)(w, ASM_WM, U(htons)(80), "tcp", tmp, R) : U(WSAAsyncGetServByName)(w, ASM_WM, "http", "tcp", tmp, R);
    CHECK(h2 && finish(h2, ASM_WM, &lp2));
    EQ(err_of(lp2), 0);
    EQ(len_of(lp2), R);
    h2 = by_port ? U(WSAAsyncGetServByPort)(w, ASM_WM, U(htons)(80), "tcp", tmp, R - 1) : U(WSAAsyncGetServByName)(w, ASM_WM, "http", "tcp", tmp, R - 1);
    CHECK(h2 && finish(h2, ASM_WM, &lp2));
    EQ(err_of(lp2), WSAENOBUFS);
    EQ(len_of(lp2), R);
}

ATEST(asm_get_servbyname_buffer_size_protocol) { W_OR_SKIP(w); size_protocol_serv(w, 0); }
ATEST(asm_get_servbyport_buffer_size_protocol) { W_OR_SKIP(w); size_protocol_serv(w, 1); }

ATEST(asm_get_serv_null_buffer_reports_nobufs_with_size)
{
    LPARAM lp = 0; HANDLE h;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetServByName)(w, ASM_WM, "http", "tcp", NULL, 0);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), WSAENOBUFS);
    CHECK(len_of(lp) > 0);
}

/* ---- hosts -------------------------------------------------------------------------------------- */

static void check_loopback_hostent(const char *buf, int buflen, const char *what)
{
    const struct hostent *he = (const struct hostent *)buf;
    CHECKF(in_buf(he->h_name, buf, buflen) && in_buf(he->h_aliases, buf, buflen) && in_buf(he->h_addr_list, buf, buflen), "%s: pointers", what);
    CHECKF(he->h_addrtype == AF_INET, "%s: addrtype %d", what, he->h_addrtype);
    CHECKF(he->h_length == 4, "%s: length %d", what, he->h_length);
    if (in_buf(he->h_addr_list, buf, buflen) && in_buf(he->h_addr_list[0], buf, buflen)) {
        const unsigned char *a = (const unsigned char *)he->h_addr_list[0];
        CHECKF(a[0] == 127 && a[1] == 0 && a[2] == 0 && a[3] == 1, "%s: first address", what);
        CHECKF(he->h_addr_list[1] == NULL || in_buf(he->h_addr_list[1], buf, buflen), "%s: list terminator", what);
    }
}

ATEST(asm_get_hostbyname_ipv4_literal)
{
    char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h;
    W_OR_SKIP(w);
    memset(buf, 0, sizeof buf);
    h = U(WSAAsyncGetHostByName)(w, ASM_WM, "127.0.0.1", buf, sizeof buf);
    CHECK(h != NULL);
    if (!h) return;
    CHECK(finish(h, ASM_WM, &lp));
    EQ(err_of(lp), 0);
    CHECK(len_of(lp) > 0 && len_of(lp) <= (int)sizeof buf);
    if (err_of(lp) == 0) check_loopback_hostent(buf, sizeof buf, "127.0.0.1");
}

ATEST(asm_get_hostbyname_buffer_size_protocol)
{
    char big[ASM_BUF], tmp[ASM_BUF]; LPARAM lp = 0, l2 = 0; HANDLE h, h2; int R;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetHostByName)(w, ASM_WM, "127.0.0.1", big, sizeof big);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), 0);
    R = len_of(lp);
    CHECK(R > 0 && R < (int)sizeof big);
    if (R <= 0) return;
    h2 = U(WSAAsyncGetHostByName)(w, ASM_WM, "127.0.0.1", tmp, R);
    CHECK(h2 && finish(h2, ASM_WM, &l2));
    EQ(err_of(l2), 0);
    EQ(len_of(l2), R);
    h2 = U(WSAAsyncGetHostByName)(w, ASM_WM, "127.0.0.1", tmp, R - 1);
    CHECK(h2 && finish(h2, ASM_WM, &l2));
    EQ(err_of(l2), WSAENOBUFS);
    EQ(len_of(l2), R);
}

ATEST(asm_get_hostbyname_null_buffer_reports_nobufs)
{
    LPARAM lp = 0; HANDLE h;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetHostByName)(w, ASM_WM, "127.0.0.1", NULL, 0);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), WSAENOBUFS);
    CHECK(len_of(lp) > 0);
}

ATEST(asm_get_hostbyname_short_buffer_leaves_tail_untouched)
{
    unsigned char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h; size_t i, bad = 0;
    W_OR_SKIP(w);
    memset(buf, 0xCC, sizeof buf);
    h = U(WSAAsyncGetHostByName)(w, ASM_WM, "127.0.0.1", (char *)buf, 12);
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), WSAENOBUFS);
    for (i = 12; i < sizeof buf; ++i) if (buf[i] != 0xCC) ++bad;
    EQ(bad, 0);
}

/* "localhost" is resolved locally; the completion must arrive, and if it succeeded it names loopback. */
ATEST(asm_get_hostbyname_localhost_completes)
{
    char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetHostByName)(w, ASM_WM, "localhost", buf, sizeof buf);
    CHECK(h != NULL);
    if (!h) return;
    CHECK(finish(h, ASM_WM, &lp));
    if (err_of(lp) == 0) check_loopback_hostent(buf, sizeof buf, "localhost");
    else t_note("localhost lookup completed with error %d", err_of(lp));
}

ATEST(asm_get_hostbyaddr_ipv4_loopback_completes)
{
    char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h; unsigned char a[4] = { 127, 0, 0, 1 };
    W_OR_SKIP(w);
    h = U(WSAAsyncGetHostByAddr)(w, ASM_WM, (char *)a, 4, AF_INET, buf, sizeof buf);
    CHECK(h != NULL);
    if (!h) return;
    CHECK(finish(h, ASM_WM, &lp));
    if (err_of(lp) == 0) {
        const struct hostent *he = (const struct hostent *)buf;
        CHECK(in_buf(he->h_name, buf, sizeof buf));
        EQ(he->h_addrtype, AF_INET);
        EQ(he->h_length, 4);
    } else t_note("reverse lookup of loopback completed with error %d", err_of(lp));
}

/* An IPv6 request whose address length is not 16 fails inside the lookup with WSAEINVAL. */
ATEST(asm_get_hostbyaddr_ipv6_wrong_length)
{
    char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h; unsigned char a[4] = { 127, 0, 0, 1 };
    W_OR_SKIP(w);
    h = U(WSAAsyncGetHostByAddr)(w, ASM_WM, (char *)a, 4, AF_INET6, buf, sizeof buf);
    CHECK(h != NULL);
    if (!h) return;
    CHECK(finish(h, ASM_WM, &lp));
    EQ(err_of(lp), WSAEINVAL);
    EQ(len_of(lp), 0);
}

ATEST(asm_get_hostbyaddr_ipv6_wrong_length_table)
{
    static const int lens[] = { 0, 1, 4, 8, 15 };
    size_t i;
    W_OR_SKIP(w);
    for (i = 0; i < sizeof lens / sizeof lens[0]; ++i) {
        char buf[ASM_BUF]; unsigned char a[16] = { 0 }; LPARAM lp = 0; HANDLE h;
        a[15] = 1;
        h = U(WSAAsyncGetHostByAddr)(w, ASM_WM, (char *)a, lens[i], AF_INET6, buf, sizeof buf);
        CHECKF(h != NULL, "len %d: no handle", lens[i]);
        if (!h) continue;
        CHECKF(finish(h, ASM_WM, &lp), "len %d: no completion", lens[i]);
        CHECKF(err_of(lp) == WSAEINVAL, "len %d: error %d", lens[i], err_of(lp));
    }
}

ATEST(asm_get_hostbyaddr_ipv6_loopback_completes)
{
    char buf[ASM_BUF]; LPARAM lp = 0; HANDLE h; unsigned char a[16] = { 0 };
    W_OR_SKIP(w);
    a[15] = 1;
    h = U(WSAAsyncGetHostByAddr)(w, ASM_WM, (char *)a, 16, AF_INET6, buf, sizeof buf);
    CHECK(h != NULL);
    if (!h) return;
    CHECK(finish(h, ASM_WM, &lp));
    t_note("reverse lookup of ::1 completed with error %d", err_of(lp));
}

ATEST(asm_get_hostbyaddr_buffer_too_small_if_found)
{
    char buf[ASM_BUF]; LPARAM lp = 0, l2 = 0; HANDLE h; unsigned char a[4] = { 127, 0, 0, 1 };
    W_OR_SKIP(w);
    h = U(WSAAsyncGetHostByAddr)(w, ASM_WM, (char *)a, 4, AF_INET, buf, sizeof buf);
    CHECK(h && finish(h, ASM_WM, &lp));
    if (err_of(lp) != 0) { t_skip("reverse lookup of loopback unavailable here"); return; }
    h = U(WSAAsyncGetHostByAddr)(w, ASM_WM, (char *)a, 4, AF_INET, buf, len_of(lp) - 1);
    CHECK(h && finish(h, ASM_WM, &l2));
    EQ(err_of(l2), WSAENOBUFS);
    EQ(len_of(l2), len_of(lp));
}

/* ---- handles and delivery -------------------------------------------------------------------- */

ATEST(asm_get_handles_are_consecutive_and_nonzero)
{
    HANDLE h1, h2, h3;
    W_OR_SKIP(w);
    h1 = U(WSAAsyncGetProtoByNumber)(w, ASM_WM, 6, NULL, 0);
    h2 = U(WSAAsyncGetProtoByNumber)(w, ASM_WM, 6, NULL, 0);
    h3 = U(WSAAsyncGetProtoByNumber)(w, ASM_WM, 6, NULL, 0);
    CHECK(h1 && h2 && h3);
    EQ((ULONG_PTR)h2, (ULONG_PTR)h1 + 1);
    EQ((ULONG_PTR)h3, (ULONG_PTR)h2 + 1);
    CHECK(finish(h1, ASM_WM, NULL) && finish(h2, ASM_WM, NULL) && finish(h3, ASM_WM, NULL));
}

/* Fresh process: the first task handle is 1 and each new request takes the next number. */
CHILD(asm_first_handle)
{
    WSADATA d; HANDLE h1, h2;
    if (U(WSAStartup)(MAKEWORD(2, 2), &d) != 0) return 50;
    h1 = U(WSAAsyncGetProtoByNumber)(NULL, ASM_WM, 6, NULL, 0);
    h2 = U(WSAAsyncGetProtoByNumber)(NULL, ASM_WM, 6, NULL, 0);
    Sleep(300);
    if (h1 != (HANDLE)1) return 1;
    if (h2 != (HANDLE)2) return 2;
    return 0;
}

TEST(asm_get_first_handle_in_fresh_process)
{
    NEED(U(WSAAsyncGetProtoByNumber));
    EQ(t_run_child("asm_first_handle", "", 20000), 0);
}

ATEST(asm_get_wparam_is_the_returned_handle)
{
    HANDLE h; asm_rec r;
    W_OR_SKIP(w);
    h = U(WSAAsyncGetProtoByName)(w, ASM_WM, "tcp", NULL, 0);
    CHECK(h != NULL);
    a_pump(500);
    CHECK(a_find_rec((WPARAM)h, ASM_WM, -1, &r));
    EQ(a_total(), 1);
    EQ(r.hwnd, w);
}

ATEST(asm_get_message_number_table)
{
    static const UINT ids[] = { WM_USER, ASM_WM, 0x7FFF, WM_APP, 0xBFFF, 0xC000, 0xFFFF };
    size_t i;
    W_OR_SKIP(w);
    for (i = 0; i < sizeof ids / sizeof ids[0]; ++i) {
        HANDLE h = U(WSAAsyncGetProtoByNumber)(w, ids[i], 6, NULL, 0);
        CHECKF(h != NULL, "0x%x: no handle", ids[i]);
        CHECKF(h && a_take((WPARAM)h, ids[i], -1, 5000, NULL), "0x%x: no completion", ids[i]);
    }
}

ATEST(asm_get_each_window_kind_receives)
{
    static const int kinds[] = { ASM_WIN_MSGONLY, ASM_WIN_POPUP, ASM_WIN_OVERLAP, ASM_WIN_CHILD };
    size_t i;
    for (i = 0; i < sizeof kinds / sizeof kinds[0]; ++i) {
        HWND w = a_win(kinds[i]); HANDLE h;
        if (!w) { t_note("window kind %d unavailable", kinds[i]); continue; }
        h = U(WSAAsyncGetProtoByNumber)(w, ASM_WM, 6, NULL, 0);
        CHECKF(h && a_take((WPARAM)h, ASM_WM, -1, 5000, NULL), "window kind %d", kinds[i]);
    }
}

ATEST(asm_get_window_on_other_thread_gets_the_message)
{
    asm_wthread t; HANDLE h; asm_rec r; int ok;
    NEED(a_wthread_start(&t, ASM_WIN_MSGONLY));
    h = U(WSAAsyncGetProtoByNumber)(t.hwnd, ASM_WM, 6, NULL, 0);
    CHECK(h != NULL);
    ok = a_take((WPARAM)h, ASM_WM, -1, 5000, NULL);
    CHECK(ok);
    a_wthread_stop(&t);
}

ATEST(asm_get_message_delivered_on_window_thread)
{
    asm_wthread t; HANDLE h; asm_rec r;
    NEED(a_wthread_start(&t, ASM_WIN_MSGONLY));
    h = U(WSAAsyncGetProtoByNumber)(t.hwnd, ASM_WM, 6, NULL, 0);
    CHECK(h != NULL);
    if (h) {
        DWORD t0 = GetTickCount();
        while (!a_find_rec((WPARAM)h, ASM_WM, -1, &r) && GetTickCount() - t0 < 5000) Sleep(10);
        CHECK(a_find_rec((WPARAM)h, ASM_WM, -1, &r));
        if (a_find_rec((WPARAM)h, ASM_WM, -1, &r)) { EQ(r.tid, t.tid); CHECK(r.tid != GetCurrentThreadId()); EQ(r.hwnd, t.hwnd); }
    }
    a_wthread_stop(&t);
}

struct req_arg { HWND w; HANDLE h; };
static DWORD WINAPI request_and_exit(LPVOID p)
{
    struct req_arg *a = p;
    a->h = U(WSAAsyncGetProtoByNumber)(a->w, ASM_WM, 6, NULL, 0);
    return 0;
}

ATEST(asm_get_requesting_thread_may_exit_first)
{
    struct req_arg arg;
    HANDLE th;
    W_OR_SKIP(w);
    arg.w = w; arg.h = NULL;
    th = CreateThread(NULL, 0, request_and_exit, &arg, 0, NULL);
    NEED(th);
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    CHECK(arg.h != NULL);
    CHECK(arg.h && a_take((WPARAM)arg.h, ASM_WM, -1, 5000, NULL));
}

/* A window that is gone when the lookup finishes loses its message silently; later requests still work. */
ATEST(asm_get_destroyed_window_drops_message_only)
{
    HWND w = a_win(ASM_WIN_MSGONLY), w2 = a_win(ASM_WIN_MSGONLY); HANDLE h1, h2;
    NEED(w && w2);
    a_destroy(w);
    h1 = U(WSAAsyncGetProtoByNumber)(w, ASM_WM, 6, NULL, 0);
    CHECK(h1 != NULL);
    h2 = U(WSAAsyncGetProtoByNumber)(w2, ASM_WM, 6, NULL, 0);
    CHECK(h2 && a_take((WPARAM)h2, ASM_WM, -1, 5000, NULL));
    a_pump(200);
    EQ(a_count((WPARAM)h1, ASM_WM), 0);
}

ATEST(asm_get_two_windows_two_messages)
{
    HWND w1 = a_win(ASM_WIN_MSGONLY), w2 = a_win(ASM_WIN_MSGONLY); HANDLE h1, h2; asm_rec r1, r2;
    NEED(w1 && w2);
    h1 = U(WSAAsyncGetProtoByNumber)(w1, ASM_WM, 6, NULL, 0);
    h2 = U(WSAAsyncGetProtoByNumber)(w2, ASM_WM2, 17, NULL, 0);
    CHECK(h1 && h2);
    a_pump(500);
    CHECK(a_find_rec((WPARAM)h1, ASM_WM, -1, &r1) && a_find_rec((WPARAM)h2, ASM_WM2, -1, &r2));
    EQ(a_total(), 2);
    EQ(r1.hwnd, w1);
    EQ(r2.hwnd, w2);
}

/* One worker handles requests in the order they were queued. */
ATEST(asm_get_requests_complete_in_request_order)
{
    enum { N = 120 };
    HANDLE hs[N]; LONG seqs[N]; int i, ok = 1;
    W_OR_SKIP(w);
    for (i = 0; i < N; ++i) { hs[i] = U(WSAAsyncGetProtoByNumber)(w, ASM_WM, 6 + (i % 3), NULL, 0); ok &= hs[i] != NULL; }
    CHECK(ok);
    {
        DWORD t0 = GetTickCount();
        while (a_total() < N && GetTickCount() - t0 < 15000) a_pump(20);
    }
    EQ(a_total(), N);
    for (i = 0; i < N; ++i) { seqs[i] = a_seq_of((WPARAM)hs[i], ASM_WM, -1); CHECKF(seqs[i] > 0, "request %d missing", i); }
    for (i = 1; i < N; ++i) CHECKF(seqs[i] > seqs[i - 1], "request %d delivered before %d", i, i - 1);
}

ATEST(asm_get_mixed_request_kinds_in_order)
{
    HANDLE hs[6]; LONG s[6]; int i; char buf[ASM_BUF];
    unsigned char a[4] = { 127, 0, 0, 1 };
    W_OR_SKIP(w);
    hs[0] = U(WSAAsyncGetProtoByName)(w, ASM_WM, "tcp", NULL, 0);
    hs[1] = U(WSAAsyncGetServByName)(w, ASM_WM, "http", "tcp", NULL, 0);
    hs[2] = U(WSAAsyncGetHostByName)(w, ASM_WM, "127.0.0.1", NULL, 0);
    hs[3] = U(WSAAsyncGetServByPort)(w, ASM_WM, U(htons)(80), "tcp", NULL, 0);
    hs[4] = U(WSAAsyncGetProtoByNumber)(w, ASM_WM, 17, buf, sizeof buf);
    hs[5] = U(WSAAsyncGetHostByAddr)(w, ASM_WM, (char *)a, 4, AF_INET, NULL, 0);
    for (i = 0; i < 6; ++i) CHECKF(hs[i] != NULL, "request %d", i);
    {
        DWORD t0 = GetTickCount();
        while (a_total() < 6 && GetTickCount() - t0 < 15000) a_pump(20);
    }
    EQ(a_total(), 6);
    for (i = 0; i < 6; ++i) s[i] = a_seq_of((WPARAM)hs[i], ASM_WM, -1);
    for (i = 1; i < 6; ++i) CHECKF(s[i] > s[i - 1], "request %d out of order", i);
}

ATEST(asm_get_name_copied_at_call_time)
{
    char name[16]; LPARAM lp = 1; HANDLE h; char buf[ASM_BUF];
    W_OR_SKIP(w);
    strcpy(name, "tcp");
    h = U(WSAAsyncGetProtoByName)(w, ASM_WM, name, buf, sizeof buf);
    memset(name, 'z', sizeof name - 1);       /* name text is private to the request once the call returns */
    name[sizeof name - 1] = 0;
    CHECK(h && finish(h, ASM_WM, &lp));
    EQ(err_of(lp), 0);
}

ATEST(asm_get_address_copied_at_call_time)
{
    unsigned char a[4] = { 127, 0, 0, 1 }; LPARAM lp = 1; HANDLE h; char buf[ASM_BUF];
    W_OR_SKIP(w);
    h = U(WSAAsyncGetHostByAddr)(w, ASM_WM, (char *)a, 4, AF_INET, buf, sizeof buf);
    memset(a, 0, sizeof a);
    CHECK(h && finish(h, ASM_WM, &lp));
    if (err_of(lp) == 0) check_loopback_hostent(buf, sizeof buf, "address copy");
}
