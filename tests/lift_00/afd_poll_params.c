/* Parameter validation and completion shape of the AFD poll request (IOCTL 0x12024).
 * Measures: the input/output size protocol (output must not be smaller than input, input must hold
 * the declared entry count), the zero-count and bad-handle rejections, and the exact IO_STATUS_BLOCK /
 * output-buffer contents for the immediate, timed-out and event-completed cases. */
#include "afd_common.h"

typedef struct {
    const char *name;
    int in_delta, out_delta;   /* relative to the size of a one-entry request */
    int null_in, null_out;
    ULONG count;
    NTSTATUS want;
} sizerow_t;

/* The entry in these requests names handle value 0, which is why same-or-larger sizes that do parse
 * end in STATUS_INVALID_HANDLE while malformed sizes end in STATUS_INVALID_PARAMETER. */
static const sizerow_t size_rows[] = {
    { "no output buffer",              0,  0, 0, 1, 1, AS_INVALID_PARAMETER },
    { "no input buffer",               0,  0, 1, 0, 1, AS_INVALID_PARAMETER },
    { "output one byte larger",        0, +1, 0, 0, 1, AS_INVALID_HANDLE },
    { "input one byte larger",        +1,  0, 0, 0, 1, AS_INVALID_PARAMETER },
    { "both one byte short",          -1, -1, 0, 0, 1, AS_INVALID_PARAMETER },
    { "both one byte larger",         +1, +1, 0, 0, 1, AS_INVALID_HANDLE },
    { "count zero",                    0,  0, 0, 0, 0, AS_INVALID_PARAMETER },
    { "exact size, handle zero",       0,  0, 0, 0, 1, AS_INVALID_HANDLE },
};

TEST(afdp_size_protocol_table)
{
    SOCKET l;
    HANDLE ev;
    size_t i;
    NEED_AFD();
    l = mk_listener(NULL);
    ev = mk_event();
    for (i = 0; i < sizeof(size_rows) / sizeof(size_rows[0]); i++) {
        const sizerow_t *r = &size_rows[i];
        pollbuf_t in, out;
        IO_STATUS_BLOCK io;
        ULONG base = (ULONG)POLL_BYTES(1);
        LONG st;
        memset(&in, 0, sizeof(in)); memset(&out, 0, sizeof(out));
        in.req.count = r->count;
        st = afd_poll((HANDLE)l, ev, &io, r->null_in ? NULL : &in, r->null_in ? 0 : base + r->in_delta,
                      r->null_out ? NULL : &out, r->null_out ? 0 : base + r->out_delta);
        CHECKF(st == r->want, "%s: got %#lx want %#lx", r->name, (unsigned long)st, (unsigned long)r->want);
    }
    CloseHandle(ev);
    sock_close(l);
}

TEST(afdp_invalid_handle_leaves_iosb_untouched)
{
    SOCKET c, s;
    HANDLE ev;
    pollbuf_t in, out;
    SOCKET socks[2];
    ULONG fl[2] = { AFDX_POLL_READ | AFDX_POLL_WRITE, AFDX_POLL_READ | AFDX_POLL_WRITE };
    IO_STATUS_BLOCK io;
    LONG st;
    NEED_AFD();
    mk_pair(&c, &s);
    ev = mk_event();
    /* one entry carries a value that is no handle at all; the whole request is rejected up front */
    socks[0] = 0xabacab; socks[1] = c;
    fill_poll(&in, REL_MS(1000), 0, 2, socks, fl);
    memset(&out, 0, sizeof(out));
    memset(&io, 0, sizeof(io));
    st = afd_poll((HANDLE)c, ev, &io, &in, (ULONG)POLL_BYTES(2), &out, (ULONG)POLL_BYTES(2));
    EXPECT_EQ((ULONG)st, (ULONG)AS_INVALID_HANDLE);
    CHECK(io.Status == 0);
    CHECK(io.Information == 0);
    CloseHandle(ev);
    sock_close(c); sock_close(s);
}

TEST(afdp_count_two_in_one_entry_buffer_rejected)
{
    SOCKET c, s;
    HANDLE ev;
    pollbuf_t in, out;
    SOCKET socks[2];
    ULONG fl[2] = { AFDX_POLL_READ, AFDX_POLL_READ };
    IO_STATUS_BLOCK io;
    NEED_AFD();
    mk_pair(&c, &s);
    ev = mk_event();
    socks[0] = c; socks[1] = s;
    fill_poll(&in, REL_MS(1000), 0, 2, socks, fl);
    memset(&out, 0, sizeof(out));
    /* the declared count needs two entries but only room for one is passed */
    EXPECT_ST(afd_poll((HANDLE)c, ev, &io, &in, (ULONG)POLL_BYTES(1), &out, (ULONG)POLL_BYTES(1)),
              AS_INVALID_PARAMETER);
    CloseHandle(ev);
    sock_close(c); sock_close(s);
}

/* ---- zero / absolute timeouts on a control handle ----------------------- */
typedef struct { HANDLE afd; SOCKET l; HANDLE ev; } ctl_t;

static int ctl_open(ctl_t *c)
{
    memset(c, 0, sizeof(*c));
    c->afd = open_afd(L"\\Device\\Afd\\pollctl");
    c->l = mk_listener(NULL);
    c->ev = mk_event();
    return c->afd != NULL;
}
static void ctl_close(ctl_t *c)
{
    if (c->afd) CloseHandle(c->afd);
    CloseHandle(c->ev);
    sock_close(c->l);
}

TEST(afdp_zero_timeout_returns_immediately_empty)
{
    ctl_t c; pollbuf_t in, out; IO_STATUS_BLOCK io; LONG st; ULONG fl = ~0u;
    NEED_AFD();
    if (!ctl_open(&c)) { ctl_close(&c); return; }
    fill_poll(&in, 0, 0, 1, &c.l, &fl);
    memset(&out, 0, sizeof(out));
    st = afd_poll(c.afd, c.ev, &io, &in, (ULONG)POLL_BYTES(1), &out, (ULONG)POLL_BYTES(1));
    EXPECT_EQ((ULONG)st, 0);
    CHECK_IO(io, 0, POLL_BYTES(0));
    CHECK(out.req.timeout == 0);
    CHECK(out.req.count == 0);
    CHECK(out.req.sockets[0].socket == 0);
    CHECK(out.req.sockets[0].flags == 0);
    CHECK(out.req.sockets[0].status == 0);
    ctl_close(&c);
}

TEST(afdp_absolute_past_timeout_completes_status_timeout)
{
    ctl_t c; pollbuf_t in, out; IO_STATUS_BLOCK io; LONG st; ULONG fl = ~0u; LARGE_INTEGER now;
    NEED_AFD();
    if (!ctl_open(&c)) { ctl_close(&c); return; }
    F.NtQuerySystemTime(&now);
    fill_poll(&in, now.QuadPart, 0, 1, &c.l, &fl);
    memset(&out, 0, sizeof(out));
    st = afd_poll(c.afd, c.ev, &io, &in, (ULONG)POLL_BYTES(1), &out, (ULONG)POLL_BYTES(1));
    EXPECT_EQ((ULONG)st, (ULONG)AS_PENDING);
    EXPECT_ST(wait_done(c.ev, 1000), WAIT_OBJECT_0);
    CHECK_IO(io, AS_TIMEOUT, POLL_BYTES(0));
    CHECK(out.req.timeout == now.QuadPart);
    CHECK(out.req.count == 0);
    ctl_close(&c);
}

TEST(afdp_relative_timeout_expires_with_status_timeout)
{
    ctl_t c; pollbuf_t in, out; IO_STATUS_BLOCK io; LONG st; ULONG fl = ~0u;
    NEED_AFD();
    if (!ctl_open(&c)) { ctl_close(&c); return; }
    fill_poll(&in, REL_MS(50), 0, 1, &c.l, &fl);
    memset(&out, 0, sizeof(out));
    st = afd_poll(c.afd, c.ev, &io, &in, (ULONG)POLL_BYTES(1), &out, (ULONG)POLL_BYTES(1));
    EXPECT_EQ((ULONG)st, (ULONG)AS_PENDING);
    EXPECT_ST(wait_done(c.ev, 2000), WAIT_OBJECT_0);
    CHECK_IO(io, AS_TIMEOUT, POLL_BYTES(0));
    CHECK(out.req.timeout == REL_MS(50));
    CHECK(out.req.count == 0);
    ctl_close(&c);
}

/* ---- listener readiness ------------------------------------------------- */
TEST(afdp_listener_accept_wakes_pending_poll)
{
    ctl_t c; pollbuf_t in, out; IO_STATUS_BLOCK io; LONG st; struct sockaddr_in a; SOCKET cl, sv, l2;
    NEED_AFD();
    if (!ctl_open(&c)) { ctl_close(&c); return; }
    sock_close(c.l);
    c.l = mk_listener(&a);
    fill_poll1(&in, REL_MS(1000), c.l, ~0u);
    memset(&out, 0, sizeof(out));
    st = afd_poll((HANDLE)c.l, c.ev, &io, &in, (ULONG)POLL_BYTES(1), &out, (ULONG)POLL_BYTES(1));
    EXPECT_EQ((ULONG)st, (ULONG)AS_PENDING);
    cl = mk_tcp();
    set_nonblock(cl, 1);
    st = F.connect(cl, (struct sockaddr *)&a, sizeof(a));
    CHECK(st == 0 || F.WSAGetLastError() == WSAEWOULDBLOCK);
    EXPECT_ST(wait_done(c.ev, 1500), WAIT_OBJECT_0);
    CHECK_IO(io, 0, POLL_BYTES(1));
    CHECK(out.req.timeout == REL_MS(1000));
    CHECK(out.req.count == 1);
    CHECK(out.req.sockets[0].socket == c.l);
    CHECK(out.req.sockets[0].flags == AFDX_POLL_ACCEPT);
    CHECK(out.req.sockets[0].status == 0);

    /* the connection is still unaccepted: a second poll returns without pending */
    memset(&out, 0, sizeof(out));
    st = afd_poll((HANDLE)c.l, c.ev, &io, &in, (ULONG)POLL_BYTES(1), &out, (ULONG)POLL_BYTES(1));
    EXPECT_EQ((ULONG)st, 0);
    CHECK_IO(io, 0, POLL_BYTES(1));
    CHECK(out.req.count == 1);
    CHECK(out.req.sockets[0].flags == AFDX_POLL_ACCEPT);

    /* excluding the accept bit from the mask leaves nothing to report until the timeout */
    {
        LARGE_INTEGER now;
        F.NtQuerySystemTime(&now);
        fill_poll1(&in, now.QuadPart, c.l, ~0u & ~(ULONG)AFDX_POLL_ACCEPT);
        memset(&out, 0, sizeof(out));
        st = afd_poll((HANDLE)c.l, c.ev, &io, &in, (ULONG)POLL_BYTES(1), &out, (ULONG)POLL_BYTES(1));
        EXPECT_EQ((ULONG)st, (ULONG)AS_PENDING);
        EXPECT_ST(wait_done(c.ev, 1000), WAIT_OBJECT_0);
        CHECK_IO(io, AS_TIMEOUT, POLL_BYTES(0));
        CHECK(out.req.count == 0);
    }
    sv = F.accept(c.l, NULL, NULL);
    CHECK(sv != INVALID_SOCKET);
    sock_close(sv); sock_close(cl);
    (void)l2;
    ctl_close(&c);
}

TEST(afdp_poll_other_sockets_via_unrelated_handle)
{
    /* a poll may name sockets other than the handle the request was issued on */
    SOCKET cl, sv, l; HANDLE ev; pollbuf_t in, out; IO_STATUS_BLOCK io; LONG st;
    NEED_AFD();
    l = mk_listener(NULL);
    mk_pair(&cl, &sv);
    ev = mk_event();
    fill_poll1(&in, REL_MS(1000), sv, ~0u);
    memset(&out, 0, sizeof(out));
    st = afd_poll((HANDLE)l, ev, &io, &in, (ULONG)POLL_BYTES(1), &out, (ULONG)POLL_BYTES(1));
    EXPECT_EQ((ULONG)st, 0);
    CHECK_IO(io, 0, POLL_BYTES(1));
    CHECK(out.req.count == 1);
    CHECK(out.req.sockets[0].socket == sv);
    CHECK(out.req.sockets[0].flags == (AFDX_POLL_WRITE | AFDX_POLL_CONNECT));
    CHECK(out.req.sockets[0].status == 0);
    CloseHandle(ev);
    sock_close(cl); sock_close(sv); sock_close(l);
}
