/* Measures how WSAIoctl reports its outcome in the overlapped forms for controls the other files touch only
 * synchronously: immediate completion with a packet on a completion port, deferred failure of unsupported
 * controls (WSA_IO_PENDING, then an NTSTATUS-translated error), completion routines, and the synchronous
 * failures that never reach the port.  The OVERLAPPED is always zeroed before use. */
#include "ib.h"

typedef struct {
    int r, err;                /* immediate result of WSAIoctl */
    DWORD n;                   /* *lpcbBytesReturned after the call */
    int got;                   /* a packet was dequeued */
    BOOL pkt_ok;               /* GetQueuedCompletionStatus result */
    DWORD pkt_err, pkt_bytes;
    ULONG_PTR key;
    OVERLAPPED *pkt_ov;
    NTSTATUS status;
} ib_port_res;

static HANDLE ib_port_for(SOCKET s)
{
    return CreateIoCompletionPort((HANDLE)s, NULL, 123, 0);
}

static ib_port_res ib_ov_port(SOCKET s, HANDLE port, DWORD code, void *in, DWORD inl, void *out, DWORD outl)
{
    ib_port_res x;
    OVERLAPPED ov;
    DWORD n = IB_UNSET;
    memset(&x, 0, sizeof x);
    memset(&ov, 0, sizeof ov);
    ib_seterr((int)IB_UNSET);
    x.r = U(WSAIoctl)(s, code, in, inl, out, outl, &n, (LPWSAOVERLAPPED)&ov, NULL);
    x.err = ib_err();
    x.n = n;
    if (x.r == 0 || x.err == WSA_IO_PENDING) {
        x.pkt_ok = GetQueuedCompletionStatus(port, &x.pkt_bytes, &x.key, &x.pkt_ov, 2000);
        x.pkt_err = x.pkt_ok ? 0 : GetLastError();
        x.got = x.pkt_ov != NULL;
        x.status = (NTSTATUS)ov.Internal;
    }
    return x;
}

IBTEST(ib_ov_port_bcast_completes_inline_with_packet)
{
    IB_SOCK(u, K_UDP4);
    HANDLE port = ib_port_for(u);
    struct sockaddr_in a;
    ib_port_res x = ib_ov_port(u, port, IB_GET_BCAST, NULL, 0, &a, sizeof a);
    CHECKF(x.r == 0 && x.n == 16, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    /* The packet carries no byte count for an inline completion even though *lpcbBytesReturned is 16. */
    CHECKF(x.got && x.pkt_ok && x.pkt_bytes == 0 && x.key == 123, "packet got=%d ok=%d bytes=%lu key=%Iu", x.got, x.pkt_ok, x.pkt_bytes, x.key);
    CHECK(x.status == 0);
    CHECK(a.sin_addr.s_addr == 0xffffffffu);
    CloseHandle(port);
    ib_close(u);
}

IBTEST(ib_ov_port_qos_completes_inline_with_packet)
{
    IB_SOCK(u, K_UDP4);
    HANDLE port = ib_port_for(u);
    unsigned char q[96];
    ib_port_res x = ib_ov_port(u, port, IB_GET_QOS, NULL, 0, q, sizeof q);
    CHECKF(x.r == 0 && x.n == 80, "r=%d err=%d n=%lu", x.r, x.err, x.n);
    CHECKF(x.got && x.pkt_ok && x.pkt_bytes == 0, "packet got=%d ok=%d bytes=%lu", x.got, x.pkt_ok, x.pkt_bytes);
    CloseHandle(port);
    ib_close(u);
}

IBTEST(ib_ov_port_qos_short_buffer_fails_synchronously_without_packet)
{
    IB_SOCK(u, K_UDP4);
    HANDLE port = ib_port_for(u);
    unsigned char q[96];
    OVERLAPPED ov, *p = NULL;
    DWORD n = IB_UNSET, got = 0;
    ULONG_PTR key;
    int r;
    memset(&ov, 0, sizeof ov);
    ib_seterr(0);
    r = U(WSAIoctl)(u, IB_GET_QOS, NULL, 0, q, 79, &n, (LPWSAOVERLAPPED)&ov, NULL);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSAEFAULT, "r=%d err=%d", r, ib_err());
    CHECKF(n == 80, "required size %lu", n);
    CHECK(!GetQueuedCompletionStatus(port, &got, &key, &p, 100) && p == NULL);
    CloseHandle(port);
    ib_close(u);
}

IBTEST(ib_ov_port_simple_setters_complete_inline_with_zero_bytes)
{
    static const struct { DWORD code; int kind; DWORD in[2]; unsigned inl; const char *name; } t[] = {
        {IB_UDP_CONNRESET, K_UDP4, {1, 0}, 4, "UDP_CONNRESET"},
        {IB_UDP_NETRESET, K_UDP4, {1, 0}, 4, "UDP_NETRESET"},
        {IB_LOOPBACK_FAST, K_TCP4, {1, 0}, 4, "LOOPBACK_FAST_PATH"},
        {IB_TCP_INITIAL_RTO, K_TCP4, {0x20bb8, 0}, 4, "TCP_INITIAL_RTO"},
        {IB_COMPAT_MODE, K_TCP4, {0, 0}, 8, "SET_COMPATIBILITY_MODE"},
        {IB_FIONBIO, K_TCP4, {1, 0}, 4, "FIONBIO"},
    };
    unsigned i;
    for (i = 0; i < sizeof t / sizeof *t; ++i) {
        SOCKET s = ib_mk(t[i].kind);
        HANDLE port;
        ib_port_res x;
        DWORD in[2] = {t[i].in[0], t[i].in[1]};
        REQUIRE(s != INVALID_SOCKET);
        port = ib_port_for(s);
        x = ib_ov_port(s, port, t[i].code, in, t[i].inl, NULL, 0);
        CHECKF(x.r == 0, "%s: r=%d err=%d", t[i].name, x.r, x.err);
        CHECKF(x.got && x.pkt_ok && x.pkt_bytes == 0 && x.key == 123, "%s: packet got=%d ok=%d bytes=%lu", t[i].name, x.got, x.pkt_ok, x.pkt_bytes);
        CloseHandle(port);
        ib_close(s);
    }
}

IBTEST(ib_ov_port_multicast_setters_pend_then_succeed_with_zero_bytes)
{
    static const struct { DWORD code; DWORD v; const char *name; } t[] = {
        {IB_MP_LOOPBACK, 1, "MULTIPOINT_LOOPBACK"}, {IB_MC_SCOPE, 8, "MULTICAST_SCOPE"},
    };
    unsigned i;
    for (i = 0; i < 2; ++i) {
        SOCKET s = ib_mk(K_UDP4);
        HANDLE port;
        ib_port_res x;
        DWORD v = t[i].v;
        REQUIRE(s != INVALID_SOCKET);
        port = ib_port_for(s);
        x = ib_ov_port(s, port, t[i].code, &v, 4, NULL, 0);
        CHECKF(x.r == SOCKET_ERROR && x.err == WSA_IO_PENDING, "%s: r=%d err=%d", t[i].name, x.r, x.err);
        CHECKF(x.got && x.pkt_ok && x.pkt_bytes == 0 && x.key == 123, "%s: packet got=%d ok=%d bytes=%lu", t[i].name, x.got, x.pkt_ok, x.pkt_bytes);
        CloseHandle(port);
        ib_close(s);
    }
}

IBTEST(ib_ov_port_multicast_setters_on_stream_pend_then_fail_invalid)
{
    static const DWORD codes[] = {IB_MP_LOOPBACK, IB_MC_SCOPE};
    unsigned i;
    for (i = 0; i < 2; ++i) {
        SOCKET s = ib_mk(K_TCP4);
        HANDLE port;
        ib_port_res x;
        DWORD v = 1;
        REQUIRE(s != INVALID_SOCKET);
        port = ib_port_for(s);
        x = ib_ov_port(s, port, codes[i], &v, 4, NULL, 0);
        CHECKF(x.r == SOCKET_ERROR && x.err == WSA_IO_PENDING, "code %#lx: r=%d err=%d", codes[i], x.r, x.err);
        CHECKF(x.got && !x.pkt_ok && x.pkt_err == ERROR_INVALID_PARAMETER && x.pkt_bytes == 0, "code %#lx: packet got=%d ok=%d err=%lu", codes[i], x.got, x.pkt_ok, x.pkt_err);
        CHECKF(x.status == (NTSTATUS)0xC000000D, "code %#lx: status %#lx", codes[i], (unsigned long)x.status);
        CloseHandle(port);
        ib_close(s);
    }
}

IBTEST(ib_ov_port_unsupported_controls_pend_then_fail_with_not_supported)
{
    static const struct { DWORD code; const char *name; } t[] = {
        {IB_FLUSH, "SIO_FLUSH"}, {IB_FIND_ROUTE, "SIO_FIND_ROUTE"}, {IB_QUERY_PNP, "SIO_QUERY_TARGET_PNP_HANDLE"},
        {IB_RSS_INFO, "SIO_QUERY_RSS_PROCESSOR_INFO"}, {IB_ABSORB_RTRALERT, "SIO_ABSORB_RTRALERT"},
        {IB_UCAST_IF, "SIO_UCAST_IF"}, {IB_LIMIT_BCAST, "SIO_LIMIT_BROADCASTS"}, {IB_BASE_HANDLE, "SIO_BASE_HANDLE"},
        {IB_BSP_HANDLE, "SIO_BSP_HANDLE"}, {IB_BSP_HANDLE_SELECT, "SIO_BSP_HANDLE_SELECT"},
        {IB_BSP_HANDLE_POLL, "SIO_BSP_HANDLE_POLL"},
    };
    unsigned i;
    for (i = 0; i < sizeof t / sizeof *t; ++i) {
        SOCKET s = ib_mk(K_TCP4);
        HANDLE port;
        ib_port_res x;
        unsigned char out[16];
        REQUIRE(s != INVALID_SOCKET);
        port = ib_port_for(s);
        x = ib_ov_port(s, port, t[i].code, NULL, 0, out, sizeof out);
        CHECKF(x.r == SOCKET_ERROR && x.err == WSA_IO_PENDING && x.n == IB_UNSET, "%s: r=%d err=%d n=%lu", t[i].name, x.r, x.err, x.n);
        CHECKF(x.got && !x.pkt_ok && x.pkt_err == ERROR_NOT_SUPPORTED && x.pkt_bytes == 0, "%s: packet got=%d ok=%d err=%lu bytes=%lu",
               t[i].name, x.got, x.pkt_ok, x.pkt_err, x.pkt_bytes);
        CHECKF(x.status == (NTSTATUS)0xC00000BB, "%s: status %#lx", t[i].name, (unsigned long)x.status);
        CloseHandle(port);
        ib_close(s);
    }
}

IBTEST(ib_ov_port_wrong_socket_kind_fails_synchronously_without_packet)
{
    /* Argument/state errors are returned directly and nothing is queued. */
    static const struct { DWORD code; int kind; int err; const char *name; } t[] = {
        {IB_UDP_CONNRESET, K_TCP4, WSAEINVAL, "UDP_CONNRESET on stream"},
        {IB_ENABLE_CIRCQ, K_TCP4, WSAEINVAL, "ENABLE_CIRCULAR_QUEUEING on stream"},
        {IB_GET_BCAST, K_TCP4, WSAEINVAL, "GET_BROADCAST_ADDRESS on stream"},
        {IB_GET_BCAST, K_UDP6, WSAENOPROTOOPT, "GET_BROADCAST_ADDRESS on IPv6"},
    };
    unsigned i;
    for (i = 0; i < sizeof t / sizeof *t; ++i) {
        SOCKET s = ib_mk(t[i].kind);
        HANDLE port;
        OVERLAPPED ov, *p = NULL;
        DWORD n = IB_UNSET, got = 0, in[2] = {1, 0};
        unsigned char out[32];
        ULONG_PTR key;
        int r;
        if (s == INVALID_SOCKET) continue;
        port = ib_port_for(s);
        memset(&ov, 0, sizeof ov);
        ib_seterr(0);
        r = U(WSAIoctl)(s, t[i].code, in, 4, out, sizeof out, &n, (LPWSAOVERLAPPED)&ov, NULL);
        CHECKF(r == SOCKET_ERROR && ib_err() == t[i].err, "%s: r=%d err=%d", t[i].name, r, ib_err());
        CHECKF(!GetQueuedCompletionStatus(port, &got, &key, &p, 50) && p == NULL, "%s: a packet was queued", t[i].name);
        CloseHandle(port);
        ib_close(s);
    }
}

IBTEST(ib_ov_port_missing_byte_count_pointer_is_fault_for_every_control)
{
    static const DWORD codes[] = {IB_GET_BCAST, IB_GET_QOS, IB_UDP_CONNRESET, IB_MC_SCOPE, IB_ENABLE_CIRCQ, IB_FLUSH,
                                  IB_BASE_HANDLE, IB_RSS_INFO, IB_FIONREAD, IB_SIOCATMARK, IB_KEEPALIVE};
    unsigned i;
    SOCKET s = ib_mk(K_UDP4);
    REQUIRE(s != INVALID_SOCKET);
    for (i = 0; i < sizeof codes / sizeof *codes; ++i) {
        OVERLAPPED ov;
        DWORD in[4] = {1, 60000, 1000, 0};
        unsigned char out[96];
        int r;
        memset(&ov, 0, sizeof ov);
        ib_seterr(0);
        r = U(WSAIoctl)(s, codes[i], in, 12, out, sizeof out, NULL, (LPWSAOVERLAPPED)&ov, NULL);
        CHECKF(r == SOCKET_ERROR && ib_err() == WSAEFAULT, "code %#lx: r=%d err=%d", codes[i], r, ib_err());
    }
    ib_close(s);
}

/* ---- completion routines ------------------------------------------------------------------------ */
static volatile LONG ib_apc_count;
static volatile DWORD ib_apc_err, ib_apc_bytes, ib_apc_flags;
static OVERLAPPED *volatile ib_apc_ov;
static void CALLBACK ib_apc(DWORD err, DWORD bytes, LPWSAOVERLAPPED ov, DWORD flags)
{
    InterlockedIncrement(&ib_apc_count);
    ib_apc_err = err; ib_apc_bytes = bytes; ib_apc_flags = flags;
    ib_apc_ov = (OVERLAPPED *)ov;
}

static int ib_run_apc(SOCKET s, DWORD code, void *in, DWORD inl, void *out, DWORD outl, int *r_out, int *err_out, DWORD *n_out)
{
    OVERLAPPED ov;
    DWORD n = IB_UNSET;
    memset(&ov, 0, sizeof ov);
    ib_apc_count = 0; ib_apc_err = 0xffff; ib_apc_bytes = 0xffff; ib_apc_ov = NULL;
    ib_seterr((int)IB_UNSET);
    *r_out = U(WSAIoctl)(s, code, in, inl, out, outl, &n, (LPWSAOVERLAPPED)&ov, ib_apc);
    *err_out = ib_err();
    *n_out = n;
    SleepEx(100, TRUE);
    return ib_apc_ov == &ov;
}

IBTEST(ib_ov_apc_bcast_runs_once_with_no_count)
{
    IB_SOCK(u, K_UDP4);
    struct sockaddr_in a;
    int r, e;
    DWORD n;
    int same = ib_run_apc(u, IB_GET_BCAST, NULL, 0, &a, sizeof a, &r, &e, &n);
    CHECKF(r == 0 && n == 16, "r=%d err=%d n=%lu", r, e, n);
    CHECKF(ib_apc_count == 1 && same && ib_apc_err == 0 && ib_apc_bytes == 0, "apc count=%ld err=%lu bytes=%lu", ib_apc_count, ib_apc_err, ib_apc_bytes);
    ib_close(u);
}

IBTEST(ib_ov_apc_setter_runs_once_with_zero_bytes)
{
    IB_SOCK(u, K_UDP4);
    DWORD v = 1;
    int r, e;
    DWORD n;
    int same = ib_run_apc(u, IB_UDP_CONNRESET, &v, 4, NULL, 0, &r, &e, &n);
    CHECKF(r == 0, "r=%d err=%d", r, e);
    CHECKF(ib_apc_count == 1 && same && ib_apc_err == 0 && ib_apc_bytes == 0, "apc count=%ld err=%lu bytes=%lu", ib_apc_count, ib_apc_err, ib_apc_bytes);
    ib_close(u);
}

IBTEST(ib_ov_apc_unsupported_control_reports_opnotsupp)
{
    IB_SOCK(t, K_TCP4);
    unsigned char out[16];
    int r, e;
    DWORD n;
    int same = ib_run_apc(t, IB_QUERY_PNP, NULL, 0, out, sizeof out, &r, &e, &n);
    CHECKF(r == SOCKET_ERROR && e == WSA_IO_PENDING && n == IB_UNSET, "r=%d err=%d n=%lu", r, e, n);
    CHECKF(ib_apc_count == 1 && same && ib_apc_err == WSAEOPNOTSUPP && ib_apc_bytes == 0, "apc count=%ld err=%lu bytes=%lu", ib_apc_count, ib_apc_err, ib_apc_bytes);
    ib_close(t);
}

IBTEST(ib_ov_apc_without_byte_count_pointer_is_fault_and_never_runs)
{
    IB_SOCK(u, K_UDP4);
    OVERLAPPED ov;
    struct sockaddr_in a;
    int r;
    memset(&ov, 0, sizeof ov);
    ib_apc_count = 0;
    ib_seterr(0);
    r = U(WSAIoctl)(u, IB_GET_BCAST, NULL, 0, &a, sizeof a, NULL, (LPWSAOVERLAPPED)&ov, ib_apc);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSAEFAULT, "r=%d err=%d", r, ib_err());
    SleepEx(50, TRUE);
    CHECK(ib_apc_count == 0);
    ib_close(u);
}

IBTEST(ib_ov_apc_synchronous_failure_never_runs_routine)
{
    IB_SOCK(t, K_TCP4);
    OVERLAPPED ov;
    DWORD v = 1, n = IB_UNSET;
    int r;
    memset(&ov, 0, sizeof ov);
    ib_apc_count = 0;
    ib_seterr(0);
    r = U(WSAIoctl)(t, IB_UDP_CONNRESET, &v, 4, NULL, 0, &n, (LPWSAOVERLAPPED)&ov, ib_apc);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSAEINVAL, "r=%d err=%d", r, ib_err());
    SleepEx(50, TRUE);
    CHECK(ib_apc_count == 0);
    ib_close(t);
}

/* ---- event-based overlapped completion --------------------------------------------------------- */
IBTEST(ib_ov_event_inline_success_signals_event_and_gives_result)
{
    IB_SOCK(u, K_UDP4);
    WSAOVERLAPPED ov;
    struct sockaddr_in a;
    DWORD n = IB_UNSET, t = 0, fl = 0;
    int r;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    r = U(WSAIoctl)(u, IB_GET_BCAST, NULL, 0, &a, sizeof a, &n, &ov, NULL);
    CHECKF(r == 0, "r=%d err=%d", r, ib_err());
    CHECK(WaitForSingleObject(ov.hEvent, 1000) == WAIT_OBJECT_0);
    CHECK(U(WSAGetOverlappedResult)(u, &ov, &t, FALSE, &fl));
    CHECKF(t == 0 && fl == 0, "bytes=%lu flags=%lu", t, fl);
    CloseHandle(ov.hEvent);
    ib_close(u);
}

IBTEST(ib_ov_event_unsupported_control_result_is_opnotsupp)
{
    IB_SOCK(t, K_TCP4);
    WSAOVERLAPPED ov;
    unsigned char out[16];
    DWORD n = IB_UNSET, tr = 0, fl = 0;
    int r;
    memset(&ov, 0, sizeof ov);
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    r = U(WSAIoctl)(t, IB_FLUSH, NULL, 0, out, sizeof out, &n, &ov, NULL);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSA_IO_PENDING, "r=%d err=%d", r, ib_err());
    CHECK(WaitForSingleObject(ov.hEvent, 2000) == WAIT_OBJECT_0);
    ib_seterr(0);
    CHECK(!U(WSAGetOverlappedResult)(t, &ov, &tr, FALSE, &fl));
    CHECKF(ib_err() == WSAEOPNOTSUPP, "err=%d", ib_err());
    CloseHandle(ov.hEvent);
    ib_close(t);
}
