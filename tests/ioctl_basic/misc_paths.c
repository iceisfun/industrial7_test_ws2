/* Measures assorted WSAIoctl/ioctlsocket situations that do not belong to one control: state shared between
 * threads, input and output sharing one buffer, sockets created without the overlapped attribute, shutdown
 * interactions and a sweep of control codes that no provider implements. */
#include "ib.h"

typedef struct { SOCKET s; int ret; } ib_thr;
static DWORD WINAPI ib_nonblock_thread(LPVOID p)
{
    ib_thr *t = p;
    u_long v = 1;
    t->ret = U(ioctlsocket)(t->s, FIONBIO, &v);
    return 0;
}

IBTEST(ib_misc_fionbio_from_other_thread_applies_to_socket)
{
    IB_PAIR(c, s);
    ib_thr t;
    HANDLE h;
    char b[2];
    int r;
    t.s = c; t.ret = -2;
    h = CreateThread(NULL, 0, ib_nonblock_thread, &t, 0, NULL);
    CHECK(WaitForSingleObject(h, 5000) == WAIT_OBJECT_0);
    CloseHandle(h);
    CHECK(t.ret == 0);
    r = U(recv)(c, b, 1, 0);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSAEWOULDBLOCK, "r=%d err=%d", r, ib_err());
    ib_close(c); ib_close(s);
}

IBTEST(ib_misc_same_buffer_for_input_and_output)
{
    IB_PAIR(c, s);
    DWORD v = 0x55555555, n = IB_UNSET;
    int r, tries;
    CHECK(U(send)(s, "abcd", 4, 0) == 4);
    for (tries = 0; tries < 50; ++tries) {
        v = 0x55555555;
        r = U(WSAIoctl)(c, IB_FIONREAD, &v, 4, &v, 4, &n, NULL, NULL);
        CHECKF(r == 0, "r=%d err=%d", r, ib_err());
        if (v >= 4) break;
        Sleep(20);
    }
    CHECKF(v == 4 && n == 4, "v=%lu n=%lu", v, n);
    ib_close(c); ib_close(s);
}

IBTEST(ib_misc_fionread_after_shutdown_receive)
{
    IB_PAIR(c, s);
    DWORD out = IB_UNSET;
    ib_res x;
    CHECK(U(shutdown)(c, SD_RECEIVE) == 0);
    x = ib_io(c, IB_FIONREAD, NULL, 0, &out, 4, 1);
    CHECKF(IB_OK(x) && out == 0, "r=%d err=%d out=%lu", x.r, x.err, out);
    x = ib_io(c, IB_SIOCATMARK, NULL, 0, &out, 4, 1);
    CHECKF(IB_OK(x), "atmark r=%d err=%d", x.r, x.err);
    ib_close(c); ib_close(s);
}

IBTEST(ib_misc_non_overlapped_socket_supports_same_controls)
{
    SOCKET s = U(WSASocketW)(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0);
    u_long v = 1;
    DWORD out = IB_UNSET;
    ib_res x;
    struct sockaddr_in a;
    REQUIRE(s != INVALID_SOCKET);
    CHECK(U(ioctlsocket)(s, FIONBIO, &v) == 0);
    x = ib_io(s, IB_FIONREAD, NULL, 0, &out, 4, 1);
    CHECKF(IB_OK(x) && out == 0, "FIONREAD r=%d err=%d", x.r, x.err);
    x = ib_io(s, IB_GET_BCAST, NULL, 0, &a, sizeof a, 1);
    CHECKF(IB_OK(x) && x.n == 16, "GET_BROADCAST_ADDRESS r=%d err=%d", x.r, x.err);
    x = ib_io(s, IB_SIOCATMARK, NULL, 0, &out, 4, 1);
    CHECKF(IB_FAILS(x, WSAEINVAL), "SIOCATMARK r=%d err=%d", x.r, x.err);
    ib_close(s);
}

IBTEST(ib_misc_non_overlapped_socket_overlapped_call_completes_inline)
{
    /* An OVERLAPPED passed on a socket created without the overlapped attribute is not rejected: a control that
     * completes at once simply succeeds. */
    SOCKET s = U(WSASocketW)(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0);
    WSAOVERLAPPED ov;
    struct sockaddr_in a;
    DWORD n = IB_UNSET;
    int r;
    REQUIRE(s != INVALID_SOCKET);
    memset(&ov, 0, sizeof ov);
    ib_seterr(0);
    r = U(WSAIoctl)(s, IB_GET_BCAST, NULL, 0, &a, sizeof a, &n, &ov, NULL);
    CHECKF(r == 0 && n == 16, "r=%d err=%d n=%lu", r, ib_err(), n);
    ib_close(s);
}

/* ---- control codes nobody implements -------------------------------------------------------------- */
IBTEST(ib_misc_unimplemented_codes_are_opnotsupp)
{
    static const DWORD codes[] = {
        0x00000000, 0x00000001, 0x00000100, 0x20000000, 0x20000001, 0x28000000, 0x28000001, 0x28000005,
        0x40000000, 0x48000000, 0x48000001, 0x48000002, 0x80000000, 0x88000000, 0x88000002, 0x88000010,
        0x88000030, 0x98000000, 0x98000100, 0xC0000000, 0xC8000000, 0xC8000001, 0xC8000040, 0xFFFFFFFF,
        0x2000667E, 0x4004667E, 0x8004667F, 0x80046680, 0x40046680,
    };
    static const int kinds[] = {K_TCP4, K_UDP4};
    unsigned i, j;
    for (j = 0; j < 2; ++j) {
        SOCKET s = ib_mk(kinds[j]);
        REQUIRE(s != INVALID_SOCKET);
        for (i = 0; i < sizeof codes / sizeof *codes; ++i) {
            DWORD in[4] = {0, 0, 0, 0}, out[4];
            ib_res x = ib_io(s, codes[i], in, 16, out, sizeof out, 1);
            if (IB_OK(x)) t_note("code %#lx unexpectedly succeeded on kind %d", codes[i], kinds[j]);
            else CHECKF(IB_FAILS(x, WSAEOPNOTSUPP) && x.n == 0, "code %#lx kind %d: r=%d err=%d n=%lu", codes[i], kinds[j], x.r, x.err, x.n);
        }
        ib_close(s);
    }
}

IBTEST(ib_misc_unimplemented_code_without_byte_count_is_fault)
{
    IB_SOCK(s, K_TCP4);
    ib_res x = ib_io(s, 0x12345, NULL, 0, NULL, 0, 0);
    CHECKF(IB_FAILS(x, WSAEFAULT), "r=%d err=%d", x.r, x.err);
    ib_close(s);
}

IBTEST(ib_misc_wsaioctl_success_clears_last_error)
{
    /* A successful call clears the stored error; a failing one overwrites it. */
    IB_SOCK(u, K_UDP4);
    DWORD out = 0, n = 0;
    int r;
    ib_seterr(WSAEMSGSIZE);
    r = U(WSAIoctl)(u, IB_FIONREAD, NULL, 0, &out, 4, &n, NULL, NULL);
    CHECK(r == 0);
    CHECKF(ib_err() == 0, "last error after success: %d", ib_err());
    r = U(WSAIoctl)(u, IB_SIOCATMARK, NULL, 0, &out, 4, &n, NULL, NULL);
    CHECKF(r == SOCKET_ERROR && ib_err() == WSAEINVAL, "r=%d err=%d", r, ib_err());
    ib_close(u);
}
