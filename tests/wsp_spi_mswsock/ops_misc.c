/* Less common provider entry-point behaviour: extension-function lookup and keep-alive controls through
 * WSPIoctl, out-of-band data, argument edge cases of select / enumerate-events / accept / QoS lookup, and
 * option size rules.  Where the exact outcome is a property of the OS rather than of the interface, the
 * observation is logged with t_note and only relations that hold on every build are checked.
 */
#include "spi.h"
#include <mswsock.h>

/* ---------------------------------------------------------------- SIO_GET_EXTENSION_FUNCTION_POINTER */
static void ext_lookup(const GUID *g, const char *nm)
{
    SOCKET s; void *fn = NULL; DWORD n = 0; int e = 0;
    s = sp_tcp();
    CHECK(s != INVALID_SOCKET);
    if (s == INVALID_SOCKET) return;
    EXPECT_EQ(P.lpWSPIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, (void *)g, sizeof *g, &fn, sizeof fn, &n, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(n, sizeof fn);
    CHECKF(fn != NULL, "%s: NULL pointer", nm);
    if (fn) {
        HMODULE h = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)fn, &h);
        CHECKF(h == t_module("mswsock.dll"), "%s: pointer outside mswsock", nm);
    }
    sp_close(s);
}
#define EXT_TEST(nm, guid) TEST(ext_pointer_##nm) { GUID g = guid; SP_NEED(); ext_lookup(&g, #nm); }
EXT_TEST(acceptex, WSAID_ACCEPTEX)
EXT_TEST(getacceptexsockaddrs, WSAID_GETACCEPTEXSOCKADDRS)
EXT_TEST(transmitfile, WSAID_TRANSMITFILE)
EXT_TEST(transmitpackets, WSAID_TRANSMITPACKETS)
EXT_TEST(connectex, WSAID_CONNECTEX)
EXT_TEST(disconnectex, WSAID_DISCONNECTEX)
EXT_TEST(wsarecvmsg, WSAID_WSARECVMSG)

TEST(ext_pointer_unknown_guid)
{
    static const GUID odd = { 0x7e57ab1e, 0x0001, 0x0002, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    SOCKET s; void *fn = (void *)0x1234; DWORD n = 77; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, (void *)&odd, sizeof odd, &fn, sizeof fn, &n, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_INVAL);
    sp_close(s);
}
TEST(ext_pointer_same_on_every_socket)
{
    GUID g = WSAID_ACCEPTEX; SOCKET a, b; void *fa = NULL, *fb = NULL; DWORD n = 0; int e = 0;
    SP_NEED();
    a = sp_tcp(); b = sp_udp();
    EXPECT_EQ(P.lpWSPIoctl(a, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fa, sizeof fa, &n, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(P.lpWSPIoctl(b, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, &fb, sizeof fb, &n, NULL, NULL, NULL, &e), 0);
    CHECK(fa == fb);
    sp_close(a); sp_close(b);
}
TEST(ext_pointer_output_buffer_too_small)
{
    GUID g = WSAID_ACCEPTEX; SOCKET s; char small[4]; DWORD n = 0; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g, sizeof g, small, sizeof small, &n, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    sp_close(s);
}

/* ---------------------------------------------------------------- keep-alive controls */
TEST(ioctl_keepalive_vals_enables_keepalive)
{
    SOCKET s; struct tcp_keepalive ka; DWORD n = 0; int e = 0; unsigned char on = 0; int l;
    SP_NEED();
    s = sp_tcp();
    ka.onoff = 1; ka.keepalivetime = 60000; ka.keepaliveinterval = 5000;
    EXPECT_EQ(P.lpWSPIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof ka, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
    l = 1; on = 0;
    EXPECT_EQ(P.lpWSPGetSockOpt(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&on, &l, &e), 0);
    EXPECT_EQ(on, 1);
    sp_close(s);
}
TEST(ioctl_keepalive_vals_short_input)
{
    SOCKET s; DWORD small = 1, n = 0; int e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPIoctl(s, SIO_KEEPALIVE_VALS, &small, sizeof small, NULL, 0, &n, NULL, NULL, NULL, &e), SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    sp_close(s);
}
TEST(ioctl_keepalive_vals_off_disables)
{
    SOCKET s; struct tcp_keepalive ka; DWORD n = 0; int e = 0; unsigned char on = 9; int l = 1;
    SP_NEED();
    s = sp_tcp();
    ka.onoff = 1; ka.keepalivetime = 60000; ka.keepaliveinterval = 5000;
    EXPECT_EQ(P.lpWSPIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof ka, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
    ka.onoff = 0;
    EXPECT_EQ(P.lpWSPIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof ka, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(P.lpWSPGetSockOpt(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&on, &l, &e), 0);
    EXPECT_EQ(on, 0);
    sp_close(s);
}

/* ---------------------------------------------------------------- argument edge cases */
TEST(select_with_every_set_null_waits_out_the_timeout)
{
    struct timeval tv; int e = 0, r;
    SP_NEED();
    tv.tv_sec = 0; tv.tv_usec = 0;
    r = P.lpWSPSelect(0, NULL, NULL, NULL, &tv, &e);
    EXPECT_EQ(r, 0);
}
TEST(select_with_empty_sets_returns_zero)
{
    fd_set r; struct timeval tv; int e = 0, rc;
    SP_NEED();
    r.fd_count = 0;
    tv.tv_sec = 0; tv.tv_usec = 0;
    rc = P.lpWSPSelect(0, &r, NULL, NULL, &tv, &e);
    EXPECT_EQ(rc, 0);
}
TEST(select_negative_timeout_is_refused)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        fd_set r; struct timeval tv; int e = 0, rc;
        r.fd_count = 1; r.fd_array[0] = a;
        tv.tv_sec = -1; tv.tv_usec = 0;
        rc = P.lpWSPSelect(0, &r, NULL, NULL, &tv, &e);
        t_note("select with a negative timeout returns %d (error %d)", rc, e);
        sp_close(c); sp_close(a);
    }
}
TEST(select_usec_out_of_range_is_refused)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        fd_set r; struct timeval tv; int e = 0, rc;
        r.fd_count = 1; r.fd_array[0] = a;
        tv.tv_sec = 0; tv.tv_usec = 2000000;
        rc = P.lpWSPSelect(0, &r, NULL, NULL, &tv, &e);
        t_note("select with 2000000 us returns %d (error %d)", rc, e);
        sp_close(c); sp_close(a);
    }
}
TEST(enum_events_null_result)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        int e = 0, rc = P.lpWSPEnumNetworkEvents(a, NULL, NULL, &e);
        EXPECT_EQ(rc, SOCKET_ERROR);
        EXPECT_EQ(e, SE_INVAL);
        sp_close(c); sp_close(a);
    }
}
TEST(get_qos_by_name_on_stream_socket)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSABUF n; QOS q; int e = 0, rc;
        n.buf = (CHAR *)"nosuchflowspec"; n.len = 14;
        memset(&q, 0, sizeof q);
        rc = P.lpWSPGetQOSByName(c, &n, &q, &e);
        EXPECT_EQ(rc, TRUE);   /* the lookup is answered even for a name nobody defined */
        sp_close(c); sp_close(a);
    }
}
TEST(accept_short_address_buffer)
{
    struct sockaddr_in la; SOCKET l, c, a; char small[4]; int e = 0, n = sizeof small;
    SP_NEED();
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_readable(l, 5000), 1);
    a = P.lpWSPAccept(l, (struct sockaddr *)small, &n, NULL, 0, &e);
    CHECK(a == INVALID_SOCKET);
    EXPECT_EQ(e, SE_FAULT);
    EXPECT_EQ(n, 4);
    sp_close(a); sp_close(c); sp_close(l);
}
TEST(accept_address_pointer_without_length)
{
    struct sockaddr_in la, pa; SOCKET l, c, a; int e = 0;
    SP_NEED();
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_readable(l, 5000), 1);
    a = P.lpWSPAccept(l, (struct sockaddr *)&pa, NULL, NULL, 0, &e);
    CHECK(a != INVALID_SOCKET);   /* the address is simply not reported */
    if (a != INVALID_SOCKET) sp_close(a);
    sp_close(c); sp_close(l);
}

/* condition callback: runs only when the socket asked for conditional accept; the verdict is honoured */
static volatile LONG g_cond_calls;
static volatile LONG g_cond_verdict;
static int CALLBACK cond_fn(LPWSABUF caller_id, LPWSABUF caller_data, LPQOS sqos, LPQOS gqos, LPWSABUF callee_id, LPWSABUF callee_data, GROUP *g, DWORD_PTR ctx)
{
    InterlockedIncrement(&g_cond_calls);
    return (int)g_cond_verdict;
}
TEST(accept_condition_function_runs_and_can_reject)
{
    struct sockaddr_in la; SOCKET l, c, a; int e = 0;
    SP_NEED();
    g_cond_calls = 0; g_cond_verdict = CF_REJECT;
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_readable(l, 5000), 1);
    a = P.lpWSPAccept(l, NULL, NULL, cond_fn, 0, &e);
    CHECK(a == INVALID_SOCKET);
    EXPECT_EQ(g_cond_calls, 1);
    t_note("rejected conditional accept reports %d", e);
    if (a != INVALID_SOCKET) sp_close(a);
    sp_close(c); sp_close(l);
}
TEST(accept_condition_function_accepting)
{
    struct sockaddr_in la; SOCKET l, c, a; int e = 0;
    SP_NEED();
    g_cond_calls = 0; g_cond_verdict = CF_ACCEPT;
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_readable(l, 5000), 1);
    a = P.lpWSPAccept(l, NULL, NULL, cond_fn, 0, &e);
    CHECK(a != INVALID_SOCKET);
    EXPECT_EQ(g_cond_calls, 1);
    if (a != INVALID_SOCKET) sp_close(a);
    sp_close(c); sp_close(l);
}
TEST(conditional_accept_option_is_accepted_on_a_fresh_socket)
{
    SOCKET l; int e = 0, on = 1, v = 0, n = 4;
    SP_NEED();
    l = sp_tcp();
    EXPECT_EQ(P.lpWSPSetSockOpt(l, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, (const char *)&on, 4, &e), 0);
    EXPECT_EQ(P.lpWSPGetSockOpt(l, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, (char *)&v, &n, &e), 0);
    CHECK(v != 0);
    sp_close(l);
}

/* ---------------------------------------------------------------- out-of-band data */
TEST(oob_byte_roundtrip)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSABUF w; DWORD sent = 0, got = 0, fl = MSG_OOB; int e = 0; char b[4] = {0};
        w.buf = "!"; w.len = 1;
        EXPECT_EQ(P.lpWSPSend(c, &w, 1, &sent, MSG_OOB, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(sent, 1);
        {   /* urgent data shows up in the exception set */
            fd_set x; struct timeval tv; int rc;
            x.fd_count = 1; x.fd_array[0] = a;
            tv.tv_sec = 5; tv.tv_usec = 0;
            rc = P.lpWSPSelect(0, NULL, NULL, &x, &tv, &e);
            EXPECT_EQ(rc, 1);
        }
        w.buf = b; w.len = sizeof b;
        EXPECT_EQ(P.lpWSPRecv(a, &w, 1, &got, &fl, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(got, 1);
        EXPECT_EQ(b[0], '!');
        sp_close(c); sp_close(a);
    }
}
TEST(oob_receive_without_urgent_data)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        WSABUF w; DWORD got = 0, fl = MSG_OOB, n = 0; int e = 0, rc; char b[4]; u_long on = 1;
        /* non-blocking: a blocking OOB receive with nothing urgent queued simply waits */
        EXPECT_EQ(P.lpWSPIoctl(a, FIONBIO, &on, 4, NULL, 0, &n, NULL, NULL, NULL, &e), 0);
        w.buf = b; w.len = sizeof b;
        rc = P.lpWSPRecv(a, &w, 1, &got, &fl, NULL, NULL, NULL, &e);
        EXPECT_EQ(rc, SOCKET_ERROR);
        EXPECT_EQ(e, SE_WOULDBLOCK);
        sp_close(c); sp_close(a);
    }
}
TEST(oob_send_on_datagram_socket)
{
    SOCKET s; WSABUF w; DWORD sent = 0; int e = 0, rc; struct sockaddr_in to;
    SP_NEED();
    s = sp_udp();
    sp_v4(&to, 9);
    w.buf = "x"; w.len = 1;
    rc = P.lpWSPSendTo(s, &w, 1, &sent, MSG_OOB, (struct sockaddr *)&to, sizeof to, NULL, NULL, NULL, &e);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(e, SE_OPNOTSUPP);
    sp_close(s);
}
TEST(ioctl_atmark_without_oob_data)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        u_long at = 7; DWORD n = 0; int e = 0;
        EXPECT_EQ(P.lpWSPIoctl(a, SIOCATMARK, NULL, 0, &at, sizeof at, &n, NULL, NULL, NULL, &e), 0);
        EXPECT_EQ(at, 1);
        EXPECT_EQ(n, 4);
        sp_close(c); sp_close(a);
    }
}

/* ---------------------------------------------------------------- option details */
TEST(opt_max_msg_size_on_datagram)
{
    SOCKET s; int v = 0, l = 4, e = 0;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(P.lpWSPGetSockOpt(s, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&v, &l, &e), 0);
    CHECK(v > 0);
    EXPECT_EQ(v, 65507);
    sp_close(s);
}
TEST(opt_max_msg_size_on_stream)
{
    SOCKET s; int v = 0, l = 4, e = 0, rc;
    SP_NEED();
    s = sp_tcp();
    rc = P.lpWSPGetSockOpt(s, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&v, &l, &e);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(v, -1);   /* stream sockets have no message limit: all ones */
    sp_close(s);
}
TEST(opt_rcvbuf_set_is_read_back)
{
    SOCKET s; int v = 16384, l = 4, e = 0, got = 0;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(P.lpWSPSetSockOpt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&v, 4, &e), 0);
    EXPECT_EQ(P.lpWSPGetSockOpt(s, SOL_SOCKET, SO_RCVBUF, (char *)&got, &l, &e), 0);
    EXPECT_EQ(got, 16384);
    sp_close(s);
}
TEST(opt_sndbuf_set_is_read_back)
{
    SOCKET s; int v = 16384, l = 4, e = 0, got = 0;
    SP_NEED();
    s = sp_udp();
    EXPECT_EQ(P.lpWSPSetSockOpt(s, SOL_SOCKET, SO_SNDBUF, (const char *)&v, 4, &e), 0);
    EXPECT_EQ(P.lpWSPGetSockOpt(s, SOL_SOCKET, SO_SNDBUF, (char *)&got, &l, &e), 0);
    EXPECT_EQ(got, 16384);
    sp_close(s);
}
TEST(opt_get_with_short_length_for_int_option)
{
    SOCKET s; char b[4] = { 1, 1, 1, 1 }; int l = 2, e = 0, rc;
    SP_NEED();
    s = sp_tcp();
    rc = P.lpWSPGetSockOpt(s, SOL_SOCKET, SO_RCVBUF, b, &l, &e);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    sp_close(s);
}
TEST(opt_set_with_short_length_for_int_option)
{
    SOCKET s; char b[4] = { 1, 0, 0, 0 }; int e = 0, rc;
    SP_NEED();
    s = sp_tcp();
    rc = P.lpWSPSetSockOpt(s, SOL_SOCKET, SO_RCVBUF, b, 2, &e);
    EXPECT_EQ(rc, SOCKET_ERROR);
    EXPECT_EQ(e, SE_FAULT);
    sp_close(s);
}
TEST(opt_so_error_after_failed_connect_persists)
{
    struct sockaddr_in la; SOCKET l, c; int e = 0, v = 0, n = 4; DWORD bytes = 0; u_long on = 1;
    SP_NEED();
    l = sp_listener(&la);
    sp_close(l);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPIoctl(c, FIONBIO, &on, 4, NULL, 0, &bytes, NULL, NULL, NULL, &e), 0);
    (void)P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e);
    {
        fd_set x; struct timeval tv;
        x.fd_count = 1; x.fd_array[0] = c; tv.tv_sec = 5; tv.tv_usec = 0;
        (void)P.lpWSPSelect(0, NULL, NULL, &x, &tv, &e);
    }
    EXPECT_EQ(P.lpWSPGetSockOpt(c, SOL_SOCKET, SO_ERROR, (char *)&v, &n, &e), 0);
    EXPECT_EQ(v, WSAECONNREFUSED);
    v = 7; n = 4;
    EXPECT_EQ(P.lpWSPGetSockOpt(c, SOL_SOCKET, SO_ERROR, (char *)&v, &n, &e), 0);
    EXPECT_EQ(v, WSAECONNREFUSED);   /* the failure of an asynchronous connect is not consumed by reading it */
    sp_close(c);
}
TEST(opt_connect_time_after_connect)
{
    SP_NEED();
    {
        SP_PAIR(c, a);
        DWORD secs = 0; int l = 4, e = 0;
        EXPECT_EQ(P.lpWSPGetSockOpt(c, SOL_SOCKET, SO_CONNECT_TIME, (char *)&secs, &l, &e), 0);
        CHECK(secs != 0xFFFFFFFFu);
        sp_close(c); sp_close(a);
    }
}
TEST(opt_connect_time_unconnected_is_all_ones)
{
    SOCKET s; DWORD secs = 0; int l = 4, e = 0;
    SP_NEED();
    s = sp_tcp();
    EXPECT_EQ(P.lpWSPGetSockOpt(s, SOL_SOCKET, SO_CONNECT_TIME, (char *)&secs, &l, &e), 0);
    EXPECT_EQ(secs, 0xFFFFFFFFu);
    sp_close(s);
}
TEST(opt_update_accept_context_roundtrip)
{
    struct sockaddr_in la; SOCKET l, c, a; int e = 0;
    SP_NEED();
    l = sp_listener(&la);
    c = sp_tcp();
    EXPECT_EQ(P.lpWSPConnect(c, (struct sockaddr *)&la, sizeof la, NULL, NULL, NULL, NULL, &e), 0);
    EXPECT_EQ(sp_readable(l, 5000), 1);
    a = P.lpWSPAccept(l, NULL, NULL, NULL, 0, &e);
    CHECK(a != INVALID_SOCKET);
    {
        SOCKET ls = l;
        EXPECT_EQ(P.lpWSPSetSockOpt(a, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (const char *)&ls, sizeof ls, &e), 0);
    }
    sp_close(a); sp_close(c); sp_close(l);
}
