/* AFD poll completion delivery: I/O completion port packets (key, APC context value) for immediate and
 * pending poll requests, and the completion of a request whose carrier handle is closed. */
#include "afd_common.h"

static HANDLE mk_port_for(SOCKET s)
{
    HANDLE p = CreateIoCompletionPort((HANDLE)s, NULL, 0, 0);
    CHECK(p != NULL);
    return p;
}

#define APC_VALUE ((void *)(ULONG_PTR)0xdeadbeef)

/* Without an APC context no packet is queued, even though the request completed. */
TEST(afdpc_iocp_no_packet_without_apc_context)
{
    SOCKET c, s; HANDLE ev, port; pollreq_t p; IO_STATUS_BLOCK io; ULONG_PTR key = 1, val = 1; LARGE_INTEGER zero = {{0}};
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event(); port = mk_port_for(c);
    memset(&p, 0, sizeof(p));
    p.timeout = REL_MS(100); p.count = 1; p.sockets[0].socket = c; p.sockets[0].flags = AFDX_POLL_WRITE;
    EXPECT_ST(afd_poll((HANDLE)c, ev, &io, &p, sizeof(p), &p, sizeof(p)), 0);
    EXPECT_ST(F.NtRemoveIoCompletion(port, &key, &val, &io, &zero), AS_TIMEOUT);
    CloseHandle(port); CloseHandle(ev); sock_close(c); sock_close(s);
}

/* An immediately completed request still posts a packet when an APC context was supplied. */
TEST(afdpc_iocp_immediate_completion_posts_packet)
{
    SOCKET c, s; HANDLE ev, port; pollreq_t p; IO_STATUS_BLOCK io; ULONG_PTR key = 1, val = 0; LARGE_INTEGER zero = {{0}};
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event(); port = mk_port_for(c);
    memset(&p, 0, sizeof(p));
    p.timeout = REL_MS(100); p.count = 1; p.sockets[0].socket = c; p.sockets[0].flags = AFDX_POLL_WRITE;
    EXPECT_ST(afd_poll_ex((HANDLE)c, ev, APC_VALUE, &io, &p, sizeof(p), &p, sizeof(p)), 0);
    EXPECT_ST(F.NtRemoveIoCompletion(port, &key, &val, &io, &zero), 0);
    CHECK(key == 0);
    CHECK(val == 0xdeadbeef);
    CloseHandle(port); CloseHandle(ev); sock_close(c); sock_close(s);
}

/* The zero-timeout, nothing-ready form completes immediately and also posts. */
TEST(afdpc_iocp_zero_timeout_empty_result_posts_packet)
{
    SOCKET c, s; HANDLE ev, port; pollreq_t p; IO_STATUS_BLOCK io; ULONG_PTR key = 1, val = 0; LARGE_INTEGER zero = {{0}};
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event(); port = mk_port_for(c);
    memset(&p, 0, sizeof(p));
    p.timeout = 0; p.count = 1; p.sockets[0].socket = c; p.sockets[0].flags = AFDX_POLL_READ;
    EXPECT_ST(afd_poll_ex((HANDLE)c, ev, APC_VALUE, &io, &p, sizeof(p), &p, sizeof(p)), 0);
    EXPECT_ST(F.NtRemoveIoCompletion(port, &key, &val, &io, &zero), 0);
    CHECK(key == 0);
    CHECK(val == 0xdeadbeef);
    CloseHandle(port); CloseHandle(ev); sock_close(c); sock_close(s);
}

/* The carrier handle is closed while its request polls another socket: the request times out and the
 * packet and event still arrive. */
TEST(afdpc_iocp_close_of_carrier_handle_still_completes)
{
    SOCKET c, s; HANDLE ev, port; pollreq_t p; IO_STATUS_BLOCK io; ULONG_PTR key = 1, val = 0; LARGE_INTEGER zero = {{0}};
    NEED_AFD();
    mk_pair(&c, &s); ev = mk_event(); port = mk_port_for(c);
    memset(&p, 0, sizeof(p));
    p.timeout = REL_MS(100); p.count = 1; p.sockets[0].socket = s; p.sockets[0].flags = AFDX_POLL_READ;
    p.sockets[0].status = (LONG)0xdeadbeef;
    EXPECT_ST(afd_poll_ex((HANDLE)c, ev, APC_VALUE, &io, &p, sizeof(p), &p, sizeof(p)), AS_PENDING);
    sock_close(c);
    EXPECT_ST(WaitForSingleObject(ev, 1500), WAIT_OBJECT_0);
    CHECK_IO(io, AS_TIMEOUT, POLL_BYTES(0));
    CHECK(p.count == 0);
    EXPECT_ST(F.NtRemoveIoCompletion(port, &key, &val, &io, &zero), 0);
    CHECK(key == 0);
    CHECK(val == 0xdeadbeef);
    CloseHandle(port); CloseHandle(ev); sock_close(s);
}
