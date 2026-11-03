/* SIO_GET_INTERFACE_LIST through WSAIoctl.
 * Measures: the result is an array of INTERFACE_INFO (size is a multiple of the element size), includes the
 * loopback interface, fields are internally consistent; an OVERLAPPED request always goes pending
 * (WSA_IO_PENDING) and completes through the port with the byte count, while a too-small buffer completes with
 * ERROR_INSUFFICIENT_BUFFER / STATUS_BUFFER_TOO_SMALL; synchronous too-small is WSAEFAULT with size 0; a completion
 * routine receives WSAEFAULT in the too-small case.
 */
#include "w.h"

#define IBUF 4096

static SOCKET if_socket(void)
{
    return p_WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
}

static DWORD if_sync_size(SOCKET s, char *buf)
{
    DWORD size = W_SENT;
    p_WSASetLastError(W_SENT);
    if (p_WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, buf, IBUF, &size, NULL, NULL)) return 0;
    return size;
}

TEST(lift10_iflist_sync_size_is_whole_elements)
{
    char buf[IBUF];
    SOCKET s;
    DWORD size = W_SENT;
    int ret;
    W_BEGIN();
    s = if_socket();
    CHECK(s != INVALID_SOCKET);
    p_WSASetLastError(W_SENT);
    ret = p_WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, buf, sizeof buf, &size, NULL, NULL);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(p_WSAGetLastError(), 0);
    CHECK(size != 0 && size != W_SENT && size % sizeof(INTERFACE_INFO) == 0);
    p_closesocket(s);
}

TEST(lift10_iflist_entries_are_consistent_and_include_loopback)
{
    char buf[IBUF];
    INTERFACE_INFO *info = (INTERFACE_INFO *)buf;
    SOCKET s;
    DWORD size;
    unsigned i, count;
    int loopback = 0, bad = 0;
    W_BEGIN();
    s = if_socket();
    size = if_sync_size(s, buf);
    count = size / sizeof(INTERFACE_INFO);
    CHECK(count > 0);
    for (i = 0; i < count; i++) {
        u_long flags = info[i].iiFlags;
        if (flags & IFF_LOOPBACK) loopback = 1;
        if (info[i].iiAddress.AddressIn.sin_family != AF_INET) bad |= 1;
        if (info[i].iiNetmask.AddressIn.sin_family != AF_INET) bad |= 2;
        if (!info[i].iiAddress.AddressIn.sin_addr.s_addr) bad |= 4;
        if (!info[i].iiNetmask.AddressIn.sin_addr.s_addr) bad |= 8;
        if (flags & IFF_BROADCAST) {
            if (info[i].iiBroadcastAddress.AddressIn.sin_family != AF_INET) bad |= 16;
            if (!info[i].iiBroadcastAddress.AddressIn.sin_addr.s_addr) bad |= 32;
        } else if (info[i].iiBroadcastAddress.AddressIn.sin_addr.s_addr) {
            bad |= 64;     /* no broadcast flag: the broadcast address must be zero */
        }
    }
    CHECKF(bad == 0, "inconsistent INTERFACE_INFO fields, mask %#x", bad);
    CHECK(loopback);
    p_closesocket(s);
}

TEST(lift10_iflist_overlapped_goes_pending_and_completes_with_size)
{
    char buf[IBUF];
    SOCKET s;
    HANDLE port;
    OVERLAPPED ov;
    DWORD expect, size = W_SENT;
    struct w_cp r;
    int ret;
    W_BEGIN();
    s = if_socket();
    port = w_port_for(s, 123);
    expect = if_sync_size(s, buf);
    CHECK(expect != 0);

    memset(&ov, 0, sizeof ov);
    ov.Internal = W_SENT;
    ov.InternalHigh = W_SENT;
    ret = p_WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, buf, sizeof buf, &size, &ov, NULL);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), ERROR_IO_PENDING);
    EXPECT_EQ(size, W_SENT);

    r = w_dequeue(port, 3000);
    CHECK(r.ret);
    EXPECT_EQ(r.bytes, expect);
    EXPECT_EQ(r.key, 123);
    CHECK(r.ov == &ov);
    EXPECT_EQ(ov.Internal, 0);
    EXPECT_EQ(ov.InternalHigh, expect);
    CloseHandle(port);
    p_closesocket(s);
}

TEST(lift10_iflist_small_buffer_sync_is_efault_with_zero_size)
{
    char buf[IBUF];
    SOCKET s;
    DWORD size = W_SENT;
    int ret;
    W_BEGIN();
    s = if_socket();
    ret = p_WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, buf, sizeof(INTERFACE_INFO) - 1, &size, NULL, NULL);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), WSAEFAULT);
    EXPECT_EQ(size, 0);
    p_closesocket(s);
}

TEST(lift10_iflist_small_buffer_overlapped_completes_with_buffer_too_small)
{
    char buf[IBUF];
    SOCKET s;
    HANDLE port;
    OVERLAPPED ov;
    DWORD size = W_SENT;
    struct w_cp r;
    int ret;
    W_BEGIN();
    s = if_socket();
    port = w_port_for(s, 123);
    memset(&ov, 0, sizeof ov);
    ov.Internal = W_SENT;
    ov.InternalHigh = W_SENT;
    ret = p_WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, buf, sizeof(INTERFACE_INFO) - 1, &size, &ov, NULL);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), ERROR_IO_PENDING);
    EXPECT_EQ(size, W_SENT);

    r = w_dequeue(port, 3000);
    CHECK(!r.ret);
    EXPECT_EQ(r.err, ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(r.bytes, 0);
    EXPECT_EQ(r.key, 123);
    CHECK(r.ov == &ov);
    EXPECT_EQ((DWORD)ov.Internal, (DWORD)STATUS_BUFFER_TOO_SMALL);
    EXPECT_EQ(ov.InternalHigh, 0);
    CloseHandle(port);
    p_closesocket(s);
}

TEST(lift10_iflist_null_bytes_returned_is_efault)
{
    char buf[IBUF];
    SOCKET s;
    int ret;
    W_BEGIN();
    s = if_socket();
    ret = p_WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, buf, sizeof buf, NULL, NULL, NULL);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), WSAEFAULT);
    p_closesocket(s);
}

TEST(lift10_iflist_completion_routine_gets_efault_for_small_buffer)
{
    char buf[IBUF];
    SOCKET s;
    OVERLAPPED ov;
    DWORD size = W_SENT, w;
    int ret;
    W_BEGIN();
    s = if_socket();
    memset(&ov, 0, sizeof ov);
    w_apc_reset();
    ret = p_WSAIoctl(s, SIO_GET_INTERFACE_LIST, NULL, 0, buf, sizeof(INTERFACE_INFO) - 1, &size, &ov, w_socket_apc);
    EXPECT_EQ(ret, SOCKET_ERROR);
    EXPECT_EQ(p_WSAGetLastError(), ERROR_IO_PENDING);
    EXPECT_EQ(size, W_SENT);
    w = SleepEx(3000, TRUE);
    EXPECT_EQ(w, WAIT_IO_COMPLETION);
    EXPECT_EQ(w_apc_count, 1);
    EXPECT_EQ(w_apc_error, WSAEFAULT);
    EXPECT_EQ(w_apc_size, 0);
    CHECK(w_apc_ov == &ov);
    p_closesocket(s);
}
