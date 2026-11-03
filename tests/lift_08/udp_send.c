/* Datagram sends through the extension WSASendMsg and through WSASendTo: parameter validation, error
 * codes, implicit (auto) binding of the sending socket, and scatter/gather byte counts.  All traffic
 * goes to a receiver socket the test binds on loopback.
 */
#include "l8.h"

typedef int (WINAPI *sendmsg_fn)(SOCKET, LPWSAMSG, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

struct udp_fix {
    SOCKET tx, rx;
    struct sockaddr_in rx_addr;
    sendmsg_fn sendmsg;
    char text[12];
    WSABUF iov[2];
    WSAMSG msg;
};

static int fix_open(struct udp_fix *f, int need_sendmsg)
{
    GUID g = WSAID_WSASENDMSG;
    DWORD tmo = 3000;
    int len = sizeof f->rx_addr;
    memset(f, 0, sizeof *f);
    f->tx = w_socket(AF_INET, SOCK_DGRAM, 0);
    f->rx = w_socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(f->tx != INVALID_SOCKET && f->rx != INVALID_SOCKET);
    f->rx_addr = l8_lo4();
    CHECK(w_bind(f->rx, (struct sockaddr *)&f->rx_addr, sizeof f->rx_addr) == 0);
    CHECK(w_getsockname(f->rx, (struct sockaddr *)&f->rx_addr, &len) == 0);
    CHECK(f->rx_addr.sin_port != 0);
    w_setsockopt(f->rx, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof tmo);
    strcpy(f->text, "hello world");
    f->iov[0].buf = f->text; f->iov[0].len = sizeof f->text;   /* 12 bytes including the NUL */
    f->iov[1].buf = f->text; f->iov[1].len = sizeof f->text / 2;   /* 6 bytes */
    f->msg.name = (struct sockaddr *)&f->rx_addr;
    f->msg.namelen = sizeof f->rx_addr;
    f->msg.lpBuffers = f->iov;
    f->msg.dwBufferCount = 1;
    if (need_sendmsg) {
        f->sendmsg = (sendmsg_fn)l8_ext(f->tx, g);
        if (!f->sendmsg) return 0;
    }
    return 1;
}

static void fix_close(struct udp_fix *f)
{
    w_closesocket(f->tx);
    w_closesocket(f->rx);
}

static int tx_is_unbound(SOCKET s)
{
    struct sockaddr_in a;
    int len = sizeof a;
    return w_getsockname(s, (struct sockaddr *)&a, &len) == SOCKET_ERROR && w_WSAGetLastError() == WSAEINVAL;
}

/* After an implicit bind the socket is on the IPv4 wildcard address with a nonzero port. */
static void check_autobound(SOCKET s)
{
    struct sockaddr_in a;
    int len = sizeof a;
    memset(&a, 0xaa, sizeof a);
    L8_EQ(w_getsockname(s, (struct sockaddr *)&a, &len), 0);
    L8_EQ(a.sin_family, AF_INET);
    L8_EQ(a.sin_addr.s_addr, 0);
    CHECK(a.sin_port != 0);
}

#define FIXTURE_SENDMSG(f) \
    NEED_WS(); \
    if (!fix_open(&(f), 1)) { fix_close(&(f)); t_skip("WSASendMsg extension not offered"); return; }

TEST(l8_sendmsg_invalid_socket)
{
    struct udp_fix f;
    FIXTURE_SENDMSG(f);
    w_WSASetLastError(0);
    L8_EQ(f.sendmsg(INVALID_SOCKET, &f.msg, 0, NULL, NULL, NULL), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAENOTSOCK);
    fix_close(&f);
}

TEST(l8_sendmsg_socket_unbound_until_used)
{
    struct udp_fix f;
    FIXTURE_SENDMSG(f);
    CHECK(tx_is_unbound(f.tx));
    fix_close(&f);
}

TEST(l8_sendmsg_single_buffer_binds_and_delivers)
{
    struct udp_fix f;
    DWORD sent = 0;
    char buf[32];
    struct sockaddr_in from;
    int fl = sizeof from, n;
    FIXTURE_SENDMSG(f);
    SetLastError(0xdeadbeef);
    L8_EQ(f.sendmsg(f.tx, &f.msg, 0, &sent, NULL, NULL), 0);
    L8_EQ(GetLastError(), 0);
    L8_EQ(sent, sizeof f.text);

    memset(buf, 0, sizeof buf);
    n = w_recvfrom(f.rx, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
    L8_EQ(n, (int)sent);
    CHECK(!memcmp(buf, "hello world", 12));
    check_autobound(f.tx);
    fix_close(&f);
}

TEST(l8_sendmsg_two_buffers_gathered)
{
    struct udp_fix f;
    DWORD sent = 0;
    char buf[32];
    int n;
    FIXTURE_SENDMSG(f);
    f.msg.dwBufferCount = 2;
    SetLastError(0xdeadbeef);
    L8_EQ(f.sendmsg(f.tx, &f.msg, 0, &sent, NULL, NULL), 0);
    L8_EQ(GetLastError(), 0);
    L8_EQ(sent, f.iov[0].len + f.iov[1].len);
    memset(buf, 0, sizeof buf);
    n = w_recvfrom(f.rx, buf, sizeof buf, 0, NULL, NULL);
    L8_EQ(n, (int)sent);
    CHECK(!memcmp(buf, "hello world\0hello", 17));
    fix_close(&f);
}

TEST(l8_sendmsg_rejects_stream_socket)
{
    struct udp_fix f;
    SOCKET s;
    DWORD sent = 0;
    FIXTURE_SENDMSG(f);
    s = w_socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s != INVALID_SOCKET);
    w_WSASetLastError(0);
    L8_EQ(f.sendmsg(s, &f.msg, 0, &sent, NULL, NULL), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEINVAL);
    w_closesocket(s);
    fix_close(&f);
}

/* ---- WSASendTo ---- */

TEST(l8_wsasendto_invalid_socket)
{
    struct udp_fix f;
    char b[12] = "hello world";
    WSABUF wb = { sizeof b, b };
    NEED_WS();
    fix_open(&f, 0);
    w_WSASetLastError(12345);
    L8_EQ(w_WSASendTo(INVALID_SOCKET, &wb, 1, NULL, 0, (struct sockaddr *)&f.rx_addr, sizeof f.rx_addr, NULL, NULL), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAENOTSOCK);
    fix_close(&f);
}

TEST(l8_wsasendto_success_clears_error_and_binds)
{
    struct udp_fix f;
    char b[12] = "hello world", rb[32];
    WSABUF wb = { sizeof b, b };
    DWORD sent = 0;
    NEED_WS();
    fix_open(&f, 0);
    w_WSASetLastError(12345);
    L8_EQ(w_WSASendTo(f.tx, &wb, 1, &sent, 0, (struct sockaddr *)&f.rx_addr, sizeof f.rx_addr, NULL, NULL), 0);
    L8_EQ(w_WSAGetLastError(), 0);
    L8_EQ(sent, sizeof b);
    L8_EQ(w_recvfrom(f.rx, rb, sizeof rb, 0, NULL, NULL), (int)sizeof b);
    {
        struct sockaddr_in a;
        int len = sizeof a;
        L8_EQ(w_getsockname(f.tx, (struct sockaddr *)&a, &len), 0);
        L8_EQ(a.sin_family, AF_INET);
        CHECK(a.sin_port != 0);
    }
    fix_close(&f);
}
