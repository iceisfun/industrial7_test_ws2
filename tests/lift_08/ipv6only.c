/* IPV6_V6ONLY socket option behaviour: the default on IPv6 sockets, how it reads on an IPv4 socket,
 * what changes once a socket is bound, and how a dual-stack IPv6 socket interacts with an IPv4 bind
 * (exclusive address use).  Only bind() is used; nothing here listens or sends.
 */
#include "l8.h"

static int v6only_get(SOCKET s, int *val)
{
    int len = sizeof *val;
    *val = 2;   /* sentinel: neither 0 nor 1 */
    return w_getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)val, &len);
}

static int v6only_set(SOCKET s, int val)
{
    return w_setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&val, sizeof val);
}

/* Wildcard IPv6 bind on an ephemeral port; returns the port in network order. */
static u_short bind_v6_any(SOCKET s)
{
    struct sockaddr_in6 a;
    int len = sizeof a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    CHECK(w_bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(w_getsockname(s, (struct sockaddr *)&a, &len) == 0);
    return a.sin6_port;
}

static int bind_v4_any(SOCKET s, u_short port)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = port;
    return w_bind(s, (struct sockaddr *)&a, sizeof a);
}

TEST(l8_v6only_default_enabled_on_v6_socket)
{
    int v;
    SOCKET s;
    NEED_WS();
    if (!l8_v6_available()) { t_skip("IPv6 sockets unavailable"); return; }
    s = w_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    L8_EQ(v6only_get(s, &v), 0);
    L8_EQ(v, 1);
    w_closesocket(s);
}

TEST(l8_v6only_v4_socket_reads_enabled)
{
    int v;
    SOCKET s;
    NEED_WS();
    if (!l8_v6_available()) { t_skip("IPv6 sockets unavailable"); return; }
    /* The option is accepted on an IPv4 socket and reads back as enabled. */
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    L8_EQ(v6only_get(s, &v), 0);
    L8_EQ(v, 1);
    w_closesocket(s);
}

TEST(l8_v6only_v4_socket_clear_reads_back)
{
    int v;
    SOCKET s;
    NEED_WS();
    if (!l8_v6_available()) { t_skip("IPv6 sockets unavailable"); return; }
    s = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    L8_EQ(v6only_set(s, 0), 0);
    L8_EQ(v6only_get(s, &v), 0);
    L8_EQ(v, 0);
    L8_EQ(v6only_set(s, 1), 0);
    L8_EQ(v6only_get(s, &v), 0);
    L8_EQ(v, 1);
    w_closesocket(s);
}

TEST(l8_v6only_v4_bind_beside_v6_wildcard)
{
    SOCKET v6, v4;
    u_short port;
    NEED_WS();
    if (!l8_v6_available()) { t_skip("IPv6 sockets unavailable"); return; }
    v6 = w_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    port = bind_v6_any(v6);
    /* The IPv6 socket is IPv6-only by default, so the same port is free for IPv4. */
    v4 = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    L8_EQ(bind_v4_any(v4, port), 0);
    w_closesocket(v4);
    w_closesocket(v6);
}

TEST(l8_v6only_v4_option_frozen_after_bind)
{
    SOCKET v6, v4;
    u_short port;
    int v;
    NEED_WS();
    if (!l8_v6_available()) { t_skip("IPv6 sockets unavailable"); return; }
    v6 = w_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    port = bind_v6_any(v6);
    v4 = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(v6only_set(v4, 1) == 0);
    L8_EQ(bind_v4_any(v4, port), 0);

    L8_EQ(v6only_get(v4, &v), 0);
    L8_EQ(v, 1);
    /* After bind the option can no longer be changed, in either direction. */
    CHECK(v6only_set(v4, 0) != 0);
    L8_EQ(v6only_get(v4, &v), 0);
    L8_EQ(v, 1);
    CHECK(v6only_set(v4, 1) != 0);
    w_closesocket(v4);
    w_closesocket(v6);
}

TEST(l8_v6only_dualstack_disable_reads_back)
{
    SOCKET s;
    int v;
    NEED_WS();
    if (!l8_v6_available()) { t_skip("IPv6 sockets unavailable"); return; }
    s = w_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    L8_EQ(v6only_set(s, 0), 0);
    L8_EQ(v6only_get(s, &v), 0);
    L8_EQ(v, 0);
    w_closesocket(s);
}

TEST(l8_v6only_dualstack_exclusive_bind_blocks_v4)
{
    SOCKET v6, v4;
    u_short port;
    int v, on = 1;
    NEED_WS();
    if (!l8_v6_available()) { t_skip("IPv6 sockets unavailable"); return; }
    v6 = w_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    CHECK(v6only_set(v6, 0) == 0);
    /* Without exclusive use a second bind would be allowed; with it the wildcard port is closed to IPv4. */
    L8_EQ(w_setsockopt(v6, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&on, sizeof on), 0);
    port = bind_v6_any(v6);

    L8_EQ(v6only_get(v6, &v), 0);
    L8_EQ(v, 0);   /* bind does not flip the option back */

    v4 = w_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    L8_EQ(w_setsockopt(v4, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof on), 0);
    w_WSASetLastError(0);
    L8_EQ(bind_v4_any(v4, port), SOCKET_ERROR);
    L8_EQ(w_WSAGetLastError(), WSAEACCES);
    w_closesocket(v4);
    w_closesocket(v6);
}
