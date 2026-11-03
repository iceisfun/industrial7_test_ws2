/* AF_UNIX stream sockets through the same bind/listen/accept/getsockname/getpeername entry points: the state
 * errors shared with the Internet families, plus the sockaddr_un length protocol of accept and the name
 * calls.  Socket files live in the per-process scratch directory and are removed with it.
 */
#include "bla.h"
#include <afunix.h>

static SOCKET usock(void)
{
    SOCKET s;
    bla_up();
    s = U(socket)(AF_UNIX, SOCK_STREAM, 0);
    return s;
}
#define NEED_UNIX(s) do { s = usock(); if (s == INVALID_SOCKET) { t_skip("AF_UNIX not available"); return; } } while (0)

static int mkaddr(SOCKADDR_UN *a, const char *leaf)
{
    char path[MAX_PATH];
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    t_tmpfile(path, sizeof path, leaf);
    if (strlen(path) >= sizeof a->sun_path) return 0;
    strcpy(a->sun_path, path);
    return 1;
}

static SOCKET ulisten(const char *leaf, SOCKADDR_UN *a)
{
    SOCKET s = usock();
    if (s == INVALID_SOCKET) return s;
    if (!mkaddr(a, leaf) || bnd(s, a, sizeof *a) != 0 || lsn(s, 1) != 0) { cls(s); return INVALID_SOCKET; }
    return s;
}

TEST(bla_unix_unbound_listen_is_einval)
{
    SOCKET s;
    NEED_UNIX(s);
    FAILS(lsn(s, 1), WSAEINVAL);
    cls(s);
}

TEST(bla_unix_unbound_name_is_einval)
{
    SOCKADDR_UN a;
    int n = sizeof a;
    SOCKET s;
    NEED_UNIX(s);
    FAILS(gsn(s, &a, &n), WSAEINVAL);
    cls(s);
}

TEST(bla_unix_unconnected_peer_is_notconn)
{
    SOCKADDR_UN a;
    int n = sizeof a;
    SOCKET s;
    NEED_UNIX(s);
    FAILS(gpn(s, &a, &n), WSAENOTCONN);
    cls(s);
}

TEST(bla_unix_unbound_accept_is_einval)
{
    SOCKET s;
    NEED_UNIX(s);
    FAILS(acc(s, NULL, NULL), WSAEINVAL);
    cls(s);
}

TEST(bla_unix_closed_socket_is_notsock)
{
    SOCKADDR_UN a;
    SOCKET s;
    int n = sizeof a;
    NEED_UNIX(s);
    EQ(cls(s), 0);
    CHECK(mkaddr(&a, "bla_closed.sock"));
    FAILS(bnd(s, &a, sizeof a), WSAENOTSOCK);
    FAILS(lsn(s, 1), WSAENOTSOCK);
    FAILS(acc(s, NULL, NULL), WSAENOTSOCK);
    FAILS(gsn(s, &a, &n), WSAENOTSOCK);
    FAILS(gpn(s, &a, &n), WSAENOTSOCK);
}

TEST(bla_unix_second_bind_is_einval)
{
    SOCKADDR_UN a, b;
    SOCKET s;
    NEED_UNIX(s);
    CHECK(mkaddr(&a, "bla_two.sock"));
    CHECK(mkaddr(&b, "bla_two_b.sock"));
    EQ(bnd(s, &a, sizeof a), 0);
    FAILS(bnd(s, &a, sizeof a), WSAEINVAL);
    FAILS(bnd(s, &b, sizeof b), WSAEINVAL);
    cls(s);
}

TEST(bla_unix_name_after_bind_has_family_and_path)
{
    SOCKADDR_UN a, got;
    int n = sizeof got;
    SOCKET s;
    NEED_UNIX(s);
    CHECK(mkaddr(&a, "bla_name.sock"));
    EQ(bnd(s, &a, sizeof a), 0);
    memset(&got, 0x5a, sizeof got);
    EQ(gsn(s, &got, &n), 0);
    EQ(got.sun_family, AF_UNIX);
    CHECK(n >= (int)sizeof(ADDRESS_FAMILY) + 1 && n <= (int)sizeof got);
    t_note("bound AF_UNIX path %s the bound spelling", strncmp(got.sun_path, a.sun_path, strlen(a.sun_path)) == 0 ? "matches" : "differs from");
    cls(s);
}

TEST(bla_unix_short_name_buffer_is_efault)
{
    SOCKADDR_UN a, got;
    int n;
    SOCKET s;
    NEED_UNIX(s);
    CHECK(mkaddr(&a, "bla_short.sock"));
    EQ(bnd(s, &a, sizeof a), 0);
    n = 2;
    memset(&got, 0x5a, sizeof got);
    wset(0x5a5a);
    CHECK(gsn(s, &got, &n) == SOCKET_ERROR);
    t_note("getsockname with a 2-byte buffer on AF_UNIX -> %s", werr_class(werr()));
    cls(s);
}

TEST(bla_unix_accept_and_peer_names)
{
    SOCKADDR_UN a, from, peer;
    SOCKET l, c, s;
    int n = sizeof from, m = sizeof peer;
    NEED_UNIX(c);
    l = ulisten("bla_acc.sock", &a);
    CHECK(l != INVALID_SOCKET);
    if (l == INVALID_SOCKET) { cls(c); return; }
    EQ(con(c, &a, sizeof a), 0);
    memset(&from, 0x5a, sizeof from);
    s = acc_wait(l, &from, &n, 3000);
    CHECK(s != INVALID_SOCKET);
    EQ(from.sun_family, AF_UNIX);
    CHECK(n >= (int)sizeof(ADDRESS_FAMILY) && n <= (int)sizeof from);
    if (s != INVALID_SOCKET) {
        EQ(gpn(c, &peer, &m), 0);
        EQ(peer.sun_family, AF_UNIX);
        t_note("AF_UNIX peer path %s the listener's spelling", strncmp(peer.sun_path, a.sun_path, strlen(a.sun_path)) == 0 ? "matches" : "differs from");
        cls(s);
    }
    cls(c); cls(l);
}

TEST(bla_unix_accept_zero_length_is_efault)
{
    SOCKADDR_UN a, from;
    SOCKET l, c, s;
    int n = 0;
    NEED_UNIX(c);
    l = ulisten("bla_acc0.sock", &a);
    CHECK(l != INVALID_SOCKET);
    if (l == INVALID_SOCKET) { cls(c); return; }
    EQ(con(c, &a, sizeof a), 0);
    CHECK(readable(l, 3000));
    FAILS(acc(l, &from, &n), WSAEFAULT);
    EQ(n, 0);
    n = sizeof from;
    s = readable(l, 3000) ? acc(l, &from, &n) : INVALID_SOCKET;
    CHECK(s != INVALID_SOCKET);                          /* the refused call left the connection queued */
    if (s != INVALID_SOCKET) cls(s);
    cls(c); cls(l);
}

TEST(bla_unix_listen_twice_and_acceptconn)
{
    SOCKADDR_UN a;
    DWORD v = 0xdead;
    int n = sizeof v;
    SOCKET l = ulisten("bla_lt.sock", &a);
    if (l == INVALID_SOCKET) { t_skip("AF_UNIX listener unavailable"); return; }
    EQ(lsn(l, SOMAXCONN), 0);
    EQ(gso(l, SOL_SOCKET, SO_ACCEPTCONN, &v, &n), 0);
    EQ(v, 1);
    cls(l);
}

TEST(bla_unix_connected_listen_is_eisconn)
{
    SOCKADDR_UN a;
    SOCKET l, c;
    NEED_UNIX(c);
    l = ulisten("bla_lc.sock", &a);
    if (l == INVALID_SOCKET) { cls(c); t_skip("AF_UNIX listener unavailable"); return; }
    EQ(con(c, &a, sizeof a), 0);
    FAILS(lsn(c, 1), WSAEISCONN);
    cls(c); cls(l);
}

TEST(bla_unix_nonblocking_accept_wouldblock)
{
    SOCKADDR_UN a;
    SOCKET l = ulisten("bla_nb.sock", &a);
    if (l == INVALID_SOCKET) { t_skip("AF_UNIX listener unavailable"); return; }
    EQ(nbio(l, 1), 0);
    FAILS(acc(l, NULL, NULL), WSAEWOULDBLOCK);
    cls(l);
}
