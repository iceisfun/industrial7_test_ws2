/* AF_UNIX stream sockets: data integrity and multi-socket behaviour. Bulk transfers in both directions with a
 * pattern check, several independent listeners at once, accepted-socket properties, and a sender/receiver
 * pair running on separate threads. All waits are bounded. */
#include "au.h"

static unsigned char pat(unsigned long i) { return (unsigned char)((i * 131u + (i >> 8)) & 0xff); }

struct pump { SOCKET s; unsigned long total; int err; };

static DWORD WINAPI pump_send(LPVOID p)
{
    struct pump *pp = p;
    unsigned char buf[4096];
    unsigned long sent = 0;
    while (sent < pp->total) {
        unsigned long n = pp->total - sent, i;
        int r;
        if (n > sizeof buf) n = sizeof buf;
        for (i = 0; i < n; i++) buf[i] = pat(sent + i);
        r = U(send)(pp->s, (char *)buf, (int)n, 0);
        if (r <= 0) { pp->err = au_err(); return 1; }
        /* a blocking stream send takes the whole buffer; a short count is treated as a failure */
        if ((unsigned long)r != n) { pp->err = -1; return 1; }
        sent += n;
    }
    U(shutdown)(pp->s, SD_SEND);
    return 0;
}

static void bulk(unsigned long total, int reverse)
{
    TRIO(t, "bulk.sock");
    struct pump pp;
    HANDLE th;
    unsigned char buf[8192];
    unsigned long got = 0, bad = 0, i;
    int r;
    pp.s = reverse ? t.srv : t.cli; pp.total = total; pp.err = 0;
    th = CreateThread(NULL, 0, pump_send, &pp, 0, NULL);
    CHECK(th != NULL);
    if (!th) { au_trio_close(&t); return; }
    for (;;) {
        r = U(recv)(reverse ? t.cli : t.srv, (char *)buf, sizeof buf, 0);
        if (r <= 0) break;
        for (i = 0; i < (unsigned long)r; i++) if (buf[i] != pat(got + i)) bad++;
        got += (unsigned long)r;
    }
    AU_EQ(r, 0);
    AU_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
    CloseHandle(th);
    AU_EQ(got, total);
    AU_EQ(bad, 0);
    AU_EQ(pp.err, 0);
    au_trio_close(&t);
}

TEST(afu_bulk_client_to_server_64k) { UP(); bulk(64 * 1024, 0); }
TEST(afu_bulk_server_to_client_64k) { UP(); bulk(64 * 1024, 1); }
TEST(afu_bulk_client_to_server_1m) { UP(); bulk(1024 * 1024, 0); }
TEST(afu_bulk_odd_size) { UP(); bulk(100003, 0); }

TEST(afu_bulk_full_duplex_pattern)
{
    TRIO(t, "duplex.sock");
    struct pump pp;
    HANDLE th;
    unsigned char buf[4096];
    unsigned long got = 0, bad = 0, i;
    int r;
    /* client floods the server on a thread while the server echoes a small marker stream back */
    pp.s = t.cli; pp.total = 32768; pp.err = 0;
    th = CreateThread(NULL, 0, pump_send, &pp, 0, NULL);
    CHECK(th != NULL);
    if (!th) { au_trio_close(&t); return; }
    AU_EQ(au_send_all(t.srv, "ping", 4), 4);
    for (;;) {
        r = U(recv)(t.srv, (char *)buf, sizeof buf, 0);
        if (r <= 0) break;
        for (i = 0; i < (unsigned long)r; i++) if (buf[i] != pat(got + i)) bad++;
        got += (unsigned long)r;
    }
    AU_EQ(WaitForSingleObject(th, 5000), WAIT_OBJECT_0);
    CloseHandle(th);
    AU_EQ(got, 32768);
    AU_EQ(bad, 0);
    memset(buf, 0, 8);
    AU_EQ(au_recv_n(t.cli, (char *)buf, 4), 4);
    CHECK(!memcmp(buf, "ping", 4));
    au_trio_close(&t);
}

TEST(afu_multi_listeners_independent)
{
    SOCKET l[3], c[3], a[3];
    SOCKADDR_UN ad[3];
    int i;
    char b[2];
    UP();
    for (i = 0; i < 3; i++) l[i] = c[i] = a[i] = INVALID_SOCKET;
    l[0] = au_sock();
    if (l[0] == INVALID_SOCKET) return;
    for (i = 1; i < 3; i++) l[i] = au_sock();
    for (i = 0; i < 3; i++) {
        char leaf[32];
        snprintf(leaf, sizeof leaf, "multi_%d.sock", i);
        au_addr_leaf(&ad[i], leaf);
        AU_EQ(au_bind_to(l[i], &ad[i]), 0);
        AU_EQ(U(listen)(l[i], 2), 0);
    }
    for (i = 2; i >= 0; i--) {
        c[i] = au_sock();
        a[i] = au_connect_accept(l[i], c[i], &ad[i]);
        b[0] = (char)('A' + i);
        AU_EQ(au_send_all(c[i], b, 1), 1);
    }
    for (i = 0; i < 3; i++) {
        b[0] = 0;
        au_rcvtimeo(a[i], 3000);
        AU_EQ(au_recv_n(a[i], b, 1), 1);
        AU_EQ(b[0], 'A' + i);
    }
    for (i = 0; i < 3; i++) {
        char leaf[32];
        if (a[i] != INVALID_SOCKET) U(closesocket)(a[i]);
        if (c[i] != INVALID_SOCKET) U(closesocket)(c[i]);
        U(closesocket)(l[i]);
        snprintf(leaf, sizeof leaf, "multi_%d.sock", i);
        au_unlink_leaf(leaf);
    }
}

TEST(afu_accepted_so_type_is_stream)
{
    int v = 0, n = sizeof v;
    TRIO(t, "acc_type.sock");
    AU_EQ(U(getsockopt)(t.srv, SOL_SOCKET, SO_TYPE, (char *)&v, &n), 0);
    AU_EQ(v, SOCK_STREAM);
    au_trio_close(&t);
}

TEST(afu_accepted_is_not_listening)
{
    int v = AU_POISON, n = sizeof v;
    TRIO(t, "acc_lis.sock");
    AU_EQ(U(getsockopt)(t.srv, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &n), 0);
    AU_EQ(v, 0);
    AU_EQ(U(getsockopt)(t.lis, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &n), 0);
    CHECK(v != 0);
    au_trio_close(&t);
}

TEST(afu_accepted_listen_is_refused)
{
    TRIO(t, "acc_listen.sock");
    au_seterr(0);
    AU_EQ(U(listen)(t.srv, 1), SOCKET_ERROR);
    AU_EQ(au_err(), WSAEISCONN);
    au_trio_close(&t);
}

TEST(afu_accepted_accept_is_inval)
{
    TRIO(t, "acc_acc.sock");
    au_seterr(0);
    AU_EQ(U(accept)(t.srv, NULL, NULL), INVALID_SOCKET);
    AU_EQ(au_err(), WSAEINVAL);
    au_trio_close(&t);
}

TEST(afu_reconnect_same_path_after_rebind_cycle)
{
    int k;
    UP();
    for (k = 0; k < 3; k++) {
        TRIO(t, "cycle.sock");
        AU_EQ(au_send_all(t.cli, "x", 1), 1);
        au_trio_close(&t);
        CHECK(GetFileAttributesA(au_path("cycle.sock")) == INVALID_FILE_ATTRIBUTES);
    }
}

TEST(afu_backlog_overflow_does_not_hang)
{
    SOCKET l, c[8];
    SOCKADDR_UN a;
    int i, ok = 0;
    UP();
    l = au_sock();
    if (l == INVALID_SOCKET) return;
    au_addr_leaf(&a, "overflow.sock");
    AU_EQ(au_bind_to(l, &a), 0);
    AU_EQ(U(listen)(l, 1), 0);
    /* non-blocking connects never block; whatever the stack does with the surplus, the calls return */
    for (i = 0; i < 8; i++) {
        c[i] = au_sock();
        au_blocking(c[i], FALSE);
        if (U(connect)(c[i], (struct sockaddr *)&a, sizeof a) == 0 || au_err() == WSAEWOULDBLOCK) ok++;
    }
    CHECK(ok >= 1);
    for (i = 0; i < 8; i++) U(closesocket)(c[i]);
    U(closesocket)(l);
    au_unlink_leaf("overflow.sock");
}
