/* Bind matrix: for every socket flavour (IPv4, IPv6 dual-stack, IPv6 V6ONLY, IPv6 as created) and every address
 * kind (wildcards, loopbacks, v4-mapped, link-local with and without scope, scoped loopback, documentation
 * prefix) the exact result of bind() and the name getsockname() then reports; TCP and UDP; plus address length
 * and family-versus-length rules.  Ports are ephemeral; nothing is sent. */
#include "sm.h"

struct brow { int sk, ak, err; const char *name; };
static const struct brow B_tcp[] = {
    { SK_V4, AK_V4ANY, 0, "v4:any:len16" },
    { SK_V4, AK_V4LOOP, 0, "v4:loop:len16" },
    { SK_V4, AK_V6ANY, 10047, "" },
    { SK_V4, AK_V6LOOP, 10047, "" },
    { SK_V4, AK_MAPANY, 10047, "" },
    { SK_V4, AK_MAPLOOP, 10047, "" },
    { SK_V4, AK_LL, 10047, "" },
    { SK_V4, AK_LL_SCOPE, 10047, "" },
    { SK_V4, AK_LL_BADSCOPE, 10047, "" },
    { SK_V4, AK_V6LOOP_SCOPE, 10047, "" },
    { SK_V4, AK_V6LOOP_BADSCOPE, 10047, "" },
    { SK_V4, AK_V6ANY_SCOPE, 10047, "" },
    { SK_V4, AK_DOC, 10047, "" },
    { SK_V6D, AK_V4ANY, 10014, "" },
    { SK_V6D, AK_V4LOOP, 10014, "" },
    { SK_V6D, AK_V6ANY, 0, "v6:any:scope0:len28" },
    { SK_V6D, AK_V6LOOP, 0, "v6:loop:scope0:len28" },
    { SK_V6D, AK_MAPANY, 0, "v6:map:any:scope0:len28" },
    { SK_V6D, AK_MAPLOOP, 0, "v6:map:loop:scope0:len28" },
    { SK_V6D, AK_LL, 10049, "" },
    { SK_V6D, AK_LL_SCOPE, 10049, "" },
    { SK_V6D, AK_LL_BADSCOPE, 10049, "" },
    { SK_V6D, AK_V6LOOP_SCOPE, 10049, "" },
    { SK_V6D, AK_V6LOOP_BADSCOPE, 10049, "" },
    { SK_V6D, AK_V6ANY_SCOPE, 10049, "" },
    { SK_V6D, AK_DOC, 10049, "" },
    { SK_V6O, AK_V4ANY, 10014, "" },
    { SK_V6O, AK_V4LOOP, 10014, "" },
    { SK_V6O, AK_V6ANY, 0, "v6:any:scope0:len28" },
    { SK_V6O, AK_V6LOOP, 0, "v6:loop:scope0:len28" },
    { SK_V6O, AK_MAPANY, 10049, "" },
    { SK_V6O, AK_MAPLOOP, 10049, "" },
    { SK_V6O, AK_LL, 10049, "" },
    { SK_V6O, AK_LL_SCOPE, 10049, "" },
    { SK_V6O, AK_LL_BADSCOPE, 10049, "" },
    { SK_V6O, AK_V6LOOP_SCOPE, 10049, "" },
    { SK_V6O, AK_V6LOOP_BADSCOPE, 10049, "" },
    { SK_V6O, AK_V6ANY_SCOPE, 10049, "" },
    { SK_V6O, AK_DOC, 10049, "" },
    { SK_V6DEF, AK_V4ANY, 10014, "" },
    { SK_V6DEF, AK_V4LOOP, 10014, "" },
    { SK_V6DEF, AK_V6ANY, 0, "v6:any:scope0:len28" },
    { SK_V6DEF, AK_V6LOOP, 0, "v6:loop:scope0:len28" },
    { SK_V6DEF, AK_MAPANY, 10049, "" },
    { SK_V6DEF, AK_MAPLOOP, 10049, "" },
    { SK_V6DEF, AK_LL, 10049, "" },
    { SK_V6DEF, AK_LL_SCOPE, 10049, "" },
    { SK_V6DEF, AK_LL_BADSCOPE, 10049, "" },
    { SK_V6DEF, AK_V6LOOP_SCOPE, 10049, "" },
    { SK_V6DEF, AK_V6LOOP_BADSCOPE, 10049, "" },
    { SK_V6DEF, AK_V6ANY_SCOPE, 10049, "" },
    { SK_V6DEF, AK_DOC, 10049, "" },
};
static const struct brow B_udp[] = {
    { SK_V4, AK_V4ANY, 0, "v4:any:len16" },
    { SK_V4, AK_V4LOOP, 0, "v4:loop:len16" },
    { SK_V4, AK_V6ANY, 10047, "" },
    { SK_V4, AK_V6LOOP, 10047, "" },
    { SK_V4, AK_MAPANY, 10047, "" },
    { SK_V4, AK_MAPLOOP, 10047, "" },
    { SK_V4, AK_LL, 10047, "" },
    { SK_V4, AK_LL_SCOPE, 10047, "" },
    { SK_V4, AK_LL_BADSCOPE, 10047, "" },
    { SK_V4, AK_V6LOOP_SCOPE, 10047, "" },
    { SK_V4, AK_V6LOOP_BADSCOPE, 10047, "" },
    { SK_V4, AK_V6ANY_SCOPE, 10047, "" },
    { SK_V4, AK_DOC, 10047, "" },
    { SK_V6D, AK_V4ANY, 10014, "" },
    { SK_V6D, AK_V4LOOP, 10014, "" },
    { SK_V6D, AK_V6ANY, 0, "v6:any:scope0:len28" },
    { SK_V6D, AK_V6LOOP, 0, "v6:loop:scope0:len28" },
    { SK_V6D, AK_MAPANY, 0, "v6:map:any:scope0:len28" },
    { SK_V6D, AK_MAPLOOP, 0, "v6:map:loop:scope0:len28" },
    { SK_V6D, AK_LL, 10049, "" },
    { SK_V6D, AK_LL_SCOPE, 10049, "" },
    { SK_V6D, AK_LL_BADSCOPE, 10049, "" },
    { SK_V6D, AK_V6LOOP_SCOPE, 10049, "" },
    { SK_V6D, AK_V6LOOP_BADSCOPE, 10049, "" },
    { SK_V6D, AK_V6ANY_SCOPE, 10049, "" },
    { SK_V6D, AK_DOC, 10049, "" },
    { SK_V6O, AK_V4ANY, 10014, "" },
    { SK_V6O, AK_V4LOOP, 10014, "" },
    { SK_V6O, AK_V6ANY, 0, "v6:any:scope0:len28" },
    { SK_V6O, AK_V6LOOP, 0, "v6:loop:scope0:len28" },
    { SK_V6O, AK_MAPANY, 10049, "" },
    { SK_V6O, AK_MAPLOOP, 10049, "" },
    { SK_V6O, AK_LL, 10049, "" },
    { SK_V6O, AK_LL_SCOPE, 10049, "" },
    { SK_V6O, AK_LL_BADSCOPE, 10049, "" },
    { SK_V6O, AK_V6LOOP_SCOPE, 10049, "" },
    { SK_V6O, AK_V6LOOP_BADSCOPE, 10049, "" },
    { SK_V6O, AK_V6ANY_SCOPE, 10049, "" },
    { SK_V6O, AK_DOC, 10049, "" },
    { SK_V6DEF, AK_V4ANY, 10014, "" },
    { SK_V6DEF, AK_V4LOOP, 10014, "" },
    { SK_V6DEF, AK_V6ANY, 0, "v6:any:scope0:len28" },
    { SK_V6DEF, AK_V6LOOP, 0, "v6:loop:scope0:len28" },
    { SK_V6DEF, AK_MAPANY, 10049, "" },
    { SK_V6DEF, AK_MAPLOOP, 10049, "" },
    { SK_V6DEF, AK_LL, 10049, "" },
    { SK_V6DEF, AK_LL_SCOPE, 10049, "" },
    { SK_V6DEF, AK_LL_BADSCOPE, 10049, "" },
    { SK_V6DEF, AK_V6LOOP_SCOPE, 10049, "" },
    { SK_V6DEF, AK_V6LOOP_BADSCOPE, 10049, "" },
    { SK_V6DEF, AK_V6ANY_SCOPE, 10049, "" },
    { SK_V6DEF, AK_DOC, 10049, "" },
};

static void run_bind(const struct brow *t, int n, int sk, int ty) {
    if (!s_up()) return;
    for (int i = 0; i < n; i++) {
        char a[32], d[64] = ""; int len, rc, e = 0; SOCKET s;
        if (t[i].sk != sk) continue;
        s = s_mk(sk, ty);
        if (s == INVALID_SOCKET) { t_skip("socket kind unavailable"); return; }
        len = s_mkaddr(a, t[i].ak, 0);
        rc = U(bind)(s, (struct sockaddr *)a, len);
        if (rc) e = s_err();
        CHECKF((rc == 0) == (t[i].err == 0), "kind %s addr %s rc=%d err=%d", SK_NAME[sk], AK_NAME[t[i].ak], rc, e);
        if (t[i].err) CHECKF(e == t[i].err, "kind %s addr %s err got %d want %d", SK_NAME[sk], AK_NAME[t[i].ak], e, t[i].err);
        else {
            struct sockaddr_in6 n6; int nl = sizeof n6;
            CHECK(U(getsockname)(s, (struct sockaddr *)&n6, &nl) == 0);
            s_desc(&n6, nl, d, sizeof d);
            CHECKF(!strcmp(d, t[i].name), "kind %s addr %s name got %s want %s", SK_NAME[sk], AK_NAME[t[i].ak], d, t[i].name);
            CHECK(n6.sin6_port != 0);
        }
        s_close(s);
    }
}
#define NB(t) ((int)(sizeof(t) / sizeof((t)[0])))
TEST(dsm_bind_tcp_v4_socket)        { run_bind(B_tcp, NB(B_tcp), SK_V4, SOCK_STREAM); }
TEST(dsm_bind_tcp_v6_dual_socket)   { run_bind(B_tcp, NB(B_tcp), SK_V6D, SOCK_STREAM); }
TEST(dsm_bind_tcp_v6_only_socket)   { run_bind(B_tcp, NB(B_tcp), SK_V6O, SOCK_STREAM); }
TEST(dsm_bind_tcp_v6_default_socket){ run_bind(B_tcp, NB(B_tcp), SK_V6DEF, SOCK_STREAM); }
TEST(dsm_bind_udp_v4_socket)        { run_bind(B_udp, NB(B_udp), SK_V4, SOCK_DGRAM); }
TEST(dsm_bind_udp_v6_dual_socket)   { run_bind(B_udp, NB(B_udp), SK_V6D, SOCK_DGRAM); }
TEST(dsm_bind_udp_v6_only_socket)   { run_bind(B_udp, NB(B_udp), SK_V6O, SOCK_DGRAM); }
TEST(dsm_bind_udp_v6_default_socket){ run_bind(B_udp, NB(B_udp), SK_V6DEF, SOCK_DGRAM); }

/* name-length rules: a v4 socket needs at least 16 bytes, an IPv6 socket at least 28; longer is accepted */
static void run_len(int sk, int ty, int family_ok_min) {
    static const int lens[] = { 0, 1, 8, 15, 16, 20, 24, 27, 28, 29, 32, 128 };
    if (!s_up()) return;
    for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
        char a[160]; SOCKET s = s_mk(sk, ty); int rc, e = 0;
        memset(a, 0, sizeof a); s_mkaddr(a, sk == SK_V4 ? AK_V4LOOP : AK_V6LOOP, 0);
        rc = U(bind)(s, (struct sockaddr *)a, lens[i]);
        if (rc) e = s_err();
        if (lens[i] >= family_ok_min) CHECKF(rc == 0, "len %d rc=%d err=%d", lens[i], rc, e);
        else { CHECKF(rc != 0, "len %d unexpectedly bound", lens[i]); CHECKF(e == WSAEFAULT, "len %d err %d", lens[i], e); }
        s_close(s);
    }
}
TEST(dsm_bindlen_tcp_v4)      { run_len(SK_V4, SOCK_STREAM, 16); }
TEST(dsm_bindlen_udp_v4)      { run_len(SK_V4, SOCK_DGRAM, 16); }
TEST(dsm_bindlen_tcp_v6_dual) { run_len(SK_V6D, SOCK_STREAM, 28); }
TEST(dsm_bindlen_tcp_v6_only) { run_len(SK_V6O, SOCK_STREAM, 28); }
TEST(dsm_bindlen_udp_v6_dual) { run_len(SK_V6D, SOCK_DGRAM, 28); }
TEST(dsm_bindlen_udp_v6_only) { run_len(SK_V6O, SOCK_DGRAM, 28); }
TEST(dsm_bindlen_tcp_v6_default) { run_len(SK_V6DEF, SOCK_STREAM, 28); }
TEST(dsm_bindlen_udp_v6_default) { run_len(SK_V6DEF, SOCK_DGRAM, 28); }

/* the address family is judged before the length: a v6 name on a v4 socket is WSAEAFNOSUPPORT even when it is
 * only 16 bytes long, an IPv4 name handed to an IPv6 socket with a full 28 bytes is WSAEAFNOSUPPORT too,
 * and an IPv6 name cut to 16 bytes on an IPv6 socket is WSAEFAULT */
static void run_mislen(int sk, int ty) {
    char a[32]; SOCKET s; int rc;
    if (!s_up()) return;
    s = s_mk(sk, ty); s_mkaddr(a, AK_V6LOOP, 0);
    rc = U(bind)(s, (struct sockaddr *)a, SA4LEN);
    if (sk == SK_V4) { CHECK(rc != 0); CHECK(s_err() == WSAEAFNOSUPPORT); }
    else { CHECK(rc != 0); CHECK(s_err() == WSAEFAULT); }
    s_close(s);
    s = s_mk(sk, ty); s_mkaddr(a, AK_V4LOOP, 0);
    rc = U(bind)(s, (struct sockaddr *)a, SA6LEN);
    if (sk == SK_V4) CHECK(rc == 0);
    else { CHECK(rc != 0); CHECK(s_err() == WSAEAFNOSUPPORT); }
    s_close(s);
}
TEST(dsm_bind_mislen_tcp_v4)  { run_mislen(SK_V4, SOCK_STREAM); }
TEST(dsm_bind_mislen_udp_v4)  { run_mislen(SK_V4, SOCK_DGRAM); }
TEST(dsm_bind_mislen_tcp_v6_dual) { run_mislen(SK_V6D, SOCK_STREAM); }
TEST(dsm_bind_mislen_tcp_v6_only) { run_mislen(SK_V6O, SOCK_STREAM); }
TEST(dsm_bind_mislen_udp_v6_dual) { run_mislen(SK_V6D, SOCK_DGRAM); }
