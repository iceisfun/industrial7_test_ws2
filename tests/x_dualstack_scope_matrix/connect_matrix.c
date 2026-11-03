/* Connect/accept matrix: listeners of every flavour (IPv4 wildcard/loopback, IPv6 dual-stack and V6ONLY wildcard,
 * dual-stack loopback, dual-stack bound to the v4-mapped wildcard/loopback) against clients of every flavour
 * (IPv4, dual-stack, V6ONLY, default IPv6) aiming at IPv4 loopback, IPv6 loopback, v4-mapped loopback, wildcards
 * and scoped loopback names.  Each row records the exact connect result (0 or the WSA error), the family/class
 * of the address accept() and getpeername()/getsockname() report on the accepted socket, the same on the
 * client, and the V6ONLY value the accepted socket carries.  Loopback only, ephemeral ports. */
#include "sm.h"

struct crow { int lsk, lak, csk, cak, err; const char *acc, *peer, *lname, *cname, *cpeer; int accv6o; };
static const struct crow C[] = {
    { SK_V4, AK_V4ANY, SK_V4, AK_V4LOOP, 0, "v4:loop:len16", "v4:loop:len16", "v4:loop:len16", "v4:loop:len16", "v4:loop:len16", 1 },
    { SK_V4, AK_V4ANY, SK_V4, AK_V4ANY, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4ANY, SK_V6D, AK_V6LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V4, AK_V4ANY, SK_V6O, AK_V6LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V4, AK_V4ANY, SK_V6DEF, AK_V6LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V4, AK_V4ANY, SK_V6D, AK_MAPLOOP, 0, "v4:loop:len16", "v4:loop:len16", "v4:loop:len16", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", 1 },
    { SK_V4, AK_V4ANY, SK_V6O, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4ANY, SK_V6DEF, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4ANY, SK_V6D, AK_V6ANY, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4ANY, SK_V6D, AK_MAPANY, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4ANY, SK_V6D, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4ANY, SK_V6D, AK_V6LOOP_BADSCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4ANY, SK_V6O, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4ANY, SK_V6D, AK_V6ANY_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4LOOP, SK_V4, AK_V4LOOP, 0, "v4:loop:len16", "v4:loop:len16", "v4:loop:len16", "v4:loop:len16", "v4:loop:len16", 1 },
    { SK_V4, AK_V4LOOP, SK_V4, AK_V4ANY, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_V6LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V4, AK_V4LOOP, SK_V6O, AK_V6LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V4, AK_V4LOOP, SK_V6DEF, AK_V6LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_MAPLOOP, 0, "v4:loop:len16", "v4:loop:len16", "v4:loop:len16", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", 1 },
    { SK_V4, AK_V4LOOP, SK_V6O, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4LOOP, SK_V6DEF, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_V6ANY, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_MAPANY, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_V6LOOP_BADSCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4LOOP, SK_V6O, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_V6ANY_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6ANY, SK_V4, AK_V4LOOP, 0, "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v4:loop:len16", "v4:loop:len16", 0 },
    { SK_V6D, AK_V6ANY, SK_V4, AK_V4ANY, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", 0 },
    { SK_V6D, AK_V6ANY, SK_V6O, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", 0 },
    { SK_V6D, AK_V6ANY, SK_V6DEF, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", 0 },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_MAPLOOP, 0, "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", 0 },
    { SK_V6D, AK_V6ANY, SK_V6O, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6ANY, SK_V6DEF, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_V6ANY, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_MAPANY, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_V6LOOP_BADSCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6ANY, SK_V6O, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_V6ANY_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6O, AK_V6ANY, SK_V4, AK_V4LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V6O, AK_V6ANY, SK_V4, AK_V4ANY, 10049, "", "", "", "", "", -1 },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", 1 },
    { SK_V6O, AK_V6ANY, SK_V6O, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", 1 },
    { SK_V6O, AK_V6ANY, SK_V6DEF, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", 1 },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_MAPLOOP, 10061, "", "", "", "", "", -1 },
    { SK_V6O, AK_V6ANY, SK_V6O, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V6O, AK_V6ANY, SK_V6DEF, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_V6ANY, 10049, "", "", "", "", "", -1 },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_MAPANY, 10049, "", "", "", "", "", -1 },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_V6LOOP_BADSCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6O, AK_V6ANY, SK_V6O, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_V6ANY_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6LOOP, SK_V4, AK_V4LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6LOOP, SK_V4, AK_V4ANY, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", 0 },
    { SK_V6D, AK_V6LOOP, SK_V6O, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", 0 },
    { SK_V6D, AK_V6LOOP, SK_V6DEF, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", 0 },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_MAPLOOP, 10061, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6LOOP, SK_V6O, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6LOOP, SK_V6DEF, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_V6ANY, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_MAPANY, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_V6LOOP_BADSCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6LOOP, SK_V6O, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_V6ANY_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPANY, SK_V4, AK_V4LOOP, 0, "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v4:loop:len16", "v4:loop:len16", 0 },
    { SK_V6D, AK_MAPANY, SK_V4, AK_V4ANY, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPANY, SK_V6D, AK_V6LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPANY, SK_V6O, AK_V6LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPANY, SK_V6DEF, AK_V6LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPANY, SK_V6D, AK_MAPLOOP, 0, "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", 0 },
    { SK_V6D, AK_MAPANY, SK_V6O, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPANY, SK_V6DEF, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPANY, SK_V6D, AK_V6ANY, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPANY, SK_V6D, AK_MAPANY, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPANY, SK_V6D, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPANY, SK_V6D, AK_V6LOOP_BADSCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPANY, SK_V6O, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPANY, SK_V6D, AK_V6ANY_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPLOOP, SK_V4, AK_V4LOOP, 0, "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v4:loop:len16", "v4:loop:len16", 0 },
    { SK_V6D, AK_MAPLOOP, SK_V4, AK_V4ANY, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_V6LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPLOOP, SK_V6O, AK_V6LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPLOOP, SK_V6DEF, AK_V6LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_MAPLOOP, 0, "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", "v6:map:loop:scope0:len28", 0 },
    { SK_V6D, AK_MAPLOOP, SK_V6O, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPLOOP, SK_V6DEF, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_V6ANY, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_MAPANY, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_V6LOOP_BADSCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPLOOP, SK_V6O, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_V6ANY_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6DEF, AK_V6ANY, SK_V4, AK_V4LOOP, 10061, "", "", "", "", "", -1 },
    { SK_V6DEF, AK_V6ANY, SK_V4, AK_V4ANY, 10049, "", "", "", "", "", -1 },
    { SK_V6DEF, AK_V6ANY, SK_V6D, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", 1 },
    { SK_V6DEF, AK_V6ANY, SK_V6O, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", 1 },
    { SK_V6DEF, AK_V6ANY, SK_V6DEF, AK_V6LOOP, 0, "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", "v6:loop:scope0:len28", 1 },
    { SK_V6DEF, AK_V6ANY, SK_V6D, AK_MAPLOOP, 10061, "", "", "", "", "", -1 },
    { SK_V6DEF, AK_V6ANY, SK_V6O, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V6DEF, AK_V6ANY, SK_V6DEF, AK_MAPLOOP, 10049, "", "", "", "", "", -1 },
    { SK_V6DEF, AK_V6ANY, SK_V6D, AK_V6ANY, 10049, "", "", "", "", "", -1 },
    { SK_V6DEF, AK_V6ANY, SK_V6D, AK_MAPANY, 10049, "", "", "", "", "", -1 },
    { SK_V6DEF, AK_V6ANY, SK_V6D, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6DEF, AK_V6ANY, SK_V6D, AK_V6LOOP_BADSCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6DEF, AK_V6ANY, SK_V6O, AK_V6LOOP_SCOPE, 10049, "", "", "", "", "", -1 },
    { SK_V6DEF, AK_V6ANY, SK_V6D, AK_V6ANY_SCOPE, 10049, "", "", "", "", "", -1 },
};

static void check_one(const struct crow *r, SOCKET ls, unsigned short port) {
    SOCKET cs = s_mk(r->csk, SOCK_STREAM); char t[32], d[64]; int tl = s_mkaddr(t, r->cak, port), e;
    struct sockaddr_in6 x; int xl;
    char what[96];
    snprintf(what, sizeof what, "L=%s/%s C=%s->%s", SK_NAME[r->lsk], AK_NAME[r->lak], SK_NAME[r->csk], AK_NAME[r->cak]);
    e = s_connect(cs, t, tl, 3000);
    CHECKF(e == r->err, "%s connect got %d want %d", what, e, r->err);
    if (e == 0 && r->err == 0) {
        SOCKET a = INVALID_SOCKET;
        CHECKF(s_readable(ls, 3000), "%s listener not readable", what);
        xl = sizeof x; memset(&x, 0, sizeof x);
        a = U(accept)(ls, (struct sockaddr *)&x, &xl);
        CHECKF(a != INVALID_SOCKET, "%s accept err %d", what, a == INVALID_SOCKET ? s_err() : 0);
        if (a != INVALID_SOCKET) {
            int v;
            s_desc(&x, xl, d, sizeof d); CHECKF(!strcmp(d, r->acc), "%s accept name got %s want %s", what, d, r->acc);
            xl = sizeof x; CHECK(U(getpeername)(a, (struct sockaddr *)&x, &xl) == 0);
            s_desc(&x, xl, d, sizeof d); CHECKF(!strcmp(d, r->peer), "%s accepted peer got %s want %s", what, d, r->peer);
            xl = sizeof x; CHECK(U(getsockname)(a, (struct sockaddr *)&x, &xl) == 0);
            s_desc(&x, xl, d, sizeof d); CHECKF(!strcmp(d, r->lname), "%s accepted local got %s want %s", what, d, r->lname);
            CHECK(s_getint(a, IPPROTO_IPV6, IPV6_V6ONLY, &v) == 0);
            CHECKF(v == r->accv6o, "%s accepted V6ONLY got %d want %d", what, v, r->accv6o);
            s_close(a);
        }
        xl = sizeof x; CHECK(U(getsockname)(cs, (struct sockaddr *)&x, &xl) == 0);
        s_desc(&x, xl, d, sizeof d); CHECKF(!strcmp(d, r->cname), "%s client local got %s want %s", what, d, r->cname);
        xl = sizeof x; CHECK(U(getpeername)(cs, (struct sockaddr *)&x, &xl) == 0);
        s_desc(&x, xl, d, sizeof d); CHECKF(!strcmp(d, r->cpeer), "%s client peer got %s want %s", what, d, r->cpeer);
    } else if (r->err) {
        /* a failed connect leaves the client unconnected */
        xl = sizeof x;
        CHECKF(U(getpeername)(cs, (struct sockaddr *)&x, &xl) != 0, "%s peer exists after failed connect", what);
    }
    s_close(cs);
}

static void run_listener(int lsk, int lak) {
    SOCKET ls; char a[32]; int len, brc, lrc;
    unsigned short port;
    if (!s_up()) return;
    ls = s_mk(lsk, SOCK_STREAM); len = s_mkaddr(a, lak, 0);
    brc = U(bind)(ls, (struct sockaddr *)a, len); lrc = brc ? -1 : U(listen)(ls, 8);
    CHECK(brc == 0); CHECK(lrc == 0);
    if (brc || lrc) { s_close(ls); return; }
    port = s_port(ls);
    for (unsigned i = 0; i < sizeof C / sizeof *C; i++)
        if (C[i].lsk == lsk && C[i].lak == lak) check_one(&C[i], ls, port);
    s_close(ls);
}
TEST(dsm_conn_listener_v4_wildcard)          { run_listener(SK_V4, AK_V4ANY); }
TEST(dsm_conn_listener_v4_loopback)          { run_listener(SK_V4, AK_V4LOOP); }
TEST(dsm_conn_listener_v6_dual_wildcard)     { run_listener(SK_V6D, AK_V6ANY); }
TEST(dsm_conn_listener_v6_only_wildcard)     { run_listener(SK_V6O, AK_V6ANY); }
TEST(dsm_conn_listener_v6_dual_loopback)     { run_listener(SK_V6D, AK_V6LOOP); }
TEST(dsm_conn_listener_v6_dual_mapped_any)   { run_listener(SK_V6D, AK_MAPANY); }
TEST(dsm_conn_listener_v6_dual_mapped_loop)  { run_listener(SK_V6D, AK_MAPLOOP); }
TEST(dsm_conn_listener_v6_default_wildcard)  { run_listener(SK_V6DEF, AK_V6ANY); }
