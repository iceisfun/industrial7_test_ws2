/* UDP across families: receivers of every flavour bound to a loopback or wildcard name, senders of every flavour
 * addressing IPv4 loopback, v4-mapped loopback, IPv6 loopback and wildcards.  Each row gives the exact sendto()
 * result (2 bytes or the WSA error), whether the datagram arrives, the family/class of the source address
 * recvfrom() reports and the implicit local name the sender gets.  Absent datagrams are waited for briefly. */
#include "sm.h"

struct urow { int rsk, rak, ssk, tak, n, err, arrives; const char *from, *sname; };
static const struct urow U_[] = {
    { SK_V4, AK_V4LOOP, SK_V4, AK_V4LOOP, 2, 0, 1, "v4:loop:len16", "v4:any:len16" },
    { SK_V4, AK_V4LOOP, SK_V4, AK_MAPLOOP, -1, 10047, 0, "", "" },
    { SK_V4, AK_V4LOOP, SK_V4, AK_V6LOOP, -1, 10047, 0, "", "" },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_MAPLOOP, 2, 0, 1, "v4:loop:len16", "v6:any:scope0:len28" },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_V6LOOP, 2, 0, 0, "", "v6:any:scope0:len28" },
    { SK_V4, AK_V4LOOP, SK_V6O, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V4, AK_V4LOOP, SK_V6O, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V4, AK_V4LOOP, SK_V6DEF, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_MAPANY, -1, 10049, 0, "", "" },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_V4ANY, -1, 10014, 0, "", "" },
    { SK_V4, AK_V4LOOP, SK_V6D, AK_V6ANY, -1, 10049, 0, "", "" },
    { SK_V4, AK_V4ANY, SK_V4, AK_V4LOOP, 2, 0, 1, "v4:loop:len16", "v4:any:len16" },
    { SK_V4, AK_V4ANY, SK_V4, AK_MAPLOOP, -1, 10047, 0, "", "" },
    { SK_V4, AK_V4ANY, SK_V4, AK_V6LOOP, -1, 10047, 0, "", "" },
    { SK_V4, AK_V4ANY, SK_V6D, AK_MAPLOOP, 2, 0, 1, "v4:loop:len16", "v6:any:scope0:len28" },
    { SK_V4, AK_V4ANY, SK_V6D, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V4, AK_V4ANY, SK_V6D, AK_V6LOOP, 2, 0, 0, "", "v6:any:scope0:len28" },
    { SK_V4, AK_V4ANY, SK_V6O, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V4, AK_V4ANY, SK_V6O, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V4, AK_V4ANY, SK_V6DEF, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V4, AK_V4ANY, SK_V6D, AK_MAPANY, -1, 10049, 0, "", "" },
    { SK_V4, AK_V4ANY, SK_V6D, AK_V4ANY, -1, 10014, 0, "", "" },
    { SK_V4, AK_V4ANY, SK_V6D, AK_V6ANY, -1, 10049, 0, "", "" },
    { SK_V6D, AK_V6ANY, SK_V4, AK_V4LOOP, 2, 0, 1, "v6:map:loop:scope0:len28", "v4:any:len16" },
    { SK_V6D, AK_V6ANY, SK_V4, AK_MAPLOOP, -1, 10047, 0, "", "" },
    { SK_V6D, AK_V6ANY, SK_V4, AK_V6LOOP, -1, 10047, 0, "", "" },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_MAPLOOP, 2, 0, 1, "v6:map:loop:scope0:len28", "v6:any:scope0:len28" },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_V6LOOP, 2, 0, 1, "v6:loop:scope0:len28", "v6:any:scope0:len28" },
    { SK_V6D, AK_V6ANY, SK_V6O, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V6D, AK_V6ANY, SK_V6O, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V6D, AK_V6ANY, SK_V6DEF, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_MAPANY, -1, 10049, 0, "", "" },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_V4ANY, -1, 10014, 0, "", "" },
    { SK_V6D, AK_V6ANY, SK_V6D, AK_V6ANY, -1, 10049, 0, "", "" },
    { SK_V6O, AK_V6ANY, SK_V4, AK_V4LOOP, 2, 0, 0, "", "v4:any:len16" },
    { SK_V6O, AK_V6ANY, SK_V4, AK_MAPLOOP, -1, 10047, 0, "", "" },
    { SK_V6O, AK_V6ANY, SK_V4, AK_V6LOOP, -1, 10047, 0, "", "" },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_MAPLOOP, 2, 0, 0, "", "v6:any:scope0:len28" },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_V6LOOP, 2, 0, 1, "v6:loop:scope0:len28", "v6:any:scope0:len28" },
    { SK_V6O, AK_V6ANY, SK_V6O, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V6O, AK_V6ANY, SK_V6O, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V6O, AK_V6ANY, SK_V6DEF, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_MAPANY, -1, 10049, 0, "", "" },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_V4ANY, -1, 10014, 0, "", "" },
    { SK_V6O, AK_V6ANY, SK_V6D, AK_V6ANY, -1, 10049, 0, "", "" },
    { SK_V6D, AK_V6LOOP, SK_V4, AK_V4LOOP, 2, 0, 0, "", "v4:any:len16" },
    { SK_V6D, AK_V6LOOP, SK_V4, AK_MAPLOOP, -1, 10047, 0, "", "" },
    { SK_V6D, AK_V6LOOP, SK_V4, AK_V6LOOP, -1, 10047, 0, "", "" },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_MAPLOOP, 2, 0, 0, "", "v6:any:scope0:len28" },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_V6LOOP, 2, 0, 1, "v6:loop:scope0:len28", "v6:any:scope0:len28" },
    { SK_V6D, AK_V6LOOP, SK_V6O, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V6D, AK_V6LOOP, SK_V6O, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V6D, AK_V6LOOP, SK_V6DEF, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_MAPANY, -1, 10049, 0, "", "" },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_V4ANY, -1, 10014, 0, "", "" },
    { SK_V6D, AK_V6LOOP, SK_V6D, AK_V6ANY, -1, 10049, 0, "", "" },
    { SK_V6D, AK_MAPLOOP, SK_V4, AK_V4LOOP, 2, 0, 1, "v6:map:loop:scope0:len28", "v4:any:len16" },
    { SK_V6D, AK_MAPLOOP, SK_V4, AK_MAPLOOP, -1, 10047, 0, "", "" },
    { SK_V6D, AK_MAPLOOP, SK_V4, AK_V6LOOP, -1, 10047, 0, "", "" },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_MAPLOOP, 2, 0, 1, "v6:map:loop:scope0:len28", "v6:any:scope0:len28" },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_V6LOOP, 2, 0, 0, "", "v6:any:scope0:len28" },
    { SK_V6D, AK_MAPLOOP, SK_V6O, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V6D, AK_MAPLOOP, SK_V6O, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V6D, AK_MAPLOOP, SK_V6DEF, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_MAPANY, -1, 10049, 0, "", "" },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_V4ANY, -1, 10014, 0, "", "" },
    { SK_V6D, AK_MAPLOOP, SK_V6D, AK_V6ANY, -1, 10049, 0, "", "" },
    { SK_V6O, AK_V6LOOP, SK_V4, AK_V4LOOP, 2, 0, 0, "", "v4:any:len16" },
    { SK_V6O, AK_V6LOOP, SK_V4, AK_MAPLOOP, -1, 10047, 0, "", "" },
    { SK_V6O, AK_V6LOOP, SK_V4, AK_V6LOOP, -1, 10047, 0, "", "" },
    { SK_V6O, AK_V6LOOP, SK_V6D, AK_MAPLOOP, 2, 0, 0, "", "v6:any:scope0:len28" },
    { SK_V6O, AK_V6LOOP, SK_V6D, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V6O, AK_V6LOOP, SK_V6D, AK_V6LOOP, 2, 0, 1, "v6:loop:scope0:len28", "v6:any:scope0:len28" },
    { SK_V6O, AK_V6LOOP, SK_V6O, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V6O, AK_V6LOOP, SK_V6O, AK_V4LOOP, -1, 10014, 0, "", "" },
    { SK_V6O, AK_V6LOOP, SK_V6DEF, AK_MAPLOOP, -1, 10049, 0, "", "" },
    { SK_V6O, AK_V6LOOP, SK_V6D, AK_MAPANY, -1, 10049, 0, "", "" },
    { SK_V6O, AK_V6LOOP, SK_V6D, AK_V4ANY, -1, 10014, 0, "", "" },
    { SK_V6O, AK_V6LOOP, SK_V6D, AK_V6ANY, -1, 10049, 0, "", "" },
};

static void run_recv(int rsk, int rak) {
    SOCKET rs; char a[32]; unsigned short port;
    if (!s_up()) return;
    rs = s_mk(rsk, SOCK_DGRAM);
    CHECK(U(bind)(rs, (struct sockaddr *)a, s_mkaddr(a, rak, 0)) == 0);
    port = s_port(rs);
    for (unsigned i = 0; i < sizeof U_ / sizeof *U_; i++) {
        const struct urow *r = &U_[i];
        SOCKET ss; char t[32], d[64]; int tl, n, e = 0;
        if (r->rsk != rsk || r->rak != rak) continue;
        ss = s_mk(r->ssk, SOCK_DGRAM); tl = s_mkaddr(t, r->tak, port);
        n = U(sendto)(ss, "ab", 2, 0, (struct sockaddr *)t, tl);
        if (n < 0) e = s_err();
        CHECKF(n == r->n && e == r->err, "S=%s->%s n=%d err=%d want n=%d err=%d", SK_NAME[r->ssk], AK_NAME[r->tak], n, e, r->n, r->err);
        if (n == 2) {
            int ready = s_readable(rs, r->arrives ? 3000 : 700);
            CHECKF(ready == r->arrives, "S=%s->%s arrival %d want %d", SK_NAME[r->ssk], AK_NAME[r->tak], ready, r->arrives);
            if (ready && r->arrives) {
                char b[8]; struct sockaddr_in6 f; int fl = sizeof f;
                int got = U(recvfrom)(rs, b, sizeof b, 0, (struct sockaddr *)&f, &fl);
                CHECK(got == 2);
                s_desc(&f, fl, d, sizeof d);
                CHECKF(!strcmp(d, r->from), "S=%s->%s source got %s want %s", SK_NAME[r->ssk], AK_NAME[r->tak], d, r->from);
            }
            { struct sockaddr_in6 n6; int nl = sizeof n6;
              CHECK(U(getsockname)(ss, (struct sockaddr *)&n6, &nl) == 0);
              s_desc(&n6, nl, d, sizeof d);
              CHECKF(!strcmp(d, r->sname), "S=%s->%s sender name got %s want %s", SK_NAME[r->ssk], AK_NAME[r->tak], d, r->sname); }
        }
        s_close(ss);
    }
    s_close(rs);
}
TEST(dsm_udp_receiver_v4_loopback)         { run_recv(SK_V4, AK_V4LOOP); }
TEST(dsm_udp_receiver_v4_wildcard)         { run_recv(SK_V4, AK_V4ANY); }
TEST(dsm_udp_receiver_v6_dual_wildcard)    { run_recv(SK_V6D, AK_V6ANY); }
TEST(dsm_udp_receiver_v6_only_wildcard)    { run_recv(SK_V6O, AK_V6ANY); }
TEST(dsm_udp_receiver_v6_dual_loopback)    { run_recv(SK_V6D, AK_V6LOOP); }
TEST(dsm_udp_receiver_v6_dual_mapped_loop) { run_recv(SK_V6D, AK_MAPLOOP); }
TEST(dsm_udp_receiver_v6_only_loopback)    { run_recv(SK_V6O, AK_V6LOOP); }
