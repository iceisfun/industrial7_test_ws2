/* TCP_NODELAY effects seen only as relations: the stream content and the byte counters do not depend on whether
 * small writes are coalesced, and the option can be flipped on a live connection without disturbing it. No timing
 * is asserted. */
#include "xt.h"

static void small_writes(int nodelay_client, int nodelay_server, int count)
{
    SOCKET c, a, l; char in[600], out[600]; int i, got; xt_info1 ci, ai; DWORD v = 1;
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_seti(c, IPPROTO_TCP, XT_TCP_NODELAY, nodelay_client), 0);
    EQ(xt_seti(a, IPPROTO_TCP, XT_TCP_NODELAY, nodelay_server), 0);
    for (i = 0; i < count; i++) out[i] = (char)('A' + i % 26);
    for (i = 0; i < count; i++) EQ(xt_send(c, out + i, 1), 1);
    got = xt_recv_all(a, in, count, 3000);
    EQ(got, count);
    EQ(memcmp(in, out, count), 0);
    for (i = 0; i < 100; i++) { xt_io(c, XT_SIO_TCP_INFO, &v, 4, &ci, sizeof ci); if (ci.b.BytesOut == (ULONG64)count) break; Sleep(20); }
    for (i = 0; i < 100; i++) { xt_io(a, XT_SIO_TCP_INFO, &v, 4, &ai, sizeof ai); if (ai.b.BytesIn == (ULONG64)count) break; Sleep(20); }
    EQ(ci.b.BytesOut, count); EQ(ai.b.BytesIn, count);
    EQ(ci.b.BytesRetrans, 0);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(nodelay_off_small_writes_arrive_complete_and_in_order) { NEED(); small_writes(0, 0, 100); }
TEST(nodelay_on_small_writes_arrive_complete_and_in_order) { NEED(); small_writes(1, 1, 100); }
TEST(nodelay_mixed_settings_small_writes_arrive_complete) { NEED(); small_writes(1, 0, 60); small_writes(0, 1, 60); }
TEST(nodelay_flipped_mid_stream_loses_nothing)
{
    SOCKET c, a, l; char in[300], out[300]; int i;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    for (i = 0; i < 300; i++) out[i] = (char)i;
    for (i = 0; i < 300; i++) {
        if (i % 50 == 0) EQ(xt_seti(c, IPPROTO_TCP, XT_TCP_NODELAY, (i / 50) & 1), 0);
        EQ(xt_send(c, out + i, 1), 1);
    }
    EQ(xt_recv_all(a, in, 300, 3000), 300);
    EQ(memcmp(in, out, 300), 0);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(nodelay_option_is_per_socket_not_per_connection)
{
    SOCKET c, a, l; long long v;
    NEED();
    if (!xt_pair(&c, &a, &l)) { t_skip("pair failed"); return; }
    EQ(xt_seti(c, IPPROTO_TCP, XT_TCP_NODELAY, 1), 0);
    EQ(xt_geti(c, IPPROTO_TCP, XT_TCP_NODELAY, &v), 0); EQ(v & 0xff, 1);
    EQ(xt_geti(a, IPPROTO_TCP, XT_TCP_NODELAY, &v), 0); EQ(v & 0xff, 0);
    xt_close(c); xt_close(a); xt_close(l);
}
TEST(nodelay_set_before_connect_survives_the_connect)
{
    SOCKET l, c, a; u_short p; long long v;
    NEED();
    EQ(xt_listen_lo(&l, &p, 2), 1);
    c = xt_tcp(); EQ(xt_seti(c, IPPROTO_TCP, XT_TCP_NODELAY, 1), 0);
    EQ(xt_connect_lo(c, p), 0);
    CHECK(xt_readable(l, 3000)); a = xt_accept(l);
    EQ(xt_geti(c, IPPROTO_TCP, XT_TCP_NODELAY, &v), 0); EQ(v & 0xff, 1);
    xt_close(c); xt_close(a); xt_close(l);
}
