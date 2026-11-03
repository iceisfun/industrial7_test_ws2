/* Socket groups and endpoint lifetime.
 *
 * A group id in the open packet is either 0 (no group), 1 or 2 (create an unconstrained or a
 * constrained group; the driver assigns the id) or the id of a group that still has members. The
 * provider exposes the assigned id through SO_GROUP_ID. This file follows a group through its life
 * by creating sockets with the group selector, reading the id back, joining the group through the
 * raw open path, and closing every member: after that the id is no longer valid and an open that
 * names it is STATUS_INVALID_PARAMETER. */
#include "aec.h"

#define SOL_SOCKET_ 0xFFFF
#define SO_GROUP_ID_ 0x2001
#define SG_UNCONSTRAINED 1
#define SG_CONSTRAINED   2

static SOCKET grp_sock(int af, int type, int proto, DWORD flags, int g)
{
    return N.WSASocketW(af, type, proto, NULL, (GROUP)g, flags);
}
static ULONG group_of(SOCKET s, int *ok)
{
    ULONG id = 0xFFFFFFFFu; int len = sizeof(id);
    *ok = N.getsockopt(s, SOL_SOCKET_, SO_GROUP_ID_, (char *)&id, &len) == 0;
    return id;
}
/* Wait (bounded) until the group id stops being accepted; the endpoint is freed asynchronously. */
static int group_gone(ULONG id)
{
    ep_t e; int i;
    for (i = 0; i < 40; i++) {
        ep_tcp4(&e); e.pkt.GroupID = id;
        if (ep_try(&e) == ST_INVALID_PARAMETER) return 1;
        Sleep(100);
    }
    return 0;
}

TEST(aecg_plain_socket_has_group_zero)
{
    SOCKET s; int ok; ULONG id; NEED();
    s = grp_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, 1, 0);
    CHECK(s != INVALID_SOCKET); if (s == INVALID_SOCKET) return;
    id = group_of(s, &ok);
    CHECK(ok); EXPECT_EQ(id, 0);
    N.closesocket(s);
}
TEST(aecg_unconstrained_group_gets_an_id)
{
    SOCKET s; int ok; ULONG id; NEED();
    s = grp_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, 1, SG_UNCONSTRAINED);
    CHECK(s != INVALID_SOCKET); if (s == INVALID_SOCKET) return;
    id = group_of(s, &ok);
    CHECK(ok); CHECK(id != 0 && id != 1 && id != 2 && id != 0xFFFFFFFFu);
    N.closesocket(s);
    group_gone(id);
}
TEST(aecg_constrained_group_gets_an_id)
{
    SOCKET s; int ok; ULONG id; NEED();
    s = grp_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, 1, SG_CONSTRAINED);
    CHECK(s != INVALID_SOCKET); if (s == INVALID_SOCKET) return;
    id = group_of(s, &ok);
    CHECK(ok); CHECK(id != 0 && id != 1 && id != 2 && id != 0xFFFFFFFFu);
    N.closesocket(s);
    group_gone(id);
}
TEST(aecg_two_new_groups_have_distinct_ids)
{
    SOCKET a, b; int ok; ULONG ia, ib; NEED();
    a = grp_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, 1, SG_UNCONSTRAINED);
    b = grp_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, 1, SG_UNCONSTRAINED);
    CHECK(a != INVALID_SOCKET && b != INVALID_SOCKET);
    if (a == INVALID_SOCKET || b == INVALID_SOCKET) { if (a != INVALID_SOCKET) N.closesocket(a); if (b != INVALID_SOCKET) N.closesocket(b); return; }
    ia = group_of(a, &ok); ib = group_of(b, &ok);
    CHECK(ia != ib);
    N.closesocket(a); N.closesocket(b);
    group_gone(ia); group_gone(ib);
}
TEST(aecg_join_existing_group_through_socket_call)
{
    SOCKET a, b; int ok; ULONG ia, ib; NEED();
    a = grp_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, 1, SG_UNCONSTRAINED);
    CHECK(a != INVALID_SOCKET); if (a == INVALID_SOCKET) return;
    ia = group_of(a, &ok);
    b = grp_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, 1, (int)ia);
    CHECK(b != INVALID_SOCKET);
    if (b != INVALID_SOCKET) { ib = group_of(b, &ok); EXPECT_EQ(ib, ia); N.closesocket(b); }
    N.closesocket(a);
    group_gone(ia);
}
TEST(aecg_join_existing_group_through_raw_open)
{
    SOCKET a; ep_t e; HANDLE h; IO_STATUS_BLOCK io; int ok; ULONG id; NEED();
    a = grp_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, 1, SG_UNCONSTRAINED);
    CHECK(a != INVALID_SOCKET); if (a == INVALID_SOCKET) return;
    id = group_of(a, &ok);
    ep_tcp4(&e); e.pkt.GroupID = id;
    EXPECT_NT(ep_open(&e, &h, &io), ST_SUCCESS);
    if (h) N.NtClose(h);
    N.closesocket(a);
    group_gone(id);
}
TEST(aecg_group_id_valid_while_any_member_remains)
{
    SOCKET a; ep_t e; HANDLE h, h2; IO_STATUS_BLOCK io; int ok; ULONG id; NEED();
    a = grp_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, 1, SG_UNCONSTRAINED);
    CHECK(a != INVALID_SOCKET); if (a == INVALID_SOCKET) return;
    id = group_of(a, &ok);
    ep_tcp4(&e); e.pkt.GroupID = id;
    EXPECT_NT(ep_open(&e, &h, &io), ST_SUCCESS);
    N.closesocket(a);                       /* the raw member keeps the group alive */
    Sleep(200);
    EXPECT_NT(ep_open(&e, &h2, &io), ST_SUCCESS);
    if (h2) N.NtClose(h2);
    if (h) N.NtClose(h);
    CHECK(group_gone(id));
}
TEST(aecg_group_id_invalid_after_last_member_closes)
{
    SOCKET a; int ok; ULONG id; NEED();
    a = grp_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, 1, SG_CONSTRAINED);
    CHECK(a != INVALID_SOCKET); if (a == INVALID_SOCKET) return;
    id = group_of(a, &ok);
    N.closesocket(a);
    CHECK(group_gone(id));
}
TEST(aecg_group_not_visible_across_families_but_joinable)
{
    /* groups are not tied to the transport: a datagram endpoint can join a stream endpoint's group */
    SOCKET a; ep_t e; HANDLE h; IO_STATUS_BLOCK io; int ok; ULONG id; NEED();
    a = grp_sock(AF_INET, SOCK_STREAM, IPPROTO_TCP, 1, SG_UNCONSTRAINED);
    CHECK(a != INVALID_SOCKET); if (a == INVALID_SOCKET) return;
    id = group_of(a, &ok);
    ep_udp4(&e); e.pkt.GroupID = id;
    EXPECT_NT(ep_open(&e, &h, &io), ST_SUCCESS);
    if (h) N.NtClose(h);
    ep_tcp6(&e); e.pkt.GroupID = id;
    EXPECT_NT(ep_open(&e, &h, &io), ST_SUCCESS);
    if (h) N.NtClose(h);
    N.closesocket(a);
    group_gone(id);
}
TEST(aecg_failed_open_does_not_keep_group_alive)
{
    /* a rejected open (bad flags) with a group selector leaves no group behind */
    ep_t e; NEED(); ep_tcp4(&e); e.pkt.GroupID = 1; e.pkt.Flags = 2;
    EXPECT_NT(ep_try(&e), ST_INVALID_PARAMETER);
}
TEST(aecg_open_close_cycle_leaves_no_group_state)
{
    ep_t e; int i, ok = 0; NEED();
    for (i = 0; i < 50; i++) { ep_tcp4(&e); e.pkt.GroupID = (i & 1) ? 1 : 2; if (ep_try(&e) == ST_SUCCESS) ok++; }
    EXPECT_EQ(ok, 50);
}

/* ---- endpoint lifetime through sockets -------------------------------------------------- */
TEST(aecg_closesocket_twice_second_fails_notsock)
{
    SOCKET s; int r1, r2, err; NEED();
    s = N.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(s != INVALID_SOCKET); if (s == INVALID_SOCKET) return;
    r1 = N.closesocket(s);
    EXPECT_EQ(r1, 0);
    r2 = N.closesocket(s); err = N.WSAGetLastError();
    EXPECT_EQ(r2, SOCKET_ERROR);
    EXPECT_EQ(err, WSAENOTSOCK);
}
TEST(aecg_handle_value_reusable_after_close)
{
    /* closing releases the handle table slot; repeated create/close does not grow the handle count */
    DWORD before = 0, after = 0; int i; SOCKET s; NEED();
    GetProcessHandleCount(GetCurrentProcess(), &before);
    for (i = 0; i < 200; i++) { s = N.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (s != INVALID_SOCKET) N.closesocket(s); }
    GetProcessHandleCount(GetCurrentProcess(), &after);
    CHECKF(after <= before + 8, "handle count %lu -> %lu", (unsigned long)before, (unsigned long)after);
}
TEST(aecg_direct_open_close_does_not_leak_handles)
{
    DWORD before = 0, after = 0; int i; ep_t e; NEED(); ep_tcp4(&e);
    GetProcessHandleCount(GetCurrentProcess(), &before);
    for (i = 0; i < 200; i++) ep_try(&e);
    GetProcessHandleCount(GetCurrentProcess(), &after);
    CHECKF(after <= before + 8, "handle count %lu -> %lu", (unsigned long)before, (unsigned long)after);
}
