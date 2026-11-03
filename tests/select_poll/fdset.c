/* fd_set layout, the FD_* header macros as an application sees them, and the exported __WSAFDIsSet
 * (the function FD_ISSET expands to): membership by scanning exactly fd_count entries, full 64-bit
 * comparison, no socket validation, no use of the thread's last-error value, no need for WSAStartup.
 * Also the export relationships between ws2_32 and wsock32 for select / __WSAFDIsSet.
 */
#include "sp.h"

/* ---- layout ---- */
TEST(sp_fdset_struct_layout)
{
    SPEQ(sizeof(fd_set), 8 + 64 * 8);
    SPEQ(offsetof(fd_set, fd_count), 0);
    SPEQ(offsetof(fd_set, fd_array), 8);
    SPEQ(sizeof(((fd_set *)0)->fd_count), 4);
    SPEQ(sizeof(((fd_set *)0)->fd_array[0]), 8);
    SPEQ(FD_SETSIZE, 64);
    SPEQ(sizeof(SOCKET), 8);
}
TEST(sp_fdset_custom_size_layout)
{
    /* A caller-sized set keeps the same two-field prefix; element i lives at 8 + 8*i. */
    fd_set *s = sp_newset(300);
    SPEQ((char *)&s->fd_array[299] - (char *)s, 8 + 299 * 8);
    SPEQ(offsetof(fd_set, fd_array[300]), 8 + 300 * 8);
    free(s);
}
TEST(sp_wsapollfd_struct_layout)
{
    SPEQ(sizeof(WSAPOLLFD), 16);
    SPEQ(offsetof(WSAPOLLFD, fd), 0);
    SPEQ(offsetof(WSAPOLLFD, events), 8);
    SPEQ(offsetof(WSAPOLLFD, revents), 10);
    SPEQ(sizeof(((WSAPOLLFD *)0)->events), 2);
}
TEST(sp_poll_flag_values)
{
    SPEQ(POLLRDNORM, 0x0100);
    SPEQ(POLLRDBAND, 0x0200);
    SPEQ(POLLIN, 0x0300);
    SPEQ(POLLPRI, 0x0400);
    SPEQ(POLLWRNORM, 0x0010);
    SPEQ(POLLOUT, 0x0010);
    SPEQ(POLLWRBAND, 0x0020);
    SPEQ(POLLERR, 0x0001);
    SPEQ(POLLHUP, 0x0002);
    SPEQ(POLLNVAL, 0x0004);
}

/* ---- the header macros (pure data-structure behaviour; no DLL call) ---- */
TEST(sp_macro_zero_and_set)
{
    fd_set s;
    memset(&s, 0xAB, sizeof s);
    FD_ZERO(&s);
    SPEQ(s.fd_count, 0);
    FD_SET((SOCKET)5, &s);
    FD_SET((SOCKET)9, &s);
    SPEQ(s.fd_count, 2);
    SPEQ(s.fd_array[0], 5);
    SPEQ(s.fd_array[1], 9);
}
TEST(sp_macro_set_ignores_duplicates)
{
    fd_set s;
    FD_ZERO(&s);
    FD_SET((SOCKET)7, &s);
    FD_SET((SOCKET)7, &s);
    FD_SET((SOCKET)7, &s);
    SPEQ(s.fd_count, 1);
}
TEST(sp_macro_set_stops_at_setsize)
{
    fd_set s;
    unsigned i;
    FD_ZERO(&s);
    for (i = 1; i <= 70; i++) FD_SET((SOCKET)(i * 4), &s);
    SPEQ(s.fd_count, 64);
    SPEQ(s.fd_array[63], 64 * 4);
}
TEST(sp_macro_clr_removes_and_keeps_others)
{
    fd_set s;
    FD_ZERO(&s);
    FD_SET((SOCKET)4, &s); FD_SET((SOCKET)8, &s); FD_SET((SOCKET)12, &s);
    FD_CLR((SOCKET)8, &s);
    SPEQ(s.fd_count, 2);
    CHECK(sp_has(&s, 4)); CHECK(sp_has(&s, 12)); CHECK(!sp_has(&s, 8));
    FD_CLR((SOCKET)99, &s);   /* absent: no change */
    SPEQ(s.fd_count, 2);
}

/* ---- __WSAFDIsSet ---- */
#define ISSET(sock, set) (U(__WSAFDIsSet)((SOCKET)(sock), (set)))

TEST(sp_isset_export_resolves)
{
    REQUIRE(U(__WSAFDIsSet));
    CHECK(UIN("ws2_32.dll", __WSAFDIsSet) != NULL);
}
TEST(sp_isset_ordinal_151_is_named_export)
{
    FARPROC byord = t_proc_ord("ws2_32.dll", 151);
    REQUIRE(UIN("ws2_32.dll", __WSAFDIsSet));
    CHECK(byord != NULL);
    CHECK(byord == (FARPROC)UIN("ws2_32.dll", __WSAFDIsSet));
}
TEST(sp_isset_wsock32_forwards_to_ws2_32)
{
    FARPROC a = (FARPROC)UIN("ws2_32.dll", __WSAFDIsSet), b = (FARPROC)UIN("wsock32.dll", __WSAFDIsSet);
    REQUIRE(a);
    REQUIRE(b);
    CHECK(a == b);   /* GetProcAddress resolves the forwarder to the target function */
}
TEST(sp_select_wsock32_forwards_to_ws2_32)
{
    FARPROC a = (FARPROC)UIN("ws2_32.dll", select), b = (FARPROC)UIN("wsock32.dll", select);
    REQUIRE(a);
    REQUIRE(b);
    CHECK(a == b);
}
TEST(sp_wsapoll_not_exported_by_wsock32)
{
    /* WSAPoll postdates the legacy shim; only the ws2_32 export exists. */
    HMODULE m = t_module("wsock32.dll");
    REQUIRE(m);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "WSAPoll") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}

TEST(sp_isset_empty_set_is_zero)
{
    fd_set s;
    REQUIRE(U(__WSAFDIsSet));
    s.fd_count = 0;
    s.fd_array[0] = 4;   /* stale content behind a zero count must not match */
    SPEQ(ISSET(4, &s), 0);
    SPEQ(ISSET(0, &s), 0);
    SPEQ(ISSET(INVALID_SOCKET, &s), 0);
}
TEST(sp_isset_member_returns_exactly_one)
{
    fd_set s;
    REQUIRE(U(__WSAFDIsSet));
    s.fd_count = 3; s.fd_array[0] = 100; s.fd_array[1] = 200; s.fd_array[2] = 300;
    SPEQ(ISSET(100, &s), 1);
    SPEQ(ISSET(200, &s), 1);
    SPEQ(ISSET(300, &s), 1);
}
TEST(sp_isset_nonmember_returns_zero)
{
    fd_set s;
    REQUIRE(U(__WSAFDIsSet));
    s.fd_count = 3; s.fd_array[0] = 100; s.fd_array[1] = 200; s.fd_array[2] = 300;
    SPEQ(ISSET(101, &s), 0);
    SPEQ(ISSET(0, &s), 0);
    SPEQ(ISSET(299, &s), 0);
    SPEQ(ISSET(INVALID_SOCKET, &s), 0);
}
TEST(sp_isset_only_scans_fd_count_entries)
{
    fd_set s;
    REQUIRE(U(__WSAFDIsSet));
    s.fd_count = 2; s.fd_array[0] = 10; s.fd_array[1] = 20; s.fd_array[2] = 30; s.fd_array[3] = 40;
    SPEQ(ISSET(20, &s), 1);
    SPEQ(ISSET(30, &s), 0);
    SPEQ(ISSET(40, &s), 0);
    s.fd_count = 3;
    SPEQ(ISSET(30, &s), 1);
    SPEQ(ISSET(40, &s), 0);
}
TEST(sp_isset_every_position_of_a_full_set)
{
    fd_set s;
    unsigned i, j;
    REQUIRE(U(__WSAFDIsSet));
    s.fd_count = 64;
    for (i = 0; i < 64; i++) s.fd_array[i] = 1000 + i * 4;
    for (i = 0; i < 64; i++) SPEQ(ISSET(1000 + i * 4, &s), 1);
    for (j = 0; j < 64; j++) SPEQ(ISSET(1002 + j * 4, &s), 0);
}
TEST(sp_isset_duplicates_still_report_one)
{
    fd_set s;
    REQUIRE(U(__WSAFDIsSet));
    s.fd_count = 4; s.fd_array[0] = 8; s.fd_array[1] = 8; s.fd_array[2] = 12; s.fd_array[3] = 8;
    SPEQ(ISSET(8, &s), 1);
    SPEQ(ISSET(12, &s), 1);
}
TEST(sp_isset_matches_invalid_socket_value)
{
    /* No validation of the handle value: INVALID_SOCKET is an ordinary 64-bit key. */
    fd_set s;
    REQUIRE(U(__WSAFDIsSet));
    s.fd_count = 2; s.fd_array[0] = INVALID_SOCKET; s.fd_array[1] = 0;
    SPEQ(ISSET(INVALID_SOCKET, &s), 1);
    SPEQ(ISSET(0, &s), 1);
    SPEQ(ISSET(4, &s), 0);
}
TEST(sp_isset_compares_all_64_bits)
{
    fd_set s;
    REQUIRE(U(__WSAFDIsSet));
    s.fd_count = 1; s.fd_array[0] = 0x100000004ULL;
    SPEQ(ISSET(0x100000004ULL, &s), 1);
    SPEQ(ISSET(4, &s), 0);
    SPEQ(ISSET(0x200000004ULL, &s), 0);
    s.fd_array[0] = 4;
    SPEQ(ISSET(0x100000004ULL, &s), 0);
}
TEST(sp_isset_large_custom_set)
{
    fd_set *s;
    unsigned i;
    REQUIRE(U(__WSAFDIsSet));
    s = sp_newset(1000);
    for (i = 0; i < 1000; i++) sp_put(s, 4 + i * 4);
    SPEQ(ISSET(4, s), 1);
    SPEQ(ISSET(4 + 999 * 4, s), 1);
    SPEQ(ISSET(4 + 500 * 4, s), 1);
    SPEQ(ISSET(4 + 1000 * 4, s), 0);
    SPEQ(ISSET(6, s), 0);
    free(s);
}
TEST(sp_isset_does_not_modify_set)
{
    fd_set s, copy;
    REQUIRE(U(__WSAFDIsSet));
    s.fd_count = 3; s.fd_array[0] = 1; s.fd_array[1] = 2; s.fd_array[2] = 3;
    memcpy(&copy, &s, sizeof s);
    ISSET(2, &s);
    ISSET(77, &s);
    CHECK(!memcmp(&copy, &s, sizeof s));
}
TEST(sp_isset_leaves_last_error_alone)
{
    fd_set s;
    NEED_WS();
    REQUIRE(U(__WSAFDIsSet));
    s.fd_count = 1; s.fd_array[0] = 5;
    sp_seterr(WSAEMFILE);
    ISSET(5, &s);
    ISSET(6, &s);
    SPEQ(sp_err(), WSAEMFILE);
}
TEST(sp_isset_model_check_against_reference)
{
    /* Deterministic random sets compared with a straightforward reference scan. */
    unsigned st = 12345, round, k;
    fd_set *s;
    REQUIRE(U(__WSAFDIsSet));
    s = sp_newset(200);
    for (round = 0; round < 200; round++) {
        unsigned n = sp_rng(&st) % 200;
        s->fd_count = n;
        for (k = 0; k < n; k++) s->fd_array[k] = (sp_rng(&st) % 300) * 4;
        for (k = 0; k < 20; k++) {
            SOCKET q = (sp_rng(&st) % 320) * 4;
            SPEQ(ISSET(q, s), sp_has(s, q));
        }
    }
    free(s);
}
TEST(sp_isset_with_real_socket_values)
{
    SOCKET a, b, c;
    fd_set s;
    NEED_WS();
    REQUIRE(U(__WSAFDIsSet));
    a = sp_sock(AF_INET, SOCK_DGRAM, 0); b = sp_sock(AF_INET, SOCK_DGRAM, 0); c = sp_sock(AF_INET, SOCK_DGRAM, 0);
    CHECK(a != INVALID_SOCKET && b != INVALID_SOCKET && c != INVALID_SOCKET);
    sp_zero(&s); sp_put(&s, a); sp_put(&s, c);
    SPEQ(ISSET(a, &s), 1);
    SPEQ(ISSET(b, &s), 0);
    SPEQ(ISSET(c, &s), 1);
    sp_close(a); sp_close(b); sp_close(c);
}

/* ---- no-startup behaviour, in a fresh process that never calls WSAStartup ---- */
CHILD(sp_fdisset_nostartup)
{
    fd_set s;
    FARPROC f = t_proc_in("ws2_32.dll", "__WSAFDIsSet");
    int (WSAAPI *isset)(SOCKET, fd_set *) = (int (WSAAPI *)(SOCKET, fd_set *))f;
    if (!isset) return 90;
    s.fd_count = 2; s.fd_array[0] = 40; s.fd_array[1] = 44;
    if (isset(44, &s) != 1) return 91;
    if (isset(48, &s) != 0) return 92;
    return 0;
}
TEST(sp_isset_needs_no_wsastartup)
{
    REQUIRE(U(__WSAFDIsSet));
    SPEQ(t_run_child("sp_fdisset_nostartup", "", 20000), 0);
}
