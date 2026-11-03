/* Information classes on an endpoint, as a contract table.
 *
 * NtQueryInformationFile / NtSetInformationFile are answered partly by the I/O manager (class validity, length
 * checks, access checks, synchronous-handle position handling) and partly by the AFD driver (everything else, mostly
 * "not implemented"). ni_tab.h records, for every class 0..79 and buffer lengths 0/4/8/16/64, the NTSTATUS and the
 * IoStatus.Information that a Windows 10 stack gives for an overlapped stream endpoint and a synchronous datagram
 * endpoint. One small test per class and direction, then cross-checks that the answers do not depend on the kind or
 * state of the endpoint.
 */
#include "acc.h"
#include "ni_tab.h"

static const int lens[5] = { 0, 4, 8, 16, 64 };
#define UNTOUCHED 0xEEEEEEEEEEEEEEEEull

static void row_check(const ni_row_t *row, int cls, int set, SOCKET s, const char *what)
{
    int k;
    for (k = 0; k < 5; k++) {
        IO_STATUS_BLOCK io; char buf[128]; LONG st;
        unsigned long long want_info = row->c[k].info == ~0ull ? UNTOUCHED : row->c[k].info;
        memset(buf, 0, sizeof buf); memset(&io, 0xEE, sizeof io);
        st = set ? UN(NtSetInformationFile)((HANDLE)s, &io, buf, (ULONG)lens[k], cls)
                 : UN(NtQueryInformationFile)((HANDLE)s, &io, buf, (ULONG)lens[k], cls);
        CHECKF((unsigned long)st == row->c[k].st, "%s class %d len %d: status %#lx want %#lx", what, cls, lens[k], (unsigned long)st, row->c[k].st);
        CHECKF((unsigned long long)io.Information == want_info, "%s class %d len %d: information %#llx want %#llx", what, cls, lens[k], (unsigned long long)io.Information, want_info);
    }
}

#define CLASS_LIST \
X(00,0) X(01,1) X(02,2) X(03,3) X(04,4) X(05,5) X(06,6) X(07,7)\
X(08,8) X(09,9) X(10,10) X(11,11) X(12,12) X(13,13) X(14,14) X(15,15)\
X(16,16) X(17,17) X(18,18) X(19,19) X(20,20) X(21,21) X(22,22) X(23,23)\
X(24,24) X(25,25) X(26,26) X(27,27) X(28,28) X(29,29) X(30,30) X(31,31)\
X(32,32) X(33,33) X(34,34) X(35,35) X(36,36) X(37,37) X(38,38) X(39,39)\
X(40,40) X(41,41) X(42,42) X(43,43) X(44,44) X(45,45) X(46,46) X(47,47)\
X(48,48) X(49,49) X(50,50) X(51,51) X(52,52) X(53,53) X(54,54) X(55,55)\
X(56,56) X(57,57) X(58,58) X(59,59) X(60,60) X(61,61) X(62,62) X(63,63)\
X(64,64) X(65,65) X(66,66) X(67,67) X(68,68) X(69,69) X(70,70) X(71,71)\
X(72,72) X(73,73) X(74,74) X(75,75) X(76,76) X(77,77) X(78,78) X(79,79)

#define X(NN, N) \
    TEST(cc_ni_query_class_##NN) { SOCKET s; UP(); s = acc_sock(SOCK_STREAM); row_check(&ni_q_ovl[N], N, 0, s, "tcp-overlapped"); CLOSES(s); } \
    TEST(cc_ni_set_class_##NN)   { SOCKET s; UP(); s = acc_sock(SOCK_STREAM); row_check(&ni_s_ovl[N], N, 1, s, "tcp-overlapped"); CLOSES(s); }
CLASS_LIST
#undef X

/* The whole table in one pass for the synchronous datagram endpoint (position and mode differ from the overlapped one). */
TEST(cc_ni_sync_endpoint_query_table)
{
    int c; SOCKET s;
    UP();
    for (c = 0; c < 80; c++) { s = acc_sock_sync(SOCK_DGRAM); row_check(&ni_q_sync[c], c, 0, s, "udp-sync"); CLOSES(s); }
}
TEST(cc_ni_sync_endpoint_set_table)
{
    int c; SOCKET s;
    UP();
    for (c = 0; c < 80; c++) { s = acc_sock_sync(SOCK_DGRAM); row_check(&ni_s_sync[c], c, 1, s, "udp-sync"); CLOSES(s); }
}

/* ---- the answer does not depend on endpoint kind or state --------------------------------------------------- */
typedef SOCKET (*mk_fn)(HANDLE *extra);

static void same_everywhere(const char *what, SOCKET s)
{
    int c;
    for (c = 0; c < 80; c++) {
        row_check(&ni_q_ovl[c], c, 0, s, what);
        if (c != 30 && c != 41 && c != 16) row_check(&ni_s_ovl[c], c, 1, s, what);
    }
}
TEST(cc_ni_same_for_udp_overlapped)  { SOCKET s; UP(); s = acc_sock(SOCK_DGRAM); same_everywhere("udp", s); CLOSES(s); }
TEST(cc_ni_same_for_listener)        { SOCKET s; UP(); s = acc_listener(NULL); same_everywhere("listener", s); CLOSES(s); }
TEST(cc_ni_same_for_connected_pair)  { UP(); PAIR(c, s); same_everywhere("client", c); same_everywhere("accepted", s); CLOSES(c); CLOSES(s); }
TEST(cc_ni_same_for_duplicate_handle)
{
    SOCKET s; HANDLE d = NULL;
    UP();
    s = acc_sock(SOCK_STREAM);
    UN(NtDuplicateObject)(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &d, 0, 0, 2);
    REQUIRE(d);
    same_everywhere("duplicate", (SOCKET)d);
    UN(NtClose)(d); CLOSES(s);
}
TEST(cc_ni_same_with_request_in_flight)
{
    pend_t p;
    UP();
    if (!acc_pend_start(&p, OP_RECV_UDP, NULL, 0)) { t_skip("could not queue"); acc_pend_done(&p); return; }
    same_everywhere("pending", p.target);
    EXPECT_ST(acc_pend_status(&p), ST_PENDING);       /* queries neither complete nor cancel the request */
    acc_pend_done(&p);
}
TEST(cc_ni_same_after_shutdown)
{
    PAIR(c, s);
    UP();
    U(shutdown)(c, SD_BOTH);
    same_everywhere("shutdown", c);
    CLOSES(c); CLOSES(s);
}
TEST(cc_ni_same_after_peer_reset)
{
    PAIR(c, s);
    UP();
    acc_rst_close(c);
    Sleep(50);
    same_everywhere("reset", s);
    CLOSES(s);
}

/* ---- closed handles -------------------------------------------------------------------------------------------- */
/* The class and length checks run before the handle is looked up, so on a closed handle a bad class or a short
 * length keeps its own status; every other request fails with STATUS_INVALID_HANDLE. */
TEST(cc_ni_closed_handle_status_order)
{
    SOCKET s; int c;
    UP();
    s = acc_sock(SOCK_STREAM);
    CLOSES(s);
    for (c = 0; c < 80; c++) {
        IO_STATUS_BLOCK io; char buf[64];
        unsigned long q = ni_q_ovl[c].c[4].st, w = ni_s_ovl[c].c[4].st;
        memset(buf, 0, sizeof buf);
        EXPECT_ST(UN(NtQueryInformationFile)((HANDLE)s, &io, buf, 64, c), (q == 0xc0000003ul || q == 0xc0000004ul) ? (LONG)q : ST_INVALID_HANDLE);
        EXPECT_ST(UN(NtSetInformationFile)((HANDLE)s, &io, buf, 64, c), (w == 0xc0000003ul || w == 0xc0000004ul) ? (LONG)w : ST_INVALID_HANDLE);
    }
}

/* ---- positions on synchronous handles are kept by the I/O manager ----------------------------------------- */
TEST(cc_ni_sync_position_roundtrip)
{
    SOCKET s; IO_STATUS_BLOCK io; LONGLONG pos = 0x1234;
    UP();
    s = acc_sock_sync(SOCK_DGRAM);
    EXPECT_ST(UN(NtSetInformationFile)((HANDLE)s, &io, &pos, 8, FI_Position), ST_SUCCESS);
    pos = -1;
    EXPECT_ST(UN(NtQueryInformationFile)((HANDLE)s, &io, &pos, 8, FI_Position), ST_SUCCESS);
    EXPECT_EQ(io.Information, 8);
    EXPECT_EQ(pos, 0x1234);
    CLOSES(s);
}
TEST(cc_ni_sync_position_starts_at_zero)
{
    SOCKET s; IO_STATUS_BLOCK io; LONGLONG pos = -1;
    UP();
    s = acc_sock_sync(SOCK_STREAM);
    EXPECT_ST(UN(NtQueryInformationFile)((HANDLE)s, &io, &pos, 8, FI_Position), ST_SUCCESS);
    EXPECT_EQ(pos, 0);
    CLOSES(s);
}

/* ---- access checks come from the handle, before the driver is asked --------------------------------------- */
TEST(cc_ni_basic_information_needs_read_attributes)
{
    SOCKET s; HANDLE d = NULL; IO_STATUS_BLOCK io; char buf[64] = {0};
    UP();
    s = acc_sock(SOCK_STREAM);
    UN(NtDuplicateObject)(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &d, SYNCHRONIZE, 0, 0);
    REQUIRE(d);
    EXPECT_ST(UN(NtQueryInformationFile)(d, &io, buf, 64, FI_Basic), ST_ACCESS_DENIED);
    EXPECT_ST(UN(NtSetInformationFile)(d, &io, buf, 64, FI_Basic), ST_ACCESS_DENIED);
    EXPECT_ST(UN(NtQueryInformationFile)((HANDLE)s, &io, buf, 64, FI_Basic), ST_NOT_IMPLEMENTED);
    UN(NtClose)(d); CLOSES(s);
}
TEST(cc_ni_access_information_needs_no_access)
{
    SOCKET s; HANDLE d = NULL; IO_STATUS_BLOCK io; ULONG a = 0xFFFFFFFF;
    UP();
    s = acc_sock(SOCK_STREAM);
    UN(NtDuplicateObject)(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &d, SYNCHRONIZE, 0, 0);
    REQUIRE(d);
    EXPECT_ST(UN(NtQueryInformationFile)(d, &io, &a, 4, FI_Access), ST_SUCCESS);
    EXPECT_EQ(a, SYNCHRONIZE);
    UN(NtClose)(d); CLOSES(s);
}
