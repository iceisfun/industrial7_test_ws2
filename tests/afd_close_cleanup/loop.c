/* Bulk create / use / close loops with the process handle count as the leak oracle, plus plain statuses for
 * closing handles that are not (or no longer) endpoints. Loops are small and bounded.
 */
#include "acc.h"

#define ROUNDS 24

/* run `body` ROUNDS times after one warm-up round; the handle count after must equal the count before */
#define LEAK_LOOP(...) do { int r_; DWORD before_, after_; \
    { __VA_ARGS__ } \
    before_ = acc_handles(); \
    for (r_ = 0; r_ < ROUNDS; r_++) { __VA_ARGS__ } \
    after_ = acc_handles(); \
    EXPECT_EQ(after_, before_); } while (0)

TEST(cc_loop_tcp_create_close_no_handle_growth)
{
    UP();
    LEAK_LOOP({ SOCKET s = acc_sock(SOCK_STREAM); CHECK(s != INVALID_SOCKET); CLOSES(s); });
}
TEST(cc_loop_udp_create_close_no_handle_growth)
{
    UP();
    LEAK_LOOP({ SOCKET s = acc_sock(SOCK_DGRAM); CHECK(s != INVALID_SOCKET); CLOSES(s); });
}
TEST(cc_loop_sync_create_close_no_handle_growth)
{
    UP();
    LEAK_LOOP({ SOCKET s = acc_sock_sync(SOCK_STREAM); CHECK(s != INVALID_SOCKET); CLOSES(s); });
}
TEST(cc_loop_closehandle_no_handle_growth)
{
    UP();
    LEAK_LOOP({ SOCKET s = acc_sock(SOCK_STREAM); CHECK(CloseHandle((HANDLE)s)); });
}
TEST(cc_loop_ntclose_no_handle_growth)
{
    UP();
    LEAK_LOOP({ SOCKET s = acc_sock(SOCK_STREAM); CHECK(UN(NtClose)((HANDLE)s) == 0); });
}
TEST(cc_loop_pair_no_handle_growth)
{
    UP();
    LEAK_LOOP({ SOCKET c, s; if (acc_pair(&c, &s)) { CLOSES(c); CLOSES(s); } else CHECK(0); });
}
TEST(cc_loop_pair_with_data_no_handle_growth)
{
    UP();
    LEAK_LOOP({ SOCKET c, s; char b[4]; int e; if (acc_pair(&c, &s)) { U(send)(c, "abc", 3, 0); acc_recv(s, b, 3, &e); CLOSES(s); CLOSES(c); } else CHECK(0); });
}
TEST(cc_loop_rst_pair_no_handle_growth)
{
    UP();
    LEAK_LOOP({ SOCKET c, s; if (acc_pair(&c, &s)) { acc_rst_close(c); CLOSES(s); } else CHECK(0); });
}
TEST(cc_loop_listener_no_handle_growth)
{
    UP();
    LEAK_LOOP({ SOCKET l = acc_listener(NULL); CHECK(l != INVALID_SOCKET); CLOSES(l); });
}
TEST(cc_loop_duplicate_no_handle_growth)
{
    UP();
    LEAK_LOOP({ SOCKET s = acc_sock(SOCK_STREAM); HANDLE d = NULL;
        UN(NtDuplicateObject)(GetCurrentProcess(), (HANDLE)s, GetCurrentProcess(), &d, 0, 0, 2);
        CHECK(d != NULL); CLOSES(s); UN(NtClose)(d); });
}
TEST(cc_loop_port_association_no_handle_growth)
{
    HANDLE p;
    UP();
    p = acc_port();
    REQUIRE(p);
    LEAK_LOOP({ SOCKET s = acc_sock(SOCK_STREAM); CHECK(CreateIoCompletionPort((HANDLE)s, p, 1, 0) == p); CLOSES(s); });
    CloseHandle(p);
}
TEST(cc_loop_pending_request_no_handle_growth)
{
    UP();
    LEAK_LOOP({ pend_t p; if (acc_pend_start(&p, OP_RECV_UDP, NULL, 0)) { CLOSES(p.target); p.target = INVALID_SOCKET; acc_pend_wait(&p, ACC_WAIT); } acc_pend_done(&p); });
}
TEST(cc_loop_pending_with_port_no_handle_growth)
{
    HANDLE port;
    UP();
    port = acc_port();
    REQUIRE(port);
    LEAK_LOOP({ pend_t p; if (acc_pend_start(&p, OP_RECV_UDP, port, 3)) {
        ULONG_PTR k, a; IO_STATUS_BLOCK io;
        CLOSES(p.target); p.target = INVALID_SOCKET; acc_remove(port, &k, &a, &io, ACC_WAIT); } acc_pend_done(&p); });
    CloseHandle(port);
}
TEST(cc_loop_accept_pending_no_handle_growth)
{
    UP();
    LEAK_LOOP({ pend_t p; if (acc_pend_start(&p, OP_ACCEPT, NULL, 0)) { CLOSES(p.target); p.target = INVALID_SOCKET; acc_pend_wait(&p, ACC_WAIT); } acc_pend_done(&p); });
}

/* Everything created in one go and released in reverse: also balanced. */
TEST(cc_loop_batch_of_endpoints_released_balanced)
{
    SOCKET s[ROUNDS]; DWORD before, after; int i;
    UP();
    { SOCKET w = acc_sock(SOCK_STREAM); CLOSES(w); }
    before = acc_handles();
    for (i = 0; i < ROUNDS; i++) { s[i] = acc_sock(i & 1 ? SOCK_DGRAM : SOCK_STREAM); CHECK(s[i] != INVALID_SOCKET); }
    EXPECT_EQ(acc_handles(), before + ROUNDS);
    for (i = ROUNDS - 1; i >= 0; i--) CLOSES(s[i]);
    after = acc_handles();
    EXPECT_EQ(after, before);
}

/* Every endpoint is exactly one handle; the value never repeats among live endpoints. */
TEST(cc_loop_live_endpoints_distinct_values)
{
    SOCKET s[ROUNDS]; int i, j, dup = 0;
    UP();
    for (i = 0; i < ROUNDS; i++) s[i] = acc_sock(SOCK_STREAM);
    for (i = 0; i < ROUNDS; i++) for (j = i + 1; j < ROUNDS; j++) if (s[i] == s[j]) dup++;
    EXPECT_EQ(dup, 0);
    for (i = 0; i < ROUNDS; i++) { CHECK(s[i] % 4 == 0); CLOSES(s[i]); }
}

/* ---- closing things that are not (or are no longer) endpoints ---------------------------------------------- */
TEST(cc_close_nt_status_matrix)
{
    SOCKET s; HANDLE ev;
    UP();
    s = acc_sock(SOCK_STREAM);
    EXPECT_ST(UN(NtClose)((HANDLE)s), ST_SUCCESS);
    EXPECT_ST(UN(NtClose)((HANDLE)s), ST_INVALID_HANDLE);                    /* second close */
    EXPECT_ST(UN(NtClose)(NULL), ST_INVALID_HANDLE);
    EXPECT_ST(UN(NtClose)((HANDLE)(ULONG_PTR)0x7ffc), ST_INVALID_HANDLE);
    ev = acc_event();
    EXPECT_ST(UN(NtClose)(ev), ST_SUCCESS);
}

TEST(cc_close_win32_error_matrix)
{
    SOCKET s;
    UP();
    s = acc_sock(SOCK_STREAM);
    CHECK(CloseHandle((HANDLE)s));
    SetLastError(0);
    CHECK(!CloseHandle((HANDLE)s)); EXPECT_ERR(ERROR_INVALID_HANDLE);
}

/* A successful closesocket clears the Winsock error state of the thread. */
TEST(cc_close_success_clears_winsock_error)
{
    SOCKET s;
    UP();
    s = acc_sock(SOCK_STREAM);
    WSETERR(WSAEINVAL);
    EXPECT_EQ(CLOSES(s), 0);
    EXPECT_EQ(WERR(), 0);
}

/* closesocket on a handle that is a live non-socket object fails WSAENOTSOCK and leaves the object open. */
TEST(cc_close_closesocket_on_event_keeps_handle)
{
    HANDLE ev; DWORD f;
    UP();
    ev = acc_event();
    WSETERR(0);
    CHECK(CLOSES((SOCKET)ev) == SOCKET_ERROR); EXPECT_EQ(WERR(), WSAENOTSOCK);
    CHECK(GetHandleInformation(ev, &f));
    CloseHandle(ev);
}
