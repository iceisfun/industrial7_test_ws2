/* WSALookupServiceBeginW / WSALookupServiceNextW / WSALookupServiceEnd.
 * Measures: the argument-validation errors of Begin and End, and that a "network list" query
 * (an empty query set with LUP_RETURN_ALL | LUP_DEEP) opens a handle whose enumeration ends with
 * WSA_E_NO_MORE and closes cleanly. The number of networks is environment data and never asserted. */
#include "l2.h"

typedef INT (WSAAPI *lbegin_fn)(LPWSAQUERYSETW, DWORD, LPHANDLE);
typedef INT (WSAAPI *lnext_fn)(HANDLE, DWORD, LPDWORD, LPWSAQUERYSETW);
typedef INT (WSAAPI *lend_fn)(HANDLE);

#define LB ((lbegin_fn)t_proc_in("ws2_32.dll", "WSALookupServiceBeginW"))
#define LN ((lnext_fn)t_proc_in("ws2_32.dll", "WSALookupServiceNextW"))
#define LE ((lend_fn)t_proc_in("ws2_32.dll", "WSALookupServiceEnd"))

/* A NULL query set or NULL handle pointer is not rejected by Begin on Windows 10: it faults, so
 * those argument shapes are deliberately not exercised here. */

TEST(lookup_begin_zero_size_query_invalid_parameter) {
    lbegin_fn b = LB; WSAQUERYSETW qs; HANDLE h = NULL; INT r;
    REQUIRE(b); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA();
    memset(&qs, 0, sizeof qs); /* dwSize == 0 */
    U(WSASetLastError)(0);
    r = b(&qs, 0, &h);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), ERROR_INVALID_PARAMETER);
}

TEST(lookup_end_null_handle_invalid_handle) {
    lend_fn e = LE; INT r;
    REQUIRE(e); REQUIRE(U(WSASetLastError)); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA();
    U(WSASetLastError)(0);
    r = e(NULL);
    EXPECT_EQ(r, SOCKET_ERROR);
    EXPECT_EQ(U(WSAGetLastError)(), ERROR_INVALID_HANDLE);
}

TEST(lookup_network_list_enumerates_and_ends) {
    lbegin_fn b = LB; lnext_fn n = LN; lend_fn e = LE;
    char buf[4096]; WSAQUERYSETW *qs = (WSAQUERYSETW *)buf, query;
    HANDLE h = (HANDLE)(ULONG_PTR)0xdeadbeef; INT r; int rounds = 0, ended = 0;
    REQUIRE(b); REQUIRE(n); REQUIRE(e); REQUIRE(U(WSAGetLastError)); L2_NEED_WSA();
    memset(&query, 0, sizeof query);
    query.dwSize = sizeof query;
    r = b(&query, LUP_RETURN_ALL | LUP_DEEP, &h);
    EXPECT_EQ(r, 0);
    if (r != 0) return;
    CHECK(h != (HANDLE)(ULONG_PTR)0xdeadbeef);
    while (rounds++ < 256) {
        DWORD size = sizeof buf;
        memset(buf, 0, sizeof buf);
        if (n(h, 0, &size, qs) == SOCKET_ERROR) {
            EXPECT_EQ(U(WSAGetLastError)(), WSA_E_NO_MORE);
            ended = 1;
            break;
        }
    }
    CHECK(ended);
    r = e(h);
    EXPECT_EQ(r, 0);
}
