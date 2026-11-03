/* inet_ntoa is the one name-conversion export that brings the stack up on its own.
 *
 * Called with no WSAStartup outstanding it starts Winsock 2.2 internally, formats the address into a
 * per-thread buffer, and releases that reference before returning; the caller's view of the process is
 * unchanged afterwards (no outstanding reference, other APIs still refuse with WSANOTINITIALISED).
 * Called with the stack up it just formats. The result lives in a thread-local buffer, so a second call on
 * the same thread overwrites the first and two threads never share one. */
#include "sc.h"

static const struct { unsigned char b[4]; const char *s; } kAddr[] = {
    {{0, 0, 0, 0}, "0.0.0.0"}, {{255, 255, 255, 255}, "255.255.255.255"}, {{127, 0, 0, 1}, "127.0.0.1"},
    {{1, 2, 3, 4}, "1.2.3.4"}, {{10, 20, 30, 40}, "10.20.30.40"}, {{100, 200, 0, 1}, "100.200.0.1"},
    {{192, 168, 1, 255}, "192.168.1.255"}, {{9, 99, 199, 9}, "9.99.199.9"}, {{0, 0, 0, 1}, "0.0.0.1"},
    {{1, 0, 0, 0}, "1.0.0.0"}, {{128, 128, 128, 128}, "128.128.128.128"}, {{224, 0, 0, 251}, "224.0.0.251"},
    {{169, 254, 0, 1}, "169.254.0.1"}, {{8, 8, 8, 8}, "8.8.8.8"}, {{172, 16, 0, 1}, "172.16.0.1"},
    {{99, 100, 101, 102}, "99.100.101.102"}, {{10, 0, 0, 10}, "10.0.0.10"}, {{100, 10, 1, 100}, "100.10.1.100"},
    {{255, 0, 255, 0}, "255.0.255.0"}, {{0, 255, 0, 255}, "0.255.0.255"},
};
#define NADDR ((int)ARRSZ(kAddr))

static struct in_addr in_of(int i)
{
    struct in_addr a;
    memcpy(&a, kAddr[i].b, 4);
    return a;
}

/* argv[1] = row, argv[2] = 0: no stack, 1: stack up, 2: stack was started and fully cleaned up again */
CHILD(ia_row)
{
    int i = argc > 1 ? atoi(argv[1]) : 0, mode = argc > 2 ? atoi(argv[2]) : 0;
    if (i < 0 || i >= NADDR) return 99;
    STEP(90, U(inet_ntoa) && U(WSAStartup) && U(WSACleanup) && U(socket));
    if (mode == 1) STEP(1, sc_up() == 0);
    if (mode == 2) { STEP(2, sc_up() == 0); STEP(3, U(WSACleanup)() == 0); }

    SETWSAERR(0);
    char *p = U(inet_ntoa)(in_of(i));
    STEP(4, p != NULL);
    STEP(5, !strcmp(p, kAddr[i].s));

    if (mode == 1) {
        STEP(6, U(WSACleanup)() == 0);           /* exactly the one reference we took */
    }
    SETWSAERR(0);
    STEP(7, U(WSACleanup)() == SOCKET_ERROR);    /* nothing is left over, in any mode */
    STEP(8, WSAERR() == WSANOTINITIALISED);
    SETWSAERR(0);
    STEP(9, U(socket)(AF_INET, SOCK_STREAM, 0) == INVALID_SOCKET);
    STEP(10, WSAERR() == WSANOTINITIALISED);
    return 0;
}
#define IA(i) \
    TEST(inet_ntoa_implicit_no_stack_##i) { REQUIRE(U(inet_ntoa)); RUN_CHILD("ia_row", #i " 0", 20000); } \
    TEST(inet_ntoa_with_stack_##i)        { REQUIRE(U(inet_ntoa)); RUN_CHILD("ia_row", #i " 1", 20000); } \
    TEST(inet_ntoa_after_cleanup_##i)     { REQUIRE(U(inet_ntoa)); RUN_CHILD("ia_row", #i " 2", 20000); }
IA(0) IA(1) IA(2) IA(3) IA(4) IA(5) IA(6) IA(7) IA(8) IA(9) IA(10) IA(11) IA(12) IA(13) IA(14) IA(15) IA(16) IA(17) IA(18) IA(19)

TEST(inet_ntoa_table_size)
{
    CHECKF(NADDR == 20, "table has %d rows but 20 row tests exist", NADDR);
}

/* ---- repeated implicit calls leave the process balanced ------------------------------------------------ */
CHILD(ia_repeat)
{
    for (int i = 0; i < 200; i++) {
        char *p = U(inet_ntoa)(in_of(i % NADDR));
        STEP(1, p && !strcmp(p, kAddr[i % NADDR].s));
    }
    SETWSAERR(0);
    STEP(2, U(WSACleanup)() == SOCKET_ERROR);
    STEP(3, WSAERR() == WSANOTINITIALISED);
    return 0;
}
TEST(inet_ntoa_repeated_implicit_calls_stay_balanced) { REQUIRE(U(inet_ntoa)); RUN_CHILD("ia_repeat", "", 30000); }

/* ---- a socket made by the caller is not disturbed by the implicit start/stop -------------------------- */
CHILD(ia_with_socket)
{
    STEP(1, sc_up() == 0);
    SOCKET s = U(socket)(AF_INET, SOCK_DGRAM, 0);
    STEP(2, s != INVALID_SOCKET);
    for (int i = 0; i < 10; i++) STEP(3, U(inet_ntoa)(in_of(i)) != NULL);
    int t = 0, len = sizeof t;
    STEP(4, U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&t, &len) == 0);
    STEP(5, t == SOCK_DGRAM);
    U(closesocket)(s);
    STEP(6, U(WSACleanup)() == 0);
    return 0;
}
TEST(inet_ntoa_does_not_disturb_running_stack) { REQUIRE(U(inet_ntoa)); RUN_CHILD("ia_with_socket", "", 20000); }

/* ---- the result buffer is per thread ------------------------------------------------------------------ */
static char *g_tp;
static char g_tcopy[32];
static DWORD WINAPI th_ntoa(LPVOID p)
{
    g_tp = U(inet_ntoa)(in_of(3));
    if (g_tp) lstrcpynA(g_tcopy, g_tp, sizeof g_tcopy);
    return 0;
}
CHILD(ia_buffers)
{
    STEP(1, sc_up() == 0);
    char *p1 = U(inet_ntoa)(in_of(3));
    STEP(2, p1 && !strcmp(p1, "1.2.3.4"));
    char *p2 = U(inet_ntoa)(in_of(4));
    STEP(3, p2 == p1);                           /* same thread, same buffer */
    STEP(4, !strcmp(p1, "10.20.30.40"));         /* the first result was overwritten */
    HANDLE h = CreateThread(NULL, 0, th_ntoa, NULL, 0, NULL);
    STEP(5, h != NULL);
    STEP(6, WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    CloseHandle(h);
    STEP(7, g_tp != NULL && !strcmp(g_tcopy, "1.2.3.4"));
    STEP(8, g_tp != p1);                         /* another thread has another buffer */
    STEP(9, !strcmp(p1, "10.20.30.40"));         /* and did not disturb ours */
    U(WSACleanup)();
    return 0;
}
TEST(inet_ntoa_buffer_is_per_thread) { REQUIRE(U(inet_ntoa)); RUN_CHILD("ia_buffers", "", 20000); }

/* ---- no other conversion/resolver export does this ---------------------------------------------------- */
CHILD(ia_others_do_not_autostart)
{
    char host[8];
    struct in_addr a;
    SETWSAERR(0);
    STEP(1, U(gethostname)(host, sizeof host) == SOCKET_ERROR);
    STEP(2, WSAERR() == WSANOTINITIALISED);
    SETWSAERR(0);
    STEP(3, U(gethostbyname)("localhost") == NULL);
    STEP(4, WSAERR() == WSANOTINITIALISED);
    /* pure parsers never need the stack */
    STEP(5, U(inet_addr)("127.0.0.1") == 0x0100007fu);
    STEP(6, U(inet_pton)(AF_INET, "9.8.7.6", &a) == 1);
    STEP(7, U(WSACleanup)() == SOCKET_ERROR);
    return 0;
}
TEST(inet_ntoa_is_the_only_autostarting_name_call) { REQUIRE(U(inet_ntoa)); RUN_CHILD("ia_others_do_not_autostart", "", 20000); }
