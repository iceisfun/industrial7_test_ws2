/* lift_04: WSAStartup / WSACleanup state machine.
 * Each scenario runs in a child process so the process-wide startup count begins at zero and the
 * test can assert on the transition from "never started" to "started" to "cleaned up".
 * Measures: WSANOTINITIALISED before any startup, startup reference counting, destruction of
 * every socket (including duplicated handles) when the last WSACleanup runs, and the error from
 * an unbalanced WSACleanup. A child exits with 0 on success or the number of the first failing step. */
#include "l4.h"

#define STEP(n, c) do { if (!(c)) return (n); } while (0)

/* ---- before any startup ---- */
CHILD(wsa_never_started)
{
    SOCKET s;
    WSADATA d;
    (void)d;
    U(WSASetLastError)(0xdeadbeef);
    s = U(WSASocketA)(0, 0, 0, NULL, 0, 0);
    STEP(1, s == INVALID_SOCKET);
    STEP(2, U(WSAGetLastError)() == WSANOTINITIALISED);

    U(WSASetLastError)(0xdeadbeef);
    STEP(3, U(gethostbyname)("localhost") == NULL);
    STEP(4, U(WSAGetLastError)() == WSANOTINITIALISED);

    U(WSASetLastError)(0xdeadbeef);
    s = U(socket)(AF_INET, SOCK_STREAM, 0);
    STEP(5, s == INVALID_SOCKET);
    STEP(6, U(WSAGetLastError)() == WSANOTINITIALISED);

    U(WSASetLastError)(0xdeadbeef);
    STEP(7, U(WSACleanup)() == SOCKET_ERROR);
    STEP(8, U(WSAGetLastError)() == WSANOTINITIALISED);
    return 0;
}
TEST(startup_calls_before_startup_fail_notinitialised)
{
    EQ(t_run_child("wsa_never_started", "", 30000), 0);
}

/* ---- sockets die with the last WSACleanup ---- */
#define NPAIR 8
CHILD(wsa_cleanup_destroys_sockets)
{
    WSADATA d;
    struct { SOCKET src, dst, dup_src, dup_dst; } p[NPAIR];
    int i, j;
    WSAPROTOCOL_INFOA info;

    STEP(1, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    STEP(2, U(gethostbyname)("localhost") != NULL);
    for (i = 0; i < NPAIR; i++) {
        STEP(3, make_pair(&p[i].src, &p[i].dst, WSA_FLAG_OVERLAPPED));
        memset(&info, 0, sizeof info);
        STEP(4, U(WSADuplicateSocketA)(p[i].src, GetCurrentProcessId(), &info) == 0);
        p[i].dup_src = U(WSASocketA)(0, 0, 0, &info, 0, 0);
        STEP(5, p[i].dup_src != INVALID_SOCKET);
        memset(&info, 0, sizeof info);
        STEP(6, U(WSADuplicateSocketA)(p[i].dst, GetCurrentProcessId(), &info) == 0);
        p[i].dup_dst = U(WSASocketA)(0, 0, 0, &info, 0, 0);
        STEP(7, p[i].dup_dst != INVALID_SOCKET);
    }
    STEP(8, U(send)(p[0].src, "TEST", 4, 0) == 4);

    U(WSACleanup)();
    STEP(9, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);

    U(WSASetLastError)(0);
    STEP(10, U(send)(p[0].src, "TEST", 4, 0) == SOCKET_ERROR);
    STEP(11, U(WSAGetLastError)() == WSAENOTSOCK);
    U(WSASetLastError)(0);
    STEP(12, U(send)(p[0].dst, "TEST", 4, 0) == SOCKET_ERROR);
    STEP(13, U(WSAGetLastError)() == WSAENOTSOCK);

    for (i = 0; i < NPAIR; i++) {
        for (j = 0; j < 4; j++) {
            struct sockaddr_in a; int len = sizeof a;
            SOCKET s = j == 0 ? p[i].src : j == 1 ? p[i].dup_src : j == 2 ? p[i].dst : p[i].dup_dst;
            U(WSASetLastError)(0);
            STEP(14, U(getsockname)(s, (struct sockaddr *)&a, &len) == SOCKET_ERROR);
            STEP(15, U(WSAGetLastError)() == WSAENOTSOCK);
        }
    }
    for (i = 0; i < NPAIR; i++) {
        U(closesocket)(p[i].src); U(closesocket)(p[i].dst);
        U(closesocket)(p[i].dup_src); U(closesocket)(p[i].dup_dst);
    }
    STEP(16, U(WSACleanup)() == 0);
    U(WSASetLastError)(0xdeadbeef);
    STEP(17, U(WSACleanup)() == SOCKET_ERROR);
    STEP(18, U(WSAGetLastError)() == WSANOTINITIALISED);
    return 0;
}
TEST(startup_cleanup_destroys_all_sockets)
{
    DWORD rc = t_run_child("wsa_cleanup_destroys_sockets", "", 60000);
    CHECKF(rc == 0, "child failed at step %lu", rc);
}

/* ---- reference counting ---- */
CHILD(wsa_refcount)
{
    WSADATA d;
    SOCKET s;
    int t = 0, sz = sizeof t;

    STEP(1, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    STEP(2, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    s = U(socket)(AF_INET, SOCK_STREAM, 0);
    STEP(3, s != INVALID_SOCKET);
    STEP(4, U(WSACleanup)() == 0);
    /* still one reference: the socket survives and the stack still answers */
    STEP(5, U(getsockopt)(s, SOL_SOCKET, SO_TYPE, (char *)&t, &sz) == 0);
    STEP(6, t == SOCK_STREAM);
    STEP(7, U(WSACleanup)() == 0);
    U(WSASetLastError)(0);
    STEP(8, U(WSACleanup)() == SOCKET_ERROR);
    STEP(9, U(WSAGetLastError)() == WSANOTINITIALISED);
    return 0;
}
TEST(startup_reference_count_keeps_sockets_alive)
{
    DWORD rc = t_run_child("wsa_refcount", "", 30000);
    CHECKF(rc == 0, "child failed at step %lu", rc);
}
