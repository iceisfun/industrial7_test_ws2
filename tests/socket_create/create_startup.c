/* socket_create: creation and closing relative to the WSAStartup / WSACleanup window.
 * Each scenario runs in a child process so that the process-wide startup count begins at zero. A child returns 0
 * when everything matched, a small step number for the first mismatch, or (for the recording scenarios) a value
 * that the parent turns into a note. Before the first WSAStartup and after the last WSACleanup the creation
 * functions fail with WSANOTINITIALISED (10093); once started again they work normally. */
#include "sc.h"

#define STEP(n, c) do { if (!(c)) return (n); } while (0)

CHILD(sockcreate_nostartup_create) {
    SOCKET s;
    sc_seterr(0);
    s = U(WSASocketW)(AF_INET, SOCK_STREAM, 0, NULL, 0, 0);
    STEP(1, s == INVALID_SOCKET);
    STEP(2, sc_err() == WSANOTINITIALISED);
    sc_seterr(0);
    s = U(WSASocketA)(AF_INET, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    STEP(3, s == INVALID_SOCKET);
    STEP(4, sc_err() == WSANOTINITIALISED);
    sc_seterr(0);
    s = U(socket)(AF_INET6, SOCK_STREAM, 0);
    STEP(5, s == INVALID_SOCKET);
    STEP(6, sc_err() == WSANOTINITIALISED);
    /* the failure is reported before any family/type validation */
    sc_seterr(0);
    s = U(socket)(SC_BAD, SC_BAD, SC_BAD);
    STEP(7, s == INVALID_SOCKET);
    STEP(8, sc_err() == WSANOTINITIALISED);
    sc_seterr(0);
    s = U(WSASocketW)(AF_UNSPEC, 0, 0, NULL, 0, 0);
    STEP(9, s == INVALID_SOCKET);
    STEP(10, sc_err() == WSANOTINITIALISED);
    sc_seterr(0);
    s = U(WSASocketW)(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, NULL, 0, 0);
    STEP(11, s == INVALID_SOCKET);
    STEP(12, sc_err() == WSANOTINITIALISED);
    return 0;
}
TEST(sockcreate_startup_creation_before_startup_is_notinitialised) {
    SC_EQ(t_run_child("sockcreate_nostartup_create", "", 30000), 0);
}

CHILD(sockcreate_nostartup_close) {
    int r;
    sc_seterr(0);
    r = U(closesocket)(INVALID_SOCKET);
    if (r != SOCKET_ERROR) return 250;
    return (int)(sc_err() - 10000);
}
TEST(sockcreate_startup_closesocket_before_startup_recorded) {
    DWORD rc = t_run_child("sockcreate_nostartup_close", "", 30000);
    t_note("closesocket(INVALID_SOCKET) before WSAStartup -> error %ld", (long)rc + 10000);
    CHECK(rc < 250);
    SC_EQ(rc + 10000, WSANOTINITIALISED);
}

CHILD(sockcreate_after_cleanup) {
    WSADATA d;
    SOCKET s, t;
    STEP(1, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    s = U(socket)(AF_INET, SOCK_STREAM, 0);
    STEP(2, s != INVALID_SOCKET);
    STEP(3, U(WSACleanup)() == 0);
    sc_seterr(0);
    t = U(socket)(AF_INET, SOCK_STREAM, 0);
    STEP(4, t == INVALID_SOCKET);
    STEP(5, sc_err() == WSANOTINITIALISED);
    sc_seterr(0);
    t = U(WSASocketW)(AF_INET, SOCK_DGRAM, 0, NULL, 0, 1);
    STEP(6, t == INVALID_SOCKET);
    STEP(7, sc_err() == WSANOTINITIALISED);
    /* a handle that died with the cleanup is not usable once the stack is up again */
    STEP(8, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    STEP(9, sc_sotype(s) == -1);
    STEP(10, sc_err() == WSAENOTSOCK);
    t = U(socket)(AF_INET, SOCK_STREAM, 0);
    STEP(11, t != INVALID_SOCKET);
    STEP(12, sc_sotype(t) == SOCK_STREAM);
    STEP(13, U(closesocket)(t) == 0);
    STEP(14, U(WSACleanup)() == 0);
    return 0;
}
TEST(sockcreate_startup_creation_after_last_cleanup_is_notinitialised) {
    SC_EQ(t_run_child("sockcreate_after_cleanup", "", 30000), 0);
}

CHILD(sockcreate_nested_startup) {
    WSADATA d;
    SOCKET s;
    STEP(1, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    STEP(2, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    STEP(3, U(WSACleanup)() == 0);
    s = U(socket)(AF_INET, SOCK_DGRAM, 0);                 /* one reference is left */
    STEP(4, s != INVALID_SOCKET);
    STEP(5, U(closesocket)(s) == 0);
    STEP(6, U(WSACleanup)() == 0);
    sc_seterr(0);
    STEP(7, U(socket)(AF_INET, SOCK_DGRAM, 0) == INVALID_SOCKET);
    STEP(8, sc_err() == WSANOTINITIALISED);
    return 0;
}
TEST(sockcreate_startup_nested_startup_keeps_creation_working) {
    SC_EQ(t_run_child("sockcreate_nested_startup", "", 30000), 0);
}

CHILD(sockcreate_startup_version) {
    static const WORD vers[] = {0x0101, 0x0002, 0x0202};
    unsigned i;
    for (i = 0; i < 3; i++) {
        WSADATA d;
        SOCKET s;
        STEP(1 + i * 4, U(WSAStartup)(vers[i], &d) == 0);
        s = U(WSASocketW)(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
        STEP(2 + i * 4, s != INVALID_SOCKET);
        STEP(3 + i * 4, sc_sotype(s) == SOCK_STREAM);
        U(closesocket)(s);
        STEP(4 + i * 4, U(WSACleanup)() == 0);
    }
    return 0;
}
TEST(sockcreate_startup_any_requested_version_allows_creation) {
    SC_EQ(t_run_child("sockcreate_startup_version", "", 30000), 0);
}

CHILD(sockcreate_exit_with_open_sockets) {
    WSADATA d;
    int i;
    STEP(1, U(WSAStartup)(MAKEWORD(2, 2), &d) == 0);
    for (i = 0; i < 20; i++) STEP(2, U(socket)(AF_INET, i & 1 ? SOCK_DGRAM : SOCK_STREAM, 0) != INVALID_SOCKET);
    return 0;                                              /* leave them open: process exit reclaims them */
}
TEST(sockcreate_startup_process_exit_with_open_sockets_is_clean) {
    SC_EQ(t_run_child("sockcreate_exit_with_open_sockets", "", 30000), 0);
}
