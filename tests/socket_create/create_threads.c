/* socket_create: socket creation and closing across threads and processes' error contexts.
 * A socket is process-wide: a handle created on one thread can be used and closed from any other, and it outlives
 * the thread that created it. The Winsock last-error value is per thread. Several threads creating and closing
 * sockets concurrently never see a failure and never get the same live handle twice. */
#include "sc.h"

typedef struct { SOCKET s[64]; int n; int af, ty; int err; } worker_t;
static DWORD WINAPI make_many(LPVOID p) {
    worker_t *w = (worker_t *)p;
    int i;
    if (!sc_up()) { w->err = -1; return 1; }
    for (i = 0; i < w->n; i++) {
        w->s[i] = sc_make(w->af, w->ty, 0, WSA_FLAG_OVERLAPPED);
        if (w->s[i] == INVALID_SOCKET) { w->err = sc_err(); return 2; }
    }
    return 0;
}
TEST(sockcreate_threads_socket_outlives_creating_thread) {
    worker_t w;
    HANDLE th;
    int i;
    SC_UP();
    memset(&w, 0, sizeof w);
    w.n = 3; w.af = AF_INET; w.ty = SOCK_STREAM;
    th = CreateThread(NULL, 0, make_many, &w, 0, NULL);
    CHECK(th != NULL);
    CHECK(WaitForSingleObject(th, 10000) == WAIT_OBJECT_0);
    CloseHandle(th);
    for (i = 0; i < 3; i++) {
        CHECK(w.s[i] != INVALID_SOCKET);
        SC_EQ(sc_sotype(w.s[i]), SOCK_STREAM);       /* the creating thread is gone; the socket is not */
        SC_EQ(U(closesocket)(w.s[i]), 0);
    }
}
TEST(sockcreate_threads_close_from_other_thread_then_enotsock) {
    worker_t w;
    HANDLE th;
    SC_UP();
    memset(&w, 0, sizeof w);
    w.n = 1; w.af = AF_INET6; w.ty = SOCK_DGRAM;
    th = CreateThread(NULL, 0, make_many, &w, 0, NULL);
    WaitForSingleObject(th, 10000);
    CloseHandle(th);
    SC_EQ(U(closesocket)(w.s[0]), 0);
    sc_seterr(0);
    CHECK(U(closesocket)(w.s[0]) == SOCKET_ERROR);
    SC_EQ(sc_err(), WSAENOTSOCK);
}
static worker_t g_w[4];
TEST(sockcreate_threads_concurrent_creation_yields_distinct_handles) {
    HANDLE th[4];
    int i, j, k, dup = 0, fails = 0;
    SC_UP();
    memset(g_w, 0, sizeof g_w);
    for (i = 0; i < 4; i++) {
        g_w[i].n = 40; g_w[i].af = (i & 1) ? AF_INET6 : AF_INET; g_w[i].ty = (i & 2) ? SOCK_DGRAM : SOCK_STREAM;
        th[i] = CreateThread(NULL, 0, make_many, &g_w[i], 0, NULL);
        CHECK(th[i] != NULL);
    }
    for (i = 0; i < 4; i++) {
        DWORD rc = 99;
        WaitForSingleObject(th[i], 20000);
        GetExitCodeThread(th[i], &rc);
        if (rc) fails++;
        CloseHandle(th[i]);
    }
    SC_EQ(fails, 0);
    for (i = 0; i < 4; i++)
        for (j = 0; j < g_w[i].n; j++)
            for (k = i; k < 4; k++) {
                int m;
                for (m = (k == i ? j + 1 : 0); m < g_w[k].n; m++)
                    if (g_w[i].s[j] == g_w[k].s[m] && g_w[i].s[j] != INVALID_SOCKET) dup++;
            }
    SC_EQ(dup, 0);
    for (i = 0; i < 4; i++)
        for (j = 0; j < g_w[i].n; j++) sc_close(g_w[i].s[j]);
}
static DWORD WINAPI churn(LPVOID p) {
    int i, bad = 0;
    (void)p;
    if (!sc_up()) return 1;
    for (i = 0; i < 150; i++) {
        SOCKET s = sc_make(AF_INET, (i & 1) ? SOCK_DGRAM : SOCK_STREAM, 0, i & 1);
        if (s == INVALID_SOCKET) { bad++; continue; }
        if (U(closesocket)(s) != 0) bad++;
    }
    return bad;
}
TEST(sockcreate_threads_concurrent_create_close_churn) {
    HANDLE th[4];
    int i, total = 0;
    SC_UP();
    for (i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, churn, NULL, 0, NULL);
    for (i = 0; i < 4; i++) {
        DWORD rc = 99;
        WaitForSingleObject(th[i], 30000);
        GetExitCodeThread(th[i], &rc);
        total += (int)rc;
        CloseHandle(th[i]);
    }
    SC_EQ(total, 0);
}
static DWORD WINAPI fail_once(LPVOID p) {
    SOCKET s;
    int *out = (int *)p;
    if (!sc_up()) return 1;
    sc_seterr(0);
    s = U(socket)(AF_INET, SOCK_SEQPACKET, 0);
    out[0] = (s == INVALID_SOCKET);
    out[1] = sc_err();
    return 0;
}
TEST(sockcreate_threads_last_error_is_per_thread) {
    int out[2] = {0, 0};
    HANDLE th;
    SC_UP();
    sc_seterr(WSAEMSGSIZE);
    th = CreateThread(NULL, 0, fail_once, out, 0, NULL);
    WaitForSingleObject(th, 10000);
    CloseHandle(th);
    SC_EQ(out[0], 1);
    SC_EQ(out[1], WSAESOCKTNOSUPPORT);
    SC_EQ(sc_err(), WSAEMSGSIZE);                    /* this thread's value was not disturbed */
}
static DWORD WINAPI use_in_thread(LPVOID p) {
    SOCKET s = (SOCKET)(ULONG_PTR)p;
    struct sockaddr_in a;
    int l = sizeof a;
    sc_loop4(&a);
    if (!sc_up()) return 1;
    if (U(bind)(s, (struct sockaddr *)&a, sizeof a)) return 2;
    if (U(getsockname)(s, (struct sockaddr *)&a, &l)) return 3;
    return a.sin_port ? 0 : 4;
}
TEST(sockcreate_threads_socket_usable_from_another_thread) {
    SOCKET s;
    HANDLE th;
    DWORD rc = 99;
    SC_UP();
    s = sc_make(AF_INET, SOCK_DGRAM, 0, 1);
    th = CreateThread(NULL, 0, use_in_thread, (LPVOID)(ULONG_PTR)s, 0, NULL);
    WaitForSingleObject(th, 10000);
    GetExitCodeThread(th, &rc);
    CloseHandle(th);
    SC_EQ(rc, 0);
    sc_close(s);
}
