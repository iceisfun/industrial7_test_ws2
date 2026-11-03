/* WSACancelAsyncRequest: the handles it rejects, the exclusive relation between a successful cancel and
 * the absence of the completion message, cancel after completion, repeated and cross-thread cancels, and
 * the state of the family when requests are cancelled in bulk. The outcome of cancelling a request that
 * may already be running is timing dependent, so those tests assert the relation (success <=> no
 * message) instead of one fixed outcome. */
#include "asm.h"

#define SOCKFAIL(call, werr) do { \
        int r_; int e_; U(WSASetLastError)(0); r_ = (call); e_ = a_err(); \
        CHECKF(r_ == SOCKET_ERROR, "%s returned %d", #call, r_); \
        CHECKF(e_ == (werr), "%s error %d want %d", #call, e_, (int)(werr)); } while (0)

static int cancel(HANDLE h, int *err)
{
    int r;
    U(WSASetLastError)(0);
    r = U(WSACancelAsyncRequest)(h);
    if (err) *err = a_err();
    return r;
}

static HANDLE quick_request(HWND w, UINT msg) { return U(WSAAsyncGetProtoByNumber)(w, msg, 6, NULL, 0); }

/* Once the async worker exists and is idle, the "current task" slot is empty, so a NULL handle matches it and
   the cancel is reported as a success. Make the worker exist first so the result does not depend on test order. */
ATEST(asm_cancel_null_handle_after_worker_started_succeeds)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE h; int e = -1;
    NEED(w);
    h = quick_request(w, ASM_WM);
    CHECK(h && a_take((WPARAM)h, ASM_WM, -1, 5000, NULL));
    EQ(cancel(NULL, &e), 0);
    EQ(e, 0);
}

ATEST(asm_cancel_unknown_small_handle)
{
    SOCKFAIL(U(WSACancelAsyncRequest)((HANDLE)(ULONG_PTR)0x7fffff01), WSAEINVAL);
}

ATEST(asm_cancel_minus_one_handle)
{
    SOCKFAIL(U(WSACancelAsyncRequest)(INVALID_HANDLE_VALUE), WSAEINVAL);
}

/* Task handles are not kernel objects: a real event handle is just another unknown number. */
ATEST(asm_cancel_kernel_handle_is_not_a_task)
{
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    SOCKFAIL(U(WSACancelAsyncRequest)(ev), WSAEINVAL);
    CloseHandle(ev);
}

ATEST(asm_cancel_after_completion_is_invalid)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE h; int e;
    NEED(w);
    h = quick_request(w, ASM_WM);
    CHECK(h && a_take((WPARAM)h, ASM_WM, -1, 5000, NULL));
    CHECK(cancel(h, &e) == SOCKET_ERROR);
    EQ(e, WSAEINVAL);
}

ATEST(asm_cancel_completed_request_does_not_repeat_message)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE h; int e;
    NEED(w);
    h = quick_request(w, ASM_WM);
    CHECK(h && a_take((WPARAM)h, ASM_WM, -1, 5000, NULL));
    cancel(h, &e);
    EQ(a_quiet(200), 0);
}

/* Cancelling succeeds exactly when no completion will be posted. */
ATEST(asm_cancel_immediate_relation)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE h; int e = 0, r, got;
    NEED(w);
    h = quick_request(w, ASM_WM);
    CHECK(h != NULL);
    r = cancel(h, &e);
    got = a_take((WPARAM)h, ASM_WM, -1, r == 0 ? 500 : 5000, NULL);
    CHECK(r == 0 ? !got : (r == SOCKET_ERROR && e == WSAEINVAL && got));
}

ATEST(asm_cancel_repeated_relation_table)
{
    HWND w = a_win(ASM_WIN_MSGONLY); int i;
    NEED(w);
    for (i = 0; i < 20; ++i) {
        HANDLE h = quick_request(w, ASM_WM); int e = 0, r, got;
        CHECKF(h != NULL, "round %d", i);
        if (!h) continue;
        r = cancel(h, &e);
        got = a_take((WPARAM)h, ASM_WM, -1, r == 0 ? 150 : 5000, NULL);
        if (r == 0) CHECKF(!got, "round %d: cancelled request still completed", i);
        else CHECKF(got && e == WSAEINVAL, "round %d: cancel failed (%d) but no completion (got %d)", i, e, got);
    }
}

ATEST(asm_cancel_second_cancel_always_fails)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE h; int e1, e2, r1, r2;
    NEED(w);
    h = quick_request(w, ASM_WM);
    CHECK(h != NULL);
    r1 = cancel(h, &e1);
    r2 = cancel(h, &e2);
    CHECK(r1 == 0 || (r1 == SOCKET_ERROR && e1 == WSAEINVAL));
    EQ(r2, SOCKET_ERROR);
    EQ(e2, WSAEINVAL);
    a_drain(300);
}

ATEST(asm_cancel_success_clears_error_state)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE h; int e;
    NEED(w);
    h = quick_request(w, ASM_WM);
    U(WSASetLastError)(WSAEBADF);
    if (U(WSACancelAsyncRequest)(h) == 0) { e = a_err(); CHECK(e == WSAEBADF || e == 0); }
    a_drain(300);
}

/* A burst of queued requests followed by a cancel of the newest one. */
ATEST(asm_cancel_last_of_burst_relation)
{
    enum { N = 300 };
    HANDLE hs[N]; HWND w = a_win(ASM_WIN_MSGONLY); int i, r, e = 0, expected;
    NEED(w);
    for (i = 0; i < N; ++i) hs[i] = quick_request(w, ASM_WM);
    r = cancel(hs[N - 1], &e);
    expected = (r == 0) ? N - 1 : N;
    {
        DWORD t0 = GetTickCount();
        while (a_total() < expected && GetTickCount() - t0 < 15000) a_pump(20);
    }
    a_pump(200);
    EQ(a_total(), expected);
    CHECK(r == 0 || e == WSAEINVAL);
    EQ(a_count((WPARAM)hs[N - 1], ASM_WM), r == 0 ? 0 : 1);
}

ATEST(asm_cancel_middle_of_burst_removes_only_that_request)
{
    enum { N = 200 };
    HANDLE hs[N]; HWND w = a_win(ASM_WIN_MSGONLY); int i, r, e = 0, expected;
    NEED(w);
    for (i = 0; i < N; ++i) hs[i] = quick_request(w, ASM_WM);
    r = cancel(hs[N / 2 + 40], &e);
    expected = (r == 0) ? N - 1 : N;
    {
        DWORD t0 = GetTickCount();
        while (a_total() < expected && GetTickCount() - t0 < 15000) a_pump(20);
    }
    a_pump(200);
    EQ(a_total(), expected);
    for (i = 0; i < N; ++i) {
        int want = (r == 0 && i == N / 2 + 40) ? 0 : 1;
        if (a_count((WPARAM)hs[i], ASM_WM) != want) { CHECKF(0, "request %d has %d messages, want %d", i, a_count((WPARAM)hs[i], ASM_WM), want); break; }
    }
}

ATEST(asm_cancel_every_other_request_in_burst)
{
    enum { N = 160 };
    HANDLE hs[N]; HWND w = a_win(ASM_WIN_MSGONLY); int i, ok[N], cancelled = 0, e;
    NEED(w);
    for (i = 0; i < N; ++i) hs[i] = quick_request(w, ASM_WM);
    for (i = N - 1; i >= 0; i -= 2) { ok[i] = cancel(hs[i], &e) == 0; cancelled += ok[i]; CHECK(ok[i] || e == WSAEINVAL); }
    {
        DWORD t0 = GetTickCount();
        while (a_total() < N - cancelled && GetTickCount() - t0 < 15000) a_pump(20);
    }
    a_pump(200);
    EQ(a_total(), N - cancelled);
    for (i = 0; i < N; ++i) {
        int want = ((i % 2) == ((N - 1) % 2) && ok[i]) ? 0 : 1;
        if (a_count((WPARAM)hs[i], ASM_WM) != want) { CHECKF(0, "request %d has %d messages, want %d", i, a_count((WPARAM)hs[i], ASM_WM), want); break; }
    }
}

/* Requests issued after a cancel are unaffected by it. */
ATEST(asm_cancel_does_not_poison_later_requests)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE h1, h2; int i;
    NEED(w);
    for (i = 0; i < 10; ++i) {
        h1 = quick_request(w, ASM_WM);
        cancel(h1, NULL);
        h2 = quick_request(w, ASM_WM);
        CHECKF(h2 && a_take((WPARAM)h2, ASM_WM, -1, 5000, NULL), "round %d", i);
        a_drain(60);
    }
}

struct cancel_arg { HANDLE h; int r; int e; };
static DWORD WINAPI cancel_thread(LPVOID p)
{
    struct cancel_arg *a = p;
    a->r = cancel(a->h, &a->e);
    return 0;
}

/* Task handles are process wide: another thread may cancel what this one started. */
ATEST(asm_cancel_from_another_thread_relation)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE h, th; struct cancel_arg arg; int got;
    NEED(w);
    h = quick_request(w, ASM_WM);
    arg.h = h; arg.r = -2; arg.e = 0;
    th = CreateThread(NULL, 0, cancel_thread, &arg, 0, NULL);
    NEED(th);
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    got = a_take((WPARAM)h, ASM_WM, -1, arg.r == 0 ? 400 : 5000, NULL);
    CHECK(arg.r == 0 ? !got : (arg.r == SOCKET_ERROR && arg.e == WSAEINVAL && got));
}

ATEST(asm_cancel_of_other_threads_completed_request)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE h, th; struct cancel_arg arg;
    NEED(w);
    h = quick_request(w, ASM_WM);
    CHECK(h && a_take((WPARAM)h, ASM_WM, -1, 5000, NULL));
    arg.h = h; arg.r = -2; arg.e = 0;
    th = CreateThread(NULL, 0, cancel_thread, &arg, 0, NULL);
    NEED(th);
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    EQ(arg.r, SOCKET_ERROR);
    EQ(arg.e, WSAEINVAL);
}

/* Cancelling with a handle that was never issued does not disturb a request in flight. */
ATEST(asm_cancel_bogus_handle_leaves_real_request_alone)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE h;
    NEED(w);
    h = quick_request(w, ASM_WM);
    SOCKFAIL(U(WSACancelAsyncRequest)((HANDLE)(ULONG_PTR)0x6fffffff), WSAEINVAL);
    CHECK(h && a_take((WPARAM)h, ASM_WM, -1, 5000, NULL));
}

/* Host and service requests are cancelled through the same entry point. */
ATEST(asm_cancel_applies_to_every_request_kind)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE hs[6]; int i; unsigned char a[4] = { 127, 0, 0, 1 };
    NEED(w);
    hs[0] = U(WSAAsyncGetHostByName)(w, ASM_WM, "127.0.0.1", NULL, 0);
    hs[1] = U(WSAAsyncGetHostByAddr)(w, ASM_WM, (char *)a, 4, AF_INET, NULL, 0);
    hs[2] = U(WSAAsyncGetServByName)(w, ASM_WM, "http", "tcp", NULL, 0);
    hs[3] = U(WSAAsyncGetServByPort)(w, ASM_WM, U(htons)(80), "tcp", NULL, 0);
    hs[4] = U(WSAAsyncGetProtoByName)(w, ASM_WM, "tcp", NULL, 0);
    hs[5] = U(WSAAsyncGetProtoByNumber)(w, ASM_WM, 6, NULL, 0);
    for (i = 5; i >= 0; --i) {
        int e = 0, r, got;
        CHECKF(hs[i] != NULL, "kind %d", i);
        if (!hs[i]) continue;
        r = cancel(hs[i], &e);
        got = a_take((WPARAM)hs[i], ASM_WM, -1, r == 0 ? 120 : 8000, NULL);
        if (r == 0) CHECKF(!got, "kind %d: completed after successful cancel", i);
        else CHECKF(got && e == WSAEINVAL, "kind %d: cancel error %d, completion %d", i, e, got);
    }
}

/* Cancelling a request whose window is gone is the same as cancelling any other. */
ATEST(asm_cancel_request_with_destroyed_window)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE h; int e = 0, r;
    NEED(w);
    h = quick_request(w, ASM_WM);
    a_destroy(w);
    r = cancel(h, &e);
    CHECK(r == 0 || (r == SOCKET_ERROR && e == WSAEINVAL));
}

/* Cancel-and-reissue many times: handles never repeat while they are live. */
ATEST(asm_cancel_reissued_handles_are_fresh)
{
    HWND w = a_win(ASM_WIN_MSGONLY); HANDLE prev = NULL; int i;
    NEED(w);
    for (i = 0; i < 25; ++i) {
        HANDLE h = quick_request(w, ASM_WM);
        CHECKF(h != NULL && h != prev, "round %d", i);
        cancel(h, NULL);
        prev = h;
    }
    a_drain(500);
}
