/* Shared helpers for the async_select_messages area: window-message driven Winsock notification
 * (WSAAsyncSelect) and the WSAAsyncGet* request family.
 *
 * Everything under test is reached with LoadLibrary -> GetProcAddress through U(); user32 services
 * (windows and the message pump) are resolved the same way via UU().  Notifications arrive as window
 * messages; every window created here uses one window procedure that appends each message in the
 * application range (0x400..0xFFFF) to a process-wide log, so a test can pump on any thread and then
 * inspect which messages were delivered, in which order, to which window and thread. */
#ifndef ASM_H
#define ASM_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

/* Evaluates the expression once (the harness macros evaluate their arguments twice). */
#define EQ(a, b) do { long long a_ = (long long)(a); t_check(a_ == (long long)(b), __FILE__, __LINE__, #a " == " #b, "got %lld want %lld", a_, (long long)(b)); } while (0)
#define NEED(c) do { if (!(c)) { t_skip("prerequisite unavailable: " #c); return; } } while (0)
#define UU(name) ((__typeof__(&name))t_proc_in("user32.dll", #name))

#define ASM_WIN_MSGONLY  0   /* message-only window                  */
#define ASM_WIN_POPUP    1   /* top-level popup, never shown         */
#define ASM_WIN_OVERLAP  2   /* top-level overlapped, never shown    */
#define ASM_WIN_CHILD    3   /* child of a hidden popup              */

#define ASM_WM   (WM_USER + 50)   /* default notification message used by the tests */
#define ASM_WM2  (WM_USER + 51)
#define ASM_LOOP_BE 0x0100007Fu   /* 127.0.0.1 in network order on a little-endian host */

typedef struct {
    HWND hwnd; UINT msg; WPARAM wp; LPARAM lp; DWORD tid; LONG seq; int used;
} asm_rec;

/* Test frame: WSAStartup once, empty log, and everything the test tracked is released afterwards. */
int  a_begin(void);
void a_end(void);
#define ATEST(n) \
    static void abody_##n(void); \
    TEST(n) { if (!a_begin()) return; abody_##n(); a_end(); } \
    static void abody_##n(void)

/* ---- thin wrappers over the exports under test ------------------------------------------------ */
int    a_err(void);
SOCKET a_sock(int af, int type, int proto);          /* tracked; INVALID_SOCKET on failure */
void   a_close(SOCKET s);                            /* closesocket + untrack */
int    a_select(SOCKET s, HWND w, UINT m, long ev);  /* WSAAsyncSelect */
void   a_loop_addr(struct sockaddr_in *a, unsigned short port_be);
SOCKET a_listener(struct sockaddr_in *addr, int backlog);        /* IPv4 loopback, ephemeral port */
SOCKET a_listener6(struct sockaddr_in6 *addr, int backlog);      /* IPv6 loopback, ephemeral port */
int    a_pair(SOCKET *cl, SOCKET *sv);               /* connected blocking TCP pair over IPv4 loopback */
int    a_pair6(SOCKET *cl, SOCKET *sv);              /* same over ::1 (0 when IPv6 is unavailable) */
int    a_udp_pair(SOCKET *a, SOCKET *b, struct sockaddr_in *aaddr, struct sockaddr_in *baddr);
int    a_send(SOCKET s, int n);                      /* n bytes of filler */
int    a_recv(SOCKET s, int n);                      /* recv up to n bytes, return recv's result */
int    a_recv_bounded(SOCKET s, int n, int *err, DWORD ms); /* recv on a helper thread; -9 if it had to be broken */

/* ---- windows --------------------------------------------------------------------------------- */
HWND a_win(int kind);                                /* tracked window owned by the calling thread */
void a_destroy(HWND w);                              /* destroy + untrack */

/* A window created and pumped by a second thread. */
typedef struct { HANDLE th; HWND hwnd; DWORD tid; HANDLE ready; int kind; volatile LONG stop; } asm_wthread;
int  a_wthread_start(asm_wthread *t, int kind);
void a_wthread_stop(asm_wthread *t);

/* ---- message log ------------------------------------------------------------------------------ */
void a_log_reset(void);
void a_pump(DWORD ms);                               /* dispatch this thread's messages for ms milliseconds */
/* Wait (pumping) up to ms for an unconsumed record (socket/handle, message id, LOWORD(lParam)==ev);
 * consumes it. ev < 0 matches any LOWORD.  *lp receives the lParam. */
int  a_take(WPARAM wp, UINT msg, int ev, DWORD ms, LPARAM *lp);
int  a_count(WPARAM wp, UINT msg);                   /* unconsumed matching records right now */
int  a_total(void);                                  /* unconsumed records right now */
int  a_quiet(DWORD ms);                              /* pump ms, then return the unconsumed total */
int  a_quiet_for(WPARAM wp, UINT msg, DWORD ms);     /* pump ms, count for one socket/message */
void a_drain(DWORD ms);                              /* pump ms and consume everything */
int  a_find_rec(WPARAM wp, UINT msg, int ev, asm_rec *out); /* peek (does not consume) */
LONG a_seq_of(WPARAM wp, UINT msg, int ev);          /* sequence number of the first unconsumed match, -1 none */

/* Wait for the posted message to be visible in this thread's queue without removing it. */
int  a_peek_posted(HWND w, UINT msg, DWORD ms, MSG *out);

/* ---- name/service request helpers ------------------------------------------------------------ */
#define ASM_BUF 1024
#endif
