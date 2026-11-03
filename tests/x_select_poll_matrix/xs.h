/* Shared declarations for the x_select_poll_matrix area.
 *
 * The area drives one socket into a named state on loopback and then reads that state through every
 * readiness interface Winsock offers: select, WSAPoll (several request masks), the AFD poll device
 * request reached through ntdll, WSAEventSelect + WSAEnumNetworkEvents, and WSAAsyncSelect messages.
 * Each (state, view) pair renders to a short deterministic string; the strings are the asserted data
 * (see xs_table.h). Nothing here links the DLLs under test: everything is resolved through the harness. */
#ifndef XS_H
#define XS_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#define XS_LOOP4 0x0100007Fu            /* 127.0.0.1, network byte order on this host */
#define XS_MAXX 8

typedef struct {
    SOCKET s;                  /* the socket whose readiness is observed */
    SOCKET peer;               /* its connection partner, when any */
    SOCKET lst;                /* listener behind an accepted/pending connection */
    SOCKET aux;                /* anything else that must stay open until teardown */
    SOCKET extra[XS_MAXX];     /* fillers */
    int    nextra;
} xs_st;

typedef int (*xs_build_fn)(xs_st *);
typedef struct { const char *name; xs_build_fn build; const char *what; } xs_state;
extern const xs_state xs_states[];
extern const int xs_nstates;

enum { XV_SEL, XV_POLL_RW, XV_POLL_BAND, XV_POLL_RD, XV_POLL_WR, XV_POLL_NONE, XV_POLL_ALL, XV_AFD, XV_ENUM, XV_ASYNC, XV_COUNT };
extern const char *const xs_view_names[XV_COUNT];

int  xs_init(void);                                  /* WSAStartup, shared event and window; 0 = unusable */
void xs_observe(int view, xs_st *st, char *out, size_t cap);
void xs_teardown(xs_st *st);
const char *xs_expect(const char *state, const char *view);   /* NULL when the table has no row */

/* low-level helpers shared by the translation units */
SOCKET xs_sock(int af, int type);
void   xs_close(SOCKET s);
int    xs_err(void);
void   xs_nb(SOCKET s, int on);
int    xs_wait(SOCKET s, char kind, int ms);         /* poll select until readable 'r', writable 'w' or except 'x' */
void   xs_settle(int ms);
int    xs_send_n(SOCKET s, int n, int flags);
void   xs_snap(SOCKET s, char *out, size_t cap);     /* sel + poll_all + afd in one string, for transition rows */
const char *xs_poll_name(unsigned rev, char *buf, size_t cap);
const char *xs_fd_name(unsigned ev, char *buf, size_t cap);
const char *xs_afd_name(unsigned ev, char *buf, size_t cap);
int    xs_poll1(SOCKET s, short events, short *revents);   /* raw WSAPoll of one socket, returns its result */
int    xs_sel(SOCKET s, int *r, int *w, int *x);          /* select over one socket, returns select's result */
int    xs_async_begin(SOCKET s, long mask);
void   xs_async_pump(char *out, size_t cap, int ms);
void   xs_async_end(SOCKET s);
HANDLE xs_event(void);                                /* the shared manual-reset event */
int    xs_match(const char *got, const char *want);        /* want may hold "||" separated alternatives */
void   xs_row_check(const char *grp, const char *step, const char *got);   /* table compare or NOTE ROW */
#endif
