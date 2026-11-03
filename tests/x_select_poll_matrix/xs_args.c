/* Argument and edge behaviour of the readiness interfaces: select with odd sets, WSAPoll with odd arrays and
 * request masks, the AFD poll request with odd counts, WSAEventSelect / WSAEnumNetworkEvents / WSAAsyncSelect
 * with bad masks and bad handles, and wake-up from a blocked wait. Every observation is a short rendered
 * string compared with the recorded table (group "ar_*"). */
#include "xs.h"

#ifndef POLLRDNORM
#define POLLRDNORM 0x0100
#define POLLRDBAND 0x0200
#define POLLPRI    0x0400
#define POLLWRNORM 0x0010
#define POLLWRBAND 0x0020
#define POLLERR    0x0001
#define POLLHUP    0x0002
#define POLLNVAL   0x0004
#endif

#define OBS(grp, step, ...) do { char b_[256]; snprintf(b_, sizeof(b_), __VA_ARGS__); xs_row_check(grp, step, b_); } while (0)
#define NEEDINIT() do { if (!xs_init()) { t_skip("winsock, poll or ntdll entry points missing"); return; } } while (0)

/* a select set that can hold more than FD_SETSIZE sockets */
typedef struct { u_int n; SOCKET a[400]; } bigset;
static int bsel(bigset *r, bigset *w, bigset *x, struct timeval *tv)
{
    return U(select)(0, (fd_set *)r, (fd_set *)w, (fd_set *)x, tv);
}
static int rc_or_err(int rc) { return rc < 0 || rc == SOCKET_ERROR ? -xs_err() : rc; }

/* ---- select ------------------------------------------------------------ */
TEST(ar_select_empty_and_null_sets)
{
    fd_set e; struct timeval tv = { 0, 0 }; int rc;
    NEEDINIT();
    FD_ZERO(&e);
    rc = U(select)(0, NULL, NULL, NULL, &tv);
    OBS("ar_select_empty", "all_null", "%d", rc_or_err(rc));
    rc = U(select)(0, &e, NULL, NULL, &tv);
    OBS("ar_select_empty", "one_empty_set", "%d", rc_or_err(rc));
    { fd_set a, b, c; FD_ZERO(&a); FD_ZERO(&b); FD_ZERO(&c);
      rc = U(select)(0, &a, &b, &c, &tv);
      OBS("ar_select_empty", "three_empty_sets", "%d", rc_or_err(rc)); }
}

TEST(ar_select_bad_handles)
{
    xs_st st; fd_set r; struct timeval tv = { 0, 0 }; int rc; SOCKET dead;
    NEEDINIT();
    memset(&st, 0, sizeof(st)); st.s = st.peer = st.lst = st.aux = INVALID_SOCKET;
    st.s = xs_sock(AF_INET, SOCK_DGRAM);
    dead = xs_sock(AF_INET, SOCK_DGRAM); xs_close(dead);
    FD_ZERO(&r); r.fd_count = 1; r.fd_array[0] = dead;
    rc = U(select)(0, &r, NULL, NULL, &tv);
    OBS("ar_select_bad", "closed_in_read", "%d count=%u", rc_or_err(rc), r.fd_count);
    FD_ZERO(&r); r.fd_count = 1; r.fd_array[0] = (SOCKET)xs_event();
    rc = U(select)(0, &r, NULL, NULL, &tv);
    OBS("ar_select_bad", "event_handle_in_read", "%d", rc_or_err(rc));
    FD_ZERO(&r); r.fd_count = 1; r.fd_array[0] = (SOCKET)xs_event();
    rc = U(select)(0, NULL, &r, NULL, &tv);
    OBS("ar_select_bad", "event_handle_in_write", "%d", rc_or_err(rc));
    FD_ZERO(&r); r.fd_count = 1; r.fd_array[0] = (SOCKET)xs_event();
    rc = U(select)(0, NULL, NULL, &r, &tv);
    OBS("ar_select_bad", "event_handle_in_except", "%d", rc_or_err(rc));
    FD_ZERO(&r); r.fd_count = 1; r.fd_array[0] = INVALID_SOCKET;
    rc = U(select)(0, &r, NULL, NULL, &tv);
    OBS("ar_select_bad", "invalid_socket_value", "%d", rc_or_err(rc));
    /* a good socket next to a bad one in another set */
    { fd_set g, b; FD_ZERO(&g); FD_ZERO(&b); g.fd_count = 1; g.fd_array[0] = st.s; b.fd_count = 1; b.fd_array[0] = dead;
      rc = U(select)(0, NULL, &g, &b, &tv);
      OBS("ar_select_bad", "good_write_bad_except", "%d", rc_or_err(rc)); }
    xs_teardown(&st);
}

TEST(ar_select_nfds_is_ignored)
{
    SOCKET s; fd_set w; struct timeval tv = { 0, 0 }; int rc[3]; int vals[3] = { 0, -1, 100000 }, i;
    NEEDINIT();
    s = xs_sock(AF_INET, SOCK_DGRAM);
    for (i = 0; i < 3; i++) {
        FD_ZERO(&w); w.fd_count = 1; w.fd_array[0] = s;
        rc[i] = U(select)(vals[i], NULL, &w, NULL, &tv);
    }
    OBS("ar_select_nfds", "zero_neg_huge", "%d %d %d", rc_or_err(rc[0]), rc_or_err(rc[1]), rc_or_err(rc[2]));
    xs_close(s);
}

TEST(ar_select_timeval_edges)
{
    SOCKET s; fd_set w; int rc; struct timeval tv;
    NEEDINIT();
    s = xs_sock(AF_INET, SOCK_DGRAM);
    FD_ZERO(&w); w.fd_count = 1; w.fd_array[0] = s; tv.tv_sec = 0; tv.tv_usec = 1000000;
    rc = U(select)(0, NULL, &w, NULL, &tv);
    OBS("ar_select_tv", "usec_one_million", "%d", rc_or_err(rc));
    FD_ZERO(&w); w.fd_count = 1; w.fd_array[0] = s; tv.tv_sec = -1; tv.tv_usec = 0;
    rc = U(select)(0, NULL, &w, NULL, &tv);
    OBS("ar_select_tv", "negative_sec", "%d", rc_or_err(rc));
    FD_ZERO(&w); w.fd_count = 1; w.fd_array[0] = s; tv.tv_sec = 0; tv.tv_usec = -1;
    rc = U(select)(0, NULL, &w, NULL, &tv);
    OBS("ar_select_tv", "negative_usec", "%d", rc_or_err(rc));
    FD_ZERO(&w); w.fd_count = 1; w.fd_array[0] = s;
    rc = U(select)(0, NULL, &w, NULL, NULL);   /* writable at once, so the unbounded wait ends immediately */
    OBS("ar_select_tv", "null_timeout_ready", "%d", rc_or_err(rc));
    xs_close(s);
}

TEST(ar_select_many_sockets)
{
    static bigset w, r; SOCKET s[130]; int i, n = 130, rc, ok = 0;
    NEEDINIT();
    for (i = 0; i < n; i++) { s[i] = xs_sock(AF_INET, SOCK_DGRAM); if (s[i] != INVALID_SOCKET) ok++; }
    if (ok != n) { for (i = 0; i < n; i++) xs_close(s[i]); t_skip("could not create sockets"); return; }
    memset(&w, 0, sizeof(w));
    for (i = 0; i < 64; i++) w.a[i] = s[i];
    w.n = 64;
    rc = bsel(NULL, &w, NULL, &(struct timeval){ 0, 0 });
    OBS("ar_select_many", "exactly_64", "%d count=%u", rc_or_err(rc), w.n);
    memset(&w, 0, sizeof(w));
    for (i = 0; i < n; i++) w.a[i] = s[i];
    w.n = n;
    rc = bsel(NULL, &w, NULL, &(struct timeval){ 0, 0 });
    OBS("ar_select_many", "130_writable", "%d count=%u", rc_or_err(rc), w.n);
    memset(&r, 0, sizeof(r)); memset(&w, 0, sizeof(w));
    for (i = 0; i < n; i++) r.a[i] = s[i];
    r.n = n;
    rc = bsel(&r, NULL, NULL, &(struct timeval){ 0, 0 });
    OBS("ar_select_many", "130_none_readable", "%d count=%u", rc_or_err(rc), r.n);
    for (i = 0; i < n; i++) xs_close(s[i]);
}

TEST(ar_select_preserves_set_order)
{
    SOCKET s[6], rx[3]; struct sockaddr_in a; int l = sizeof(a), i; fd_set r; struct timeval tv = { 0, 0 }; int rc;
    char o[64];
    NEEDINIT();
    for (i = 0; i < 6; i++) s[i] = xs_sock(AF_INET, SOCK_DGRAM);
    memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_addr.s_addr = XS_LOOP4;
    for (i = 0; i < 6; i++) U(bind)(s[i], (struct sockaddr *)&a, sizeof(a));
    /* datagrams to sockets 4, 1 and 3, in that order */
    { int order[3] = { 4, 1, 3 };
      for (i = 0; i < 3; i++) { l = sizeof(a); U(getsockname)(s[order[i]], (struct sockaddr *)&a, &l); U(sendto)(s[5], "z", 1, 0, (struct sockaddr *)&a, l); }
      xs_wait(s[4], 'r', 3000); xs_wait(s[1], 'r', 3000); xs_wait(s[3], 'r', 3000); }
    FD_ZERO(&r);
    for (i = 0; i < 5; i++) { r.fd_array[i] = s[i]; } r.fd_count = 5;
    rc = U(select)(0, &r, NULL, NULL, &tv);
    o[0] = 0;
    for (i = 0; i < (int)r.fd_count; i++) { int k, idx = -1; char t[8]; for (k = 0; k < 6; k++) if (s[k] == r.fd_array[i]) idx = k; snprintf(t, sizeof(t), "%d", idx); if (i) strcat(o, ","); strcat(o, t); }
    OBS("ar_select_order", "ready_indexes", "n=%d idx=%s", rc, o);
    /* duplicate entry */
    FD_ZERO(&r); r.fd_array[0] = s[1]; r.fd_array[1] = s[1]; r.fd_count = 2;
    rc = U(select)(0, &r, NULL, NULL, &tv);
    OBS("ar_select_order", "duplicate_entry", "n=%d count=%u", rc, r.fd_count);
    (void)rx;
    for (i = 0; i < 6; i++) xs_close(s[i]);
}

/* ---- WSAPoll ------------------------------------------------------------ */
TEST(ar_poll_argument_errors)
{
    WSAPOLLFD f; int rc; SOCKET s;
    NEEDINIT();
    s = xs_sock(AF_INET, SOCK_DGRAM);
    f.fd = s; f.events = POLLWRNORM; f.revents = 0;
    rc = U(WSAPoll)(&f, 0, 0);
    OBS("ar_poll_args", "zero_count", "%d", rc_or_err(rc));
    f.revents = 0;
    rc = U(WSAPoll)(&f, 1, -2);
    OBS("ar_poll_args", "timeout_minus2_ready", "%d rev=0x%x", rc_or_err(rc), (unsigned short)f.revents);
    f.revents = 0;
    rc = U(WSAPoll)(&f, 1, -1);
    OBS("ar_poll_args", "timeout_minus1_ready", "%d rev=0x%x", rc_or_err(rc), (unsigned short)f.revents);
    f.revents = 0;
    xs_close(s);
}

TEST(ar_poll_request_bits)
{
    static const struct { const char *n; short ev; } m[] = {
        { "POLLRDNORM", POLLRDNORM }, { "POLLWRNORM", POLLWRNORM }, { "POLLRDBAND", POLLRDBAND },
        { "RDNORM|RDBAND|WRNORM", POLLRDNORM | POLLRDBAND | POLLWRNORM }, { "none", 0 },
        { "POLLPRI", POLLPRI }, { "POLLWRBAND", POLLWRBAND }, { "POLLERR", POLLERR }, { "POLLHUP", POLLHUP },
        { "POLLNVAL", POLLNVAL }, { "RDNORM|PRI", POLLRDNORM | POLLPRI }, { "WRNORM|WRBAND", POLLWRNORM | POLLWRBAND },
        { "0x0008", 0x0008 }, { "0x0040", 0x0040 }, { "0x8000", (short)0x8000 }, { "0x1000", 0x1000 }, { "RDNORM|0x0008", POLLRDNORM | 0x0008 } };
    SOCKET s; size_t i;
    NEEDINIT();
    s = xs_sock(AF_INET, SOCK_DGRAM);
    for (i = 0; i < sizeof(m) / sizeof(m[0]); i++) {
        short rev; int rc = xs_poll1(s, m[i].ev, &rev); char nm[80];
        if (rc < 0) OBS("ar_poll_bits", m[i].n, "n=-1 err=%d", xs_err());
        else OBS("ar_poll_bits", m[i].n, "n=%d %s", rc, xs_poll_name((unsigned short)rev, nm, sizeof(nm)));
    }
    xs_close(s);
}

TEST(ar_poll_bad_entries)
{
    WSAPOLLFD f[4]; SOCKET s, dead; int rc, i; char o[200], nm[40];
    NEEDINIT();
    s = xs_sock(AF_INET, SOCK_DGRAM);
    dead = xs_sock(AF_INET, SOCK_DGRAM); xs_close(dead);
    /* closed + invalid + event handle + good */
    f[0].fd = dead; f[1].fd = INVALID_SOCKET; f[2].fd = (SOCKET)xs_event(); f[3].fd = s;
    for (i = 0; i < 4; i++) { f[i].events = POLLWRNORM; f[i].revents = (short)0x7777; }
    rc = U(WSAPoll)(f, 4, 0);
    o[0] = 0; for (i = 0; i < 4; i++) { snprintf(nm, sizeof(nm), "%s[0x%x]", i ? " " : "", (unsigned short)f[i].revents); strcat(o, nm); }
    OBS("ar_poll_bad", "four_kinds", "%d %s", rc_or_err(rc), o);
    /* only invalid entries */
    f[0].fd = INVALID_SOCKET; f[1].fd = INVALID_SOCKET;
    for (i = 0; i < 2; i++) { f[i].events = POLLRDNORM; f[i].revents = (short)0x7777; }
    rc = U(WSAPoll)(f, 2, 0);
    OBS("ar_poll_bad", "only_invalid_values", "%d [0x%x] [0x%x]", rc_or_err(rc), (unsigned short)f[0].revents, (unsigned short)f[1].revents);
    /* only a closed socket */
    f[0].fd = dead; f[0].events = POLLRDNORM; f[0].revents = (short)0x7777;
    rc = U(WSAPoll)(f, 1, 0);
    OBS("ar_poll_bad", "only_closed", "%d [0x%x]", rc_or_err(rc), (unsigned short)f[0].revents);
    /* same socket twice */
    f[0].fd = s; f[1].fd = s; for (i = 0; i < 2; i++) { f[i].events = POLLWRNORM; f[i].revents = (short)0x7777; }
    rc = U(WSAPoll)(f, 2, 0);
    OBS("ar_poll_bad", "duplicate_socket", "%d [0x%x] [0x%x]", rc_or_err(rc), (unsigned short)f[0].revents, (unsigned short)f[1].revents);
    xs_close(s);
}

typedef struct { SOCKET s; int delay; const char *what; } wake_arg;
static DWORD WINAPI wake_thread(LPVOID p)
{
    wake_arg *a = (wake_arg *)p;
    Sleep(a->delay);
    if (!strcmp(a->what, "data")) U(send)(a->s, "w", 1, 0);
    else if (!strcmp(a->what, "fin")) U(shutdown)(a->s, SD_SEND);
    else if (!strcmp(a->what, "close")) xs_close(a->s);
    return 0;
}

static int bld(const char *name, xs_st *st)
{
    int i;
    memset(st, 0, sizeof(*st));
    st->s = st->peer = st->lst = st->aux = INVALID_SOCKET;
    for (i = 0; i < xs_nstates; i++) if (!strcmp(xs_states[i].name, name)) return xs_states[i].build(st);
    return 0;
}
#define NEED(st, name) xs_st st; \
    if (!xs_init()) { t_skip("winsock, poll or ntdll entry points missing"); return; } \
    if (!bld(name, &st)) { xs_teardown(&st); t_skip("could not reach state " name); return; }

/* A helper thread acts after a short delay while the main thread waits in a readiness call with a bounded
 * timeout; the observation is whether and how the wait ended, never how long it took. */
TEST(ar_poll_wakes_on_data)
{
    NEED(st, "tcp_conn_client");
    HANDLE th; wake_arg a; WSAPOLLFD f; int rc; char nm[60];
    a.s = st.peer; a.delay = 100; a.what = "data";
    th = CreateThread(NULL, 0, wake_thread, &a, 0, NULL);
    f.fd = st.s; f.events = POLLRDNORM; f.revents = 0;
    rc = U(WSAPoll)(&f, 1, 5000);
    WaitForSingleObject(th, 5000); CloseHandle(th);
    OBS("ar_wake", "poll_data", "n=%d %s", rc, xs_poll_name((unsigned short)f.revents, nm, sizeof(nm)));
    xs_teardown(&st);
}

TEST(ar_poll_wakes_on_fin)
{
    NEED(st, "tcp_conn_client");
    HANDLE th; wake_arg a; WSAPOLLFD f; int rc; char nm[60];
    a.s = st.peer; a.delay = 100; a.what = "fin";
    th = CreateThread(NULL, 0, wake_thread, &a, 0, NULL);
    f.fd = st.s; f.events = POLLRDNORM; f.revents = 0;
    rc = U(WSAPoll)(&f, 1, 5000);
    WaitForSingleObject(th, 5000); CloseHandle(th);
    OBS("ar_wake", "poll_fin", "n=%d %s", rc, xs_poll_name((unsigned short)f.revents, nm, sizeof(nm)));
    xs_teardown(&st);
}

TEST(ar_select_wakes_on_data)
{
    NEED(st, "tcp_conn_client");
    HANDLE th; wake_arg a; fd_set r; struct timeval tv = { 5, 0 }; int rc;
    a.s = st.peer; a.delay = 100; a.what = "data";
    th = CreateThread(NULL, 0, wake_thread, &a, 0, NULL);
    FD_ZERO(&r); r.fd_count = 1; r.fd_array[0] = st.s;
    rc = U(select)(0, &r, NULL, NULL, &tv);
    WaitForSingleObject(th, 5000); CloseHandle(th);
    OBS("ar_wake", "select_data", "n=%d count=%u", rc, r.fd_count);
    xs_teardown(&st);
}

TEST(ar_select_timeout_expires_empty)
{
    NEED(st, "tcp_conn_client");
    fd_set r; struct timeval tv = { 0, 50000 }; int rc;
    FD_ZERO(&r); r.fd_count = 1; r.fd_array[0] = st.s;
    rc = U(select)(0, &r, NULL, NULL, &tv);
    OBS("ar_wake", "select_expires", "n=%d count=%u", rc, r.fd_count);
    { WSAPOLLFD f; f.fd = st.s; f.events = POLLRDNORM; f.revents = 0x55;
      rc = U(WSAPoll)(&f, 1, 50);
      OBS("ar_wake", "poll_expires", "n=%d rev=0x%x", rc, (unsigned short)f.revents); }
    xs_teardown(&st);
}

TEST(ar_poll_wakes_on_accept)
{
    NEED(st, "tcp_listen_idle");
    struct sockaddr_in a; int l = sizeof(a); WSAPOLLFD f; int rc; char nm[60]; SOCKET c = xs_sock(AF_INET, SOCK_STREAM);
    U(getsockname)(st.s, (struct sockaddr *)&a, &l);
    xs_nb(c, 1);
    U(connect)(c, (struct sockaddr *)&a, l);   /* nonblocking: in progress or done, the listener sees it */
    f.fd = st.s; f.events = POLLRDNORM; f.revents = 0;
    rc = U(WSAPoll)(&f, 1, 5000);
    OBS("ar_wake", "poll_accept", "n=%d %s", rc, xs_poll_name((unsigned short)f.revents, nm, sizeof(nm)));
    xs_close(c);
    xs_teardown(&st);
}

/* ---- AFD poll request ------------------------------------------------------- */
typedef struct { ULONG_PTR h; ULONG ev; LONG st; } ent;
typedef struct { LONGLONG to; ULONG n; ULONG ex; ent e[4]; } preq;

static LONG afd_poll(HANDLE dev, preq *in, ULONG inlen, preq *out, ULONG outlen, ULONG_PTR *info)
{
    IO_STATUS_BLOCK io; LONG st;
    ResetEvent(xs_event());
    memset(&io, 0xcc, sizeof(io));
    st = ((LONG (WINAPI *)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG))
          t_proc_in("ntdll.dll", "NtDeviceIoControlFile"))(dev, xs_event(), NULL, NULL, &io, 0x12024, in, inlen, out, outlen);
    if (st == 0x103) {
        if (WaitForSingleObject(xs_event(), 3000) != WAIT_OBJECT_0) {
            IO_STATUS_BLOCK c; ((LONG (WINAPI *)(HANDLE, PIO_STATUS_BLOCK))t_proc_in("ntdll.dll", "NtCancelIoFile"))(dev, &c);
            WaitForSingleObject(xs_event(), 3000);
            if (info) *info = 0;
            return 0x7ffffff0;   /* marker: never completed */
        }
        st = io.Status;
    }
    if (info) *info = io.Information;
    return st;
}

TEST(ar_afd_poll_shapes)
{
    NEED(st, "tcp_data_client");
    preq in, out; LONG rc; ULONG_PTR info;
    /* mask of zero events for a ready socket */
    memset(&in, 0, sizeof(in)); in.n = 1; in.e[0].h = st.s; in.e[0].ev = 0;
    memset(&out, 0xcc, sizeof(out));
    rc = afd_poll((HANDLE)st.s, &in, 32, &out, 32, &info);
    OBS("ar_afd", "zero_event_mask", "st=0x%08lx n=%lu info=%lu", (unsigned long)rc, (unsigned long)out.n, (unsigned long)info);
    /* two entries naming the same socket */
    memset(&in, 0, sizeof(in)); in.n = 2; in.e[0].h = st.s; in.e[0].ev = 0x1FF; in.e[1].h = st.s; in.e[1].ev = 0x1FF;
    memset(&out, 0xcc, sizeof(out));
    rc = afd_poll((HANDLE)st.s, &in, 48, &out, 48, &info);
    OBS("ar_afd", "same_socket_twice", "st=0x%08lx n=%lu e0=0x%lx e1=0x%lx", (unsigned long)rc, (unsigned long)out.n, (unsigned long)out.e[0].ev, (unsigned long)out.e[1].ev);
    /* count of zero */
    memset(&in, 0, sizeof(in)); in.n = 0;
    memset(&out, 0xcc, sizeof(out));
    rc = afd_poll((HANDLE)st.s, &in, 32, &out, 32, &info);
    OBS("ar_afd", "zero_count", "st=0x%08lx", (unsigned long)rc);
    /* input shorter than the header, and shorter than the entries named */
    memset(&in, 0, sizeof(in)); in.n = 1; in.e[0].h = st.s; in.e[0].ev = 0x1FF;
    rc = afd_poll((HANDLE)st.s, &in, 8, &out, 32, &info);
    OBS("ar_afd", "input_8_bytes", "st=0x%08lx", (unsigned long)rc);
    rc = afd_poll((HANDLE)st.s, &in, 24, &out, 32, &info);
    OBS("ar_afd", "input_24_bytes_one_entry", "st=0x%08lx", (unsigned long)rc);
    rc = afd_poll((HANDLE)st.s, &in, 32, &out, 16, &info);
    OBS("ar_afd", "output_16_bytes", "st=0x%08lx", (unsigned long)rc);
    in.n = 3;
    rc = afd_poll((HANDLE)st.s, &in, 32, &out, 32, &info);
    OBS("ar_afd", "count_3_input_for_1", "st=0x%08lx", (unsigned long)rc);
    in.n = 1;
    /* a handle that is not a socket */
    in.e[0].h = (ULONG_PTR)xs_event();
    memset(&out, 0xcc, sizeof(out));
    rc = afd_poll((HANDLE)st.s, &in, 32, &out, 32, &info);
    OBS("ar_afd", "entry_is_event_handle", "st=0x%08lx", (unsigned long)rc);
    /* the control handle is not a socket */
    in.e[0].h = st.s;
    rc = afd_poll(xs_event(), &in, 32, &out, 32, &info);
    OBS("ar_afd", "device_handle_is_event", "st=0x%08lx", (unsigned long)rc);
    xs_teardown(&st);
}

TEST(ar_afd_poll_timeout_and_blocking)
{
    NEED(st, "tcp_conn_client");
    preq in, out; LONG rc; ULONG_PTR info;
    /* nothing readable: ask only for RECEIVE with a relative 30 ms timeout (100 ns units, negative) */
    memset(&in, 0, sizeof(in)); in.to = -300000; in.n = 1; in.e[0].h = st.s; in.e[0].ev = 0x1;
    memset(&out, 0xcc, sizeof(out));
    rc = afd_poll((HANDLE)st.s, &in, 32, &out, 32, &info);
    OBS("ar_afd_wait", "relative_timeout_expires", "st=0x%08lx n=%lu", (unsigned long)rc, (unsigned long)out.n);
    /* send is ready: asking for SEND returns immediately even with a long timeout */
    memset(&in, 0, sizeof(in)); in.to = -30000000; in.n = 1; in.e[0].h = st.s; in.e[0].ev = 0x4;
    memset(&out, 0xcc, sizeof(out));
    rc = afd_poll((HANDLE)st.s, &in, 32, &out, 32, &info);
    OBS("ar_afd_wait", "ready_returns_at_once", "st=0x%08lx n=%lu ev=0x%lx", (unsigned long)rc, (unsigned long)out.n, (unsigned long)out.e[0].ev);
    /* the request reports only the bits asked for */
    memset(&in, 0, sizeof(in)); in.n = 1; in.e[0].h = st.s; in.e[0].ev = 0x1 | 0x2;
    memset(&out, 0xcc, sizeof(out));
    rc = afd_poll((HANDLE)st.s, &in, 32, &out, 32, &info);
    OBS("ar_afd_wait", "recv_oob_only_asked", "st=0x%08lx n=%lu", (unsigned long)rc, (unsigned long)out.n);
    xs_teardown(&st);
}

/* ---- event based selection --------------------------------------------------- */
TEST(ar_evsel_argument_errors)
{
    SOCKET s, dead; WSANETWORKEVENTS ne; int rc;
    NEEDINIT();
    s = xs_sock(AF_INET, SOCK_STREAM);
    dead = xs_sock(AF_INET, SOCK_STREAM); xs_close(dead);
    rc = U(WSAEventSelect)(s, NULL, FD_READ);
    OBS("ar_evsel", "null_event_with_mask", "%d", rc ? xs_err() : 0);
    rc = U(WSAEventSelect)(s, NULL, 0);
    OBS("ar_evsel", "null_event_zero_mask", "%d", rc ? xs_err() : 0);
    rc = U(WSAEventSelect)(s, xs_event(), 0x8000);
    OBS("ar_evsel", "undefined_mask_bit", "%d", rc ? xs_err() : 0);
    rc = U(WSAEventSelect)(s, xs_event(), (long)0x80000000);
    OBS("ar_evsel", "high_mask_bit", "%d", rc ? xs_err() : 0);
    rc = U(WSAEventSelect)(s, xs_event(), FD_ALL_EVENTS);
    OBS("ar_evsel", "all_events", "%d", rc ? xs_err() : 0);
    rc = U(WSAEventSelect)(s, xs_event(), FD_ALL_EVENTS | 0x400);
    OBS("ar_evsel", "all_plus_0x400", "%d", rc ? xs_err() : 0);
    rc = U(WSAEventSelect)(s, NULL, 0);
    rc = U(WSAEventSelect)(s, (WSAEVENT)(ULONG_PTR)0x7fff0, FD_READ);
    OBS("ar_evsel", "bogus_event_handle", "%d", rc ? xs_err() : 0);
    rc = U(WSAEventSelect)(s, NULL, 0);
    rc = U(WSAEventSelect)(dead, xs_event(), FD_READ);
    OBS("ar_evsel", "closed_socket", "%d", rc ? xs_err() : 0);
    rc = U(WSAEventSelect)(INVALID_SOCKET, xs_event(), FD_READ);
    OBS("ar_evsel", "invalid_socket", "%d", rc ? xs_err() : 0);
    rc = U(WSAEventSelect)((SOCKET)xs_event(), xs_event(), FD_READ);
    OBS("ar_evsel", "event_as_socket", "%d", rc ? xs_err() : 0);
    memset(&ne, 0, sizeof(ne));
    rc = U(WSAEnumNetworkEvents)(dead, NULL, &ne);
    OBS("ar_enum", "closed_socket", "%d", rc ? xs_err() : 0);
    rc = U(WSAEnumNetworkEvents)((SOCKET)xs_event(), NULL, &ne);
    OBS("ar_enum", "event_as_socket", "%d", rc ? xs_err() : 0);
    memset(&ne, 0x55, sizeof(ne));
    rc = U(WSAEnumNetworkEvents)(s, NULL, &ne);
    OBS("ar_enum", "no_selection_made", "%d events=0x%lx err0=%d", rc ? xs_err() : 0, (unsigned long)ne.lNetworkEvents, ne.iErrorCode[0]);
    xs_close(s);
}

TEST(ar_enum_event_reset_rules)
{
    NEED(st, "tcp_data_client");
    WSANETWORKEVENTS ne; int rc;
    ResetEvent(xs_event());
    U(WSAEventSelect)(st.s, xs_event(), FD_READ | FD_WRITE | FD_CLOSE);
    OBS("ar_enum_reset", "signalled_after_select", "%d", WaitForSingleObject(xs_event(), 0) == WAIT_OBJECT_0);
    rc = U(WSAEnumNetworkEvents)(st.s, NULL, &ne);
    OBS("ar_enum_reset", "enum_without_event_arg", "%d events=0x%lx", rc, (unsigned long)ne.lNetworkEvents);
    OBS("ar_enum_reset", "still_signalled", "%d", WaitForSingleObject(xs_event(), 0) == WAIT_OBJECT_0);
    SetEvent(xs_event());
    rc = U(WSAEnumNetworkEvents)(st.s, xs_event(), &ne);
    OBS("ar_enum_reset", "enum_with_event_arg", "%d events=0x%lx", rc, (unsigned long)ne.lNetworkEvents);
    OBS("ar_enum_reset", "reset_by_enum", "%d", WaitForSingleObject(xs_event(), 0) == WAIT_OBJECT_0);
    rc = U(WSAEnumNetworkEvents)(st.s, xs_event(), &ne);
    OBS("ar_enum_reset", "enum_again", "%d events=0x%lx", rc, (unsigned long)ne.lNetworkEvents);
    U(WSAEventSelect)(st.s, NULL, 0);
    xs_teardown(&st);
}

TEST(ar_evsel_reselect_rules)
{
    NEED(st, "tcp_data_client");
    WSANETWORKEVENTS ne; int rc; HANDLE e2 = CreateEventW(NULL, TRUE, FALSE, NULL);
    ResetEvent(xs_event());
    U(WSAEventSelect)(st.s, xs_event(), FD_CLOSE);
    OBS("ar_reselect", "close_only_signalled", "%d", WaitForSingleObject(xs_event(), 0) == WAIT_OBJECT_0);
    /* reselecting with a wider mask raises the pending readable condition again */
    U(WSAEventSelect)(st.s, xs_event(), FD_READ | FD_CLOSE);
    OBS("ar_reselect", "widened_signalled", "%d", WaitForSingleObject(xs_event(), 0) == WAIT_OBJECT_0);
    /* moving to a second event: the first one is not touched, the second is signalled */
    ResetEvent(xs_event());
    U(WSAEventSelect)(st.s, e2, FD_READ | FD_CLOSE);
    OBS("ar_reselect", "old_event_after_move", "%d", WaitForSingleObject(xs_event(), 0) == WAIT_OBJECT_0);
    OBS("ar_reselect", "new_event_after_move", "%d", WaitForSingleObject(e2, 0) == WAIT_OBJECT_0);
    /* zero mask with an event cancels the association */
    ResetEvent(e2);
    rc = U(WSAEventSelect)(st.s, e2, 0);
    OBS("ar_reselect", "cancel_rc", "%d", rc ? xs_err() : 0);
    OBS("ar_reselect", "cancelled_signalled", "%d", WaitForSingleObject(e2, 0) == WAIT_OBJECT_0);
    memset(&ne, 0x55, sizeof(ne));
    rc = U(WSAEnumNetworkEvents)(st.s, NULL, &ne);
    OBS("ar_reselect", "enum_after_cancel", "%d events=0x%lx", rc ? xs_err() : 0, (unsigned long)ne.lNetworkEvents);
    CloseHandle(e2);
    xs_teardown(&st);
}

TEST(ar_two_sockets_share_one_event)
{
    xs_st a, b;
    xs_st dummy; (void)dummy;
    if (!xs_init()) { t_skip("missing entry points"); return; }
    if (!bld("tcp_conn_client", &a) || !bld("tcp_conn_client", &b)) { t_skip("states unreachable"); xs_teardown(&a); return; }
    {
        WSANETWORKEVENTS na, nb; int sig;
        ResetEvent(xs_event());
        U(WSAEventSelect)(a.s, xs_event(), FD_READ);
        U(WSAEventSelect)(b.s, xs_event(), FD_READ);
        xs_send_n(b.peer, 3, 0); xs_wait(b.s, 'r', 3000);
        WaitForSingleObject(xs_event(), 2000);
        memset(&na, 0, sizeof(na)); memset(&nb, 0, sizeof(nb));
        U(WSAEnumNetworkEvents)(a.s, xs_event(), &na);
        sig = WaitForSingleObject(xs_event(), 0) == WAIT_OBJECT_0;
        OBS("ar_shared_event", "a_after_b_data", "a=0x%lx signalled_after=%d", (unsigned long)na.lNetworkEvents, sig);
        U(WSAEnumNetworkEvents)(b.s, xs_event(), &nb);
        OBS("ar_shared_event", "b_after_b_data", "b=0x%lx", (unsigned long)nb.lNetworkEvents);
        U(WSAEventSelect)(a.s, NULL, 0); U(WSAEventSelect)(b.s, NULL, 0);
    }
    xs_teardown(&a); xs_teardown(&b);
}

TEST(ar_accepted_socket_inherits_selection)
{
    NEED(st, "tcp_listen_idle");
    struct sockaddr_in a; int l = sizeof(a); SOCKET c, acc; WSANETWORKEVENTS ne; int rc; u_long z = 0; char b[4];
    U(getsockname)(st.s, (struct sockaddr *)&a, &l);
    ResetEvent(xs_event());
    U(WSAEventSelect)(st.s, xs_event(), FD_ACCEPT | FD_READ | FD_CLOSE);
    c = xs_sock(AF_INET, SOCK_STREAM);
    U(connect)(c, (struct sockaddr *)&a, l);
    WaitForSingleObject(xs_event(), 3000);
    memset(&ne, 0, sizeof(ne));
    U(WSAEnumNetworkEvents)(st.s, xs_event(), &ne);
    OBS("ar_inherit", "listener_accept_event", "0x%lx", (unsigned long)ne.lNetworkEvents);
    acc = U(accept)(st.s, NULL, NULL);
    /* the accepted socket carries the listener's selection, so data on it signals the same event */
    OBS("ar_inherit", "accepted_nonblocking_recv", "%d", (rc = U(recv)(acc, b, 4, 0)) < 0 ? xs_err() : rc);
    OBS("ar_inherit", "event_after_accept", "%d", WaitForSingleObject(xs_event(), 0) == WAIT_OBJECT_0);
    ResetEvent(xs_event());
    xs_send_n(c, 2, 0); xs_wait(acc, 'r', 3000);
    OBS("ar_inherit", "event_after_data", "%d", WaitForSingleObject(xs_event(), 2000) == WAIT_OBJECT_0);
    memset(&ne, 0, sizeof(ne));
    U(WSAEnumNetworkEvents)(acc, xs_event(), &ne);
    OBS("ar_inherit", "accepted_events", "0x%lx", (unsigned long)ne.lNetworkEvents);
    /* cancelling on the listener leaves the accepted socket nonblocking; blocking mode must be restored by hand */
    U(WSAEventSelect)(st.s, NULL, 0);
    U(WSAEventSelect)(acc, NULL, 0);
    rc = U(ioctlsocket)(acc, FIONBIO, &z);
    OBS("ar_inherit", "restore_blocking_rc", "%d", rc ? xs_err() : 0);
    xs_close(acc); xs_close(c);
    xs_teardown(&st);
}

TEST(ar_fionbio_after_selection)
{
    NEED(st, "tcp_conn_client");
    u_long z = 0, v = 7; int rc;
    U(WSAEventSelect)(st.s, xs_event(), FD_READ);
    rc = U(ioctlsocket)(st.s, FIONBIO, &z);
    OBS("ar_fionbio", "clear_while_event_selected", "%d", rc ? xs_err() : 0);
    U(WSAEventSelect)(st.s, NULL, 0);
    rc = U(ioctlsocket)(st.s, FIONBIO, &z);
    OBS("ar_fionbio", "clear_after_cancel", "%d", rc ? xs_err() : 0);
    xs_async_begin(st.s, FD_READ);
    rc = U(ioctlsocket)(st.s, FIONBIO, &z);
    OBS("ar_fionbio", "clear_while_async_selected", "%d", rc ? xs_err() : 0);
    xs_async_end(st.s);
    rc = U(ioctlsocket)(st.s, FIONBIO, &z);
    OBS("ar_fionbio", "clear_after_async_cancel", "%d", rc ? xs_err() : 0);
    (void)v;
    xs_teardown(&st);
}

TEST(ar_async_argument_errors)
{
    SOCKET s, dead; int rc;
    NEEDINIT();
    s = xs_sock(AF_INET, SOCK_STREAM);
    dead = xs_sock(AF_INET, SOCK_STREAM); xs_close(dead);
    rc = U(WSAAsyncSelect)(s, NULL, WM_USER + 9, FD_READ);
    OBS("ar_async", "null_window_with_mask", "%d", rc ? xs_err() : 0);
    rc = U(WSAAsyncSelect)(s, NULL, 0, 0);
    OBS("ar_async", "null_window_zero_mask", "%d", rc ? xs_err() : 0);
    rc = U(WSAAsyncSelect)(s, (HWND)(ULONG_PTR)0x7ff0, WM_USER + 9, FD_READ);
    OBS("ar_async", "bogus_window", "%d", rc ? xs_err() : 0);
    rc = U(WSAAsyncSelect)(dead, UIN("user32.dll", GetDesktopWindow)(), WM_USER + 9, FD_READ);
    OBS("ar_async", "closed_socket", "%d", rc ? xs_err() : 0);
    rc = U(WSAAsyncSelect)(s, UIN("user32.dll", GetDesktopWindow)(), WM_USER + 9, 0x8000);
    OBS("ar_async", "undefined_mask_bit", "%d", rc ? xs_err() : 0);
    rc = U(WSAAsyncSelect)((SOCKET)xs_event(), UIN("user32.dll", GetDesktopWindow)(), WM_USER + 9, FD_READ);
    OBS("ar_async", "event_as_socket", "%d", rc ? xs_err() : 0);
    xs_close(s);
}

TEST(ar_switch_between_selection_models)
{
    NEED(st, "tcp_conn_client");
    int rc; WSANETWORKEVENTS ne;
    U(WSAEventSelect)(st.s, xs_event(), FD_READ);
    xs_nb(st.s, 1);
    rc = xs_async_begin(st.s, FD_READ);
    OBS("ar_switch", "async_over_event", "%d", rc ? xs_err() : 0);
    memset(&ne, 0x55, sizeof(ne));
    rc = U(WSAEnumNetworkEvents)(st.s, NULL, &ne);
    OBS("ar_switch", "enum_after_async_over_event", "%d events=0x%lx", rc ? xs_err() : 0, (unsigned long)ne.lNetworkEvents);
    xs_async_end(st.s);
    rc = U(WSAEventSelect)(st.s, xs_event(), FD_READ);
    OBS("ar_switch", "event_over_async", "%d", rc ? xs_err() : 0);
    U(WSAEventSelect)(st.s, NULL, 0);
    xs_teardown(&st);
}

TEST(ar_enum_null_output_struct)
{
    SOCKET s; int rc;
    NEEDINIT();
    s = xs_sock(AF_INET, SOCK_STREAM);
    rc = U(WSAEnumNetworkEvents)(s, NULL, NULL);
    OBS("ar_enum", "null_output", "%d", rc ? xs_err() : 0);
    xs_close(s);
}

TEST(ar_poll_null_array_zero_count)
{
    int rc;
    NEEDINIT();
    rc = U(WSAPoll)(NULL, 0, 0);
    OBS("ar_poll_args", "null_array_zero_count", "%d", rc_or_err(rc));
}

TEST(ar_poll_close_from_other_thread)
{
    NEED(st, "tcp_conn_client");
    HANDLE th; wake_arg a; WSAPOLLFD f; int rc; char nm[60];
    a.s = st.s; a.delay = 150; a.what = "close";
    th = CreateThread(NULL, 0, wake_thread, &a, 0, NULL);
    f.fd = st.s; f.events = POLLRDNORM; f.revents = 0;
    rc = U(WSAPoll)(&f, 1, 1500);
    WaitForSingleObject(th, 5000); CloseHandle(th);
    st.s = INVALID_SOCKET;
    OBS("ar_wake", "poll_closed_by_other_thread", "n=%d %s err=%d", rc, xs_poll_name((unsigned short)f.revents, nm, sizeof(nm)), rc < 0 ? xs_err() : 0);
    xs_teardown(&st);
}

TEST(ar_select_close_from_other_thread)
{
    NEED(st, "tcp_conn_client");
    HANDLE th; wake_arg a; fd_set r; struct timeval tv = { 1, 500000 }; int rc;
    a.s = st.s; a.delay = 150; a.what = "close";
    th = CreateThread(NULL, 0, wake_thread, &a, 0, NULL);
    FD_ZERO(&r); r.fd_count = 1; r.fd_array[0] = st.s;
    rc = U(select)(0, &r, NULL, NULL, &tv);
    WaitForSingleObject(th, 5000); CloseHandle(th);
    st.s = INVALID_SOCKET;
    OBS("ar_wake", "select_closed_by_other_thread", "n=%d count=%u err=%d", rc, r.fd_count, rc < 0 ? xs_err() : 0);
    xs_teardown(&st);
}

/* WSAAsyncSelect on a socket whose nonblocking connect finished a while ago: the FD_WRITE message always
 * arrives; the FD_CONNECT message arrives only when the selection is made almost at once after completion.
 * The recorded rows allow both outcomes for the immediate case and require none after a long settle. */
TEST(ar_async_connect_settle)
{
    static const struct { const char *state; const char *step; int delay; } c[] = {
        { "tcp_connect_nb_done", "done_then_500ms", 500 },
        { "tcp_connect_nb_done", "done_then_1500ms", 1500 },
        { "tcp_connect_nb_done_accepted", "accepted_then_500ms", 500 },
        { "tcp_connect_nb_done_accepted", "accepted_immediately", 0 },
        { "tcp_connect_refused_nb", "refused_then_1500ms", 1500 },
    };
    size_t i;
    NEEDINIT();
    for (i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
        xs_st st; char b[128];
        if (!bld(c[i].state, &st)) { xs_teardown(&st); t_skip("state unreachable"); return; }
        Sleep(c[i].delay);
        xs_async_begin(st.s, FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE);
        xs_async_pump(b, sizeof(b), 300); xs_async_end(st.s);
        xs_row_check("ar_async_settle", c[i].step, b);
        xs_teardown(&st);
    }
}
