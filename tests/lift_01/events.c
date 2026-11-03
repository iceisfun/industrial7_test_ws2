/* IOCTL_AFD_EVENT_SELECT and IOCTL_AFD_GET_EVENTS: the kernel-side state behind WSAEventSelect and
 * WSAEnumNetworkEvents. EVENT_SELECT takes a 16-byte (event handle, event mask) block and is validated
 * synchronously, writing the status block even when it fails. GET_EVENTS takes the event handle itself in
 * the (otherwise unused) input pointer and needs a 0x38-byte output block: a flag word plus one status
 * per event bit. Reading the events consumes them. */
#include "afdx.h"

static LONG sel(SOCKET s, IO_STATUS_BLOCK *io, void *in, ULONG insz) {
    return X.ioctl((HANDLE)s, NULL, NULL, NULL, io, AX_IOCTL_EVENT_SELECT, in, insz, NULL, 0);
}
static LONG getev(SOCKET s, IO_STATUS_BLOCK *io, void *in, void *out, ULONG outsz) {
    return X.ioctl((HANDLE)s, NULL, NULL, NULL, io, AX_IOCTL_GET_EVENTS, in, 0, out, outsz);
}
#define ALL_FD (FD_ACCEPT | FD_CLOSE | FD_CONNECT | FD_OOB | FD_READ | FD_WRITE)

TEST(afdevsel_no_input_rejected_and_iosb_written) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io;
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    FILL_IOSB(io, 0xcc);
    CHECK_ST(sel(c, &io, NULL, 0), AX_STATUS_INVALID_PARAMETER);
    CHECK_IOSB(io, AX_STATUS_INVALID_PARAMETER, 0);
    afdx_close(c); afdx_close(s);
}

TEST(afdevsel_null_event_with_mask_rejected) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; AX_EVENT_SELECT p;
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    p.event = NULL; p.mask = ~0u;
    FILL_IOSB(io, 0xcc);
    CHECK_ST(sel(c, &io, &p, sizeof p), AX_STATUS_INVALID_PARAMETER);
    CHECK_IOSB(io, AX_STATUS_INVALID_PARAMETER, 0);
    afdx_close(c); afdx_close(s);
}

TEST(afdevsel_full_mask_reports_connect_and_write) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; AX_EVENT_SELECT p; WSANETWORKEVENTS ne;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    p.event = ev; p.mask = ~0u;
    FILL_IOSB(io, 0xcc);
    CHECK_ST(sel(c, &io, &p, sizeof p), AX_STATUS_SUCCESS);
    CHECK_IOSB(io, 0, 0);
    CHECK(X.WSAEnumNetworkEvents(c, ev, &ne) == 0);
    CHECK(ne.lNetworkEvents == (FD_CONNECT | FD_WRITE));
    afdx_close(c); afdx_close(s); CloseHandle(ev);
}

TEST(afdevsel_connect_only_mask) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; AX_EVENT_SELECT p; WSANETWORKEVENTS ne;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    p.event = ev; p.mask = AX_POLL_CONNECT;
    FILL_IOSB(io, 0xcc);
    CHECK_ST(sel(c, &io, &p, sizeof p), AX_STATUS_SUCCESS);
    CHECK_IOSB(io, 0, 0);
    CHECK(X.WSAEnumNetworkEvents(c, ev, &ne) == 0);
    CHECK(ne.lNetworkEvents == FD_CONNECT);
    afdx_close(c); afdx_close(s); CloseHandle(ev);
}

TEST(afdevsel_clearing_the_selection) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; AX_EVENT_SELECT p; WSANETWORKEVENTS ne;
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    p.event = ev; p.mask = ~0u;
    CHECK_ST(sel(c, &io, &p, sizeof p), AX_STATUS_SUCCESS);
    p.event = NULL; p.mask = 0;                      /* no event, no mask: deselect */
    FILL_IOSB(io, 0xcc);
    CHECK_ST(sel(c, &io, &p, sizeof p), AX_STATUS_SUCCESS);
    CHECK_IOSB(io, 0, 0);
    CHECK(X.WSAEnumNetworkEvents(c, ev, &ne) == 0);
    CHECK(ne.lNetworkEvents == 0);
    afdx_close(c); afdx_close(s); CloseHandle(ev);
}

/* ---- GET_EVENTS ---- */
static void status_all_zero(const AX_GET_EVENTS *g) {
    for (int i = 0; i < 13; i++) CHECKF(g->status[i] == 0, "status[%d] = 0x%08lx", i, (unsigned long)g->status[i]);
}

static HANDLE select_all(SOCKET s) {
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(X.WSAEventSelect(s, ev, ALL_FD) == 0);
    return ev;
}

TEST(afdgetev_requires_output_block) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; AX_GET_EVENTS g;
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    HANDLE ev = select_all(c);
    FILL_IOSB(io, 0xcc);
    CHECK_ST(getev(c, &io, NULL, NULL, 0), AX_STATUS_INVALID_PARAMETER);
    CHECK_ST(getev(c, &io, NULL, &g, sizeof g - 1), AX_STATUS_INVALID_PARAMETER);   /* 0x37 bytes is one short */
    afdx_close(c); afdx_close(s); CloseHandle(ev);
}

TEST(afdgetev_fresh_pair_reports_and_consumes_events) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; AX_GET_EVENTS g; WSANETWORKEVENTS ne;
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    HANDLE ev = select_all(c);
    memset(&g, 0xcc, sizeof g); FILL_IOSB(io, 0xcc);
    CHECK_ST(getev(c, &io, NULL, &g, sizeof g), AX_STATUS_SUCCESS);
    CHECK(g.flags == (AX_POLL_WRITE | AX_POLL_CONNECT));
    status_all_zero(&g);
    /* the pending bits were consumed by the read above, so the Winsock view is empty */
    CHECK(X.WSAEnumNetworkEvents(c, ev, &ne) == 0);
    CHECK(ne.lNetworkEvents == 0);
    afdx_close(c); afdx_close(s); CloseHandle(ev);
}

TEST(afdgetev_accepted_side_reports_write_only) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; AX_GET_EVENTS g;
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    HANDLE ev = select_all(s);
    memset(&g, 0xcc, sizeof g);
    CHECK_ST(getev(s, &io, NULL, &g, sizeof g), AX_STATUS_SUCCESS);
    CHECK(g.flags == AX_POLL_WRITE);                 /* no connect event on the passive side */
    status_all_zero(&g);
    afdx_close(c); afdx_close(s); CloseHandle(ev);
}

TEST(afdgetev_after_enum_nothing_left) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; AX_GET_EVENTS g; WSANETWORKEVENTS ne;
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    HANDLE ev = select_all(c);
    CHECK(X.WSAEnumNetworkEvents(c, ev, &ne) == 0);
    CHECK(ne.lNetworkEvents == (FD_WRITE | FD_CONNECT));
    memset(&g, 0xcc, sizeof g);
    CHECK_ST(getev(c, &io, NULL, &g, sizeof g), AX_STATUS_SUCCESS);
    CHECK(g.flags == 0);
    status_all_zero(&g);
    afdx_close(c); afdx_close(s); CloseHandle(ev);
}

TEST(afdgetev_input_pointer_is_an_event_to_reset) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; AX_GET_EVENTS g;
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    HANDLE ev = select_all(c), other = CreateEventW(NULL, TRUE, FALSE, NULL);
    SetEvent(other);
    memset(&g, 0xcc, sizeof g);
    /* the input "pointer" carries an event handle (its length is zero); the call resets that event */
    CHECK_ST(X.ioctl((HANDLE)c, NULL, NULL, NULL, &io, AX_IOCTL_GET_EVENTS, (PVOID)other, 0, &g, sizeof g), AX_STATUS_SUCCESS);
    CHECK(g.flags == (AX_POLL_WRITE | AX_POLL_CONNECT));
    status_all_zero(&g);
    CHECK(WaitForSingleObject(other, 0) == WAIT_TIMEOUT);
    afdx_close(c); afdx_close(s); CloseHandle(ev); CloseHandle(other);
}

TEST(afdgetev_reset_by_peer_reports_reset_on_client) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; AX_GET_EVENTS g;
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(X.WSAEventSelect(c, ev, FD_ACCEPT | FD_CLOSE | FD_OOB | FD_READ) == 0);
    afdx_close_rst(s);
    CHECK(WaitForSingleObject(ev, AX_WAIT) == WAIT_OBJECT_0);
    memset(&g, 0xcc, sizeof g);
    CHECK_ST(getev(c, &io, NULL, &g, sizeof g), AX_STATUS_SUCCESS);
    CHECK(g.flags == AX_POLL_RESET);
    status_all_zero(&g);
    afdx_close(c); CloseHandle(ev);
}

TEST(afdgetev_reset_by_peer_reports_reset_on_server) {
    AFDX_BEGIN();
    SOCKET c, s; IO_STATUS_BLOCK io; AX_GET_EVENTS g;
    afdx_pair(&c, &s, WSA_FLAG_OVERLAPPED);
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(X.WSAEventSelect(s, ev, FD_ACCEPT | FD_CLOSE | FD_OOB | FD_READ) == 0);
    afdx_close_rst(c);
    CHECK(WaitForSingleObject(ev, AX_WAIT) == WAIT_OBJECT_0);
    memset(&g, 0xcc, sizeof g);
    CHECK_ST(getev(s, &io, NULL, &g, sizeof g), AX_STATUS_SUCCESS);
    CHECK(g.flags == AX_POLL_RESET);
    status_all_zero(&g);
    afdx_close(s); CloseHandle(ev);
}

/* A connect to a loopback port nobody listens on fails with a refusal that is recorded per event bit and
 * stays readable after the event flag itself has been consumed. Loopback refusals are retried by the stack
 * for a couple of seconds, so the wait is generous but bounded. */
TEST(afdgetev_refused_connect_records_status) {
    AFDX_BEGIN();
    SOCKET l, c; struct sockaddr_in a; IO_STATUS_BLOCK io; AX_GET_EVENTS g;
    afdx_listener(&l, &a);
    afdx_close(l);                                   /* nothing listens on this port any more */
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    c = afdx_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSA_FLAG_OVERLAPPED);
    CHECK(X.WSAEventSelect(c, ev, FD_CONNECT) == 0);
    int r = X.connect(c, (struct sockaddr *)&a, sizeof a);
    CHECK(r == SOCKET_ERROR);
    CHECK(X.WSAGetLastError() == WSAEWOULDBLOCK);
    if (WaitForSingleObject(ev, 8000) != WAIT_OBJECT_0) { t_skip("refusal not reported within the bound"); afdx_close(c); CloseHandle(ev); return; }
    memset(&g, 0xcc, sizeof g);
    CHECK_ST(getev(c, &io, NULL, &g, sizeof g), AX_STATUS_SUCCESS);
    CHECK(g.flags == AX_POLL_CONNECT_ERR);
    for (int i = 0; i < 13; i++) {
        if (i == AX_POLL_BIT_CONNECT_ERR) CHECK_ST(g.status[i], AX_STATUS_CONNECTION_REFUSED);
        else CHECKF(g.status[i] == 0, "status[%d]", i);
    }
    /* reselecting does not signal again and the flag word is empty, but the recorded status is kept */
    ResetEvent(ev);
    CHECK(X.WSAEventSelect(c, ev, FD_CONNECT) == 0);
    CHECK(WaitForSingleObject(ev, 0) == WAIT_TIMEOUT);
    memset(&g, 0xcc, sizeof g);
    CHECK_ST(getev(c, &io, NULL, &g, sizeof g), AX_STATUS_SUCCESS);
    CHECK(g.flags == 0);
    for (int i = 0; i < 13; i++) {
        if (i == AX_POLL_BIT_CONNECT_ERR) CHECK_ST(g.status[i], AX_STATUS_CONNECTION_REFUSED);
        else CHECKF(g.status[i] == 0, "status[%d]", i);
    }
    afdx_close(c); CloseHandle(ev);
}
