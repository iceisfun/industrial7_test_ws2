/* Request set-up shared by the pending-request tests: one function per kind of in-flight request. */
#include "acc.h"

typedef struct { LONGLONG timeout; ULONG count; ULONG exclusive; struct { ULONG_PTR h; ULONG flags; LONG status; } e[1]; } pollin_t;

int acc_pend_start(pend_t *p, int op, HANDLE port, ULONG_PTR key)
{
    struct sockaddr_in a;
    DWORD got = 0;
    memset(p, 0, sizeof *p);
    p->op = op; p->target = p->other = p->extra = p->holder = INVALID_SOCKET;
    p->ev = acc_event();
    if (!p->ev) return 0;
    acc_ov_init(&p->ov, p->ev);
    p->io.Status = ST_PENDING;
    switch (op) {
    case OP_RECV_TCP: case OP_NTREAD: case OP_POLL: {
        SOCKET c, s;
        if (!acc_pair(&c, &s)) return 0;
        p->target = c; p->other = s;
        break;
    }
    case OP_SEND_FULL: {
        SOCKET c, s;
        if (!acc_pair(&c, &s)) return 0;
        p->target = c; p->other = s;
        if (acc_fill_send(c, 32u << 20) == 0) return 0;
        break;
    }
    case OP_RECV_UDP:
        p->target = acc_udp(&a);
        if (p->target == INVALID_SOCKET) return 0;
        break;
    case OP_ACCEPT:
        p->target = acc_listener(&a);
        p->extra = acc_sock(SOCK_STREAM);
        if (p->target == INVALID_SOCKET || p->extra == INVALID_SOCKET) return 0;
        break;
    case OP_ADDRCHANGE:
        p->target = acc_sock(SOCK_STREAM);
        if (p->target == INVALID_SOCKET) return 0;
        break;
    default: return 0;
    }
    if (port) {
        if (CreateIoCompletionPort((HANDLE)p->target, port, key, 0) != port) return 0;
    }
    switch (op) {
    case OP_RECV_TCP:
        p->wb.buf = p->buf; p->wb.len = 16;
        if (U(WSARecv)(p->target, &p->wb, 1, NULL, &p->flags, &p->ov, NULL) != SOCKET_ERROR || WERR() != WSA_IO_PENDING) return 0;
        break;
    case OP_RECV_UDP:
        p->wb.buf = p->buf; p->wb.len = 16; p->fromlen = sizeof p->from;
        if (U(WSARecvFrom)(p->target, &p->wb, 1, NULL, &p->flags, (struct sockaddr *)&p->from, &p->fromlen, &p->ov, NULL) != SOCKET_ERROR
            || WERR() != WSA_IO_PENDING) return 0;
        break;
    case OP_ACCEPT:
        if (U(AcceptEx)(p->target, p->extra, p->buf, 0, 32, 32, &got, &p->ov) || WERR() != WSA_IO_PENDING) return 0;
        break;
    case OP_ADDRCHANGE:
        if (U(WSAIoctl)(p->target, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0, &got, &p->ov, NULL) != SOCKET_ERROR
            || WERR() != WSA_IO_PENDING) return 0;
        break;
    case OP_SEND_FULL:
        p->wb.buf = p->buf; p->wb.len = sizeof p->buf;
        if (U(WSASend)(p->target, &p->wb, 1, NULL, 0, &p->ov, NULL) != SOCKET_ERROR || WERR() != WSA_IO_PENDING) return 0;
        break;
    case OP_NTREAD: {
        LONG st;
        p->is_nt = 1;
        LARGE_INTEGER off; off.QuadPart = 0;
        st = UN(NtReadFile)((HANDLE)p->target, p->ev, NULL, &p->io, &p->io, p->buf, 16, &off, NULL);
        if (st != ST_PENDING) { t_note("NtReadFile did not pend: %#lx", (unsigned long)st); return 0; }
        break;
    }
    case OP_POLL: {
        pollin_t *pi = (pollin_t *)p->poll;
        LONG st;
        p->is_nt = 1;
        pi->timeout = -(LONGLONG)20000 * 10000;     /* 20 s relative: far longer than any test waits */
        pi->count = 1; pi->exclusive = 0;
        pi->e[0].h = (ULONG_PTR)p->target; pi->e[0].flags = AFD_POLL_RECEIVE | AFD_POLL_DISC | AFD_POLL_ABORT; pi->e[0].status = 0;
        st = UN(NtDeviceIoControlFile)((HANDLE)p->target, p->ev, NULL, &p->io, &p->io, AFD_IOCTL_POLL, p->poll, sizeof(pollin_t), p->poll, sizeof(pollin_t));
        if (st != ST_PENDING) return 0;
        break;
    }
    }
    return 1;
}

void acc_pend_done(pend_t *p)
{
    if (p->target != INVALID_SOCKET) CLOSES(p->target);
    if (p->other != INVALID_SOCKET) CLOSES(p->other);
    if (p->extra != INVALID_SOCKET) CLOSES(p->extra);
    p->target = p->other = p->extra = INVALID_SOCKET;
    if (p->ev) CloseHandle(p->ev);
    p->ev = NULL;
}

int acc_pend_wait(pend_t *p, int ms)
{
    return WaitForSingleObject(p->ev, ms) == WAIT_OBJECT_0;
}

LONG acc_pend_status(const pend_t *p)
{
    return p->is_nt ? (LONG)p->io.Status : OV_STATUS(&p->ov);
}
