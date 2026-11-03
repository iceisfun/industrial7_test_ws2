/* Table-driven sweeps over AcceptEx accept-socket kinds and address-slot sizes, oversized TransmitFile head and
 * tail buffers, and the extension functions on AF_UNIX sockets (observations only: what is offered and what each
 * call reports). */
#include "mx.h"

#define ADDR4 ((DWORD)(sizeof(struct sockaddr_in) + 16))

/* Slot sizes at and above the minimum all work, and the length field always reads sizeof(sockaddr_in). */
TEST(matrix_acceptex_slot_sizes_at_or_above_the_minimum_complete)
{
    static const DWORD sizes[] = { 32, 33, 40, 48, 64, 100, 256, 1024 };
    struct mx_ext x;
    struct sockaddr_in addr;
    SOCKET lst;
    unsigned i, j;
    NEED_NET();
    if (!mx_load_ext(&x)) { t_skip("extension functions not offered"); return; }
    lst = mx_listener(&addr, 8);
    for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) for (j = 0; j < sizeof sizes / sizeof sizes[0]; j += 3) {
        unsigned char *buf = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizes[i] + sizes[j] + 8);
        OVERLAPPED ov;
        SOCKET acc = mx_tcp(), cli = mx_tcp();
        struct sockaddr_in *pl = NULL, *pr = NULL;
        int ll = 0, rl = 0;
        DWORD n = 0, err = 0;
        memset(&ov, 0, sizeof ov);
        ov.hEvent = mx_event();
        x.acceptex(lst, acc, buf, 0, sizes[i], sizes[j], &n, &ov);
        CHECK(mx_connect(cli, (struct sockaddr *)&addr, sizeof addr) == 0);
        t_check(mx_ov_done(lst, &ov, &n, 5000, &err), __FILE__, __LINE__, "completes", "local %lu remote %lu err %lu", sizes[i], sizes[j], err);
        x.gaes(buf, 0, sizes[i], sizes[j], (struct sockaddr **)&pl, &ll, (struct sockaddr **)&pr, &rl);
        t_check(ll == sizeof(struct sockaddr_in) && rl == sizeof(struct sockaddr_in) && pl && pr && pl->sin_port == addr.sin_port,
                __FILE__, __LINE__, "slots parse", "local %lu remote %lu: ll %d rl %d", sizes[i], sizes[j], ll, rl);
        CloseHandle(ov.hEvent);
        mx_closesocket(cli); mx_closesocket(acc);
        HeapFree(GetProcessHeap(), 0, buf);
    }
    mx_closesocket(lst);
}

/* Accept-socket kinds beyond the ones other areas pin down; the results are recorded, with the property that
 * must hold on any answer asserted: the call never reports success without a connection. */
TEST(matrix_acceptex_unusual_accept_sockets_recorded)
{
    struct mx_ext x;
    struct sockaddr_in addr;
    SOCKET lst, acc[4];
    static const char *what[4] = { "the listening socket itself", "another listening socket", "IPv6 stream socket", "non-overlapped stream socket" };
    struct sockaddr_in addr2;
    unsigned i;
    NEED_NET();
    if (!mx_load_ext(&x)) { t_skip("extension functions not offered"); return; }
    lst = mx_listener(&addr, 8);
    acc[0] = lst;
    acc[1] = mx_listener(&addr2, 2);
    acc[2] = mx_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    acc[3] = mx_WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    for (i = 0; i < 4; i++) {
        OVERLAPPED ov;
        unsigned char buf[128];
        DWORD n = 0;
        int e;
        if (acc[i] == INVALID_SOCKET) { t_note("%s: could not be created", what[i]); continue; }
        memset(&ov, 0, sizeof ov);
        ov.hEvent = mx_event();
        e = x.acceptex(lst, acc[i], buf, 0, 32, 32, &n, &ov) ? 0 : mx_WSAGetLastError();
        t_note("AcceptEx with %s as the accept socket: %s %d", what[i], e == ERROR_IO_PENDING ? "pending" : "immediate", e);
        if (e == ERROR_IO_PENDING) {
            if (i == 3) {   /* a usable candidate: finish the accept so the handle is quiescent */
                SOCKET c = mx_tcp();
                mx_connect(c, (struct sockaddr *)&addr, sizeof addr);
                mx_ov_done(lst, &ov, &n, 3000, NULL);
                mx_closesocket(c);
            } else {
                CancelIo((HANDLE)lst);
                WaitForSingleObject(ov.hEvent, 1000);
            }
        }
        CloseHandle(ov.hEvent);
    }
    mx_closesocket(acc[1]); mx_closesocket(acc[2]); mx_closesocket(acc[3]); mx_closesocket(lst);
}

/* Head and tail buffers far larger than the socket buffers, with the file between them. */
TEST(matrix_transmitfile_oversized_head_and_tail_arrive_whole)
{
    enum { HB = 300 * 1024, TB = 200 * 1024, FB = 64 * 1024 };
    struct mx_ext x;
    TRANSMIT_FILE_BUFFERS b;
    unsigned char *head = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, HB);
    unsigned char *tail = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, TB);
    struct mx_sink k;
    HANDLE f;
    int bad = 0, i;
    MX_PAIR(c, a);
    if (!mx_load_ext(&x)) { mx_closesocket(c); mx_closesocket(a); t_skip("extension functions not offered"); return; }
    mx_fill(head, HB, 1, 0);
    mx_fill(tail, TB, 2, 0);
    f = mx_make_file("mx_ht.bin", FB, 3, GENERIC_READ | GENERIC_WRITE, 0);
    b.Head = head; b.HeadLength = HB; b.Tail = tail; b.TailLength = TB;
    mx_sink_start(&k, a, HB + FB + TB);
    CHECK(x.transmitfile(c, f, 0, 0, NULL, &b, 0));
    MX_EQ(mx_sink_join(&k), HB + FB + TB);
    for (i = 0; i < HB + FB + TB && k.got == HB + FB + TB; i += 61) {
        unsigned char want = i < HB ? mx_pat((DWORD)i, 1) : i < HB + FB ? mx_pat((DWORD)(i - HB), 3) : mx_pat((DWORD)(i - HB - FB), 2);
        if (k.buf[i] != want) bad++;
    }
    MX_EQ(bad, 0);
    mx_sink_free(&k);
    CloseHandle(f);
    HeapFree(GetProcessHeap(), 0, head);
    HeapFree(GetProcessHeap(), 0, tail);
    mx_closesocket(c); mx_closesocket(a);
}

/* ---- AF_UNIX ------------------------------------------------------------------------------------------------- */

struct sockaddr_un_ { USHORT sun_family; char sun_path[108]; };

static SOCKET unix_stream(void) { return mx_socket(AF_UNIX, SOCK_STREAM, 0); }

TEST(matrix_afunix_extension_pointers_offered_recorded)
{
    SOCKET s;
    GUID ids[6] = { WSAID_ACCEPTEX, WSAID_GETACCEPTEXSOCKADDRS, WSAID_CONNECTEX, WSAID_DISCONNECTEX, WSAID_TRANSMITFILE, WSAID_TRANSMITPACKETS };
    static const char *names[6] = { "AcceptEx", "GetAcceptExSockaddrs", "ConnectEx", "DisconnectEx", "TransmitFile", "TransmitPackets" };
    int i;
    NEED_NET();
    s = unix_stream();
    if (s == INVALID_SOCKET) { t_skip("AF_UNIX not available"); return; }
    for (i = 0; i < 6; i++) {
        void *fn = mx_ext_lookup(s, ids[i]);
        t_note("AF_UNIX stream socket, %s pointer: %s (err %d)", names[i], fn ? "offered" : "refused", fn ? 0 : mx_WSAGetLastError());
    }
    mx_closesocket(s);
}

TEST(matrix_afunix_acceptex_and_transmitfile_on_unconnected_sockets_recorded)
{
    SOCKET s, acc;
    LPFN_ACCEPTEX ax;
    LPFN_TRANSMITFILE tf;
    unsigned char buf[256];
    OVERLAPPED ov;
    DWORD n = 0;
    int e;
    NEED_NET();
    s = unix_stream();
    if (s == INVALID_SOCKET) { t_skip("AF_UNIX not available"); return; }
    acc = unix_stream();
    ax = (LPFN_ACCEPTEX)mx_ext_lookup(s, (GUID)WSAID_ACCEPTEX);
    tf = (LPFN_TRANSMITFILE)mx_ext_lookup(s, (GUID)WSAID_TRANSMITFILE);
    memset(&ov, 0, sizeof ov);
    ov.hEvent = mx_event();
    if (ax) {
        e = ax(s, acc, buf, 0, 128 + 16, 128 + 16, &n, &ov) ? 0 : mx_WSAGetLastError();
        t_note("AcceptEx on a non-listening AF_UNIX socket: error %d", e);
    }
    if (tf) {
        e = tf(s, NULL, 0, 0, NULL, NULL, 0) ? 0 : mx_WSAGetLastError();
        t_note("TransmitFile on an unconnected AF_UNIX socket: error %d", e);
    }
    CloseHandle(ov.hEvent);
    mx_closesocket(acc);
    mx_closesocket(s);
}
