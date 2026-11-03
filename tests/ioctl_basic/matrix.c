/* Measures the outcome of WSAIoctl for every control code in scope across a matrix of socket kinds (unbound
 * stream, datagram, listening, connected-then-peer-closed, IPv6 stream/datagram, AF_UNIX), call modes (plain
 * with a byte count, plain without a byte count, overlapped with an event) and input/output buffer lengths
 * (0, 4, 16, 32 in; 0, 4, 16, 4096 out).  Each cell is a short string:
 *     ok            success, byte count untouched          ok:N   success, byte count N
 *     E<code>       failure with WSAGetLastError code      E<code>:N  failure, byte count N
 *     P<...>        overlapped call returned WSA_IO_PENDING; the rest is the final outcome (Pok<ec>:N / PE<code>:N)
 * A '*' count stands for "any non-zero count" where the size depends on the machine's address set.
 * Control codes whose behaviour is to wait for a network event, or that fault, are only present for the
 * combinations that complete immediately.  The expected strings were taken from genuine Windows 10 22H2. */
#include "ib.h"

typedef struct { unsigned char kind, mode, inl; const char *cell[4]; } mx_row;
static const int MX_OUT[4] = {0, 4, 16, 4096};

/* Run one cell; text receives the outcome string. */
static void mx_cell(char *text, int mode, SOCKET s, DWORD code, int dw1, int async, int inl, int outl)
{
    unsigned char in[64], out[4200];
    DWORD n = 0xffffffffu, t = 0, fl = 0;
    WSAOVERLAPPED ov;
    int r, e;
    memset(in, 0, sizeof in);
    if (dw1) *(DWORD *)in = 1;
    memset(out, 0xcc, sizeof out);
    if (async) { u_long one = 1; U(ioctlsocket)(s, FIONBIO, &one); }
    memset(&ov, 0, sizeof ov);
    if (mode == 0) r = U(WSAIoctl)(s, code, in, inl, out, outl, &n, NULL, NULL);
    else if (mode == 1) r = U(WSAIoctl)(s, code, in, inl, out, outl, NULL, NULL, NULL);
    else { ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL); r = U(WSAIoctl)(s, code, in, inl, out, outl, &n, &ov, NULL); }
    e = ib_err();
    if (mode < 2 || r == 0) {
        if (r == 0) strcpy(text, "ok"); else sprintf(text, "E%d", e);
        if (n != 0xffffffffu) sprintf(text + strlen(text), ":%lu", n);
    } else if (e != WSA_IO_PENDING) {
        sprintf(text, "E%d", e);            /* overlapped call failed at once: the byte count is not part of the key */
    } else {
        if (WaitForSingleObject(ov.hEvent, t_is_wine() ? 50 : 3000) != WAIT_OBJECT_0) {
            CancelIoEx((HANDLE)s, (LPOVERLAPPED)&ov);
            WaitForSingleObject(ov.hEvent, 1000);
            strcpy(text, "P-timeout");
        } else {
            BOOL ok = U(WSAGetOverlappedResult)(s, &ov, &t, FALSE, &fl);
            sprintf(text, "P%s%d:%lu", ok ? "ok" : "E", ok ? 0 : ib_err(), t);
        }
    }
    if (mode == 2) CloseHandle(ov.hEvent);
}

/* Compare an outcome with an expectation; a trailing ":*" in the expectation accepts any non-zero count. */
static int mx_match(const char *got, const char *want)
{
    size_t w = strlen(want);
    if (w >= 2 && !strcmp(want + w - 2, ":*")) {
        const char *c = strrchr(got, ':');
        return c && strncmp(got, want, w - 1) == 0 && c == got + (w - 2) && strcmp(c, ":0") != 0;
    }
    return !strcmp(got, want);
}

static const char *const mx_kind_name[] = {"tcp4", "udp4", "listen4", "tcp6", "udp6", "unix", "conn4"};
static const int mx_kind_of[] = {K_TCP4, K_UDP4, K_LISTEN4, K_TCP6, K_UDP6, K_UNIX, K_CONN4};

static void mx_run(const char *name, DWORD code, int dw1, int async, const mx_row *rows, unsigned count)
{
    unsigned i;
    int o, seen_unix = 0;
    if (!ib_up()) { t_skip("WSAStartup failed"); return; }
    for (i = 0; i < count; ++i) {
        const mx_row *w = &rows[i];
        if (t_is_wine() && (i % 9)) continue;   /* emulator socket setup is slow; sample the table */
        for (o = 0; o < 4; ++o) {
            char text[160];
            SOCKET s = ib_mk(mx_kind_of[w->kind]);
            if (s == INVALID_SOCKET) {
                if (!seen_unix) { t_note("%s: socket kind %s unavailable", name, mx_kind_name[w->kind]); seen_unix = 1; }
                break;
            }
            mx_cell(text, w->mode, s, code, dw1, async, w->inl, MX_OUT[o]);
            ib_close(s);
            CHECKF(mx_match(text, w->cell[o]), "%s %s mode %d in %d out %d: got %s want %s", name,
                   mx_kind_name[w->kind], w->mode, w->inl, MX_OUT[o], text, w->cell[o]);
        }
    }
}

#include "matrix_data.h"
#define MXTEST(nm, code, dw1, async) \
    TEST(ib_matrix_##nm) { mx_run(#nm, code, dw1, async, mx_##nm, sizeof mx_##nm / sizeof mx_##nm[0]); }
#include "matrix_tests.h"
