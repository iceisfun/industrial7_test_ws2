/* lift_04: SO_OPENTYPE, the per-thread default for overlapped vs. synchronous socket creation.
 * It is addressed with INVALID_SOCKET (no socket involved), is stored per thread, and every new thread
 * starts at 0 regardless of what its creator set. */
#include "l4.h"

static int set_opentype(int v) { return sso(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, &v, sizeof v); }
static int get_opentype(int *v) { int sz = sizeof *v; return gso(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, v, &sz); }

TEST(opentype_roundtrip_without_socket)
{
    int v = -1, i;
    if (!ws_up()) return;
    for (i = 1; i >= 0; i--) {
        EQ(set_opentype(i), 0);
        v = -1;
        EQ(get_opentype(&v), 0);
        EQ(v, i);
    }
    ws_down();
}

static DWORD WINAPI opentype_thread(LPVOID p)
{
    int v = 77;
    if (get_opentype(&v)) return 100;
    return (DWORD)v;
}

TEST(opentype_new_thread_starts_at_zero)
{
    HANDLE h; DWORD id, rc = 55;
    if (!ws_up()) return;
    EQ(set_opentype(1), 0);          /* creator selects synchronous sockets */
    h = CreateThread(NULL, 0, opentype_thread, NULL, 0, &id);
    CHECK(h != NULL);
    if (h) {
        EQ(WaitForSingleObject(h, 10000), WAIT_OBJECT_0);
        GetExitCodeThread(h, &rc);
        CloseHandle(h);
    }
    EQ(rc, 0);
    set_opentype(0);
    ws_down();
}

TEST(opentype_value_sticks_until_reset)
{
    int v = -1;
    if (!ws_up()) return;
    EQ(set_opentype(1), 0);
    EQ(get_opentype(&v), 0);
    EQ(v, 1);
    set_opentype(0);
    EQ(get_opentype(&v), 0);
    EQ(v, 0);
    ws_down();
}
