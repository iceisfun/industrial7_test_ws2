/* Helpers for the dx_gap_02 area: guarded registration and removal of a service class under a throwaway id.
 * Everything created here carries ids owned by this corpus, runs only elevated, is swept before and after
 * each test, and never touches an entry it did not create. Entry points are reached through
 * LoadLibrary -> GetProcAddress. */
#ifndef DX2_H
#define DX2_H
#include "t.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <nspapi.h>
#include <wchar.h>

#undef EXPECT_EQ
#define EXPECT_EQ(a, b) do { unsigned long long ea_ = (unsigned long long)(ULONG_PTR)(a), eb_ = (unsigned long long)(ULONG_PTR)(b); \
    t_check(ea_ == eb_, __FILE__, __LINE__, #a " == " #b, "got 0x%llx want 0x%llx", ea_, eb_); } while (0)

#define WS(name) UIN("ws2_32.dll", name)
#define DX_N(a) ((int)(sizeof(a) / sizeof((a)[0])))
#define W_ERR()     (WS(WSAGetLastError)())
#define W_SETERR(e) (WS(WSASetLastError)(e))

#define DE_FAULT 10014
#define DE_INVAL 10022

extern const GUID dx2_class_a;   /* throwaway service class ids */
extern const GUID dx2_class_b;

int  dx2_up(void);
#define DX2_NEED() do { if (!dx2_up()) { t_skip("WSAStartup failed"); return; } } while (0)
int  dx2_elevated(void);
#define DX2_ELEVATED() do { if (!dx2_elevated()) { t_skip("not elevated"); return; } } while (0)

/* Remove the class from every provider; never fails the test. */
void dx2_sweep(void);
/* Install a one-value class under id with the given W name; returns 0 or the WSA error. */
int  dx2_install(const GUID *id, const WCHAR *name, DWORD ns, DWORD value);
#endif
