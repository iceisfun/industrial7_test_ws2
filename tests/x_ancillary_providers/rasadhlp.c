/* The autodial helper (rasadhlp.dll). Measures: that every entry point declines politely for the inputs that need no
 * dial-up state: an unrelated or unsupported address family, an empty name, a query for a different class, and
 * loopback targets. Nothing is recorded in the autodial database (the notification routine is called with empty input only). */
#include "anc.h"

typedef DWORD (WINAPI *acs_fn)(LPCWSTR);
typedef DWORD (WINAPI *addr_fn)(const SOCKADDR *);
typedef DWORD (WINAPI *name_fn)(void *);
typedef void (WINAPI *note_fn)(const char *, DWORD);
static void *rfn(const char *n) { HMODULE m = t_module("rasadhlp.dll"); return m ? (void *)GetProcAddress(m, n) : NULL; }

TEST(autodial_addr_declines_every_family) {
    addr_fn f = rfn("WSAttemptAutodialAddr"); if (!f) { t_skip("rasadhlp.dll absent"); return; }
    static const int fams[] = { 0, 1, 3, 6, 11, 17, 18, 23, 24, 32, 0x7fff, 0xffff };
    for (size_t i = 0; i < ANC_N(fams); i++) {
        SOCKADDR_STORAGE s; memset(&s, 0, sizeof s); s.ss_family = (ADDRESS_FAMILY)fams[i];
        CHECKF(f((SOCKADDR *)&s) == 0, "family %d", fams[i]);
    }
}
TEST(autodial_addr_loopback_and_wildcard_are_not_dialled) {
    addr_fn f = rfn("WSAttemptAutodialAddr"); if (!f) { t_skip("rasadhlp.dll absent"); return; }
    SOCKADDR_IN a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons(80);
    a.sin_addr.s_addr = 0x0100007f; CHECK(f((SOCKADDR *)&a) == 0);
    a.sin_addr.s_addr = 0; CHECK(f((SOCKADDR *)&a) == 0);
    a.sin_addr.s_addr = 0x0100007f; a.sin_port = 0; CHECK(f((SOCKADDR *)&a) == 0);
}
TEST(autodial_name_declines_without_a_host_name) {
    name_fn f = rfn("WSAttemptAutodialName"); if (!f) { t_skip("rasadhlp.dll absent"); return; }
    WSAQUERYSETW q; memset(&q, 0, sizeof q); q.dwSize = sizeof q;
    CHECK(f(&q) == 0);                                   /* no name */
    GUID other = { 0x0002a803, 0, 0, { 0xc0, 0, 0, 0, 0, 0, 0, 0x46 } };
    q.lpszServiceInstanceName = L"localhost"; q.lpServiceClassId = &other;
    CHECK(f(&q) == 0);                                   /* not the host-name class */
}
TEST(autodial_netbios_connection_declines_loopback_and_empty_names) {
    acs_fn f = rfn("AcsHlpNbConnection"); if (!f) { t_skip("rasadhlp.dll absent"); return; }
    static const WCHAR *names[] = { NULL, L"", L"127.0.0.1", L"localhost", L"::1" };
    for (size_t i = 0; i < ANC_N(names); i++) CHECKF(f(names[i]) == 0, "name %zu", i);
}
TEST(autodial_note_lookup_ignores_empty_input) {
    note_fn f = rfn("WSNoteSuccessfulHostentLookup"); if (!f) { t_skip("rasadhlp.dll absent"); return; }
    f(NULL, 0); f("", 0); f("", 0x0100007f);
    CHECK(1);
}
TEST(autodial_ordinals_are_in_declaration_order) {
    static const char *const n[] = { "AcsHlpNbConnection", "WSAttemptAutodialAddr", "WSAttemptAutodialName", "WSNoteSuccessfulHostentLookup" };
    HMODULE m = t_module("rasadhlp.dll"); if (!m) { t_skip("rasadhlp.dll absent"); return; }
    for (unsigned i = 0; i < 4; i++) CHECKF(GetProcAddress(m, (LPCSTR)(ULONG_PTR)(i + 1)) == GetProcAddress(m, n[i]), "ordinal %u", i + 1);
}
