/* Guest probe: reports the identity the process runs with and proves that loopback TCP works.
 * Prints PROBE lines only (no OK/FAIL), exit 0 always; the verdict is read from the lines:
 *   session, user SID, integrity RID, elevation, restricted flag, window station, desktop, privileges,
 *   Administrators membership, then "loopback=ok|fail:<step>" from a listen/connect/accept/send/recv round
 *   trip on 127.0.0.1 with an ephemeral port. ws2_32 is loaded dynamically, never linked. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *tinfo(HANDLE t, TOKEN_INFORMATION_CLASS c) {
    DWORD n = 0; GetTokenInformation(t, c, NULL, 0, &n);
    void *p = n ? malloc(n) : NULL;
    if (p && !GetTokenInformation(t, c, p, n, &n)) { free(p); p = NULL; }
    return p;
}
static const char *loopback(void) {
    HMODULE m = LoadLibraryA("ws2_32.dll"); if (!m) return "fail:load";
#define P(n) typeof(&n) p_##n = (typeof(&n))GetProcAddress(m, #n); if (!p_##n) return "fail:resolve_" #n
    P(WSAStartup); P(WSACleanup); P(socket); P(bind); P(listen); P(getsockname); P(connect); P(accept); P(send); P(recv); P(closesocket); P(setsockopt);
    WSADATA wd; if (p_WSAStartup(MAKEWORD(2, 2), &wd)) return "fail:startup";
    const char *r = "ok";
    SOCKET l = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), c = INVALID_SOCKET, a = INVALID_SOCKET;
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_addr.s_addr = 0x0100007fu /* 127.0.0.1, network order on little-endian */;
    int len = sizeof sa; char buf[8] = { 0 }; DWORD tmo = 5000;
    if (l == INVALID_SOCKET) { r = "fail:socket"; goto out; }
    if (p_bind(l, (struct sockaddr *)&sa, sizeof sa) || p_listen(l, 1) || p_getsockname(l, (struct sockaddr *)&sa, &len)) { r = "fail:listen"; goto out; }
    c = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    p_setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (char *)&tmo, sizeof tmo);
    if (c == INVALID_SOCKET || p_connect(c, (struct sockaddr *)&sa, sizeof sa)) { r = "fail:connect"; goto out; }
    a = p_accept(l, NULL, NULL); if (a == INVALID_SOCKET) { r = "fail:accept"; goto out; }
    p_setsockopt(a, SOL_SOCKET, SO_RCVTIMEO, (char *)&tmo, sizeof tmo);
    if (p_send(c, "ping", 4, 0) != 4) { r = "fail:send"; goto out; }
    if (p_recv(a, buf, sizeof buf, 0) != 4 || memcmp(buf, "ping", 4)) { r = "fail:recv"; goto out; }
    if (p_send(a, "pong", 4, 0) != 4 || p_recv(c, buf, sizeof buf, 0) != 4 || memcmp(buf, "pong", 4)) r = "fail:echo";
out:
    if (a != INVALID_SOCKET) p_closesocket(a);
    if (c != INVALID_SOCKET) p_closesocket(c);
    if (l != INVALID_SOCKET) p_closesocket(l);
    p_WSACleanup();
    return r;
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    HANDLE t; OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t);
    DWORD sid = (DWORD)-1; ProcessIdToSessionId(GetCurrentProcessId(), &sid);
    printf("PROBE session=%lu\n", sid);
    TOKEN_USER *u = tinfo(t, TokenUser); char *s = NULL;
    if (u && ConvertSidToStringSidA(u->User.Sid, &s)) {
        /* the account's own RID is guest-specific: print only the well-known classification */
        const char *k = strstr(s, "-500") ? "builtin-administrator" : strstr(s, "-501") ? "guest" : "other-account";
        printf("PROBE account=%s\n", k);
    }
    TOKEN_MANDATORY_LABEL *il = tinfo(t, TokenIntegrityLevel);
    if (il) { PUCHAR n = GetSidSubAuthorityCount(il->Label.Sid); printf("PROBE integrity_rid=0x%lx\n", *GetSidSubAuthority(il->Label.Sid, *n - 1)); }
    TOKEN_ELEVATION_TYPE et = 0; DWORD n; GetTokenInformation(t, TokenElevationType, &et, sizeof et, &n);
    TOKEN_ELEVATION el = { 0 }; GetTokenInformation(t, TokenElevation, &el, sizeof el, &n);
    DWORD restricted = 0; GetTokenInformation(t, TokenHasRestrictions, &restricted, sizeof restricted, &n);
    printf("PROBE elevation_type=%d is_elevated=%lu has_restrictions=%lu\n", (int)et, el.TokenIsElevated, restricted);
    char nm[128] = "?";
    GetUserObjectInformationA(GetProcessWindowStation(), UOI_NAME, nm, sizeof nm, &n);
    printf("PROBE window_station=%s\n", nm);
    strcpy(nm, "?");
    GetUserObjectInformationA(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, nm, sizeof nm, &n);
    printf("PROBE desktop=%s\n", nm);
    TOKEN_PRIVILEGES *tp = tinfo(t, TokenPrivileges); int dbg = 0;
    if (tp) for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
        char pn[64]; DWORD l = sizeof pn; LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, pn, &l);
        if (!strcmp(pn, "SeDebugPrivilege")) dbg = 1;
    }
    printf("PROBE privileges=%lu SeDebugPrivilege=%s\n", tp ? tp->PrivilegeCount : 0, dbg ? "present" : "absent");
    PSID adm = NULL; ConvertStringSidToSidA("S-1-5-32-544", &adm);
    TOKEN_GROUPS *g = tinfo(t, TokenGroups); const char *state = "not-in-token";
    if (g) for (DWORD i = 0; i < g->GroupCount; i++) if (EqualSid(g->Groups[i].Sid, adm)) {
        DWORD a = g->Groups[i].Attributes;
        state = (a & SE_GROUP_USE_FOR_DENY_ONLY) ? "deny-only" : (a & SE_GROUP_ENABLED) ? "enabled" : "disabled";
    }
    printf("PROBE administrators_sid=%s\n", state);
    printf("PROBE loopback=%s\n", loopback());
    return 0;
}
