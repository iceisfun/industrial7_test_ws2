/* Launch a command line as an unprivileged account, for the "std" run mode.
 *
 * usage: ws2_runas.exe --user NAME --pass PASSWORD <command line>     real local standard user
 *        ws2_runas.exe --restricted <command line>                     restricted-admin fallback
 *
 * --user: the account must already exist (the runner creates it inside the throwaway guest). The child is
 *   started with CreateProcessWithLogonW and a profile, so it runs as a genuine local standard user: its own
 *   SID, Medium integrity, not elevated, no Administrators membership, the standard five privileges. Verified
 *   on Windows 10 22H2: it lands in the caller's interactive session on WinSta0\Default.
 * --restricted: the older approach. A CreateRestrictedToken copy of the caller's elevated Administrator token
 *   (privileges stripped, Administrators and other powerful aliases deny-only, Medium integrity) started on
 *   winsta0\default in the caller's session. It is a restricted-admin token, NOT a real standard account: the
 *   user SID is still the Administrator's, and the token carries the restricted marker.
 *
 * In both modes the child's standard handles are inherited from this process and it runs inside a
 * kill-on-close job, so killing this helper kills the whole tree.
 * Exit code: the child's exit code, or 0xDEAD00xx when launching failed (message on stderr). */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <shellapi.h>

#define FAIL(code, what) do { fprintf(stderr, "ws2_runas: %s failed, error %lu\n", what, GetLastError()); return 0xDEAD0000 | (code); } while (0)

static void enable_priv(HANDLE tok, const wchar_t *name) {
    TOKEN_PRIVILEGES tp; tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid)) AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
}
static void *tok_info(HANDLE t, TOKEN_INFORMATION_CLASS c) {
    DWORD n = 0; GetTokenInformation(t, c, NULL, 0, &n);
    void *p = n ? malloc(n) : NULL;
    if (p && !GetTokenInformation(t, c, p, n, &n)) { free(p); p = NULL; }
    return p;
}
static HANDLE make_job(void) {
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION li; memset(&li, 0, sizeof li);
        li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &li, sizeof li);
    }
    return job;
}
static int finish(HANDLE job, PROCESS_INFORMATION *pi) {
    if (job && !AssignProcessToJobObject(job, pi->hProcess)) fprintf(stderr, "ws2_runas: warning, job assign failed %lu\n", GetLastError());
    ResumeThread(pi->hThread);
    WaitForSingleObject(pi->hProcess, INFINITE);
    DWORD rc = 0; GetExitCodeProcess(pi->hProcess, &rc);
    return (int)rc;
}
/* Skip the first n argument tokens of the command line (the program name counts as one). */
static const wchar_t *skip_tokens(int n) {
    const wchar_t *p = GetCommandLineW();
    for (int i = 0; i < n; i++) {
        while (*p == L' ' || *p == L'\t') p++;
        if (*p == L'"') { p++; while (*p && *p != L'"') p++; if (*p) p++; }
        else while (*p && *p != L' ' && *p != L'\t') p++;
    }
    while (*p == L' ' || *p == L'\t') p++;
    return p;
}

static int run_real(const wchar_t *user, const wchar_t *pass, const wchar_t *cmd) {
    HANDLE job = make_job();
    wchar_t *cl = _wcsdup(cmd);
    STARTUPINFOW si; memset(&si, 0, sizeof si); si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE); si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE); si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi;
    if (!CreateProcessWithLogonW(user, L".", pass, LOGON_WITH_PROFILE, NULL, cl, CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP, NULL, L"C:\\ws2t\\cwd", &si, &pi))
        FAIL(8, "CreateProcessWithLogonW");
    return finish(job, &pi);
}

static int run_restricted(const wchar_t *cmd) {
    HANDLE self = NULL, rtok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &self)) FAIL(2, "OpenProcessToken");
    enable_priv(self, L"SeIncrementQuotaPrivilege");
    enable_priv(self, L"SeAssignPrimaryTokenPrivilege");
    static const char *powerful[] = { "S-1-5-32-544", "S-1-5-32-547", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550",
                                      "S-1-5-32-551", "S-1-5-32-552", "S-1-5-32-556", "S-1-5-32-578", "S-1-5-32-580" };
    PSID psid[16]; int np = 0;
    for (int i = 0; i < (int)(sizeof powerful / sizeof *powerful); i++) { PSID s = NULL; if (ConvertStringSidToSidA(powerful[i], &s)) psid[np++] = s; }
    TOKEN_GROUPS *groups = tok_info(self, TokenGroups);
    if (!groups) FAIL(3, "TokenGroups");
    SID_AND_ATTRIBUTES dis[16]; int nd = 0;
    for (DWORD g = 0; g < groups->GroupCount; g++)
        for (int i = 0; i < np; i++)
            if (EqualSid(groups->Groups[g].Sid, psid[i]) && nd < 16) { dis[nd].Sid = groups->Groups[g].Sid; dis[nd].Attributes = 0; nd++; }
    if (!CreateRestrictedToken(self, DISABLE_MAX_PRIVILEGE, nd, nd ? dis : NULL, 0, NULL, 0, NULL, &rtok)) FAIL(4, "CreateRestrictedToken");
    PSID med = NULL; ConvertStringSidToSidA("S-1-16-8192", &med);
    TOKEN_MANDATORY_LABEL tml = { { med, SE_GROUP_INTEGRITY } };
    if (!SetTokenInformation(rtok, TokenIntegrityLevel, &tml, sizeof tml + GetLengthSid(med))) FAIL(5, "set integrity");
    TOKEN_USER *user = tok_info(self, TokenUser);
    if (!user) FAIL(6, "TokenUser");
    TOKEN_OWNER own = { user->User.Sid };
    SetTokenInformation(rtok, TokenOwner, &own, sizeof own);
    {
        PSID sys = NULL; ConvertStringSidToSidA("S-1-5-18", &sys);
        DWORD sz = sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(user->User.Sid) + GetLengthSid(sys) + 16;
        ACL *acl = calloc(1, sz);
        InitializeAcl(acl, sz, ACL_REVISION);
        AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, user->User.Sid);
        AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, sys);
        TOKEN_DEFAULT_DACL dd = { acl };
        SetTokenInformation(rtok, TokenDefaultDacl, &dd, sizeof dd);
    }
    HANDLE job = make_job();
    wchar_t *cl = _wcsdup(cmd);
    STARTUPINFOW si; memset(&si, 0, sizeof si); si.cb = sizeof si;
    si.lpDesktop = L"winsta0\\default";
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE); si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE); si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi;
    if (!CreateProcessAsUserW(rtok, NULL, cl, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi)) {
        if (!CreateProcessAsUserW(rtok, NULL, cl, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi)) FAIL(7, "CreateProcessAsUser");
    }
    return finish(job, &pi);
}

int main(void) {
    int argc; wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    const wchar_t *user = NULL, *pass = NULL; int restricted = 0, i = 1;
    for (; i < argc; i++) {
        if (!wcscmp(argv[i], L"--user") && i + 1 < argc) user = argv[++i];
        else if (!wcscmp(argv[i], L"--pass") && i + 1 < argc) pass = argv[++i];
        else if (!wcscmp(argv[i], L"--restricted")) restricted = 1;
        else break;
    }
    const wchar_t *cmd = skip_tokens(i);
    if (!*cmd || (!restricted && !(user && pass))) { fprintf(stderr, "usage: ws2_runas (--user N --pass P | --restricted) <command line>\n"); return 0xDEAD0001; }
    return restricted ? run_restricted(cmd) : run_real(user, pass, cmd);
}
