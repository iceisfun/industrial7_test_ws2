/* Service-class and service-registration entry points: WSAInstallServiceClass, WSARemoveServiceClass,
 * WSAGetServiceClassInfo and WSASetService (A and W).
 * Measures: the argument checks that run before any provider is asked, which of them run before the
 * per-process initialisation, the error a name space without registration support reports, and
 * the selection of providers by name space. Anything that would really install a class uses a
 * private throwaway GUID, runs only when elevated, and always removes what it may have added. */
#include "nsp.h"

#define W_INSTALL_W UIN("ws2_32.dll", WSAInstallServiceClassW)
#define W_INSTALL_A UIN("ws2_32.dll", WSAInstallServiceClassA)
#define W_REMOVE    UIN("ws2_32.dll", WSARemoveServiceClass)
#define W_GETINFO_W UIN("ws2_32.dll", WSAGetServiceClassInfoW)
#define W_GETINFO_A UIN("ws2_32.dll", WSAGetServiceClassInfoA)
#define W_SET_W     UIN("ws2_32.dll", WSASetServiceW)
#define W_SET_A     UIN("ws2_32.dll", WSASetServiceA)

static int is_elevated(void) {
    HANDLE tok = NULL; TOKEN_ELEVATION el; DWORD got = 0; int r = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &got)) r = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}

/* ---- argument checks ---- */

TEST(sc_install_wide_null_is_invalid) {
    REQUIRE(W_INSTALL_W); NSP_NEED();
    W_SETERR(0);
    EXPECT_EQ(W_INSTALL_W(NULL), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_INVAL);
}

TEST(sc_install_ansi_null_is_invalid) {
    REQUIRE(W_INSTALL_A); NSP_NEED();
    W_SETERR(0);
    EXPECT_EQ(W_INSTALL_A(NULL), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_INVAL);
}

TEST(sc_remove_null_is_invalid) {
    REQUIRE(W_REMOVE); NSP_NEED();
    W_SETERR(0);
    EXPECT_EQ(W_REMOVE(NULL), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_INVAL);
}

TEST(sc_set_service_null_is_fault) {
    REQUIRE(W_SET_W); REQUIRE(W_SET_A); NSP_NEED();
    W_SETERR(0);
    EXPECT_EQ(W_SET_W(NULL, RNRSERVICE_REGISTER, 0), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_FAULT);
    W_SETERR(0);
    EXPECT_EQ(W_SET_A(NULL, RNRSERVICE_REGISTER, 0), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_FAULT);
}

typedef struct { int nul_class, nul_prov, nul_len, nul_out; } gi_case;
static const gi_case gi_cases[] = {
    { 1, 0, 0, 0 }, { 0, 1, 0, 0 }, { 0, 0, 1, 0 }, { 0, 0, 0, 1 },
    { 1, 1, 1, 1 }, { 1, 0, 1, 0 }, { 0, 1, 0, 1 },
};

TEST(sc_get_class_info_wide_null_arguments_are_invalid) {
    size_t i;
    REQUIRE(W_GETINFO_W); NSP_NEED();
    for (i = 0; i < NSP_N(gi_cases); i++) {
        GUID prov = nsp_guid_throwaway, cls = nsp_guid_throwaway; DWORD len = 0x100; BYTE out[0x100];
        INT r;
        W_SETERR(0);
        r = W_GETINFO_W(gi_cases[i].nul_prov ? NULL : &prov, gi_cases[i].nul_class ? NULL : &cls,
                        gi_cases[i].nul_len ? NULL : &len, gi_cases[i].nul_out ? NULL : (LPWSASERVICECLASSINFOW)out);
        CHECKF(r == SOCKET_ERROR, "case %zu returned %d", i, r);
        CHECKF(W_ERR() == (int)E_INVAL, "case %zu error %d", i, W_ERR());
    }
}

TEST(sc_get_class_info_ansi_null_arguments_are_invalid) {
    size_t i;
    REQUIRE(W_GETINFO_A); NSP_NEED();
    for (i = 0; i < NSP_N(gi_cases); i++) {
        GUID prov = nsp_guid_throwaway, cls = nsp_guid_throwaway; DWORD len = 0x100; BYTE out[0x100];
        INT r;
        W_SETERR(0);
        r = W_GETINFO_A(gi_cases[i].nul_prov ? NULL : &prov, gi_cases[i].nul_class ? NULL : &cls,
                        gi_cases[i].nul_len ? NULL : &len, gi_cases[i].nul_out ? NULL : (LPWSASERVICECLASSINFOA)out);
        CHECKF(r == SOCKET_ERROR, "case %zu returned %d", i, r);
        CHECKF(W_ERR() == (int)E_INVAL, "case %zu error %d", i, W_ERR());
    }
}

TEST(sc_get_class_info_unregistered_provider_fails) {
    GUID prov = nsp_guid_throwaway, cls = nsp_guid_throwaway; DWORD len = 0x100; BYTE out[0x100];
    REQUIRE(W_GETINFO_W); NSP_NEED();
    W_SETERR(0);
    EXPECT_EQ(W_GETINFO_W(&prov, &cls, &len, (LPWSASERVICECLASSINFOW)out), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_INVAL);
}

TEST(sc_get_class_info_dns_provider_refuses) {
    /* The DNS entry does not store service classes: the catalog gate answers WSAEINVAL, or if the
     * provider is reached anyway its own GetServiceClassInfo answers WSAEOPNOTSUPP. */
    GUID id, cls = nsp_guid_throwaway; DWORD len = 0x100; BYTE out[0x100];
    REQUIRE(W_GETINFO_W); NSP_NEED();
    if (!nsp_provider_for(NS_DNS, &id)) { t_skip("no DNS provider in the catalog"); return; }
    W_SETERR(0);
    EXPECT_EQ(W_GETINFO_W(&id, &cls, &len, (LPWSASERVICECLASSINFOW)out), SOCKET_ERROR);
    CHECKF(W_ERR() == (int)E_INVAL || W_ERR() == WSAEOPNOTSUPP, "error %d", W_ERR());
}

/* ---- WSASetService provider selection ---- */

static WSAQUERYSETW *set_query(WSAQUERYSETW *qs, DWORD ns) {
    static WCHAR nm[] = L"ws2t-throwaway-service";
    nsp_query_w(qs, nm, &nsp_guid_throwaway, ns);
    return qs;
}

TEST(sc_set_service_unknown_namespace_is_no_data) {
    WSAQUERYSETW qs;
    REQUIRE(W_SET_W); NSP_NEED();
    set_query(&qs, 0x7e57);
    W_SETERR(0);
    EXPECT_EQ(W_SET_W(&qs, RNRSERVICE_REGISTER, 0), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_NODATA);
}

TEST(sc_set_service_unknown_namespace_all_operations) {
    static const WSAESETSERVICEOP ops[] = { RNRSERVICE_REGISTER, RNRSERVICE_DEREGISTER, RNRSERVICE_DELETE };
    size_t i; WSAQUERYSETW qs;
    REQUIRE(W_SET_W); NSP_NEED();
    for (i = 0; i < NSP_N(ops); i++) {
        set_query(&qs, 0x7e57);
        W_SETERR(0);
        CHECKF(W_SET_W(&qs, ops[i], 0) == SOCKET_ERROR, "op %zu accepted", i);
        CHECKF(W_ERR() == (int)E_NODATA, "op %zu error %d", i, W_ERR());
    }
}

TEST(sc_set_service_ansi_unknown_namespace_is_no_data) {
    WSAQUERYSETA qs; char nm[] = "ws2t-throwaway-service";
    REQUIRE(W_SET_A); NSP_NEED();
    nsp_query_a(&qs, nm, &nsp_guid_throwaway, 0x7e57);
    W_SETERR(0);
    EXPECT_EQ(W_SET_A(&qs, RNRSERVICE_REGISTER, 0), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_NODATA);
}

TEST(sc_set_service_dns_namespace_not_supported) {
    /* The DNS provider cannot register services; its SetService fails with ERROR_NOT_SUPPORTED,
     * and that is what the caller sees because DNS is the only provider selected. */
    WSAQUERYSETW qs; GUID id;
    REQUIRE(W_SET_W); NSP_NEED();
    if (!nsp_provider_for(NS_DNS, &id)) { t_skip("no DNS provider in the catalog"); return; }
    set_query(&qs, NS_DNS);
    W_SETERR(0);
    EXPECT_EQ(W_SET_W(&qs, RNRSERVICE_REGISTER, 0), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), ERROR_NOT_SUPPORTED);
}

TEST(sc_set_service_dns_provider_id_not_supported) {
    WSAQUERYSETW qs; GUID id;
    REQUIRE(W_SET_W); NSP_NEED();
    if (!nsp_provider_for(NS_DNS, &id)) { t_skip("no DNS provider in the catalog"); return; }
    set_query(&qs, NS_ALL);
    qs.lpNSProviderId = &id;
    W_SETERR(0);
    EXPECT_EQ(W_SET_W(&qs, RNRSERVICE_REGISTER, 0), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), ERROR_NOT_SUPPORTED);
}

TEST(sc_set_service_unregistered_provider_id_logged) {
    WSAQUERYSETW qs;
    REQUIRE(W_SET_W); NSP_NEED();
    set_query(&qs, NS_ALL);
    qs.lpNSProviderId = (GUID *)&nsp_guid_throwaway;
    W_SETERR(0);
    EXPECT_EQ(W_SET_W(&qs, RNRSERVICE_REGISTER, 0), SOCKET_ERROR);
    EXPECT_EQ(W_ERR(), E_NODATA);
}

/* ---- guarded installs (private class id) ---- */

static void fill_class_w(WSASERVICECLASSINFOW *sc, WSANSCLASSINFOW *ci, DWORD *val) {
    static WCHAR cname[] = L"ws2t-throwaway-class", vname[] = L"ws2tValue";
    *val = 0x1234;
    memset(ci, 0, sizeof *ci);
    ci->lpszName = vname; ci->dwNameSpace = NS_ALL; ci->dwValueType = REG_DWORD;
    ci->dwValueSize = sizeof *val; ci->lpValue = val;
    memset(sc, 0, sizeof *sc);
    sc->lpServiceClassId = (GUID *)&nsp_guid_throwaway;
    sc->lpszServiceClassName = cname;
    sc->dwCount = 1; sc->lpClassInfos = ci;
}

TEST(sc_dx_install_and_remove_private_class_wide) {
    WSASERVICECLASSINFOW sc; WSANSCLASSINFOW ci; DWORD val; INT r;
    REQUIRE(W_INSTALL_W); REQUIRE(W_REMOVE); NSP_NEED();
    if (!is_elevated()) { t_skip("not elevated"); return; }
    fill_class_w(&sc, &ci, &val);
    W_SETERR(0);
    r = W_INSTALL_W(&sc);
    t_note("install of a private class: %s (error %d)", r == 0 ? "accepted" : "refused", r == 0 ? 0 : W_ERR());
    if (r == 0) {
        /* Installing the same class again must not succeed silently twice with different results. */
        W_SETERR(0);
        t_note("second install: %s", W_INSTALL_W(&sc) == 0 ? "accepted" : "refused");
    }
    W_SETERR(0);
    r = W_REMOVE((GUID *)&nsp_guid_throwaway);
    t_note("remove of the private class: %s (error %d)", r == 0 ? "removed" : "refused", r == 0 ? 0 : W_ERR());
    /* Whatever happened, a further remove has nothing left to find. */
    W_SETERR(0);
    r = W_REMOVE((GUID *)&nsp_guid_throwaway);
    CHECK(r == SOCKET_ERROR);
    t_note("final remove error %d", W_ERR());
}

TEST(sc_dx_install_ansi_private_class) {
    WSASERVICECLASSINFOA sc; WSANSCLASSINFOA ci; DWORD val = 7; INT r;
    static char cname[] = "ws2t-throwaway-class", vname[] = "ws2tValue";
    REQUIRE(W_INSTALL_A); REQUIRE(W_REMOVE); NSP_NEED();
    if (!is_elevated()) { t_skip("not elevated"); return; }
    memset(&ci, 0, sizeof ci); memset(&sc, 0, sizeof sc);
    ci.lpszName = vname; ci.dwNameSpace = NS_ALL; ci.dwValueType = REG_DWORD; ci.dwValueSize = sizeof val; ci.lpValue = &val;
    sc.lpServiceClassId = (GUID *)&nsp_guid_throwaway; sc.lpszServiceClassName = cname; sc.dwCount = 1; sc.lpClassInfos = &ci;
    W_SETERR(0);
    r = W_INSTALL_A(&sc);
    t_note("ansi install of a private class: %s (error %d)", r == 0 ? "accepted" : "refused", r == 0 ? 0 : W_ERR());
    W_REMOVE((GUID *)&nsp_guid_throwaway);
}

TEST(sc_dx_remove_unknown_class_fails) {
    GUID g = nsp_guid_throwaway; g.Data1 ^= 0x5a5a5a5a;    /* never installed by anyone */
    REQUIRE(W_REMOVE); NSP_NEED();
    if (!is_elevated()) { t_skip("not elevated"); return; }
    W_SETERR(0);
    EXPECT_EQ(W_REMOVE(&g), SOCKET_ERROR);
    t_note("removing a class that was never installed: error %d", W_ERR());
}

TEST(sc_dx_get_class_info_private_class_not_found) {
    /* Look the private class up through every catalog entry that stores classes. */
    WSANAMESPACE_INFOW *info; DWORD len = 0, i; int n;
    typeof(&WSAEnumNameSpaceProvidersW) en = UIN("ws2_32.dll", WSAEnumNameSpaceProvidersW);
    REQUIRE(W_GETINFO_W); REQUIRE(en); NSP_NEED();
    en(&len, NULL);
    if (!len) { t_skip("empty catalog"); return; }
    info = (WSANAMESPACE_INFOW *)HeapAlloc(GetProcessHeap(), 0, len);
    if (!info) return;
    n = en(&len, info);
    for (i = 0; n > 0 && i < (DWORD)n; i++) {
        GUID cls = nsp_guid_throwaway; DWORD l = 0x400; BYTE out[0x400] = {0};
        if (!info[i].fActive) continue;
        W_SETERR(0);
        CHECKF(W_GETINFO_W(&info[i].NSProviderId, &cls, &l, (LPWSASERVICECLASSINFOW)out) == SOCKET_ERROR, "name space %lu returned a class that was never installed", (unsigned long)info[i].dwNameSpace);
    }
    HeapFree(GetProcessHeap(), 0, info);
}
