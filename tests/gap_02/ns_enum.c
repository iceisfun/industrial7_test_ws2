/* WSAEnumNameSpaceProvidersA / ExA / ExW against the wide catalog listing.
 * Measures: the size-query protocol (required size, WSAEFAULT, buffer left untouched when too small),
 * the fixed-entry sizes the required length must cover, ANSI/wide/extended agreement on count, order,
 * ids and identifiers, that every identifier lies inside the caller's buffer behind the fixed array,
 * that a successful call leaves the length argument and the unused tail of the buffer alone, and that
 * the required size is stable between calls.
 * Why: the enumerator first computes the required size from the catalog, compares with the supplied
 * length, and only then copies; failure always reports WSAEFAULT together with the size needed. */
#include "g2.h"

typedef enum { V_A, V_EXA, V_EXW, V_W } variant;
static const char *vname[] = { "A", "ExA", "ExW", "W" };
static const unsigned fixed_size[] = { 0x28, 0x38, 0x38, 0x28 };

/* One call through the variant's pointer; buf may be NULL. */
static int enum_call(variant v, DWORD *len, void *buf) {
    switch (v) {
    case V_A:   return WS(WSAEnumNameSpaceProvidersA)(len, (LPWSANAMESPACE_INFOA)buf);
    case V_EXA: return WS(WSAEnumNameSpaceProvidersExA)(len, (LPWSANAMESPACE_INFOEXA)buf);
    case V_EXW: return WS(WSAEnumNameSpaceProvidersExW)(len, (LPWSANAMESPACE_INFOEXW)buf);
    default:    return WS(WSAEnumNameSpaceProvidersW)(len, (LPWSANAMESPACE_INFOW)buf);
    }
}
static int have(variant v) {
    switch (v) {
    case V_A:   return WS(WSAEnumNameSpaceProvidersA) != NULL;
    case V_EXA: return WS(WSAEnumNameSpaceProvidersExA) != NULL;
    case V_EXW: return WS(WSAEnumNameSpaceProvidersExW) != NULL;
    default:    return WS(WSAEnumNameSpaceProvidersW) != NULL;
    }
}
/* Required size via the NULL-buffer query. */
static DWORD required(variant v) {
    DWORD len = 0;
    W_SETERR(0);
    if (enum_call(v, &len, NULL) != SOCKET_ERROR) return 0;
    return len;
}
#define FOR_VARIANTS(...) do { int vi_; for (vi_ = 0; vi_ < 4; vi_++) { variant v = (variant)vi_; \
    if (!have(v)) { t_note("export missing: %s", vname[v]); continue; } __VA_ARGS__ } } while (0)

TEST(gap2_ns_enum_null_buffer_reports_fault_and_size) {
    G2_NEED();
    FOR_VARIANTS(
        DWORD len = 0;
        int r;
        W_SETERR(0);
        r = enum_call(v, &len, NULL);
        CHECKF(r == SOCKET_ERROR, "%s returned %d", vname[v], r);
        CHECKF(W_ERR() == GE_FAULT, "%s error %d", vname[v], W_ERR());
        CHECKF(len > 0, "%s required size %lu", vname[v], (unsigned long)len);
    );
}

/* A non-NULL length does not matter when the buffer pointer is NULL: the size is reported regardless. */
TEST(gap2_ns_enum_null_buffer_ignores_supplied_length) {
    G2_NEED();
    FOR_VARIANTS(
        DWORD base = required(v), len = 0x10000;
        int r;
        W_SETERR(0);
        r = enum_call(v, &len, NULL);
        CHECKF(r == SOCKET_ERROR && W_ERR() == GE_FAULT, "%s r=%d err=%d", vname[v], r, W_ERR());
        CHECKF(len == base, "%s reported %lu, first query %lu", vname[v], (unsigned long)len, (unsigned long)base);
    );
}

TEST(gap2_ns_enum_required_size_is_stable) {
    G2_NEED();
    FOR_VARIANTS(
        DWORD a = required(v), b = required(v), c = required(v);
        CHECKF(a != 0 && a == b && b == c, "%s sizes %lu %lu %lu", vname[v], (unsigned long)a, (unsigned long)b, (unsigned long)c);
    );
}

TEST(gap2_ns_enum_required_size_covers_fixed_array) {
    int n = 0; WSANAMESPACE_INFOW *cat;
    G2_NEED();
    cat = g2_catalog(&n);
    if (!cat) { t_skip("no catalog"); return; }
    FOR_VARIANTS(
        DWORD need = required(v);
        CHECKF(need >= (DWORD)n * fixed_size[v], "%s: %lu < %d entries of %u bytes", vname[v], (unsigned long)need, n, fixed_size[v]);
    );
    g2_free(cat);
}

TEST(gap2_ns_enum_required_size_covers_identifier_strings) {
    int n = 0, i; WSANAMESPACE_INFOW *cat;
    G2_NEED();
    cat = g2_catalog(&n);
    if (!cat) { t_skip("no catalog"); return; }
    FOR_VARIANTS(
        DWORD strings = 0, need = required(v);
        for (i = 0; i < n; i++) {
            size_t c = cat[i].lpszIdentifier ? wcslen(cat[i].lpszIdentifier) + 1 : 0;
            strings += (DWORD)(v == V_A || v == V_EXA ? c : c * 2);
        }
        CHECKF(need >= (DWORD)n * fixed_size[v] + strings, "%s: %lu < %lu", vname[v], (unsigned long)need,
               (unsigned long)((DWORD)n * fixed_size[v] + strings));
    );
    g2_free(cat);
}

TEST(gap2_ns_enum_narrow_form_not_larger_than_wide) {
    G2_NEED();
    CHECK(required(V_A) <= required(V_W));
    CHECK(required(V_EXA) <= required(V_EXW));
}

TEST(gap2_ns_enum_extended_form_not_smaller_than_plain) {
    G2_NEED();
    CHECK(required(V_EXW) >= required(V_W));
    CHECK(required(V_EXA) >= required(V_A));
}

TEST(gap2_ns_enum_short_buffer_leaves_it_untouched) {
    G2_NEED();
    FOR_VARIANTS(
        DWORD need = required(v), len;
        BYTE *buf;
        int r; DWORD i; int bad = 0;
        if (!need) { t_skip("no size"); return; }
        buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, need);
        memset(buf, 0xCD, need);
        len = need - 1;
        W_SETERR(0);
        r = enum_call(v, &len, buf);
        CHECKF(r == SOCKET_ERROR && W_ERR() == GE_FAULT, "%s r=%d err=%d", vname[v], r, W_ERR());
        CHECKF(len == need, "%s reported %lu want %lu", vname[v], (unsigned long)len, (unsigned long)need);
        for (i = 0; i < need; i++) if (buf[i] != 0xCD) bad++;
        CHECKF(bad == 0, "%s wrote %d bytes into a too-small buffer", vname[v], bad);
        HeapFree(GetProcessHeap(), 0, buf);
    );
}

TEST(gap2_ns_enum_zero_length_with_buffer_is_fault) {
    G2_NEED();
    FOR_VARIANTS(
        DWORD need = required(v), len = 0;
        BYTE buf[8] = { 0 };
        int r;
        W_SETERR(0);
        r = enum_call(v, &len, buf);
        CHECKF(r == SOCKET_ERROR && W_ERR() == GE_FAULT, "%s r=%d err=%d", vname[v], r, W_ERR());
        CHECKF(len == need, "%s reported %lu want %lu", vname[v], (unsigned long)len, (unsigned long)need);
    );
}

TEST(gap2_ns_enum_exact_buffer_succeeds_and_keeps_length) {
    int n = 0; WSANAMESPACE_INFOW *cat;
    G2_NEED();
    cat = g2_catalog(&n);
    if (!cat) { t_skip("no catalog"); return; }
    FOR_VARIANTS(
        DWORD need = required(v), len;
        BYTE *buf;
        int r;
        buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need);
        len = need;
        W_SETERR(0);
        r = enum_call(v, &len, buf);
        CHECKF(r == n, "%s returned %d for %d catalog entries", vname[v], r, n);
        CHECKF(len == need, "%s changed the length to %lu", vname[v], (unsigned long)len);
        HeapFree(GetProcessHeap(), 0, buf);
    );
    g2_free(cat);
}

TEST(gap2_ns_enum_oversized_buffer_keeps_tail_and_length) {
    G2_NEED();
    FOR_VARIANTS(
        DWORD need = required(v), len, i; int bad = 0;
        DWORD cap = need + 256;
        BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, cap);
        int r;
        memset(buf, 0xCD, cap);
        len = cap;
        r = enum_call(v, &len, buf);
        CHECKF(r > 0, "%s returned %d", vname[v], r);
        CHECKF(len == cap, "%s changed the length to %lu", vname[v], (unsigned long)len);
        for (i = need; i < cap; i++) if (buf[i] != 0xCD) bad++;
        CHECKF(bad == 0, "%s wrote %d bytes beyond the required size", vname[v], bad);
        HeapFree(GetProcessHeap(), 0, buf);
    );
}

/* All four listings describe the same catalog in the same order. */
TEST(gap2_ns_enum_variants_agree_on_ids_and_order) {
    int n = 0, i; WSANAMESPACE_INFOW *w;
    G2_NEED();
    w = g2_catalog(&n);
    if (!w) { t_skip("no catalog"); return; }
    {
        DWORD la = required(V_A), lxa = required(V_EXA), lxw = required(V_EXW);
        WSANAMESPACE_INFOA *a = (WSANAMESPACE_INFOA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, la);
        WSANAMESPACE_INFOEXA *xa = (WSANAMESPACE_INFOEXA *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lxa);
        WSANAMESPACE_INFOEXW *xw = (WSANAMESPACE_INFOEXW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lxw);
        if (WS(WSAEnumNameSpaceProvidersA) && WS(WSAEnumNameSpaceProvidersExA) && WS(WSAEnumNameSpaceProvidersExW)) {
            CHECK(WS(WSAEnumNameSpaceProvidersA)(&la, a) == n);
            CHECK(WS(WSAEnumNameSpaceProvidersExA)(&lxa, xa) == n);
            CHECK(WS(WSAEnumNameSpaceProvidersExW)(&lxw, xw) == n);
            for (i = 0; i < n; i++) {
                CHECKF(!memcmp(&a[i].NSProviderId, &w[i].NSProviderId, sizeof(GUID)), "A id %d", i);
                CHECKF(!memcmp(&xa[i].NSProviderId, &w[i].NSProviderId, sizeof(GUID)), "ExA id %d", i);
                CHECKF(!memcmp(&xw[i].NSProviderId, &w[i].NSProviderId, sizeof(GUID)), "ExW id %d", i);
                CHECKF(a[i].dwNameSpace == w[i].dwNameSpace && xa[i].dwNameSpace == w[i].dwNameSpace && xw[i].dwNameSpace == w[i].dwNameSpace, "namespace %d", i);
                CHECKF(a[i].fActive == w[i].fActive && xa[i].fActive == w[i].fActive && xw[i].fActive == w[i].fActive, "active %d", i);
                CHECKF(a[i].dwVersion == w[i].dwVersion && xa[i].dwVersion == w[i].dwVersion && xw[i].dwVersion == w[i].dwVersion, "version %d", i);
                CHECKF(a[i].lpszIdentifier && g2_wide_to_ansi_equal(w[i].lpszIdentifier, a[i].lpszIdentifier), "A identifier %d", i);
                CHECKF(xa[i].lpszIdentifier && g2_wide_to_ansi_equal(w[i].lpszIdentifier, xa[i].lpszIdentifier), "ExA identifier %d", i);
                CHECKF(xw[i].lpszIdentifier && !lstrcmpW(xw[i].lpszIdentifier, w[i].lpszIdentifier), "ExW identifier %d", i);
            }
        }
        g2_free(a); g2_free(xa); g2_free(xw);
    }
    g2_free(w);
}

/* Identifier pointers address the caller's buffer, behind the fixed array, and end inside it. */
TEST(gap2_ns_enum_identifiers_lie_inside_buffer) {
    G2_NEED();
    FOR_VARIANTS(
        DWORD need = required(v), len = need; int n, i;
        BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need);
        n = enum_call(v, &len, buf);
        CHECKF(n > 0, "%s returned %d", vname[v], n);
        for (i = 0; i < n; i++) {
            BYTE *id = *(BYTE **)(buf + (size_t)i * fixed_size[v] + 0x20 - (v == V_A || v == V_W ? 0 : 0));
            /* lpszIdentifier is the last pointer of the fixed part of the plain entry (offset 0x20). */
            CHECKF(id >= buf + (size_t)n * fixed_size[v] && id < buf + need, "%s entry %d identifier outside the buffer", vname[v], i);
            if (id >= buf + (size_t)n * fixed_size[v] && id < buf + need) {
                size_t room = (size_t)(buf + need - id);
                int terminated = 0;
                if (v == V_A || v == V_EXA) { size_t k; for (k = 0; k < room; k++) if (id[k] == 0) { terminated = 1; break; } }
                else { size_t k; for (k = 0; k + 1 < room; k += 2) if (id[k] == 0 && id[k + 1] == 0) { terminated = 1; break; } }
                CHECKF(terminated, "%s entry %d identifier not terminated inside the buffer", vname[v], i);
            }
        }
        HeapFree(GetProcessHeap(), 0, buf);
    );
}

TEST(gap2_ns_enum_provider_ids_distinct_and_nonzero) {
    int n = 0, i, j; WSANAMESPACE_INFOW *w;
    GUID zero; memset(&zero, 0, sizeof zero);
    G2_NEED();
    w = g2_catalog(&n);
    if (!w) { t_skip("no catalog"); return; }
    for (i = 0; i < n; i++) {
        CHECKF(memcmp(&w[i].NSProviderId, &zero, sizeof zero) != 0, "entry %d has a zero provider id", i);
        for (j = i + 1; j < n; j++) CHECKF(memcmp(&w[i].NSProviderId, &w[j].NSProviderId, sizeof(GUID)) != 0, "entries %d and %d share an id", i, j);
    }
    g2_free(w);
}

TEST(gap2_ns_enum_every_entry_has_nonempty_identifier_and_namespace) {
    int n = 0, i; WSANAMESPACE_INFOW *w;
    G2_NEED();
    w = g2_catalog(&n);
    if (!w) { t_skip("no catalog"); return; }
    for (i = 0; i < n; i++) {
        CHECKF(w[i].lpszIdentifier && w[i].lpszIdentifier[0], "entry %d has no identifier", i);
        CHECKF(w[i].dwNameSpace != 0, "entry %d has name space 0", i);
        CHECKF(w[i].fActive == 0 || w[i].fActive == 1, "entry %d active flag %d", i, (int)w[i].fActive);
    }
    g2_free(w);
}

TEST(gap2_ns_enum_dns_entry_present_and_active) {
    GUID id;
    G2_NEED();
    CHECK(g2_provider_for(NS_DNS, &id));
}

/* The ANSI listing and the wide listing succeed independently: a failed small query does not poison the next call. */
TEST(gap2_ns_enum_failure_then_success_sequence) {
    G2_NEED();
    FOR_VARIANTS(
        DWORD need = required(v), len = 4;
        BYTE tiny[4] = { 0 }, *buf;
        int r;
        r = enum_call(v, &len, tiny);
        CHECKF(r == SOCKET_ERROR, "%s tiny buffer returned %d", vname[v], r);
        buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need);
        len = need;
        r = enum_call(v, &len, buf);
        CHECKF(r > 0, "%s followed by a good buffer returned %d", vname[v], r);
        HeapFree(GetProcessHeap(), 0, buf);
    );
}

/* With no provider-specific blob in any entry the extended listing is exactly one blob descriptor (16 bytes)
 * per entry larger than the plain one. */
TEST(gap2_ns_enum_extended_listing_adds_one_blob_descriptor_per_entry) {
    int n = 0, i, any_blob = 0; DWORD lx, lw; BYTE *buf; LPWSANAMESPACE_INFOEXW x;
    G2_NEED();
    lx = required(V_EXW); lw = required(V_W);
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lx);
    x = (LPWSANAMESPACE_INFOEXW)buf;
    n = WS(WSAEnumNameSpaceProvidersExW)(&lx, x);
    if (n <= 0) { HeapFree(GetProcessHeap(), 0, buf); CHECK(n > 0); return; }
    for (i = 0; i < n; i++) if (x[i].ProviderSpecific.cbSize != 0 || x[i].ProviderSpecific.pBlobData != NULL) any_blob = 1;
    if (any_blob) t_note("some entries carry a provider-specific blob");
    else EXPECT_EQ(required(V_EXW) - lw, (DWORD)n * 16);
    HeapFree(GetProcessHeap(), 0, buf);
}

TEST(gap2_ns_enum_extended_entries_have_empty_blob_pointer_when_size_is_zero) {
    int n = 0, i; DWORD lx; BYTE *buf; LPWSANAMESPACE_INFOEXW x;
    G2_NEED();
    lx = required(V_EXW);
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lx);
    x = (LPWSANAMESPACE_INFOEXW)buf;
    memset(buf, 0xCD, lx);
    n = WS(WSAEnumNameSpaceProvidersExW)(&lx, x);
    CHECK(n > 0);
    for (i = 0; i < n; i++) {
        if (x[i].ProviderSpecific.cbSize == 0) CHECKF(x[i].ProviderSpecific.pBlobData == NULL, "entry %d: size 0 but a blob pointer", i);
        else CHECKF((BYTE *)x[i].ProviderSpecific.pBlobData >= buf && (BYTE *)x[i].ProviderSpecific.pBlobData < buf + lx, "entry %d: blob outside the buffer", i);
    }
    HeapFree(GetProcessHeap(), 0, buf);
}
