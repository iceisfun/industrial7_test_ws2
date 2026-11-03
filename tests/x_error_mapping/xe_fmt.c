/* x_error_mapping / FormatMessage for Winsock error numbers. The system message table has entries for the classic
 * block 10004..10071 (with gaps), the extended block 10091..10093 and 10101..10112, and the name-service / QoS block
 * 11001..11033. Presence of a text is asserted per number, the English wording only recorded as a note. */
#include "xe.h"

static int fm(DWORD id, char *out, DWORD cap, DWORD extra) {
    DWORD n; out[0] = 0;
    n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | extra, NULL, id, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), out, cap, NULL);
    return (int)n;
}
static void range_has(unsigned lo, unsigned hi, int want) {
    unsigned id; char b[512];
    for (id = lo; id <= hi; id++) {
        int len = fm(id, b, sizeof b, 0);
        t_check((len > 0) == want, "x_error_mapping", 0, "fmt", "id %u: length %d, expected %s", id, len, want ? "a text" : "no text");
    }
}
/* present */
TEST(xefmt_present_10004) { range_has(10004, 10004, 1); }
TEST(xefmt_present_10009_10014) { range_has(10009, 10009, 1); range_has(10013, 10014, 1); }
TEST(xefmt_present_10022_10024) { range_has(10022, 10022, 1); range_has(10024, 10024, 1); }
TEST(xefmt_present_10035_10071) { range_has(10035, 10071, 1); }
TEST(xefmt_present_10091_10093) { range_has(10091, 10093, 1); }
TEST(xefmt_present_10101_10112) { range_has(10101, 10112, 1); }
TEST(xefmt_present_11001_11004) { range_has(11001, 11004, 1); }
TEST(xefmt_present_qos_11005_11031) { range_has(11005, 11031, 1); }
TEST(xefmt_present_11032_11033) { range_has(11032, 11033, 1); }
/* absent: the gaps in the table */
TEST(xefmt_absent_10005_10008) { range_has(10005, 10008, 0); }
TEST(xefmt_absent_10010_10012) { range_has(10010, 10012, 0); }
TEST(xefmt_absent_10015_10021) { range_has(10015, 10021, 0); }
TEST(xefmt_absent_10023) { range_has(10023, 10023, 0); }
TEST(xefmt_absent_10025_10034) { range_has(10025, 10034, 0); }
TEST(xefmt_absent_10072_10090) { range_has(10072, 10090, 0); }
TEST(xefmt_absent_10094_10100) { range_has(10094, 10100, 0); }
TEST(xefmt_absent_above_10112) { range_has(10113, 10130, 0); }
TEST(xefmt_absent_11000_and_above_11033) { range_has(11000, 11000, 0); range_has(11034, 11040, 0); }
TEST(xefmt_absent_sets_message_not_found_error) {
    char b[64]; DWORD n;
    SetLastError(0);
    n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 10005, 0, b, sizeof b, NULL);
    CHECK(n == 0); t_note("missing message id sets error %lu", (unsigned long)GetLastError());
}
TEST(xefmt_texts_are_english_notes) {
    static const unsigned ids[] = {10004, 10013, 10035, 10038, 10048, 10053, 10054, 10057, 10060, 10061, 10093, 10101, 11001, 11004};
    unsigned i; char b[512];
    for (i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        int len = fm(ids[i], b, sizeof b, FORMAT_MESSAGE_MAX_WIDTH_MASK);
        CHECK(len > 0); t_note("fmt %u: %s", ids[i], b);
    }
}
TEST(xefmt_max_width_mask_drops_line_breaks) {
    char b[512]; int len = fm(10054, b, sizeof b, FORMAT_MESSAGE_MAX_WIDTH_MASK);
    CHECK(len > 0 && strchr(b, '\r') == NULL && strchr(b, '\n') == NULL);
}
TEST(xefmt_default_text_ends_with_line_break) {
    char b[512]; int len = fm(10054, b, sizeof b, 0);
    CHECK(len > 2 && b[len - 2] == '\r' && b[len - 1] == '\n');
}
TEST(xefmt_buffer_too_small_fails_with_122) {
    char b[8]; DWORD n; SetLastError(0);
    n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 10054, 0, b, sizeof b, NULL);
    CHECK(n == 0); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
}
TEST(xefmt_wide_and_ansi_lengths_agree) {
    char a[512]; WCHAR w[512]; int la = fm(10061, a, sizeof a, 0); DWORD lw;
    lw = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 10061, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), w, 512, NULL);
    CHECK(la > 0 && lw == (DWORD)la);
}
TEST(xefmt_allocate_buffer_variant) {
    char *p = NULL; DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, 10035, 0, (char *)&p, 0, NULL);
    CHECK(n > 0 && p != NULL); if (p) LocalFree(p);
}
TEST(xefmt_english_language_id_present) {
    char b[512]; DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 10035, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), b, sizeof b, NULL);
    if (n == 0) t_note("no English (US) text, error %lu", (unsigned long)GetLastError());
}
TEST(xefmt_ws2_module_has_no_message_table) {
    HMODULE m = t_module("ws2_32.dll"); char b[256]; DWORD n;
    n = FormatMessageA(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, m, 10035, 0, b, sizeof b, NULL);
    CHECK(n == 0);
}
TEST(xefmt_win32_numbers_overlapping_wsa_aliases) {
    /* the aliases that equal Win32 numbers (6, 8, 87, 995..997) have the Win32 texts */
    static const unsigned ids[] = {6, 8, 87, 995, 996, 997};
    unsigned i; char b[256];
    for (i = 0; i < 6; i++) CHECK(fm(ids[i], b, sizeof b, 0) > 0);
}
TEST(xefmt_wsaGetLastError_text_roundtrip) {
    char b[256]; XE_UP();
    closesocket(INVALID_SOCKET); CHECK(WSAGetLastError() == WSAENOTSOCK);
    CHECK(fm(WSAGetLastError(), b, sizeof b, 0) > 0);
}
