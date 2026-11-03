/* Cross-interface relations: for every state the recorded readiness of one interface is derived from another.
 * Each test walks all states with live observations (nothing is read from the recorded table), so a stack
 * that gets one interface right and another wrong fails here with the state name. */
#include "xs.h"

typedef struct { char v[XV_COUNT][256]; int ok; } xs_obs;

static int has(const char *s, const char *tok) { return strstr(s, tok) != NULL; }

/* Observe every non-destructive view of one fresh instance of each state, then the enum view on a second. */
static int observe_state(const xs_state *d, xs_obs *o)
{
    xs_st st; int v;
    memset(o, 0, sizeof(*o));
    memset(&st, 0, sizeof(st)); st.s = st.peer = st.lst = st.aux = INVALID_SOCKET;
    if (!d->build(&st)) { xs_teardown(&st); return 0; }
    for (v = XV_SEL; v <= XV_AFD; v++) xs_observe(v, &st, o->v[v], sizeof(o->v[v]));
    xs_teardown(&st);
    memset(&st, 0, sizeof(st)); st.s = st.peer = st.lst = st.aux = INVALID_SOCKET;
    if (!d->build(&st)) { xs_teardown(&st); return 0; }
    xs_observe(XV_ENUM, &st, o->v[XV_ENUM], sizeof(o->v[XV_ENUM]));
    xs_teardown(&st);
    o->ok = 1;
    return 1;
}

typedef void (*rel_fn)(const char *name, const xs_obs *o);

static void walk(rel_fn f)
{
    int i;
    if (!xs_init()) { t_skip("winsock, poll or ntdll entry points missing"); return; }
    for (i = 0; i < xs_nstates; i++) {
        xs_obs o;
        if (!observe_state(&xs_states[i], &o)) continue;
        f(xs_states[i].name, &o);
    }
}

static int is_err(const xs_obs *o) { return has(o->v[XV_SEL], "err="); }

#define SELR(o) (has((o)->v[XV_SEL], " R"))
#define SELW(o) (has((o)->v[XV_SEL], "RW") || has((o)->v[XV_SEL], "-W"))

static void rel_sel_afd(const char *n, const xs_obs *o)
{
    const char *sel = o->v[XV_SEL], *afd = o->v[XV_AFD];
    int r, w, x, ar, aw, ax;
    if (is_err(o)) return;

    { const char *p = strchr(sel, ' '); r = p[1] == 'R'; w = p[2] == 'W'; x = p[3] == 'X'; }
    ar = has(afd, "RECEIVE") || has(afd, "ACCEPT") || has(afd, "DISCONNECT") || has(afd, "ABORT");
    aw = has(afd, "SEND");
    ax = has(afd, "OOB") || has(afd, "CONNECT_FAIL");
    CHECKF(r == ar, "%s: select readable %d vs AFD receive/accept/disconnect/abort %d [%s] [%s]", n, r, ar, sel, afd);
    CHECKF(w == aw, "%s: select writable %d vs AFD send %d [%s] [%s]", n, w, aw, sel, afd);
    CHECKF(x == ax, "%s: select except %d vs AFD oob/connect-fail %d [%s] [%s]", n, x, ax, sel, afd);
}
TEST(rel_select_is_the_afd_event_mask_grouped) { walk(rel_sel_afd); }

static void rel_poll_afd(const char *n, const xs_obs *o)
{
    const char *all = o->v[XV_POLL_ALL], *afd = o->v[XV_AFD];
    if (is_err(o)) return;
    CHECKF(has(all, "RDNORM") == (has(afd, "RECEIVE") || has(afd, "ACCEPT")), "%s: RDNORM vs AFD [%s] [%s]", n, all, afd);
    CHECKF(has(all, "RDBAND") == has(afd, "OOB"), "%s: RDBAND vs AFD oob [%s] [%s]", n, all, afd);
    CHECKF(has(all, "HUP") == (has(afd, "DISCONNECT") || has(afd, "ABORT") || has(afd, "CONNECT_FAIL")), "%s: HUP vs AFD [%s] [%s]", n, all, afd);
    CHECKF(has(all, "ERR") == (has(afd, "ABORT") || has(afd, "CONNECT_FAIL")), "%s: ERR vs AFD [%s] [%s]", n, all, afd);
    CHECKF(has(all, "WRNORM") == (has(afd, "SEND") || has(afd, "CONNECT_FAIL")), "%s: WRNORM vs AFD [%s] [%s]", n, all, afd);
}
TEST(rel_poll_is_the_afd_event_mask_mapped) { walk(rel_poll_afd); }

static void rel_poll_never(const char *n, const xs_obs *o)
{
    int v;
    for (v = XV_POLL_RW; v <= XV_POLL_ALL; v++) {
        CHECKF(!has(o->v[v], "PRI"), "%s/%s: POLLPRI is never reported [%s]", n, xs_view_names[v], o->v[v]);
        CHECKF(!has(o->v[v], "WRBAND"), "%s/%s: POLLWRBAND is never reported [%s]", n, xs_view_names[v], o->v[v]);
        if (!has(o->v[v], "err=")) CHECKF(!has(o->v[v], "NVAL"), "%s/%s: POLLNVAL only for a bad handle [%s]", n, xs_view_names[v], o->v[v]);
    }
}
TEST(rel_poll_never_reports_pri_or_wrband) { walk(rel_poll_never); }

static void rel_poll_masks(const char *n, const xs_obs *o)
{
    const char *none = o->v[XV_POLL_NONE], *all = o->v[XV_POLL_ALL], *rd = o->v[XV_POLL_RD], *wr = o->v[XV_POLL_WR], *bd = o->v[XV_POLL_BAND], *rw = o->v[XV_POLL_RW];
    int failed_connect = has(o->v[XV_AFD], "CONNECT_FAIL");
    if (is_err(o)) return;
    /* the requested bits select which of the normal bits come back */
    CHECKF(has(none, "RDNORM") == 0 && has(none, "WRNORM") == 0 && has(none, "RDBAND") == 0, "%s: empty request reports no data bits [%s]", n, none);
    CHECKF(has(rd, "WRNORM") == 0 && has(rd, "RDBAND") == 0, "%s: read-only request [%s]", n, rd);
    CHECKF(has(wr, "RDNORM") == 0 && has(wr, "RDBAND") == 0, "%s: write-only request [%s]", n, wr);
    CHECKF(has(bd, "RDNORM") == 0 && has(bd, "WRNORM") == 0, "%s: band-only request [%s]", n, bd);
    CHECKF(has(rd, "RDNORM") == has(all, "RDNORM") && has(wr, "WRNORM") == has(all, "WRNORM") && has(bd, "RDBAND") == has(all, "RDBAND"), "%s: union of single requests [%s]", n, all);
    CHECKF(has(rw, "RDNORM") == has(all, "RDNORM") && has(rw, "WRNORM") == has(all, "WRNORM") && has(rw, "RDBAND") == 0, "%s: RDNORM|WRNORM request [%s]", n, rw);
    if (!failed_connect) {
        /* HUP and ERR come back for any request, even an empty one */
        CHECKF(has(none, "HUP") == has(all, "HUP") && has(none, "ERR") == has(all, "ERR"), "%s: HUP/ERR independent of the request [%s] [%s]", n, none, all);
        CHECKF(has(rd, "HUP") == has(all, "HUP") && has(wr, "HUP") == has(all, "HUP") && has(bd, "HUP") == has(all, "HUP"), "%s: HUP for every request [%s]", n, all);
    } else {
        /* a failed connect is reported only to a request that includes write readiness */
        CHECKF(!strcmp(none, "n=0 0") && !strcmp(rd, "n=0 0") && !strcmp(bd, "n=0 0"), "%s: failed connect needs a write request [%s] [%s] [%s]", n, none, rd, bd);
        CHECKF(has(wr, "ERR") && has(wr, "HUP") && has(rw, "ERR") && has(rw, "HUP"), "%s: failed connect with write request [%s] [%s]", n, wr, rw);
    }
}
TEST(rel_poll_request_mask_selects_data_bits) { walk(rel_poll_masks); }

static void rel_sel_poll(const char *n, const xs_obs *o)
{
    const char *sel = o->v[XV_SEL], *all = o->v[XV_POLL_ALL];
    int r, w, x;
    const char *p;
    if (is_err(o)) {
        CHECKF(has(all, "err=") && !strcmp(strstr(sel, "err="), strstr(all, "err=")), "%s: same WSA error from both [%s] [%s]", n, sel, all);
        return;
    }
    p = strchr(sel, ' '); r = p[1] == 'R'; w = p[2] == 'W'; x = p[3] == 'X';
    if (has(o->v[XV_AFD], "CONNECT_FAIL")) {
        /* failed connect: select reports except only; WSAPoll reports writable plus error and hangup */
        CHECKF(!r && !w && x, "%s: failed connect is except-only to select [%s]", n, sel);
        CHECKF(has(all, "WRNORM") && has(all, "ERR") && has(all, "HUP") && !has(all, "RDNORM"), "%s: failed connect to poll [%s]", n, all);
        return;
    }
    CHECKF(r == (has(all, "RDNORM") || has(all, "HUP") || has(all, "ERR")), "%s: select readable vs poll [%s] [%s]", n, sel, all);
    CHECKF(w == has(all, "WRNORM"), "%s: select writable vs poll [%s] [%s]", n, sel, all);
    if (has(all, "RDBAND")) CHECKF(x, "%s: RDBAND implies select except [%s] [%s]", n, sel, all);
}
TEST(rel_select_versus_poll_known_differences) { walk(rel_sel_poll); }

static void rel_enum_afd(const char *n, const xs_obs *o)
{
    const char *en = o->v[XV_ENUM], *afd = o->v[XV_AFD];
    if (is_err(o)) return;
    CHECKF(has(en, "ACCEPT") == has(afd, "ACCEPT"), "%s: FD_ACCEPT vs AFD accept [%s] [%s]", n, en, afd);
    CHECKF(has(en, "OOB") == has(afd, "OOB"), "%s: FD_OOB vs AFD oob [%s] [%s]", n, en, afd);
    CHECKF(has(en, "CLOSE") == (has(afd, "DISCONNECT") || has(afd, "ABORT")), "%s: FD_CLOSE vs AFD disconnect/abort [%s] [%s]", n, en, afd);
    if (has(afd, "RECEIVE")) CHECKF(has(en, "READ"), "%s: AFD receive implies FD_READ [%s] [%s]", n, en, afd);
    if (has(afd, "CONNECT_FAIL")) CHECKF(has(en, "CONNECT") && !has(en, "WRITE"), "%s: failed connect shows as FD_CONNECT with an error [%s]", n, en);
    if (has(afd, "ABORT")) CHECKF(has(en, "CLOSE=10053"), "%s: abort shows as FD_CLOSE with WSAECONNABORTED [%s]", n, en);
    if (has(afd, "CONNECT_FAIL")) CHECKF(has(en, "CONNECT=10061"), "%s: refused connect carries WSAECONNREFUSED [%s]", n, en);
}
TEST(rel_enum_events_follow_the_afd_mask) { walk(rel_enum_afd); }

static void rel_enum_nonblock_signal(const char *n, const xs_obs *o)
{
    const char *en = o->v[XV_ENUM];
    if (is_err(o)) return;
    /* an event is signalled at WSAEventSelect time exactly when the enumeration then reports something */
    CHECKF((en[4] == '1') == (strchr(en, ' ') && strchr(en, ' ')[1] != '0'), "%s: event signalled iff events enumerated [%s]", n, en);
}
TEST(rel_event_signalled_iff_events_pending) { walk(rel_enum_nonblock_signal); }
