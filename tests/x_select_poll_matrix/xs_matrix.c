/* Matrix driver: build a state, read every view, compare with the recorded Windows 10 table. */
#include "xs.h"

typedef struct { const char *state, *view, *val; } xs_row;
#include "xs_table.h"

const char *xs_expect(const char *state, const char *view)
{
    size_t i;
    for (i = 0; i < sizeof(xs_rows) / sizeof(xs_rows[0]); i++)
        if (xs_rows[i].state && !strcmp(xs_rows[i].state, state) && !strcmp(xs_rows[i].view, view)) return xs_rows[i].val;
    return NULL;
}

/* A recorded value may list alternatives separated by "||" for observations that depend on how long the
 * socket has been settled (see ar_async_connect_settle). */
int xs_match(const char *got, const char *want)
{
    const char *p = want;
    for (;;) {
        const char *e = strstr(p, "||");
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (strlen(got) == n && !strncmp(got, p, n)) return 1;
        if (!e) return 0;
        p = e + 2;
    }
}

void xs_run_state(const char *name)
{
    int i, v;
    const xs_state *def = NULL;
    for (i = 0; i < xs_nstates; i++) if (!strcmp(xs_states[i].name, name)) def = &xs_states[i];
    if (!xs_init()) { t_skip("winsock, poll or ntdll entry points missing"); return; }
    if (!def) { CHECKF(0, "unknown state %s", name); return; }
    for (v = 0; v < XV_COUNT; v++) {
        xs_st st; char got[256]; const char *want;
        memset(&st, 0, sizeof(st));
        st.s = st.peer = st.lst = st.aux = INVALID_SOCKET;
        if (!def->build(&st)) { xs_teardown(&st); t_skip("could not reach state %s on this host", name); return; }
        xs_observe(v, &st, got, sizeof(got));
        xs_teardown(&st);
        want = xs_expect(name, xs_view_names[v]);
        if (!want) t_note("ROW %s %s | %s", name, xs_view_names[v], got);
        else CHECKF(xs_match(got, want), "%s/%s got [%s] want [%s]", name, xs_view_names[v], got, want);
    }
}

void xs_row_check(const char *grp, const char *step, const char *got)
{
    const char *want = xs_expect(grp, step);
    if (!want) t_note("ROW %s %s | %s", grp, step, got);
    else CHECKF(xs_match(got, want), "%s/%s got [%s] want [%s]", grp, step, got, want);
}
