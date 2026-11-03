#ifndef XOM_TYPES_H
#define XOM_TYPES_H
/* One expectation: observation key and the token line a Windows 10 run produced ('?' matches any value, 'a|b' either). */
struct xom_exp { const char *key; const char *val; };
extern const struct xom_exp xom_table[];
extern const unsigned xom_table_n;
#endif
