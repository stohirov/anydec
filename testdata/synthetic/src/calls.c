// Calling conventions: many arguments, stack arguments, external calls,
// recursion, function pointers.

extern int printf(const char *, ...);
extern void *memcpy(void *, const void *, unsigned);

int many(int a, int b, int c, int d, int e, int f) { return a + b + c + d + e + f; }

int call_many(void) { return many(1, 2, 3, 4, 5, 6); }

unsigned fib(unsigned n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

int apply(int (*fn)(int, int), int x) { return fn(x, x + 1); }

void report(const char *name, int v) { printf("%s:%d\n", name, v); }

void copy16(void *dst, const void *src) { memcpy(dst, src, 16); }
