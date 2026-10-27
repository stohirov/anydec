// Native reference runs for the synthetic corpus. `make vectors` compiles
// this file with ../src/*.c for the host and records, for every function,
// seeded random inputs and the results the host computes. The IR
// interpreter test (engine/exec_test.go) runs the same inputs through the
// lifted corpus objects and must get the same results.
//
// One JSON object per line:
//   fn    function name
//   sig   return type, ':', parameter types (one letter each, see below)
//   args  each argument: its bits in hex, "b<i>" for buffer i, or the name
//         of a callback
//   bufs  memory arguments: type "w" (int32 words), "f" (float bits),
//         "b" (bytes), "pt" (struct point words) or "list" (value,tag
//         pairs of a linked list); contents before ("in") and after ("out")
//   ret   result bits in hex, absent for void
//   calls external functions called, in order
//   out   bytes written by printf, in hex
//
// Types: i int, u unsigned, I long long, U unsigned long long, s short,
// S unsigned short, c signed char, C unsigned char, f float, d double,
// p pointer, F function pointer, v void.

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Interceptions: calls.c and switch.c call these externals, renamed with
// -D so the host's own printf and memcpy are not replaced.
static char trace[256];
static char printed[256];
static int nprinted;

static void record(const char *name) {
	if (trace[0])
		strcat(trace, ",");
	strcat(trace, "\"");
	strcat(trace, name);
	strcat(trace, "\"");
}

int h_printf(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(printed + nprinted, sizeof printed - nprinted, fmt, ap);
	va_end(ap);
	nprinted += n;
	record("printf");
	return n;
}

// Not recorded: compilers inline small copies, so the call is not part of
// a function's behavior.
void *h_memcpy(void *dst, const void *src, unsigned n) { return memcpy(dst, src, n); }

void on_a(void) { record("on_a"); }
void on_b(void) { record("on_b"); }
void on_c(void) { record("on_c"); }

// The callback passed to apply; engine/exec_test.go implements it too.
int cb_mix(int a, int b) { return a * 3 - b; }

// The functions under test.
int add(int, int);
int mul_add(int, int, int);
unsigned shifts(unsigned, int);
int sdiv(int, int);
int clamp(int, int, int);
long long wide_add(long long, long long);
unsigned popcount(unsigned);
unsigned bswap(unsigned);
unsigned clz(unsigned);
unsigned long long mul64(unsigned long long, unsigned long long);
long long smull(int, int);
unsigned rotl(unsigned, unsigned);
unsigned extract(unsigned);
unsigned insert(unsigned, unsigned);
short sext(signed char);
unsigned short zext(unsigned char);
int fetch_add(int *, int);
int cas(int *, int, int);
int sum(const int *, int);
unsigned strlen_(const char *);
int find(const int *, int, int);
void matmul(int, const int *, const int *, int *);
unsigned collatz(unsigned);
int many(int, int, int, int, int, int);
int call_many(void);
unsigned fib(unsigned);
int apply(int (*)(int, int), int);
void report(const char *, int);
void copy16(void *, const void *);
float lerp(float, float, float);
double poly(double);
int to_int(float);
float from_int(int);
double widen(float);
float fmax_(float, float);
float dot(const float *, const float *, int);
struct point { int x, y; };
struct node { struct node *next; int value; unsigned char tag; };
int manhattan(const struct point *);
int list_sum(const struct node *);
void bump(struct point *, int);
int dense(int);
int sparse(int);
void dispatch(int);
int alu(int, int, int);
int offset_switch(int, int);
unsigned byte_switch(unsigned char, unsigned);
int interp(const unsigned char *, int);

// xorshift64*, fixed seed: the vectors are reproducible.
static uint64_t state = 0x2545f4914f6cdd1dULL;

static uint64_t next(void) {
	state ^= state >> 12;
	state ^= state << 25;
	state ^= state >> 27;
	return state * 0x2545f4914f6cdd1dULL;
}

static int range(int lo, int hi) { return lo + (int)(next() % (uint64_t)(hi - lo + 1)); }

// anyint favors boundary values a quarter of the time.
static uint32_t anyint(void) {
	static const uint32_t edges[] = {0, 1, 2, 0xffffffff, 0x7fffffff, 0x80000000, 0x80000001, 0xfffffffe, 31, 32, 255, 256};
	if (next() % 4 == 0)
		return edges[next() % (sizeof edges / sizeof edges[0])];
	return (uint32_t)next();
}

static float anyfloat(void) { return (float)range(-1000000, 1000000) / (float)range(1, 1000); }

static uint32_t fbits(float f) {
	uint32_t u;
	memcpy(&u, &f, 4);
	return u;
}

static uint64_t dbits(double d) {
	uint64_t u;
	memcpy(&u, &d, 8);
	return u;
}

// Output helpers. A case is built up with begin, arg*, buf*, then end.
static char line[8192];

static void begin(const char *fn, const char *sig) {
	trace[0] = 0;
	nprinted = 0;
	snprintf(line, sizeof line, "{\"fn\":\"%s\",\"sig\":\"%s\",\"args\":[", fn, sig);
}

static void sep(void) {
	size_t n = strlen(line);
	if (line[n - 1] != '[')
		strcat(line, ",");
}

static void arg(uint64_t bits) {
	sep();
	snprintf(line + strlen(line), sizeof line - strlen(line), "\"%#llx\"", (unsigned long long)bits);
}

static void argname(const char *name) {
	sep();
	snprintf(line + strlen(line), sizeof line - strlen(line), "\"%s\"", name);
}

struct buf {
	const char *type;
	int n;
	uint32_t in[64], *out; // out points at the live memory after the call
};

static struct buf bufs[4];
static int nbufs;

static void bufarg(int i) {
	char name[8];
	snprintf(name, sizeof name, "b%d", i);
	argname(name);
}

static void words(const char *label, const uint32_t *w, int n) {
	snprintf(line + strlen(line), sizeof line - strlen(line), ",\"%s\":[", label);
	for (int i = 0; i < n; i++)
		snprintf(line + strlen(line), sizeof line - strlen(line), "%s%u", i ? "," : "", w[i]);
	strcat(line, "]");
}

static void end(int has_ret, uint64_t ret) {
	strcat(line, "]");
	if (nbufs) {
		strcat(line, ",\"bufs\":[");
		for (int i = 0; i < nbufs; i++) {
			struct buf *b = &bufs[i];
			snprintf(line + strlen(line), sizeof line - strlen(line), "%s{\"type\":\"%s\"", i ? "," : "", b->type);
			words("in", b->in, b->n);
			if (b->out)
				words("out", b->out, b->n);
			strcat(line, "}");
		}
		strcat(line, "]");
	}
	if (has_ret)
		snprintf(line + strlen(line), sizeof line - strlen(line), ",\"ret\":\"%#llx\"", (unsigned long long)ret);
	if (trace[0])
		snprintf(line + strlen(line), sizeof line - strlen(line), ",\"calls\":[%s]", trace);
	if (nprinted) {
		strcat(line, ",\"out\":\"");
		for (int i = 0; i < nprinted; i++)
			snprintf(line + strlen(line), sizeof line - strlen(line), "%02x", (unsigned char)printed[i]);
		strcat(line, "\"");
	}
	strcat(line, "}");
	puts(line);
	nbufs = 0;
}

// newbuf registers buffer contents and returns its index. Callers set
// out to the live memory when the function may write it.
static int newbuf(const char *type, const uint32_t *w, int n) {
	struct buf *b = &bufs[nbufs];
	b->type = type;
	b->n = n;
	b->out = 0;
	memcpy(b->in, w, n * 4);
	return nbufs++;
}

#define CASES 24

static void ints(void) {
	for (int k = 0; k < CASES; k++) {
		uint32_t a = anyint(), b = anyint(), c = anyint();
		begin("add", "i:ii"); arg(a); arg(b); end(1, (uint32_t)add(a, b));
		begin("mul_add", "i:iii"); arg(a); arg(b); arg(c); end(1, (uint32_t)mul_add(a, b, c));
		int n = range(1, 31);
		begin("shifts", "u:ui"); arg(a); arg((uint32_t)n); end(1, shifts(a, n));
		int32_t d = (int32_t)b;
		if (d == -1 && (int32_t)a == INT32_MIN)
			d = 7;
		if (k % 6 == 0)
			d = 0;
		begin("sdiv", "i:ii"); arg(a); arg((uint32_t)d); end(1, (uint32_t)sdiv(a, d));
		int lo = range(-100, 100), hi = lo + range(0, 200), x = range(-400, 400);
		begin("clamp", "i:iii"); arg((uint32_t)x); arg((uint32_t)lo); arg((uint32_t)hi); end(1, (uint32_t)clamp(x, lo, hi));
		uint64_t p = next(), q = next();
		begin("wide_add", "I:II"); arg(p); arg(q); end(1, (uint64_t)wide_add(p, q));
		begin("popcount", "u:u"); arg(a); end(1, popcount(a));
		begin("bswap", "u:u"); arg(a); end(1, bswap(a));
		uint32_t z = a >> range(0, 31);
		begin("clz", "u:u"); arg(z); end(1, clz(z));
		begin("mul64", "U:UU"); arg(p); arg(q); end(1, mul64(p, q));
		begin("smull", "I:ii"); arg(a); arg(b); end(1, (uint64_t)smull(a, b));
		begin("rotl", "u:uu"); arg(a); arg(b); end(1, rotl(a, b));
		begin("extract", "u:u"); arg(a); end(1, extract(a));
		begin("insert", "u:uu"); arg(a); arg(b); end(1, insert(a, b));
		begin("sext", "s:c"); arg(a & 0xff); end(1, (uint16_t)sext((signed char)a));
		begin("zext", "S:C"); arg(a & 0xff); end(1, zext((unsigned char)a));
		unsigned cx = (unsigned)range(1, 5000);
		begin("collatz", "u:u"); arg(cx); end(1, collatz(cx));
		int sw = range(-3, 9);
		begin("dense", "i:i"); arg((uint32_t)sw); end(1, (uint32_t)dense(sw));
		static const int sparse_keys[] = {3, 100, 1000, 99999, 4, 0, -1, 101};
		int sk = k % 3 ? sparse_keys[next() % 8] : (int)a;
		begin("sparse", "i:i"); arg((uint32_t)sk); end(1, (uint32_t)sparse(sk));
		begin("dispatch", "v:i"); arg((uint32_t)sw); dispatch(sw); end(0, 0);
	}
}

static void memory(void) {
	for (int k = 0; k < CASES; k++) {
		uint32_t w[64], w2[64];
		int n = range(0, 16);
		for (int i = 0; i < n; i++)
			w[i] = k % 2 ? anyint() : (uint32_t)range(-50, 50);
		begin("sum", "i:pi"); bufarg(newbuf("w", w, n)); arg((uint32_t)n);
		end(1, (uint32_t)sum((const int *)w, n));

		int key = n && k % 3 ? (int)w[next() % n] : range(-50, 50);
		begin("find", "i:pii"); bufarg(newbuf("w", w, n)); arg((uint32_t)n); arg((uint32_t)key);
		end(1, (uint32_t)find((const int *)w, n, key));

		char s[64];
		int len = range(0, 40);
		for (int i = 0; i < len; i++)
			s[i] = (char)range(1, 255);
		s[len] = 0;
		uint32_t sw[16] = {0};
		memcpy(sw, s, len + 1);
		begin("strlen_", "u:p"); bufarg(newbuf("b", sw, (len + 4) / 4)); end(1, strlen_(s));

		int m = range(0, 4);
		for (int i = 0; i < m * m; i++) {
			w[i] = (uint32_t)range(-20, 20);
			w2[i] = (uint32_t)range(-20, 20);
		}
		int c[16];
		memset(c, 0xa5, sizeof c);
		begin("matmul", "v:ippp"); arg((uint32_t)m);
		bufarg(newbuf("w", w, m * m)); bufarg(newbuf("w", w2, m * m));
		int ci = newbuf("w", (uint32_t *)c, 16);
		bufarg(ci);
		matmul(m, (const int *)w, (const int *)w2, c);
		bufs[ci].out = (uint32_t *)c;
		end(0, 0);

		int32_t cell = (int32_t)anyint(), v = (int32_t)anyint();
		begin("fetch_add", "i:pi"); int fi = newbuf("w", (uint32_t *)&cell, 1); bufarg(fi); arg((uint32_t)v);
		int r = fetch_add(&cell, v);
		bufs[fi].out = (uint32_t *)&cell;
		end(1, (uint32_t)r);

		int32_t old = k % 2 ? cell : (int32_t)anyint(), nw = (int32_t)anyint();
		begin("cas", "i:pii"); int ki = newbuf("w", (uint32_t *)&cell, 1); bufarg(ki); arg((uint32_t)old); arg((uint32_t)nw);
		r = cas(&cell, old, nw);
		bufs[ki].out = (uint32_t *)&cell;
		end(1, (uint32_t)r);
	}
}

static void calls(void) {
	for (int k = 0; k < CASES; k++) {
		uint32_t a[6];
		for (int i = 0; i < 6; i++)
			a[i] = anyint();
		begin("many", "i:iiiiii");
		for (int i = 0; i < 6; i++)
			arg(a[i]);
		end(1, (uint32_t)many(a[0], a[1], a[2], a[3], a[4], a[5]));
		unsigned n = (unsigned)range(0, 16);
		begin("fib", "u:u"); arg(n); end(1, fib(n));
		int x = (int)anyint();
		begin("apply", "i:Fi"); argname("cb_mix"); arg((uint32_t)x); end(1, (uint32_t)apply(cb_mix, x));
		static const char *names[] = {"x", "yy", "temp"};
		const char *name = names[k % 3];
		uint32_t nb[4] = {0};
		memcpy(nb, name, strlen(name) + 1);
		begin("report", "v:pi"); bufarg(newbuf("b", nb, 2)); arg((uint32_t)x);
		report(name, x);
		end(0, 0);
		uint32_t src[4], dst[4];
		for (int i = 0; i < 4; i++) {
			src[i] = anyint();
			dst[i] = 0;
		}
		begin("copy16", "v:pp"); int di = newbuf("w", dst, 4); bufarg(di); bufarg(newbuf("w", src, 4));
		copy16(dst, src);
		bufs[di].out = dst;
		end(0, 0);
	}
	begin("call_many", "i:"); end(1, (uint32_t)call_many());
}

static void floats(void) {
	for (int k = 0; k < CASES; k++) {
		float a = anyfloat(), b = anyfloat(), t = (float)range(0, 1000) / 1000.0f;
		begin("lerp", "f:fff"); arg(fbits(a)); arg(fbits(b)); arg(fbits(t)); end(1, fbits(lerp(a, b, t)));
		double x = (double)range(-100000, 100000) / 997.0;
		begin("poly", "d:d"); arg(dbits(x)); end(1, dbits(poly(x)));
		begin("to_int", "i:f"); arg(fbits(a)); end(1, (uint32_t)to_int(a));
		int i = (int)anyint();
		begin("from_int", "f:i"); arg((uint32_t)i); end(1, fbits(from_int(i)));
		begin("widen", "d:f"); arg(fbits(a)); end(1, dbits(widen(a)));
		begin("fmax_", "f:ff"); arg(fbits(a)); arg(fbits(k % 5 ? b : a)); end(1, fbits(fmax_(a, k % 5 ? b : a)));
		uint32_t fa[16], fb[16];
		int n = range(0, 16);
		for (int j = 0; j < n; j++) {
			fa[j] = fbits(anyfloat());
			fb[j] = fbits(anyfloat());
		}
		begin("dot", "f:ppi"); bufarg(newbuf("f", fa, n)); bufarg(newbuf("f", fb, n)); arg((uint32_t)n);
		end(1, fbits(dot((const float *)fa, (const float *)fb, n)));
	}
}

static void structs(void) {
	for (int k = 0; k < CASES; k++) {
		struct point p = {range(-1000, 1000), range(-1000, 1000)};
		begin("manhattan", "i:p"); bufarg(newbuf("pt", (uint32_t *)&p, 2)); end(1, (uint32_t)manhattan(&p));

		struct node nodes[8];
		uint32_t pairs[16];
		int n = range(0, 8);
		for (int i = 0; i < n; i++) {
			nodes[i].next = i + 1 < n ? &nodes[i + 1] : 0;
			nodes[i].value = range(-1000, 1000);
			nodes[i].tag = (unsigned char)(next() % 3 ? range(1, 255) : 0);
			pairs[2 * i] = (uint32_t)nodes[i].value;
			pairs[2 * i + 1] = nodes[i].tag;
		}
		begin("list_sum", "i:p"); bufarg(newbuf("list", pairs, 2 * n)); end(1, (uint32_t)list_sum(n ? nodes : 0));

		struct point pts[8];
		int m = range(0, 8);
		for (int i = 0; i < m; i++) {
			pts[i].x = range(-1000, 1000);
			pts[i].y = range(-1000, 1000);
		}
		begin("bump", "v:pi"); int bi = newbuf("pt", (uint32_t *)pts, 2 * m); bufarg(bi); arg((uint32_t)m);
		bump(pts, m);
		bufs[bi].out = (uint32_t *)pts;
		end(0, 0);
	}
}

static void jumps(void) {
	for (int k = 0; k < CASES; k++) {
		for (int code = -2; code <= 13; code++) {
			uint32_t a = anyint(), b = anyint();
			if (code == 2 || code == 10) // keep multiplication and negation defined
				a = (uint32_t)range(-30000, 30000), b = (uint32_t)range(-30000, 30000);
			begin("alu", "i:iii"); arg((uint32_t)code); arg(a); arg(b);
			end(1, (uint32_t)alu(code, (int)a, (int)b));
		}
		int x = range(95, 112), y = range(-1000, 1000);
		begin("offset_switch", "i:ii"); arg((uint32_t)x); arg((uint32_t)y); end(1, (uint32_t)offset_switch(x, y));
		unsigned char ch = k % 2 ? (unsigned char)range('a' - 2, 'h' + 2) : (unsigned char)next();
		uint32_t v = anyint();
		begin("byte_switch", "u:Cu"); arg(ch); arg(v); end(1, byte_switch(ch, v));
		unsigned char prog[32];
		uint32_t pw[8] = {0};
		int n = range(0, 31);
		for (int i = 0; i < n; i++)
			prog[i] = (unsigned char)(next() % 4 ? range(0, 7) | range(0, 3) << 3 : next());
		memcpy(pw, prog, n);
		begin("interp", "i:pi"); bufarg(newbuf("b", pw, (n + 3) / 4)); arg((uint32_t)n);
		end(1, (uint32_t)interp(prog, n));
	}
}

int main(void) {
	jumps();
	ints();
	memory();
	calls();
	floats();
	structs();
	return 0;
}
