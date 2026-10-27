// Bit manipulation, 64-bit arithmetic, byte swaps and atomics.

unsigned popcount(unsigned x) {
	unsigned n = 0;
	while (x) {
		x &= x - 1;
		n++;
	}
	return n;
}

unsigned bswap(unsigned x) { return __builtin_bswap32(x); }

unsigned clz(unsigned x) { return x ? __builtin_clz(x) : 32; }

unsigned long long mul64(unsigned long long a, unsigned long long b) { return a * b; }

long long smull(int a, int b) { return (long long)a * b; }

unsigned rotl(unsigned x, unsigned n) { return (x << (n & 31)) | (x >> (-n & 31)); }

unsigned extract(unsigned x) { return (x >> 7) & 0x1f; }

unsigned insert(unsigned x, unsigned v) { return (x & ~0xf80u) | ((v & 0x1f) << 7); }

short sext(signed char c) { return c; }

unsigned short zext(unsigned char c) { return c; }

int fetch_add(int *p, int v) { return __atomic_fetch_add(p, v, __ATOMIC_SEQ_CST); }

int cas(int *p, int old, int new_) {
	return __atomic_compare_exchange_n(p, &old, new_, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
