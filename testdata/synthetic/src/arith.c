// Straight-line integer arithmetic, shifts and compares.

int add(int a, int b) { return a + b; }

int mul_add(int a, int b, int c) { return a * b + c; }

unsigned shifts(unsigned x, int n) { return (x << n) ^ (x >> (32 - n)); }

int sdiv(int a, int b) { return b ? a / b : 0; }

int clamp(int x, int lo, int hi) {
	if (x < lo)
		return lo;
	if (x > hi)
		return hi;
	return x;
}

long long wide_add(long long a, long long b) { return a + b; }
