// Loop shapes: counted, while, do-while, nested, early exit.

int sum(const int *p, int n) {
	int s = 0;
	for (int i = 0; i < n; i++)
		s += p[i];
	return s;
}

unsigned strlen_(const char *s) {
	unsigned n = 0;
	while (s[n])
		n++;
	return n;
}

int find(const int *p, int n, int key) {
	for (int i = 0; i < n; i++)
		if (p[i] == key)
			return i;
	return -1;
}

void matmul(int n, const int *a, const int *b, int *c) {
	for (int i = 0; i < n; i++)
		for (int j = 0; j < n; j++) {
			int s = 0;
			for (int k = 0; k < n; k++)
				s += a[i * n + k] * b[k * n + j];
			c[i * n + j] = s;
		}
}

unsigned collatz(unsigned x) {
	unsigned steps = 0;
	do {
		x = x & 1 ? 3 * x + 1 : x / 2;
		steps++;
	} while (x != 1);
	return steps;
}
