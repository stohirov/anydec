// Floating point: arithmetic, conversions, compares, double precision.

float lerp(float a, float b, float t) { return a + (b - a) * t; }

double poly(double x) { return ((3.0 * x + 2.0) * x - 1.0) * x + 0.5; }

int to_int(float f) { return (int)f; }

float from_int(int i) { return (float)i; }

double widen(float f) { return f; }

float fmax_(float a, float b) { return a > b ? a : b; }

float dot(const float *a, const float *b, int n) {
	float s = 0;
	for (int i = 0; i < n; i++)
		s += a[i] * b[i];
	return s;
}
