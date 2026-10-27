// Jump tables: dense switches whose cases do different work, so compilers
// emit a table of code addresses rather than a table of values.

int alu(int code, int a, int b) {
	switch (code) {
	case 0: return a + b;
	case 1: return a - b;
	case 2: return a * b;
	case 3: return a & b;
	case 4: return a | b;
	case 5: return a ^ b;
	case 6: return a << (b & 31);
	case 7: return (int)((unsigned)a >> (b & 31));
	case 8: return a >> (b & 31);
	case 9: return a < b;
	case 10: return -a;
	case 11: return ~b;
	default: return 0;
	}
}

// Cases that start at 100: the index is x - 100.
int offset_switch(int x, int y) {
	switch (x) {
	case 100: return y * 3;
	case 101: return y + 17;
	case 102: return y ^ 0x55;
	case 103: return y - 9;
	case 104: return y << 2;
	case 105: return y >> 1;
	case 106: return y * y;
	case 107: return 7 - y;
	default: return -1;
	}
}

unsigned byte_switch(unsigned char c, unsigned v) {
	switch (c) {
	case 'a': return v + 1;
	case 'b': return v * 2;
	case 'c': return v - 3;
	case 'd': return v ^ 4;
	case 'e': return v | 5;
	case 'f': return v & 6;
	case 'g': return v << 7;
	case 'h': return v >> 8;
	default: return v;
	}
}

// A switch in a loop: a tiny stack machine.
int interp(const unsigned char *code, int n) {
	int stack[16], sp = 0;
	for (int pc = 0; pc < n; pc++) {
		unsigned char op = code[pc];
		switch (op & 7) {
		case 0: if (sp < 16) stack[sp++] = op >> 3; break;
		case 1: if (sp >= 2) { sp--; stack[sp - 1] += stack[sp]; } break;
		case 2: if (sp >= 2) { sp--; stack[sp - 1] -= stack[sp]; } break;
		case 3: if (sp >= 2) { sp--; stack[sp - 1] *= stack[sp]; } break;
		case 4: if (sp >= 1) stack[sp - 1] = -stack[sp - 1]; break;
		case 5: if (sp >= 1 && sp < 16) { stack[sp] = stack[sp - 1]; sp++; } break;
		case 6: if (sp >= 1) sp--; break;
		case 7: return sp ? stack[sp - 1] : -1;
		}
	}
	return sp ? stack[sp - 1] : 0;
}
