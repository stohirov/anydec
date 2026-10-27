// Switch styles: dense jump table, sparse compare chain.

int dense(int x) {
	switch (x) {
	case 0: return 11;
	case 1: return 23;
	case 2: return 37;
	case 3: return 41;
	case 4: return 59;
	case 5: return 61;
	case 6: return 73;
	default: return -1;
	}
}

int sparse(int x) {
	switch (x) {
	case 3: return 1;
	case 100: return 2;
	case 1000: return 3;
	case 99999: return 4;
	default: return 0;
	}
}

extern void on_a(void);
extern void on_b(void);
extern void on_c(void);

void dispatch(int op) {
	switch (op) {
	case 0: on_a(); break;
	case 1: on_b(); break;
	case 2: on_c(); break;
	}
}
