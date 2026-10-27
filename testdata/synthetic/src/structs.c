// Struct field access, arrays of structs, linked lists, globals.

struct point { int x, y; };
struct node { struct node *next; int value; unsigned char tag; };

int counter;
struct point origin = {3, 4};

int manhattan(const struct point *p) {
	int dx = p->x - origin.x, dy = p->y - origin.y;
	return (dx < 0 ? -dx : dx) + (dy < 0 ? -dy : dy);
}

int list_sum(const struct node *n) {
	int s = 0;
	for (; n; n = n->next)
		if (n->tag)
			s += n->value;
	return s;
}

void bump(struct point *pts, int n) {
	for (int i = 0; i < n; i++) {
		pts[i].x++;
		pts[i].y += 2;
	}
	counter += n;
}
