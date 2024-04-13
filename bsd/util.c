#include <stddef.h>

#include "extern.h"

int
count_char(const void *p, int c, size_t len)
{
	int n = 0;

	for (size_t i = 0; i < len; i++)
		if (*((const unsigned char *)p + i) == c)
			n++;

	return n;
}
