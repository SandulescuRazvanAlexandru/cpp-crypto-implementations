#include <stdio.h>
#include <malloc.h>

int sum_by_ref(char x, char& y)
{
	y = x + y;

	return (x + y);
}

void alloc(char* y, char no)
{
	y = (char*)malloc(sizeof(char) * no);
	for (char i = 0; i < no; i++)
		y[i] = 0;
}

void alloc_by_address(char* *y, char no)
{
	*y = (char*)malloc(sizeof(char) * no);
	for (char i = 0; i < no; i++)
		(*y)[i] = 0;
}

void alloc_by_ref(char* &y, char no)
{
	y = (char*)malloc(sizeof(char) * no);
	for (char i = 0; i < no; i++)
		y[i] = 0;
}

int main()
{
	char a, b;
	int s;

	a = 0x41;
	b = 10;

	s = sum_by_ref(a, b);
	printf("s = %d, a = %d, b = %d\n", s, a, b);

	char* pa = NULL;
	alloc(pa, 7);
	alloc_by_address(&pa, 7);

	alloc_by_ref(pa, 7);
}