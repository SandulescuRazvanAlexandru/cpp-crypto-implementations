#include <stdio.h>


int sum_by_value(char x, char y)
{
	y = x + y;

	return (x + y);
}

int sum_by_address(char x, char *y)
{
	*y = x + *y;

	return (x + *y);
}

//int sum_by_ref(char x, char& y)
//{
//	y = x + y;
//
//	return (x + y);
//}

int main()
{
	char a, b;
	int s;

	a = 0x41;
	b = 10;

	s = sum_by_value(a, b);
	printf("s = %d, a = %d, b = %d\n", s, a, b);

	s = sum_by_address(a, &b);
	printf("s = %d, a = %d, b = %d\n", s, a, b);

	//int c = 11;
	//s = sum_by_address(a, &c);
}