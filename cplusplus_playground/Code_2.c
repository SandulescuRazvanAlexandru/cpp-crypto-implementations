#include <stdio.h>

#define MACRO_1
#define MACRO_2
#define A_VALUE 1

#define macro1(s) # s

#define macro2(s1, s2) s1 ## s2

int main()
{
	unsigned char a, b, bc;
	a = A_VALUE;
	b = 2;

// #undef MACRO_1
#if (a < 0)
	#ifdef MACRO_1
		char s[] = macro1(Ionescu); // "Ionescu"
		printf("%s\n", s);
	#endif
#else
	#ifdef MACRO_2
		macro2(b, c) = a + b; // bc = a + b
		printf("%d\n", macro2(b, c));
	#endif
#endif
	return 0;
}