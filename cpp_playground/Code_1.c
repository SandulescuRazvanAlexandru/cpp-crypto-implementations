#include <stdio.h>
#include <malloc.h>

//// variables & pointers
//unsigned char b;
//
//int main()
//{
//	unsigned char a; // [signed | unsigned] [short | long ] int, float (double, long double)
//	unsigned char* pa; // pointer;
//	signed char i;
//	signed char n = 30; // number of bytes to be parse on the right side of the memory address contained by pa
//	int x = 0;
//
//	a = 'A';
//	pa = &a; // memory address of a stored by the pointer pa
//	printf(" %d %c\n", a, a);
//	printf(" %d %c\n", *pa, *pa);
//
//	a = 96; // 0x41 = 65; 0x60 = 96
//	printf(" %d %c\n", a, a);
//	printf(" %d %c\n", *pa, *pa);
//
//	for (i = 0; i < n; i++) // dump the right side of memory starting from a (low to high)
//		printf(" %2X ", pa[i]);
//	printf("\n");
//
//	n = -30;
//	for (i = n - 1 ; i <= 0; i++) // dump the left side of memory till a (low to high)
//		printf(" %2X ", pa[i]);
//	printf("\n");
//
//	// &pa = &a; // not allowed to change the stack memory address allocated at compile-time
//
//	pa = &n;
//
//	pa = (unsigned char*)&x;
//
//	return 0;
//}

// arrays allocated at compile-time
//int main()
//{
//	int y[10][10], m, n;
//	int x[3][3];
//
//	for (int i = 0; i < 10; i++)
//		for (int j = 0; j < 10; j++)
//			y[i][j] = 0;
//
//	scanf("%d", &m);
//	scanf("%d", &n);
//	for (int i = 0; i < m; i++)
//		for (int j = 0; j < n; j++)
//			x[i][j] = 0;
//
//	printf("Address(x) = %p \n", x);
//	for (int i = 0; i < 3; i++)
//	{
//		// printf("Start address(line %d) = %p ", i + 1, x + i);
//		printf("Start address(line %d) = %p ", i + 1, x[i]);
//	}
//
//	for (int i = 0; i < 3; i++)
//	{
//		for (int j = 0; j < 3; j++)
//			// printf("Address item [%d][%d] = %p ", i + 1, j + 1,  *(x + i) + j);
//			printf("Address item [%d][%d] = %p ", i + 1, j + 1, &x[i][j]);
//		printf("\n");
//	}
//
//
//	return 0;
//}

//// vector allocated in heap memory dynamically
//int main() {
//	int* pV, n;
//	scanf("%d", &n);
//	pV = (int*)malloc(n * sizeof(int));
//
//	for (int i = 0; i < n; i++)
//		pV[i] = 0;
//
//	printf("Adrress stack seg = %p, Address contained by = %p\n", &pV, pV);
//	for (int i = 0; i < n; i++)
//		printf("Adrress item #%d = %p \n", i + 1, pV + i); // pV + i ---> mem address pf item #i = pV + sizeof(int) * i
//
//	for (int i = 0; i < n; i++)
//		*(pV + i) = i + 1;
//	for (int i = 0; i < n; i++)
//		printf(" %d ", pV[i]);
//	printf("\n");
//
//	free(pV);
//	pV = NULL;
//	// pV = &n;
//	free(pV);
//
//	return 0;
//}

// bi-dimensional array (matrix) allocated in heap memory dynamically
int main() {
	int** pM, m, n;
	scanf("%d", &m);
	scanf("%d", &n);
	// allocation
	pM = (int**)malloc(m * sizeof(int*)); // intermediate structure containing heap mem addresses of the lines
	for (int i = 0; i < m; i++)
		*(pM + i) = (int*)malloc(n * sizeof(int));

	for (int i = 0; i < m; i++)
		for (int j = 0; j < n; j++)
			pM[i][j] = i * 10 + j;

	// deallocation
	for (int i = 0; i < m; i++)
		free(*(pM + i));
	free(pM);

	return 0;
}