#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

//int main()
//{
//	unsigned char str[] = "7F 80";
//	unsigned char* ptr;
//	long int result;
//
//	result = strtol(str, &ptr, 16);
//	printf("Internal value after conversion ASCII-to-binary is %d or %X\n", result, result);
//	result = strtol(ptr, &ptr, 16);
//	printf("Internal value after conversion ASCII-to-binary is %d or %X\n", result, result);
//}

int main()
{
	unsigned char str[] = "7F808182ABAC";
	unsigned char* ptr, pair[2];
	long int result;

	ptr = str;
	for (unsigned char i = 0; i < strlen(str); i += 2)
	{
		memcpy(pair, ptr, 2);
		result = strtol(pair, NULL, 16);
		printf(" %X", result);
		ptr += 2;
	}
}