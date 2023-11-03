#include <stdio.h>

int main()
{
	FILE* f;
	int c;

	f = fopen("file.txt", "r");

	//while (1)
	//{
	//	c = fgetc(f);
	//	if (feof(f))
	//	{
	//		break;
	//	}
	//	printf("%c", c);
	//}

	char buffer[256], * pb;
	while (1)
	{
		pb = fgets(buffer, sizeof(buffer), f);
		printf("%s", buffer);
		if (feof(f))
		{
			break;
		}
	}

	fclose(f);

	return 0;
}