#include <stdio.h>

int main()
{
	FILE* f;
	short int a = 0x1234, ra;
	signed int b = 0xffee0011, rb;
	float c = (float)13.13131313, rc;
	char buffer[] = "A small string.", rbuffer[30];

	f = fopen("file.bin", "wb+");

	size_t n = fwrite(&a, sizeof(short int), 1, f);
	n = fwrite(&b, sizeof(signed int), 1, f);
	n = fwrite(&c, sizeof(float), 1, f);
	n = fwrite(buffer, sizeof(buffer), 1, f);

	if (fseek(f, 0, SEEK_SET)) return 1; // place the file pointer on the beginning of the file

	n = fread(&ra, sizeof(ra), 1, f);
	n = fread(&rb, sizeof(rb), 1, f);
	n = fread(&rc, sizeof(rc), 1, f);
	n = fread(&rbuffer, sizeof(buffer), 1, f);

	printf("Results of fread operation: %X, %X, %.8f, %s\n", ra, rb, rc, rbuffer);

	fclose(f);

	return 0;
}