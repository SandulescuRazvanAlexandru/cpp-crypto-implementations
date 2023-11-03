#include <stdio.h>

int main()
{
	FILE* f;
	char s[] = "This is the new content of the file.txt";
	char buffer[100];

	f = fopen("file.txt", "w+");

	// size_t n = fwrite(s, sizeof(s), 1, f); // write 1 single time (1 operation/block) the string s
	size_t n = fwrite(s, 1, sizeof(s), f); // write sizeof(s) times (sizeof(s) operations/blocks) the string s
	printf("Result of fwrite as number of blocks: %d\n", n);

	if (fseek(f, 0, SEEK_SET)) return 1; // place the file pointer on the beginning of the file

	// n = fread(&buffer, sizeof(s), 1, f);
	// n = fread(&buffer, strlen(s) + 1, 1, f);
	n = fread(&buffer, 1, strlen(s) + 1, f); // strlen(s) + 1 read operations; each read operation applied for 1 single byte
	printf("Result of fread as number of blocks: %d\n", n); 
	printf("%s\n", buffer);

	fclose(f);

	return 0;
}