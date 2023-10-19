#include <stdio.h>

int main()
{
	FILE* f;
	fpos_t position;

	f = fopen("file.txt", "w"); // create a new file in current working folder (Proj folder of the VS solution)
	if (fgetpos(f, &position)) return 1; // get the current position of the file pointer (beginning of the file)

	fputs("Hello World!", f); // write the first/initial string

	if (fsetpos(f, &position)) return 2; // set the current position as beginning of the file
	
	fputs("New ", f); // write new string starting from beginning of the file
	fclose(f);

	return 0;
}