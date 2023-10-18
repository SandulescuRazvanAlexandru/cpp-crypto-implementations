# SHA-1 File Hasher

This program computes the SHA-1 hash of a file named `input.txt` and writes the result both to the console and to a file named `output.txt`.

## Requirements

- OpenSSL library: This program uses the OpenSSL library for SHA-1 computation. Make sure to have it installed and properly linked during compilation.

## How It Works

1. The program reads the content of `input.txt`.
2. It computes the SHA-1 hash of the content in chunks of size 128 bytes (or less if the remaining data is smaller than 128 bytes).
3. The computed hash is printed to the console, written to `output.txt`, and stored in a string for a final cross-check.
4. If `input.txt` is not found, an error message is displayed.

## Usage

1. Place the file you want to compute the SHA-1 hash for as `input.txt` in the same directory as the executable.
2. Run the program.
3. Check `output.txt` for the computed SHA-1 hash.

## Code Overview

- `computeSha1(int fileLen, unsigned char* buffer, char sha1[])`: This function takes in the length and content of a file and computes its SHA-1 hash. The result is returned in the `sha1` parameter as a string.
- `main()`: This function handles file reading and invokes the `computeSha1` function.

## Notes

- The program assumes that the input file will fit into memory. For very large files, you might want to consider reading and hashing in smaller chunks.
- Remember to link against the OpenSSL libraries when compiling.

## License

[Specify your licensing details here if applicable]

