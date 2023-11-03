# SHA-256 File Hasher

This program computes the SHA-256 hash of a file named `input.txt` and writes the result both to the console and to a file named `output.txt`.

## Requirements

- OpenSSL library: This program uses the OpenSSL library for SHA-256 computation. Ensure it's installed and properly linked during compilation.

## How It Works

1. The program reads the content of `input.txt`.
2. It computes the SHA-256 hash of the content in chunks of size 256 bytes (or less if the remaining data is smaller than 256 bytes).
3. The computed hash is printed to the console, written to `output.txt`, and stored in a string for a final cross-check.
4. If `input.txt` is not found, an error message is displayed.

## Usage

1. Place the file you want to compute the SHA-256 hash for as `input.txt` in the same directory as the executable.
2. Run the program.
3. Check `output.txt` for the computed SHA-256 hash.

## Code Overview

- `computeSha1(int fileLen, unsigned char* buffer, char sha256[])`: This function takes in the length and content of a file and computes its SHA-256 hash. The result is returned in the `sha256` parameter as a string.
- `main()`: This function handles file reading and invokes the `computeSha1` function.

## Notes

- The program assumes that the input file will fit into memory. For very large files, you might want to consider reading and hashing in smaller chunks.
- Remember to link against the OpenSSL libraries when compiling.
- Despite the function being named `computeSha1`, it actually computes the SHA-256 hash. Consider renaming it to avoid confusion.

## License

[Specify your licensing details here if applicable]

