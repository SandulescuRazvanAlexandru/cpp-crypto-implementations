## ism::string - Custom String Implementation in C++

### Overview

`ism::string` is a custom string class implementation in C++ that provides basic string manipulation functionalities, with the primary methods residing in an external DLL. This repository contains demonstration code for using the `ism::string` class.

### Features

- Initialization from C-style strings
- Copy-construction and assignment
- String concatenation (both appending and combining)
- Basic string comparison (==, !=, <, >, <=, >=)
- Input and output stream support (cin and cout)
- Index-based character access

### Usage

The primary source code can be found in `main.cpp`, where the `ism::string` class is showcased alongside the built-in `std::string` for comparison. The `ism::string` class is defined in `ex23string.hpp`.

**Note**: The actual implementations of the methods are located in an external DLL, as indicated by the `__declspec(dllimport)` directive.

### Sample Code

```cpp
ism::string s1("First string ");
ism::string s2("and the second one.");

s1 += s2;

cout << "s1=" << s1;

ism::string s3, s4, s5;
cout << "s3="; 
cin >> s3;
cout << "s4="; 
cin >> s4;

s5 = s3 + s4;

cout << "\n s5=" << s5;
```

### Dependencies

- A compatible C++ compiler (e.g., GCC, MSVC)
- External DLL (not provided) for `ism::string` method implementations

### Building

[Provide build instructions here, like how to compile and link against the required DLL.]

### Contributing

Feel free to open issues or PRs if you find any problems or have suggestions for improvements.

### License

[Specify the license or add a link to the license file here.]
