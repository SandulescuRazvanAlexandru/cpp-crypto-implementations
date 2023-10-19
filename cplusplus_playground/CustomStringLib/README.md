## CustomStringLib: A Custom String Class in C++

### Introduction

CustomStringLib is a simple custom implementation of a string class in C++. It aims to mimic some of the functionalities of the standard string library in C++ but offers its own logic and structures.

### Directory Structure

```
CustomStringLib/
│
├── main.cpp
│
└── ex21string.hpp
```

### Features

1. **Dynamic Memory Allocation**: Memory for the string is allocated dynamically.
2. **String Concatenation**: Using `+=` and `+` operators.
3. **Stream Insertion and Extraction**: Overloaded `<<` and `>>` operators for easy stream operations.
4. **Index-based Access**: Using the `[]` operator.
5. **String Emptiness Check**: A unary `!` operator to check if the string is empty.
6. **String Comparisons**: Relational operators like `==`, `!=`, `<`, `>`, `<=`, and `>=`.

### Usage

After including `ex21string.hpp`, you can create an instance of the `ism::string` class and perform various string operations.

```cpp
ism::string s1("Hello, ");
ism::string s2("world!");
s1 += s2;
std::cout << s1;  // Outputs: Hello, world!
```

### Note

In the `main.cpp`, there's a declaration `void main()`. It's recommended to use `int main()` in standard C++.

### Contributing

Feel free to fork this repository, make your improvements, and raise a pull request.

### License

[MIT License](#) (Replace '#' with the link to your license, if applicable)
