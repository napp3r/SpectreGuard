# SpectreGuard

A security tool for code obfuscation and binary protection.

## Features

- **Source Code Obfuscation**: Using OLLVM (Obfuscator-LLVM)
- **Binary Code Injection**: Direct manipulation of binary files using Keystone (assembler) and Capstone (disassembler)
- **String Obfuscation**: Encrypt and hide strings in your code
- **Encryption**: Secure your files

## Building with Keystone and Capstone

This project now uses Keystone and Capstone for direct assembly/disassembly of binary files, allowing for advanced code injection techniques to obfuscate executables.

### Prerequisites

- CMake 3.16 or higher
- C++ compiler with C++17 support
- Qt5 or Qt6
- Git (for downloading dependencies)

### Setup Dependencies

#### On Windows:

1. Run the provided setup script:
   ```
   setup_dependencies.bat
   ```

2. The script will:
   - Clone Keystone and Capstone repositories into a `third_party` directory
   - Configure them for static linking
   - Prepare them to be built along with the main project

#### On Linux/macOS:

1. Run the provided setup script:
   ```
   chmod +x setup_dependencies.sh
   ./setup_dependencies.sh
   ```

2. The script performs the same actions as the Windows version.

### Building

After setting up the dependencies:

1. Create a build directory:
   ```
   mkdir build && cd build
   ```

2. Configure with CMake:
   ```
   cmake ..
   ```

3. Build:
   ```
   cmake --build .
   ```

## Usage

### Binary Code Injection

1. Select "Executable Obfuscation" in the obfuscation tab
2. Choose an executable file (.exe or .dll)
3. Select one or more injection methods:
   - Jump Modification: Replaces jump instructions with equivalent but obfuscated ones
   - Code Cave Injection: Inserts junk code into unused spaces
   - New Section Addition: Adds a new section with junk code
   - Random Instruction Insertion: Adds harmless but confusing instructions

### Source Code Obfuscation

1. Select "OLLVM Obfuscation" in the obfuscation tab
2. Choose a C/C++ source file
3. Select obfuscation options

## Notes

- Binary code injection works on PE (Windows executable) format files
- The obfuscation preserves the functionality of the executable while making it harder to reverse engineer 