# Binary Tools Integration

This directory contains placeholders for various binary tools that will be embedded in the application:

## OLLVM (Obfuscator-LLVM)

The Obfuscator-LLVM binary (`ollvm-clang`) is used to obfuscate C/C++ source code.

### How to Replace the OLLVM Placeholder

1. Download the Obfuscator-LLVM from the official source: https://github.com/obfuscator-llvm/obfuscator
2. Build the OLLVM according to its documentation
3. Copy the compiled `clang` binary to this directory, renaming it to `ollvm-clang`
4. For Windows, make sure to rename it to `ollvm-clang.exe`

## Executable Obfuscation Tools

The following tools are used for binary/executable obfuscation:

1. **UPX** (`upx.exe`) - Ultimate Packer for eXecutables, compresses and encrypts executables
2. **PE-Protect** (`peprotect.exe`) - Applies code virtualization and anti-debug protections
3. **PE-BindBlur** (`pebindblur.exe`) - Protects against import table dumping and static analysis

### How to Replace the Executable Tool Placeholders

1. **UPX**: Download from https://github.com/upx/upx/releases and rename to `upx.exe`
2. **PE-Protect**: This is a custom tool (or use an alternative like VMProtect)
3. **PE-BindBlur**: This is a custom tool (or use an alternative like Themida)

## Important Notes

- The build process will embed these binaries into the application resources, allowing users to use them without having to download or install them separately.
- If you modify any tool or use different versions, you may need to update the corresponding handler code to match the command-line options supported by your versions.
- Most of these binaries are quite large (typically 20MB+ each), so make sure your deployment system can handle embedding large binary resources.
- Make sure you have the appropriate licenses to distribute any third-party tools that you include.

## Additional Resources

- OLLVM Official Repository: https://github.com/obfuscator-llvm/obfuscator
- OLLVM Documentation: https://github.com/obfuscator-llvm/obfuscator/wiki
- UPX Official Website: https://upx.github.io/ 