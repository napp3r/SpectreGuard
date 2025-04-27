@echo off
echo Setting up dependencies for binary code injection...

:: Create third_party directory if it doesn't exist
if not exist third_party mkdir third_party
cd third_party

:: Clone Keystone
if not exist keystone (
    echo Downloading Keystone...
    git clone https://github.com/keystone-engine/keystone.git keystone
    cd keystone
    mkdir build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="X86" -G "MinGW Makefiles" ..
    :: Note: You may need to adjust the generator (e.g., "Visual Studio 16 2019" for MSVC)
    echo Keystone is ready to be built by the main CMake project
    cd ..\..
) else (
    echo Keystone already downloaded
)

:: Clone Capstone
if not exist capstone (
    echo Downloading Capstone...
    git clone https://github.com/capstone-engine/capstone.git capstone
    cd capstone
    mkdir build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_X86_SUPPORT=ON -G "MinGW Makefiles" ..
    :: Note: You may need to adjust the generator as above
    echo Capstone is ready to be built by the main CMake project
    cd ..\..
) else (
    echo Capstone already downloaded
)

cd ..

echo Done setting up dependencies.
echo You can now build the project with CMake.
pause 