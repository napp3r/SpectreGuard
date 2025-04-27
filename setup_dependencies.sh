#!/bin/bash
echo "Setting up dependencies for binary code injection..."

# Create third_party directory if it doesn't exist
mkdir -p third_party
cd third_party

# Clone Keystone
if [ ! -d "keystone" ]; then
    echo "Downloading Keystone..."
    git clone https://github.com/keystone-engine/keystone.git keystone
    cd keystone
    mkdir -p build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="X86" ..
    echo "Keystone is ready to be built by the main CMake project"
    cd ../..
else
    echo "Keystone already downloaded"
fi

# Clone Capstone
if [ ! -d "capstone" ]; then
    echo "Downloading Capstone..."
    git clone https://github.com/capstone-engine/capstone.git capstone
    cd capstone
    mkdir -p build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_X86_SUPPORT=ON ..
    echo "Capstone is ready to be built by the main CMake project"
    cd ../..
else
    echo "Capstone already downloaded"
fi

cd ..

echo "Done setting up dependencies."
echo "You can now build the project with CMake." 