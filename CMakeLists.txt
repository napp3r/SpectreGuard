cmake_minimum_required(VERSION 3.16)

project(SpectreGuard VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

# Add Keystone and Capstone build configurations
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/third_party/keystone EXCLUDE_FROM_ALL)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone EXCLUDE_FROM_ALL)

# Define include directories for Keystone and Capstone
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/keystone/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone/include
)

set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    resources.qrc  # Resource file
    sidebar.h sidebar.cpp
    encryptionwidget.h encryptionwidget.cpp
    settingswidget.h settingswidget.cpp
    historywidget.h historywidget.cpp
    obfuscationwidget.h obfuscationwidget.cpp
    filehistory.h filehistory.cpp
    ollvmhandler.h ollvmhandler.cpp
    binaryobfuscator.h binaryobfuscator.cpp
    binarycodeinjector.h binarycodeinjector.cpp
)

qt_add_resources(RESOURCES resources.qrc) # Explicit resource addition

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(asd
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        ${RESOURCES}
        historywidget.h historywidget.cpp
        obfuscationwidget.h obfuscationwidget.cpp
        filehistory.h filehistory.cpp
        ollvmhandler.h ollvmhandler.cpp
        binaryobfuscator.h binaryobfuscator.cpp
        binarycodeinjector.h binarycodeinjector.cpp
    )
else()
    if(ANDROID)
        add_library(asd SHARED
            ${PROJECT_SOURCES}
            ${RESOURCES}
        )
    else()
        add_executable(asd
            ${PROJECT_SOURCES}
            ${RESOURCES}
            historywidget.h historywidget.cpp
            obfuscationwidget.h obfuscationwidget.cpp
            filehistory.h filehistory.cpp
            ollvmhandler.h ollvmhandler.cpp
            binaryobfuscator.h binaryobfuscator.cpp
            binarycodeinjector.h binarycodeinjector.cpp
        )
    endif()
endif()

# Link with Keystone and Capstone libraries
target_link_libraries(asd PRIVATE 
    Qt${QT_VERSION_MAJOR}::Widgets 
    keystone
    capstone
)

set_target_properties(asd PROPERTIES
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS asd
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(asd)
endif()
