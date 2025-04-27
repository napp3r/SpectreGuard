#include "ollvmhandler.h"
#include <QFile>
#include <QDir>
#include <QProcess>
#include <QCoreApplication>
#include <QStandardPaths>
#include <QDebug>
#include <QResource>

// Binary data for embedded OLLVM files
// The actual binary data will be included here
// Below is a placeholder resource reference
extern const unsigned char ollvm_clang_binary[];
extern const unsigned int ollvm_clang_binary_size;

OLLVMHandler::OLLVMHandler() {
}

OLLVMHandler::~OLLVMHandler() {
}

bool OLLVMHandler::isAvailable() {
    return QFile::exists(getOLLVMPath());
}

QStringList OLLVMHandler::getSupportedFlags() {
    return {
        "Control Flow",
        "String Encryption",
        "Function Call Obfuscation",
        "Bogus Control Flow"
    };
}

bool OLLVMHandler::obfuscateFile(const QString &inputFile, const QString &outputFile, int flags) {
    // Make sure OLLVM is extracted and available
    if (!isAvailable()) {
        if (!extractEmbeddedOLLVM()) {
            return false;
        }
    }

    // Build the command for running OLLVM
    QString command = getCompilerCommand(inputFile, outputFile, flags);
    
    // Execute the command
    QProcess process;
    process.start(command);
    
    if (!process.waitForStarted()) {
        qDebug() << "Failed to start OLLVM process";
        return false;
    }
    
    if (!process.waitForFinished()) {
        qDebug() << "OLLVM process failed to finish";
        return false;
    }
    
    // Check if output file was created
    return QFile::exists(outputFile);
}

bool OLLVMHandler::extractEmbeddedOLLVM() {
    QString ollvmPath = getOLLVMPath();
    QString ollvmDir = QFileInfo(ollvmPath).dir().absolutePath();

    // Create directory if it doesn't exist
    QDir dir;
    if (!dir.exists(ollvmDir)) {
        if (!dir.mkpath(ollvmDir)) {
            qDebug() << "Failed to create directory for OLLVM";
            return false;
        }
    }
    
    // Check if OLLVM is already extracted
    if (QFile::exists(ollvmPath)) {
        return true;
    }
    
    // Extract OLLVM binary from resources
    QFile resourceFile(":/binaries/ollvm-clang");
    if (!resourceFile.exists()) {
        qDebug() << "OLLVM resource not found";
        return false;
    }
    
    if (!resourceFile.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open OLLVM resource";
        return false;
    }
    
    QFile outputFile(ollvmPath);
    if (!outputFile.open(QIODevice::WriteOnly)) {
        qDebug() << "Failed to create OLLVM binary file";
        resourceFile.close();
        return false;
    }
    
    outputFile.write(resourceFile.readAll());
    outputFile.close();
    resourceFile.close();
    
    // Make the extracted binary executable
    QFile::setPermissions(ollvmPath, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner |
                                    QFile::ReadGroup | QFile::ExeGroup |
                                    QFile::ReadOther | QFile::ExeOther);
    
    return true;
}

QString OLLVMHandler::getOLLVMPath() {
    // Store OLLVM binary in a standard location
    QString dataLocation = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QString binaryName = "ollvm-clang";
    
    #ifdef Q_OS_WIN
    binaryName += ".exe";
    #endif
    
    return QDir(dataLocation).filePath("ollvm/" + binaryName);
}

QString OLLVMHandler::getCompilerCommand(const QString &inputFile, const QString &outputFile, int flags) {
    QString ollvmPath = getOLLVMPath();
    QStringList args;
    
    // Add compiler flags
    args << inputFile << "-o" << outputFile;
    
    // Add obfuscation flags based on the input flags
    if (flags & CONTROL_FLOW) {
        args << "-mllvm" << "-fla";
    }
    
    if (flags & STRING_ENCRYPTION) {
        args << "-mllvm" << "-sobf";
    }
    
    if (flags & FUNCTION_CALL) {
        args << "-mllvm" << "-bcf";
    }
    
    if (flags & BOGUS_CONTROL_FLOW) {
        args << "-mllvm" << "-sub";
    }
    
    // Construct complete command
    QString command = QString("\"%1\" %2").arg(ollvmPath, args.join(" "));
    return command;
} 