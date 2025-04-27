#ifndef OLLVMHANDLER_H
#define OLLVMHANDLER_H

#include <QString>
#include <QStringList>

class OLLVMHandler {
public:
    explicit OLLVMHandler();
    ~OLLVMHandler();

    enum ObfuscationFlag {
        CONTROL_FLOW = 0x01,
        STRING_ENCRYPTION = 0x02,
        FUNCTION_CALL = 0x04,
        BOGUS_CONTROL_FLOW = 0x08,
        ALL = 0x0F
    };
    
    static bool isAvailable();
    static bool obfuscateFile(const QString &inputFile, const QString &outputFile, int flags);
    static QStringList getSupportedFlags();
    
private:
    static bool extractEmbeddedOLLVM();
    static QString getOLLVMPath();
    static QString getCompilerCommand(const QString &inputFile, const QString &outputFile, int flags);
};

#endif // OLLVMHANDLER_H 