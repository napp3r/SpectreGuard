#ifndef BINARYOBFUSCATOR_H
#define BINARYOBFUSCATOR_H

#include <QObject>
#include <QList>
#include <QString>
#include "binarycodeinjector.h"

class BinaryObfuscator : public QObject
{
    Q_OBJECT
public:
    explicit BinaryObfuscator(QObject *parent = nullptr);
    
    // Static methods for initialization and information
    static bool isAvailable();
    static bool initializeLibraries();
    static QStringList getSupportedMethods();
    
    // Main obfuscation method
    bool obfuscateExe(const QString &inputFile, const QString &outputFile, 
                     const QList<BinaryCodeInjector::InjectionType> &methods);
                     
signals:
    void progressUpdate(const QString &message, int progress);
    
private:
    bool injectJumpModifications(const QString &file);
    bool injectCodeCave(const QString &file);
    bool addNewSection(const QString &file);
    bool insertRandomInstructions(const QString &file);
    bool insertJunkFunctions(const QString &file);
    bool insertFakeApiCalls(const QString &file);
    
    bool copyPEFile(const QString &source, const QString &destination);
};

#endif // BINARYOBFUSCATOR_H 