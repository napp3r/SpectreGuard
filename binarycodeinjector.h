#ifndef BINARYCODEINJECTOR_H
#define BINARYCODEINJECTOR_H

#include <QString>
#include <QByteArray>
#include <QVector>
#include <QList>
#include <QPair>
#include <windows.h>

// Include Keystone and Capstone headers directly
#include "keystone/keystone.h"
#include "capstone/capstone.h"

class BinaryCodeInjector {
public:
    enum InjectionType {
        JUMP_MODIFICATION,    // Modifies existing jumps
        CODE_CAVE_INJECTION,  // Injects code into existing empty spaces
        SECTION_ADDITION,     // Adds a new section to the PE file
        RANDOM_INSTRUCTION,   // Inserts random valid instructions
        JUNK_FUNCTION,        // Adds completely fake functions
        FAKE_API_CALLS        // Adds fake Windows API calls
    };
    
    struct InjectionPoint {
        quint64 offset;      // Offset in the file
        quint64 virtualAddr; // Virtual address (RVA + ImageBase)
        quint32 size;        // Available size
        bool executable;     // Is it in an executable section
    };
    
    struct PEInfo {
        quint32 peOffset;
        quint32 sectionCount;
        quint32 optHeaderSize;
        quint32 sectionTableOffset;
        quint32 entryPointRVA;
        quint32 imageBase;
        quint32 fileAlignment;
        quint32 sectionAlignment;
        quint32 sizeOfImage;
        bool isPE32Plus;  // Whether the file is PE32+ (64-bit)
    };
    
    // Initialize the injector
    static bool initialize();
    
    // Clean up resources
    static void cleanup();
    
    // Check if libraries are properly initialized
    static bool isAvailable();
    
    // Main function to inject junk code into EXE
    static bool injectJunkCode(const QString &inputFile, const QString &outputFile, 
                              const QList<InjectionType> &methods);
    
    // Get supported injection methods
    static QStringList getSupportedMethods();
    
    // Convert InjectionType enum to string description
    static QString injectionTypeToString(InjectionType type);
    
    // Instance methods for additional functionality
    static bool injectCustomPadding(const QString &filePath, const QByteArray &paddingBytes);
    static bool injectFakeApiCalls(const QString &filePath, const QStringList &apiNames, int numApiCalls);
    static bool injectJunkFunctions(const QString &filePath, int numFunctions, const QStringList &apiNames);
    
    // Verify that obfuscation was properly applied
    static bool verifyObfuscation(const QString &filePath);
    
private:
    // Find suitable injection points in the PE file
    static QList<InjectionPoint> findInjectionPoints(const QByteArray &peData);
    
    // Add junk code to a specific injection point
    static bool injectAtPoint(QByteArray &peData, const InjectionPoint &point, InjectionType method);
    
    // Various injection strategies
    static bool modifyJumps(QByteArray &peData, const InjectionPoint &point);
    static bool injectIntoCodeCave(QByteArray &peData, const InjectionPoint &point);
    static bool addSection(QByteArray &peData);
    static bool insertRandomInstructions(QByteArray &peData, const InjectionPoint &point);
    static bool insertJunkFunctions(QByteArray &peData);
    static bool insertFakeAPICalls(QByteArray &peData, const InjectionPoint &point);
    
    // Helper for jump obfuscation
    static QString invertJumpCondition(const QString &jumpMnemonic);
    
    // Helper for junk function creation
    static QByteArray createJunkFunction(int complexity, quint64 baseAddress);
    static QList<QString> getJunkFunctionNames(int count);
    static QByteArray createFakeApiCall(const QString &apiName, quint64 address);
    
    // Section manipulation helpers
    static bool addCodeSection(QByteArray &peData, const QByteArray &sectionData, 
                               const QString &sectionName, PEInfo &peInfo);
    static bool updatePEHeaders(QByteArray &peData, const PEInfo &peInfo);
    
    // PE file analysis helpers
    static bool isPEFile(const QByteArray &data);
    static PEInfo getPEInfo(const QByteArray &data);
    static QPair<quint64, quint64> getEntryPointInfo(const QByteArray &data);
    static QVector<QPair<quint64, quint64>> getSectionInfo(const QByteArray &data);
    
    // Assembler/disassembler helpers
    static QByteArray assembleX86(const QString &asmCode, quint64 address);
    static QString disassembleX86(const QByteArray &code, quint64 address);
    
    // Keystone/Capstone engine instances
    static ks_engine *ks;
    static csh cs;
    
    // Helper functions for working with PE files
    static bool loadPeFile(const QString &filePath, PEInfo &peInfo);
    static bool savePeFile(const PEInfo &peInfo, const QString &filePath);
    static bool createNewSection(PEInfo &peInfo, const QString &sectionName, quint32 sectionSize, DWORD characteristics, quint64 &virtualAddress, quint64 &relativeVirtualAddress);
    static bool writeBytesToSection(PEInfo &peInfo, const QString &sectionName, quint32 offset, const QByteArray &data);
    static QVector<QString> generateFunctionNames(int count = 10);
};

#endif // BINARYCODEINJECTOR_H 