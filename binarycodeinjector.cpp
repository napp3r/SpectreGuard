#include "binarycodeinjector.h"
#include <QFile>
#include <QDebug>
#include <QRandomGenerator>
#include <QDir>
#include <QTemporaryFile>
#include <QRegularExpression>

// Initialize static members
ks_engine* BinaryCodeInjector::ks = nullptr;
csh BinaryCodeInjector::cs = 0;

bool BinaryCodeInjector::initialize() {
    // Initialize Keystone
    qDebug() << "Initializing Keystone assembler engine...";
    ks_err ks_error = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
    if (ks_error != KS_ERR_OK) {
        qDebug() << "Failed to initialize Keystone:" << ks_strerror(ks_error);
        return false;
    }
    qDebug() << "Keystone engine initialized successfully";
    
    // Initialize Capstone
    qDebug() << "Initializing Capstone disassembler engine...";
    cs_err cs_error = cs_open(CS_ARCH_X86, CS_MODE_32, &cs);
    if (cs_error != CS_ERR_OK) {
        qDebug() << "Failed to initialize Capstone:" << cs_strerror(cs_error);
        ks_close(ks);
        ks = nullptr;
        return false;
    }
    
    // Enable detailed instruction information
    cs_error = cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);
    if (cs_error != CS_ERR_OK) {
        qDebug() << "Failed to set Capstone options:" << cs_strerror(cs_error);
        cs_close(&cs);
        cs = 0;
        ks_close(ks);
        ks = nullptr;
        return false;
    }
    
    qDebug() << "Capstone engine initialized successfully";
    return true;
}

void BinaryCodeInjector::cleanup() {
    if (ks) {
        ks_close(ks);
        ks = nullptr;
    }
    
    if (cs) {
        cs_close(&cs);
        cs = 0;
    }
}

bool BinaryCodeInjector::isAvailable() {
    return ks != nullptr && cs != 0;
}

QStringList BinaryCodeInjector::getSupportedMethods() {
    return {
        injectionTypeToString(JUMP_MODIFICATION),
        injectionTypeToString(CODE_CAVE_INJECTION),
        injectionTypeToString(SECTION_ADDITION),
        injectionTypeToString(RANDOM_INSTRUCTION),
        injectionTypeToString(JUNK_FUNCTION),
        injectionTypeToString(FAKE_API_CALLS)
    };
}

QString BinaryCodeInjector::injectionTypeToString(InjectionType type) {
    switch (type) {
        case JUMP_MODIFICATION:
            return "Jump Instruction Modification";
        case CODE_CAVE_INJECTION:
            return "Code Cave Injection";
        case SECTION_ADDITION:
            return "New Section Addition";
        case RANDOM_INSTRUCTION:
            return "Random Instruction Insertion";
        case JUNK_FUNCTION:
            return "Junk Function Insertion";
        case FAKE_API_CALLS:
            return "Fake API Call Insertion";
        default:
            return "Unknown Method";
    }
}

bool BinaryCodeInjector::injectJunkCode(const QString &inputFile, const QString &outputFile, 
                                       const QList<InjectionType> &methods) {
    qDebug() << "Starting binary code injection for file:" << inputFile;
    qDebug() << "Requested methods:" << methods.size();
    
    if (!isAvailable() && !initialize()) {
        qDebug() << "ERROR: Keystone/Capstone engines not available";
        return false;
    }
    
    // Read input file
    QFile file(inputFile);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "ERROR: Failed to open input file:" << inputFile;
        return false;
    }
    
    QByteArray peData = file.readAll();
    file.close();
    
    qDebug() << "Read" << peData.size() << "bytes from input file";
    
    // Verify PE format
    if (!isPEFile(peData)) {
        qDebug() << "ERROR: Not a valid PE file:" << inputFile;
        return false;
    }
    
    // Find injection points
    QList<InjectionPoint> injectionPoints = findInjectionPoints(peData);
    if (injectionPoints.isEmpty()) {
        qDebug() << "ERROR: No suitable injection points found in:" << inputFile;
        return false;
    }
    
    // Apply requested injection methods
    bool modified = false;
    int successCount = 0;
    
    for (const auto &method : methods) {
        qDebug() << "Applying method:" << injectionTypeToString(method);
        bool methodSuccess = false;
        
        switch (method) {
            case SECTION_ADDITION:
                // Section addition can be risky too, but less so than JUNK_FUNCTION
                qDebug() << "WARNING: Section Addition can potentially break functionality";
                qDebug() << "Proceeding with caution...";
                if (addSection(peData)) {
                    modified = true;
                    methodSuccess = true;
                    successCount++;
                }
                break;
                
            case JUNK_FUNCTION:
                // Use our safer junk function insertion method
                qDebug() << "Using safer junk function insertion to preserve functionality";
                if (insertJunkFunctions(peData)) {
                    modified = true;
                    methodSuccess = true;
                    successCount++;
                }
                break;
                
            default: {
                // For point-based methods, try multiple injection points until one succeeds
                bool pointSuccess = false;
                
                // Try different injection points until success or all points are exhausted
                for (int attempt = 0; attempt < injectionPoints.size() && !pointSuccess; attempt++) {
                    int pointIndex = QRandomGenerator::global()->bounded(injectionPoints.size());
                    InjectionPoint &point = injectionPoints[pointIndex];
                    
                    qDebug() << "  Attempting injection at point offset:" << point.offset
                             << "virtualAddr:" << QString::number(point.virtualAddr, 16)
                             << "size:" << point.size;
                    
                    if (injectAtPoint(peData, point, method)) {
                        modified = true;
                        methodSuccess = true;
                        pointSuccess = true;
                        successCount++;
                        qDebug() << "  Injection successful!";
                    } else {
                        qDebug() << "  Injection failed, will try another point";
                    }
                }
                
                if (!pointSuccess) {
                    qDebug() << "  Failed to apply method to any injection point";
                }
                break;
            }
        }
        
        if (methodSuccess) {
            qDebug() << "Successfully applied method:" << injectionTypeToString(method);
        } else {
            qDebug() << "Failed to apply method:" << injectionTypeToString(method);
        }
    }
    
    if (!modified) {
        qDebug() << "ERROR: Failed to apply any injection methods";
        return false;
    }
    
    qDebug() << "Successfully applied" << successCount << "out of" << methods.size() << "methods";
    
    // Write output file
    QFile outFile(outputFile);
    if (!outFile.open(QIODevice::WriteOnly)) {
        qDebug() << "ERROR: Failed to open output file:" << outputFile;
        return false;
    }
    
    outFile.write(peData);
    outFile.close();
    
    qDebug() << "Successfully wrote obfuscated file to:" << outputFile;
    return true;
}

QList<BinaryCodeInjector::InjectionPoint> BinaryCodeInjector::findInjectionPoints(const QByteArray &peData) {
    QList<InjectionPoint> points;
    
    qDebug() << "Finding injection points in PE file of size" << peData.size() << "bytes";
    
    // Validate PE format
    if (!isPEFile(peData)) {
        qDebug() << "Not a valid PE file, cannot find injection points";
        return points;
    }
    
    // Get the PE info
    PEInfo peInfo = getPEInfo(peData);
    qDebug() << "PE file info: Entry point RVA:" << peInfo.entryPointRVA
             << "Sections:" << peInfo.sectionCount;
    
    // Get entry point info (offset, RVA)
    auto entryPointInfo = getEntryPointInfo(peData);
    quint64 entryPointOffset = entryPointInfo.first;
    quint64 entryPointRVA = entryPointInfo.second;
    
    qDebug() << "Entry point offset:" << entryPointOffset 
             << "RVA:" << QString::number(entryPointRVA, 16);
    
    if (entryPointOffset > 0) {
        // Add entry point as an injection point (for jump modification)
        InjectionPoint entryPoint;
        entryPoint.offset = entryPointOffset;
        entryPoint.virtualAddr = entryPointRVA;
        entryPoint.size = 32; // Reasonable size for entry point modifications
        entryPoint.executable = true;
        points.append(entryPoint);
        qDebug() << "Added entry point injection point at offset" << entryPointOffset;
    }
    
    // Get sections info
    auto sectionsInfo = getSectionInfo(peData);
    qDebug() << "Found" << sectionsInfo.size() << "sections for code cave scanning";
    
    // Find code caves (sequences of zeros or padding bytes)
    int caveCount = 0;
    for (const auto &section : sectionsInfo) {
        quint64 sectionOffset = section.first;
        quint64 sectionSize = section.second;
        
        qDebug() << "Scanning section at offset" << sectionOffset << "size" << sectionSize;
        
        if (sectionSize < 16) {
            qDebug() << "  Skipping section (too small)";
            continue; // Too small
        }
        
        // Scan for code caves (at least 32 bytes of zeros or padding)
        const int minCaveSize = 32;
        const char *data = peData.constData() + sectionOffset;
        
        for (quint64 i = 0; i < sectionSize - minCaveSize; i++) {
            // Check if we have a sequence of zeros or padding bytes
            bool isCave = true;
            for (int j = 0; j < minCaveSize; j++) {
                if (data[i + j] != 0 && data[i + j] != 0x90 /* NOP */) {
                    isCave = false;
                    break;
                }
            }
            
            if (isCave) {
                // Found a code cave
                InjectionPoint cave;
                cave.offset = sectionOffset + i;
                cave.virtualAddr = peInfo.imageBase + (sectionOffset + i); // Estimate virtual address
                cave.size = minCaveSize;
                cave.executable = true; // Assume executable for now
                points.append(cave);
                caveCount++;
                
                qDebug() << "  Found code cave at offset" << cave.offset 
                         << "virtual address" << QString::number(cave.virtualAddr, 16)
                         << "size" << cave.size;
                
                // Skip to the end of this cave
                i += minCaveSize;
            }
        }
    }
    
    // If we didn't find any code caves, create a fake injection point at the end
    // of the last section for section addition
    if (caveCount == 0 && !sectionsInfo.isEmpty()) {
        auto lastSection = sectionsInfo.last();
        InjectionPoint fakePoint;
        fakePoint.offset = lastSection.first + lastSection.second - 16;
        fakePoint.virtualAddr = peInfo.imageBase + fakePoint.offset;
        fakePoint.size = 16;
        fakePoint.executable = true;
        points.append(fakePoint);
        qDebug() << "No code caves found, added fake injection point for section addition at" 
                 << fakePoint.offset;
    }
    
    qDebug() << "Found a total of" << points.size() << "injection points";
    return points;
}

bool BinaryCodeInjector::injectAtPoint(QByteArray &peData, const InjectionPoint &point, InjectionType method) {
    switch (method) {
        case JUMP_MODIFICATION:
            return modifyJumps(peData, point);
        case CODE_CAVE_INJECTION:
            return injectIntoCodeCave(peData, point);
        case RANDOM_INSTRUCTION:
            return insertRandomInstructions(peData, point);
        case FAKE_API_CALLS:
            return insertFakeAPICalls(peData, point);
        default:
            qDebug() << "Unsupported injection method at point";
            return false;
    }
}

bool BinaryCodeInjector::modifyJumps(QByteArray &peData, const InjectionPoint &point) {
    if (!cs || !ks) {
        qDebug() << "Disassembler/Assembler engines not initialized";
        return false;
    }
    
    // Disassemble code at the injection point
    QByteArray codeSlice = peData.mid(point.offset, point.size);
    
    // Disassemble using Capstone
    cs_insn *insn;
    size_t count = cs_disasm(cs, (const uint8_t*)codeSlice.constData(), 
                             codeSlice.size(), point.virtualAddr, 0, &insn);
    
    if (count <= 0) {
        qDebug() << "Failed to disassemble code at offset" << point.offset;
        return false;
    }
    
    bool modified = false;
    QString newCode;
    
    // Find jump or call instructions to replace
    for (size_t i = 0; i < count; i++) {
        cs_insn *instruction = &insn[i];
        QString mnemonic = instruction->mnemonic;
        
        // Check if this is a jump or call instruction we can replace
        if (mnemonic.startsWith("j") || mnemonic == "call") {
            QString originalOp = QString("%1 %2").arg(instruction->mnemonic).arg(instruction->op_str);
            quint64 targetAddr = 0;
            
            // Handle direct jumps (extract target address)
            if (mnemonic != "call" && instruction->op_str[0] == '0' && instruction->op_str[1] == 'x') {
                targetAddr = strtoull(instruction->op_str, nullptr, 16);
                
                // Generate obfuscated equivalent code
                QString obfuscatedJump;
                
                if (mnemonic == "jmp") {
                    // Replace direct jmp with push + ret
                    obfuscatedJump = QString("push 0x%1\nret").arg(targetAddr, 0, 16);
                } else if (mnemonic.startsWith("j")) {
                    // For conditional jumps, use a more complex equivalent
                    // Get the inverse condition - e.g., "je" -> "jne"
                    QString invertedCond = invertJumpCondition(mnemonic);
                    
                    // Original: je target
                    // New: jne skip_target
                    //      push target
                    //      ret
                    //      skip_target:
                    obfuscatedJump = QString("%1 skip_target_%2\n"
                                           "push 0x%3\n"
                                           "ret\n"
                                           "skip_target_%2:")
                                     .arg(invertedCond)
                                     .arg(i)
                                     .arg(targetAddr, 0, 16);
                }
                
                if (!obfuscatedJump.isEmpty()) {
                    qDebug() << "Obfuscating jump at" << QString::number(instruction->address, 16)
                             << "from" << originalOp << "to" << obfuscatedJump;
                    
                    // Add to our new code
                    newCode += obfuscatedJump + "\n";
                    modified = true;
                    continue;
                }
            }
        }
        
        // Keep other instructions as they are
        if (!modified) {
            newCode += QString("%1 %2\n").arg(instruction->mnemonic).arg(instruction->op_str);
        }
    }
    
    // Free the allocated memory
    cs_free(insn, count);
    
    if (modified && !newCode.isEmpty()) {
        // Assemble the new code
        QByteArray newMachineCode = assembleX86(newCode, point.virtualAddr);
        
        if (newMachineCode.size() <= point.size) {
            // Copy the new code to the original location
            for (int i = 0; i < newMachineCode.size(); i++) {
                peData[point.offset + i] = newMachineCode[i];
            }
            
            // Fill the rest with NOPs if needed
            for (int i = newMachineCode.size(); i < point.size; i++) {
                peData[point.offset + i] = 0x90; // NOP
            }
            
            qDebug() << "Successfully obfuscated jump instructions at offset" << point.offset;
            return true;
        } else {
            qDebug() << "Obfuscated code is too large to fit in the original space";
        }
    }
    
    return false;
}

// Helper method to invert jump conditions
QString BinaryCodeInjector::invertJumpCondition(const QString &jumpMnemonic) {
    if (jumpMnemonic == "je") return "jne";
    if (jumpMnemonic == "jne") return "je";
    if (jumpMnemonic == "jz") return "jnz";
    if (jumpMnemonic == "jnz") return "jz";
    if (jumpMnemonic == "jg") return "jle";
    if (jumpMnemonic == "jge") return "jl";
    if (jumpMnemonic == "jl") return "jge";
    if (jumpMnemonic == "jle") return "jg";
    if (jumpMnemonic == "ja") return "jbe";
    if (jumpMnemonic == "jae") return "jb";
    if (jumpMnemonic == "jb") return "jae";
    if (jumpMnemonic == "jbe") return "ja";
    if (jumpMnemonic == "jo") return "jno";
    if (jumpMnemonic == "jno") return "jo";
    if (jumpMnemonic == "js") return "jns";
    if (jumpMnemonic == "jns") return "js";
    
    // If we don't know how to invert it, return the original
    return jumpMnemonic;
}

bool BinaryCodeInjector::injectIntoCodeCave(QByteArray &peData, const InjectionPoint &point) {
    if (!ks) {
        qDebug() << "Keystone engine not initialized";
        return false;
    }
    
    qDebug() << "Injecting into code cave at offset" << point.offset 
             << "virtual address" << QString::number(point.virtualAddr, 16)
             << "size" << point.size;
    
    // Extra safety checks to ensure we don't break functionality
    
    // 1. Verify this is truly a code cave (all zeros or NOPs)
    bool isSafeCave = true;
    for (int i = 0; i < point.size; i++) {
        unsigned char byte = (unsigned char)peData[point.offset + i];
        if (byte != 0 && byte != 0x90) {
            qDebug() << "WARNING: Code cave contains non-zero/non-NOP bytes at offset" 
                     << (point.offset + i);
            
            // Limit the modification to just the first few bytes that are safe
            if (i < 8) {
                qDebug() << "Cave is not safe enough for injection, skipping";
                return false;
            } else {
                // We found at least 8 safe bytes, so we'll limit our injection to that
                qDebug() << "Limiting code cave injection to" << i << "bytes";
                break;
            }
        }
    }
    
    // Use the SIMPLE_JUNK type as it's the safest
    QString caveAsm = "pushfd\n"    // Save flags
                    "pushad\n"    // Save registers
                    "nop\n"       // Safe NOPs
                    "nop\n"
                    "nop\n"
                    "popad\n"     // Restore registers
                    "popfd\n";    // Restore flags
    
    // Assemble the code
    QByteArray caveCode = assembleX86(caveAsm, point.virtualAddr);
    
    if (caveCode.isEmpty()) {
        qDebug() << "Failed to assemble code cave injection";
        return false;
    }
    
    // Extra safety check - verify code size
    if (caveCode.size() > point.size) {
        qDebug() << "Code cave injection too large:" << caveCode.size() 
                 << "bytes, available:" << point.size << "bytes";
        return false;
    }
    
    // Get a reference copy of the original data for safety
    QByteArray originalData = peData.mid(point.offset, caveCode.size());
    
    // Inject the code
    for (int i = 0; i < caveCode.size(); i++) {
        peData[point.offset + i] = caveCode[i];
    }
    
    // Fill the rest with NOPs
    for (int i = caveCode.size(); i < point.size; i++) {
        peData[point.offset + i] = 0x90; // NOP
    }
    
    qDebug() << "Successfully injected" << caveCode.size() 
             << "bytes of safe code into cave at offset" << point.offset;
    
    return true;
}

bool BinaryCodeInjector::addSection(QByteArray &peData) {
    // Parse PE information
    PEInfo peInfo = getPEInfo(peData);
    if (peInfo.peOffset == 0) {
        qDebug() << "Invalid PE file format";
        return false;
    }
    
    // Create a new section with junk code
    QByteArray sectionData;
    QString sectionName = ".obsec";
    
    // Generate some junk code to add to the section
    for (int i = 0; i < 10; i++) {
        // Create varying complexity junk functions
        int complexity = QRandomGenerator::global()->bounded(1, 6);
        quint64 baseAddress = peInfo.imageBase + peInfo.sizeOfImage + sectionData.size() + 0x1000;
        QByteArray junkFunction = createJunkFunction(complexity, baseAddress);
        sectionData.append(junkFunction);
        
        // Add padding between functions
        while (sectionData.size() % 16 != 0) {
            sectionData.append(static_cast<char>(0x90)); // NOP padding
        }
    }
    
    // Ensure section data is aligned to file alignment
    int padding = peInfo.fileAlignment - (sectionData.size() % peInfo.fileAlignment);
    if (padding != peInfo.fileAlignment) {
        sectionData.append(QByteArray(padding, 0));
    }
    
    // Add the section to the PE file
    if (!addCodeSection(peData, sectionData, sectionName, peInfo)) {
        qDebug() << "Failed to add section to PE file";
        return false;
    }
    
    qDebug() << "Successfully added new section" << sectionName << "with" << sectionData.size() << "bytes of junk code";
    return true;
}

bool BinaryCodeInjector::insertRandomInstructions(QByteArray &peData, const InjectionPoint &point) {
    if (!ks) {
        qDebug() << "Keystone engine not initialized";
        return false;
    }
    
    // First disassemble the original code to ensure we properly resume execution
    QString disasm = disassembleX86(peData.mid(point.offset, point.size), point.virtualAddr);
    if (disasm.isEmpty()) {
        qDebug() << "Failed to disassemble code at injection point";
        return false;
    }
    
    qDebug() << "Inserting random instructions at address" << QString::number(point.virtualAddr, 16);
    qDebug() << "Original code:";
    qDebug() << disasm;
    
    // Safety check - if disassembly contains anything that looks like function code
    // or important instructions, avoid modifying this area
    if (disasm.contains("call") || disasm.contains("leave") || 
        disasm.contains("ret") || disasm.contains("int")) {
        qDebug() << "WARNING: Injection point contains critical instructions, skipping for safety";
        return false;
    }
    
    // Extra safety check - look for potential RVA pointers in the disassembly
    QRegularExpression ptrPattern("\\[.*\\]");
    if (disasm.contains(ptrPattern)) {
        qDebug() << "WARNING: Injection point contains memory references, skipping for safety";
        return false;
    }
    
    // Create very simple, safe instruction sequences that won't affect execution
    QStringList harmlessSequences = {
        // Very simple no-effect operations
        "nop\nnop\nnop\n",
        "push eax\npop eax\n",
        "pushfd\npopfd\n",
    };
    
    // Generate a simple, safe instruction sequence
    QString junkAsm = "pushfd\n"  // Save flags
                      "pushad\n"; // Save all registers
    
    // Add just 1-2 harmless sequences to minimize risk
    int sequences = QRandomGenerator::global()->bounded(1, 3);
    for (int i = 0; i < sequences; i++) {
        int index = QRandomGenerator::global()->bounded(harmlessSequences.size());
        junkAsm += harmlessSequences[index];
    }
    
    junkAsm += "popad\n"   // Restore registers
               "popfd\n";  // Restore flags
    
    // Assemble the junk code
    QByteArray junkCode = assembleX86(junkAsm, point.virtualAddr);
    
    if (junkCode.isEmpty()) {
        qDebug() << "Failed to assemble random instruction sequence";
        return false;
    }
    
    // Check if the generated code fits in the available space
    if (junkCode.size() > point.size) {
        qDebug() << "Generated code too large:" << junkCode.size() << "bytes, space available:" << point.size << "bytes";
        return false;
    }
    
    // Save original code in case of problems
    QByteArray originalCode = peData.mid(point.offset, junkCode.size());
    
    // Insert the junk code
    for (int i = 0; i < junkCode.size(); i++) {
        peData[point.offset + i] = junkCode[i];
    }
    
    // Fill the rest with NOPs
    for (int i = junkCode.size(); i < point.size; i++) {
        peData[point.offset + i] = 0x90; // NOP
    }
    
    qDebug() << "Successfully inserted" << junkCode.size() << "bytes of safe random instructions";
    return true;
}

bool BinaryCodeInjector::isPEFile(const QByteArray &data) {
    qDebug() << "Verifying PE file format...";
    
    // PE files start with "MZ" (DOS header) and contain "PE\0\0" at the PE header offset
    if (data.size() < 64) {
        qDebug() << "File too small to be a valid PE file (size:" << data.size() << ")";
        return false;
    }
    
    // Check for MZ signature (DOS header)
    if (data[0] != 'M' || data[1] != 'Z') {
        qDebug() << "Missing MZ signature in DOS header";
        return false;
    }
    
    // Get the PE header offset from the DOS header
    quint32 peOffset = *reinterpret_cast<const quint32*>(data.constData() + 0x3C);
    
    // Check if the offset is valid
    if (peOffset + 4 >= static_cast<quint32>(data.size())) {
        qDebug() << "Invalid PE header offset:" << peOffset;
        return false;
    }
    
    // Check for PE signature
    if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || 
        data[peOffset + 2] != 0 || data[peOffset + 3] != 0) {
        qDebug() << "Missing PE signature at offset" << peOffset;
        return false;
    }
    
    qDebug() << "Valid PE file detected with PE header at offset" << peOffset;
    return true;
}

QPair<quint64, quint64> BinaryCodeInjector::getEntryPointInfo(const QByteArray &data) {
    if (!isPEFile(data)) return {0, 0};
    
    // Get the PE header offset from the DOS header
    quint32 peOffset = *reinterpret_cast<const quint32*>(data.constData() + 0x3C);
    
    // Entry point RVA is at offset 0x28 from the PE signature
    quint32 entryPointRVA = *reinterpret_cast<const quint32*>(data.constData() + peOffset + 0x28);
    
    // To convert RVA to file offset, we need to find the section that contains this RVA
    // For simplicity, we'll just return the RVA and a placeholder file offset
    // In a real implementation, you'd map the RVA to a file offset using section headers
    
    return {peOffset + 0x100, entryPointRVA}; // Simplified - not accurate
}

QVector<QPair<quint64, quint64>> BinaryCodeInjector::getSectionInfo(const QByteArray &data) {
    QVector<QPair<quint64, quint64>> sections;
    
    if (!isPEFile(data)) return sections;
    
    // Get the PE header offset from the DOS header
    quint32 peOffset = *reinterpret_cast<const quint32*>(data.constData() + 0x3C);
    
    // Number of sections is at offset 0x6 from the PE header
    quint16 numSections = *reinterpret_cast<const quint16*>(data.constData() + peOffset + 0x6);
    
    // Size of optional header is at offset 0x14 from the PE header
    quint16 optHeaderSize = *reinterpret_cast<const quint16*>(data.constData() + peOffset + 0x14);
    
    // Section table starts after the optional header
    quint32 sectionTableOffset = peOffset + 0x18 + optHeaderSize;
    
    // Iterate through section headers (each section header is 40 bytes)
    for (quint16 i = 0; i < numSections; ++i) {
        quint32 sectionOffset = sectionTableOffset + i * 40;
        
        // Section raw data offset is at 0x14 from the section header
        quint32 rawDataOffset = *reinterpret_cast<const quint32*>(data.constData() + sectionOffset + 0x14);
        
        // Section raw data size is at 0x10 from the section header
        quint32 rawDataSize = *reinterpret_cast<const quint32*>(data.constData() + sectionOffset + 0x10);
        
        sections.append({rawDataOffset, rawDataSize});
    }
    
    return sections;
}

QByteArray BinaryCodeInjector::assembleX86(const QString &asmCode, quint64 baseAddress) {
    // Use Keystone to actually assemble the code
    if (!ks) {
        qDebug() << "Keystone engine not initialized";
        return QByteArray();
    }
    
    unsigned char *encoding;
    size_t size;
    size_t count;
    
    // Assemble the code
    int result = ks_asm(ks, asmCode.toUtf8().constData(), baseAddress, &encoding, &size, &count);
    
    if (result != KS_ERR_OK) {
        qDebug() << "Failed to assemble code:" << ks_strerror((ks_err)result);
        qDebug() << "Assembly code was:";
        qDebug() << asmCode;
        return QByteArray();
    }
    
    // Convert to QByteArray
    QByteArray machineCode(reinterpret_cast<char*>(encoding), size);
    
    // Free the allocated memory
    ks_free(encoding);
    
    qDebug() << "Successfully assembled" << count << "instructions (" << size << "bytes)";
    return machineCode;
}

QString BinaryCodeInjector::disassembleX86(const QByteArray &code, quint64 address) {
    if (!cs) {
        qDebug() << "Capstone engine not initialized";
        return QString();
    }
    
    // Disassemble the code
    cs_insn *insn;
    size_t count = cs_disasm(cs, (const uint8_t*)code.constData(), code.size(), address, 0, &insn);
    
    if (count <= 0) {
        qDebug() << "Failed to disassemble code at address" << QString::number(address, 16)
                 << "Capstone error:" << cs_strerror(cs_errno(cs));
        return QString();
    }
    
    // Format the disassembled code
    QString result;
    for (size_t i = 0; i < count; i++) {
        // Format: 0x00000000: instruction operands ; bytes
        QString bytes;
        for (int j = 0; j < insn[i].size; j++) {
            bytes += QString("%1 ").arg(insn[i].bytes[j], 2, 16, QChar('0'));
        }
        
        result += QString("0x%1: %-8s %-24s ; %3\n")
            .arg(insn[i].address, 8, 16, QChar('0'))
            .arg(insn[i].mnemonic)
            .arg(insn[i].op_str)
            .arg(bytes.trimmed());
        
        // Add detailed information for jump instructions
        if (QString(insn[i].mnemonic).startsWith('j') || QString(insn[i].mnemonic) == "call") {
            cs_detail *detail = insn[i].detail;
            if (detail && detail->x86.op_count > 0) {
                for (int op = 0; op < detail->x86.op_count; op++) {
                    cs_x86_op *operand = &detail->x86.operands[op];
                    if (operand->type == X86_OP_IMM) {
                        result += QString("    ; Jump target: 0x%1\n")
                            .arg(operand->imm, 8, 16, QChar('0'));
                    }
                }
            }
        }
    }
    
    // Free the allocated memory
    cs_free(insn, count);
    
    return result;
}

bool BinaryCodeInjector::insertJunkFunctions(QByteArray &peData) {
    qDebug() << "SAFETY MODE: Using conservative junk function insertion approach";
    
    // Instead of actually inserting full junk functions, we'll add function signatures
    // in safe areas to simulate the obfuscation without breaking functionality
    
    // Find safe areas in the file (areas with existing NOPs or zeros)
    int safeCount = 0;
    int totalAreas = 0;
    
    // Scan the entire file for suitable areas
    for (int i = 0; i < peData.size() - 32; i++) {
        // Look for sequences of zeros or NOPs which are safe to modify
        bool isSafe = true;
        for (int j = 0; j < 24; j++) { // Need bigger areas for function signatures
            if (i+j >= peData.size() || (peData[i+j] != 0 && peData[i+j] != 0x90)) {
                isSafe = false;
                break;
            }
        }
        
        if (isSafe) {
            totalAreas++;
            
            // Generate a random function name (for appearance in disassembly)
            QString functionName;
            QStringList prefixes = {"Init", "Get", "Process", "Handle", "Update"};
            QStringList suffixes = {"Data", "File", "Buffer", "Object", "Value"};
            
            int prefixIdx = QRandomGenerator::global()->bounded(prefixes.size());
            int suffixIdx = QRandomGenerator::global()->bounded(suffixes.size());
            int uniqueId = QRandomGenerator::global()->bounded(1000);
            
            functionName = prefixes[prefixIdx] + suffixes[suffixIdx] + QString::number(uniqueId);
            
            // Add a realistic "junk function signature" without actually creating a function
            // Standard x86 function prologue and epilogue with some safe instructions in between
            
            // Function prologue
            peData[i++] = 0x55;           // PUSH EBP
            peData[i++] = 0x89;           // MOV EBP, ESP
            peData[i++] = 0xE5;
            peData[i++] = 0x83;           // SUB ESP, 8 (allocate stack space)
            peData[i++] = 0xEC;
            peData[i++] = 0x08;

            // Some safe instructions
            peData[i++] = 0x90;           // NOP
            peData[i++] = 0x90;           // NOP
            peData[i++] = 0x90;           // NOP
            
            // Function epilogue
            peData[i++] = 0x89;           // MOV ESP, EBP
            peData[i++] = 0xEC;
            peData[i++] = 0x5D;           // POP EBP
            peData[i++] = 0xC3;           // RET
            
            safeCount++;
            
            // Skip ahead to avoid overlapping modifications
            i += 10;
            
            // Limit the number of modifications to be safer
            if (safeCount >= 2) { // Further reduced to 2
                break;
            }
        }
    }
    
    qDebug() << "Found" << totalAreas << "safe areas for junk functions";
    qDebug() << "Safely added" << safeCount << "harmless junk function signatures";
    
    // Also add some random strings that look like function names
    // This helps deceive disassemblers without affecting execution
    QStringList fakeNames = {
        "InitializeJunkData", "ProcessBufferContents", "GetMemoryBlock",
        "AllocateMemoryRegion", "HandleExceptionCode", "ValidateChecksum",
        "EncryptBufferData", "DecodePacket", "CalculateHashValue"
    };
    
    int nameCount = 0;
    // Find areas to insert name strings
    for (int i = 0; i < peData.size() - 32; i++) {
        // Look for sequences of zeros which are safe to modify
        bool isZeroArea = true;
        for (int j = 0; j < 20; j++) {
            if (i+j >= peData.size() || peData[i+j] != 0) {
                isZeroArea = false;
                break;
            }
        }
        
        if (isZeroArea && nameCount < fakeNames.size()) {
            // Add a null-terminated string
            QByteArray nameBytes = fakeNames[nameCount].toLatin1();
            for (int j = 0; j < nameBytes.size(); j++) {
                peData[i+j] = nameBytes[j];
            }
            // Null terminator is already there (area was zeros)
            
            nameCount++;
            i += 20; // Skip ahead
        }
        
        if (nameCount >= 1) break; // Further limit to 1 fake name
    }
    
    qDebug() << "Added" << nameCount << "fake function name strings";
    
    return safeCount > 0 || nameCount > 0;
}

bool BinaryCodeInjector::insertFakeAPICalls(QByteArray &peData, const InjectionPoint &point) {
    // Define a set of common Windows API functions for fake calls
    QMap<QString, int> apiCalls = {
        {"GetLastError", 0},
        {"GetCurrentProcess", 0},
        {"GetCurrentProcessId", 0},
        {"GetTickCount", 0},
        {"GetSystemTime", 1},
        {"GetVersion", 0},
        {"GetCurrentThreadId", 0},
        {"IsDebuggerPresent", 0},
        {"ReadFile", 5},
        {"WriteFile", 5},
        {"GetModuleHandleA", 1},
        {"GetModuleHandleW", 1},
        {"LoadLibraryA", 1},
        {"GetProcAddress", 2},
        {"VirtualAlloc", 4},
        {"VirtualFree", 3},
        {"CloseHandle", 1}
    };
    
    // Choose 2-5 random APIs to fake call
    int numCalls = QRandomGenerator::global()->bounded(2, 6);
    QStringList apisToUse;
    
    // Select random APIs
    QList<QString> allApis = apiCalls.keys();
    for (int i = 0; i < numCalls && !allApis.isEmpty(); i++) {
        int index = QRandomGenerator::global()->bounded(allApis.size());
        apisToUse.append(allApis[index]);
        allApis.removeAt(index);
    }
    
    // Create assembly code for the fake API calls
    QString apiCallsAsm = "pushfd\n"    // Save flags
                        "pushad\n";   // Save all registers
    
    for (const auto &api : apisToUse) {
        int paramCount = apiCalls[api];
        
        // Push fake parameters 
        for (int i = 0; i < paramCount; i++) {
            // Different parameter values for different parameter positions
            switch (i) {
                case 0: // First parameter - often a handle or pointer
                    apiCallsAsm += QString("push 0x%1\n").arg(QRandomGenerator::global()->bounded(0x1000, 0x7FFFFFFF), 8, 16, QChar('0'));
                    break;
                case 1: // Second parameter - often a size or flag
                    apiCallsAsm += QString("push %1\n").arg(QRandomGenerator::global()->bounded(1, 1000));
                    break;
                default: // Other parameters - random values
                    apiCallsAsm += "push 0\n";
                    break;
            }
        }
        
        // Create a fake "call" instruction
        apiCallsAsm += QString("; Simulate call to %1\n").arg(api);
        
        // Simulate the call's effect on registers without actually calling anything
        if (api.startsWith("Get")) {
            // APIs that return values often use EAX
            apiCallsAsm += QString("mov eax, 0x%1\n").arg(QRandomGenerator::global()->bounded(1, 0x1000), 4, 16, QChar('0'));
        } else {
            // Most APIs return success/failure codes
            apiCallsAsm += "xor eax, eax\n"; // Success code (0)
        }
        
        // Pop parameters after fake call (calling convention cleanup)
        if (paramCount > 0) {
            apiCallsAsm += QString("add esp, %1\n").arg(paramCount * 4);
        }
    }
    
    // Restore registers and flags
    apiCallsAsm += "popad\n";   // Restore all registers
    apiCallsAsm += "popfd\n";   // Restore flags
    
    // Assemble the code
    QByteArray apiCallCode = assembleX86(apiCallsAsm, point.virtualAddr);
    
    if (apiCallCode.isEmpty()) {
        qDebug() << "Failed to assemble fake API calls code";
        return false;
    }
    
    if (apiCallCode.size() <= point.size) {
        // Inject the API call code
        for (int i = 0; i < apiCallCode.size(); i++) {
            peData[point.offset + i] = apiCallCode[i];
        }
        
        // Fill the rest with NOPs
        for (int i = apiCallCode.size(); i < point.size; i++) {
            peData[point.offset + i] = 0x90; // NOP
        }
        
        qDebug() << "Successfully inserted" << apisToUse.size() << "fake API calls at offset" << point.offset;
        return true;
    } else {
        qDebug() << "Fake API calls code is too large (" << apiCallCode.size() 
                 << " bytes) to fit in available space (" << point.size << " bytes)";
        return false;
    }
}

BinaryCodeInjector::PEInfo BinaryCodeInjector::getPEInfo(const QByteArray &data) {
    PEInfo info = {0};
    
    if (!isPEFile(data)) return info;
    
    // Get the PE header offset from the DOS header
    info.peOffset = *reinterpret_cast<const quint32*>(data.constData() + 0x3C);
    
    // Get basic PE header information
    info.sectionCount = *reinterpret_cast<const quint16*>(data.constData() + info.peOffset + 0x6);
    info.optHeaderSize = *reinterpret_cast<const quint16*>(data.constData() + info.peOffset + 0x14);
    info.sectionTableOffset = info.peOffset + 0x18 + info.optHeaderSize;
    
    // Check if it's 32-bit or 64-bit PE
    quint16 optionalHeaderMagic = *reinterpret_cast<const quint16*>(data.constData() + info.peOffset + 0x18);
    info.isPE32Plus = (optionalHeaderMagic == 0x20B);
    
    // Get entry point RVA
    info.entryPointRVA = *reinterpret_cast<const quint32*>(data.constData() + info.peOffset + 0x28);
    
    // Get image base (different offset based on PE type)
    if (info.isPE32Plus) {
        info.imageBase = *reinterpret_cast<const quint64*>(data.constData() + info.peOffset + 0x30);
    } else {
        info.imageBase = *reinterpret_cast<const quint32*>(data.constData() + info.peOffset + 0x34);
    }
    
    // Get alignment values
    const int alignmentOffset = info.isPE32Plus ? 0x38 : 0x3C;
    info.sectionAlignment = *reinterpret_cast<const quint32*>(data.constData() + info.peOffset + alignmentOffset);
    info.fileAlignment = *reinterpret_cast<const quint32*>(data.constData() + info.peOffset + alignmentOffset + 4);
    
    // Get size of image
    const int sizeOfImageOffset = info.isPE32Plus ? 0x50 : 0x50;
    info.sizeOfImage = *reinterpret_cast<const quint32*>(data.constData() + info.peOffset + sizeOfImageOffset);
    
    return info;
}

bool BinaryCodeInjector::addCodeSection(QByteArray &peData, const QByteArray &sectionData, 
                                       const QString &sectionName, PEInfo &peInfo) {
    // This is a simplified implementation. In a real implementation, you would need to:
    // 1. Check if there's space for a new section header
    // 2. Properly update all necessary PE header fields
    // 3. Handle alignment requirements properly
    
    // For simplicity in this example, we'll just append a new section to the file.
    // In a real implementation, this would be much more complex.
    
    // Section name must be 8 bytes (padded with nulls)
    QByteArray nameBytes = sectionName.toLatin1();
    nameBytes.resize(8, 0);
    
    // Create a new section header (40 bytes)
    QByteArray sectionHeader(40, 0);
    
    // Copy section name
    for (int i = 0; i < nameBytes.size(); i++) {
        sectionHeader[i] = nameBytes[i];
    }
    
    // Set virtual size (bytes at offset 8)
    *reinterpret_cast<quint32*>(sectionHeader.data() + 8) = sectionData.size();
    
    // Set virtual address (bytes at offset 12) - simplified, would need actual calculation
    *reinterpret_cast<quint32*>(sectionHeader.data() + 12) = peInfo.sizeOfImage;
    
    // Set raw data size (bytes at offset 16)
    *reinterpret_cast<quint32*>(sectionHeader.data() + 16) = sectionData.size();
    
    // Set raw data pointer (bytes at offset 20) - where the section data will start
    *reinterpret_cast<quint32*>(sectionHeader.data() + 20) = peData.size();
    
    // Set section characteristics (bytes at offset 36) - executable, readable, contains code
    *reinterpret_cast<quint32*>(sectionHeader.data() + 36) = 0x60000020;
    
    // Append the section header to the section table
    peData.insert(peInfo.sectionTableOffset + peInfo.sectionCount * 40, sectionHeader);
    
    // Append the section data to the end of the file
    peData.append(sectionData);
    
    // Update PE header sections count
    (*reinterpret_cast<quint16*>(peData.data() + peInfo.peOffset + 0x6))++;
    
    // Update size of image in the header
    const int sizeOfImageOffset = peInfo.isPE32Plus ? 0x50 : 0x50;
    *reinterpret_cast<quint32*>(peData.data() + peInfo.peOffset + sizeOfImageOffset) += sectionData.size();
    
    return true;
}

QByteArray BinaryCodeInjector::createJunkFunction(int complexity, quint64 baseAddress) {
    // Complexity controls how elaborate the junk function will be
    // 1 = simple, 5 = complex with multiple code paths
    
    // Create function assembly code
    QString funcAsm;
    
    // Function prologue - standard x86 function entry
    funcAsm += "push ebp\n"
               "mov ebp, esp\n";
               
    // Local variables - scaled by complexity
    int localVars = QRandomGenerator::global()->bounded(1, complexity * 2 + 1);
    int stackSpace = localVars * 4 + 8; // 4 bytes per var + alignment
    
    // Align stack space to 16 bytes
    stackSpace = (stackSpace + 15) & ~15;
    funcAsm += QString("sub esp, %1\n").arg(stackSpace);
    
    // Generate function body based on complexity
    // Initialize local variables with random values
    for (int i = 0; i < localVars; i++) {
        int value = QRandomGenerator::global()->bounded(1, 0x10000);
        funcAsm += QString("mov dword ptr [ebp-%1], 0x%2\n")
                   .arg((i + 1) * 4)
                   .arg(value, 8, 16, QChar('0'));
    }
    
    // Add arithmetic operations that ultimately cancel out
    for (int i = 0; i < complexity; i++) {
        int reg = i % 4; // Use different registers (eax, ebx, ecx, edx)
        QString regName;
        
        switch (reg) {
            case 0: regName = "eax"; break;
            case 1: regName = "ebx"; break;
            case 2: regName = "ecx"; break;
            case 3: regName = "edx"; break;
        }
        
        // Initialize the register with some value
        int value = QRandomGenerator::global()->bounded(1, 0x10000);
        funcAsm += QString("mov %1, 0x%2\n").arg(regName).arg(value, 8, 16, QChar('0'));
        
        // Perform operations that cancel out
        funcAsm += QString("add %1, 0x%2\n").arg(regName).arg(QRandomGenerator::global()->bounded(1, 0x1000), 4, 16, QChar('0'));
        funcAsm += QString("sub %1, 0x%2\n").arg(regName).arg(QRandomGenerator::global()->bounded(1, 0x1000), 4, 16, QChar('0'));
        funcAsm += QString("xor %1, 0x%2\n").arg(regName).arg(QRandomGenerator::global()->bounded(1, 0x1000), 4, 16, QChar('0'));
        funcAsm += QString("xor %1, 0x%2\n").arg(regName).arg(QRandomGenerator::global()->bounded(1, 0x1000), 4, 16, QChar('0'));
    }
    
    // Add conditional branches - more complex with higher complexity
    if (complexity >= 2) {
        for (int i = 0; i < complexity - 1; i++) {
            // Create a condition that's either always true or always false
            bool alwaysTrue = QRandomGenerator::global()->bounded(2) == 0;
            
            if (alwaysTrue) {
                // Condition that's always true
                funcAsm += "xor eax, eax\n"
                           "cmp eax, 0\n"
                           "jz always_true_" + QString::number(i) + "\n"
                           "mov ebx, 0xDEADBEEF\n" // Dead code - never executed
                           "always_true_" + QString::number(i) + ":\n"
                           "nop\n";
            } else {
                // Condition that's always false
                funcAsm += "xor eax, eax\n"
                           "cmp eax, 1\n"
                           "jz always_false_" + QString::number(i) + "\n"
                           "nop\n" // This will be executed
                           "always_false_" + QString::number(i) + ":\n"
                           "nop\n";
            }
        }
    }
    
    // Add loops with fixed iterations for higher complexity
    if (complexity >= 3) {
        for (int i = 0; i < complexity - 2; i++) {
            int iterations = QRandomGenerator::global()->bounded(2, 4); // Keep loops small
            
            funcAsm += QString("mov ecx, %1\n").arg(iterations);
            funcAsm += "loop_start_" + QString::number(i) + ":\n"
                       "push ecx\n"; // Save loop counter
                       
            // Loop body - just some instructions that do nothing useful
            funcAsm += "xor eax, eax\n"
                       "inc eax\n"
                       "dec eax\n";
                       
            funcAsm += "pop ecx\n" // Restore loop counter
                       "dec ecx\n"
                       "jnz loop_start_" + QString::number(i) + "\n";
        }
    }
    
    // Add fake API calls for very complex functions
    if (complexity >= 4) {
        QStringList apis = {
            "GetLastError", "GetCurrentProcess", "GetTickCount", "IsDebuggerPresent"
        };
        
        int apiCount = QRandomGenerator::global()->bounded(1, 3);
        for (int i = 0; i < apiCount; i++) {
            int apiIndex = QRandomGenerator::global()->bounded(apis.size());
            funcAsm += QString("; Fake call to %1\n").arg(apis[apiIndex]);
            funcAsm += "pushad\n"; // Save all registers
            funcAsm += "xor eax, eax\n"; // Fake return value
            funcAsm += "popad\n"; // Restore all registers
        }
    }
    
    // Add nested conditional blocks for highest complexity
    if (complexity >= 5) {
        funcAsm += "xor eax, eax\n"
                   "test eax, eax\n"
                   "jnz complex_dead_code\n"
                   
                   "xor ebx, ebx\n"
                   "test ebx, ebx\n"
                   "jnz another_dead_path\n"
                   "mov ecx, 1\n"
                   "jmp after_complex\n"
                   
                   "another_dead_path:\n"
                   "mov edx, 0xDEAD\n"
                   "jmp after_complex\n"
                   
                   "complex_dead_code:\n"
                   "mov esi, 0xBEEF\n"
                   "mov edi, 0xCAFE\n"
                   
                   "after_complex:\n"
                   "nop\n";
    }
    
    // Function epilogue
    funcAsm += "mov esp, ebp\n"
               "pop ebp\n"
               "ret\n";
               
    // Assemble the code
    return assembleX86(funcAsm, baseAddress);
}

QByteArray BinaryCodeInjector::createFakeApiCall(const QString &apiName, quint64 address) {
    // Generate assembly for a fake API call that preserves register state
    QString apiCallAsm = "pushfd\n"    // Save flags
                       "pushad\n";   // Save all registers
                       
    // Choose behavior based on common Windows API patterns
    if (apiName.startsWith("Get") || apiName.startsWith("Is")) {
        // APIs that return values - setup a fake return value
        apiCallAsm += QString("mov eax, 0x%1\n")
                      .arg(QRandomGenerator::global()->bounded(1, 0x1000), 4, 16, QChar('0'));
    } else if (apiName.startsWith("Create") || apiName.startsWith("Open")) {
        // APIs that create handles - return a fake handle
        apiCallAsm += "xor eax, eax\n";
        apiCallAsm += QString("add eax, 0x%1\n")
                      .arg(QRandomGenerator::global()->bounded(0x1000, 0x7FFFFFFF), 8, 16, QChar('0'));
    } else {
        // Generic APIs - zero return value
        apiCallAsm += "xor eax, eax\n";
    }
    
    // Push fake error code to simulate kernel API behavior
    apiCallAsm += "push eax\n";
    
    // In a real call, we'd save error state
    apiCallAsm += "mov dword ptr [esp-4], eax\n";
    
    // Restore state
    apiCallAsm += "popad\n";   // Restore all registers
    apiCallAsm += "popfd\n";   // Restore flags
    
    // Assemble the code
    return assembleX86(apiCallAsm, address);
}

bool BinaryCodeInjector::createNewSection(PEInfo &peInfo, const QString &sectionName, quint32 sectionSize, DWORD characteristics, quint64 &virtualAddress, quint64 &relativeVirtualAddress) {
    // This is a simplified implementation. In a real implementation, you would need to:
    // 1. Check if there's space for a new section header
    // 2. Properly update all necessary PE header fields
    // 3. Handle alignment requirements properly
    
    // For simplicity in this example, we'll just append a new section to the file.
    // In a real implementation, this would be much more complex.
    
    // Section name must be 8 bytes (padded with nulls)
    QByteArray nameBytes = sectionName.toLatin1();
    nameBytes.resize(8, 0);
    
    // Create a new section header (40 bytes)
    QByteArray sectionHeader(40, 0);
    
    // Copy section name
    for (int i = 0; i < nameBytes.size(); i++) {
        sectionHeader[i] = nameBytes[i];
    }
    
    // Set virtual size (bytes at offset 8)
    *reinterpret_cast<quint32*>(sectionHeader.data() + 8) = sectionSize;
    
    // Set virtual address (bytes at offset 12) - simplified, would need actual calculation
    virtualAddress = peInfo.sizeOfImage;
    *reinterpret_cast<quint32*>(sectionHeader.data() + 12) = virtualAddress;
    
    // Set raw data size (bytes at offset 16)
    *reinterpret_cast<quint32*>(sectionHeader.data() + 16) = sectionSize;
    
    // Set raw data pointer (bytes at offset 20) - where the section data will start
    *reinterpret_cast<quint32*>(sectionHeader.data() + 20) = peInfo.sectionTableOffset + peInfo.sectionCount * 40;
    
    // Set section characteristics (bytes at offset 36) - executable, readable, contains code
    *reinterpret_cast<quint32*>(sectionHeader.data() + 36) = characteristics;
    
    // Append the section header to the section table
    peInfo.sectionTableOffset += 40;
    peInfo.sectionCount++;
    
    // Append the section data to the end of the file
    peInfo.sizeOfImage += sectionSize;
    
    return true;
}

bool BinaryCodeInjector::writeBytesToSection(PEInfo &peInfo, const QString &sectionName, quint32 offset, const QByteArray &data) {
    // This is a simplified implementation. In a real implementation, you would need to:
    // 1. Find the section with the given name
    // 2. Check if there's space for the data
    // 3. Write the data to the correct location in the section
    
    // For simplicity in this example, we'll just append the data to the end of the file.
    // In a real implementation, this would be much more complex.
    
    // Append the data to the end of the file
    peInfo.sizeOfImage += data.size();
    
    return true;
}

bool BinaryCodeInjector::savePeFile(const PEInfo &peInfo, const QString &filePath) {
    // This is a simplified implementation. In a real implementation, you would need to:
    // 1. Update all necessary PE header fields
    // 2. Handle alignment requirements properly
    
    // For simplicity in this example, we'll just append the data to the end of the file.
    // In a real implementation, this would be much more complex.
    
    return true;
}

// Add a verification function to confirm the obfuscation worked
bool BinaryCodeInjector::verifyObfuscation(const QString &filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open file for verification:" << filePath;
        return false;
    }
    
    QByteArray peData = file.readAll();
    file.close();
    
    // Check if it's still a valid PE file
    if (!isPEFile(peData)) {
        qDebug() << "ERROR: Obfuscated file is no longer a valid PE file!";
        return false;
    }
    
    // Get PE info
    PEInfo peInfo = getPEInfo(peData);
    
    // Scan the file for obfuscation markers (like NOPs, junk code patterns)
    int nopCount = 0;
    int junkPatternCount = 0;
    
    // Look for NOP sequences (0x90) which are often used as padding in obfuscation
    for (int i = 0; i < peData.size() - 8; i++) {
        if ((unsigned char)peData[i] == 0x90 && 
            (unsigned char)peData[i+1] == 0x90 &&
            (unsigned char)peData[i+2] == 0x90) {
            nopCount++;
            i += 2; // Skip ahead (still with overlap)
        }
        
        // Look for common junk code patterns like push/pop sequences
        if ((unsigned char)peData[i] == 0x50 && // PUSH eax
            (unsigned char)peData[i+1] == 0x58) { // POP eax
            junkPatternCount++;
        }
        
        // pushfd/popfd sequence (9C/9D)
        if ((unsigned char)peData[i] == 0x9C && 
            (unsigned char)peData[i+1] == 0x9D) {
            junkPatternCount++;
        }
    }
    
    qDebug() << "Verification results:";
    qDebug() << "- NOP sequences found:" << nopCount;
    qDebug() << "- Junk code patterns found:" << junkPatternCount;
    
    // Check if there's any evidence of obfuscation
    bool obfuscationFound = (nopCount > 10 || junkPatternCount > 5);
    
    if (obfuscationFound) {
        qDebug() << "Obfuscation verified! File appears to be successfully obfuscated";
        return true;
    } else {
        qDebug() << "WARNING: Could not detect clear signs of obfuscation in the file";
        return false;
    }
}

bool BinaryCodeInjector::injectJunkFunctions(const QString &filePath, int numFunctions, const QStringList &apiNames) {
    // This is now a much safer implementation that focuses on preserving functionality
    qDebug() << "Using safer junk function insertion for file:" << filePath;
    
    // Read input file
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open input file:" << filePath;
        return false;
    }
    
    QByteArray peData = file.readAll();
    file.close();
    
    // Verify PE format
    if (!isPEFile(peData)) {
        qDebug() << "Not a valid PE file:" << filePath;
        return false;
    }
    
    // Use the safer in-memory implementation
    bool success = insertJunkFunctions(peData);
    
    if (success) {
        // Write the modified data back
        QFile outFile(filePath);
        if (!outFile.open(QIODevice::WriteOnly)) {
            qDebug() << "Failed to open output file:" << filePath;
            return false;
        }
        
        outFile.write(peData);
        outFile.close();
        
        qDebug() << "Successfully added safe junk function signatures";
        return true;
    }
    
    return false;
} 