#include "obfuscationwidget.h"
#include "filehistory.h"
#include "ollvmhandler.h"
#include "binaryobfuscator.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QSlider>
#include <QFileDialog>
#include <QStyle>
#include <QMessageBox>
#include <QSettings>
#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QGroupBox>
#include <QCheckBox>
#include <QListWidget>
#include <QFileInfo>
#include <QApplication>
#include <random>

ObfuscationWidget::ObfuscationWidget(QWidget *parent) : QWidget(parent) {
    setupUI();
    setupConnections();
    
    obfuscator = new BinaryObfuscator(this);
    connect(obfuscator, &BinaryObfuscator::progressUpdate, 
            this, &ObfuscationWidget::updateObfuscationStatus);
}

ObfuscationWidget::~ObfuscationWidget() {
    // Clean up resources if needed
}

void ObfuscationWidget::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(30, 30, 30, 30);
    mainLayout->setSpacing(20);

    // Title
    QLabel *titleLabel = new QLabel("Obfuscation");
    titleLabel->setObjectName("pageTitle");
    mainLayout->addWidget(titleLabel);

    // File selection section
    QHBoxLayout *fileLayout = new QHBoxLayout();
    
    selectLabel = new QLabel("No file selected");
    selectLabel->setObjectName("fileLabel");
    fileLayout->addWidget(selectLabel);
    
    QPushButton *browseButton = new QPushButton("Browse");
    browseButton->setObjectName("browseButton");
    fileLayout->addWidget(browseButton);
    
    mainLayout->addLayout(fileLayout);

    // Obfuscation type selection
    typeCombo = new QComboBox();
    typeCombo->addItems({"String Obfuscation", "OLLVM Obfuscation", "Executable Obfuscation"});
    mainLayout->addWidget(typeCombo);

    // Max strings slider - for string obfuscation
    QHBoxLayout *sliderLayout = new QHBoxLayout();
    QLabel *sliderLabel = new QLabel("Max Strings:");
    maxStringsSlider = new QSlider(Qt::Horizontal);
    maxStringsSlider->setRange(10, 100);
    maxStringsSlider->setValue(50);
    sliderLayout->addWidget(sliderLabel);
    sliderLayout->addWidget(maxStringsSlider);
    mainLayout->addLayout(sliderLayout);

    // OLLVM-specific options in a group box
    ollvmGroup = new QGroupBox("OLLVM Options");
    QVBoxLayout *ollvmLayout = new QVBoxLayout();
    
    controlFlowCheck = new QCheckBox("Control Flow Flattening");
    stringEncryptionCheck = new QCheckBox("String Encryption");
    functionCallCheck = new QCheckBox("Function Call Obfuscation");
    bogusControlFlowCheck = new QCheckBox("Bogus Control Flow");
    
    ollvmLayout->addWidget(controlFlowCheck);
    ollvmLayout->addWidget(stringEncryptionCheck);
    ollvmLayout->addWidget(functionCallCheck);
    ollvmLayout->addWidget(bogusControlFlowCheck);
    
    ollvmGroup->setLayout(ollvmLayout);
    mainLayout->addWidget(ollvmGroup);
    ollvmGroup->setVisible(false); // Hidden by default
    
    // Executable obfuscation options
    exeGroup = new QGroupBox("Executable Code Injection Methods");
    QVBoxLayout *exeLayout = new QVBoxLayout();
    
    QLabel *exeInfoLabel = new QLabel("Select code injection methods to apply:");
    exeMethodsList = new QListWidget();
    exeMethodsList->setSelectionMode(QAbstractItemView::MultiSelection);
    
    // Add injection methods
    QStringList methods = BinaryCodeInjector::getSupportedMethods();
    for (const auto &method : methods) {
        QListWidgetItem *item = new QListWidgetItem(method);
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
        item->setCheckState(Qt::Unchecked);
        exeMethodsList->addItem(item);
    }
    
    // Select default method
    if (exeMethodsList->count() > 0) {
        exeMethodsList->item(3)->setCheckState(Qt::Checked); // Random Instruction Insertion
    }
    
    exeLayout->addWidget(exeInfoLabel);
    exeLayout->addWidget(exeMethodsList);
    
    // Add explanations for each injection method
    QLabel *explanationLabel = new QLabel(
        "• Jump Modification: Replaces jump instructions with equivalent but more complex code\n"
        "• Code Cave Injection: Inserts junk code into unused spaces in the executable\n"
        "• New Section Addition: Adds a new section containing junk code\n"
        "• Random Instruction: Inserts harmless random instructions throughout the code\n"
        "• Junk Function: Adds fake functions that are never called to confuse analysis\n"
        "• Fake API Calls: Inserts harmless API call instructions that do nothing useful"
    );
    explanationLabel->setWordWrap(true);
    exeLayout->addWidget(explanationLabel);
    
    exeGroup->setLayout(exeLayout);
    mainLayout->addWidget(exeGroup);
    exeGroup->setVisible(false); // Hidden by default

    // File selection for new interface
    QGroupBox *fileGroup = new QGroupBox("File Selection");
    QVBoxLayout *fileBoxLayout = new QVBoxLayout();
    
    QHBoxLayout *inputLayout = new QHBoxLayout();
    QLabel *inputLabel = new QLabel("Input File:");
    inputFileEdit = new QLineEdit();
    inputFileEdit->setReadOnly(true);
    inputBrowseButton = new QPushButton("Browse");
    
    inputLayout->addWidget(inputLabel);
    inputLayout->addWidget(inputFileEdit);
    inputLayout->addWidget(inputBrowseButton);
    
    QHBoxLayout *outputLayout = new QHBoxLayout();
    QLabel *outputLabel = new QLabel("Output File:");
    outputFileEdit = new QLineEdit();
    outputBrowseButton = new QPushButton("Browse");
    
    outputLayout->addWidget(outputLabel);
    outputLayout->addWidget(outputFileEdit);
    outputLayout->addWidget(outputBrowseButton);
    
    fileBoxLayout->addLayout(inputLayout);
    fileBoxLayout->addLayout(outputLayout);
    
    fileGroup->setLayout(fileBoxLayout);
    mainLayout->addWidget(fileGroup);
    
    // Add checkboxes for each obfuscation method
    QGroupBox *methodsGroup = new QGroupBox("Obfuscation Methods");
    QVBoxLayout *methodsLayout = new QVBoxLayout();
    
    jumpModificationCheckBox = new QCheckBox("Jump Modification");
    codeCaveCheckBox = new QCheckBox("Code Cave Injection");
    sectionAdditionCheckBox = new QCheckBox("New Section Addition");
    randomInstructionCheckBox = new QCheckBox("Random Instruction Insertion");
    junkFunctionCheckBox = new QCheckBox("Junk Function Insertion");
    fakeApiCallsCheckBox = new QCheckBox("Fake API Call Insertion");
    
    // Set default checked state
    randomInstructionCheckBox->setChecked(true);
    junkFunctionCheckBox->setChecked(true);
    
    methodsLayout->addWidget(jumpModificationCheckBox);
    methodsLayout->addWidget(codeCaveCheckBox);
    methodsLayout->addWidget(sectionAdditionCheckBox);
    methodsLayout->addWidget(randomInstructionCheckBox);
    methodsLayout->addWidget(junkFunctionCheckBox);
    methodsLayout->addWidget(fakeApiCallsCheckBox);
    
    methodsGroup->setLayout(methodsLayout);
    mainLayout->addWidget(methodsGroup);
    
    // Progress display
    progressBar = new QProgressBar();
    progressBar->setRange(0, 100);
    progressBar->setValue(0);
    mainLayout->addWidget(progressBar);
    
    statusLabel = new QLabel("Ready");
    mainLayout->addWidget(statusLabel);
    
    // Obfuscate button
    obfuscateButton = new QPushButton("Obfuscate");
    obfuscateButton->setObjectName("obfuscateButton");
    mainLayout->addWidget(obfuscateButton);

    // Action buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    
    QPushButton *submitButton = new QPushButton("Submit");
    submitButton->setObjectName("submitButton");
    buttonLayout->addWidget(submitButton);
    
    QPushButton *tryAgainButton = new QPushButton("Try Again");
    tryAgainButton->setObjectName("tryAgainButton");
    buttonLayout->addWidget(tryAgainButton);
    
    mainLayout->addLayout(buttonLayout);
    mainLayout->addStretch();
    
    // Set initial UI state
    updateUIForObfuscationType(0);
}

void ObfuscationWidget::setupConnections() {
    connect(findChild<QPushButton*>("browseButton"), &QPushButton::clicked, this, &ObfuscationWidget::browseFile);
    connect(findChild<QPushButton*>("submitButton"), &QPushButton::clicked, this, &ObfuscationWidget::processFile);
    connect(findChild<QPushButton*>("tryAgainButton"), &QPushButton::clicked, this, &ObfuscationWidget::tryAgain);
    connect(typeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &ObfuscationWidget::onObfuscationTypeChanged);
    
    // Add connections for new UI elements
    connect(inputBrowseButton, &QPushButton::clicked, this, &ObfuscationWidget::browseInputFile);
    connect(outputBrowseButton, &QPushButton::clicked, this, &ObfuscationWidget::browseOutputFile);
    connect(obfuscateButton, &QPushButton::clicked, this, &ObfuscationWidget::performObfuscation);
}

void ObfuscationWidget::onObfuscationTypeChanged(int index) {
    updateUIForObfuscationType(index);
}

void ObfuscationWidget::updateUIForObfuscationType(int type) {
    // Show/hide UI elements based on selected obfuscation type
    bool isStringObfuscation = (type == 0);
    bool isOLLVMObfuscation = (type == 1);
    bool isExeObfuscation = (type == 2);
    
    maxStringsSlider->parentWidget()->setVisible(isStringObfuscation);
    ollvmGroup->setVisible(isOLLVMObfuscation);
    exeGroup->setVisible(isExeObfuscation);
    
    // Set defaults for OLLVM options
    if (isOLLVMObfuscation) {
        controlFlowCheck->setChecked(true);
        stringEncryptionCheck->setChecked(true);
        functionCallCheck->setChecked(false);
        bogusControlFlowCheck->setChecked(false);
    }
    
    // If we already have a file, check if it's valid for the selected obfuscation type
    if (!currentFilePath.isEmpty()) {
        bool isExeFile = isExecutableFile(currentFilePath);
        bool validFileForType = (isExeObfuscation && isExeFile) || 
                               (!isExeObfuscation && !isExeFile);
        
        if (!validFileForType) {
            // Show a warning if the file doesn't match the obfuscation type
            QMessageBox::warning(this, "File Type Mismatch",
                "The current file type doesn't match the selected obfuscation method. "
                "Please select a different file or change the obfuscation method.");
            
            // Reset the file selection
            currentFilePath.clear();
            selectLabel->setText("No file selected");
        }
    }
}

bool ObfuscationWidget::isExecutableFile(const QString &filePath) {
    if (filePath.isEmpty()) {
        return false;
    }
    
    // Check the file extension
    QFileInfo fileInfo(filePath);
    QString extension = fileInfo.suffix().toLower();
    
    return extension == "exe" || extension == "dll";
}

void ObfuscationWidget::browseFile() {
    int obfuscationType = typeCombo->currentIndex();
    QString filter;
    
    if (obfuscationType == 2) { // Executable Obfuscation
        filter = "Executable Files (*.exe *.dll);;All Files (*.*)";
    } else { // String or OLLVM Obfuscation
        filter = "C/C++ Files (*.c *.cpp *.h *.hpp);;All Files (*.*)";
    }
    
    QString fileName = QFileDialog::getOpenFileName(this,
        "Select File to Obfuscate", "", filter);
    
    if (!fileName.isEmpty()) {
        bool isExe = isExecutableFile(fileName);
        bool isExeType = (obfuscationType == 2);
        
        if (isExe && !isExeType) {
            QMessageBox::warning(this, "File Type Mismatch",
                "You've selected an executable file. Please switch to 'Executable Obfuscation' mode.");
            return;
        } else if (!isExe && isExeType) {
            QMessageBox::warning(this, "File Type Mismatch",
                "You've selected a non-executable file. Please select an .exe or .dll file.");
            return;
        }
        
        currentFilePath = fileName;
        selectLabel->setText(QFileInfo(fileName).fileName());
    }
}

void ObfuscationWidget::openFile(const QString &filePath) {
    if (QFile::exists(filePath)) {
        bool isExe = isExecutableFile(filePath);
        bool isExeType = (typeCombo->currentIndex() == 2);
        
        // Auto-switch to the appropriate mode based on file type
        if (isExe && !isExeType) {
            typeCombo->setCurrentIndex(2);
        } else if (!isExe && isExeType) {
            typeCombo->setCurrentIndex(0);
        }
        
        currentFilePath = filePath;
        selectLabel->setText(QFileInfo(filePath).fileName());
    } else {
        QMessageBox::warning(this, "Error", "File not found: " + filePath);
    }
}

QString ObfuscationWidget::getObfuscationLevel() const {
    QSettings settings;
    return settings.value("obfuscation/level", "Low").toString();
}

bool ObfuscationWidget::obfuscateFile(const QString &inputPath, const QString &outputPath) {
    int obfuscationType = typeCombo->currentIndex();
    
    if (obfuscationType == 1) { // OLLVM Obfuscation
        return obfuscateWithOLLVM(inputPath, outputPath);
    } else if (obfuscationType == 2) { // Executable Obfuscation
        return obfuscateExecutable(inputPath, outputPath);
    }
    
    // Original string obfuscation
    QFile inputFile(inputPath);
    if (!inputFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return false;
    }

    QFile outputFile(outputPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        inputFile.close();
        return false;
    }

    QTextStream in(&inputFile);
    QTextStream out(&outputFile);
    
    QString obfuscationLevel = getObfuscationLevel();
    int maxStrings = maxStringsSlider->value();
    
    QString content = in.readAll();
    
    // String obfuscation using regex iterator
    QRegularExpression stringPattern("\"[^\"]*\"");
    QRegularExpressionMatchIterator matchIterator = stringPattern.globalMatch(content);
    
    int stringCount = 0;
    QVector<QPair<int, int>> positions;
    QStringList replacements;
    
    // First collect all matches and calculate replacements
    while (matchIterator.hasNext() && stringCount < maxStrings) {
        QRegularExpressionMatch match = matchIterator.next();
        QString str = match.captured();
        QString obfuscated = "QString::fromUtf8(QByteArray::fromBase64(\"" + 
                           str.toUtf8().toBase64() + "\"))";
        
        positions.append(qMakePair(match.capturedStart(), match.capturedLength()));
        replacements.append(obfuscated);
        stringCount++;
    }
    
    // Apply replacements in reverse order to avoid invalidating positions
    for (int i = positions.size() - 1; i >= 0; --i) {
        int pos = positions[i].first;
        int len = positions[i].second;
        content.replace(pos, len, replacements[i]);
    }
    
    out << content;
    
    inputFile.close();
    outputFile.close();
    return true;
}

bool ObfuscationWidget::obfuscateWithOLLVM(const QString &inputPath, const QString &outputPath) {
    // Check if OLLVM is available
    if (!OLLVMHandler::isAvailable()) {
        if (!QMessageBox::question(this, "OLLVM Setup",
                                 "OLLVM needs to be set up for first use. Continue?",
                                 QMessageBox::Yes | QMessageBox::No,
                                 QMessageBox::Yes) == QMessageBox::Yes) {
            return false;
        }
    }
    
    // Calculate flags based on selected options
    int flags = 0;
    if (controlFlowCheck->isChecked()) {
        flags |= OLLVMHandler::CONTROL_FLOW;
    }
    if (stringEncryptionCheck->isChecked()) {
        flags |= OLLVMHandler::STRING_ENCRYPTION;
    }
    if (functionCallCheck->isChecked()) {
        flags |= OLLVMHandler::FUNCTION_CALL;
    }
    if (bogusControlFlowCheck->isChecked()) {
        flags |= OLLVMHandler::BOGUS_CONTROL_FLOW;
    }
    
    // If no flags are selected, use default CONTROL_FLOW flag
    if (flags == 0) {
        flags = OLLVMHandler::CONTROL_FLOW;
    }
    
    // Call OLLVM handler to obfuscate the file
    return OLLVMHandler::obfuscateFile(inputPath, outputPath, flags);
}

bool ObfuscationWidget::obfuscateExecutable(const QString &inputPath, const QString &outputPath) {
    // Check if binary obfuscator is available
    if (!BinaryObfuscator::isAvailable()) {
        QMessageBox::StandardButton button = QMessageBox::question(this, "Binary Obfuscator Setup",
                             "Binary code injection tools need to be set up for first use. Continue?",
                             QMessageBox::Yes | QMessageBox::No,
                             QMessageBox::Yes);
                             
        if (button != QMessageBox::Yes) {
            return false;
        }
    }
    
    // Get selected methods
    QList<BinaryCodeInjector::InjectionType> methods;
    
    for (int i = 0; i < exeMethodsList->count(); ++i) {
        QListWidgetItem *item = exeMethodsList->item(i);
        if (item->checkState() == Qt::Checked) {
            methods.append(static_cast<BinaryCodeInjector::InjectionType>(i));
        }
    }
    
    // If no methods are selected, select random instruction insertion by default
    if (methods.isEmpty()) {
        methods.append(BinaryCodeInjector::RANDOM_INSTRUCTION);
    }
    
    // Apply binary obfuscation
    BinaryObfuscator obfuscator;
    return obfuscator.obfuscateExe(inputPath, outputPath, methods);
}

void ObfuscationWidget::processFile() {
    if (currentFilePath.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please select a file first.");
        return;
    }

    QString outputPath = currentFilePath + ".obfuscated";
    
    // Add extension for exe files
    if (isExecutableFile(currentFilePath) && typeCombo->currentIndex() == 2) {
        QFileInfo fileInfo(currentFilePath);
        outputPath = fileInfo.absolutePath() + "/" + fileInfo.completeBaseName() + "_protected." + fileInfo.suffix();
    }
    
    if (obfuscateFile(currentFilePath, outputPath)) {
        // Add to file history
        FileHistory::addEntry(currentFilePath, getObfuscationLevel(), "Obfuscation");
        
        QMessageBox::information(this, "Success", 
            "File obfuscated successfully!\nSaved as: " + outputPath);
            
        // Emit signal that file was processed
        emit fileProcessed();
    } else {
        QMessageBox::critical(this, "Error", 
            "Failed to obfuscate file. Please check file permissions or try a different method.");
    }
}

void ObfuscationWidget::tryAgain() {
    currentFilePath.clear();
    selectLabel->setText("No file selected");
    typeCombo->setCurrentIndex(0);
    maxStringsSlider->setValue(50);
    
    // Reset executable protection options
    for (int i = 0; i < exeMethodsList->count(); ++i) {
        exeMethodsList->item(i)->setCheckState(i == 0 ? Qt::Checked : Qt::Unchecked);
    }
}

void ObfuscationWidget::saveSettings() {
    QSettings settings;
    settings.setValue("obfuscation/type", typeCombo->currentText());
    settings.setValue("obfuscation/maxStrings", maxStringsSlider->value());
}

void ObfuscationWidget::browseInputFile() {
    QString filter = "Executable Files (*.exe *.dll);;All Files (*.*)";
    
    QString fileName = QFileDialog::getOpenFileName(this,
        "Select Input File", "", filter);
    
    if (!fileName.isEmpty()) {
        inputFileEdit->setText(fileName);
        
        // Auto-generate output filename
        QFileInfo fileInfo(fileName);
        QString outputPath = fileInfo.absolutePath() + "/" + fileInfo.completeBaseName() + "_protected." + fileInfo.suffix();
        outputFileEdit->setText(outputPath);
    }
}

void ObfuscationWidget::browseOutputFile() {
    QString filter = "Executable Files (*.exe *.dll);;All Files (*.*)";
    
    QString fileName = QFileDialog::getSaveFileName(this,
        "Select Output File", outputFileEdit->text(), filter);
    
    if (!fileName.isEmpty()) {
        outputFileEdit->setText(fileName);
    }
}

void ObfuscationWidget::performObfuscation() {
    QString inputFile = inputFileEdit->text();
    QString outputFile = outputFileEdit->text();
    
    if (inputFile.isEmpty() || outputFile.isEmpty()) {
        QMessageBox::warning(this, "Error", "Please select both input and output files.");
        return;
    }
    
    // Collect selected methods
    QList<BinaryCodeInjector::InjectionType> methods;
    
    if (jumpModificationCheckBox->isChecked())
        methods.append(BinaryCodeInjector::JUMP_MODIFICATION);
    if (codeCaveCheckBox->isChecked())
        methods.append(BinaryCodeInjector::CODE_CAVE_INJECTION);
    if (sectionAdditionCheckBox->isChecked())
        methods.append(BinaryCodeInjector::SECTION_ADDITION);
    if (randomInstructionCheckBox->isChecked())
        methods.append(BinaryCodeInjector::RANDOM_INSTRUCTION);
    if (junkFunctionCheckBox->isChecked())
        methods.append(BinaryCodeInjector::JUNK_FUNCTION);
    if (fakeApiCallsCheckBox->isChecked())
        methods.append(BinaryCodeInjector::FAKE_API_CALLS);
    
    // If no methods selected, use default
    if (methods.isEmpty()) {
        methods.append(BinaryCodeInjector::RANDOM_INSTRUCTION);
        methods.append(BinaryCodeInjector::JUNK_FUNCTION);
    }
    
    // Update UI
    progressBar->setValue(0);
    statusLabel->setText("Starting obfuscation...");
    obfuscateButton->setEnabled(false);
    
    // Perform obfuscation in a separate thread
    QApplication::processEvents();
    
    bool success = obfuscator->obfuscateExe(inputFile, outputFile, methods);
    
    // Re-enable UI
    obfuscateButton->setEnabled(true);
    
    if (success) {
        // Add to file history
        FileHistory::addEntry(inputFile, getObfuscationLevel(), "Obfuscation");
        
        QMessageBox::information(this, "Success", 
            "File obfuscated successfully!\nSaved as: " + outputFile);
            
        // Emit signal that file was processed
        emit fileProcessed();
    } else {
        QMessageBox::critical(this, "Error", 
            "Failed to obfuscate file. Please check file permissions or try a different method.");
    }
}

void ObfuscationWidget::updateObfuscationStatus(const QString &message, int progress) {
    statusLabel->setText(message);
    progressBar->setValue(progress);
    QApplication::processEvents();
}
