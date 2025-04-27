#ifndef OBFUSCATIONWIDGET_H
#define OBFUSCATIONWIDGET_H

#include <QWidget>
#include <QLabel>
#include <QComboBox>
#include <QSlider>
#include <QPushButton>
#include <QCheckBox>
#include <QGroupBox>
#include <QListWidget>
#include <QLineEdit>
#include <QProgressBar>
#include <QFileDialog>
#include "binarycodeinjector.h"
#include "binaryobfuscator.h"

class ObfuscationWidget : public QWidget {
    Q_OBJECT

public:
    explicit ObfuscationWidget(QWidget *parent = nullptr);
    ~ObfuscationWidget();

public slots:
    void openFile(const QString &filePath);

signals:
    void fileProcessed(); // Signal emitted when a file is successfully processed

private slots:
    void browseFile();
    void processFile();
    void tryAgain();
    void saveSettings();
    void onObfuscationTypeChanged(int index);
    void browseInputFile();
    void browseOutputFile();
    void performObfuscation();
    void updateObfuscationStatus(const QString &message, int progress);

private:
    QLabel *selectLabel; // Для отображения имени выбранного файла
    QComboBox *typeCombo;
    QSlider *maxStringsSlider;
    QString currentFilePath;
    
    // OLLVM-specific UI components
    QGroupBox *ollvmGroup;
    QCheckBox *controlFlowCheck;
    QCheckBox *stringEncryptionCheck;
    QCheckBox *functionCallCheck;
    QCheckBox *bogusControlFlowCheck;
    
    // Executable obfuscation UI components
    QGroupBox *exeGroup;
    QListWidget *exeMethodsList;
    
    QLineEdit *inputFileEdit;
    QLineEdit *outputFileEdit;
    QPushButton *inputBrowseButton;
    QPushButton *outputBrowseButton;
    QPushButton *obfuscateButton;
    QProgressBar *progressBar;
    QLabel *statusLabel;
    
    // Obfuscation method checkboxes
    QCheckBox *jumpModificationCheckBox;
    QCheckBox *codeCaveCheckBox;
    QCheckBox *sectionAdditionCheckBox;
    QCheckBox *randomInstructionCheckBox;
    QCheckBox *junkFunctionCheckBox;
    QCheckBox *fakeApiCallsCheckBox;

    BinaryObfuscator *obfuscator;

    void setupUI();
    void setupConnections();
    QString getObfuscationLevel() const;
    bool obfuscateFile(const QString &inputPath, const QString &outputPath);
    bool obfuscateWithOLLVM(const QString &inputPath, const QString &outputPath);
    bool obfuscateExecutable(const QString &inputPath, const QString &outputPath);
    void updateUIForObfuscationType(int type);
    bool isExecutableFile(const QString &filePath);
};

#endif // OBFUSCATIONWIDGET_H
