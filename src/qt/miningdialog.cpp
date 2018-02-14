// Copyright (c) 2018 The Luxcore Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdio.h>
#include <cuda_runtime_api.h>
#include <cuda.h>
#include "miningdialog.h"
#include "guiutil.h"
#include "ui_miningdialog.h"

#include "transactiontablemodel.h"

#include <QModelIndex>
#include <QSettings>
#include <QString>
#include <QProcess>
#include <QCloseEvent>
#include <QMainWindow>
#include <QFontDatabase>
#include <QTextBlockFormat>



void MiningDialog::closeEvent (QCloseEvent *event)
{
    QMessageBox::StandardButton resBtn = QMessageBox::question( this, "Exit Mining",
                                                                tr("Are you sure?\n"),
                                                                QMessageBox::Cancel | QMessageBox::No | QMessageBox::Yes,
                                                                QMessageBox::Yes);
    if (resBtn != QMessageBox::Yes) {
        event->ignore();
    } else {
        if(minerLogProcess) {
            minerLogProcess->deleteLater();
            minerLogProcess = NULL;
        }
        ui->textBrowser->setText("");
        event->accept();

    }
}

MiningDialog::MiningDialog(QWidget* parent) : QMainWindow(parent),
                                              ui(new Ui::MiningDialog),
                                              m_NeverShown(true),
                                              m_HistoryIndex(0)
{
    ui->setupUi(this);
    ui->stopButton->setEnabled(false);

    /* Open CSS when configured */
    this->setStyleSheet(GUIUtil::loadStyleSheet());

    ui->textBrowser->setStyleSheet("background-color: black;");
   // ui->textBrowser->setTextColor( QColor( "red" ) );

    ui->poolComboBox->addItem(tr("pool.luxcore.com.au:3033"));
    ui->poolComboBox->addItem(tr("eu1.altminer.net:6667"));    
    ui->poolComboBox->addItem(tr("yiimp.eu:8333"));
    ui->poolComboBox->addItem(tr("omegapool.cc:8003"));
    ui->poolComboBox->addItem(tr("pickaxe.pro:8333"));
    ui->poolComboBox->addItem(tr("pool.ionik.fr:8333"));                                              
    ui->poolComboBox->addItem(tr("phi.mine.zpool.ca:8333"));
    ui->poolComboBox->addItem(tr("mine.zergpool.com:8333"));
    ui->poolComboBox->addItem(tr("eu1.unimining.net:8533"));
    ui->poolComboBox->setCurrentIndex(0);

    connect(ui->benchmarkButton, SIGNAL(clicked()), this, SLOT(run_benchmark()));
    connect(ui->startButton, SIGNAL(clicked()), this, SLOT(run_mining()));
    connect(ui->stopButton, SIGNAL(clicked()), this, SLOT(stop_mining()));

    //QString desc = "Tra la la";//idx.data(TransactionTableModel::LongDescriptionRole).toString();
    //ui->detailText->setHtml(desc);
}

void MiningDialog::run_benchmark()
{

    /*const int ARRAY_SIZE = 96;
    const int ARRAY_BYTES = ARRAY_SIZE * sizeof(float);

    // generate the input array on the host
    float h_in[ARRAY_SIZE];
    for (int i = 0; i < ARRAY_SIZE; i++) {
        h_in[i] = float(i);
    }
    float h_out[ARRAY_SIZE];

    // declare GPU memory pointers
    float * d_in;
    float * d_out;

    // allocate GPU memory
    cudaMalloc((void**) &d_in, ARRAY_BYTES);
    cudaMalloc((void**) &d_out, ARRAY_BYTES);

    // transfer the array to the GPU
    cudaMemcpy(d_in, h_in, ARRAY_BYTES, cudaMemcpyHostToDevice);

    // launch the kernel
    /*cube<<<1, ARRAY_SIZE>>>(d_out, d_in);

    // copy back the result array to the CPU
    cudaMemcpy(h_out, d_out, ARRAY_BYTES, cudaMemcpyDeviceToHost);

    // print out the resulting array
    for (int i =0; i < ARRAY_SIZE; i++) {
        printf("%f", h_out[i]);
        printf(((i % 4) != 3) ? "\t" : "\n");
    }

    cudaFree(d_in);
    cudaFree(d_out);

    cudaDeviceReset();*/


    int nDevices;

    cudaGetDeviceCount(&nDevices);
    for (int i = 0; i < nDevices; i++) {
        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, i);
        printf("Device Number: %d\n", i);
        printf("  Device name: %s\n", prop.name);
        printf("  Memory Clock Rate (KHz): %d\n",
               prop.memoryClockRate);
        printf("  Memory Bus Width (bits): %d\n",
               prop.memoryBusWidth);
        printf("  Peak Memory Bandwidth (GB/s): %f\n\n",
               2.0 * prop.memoryClockRate * (prop.memoryBusWidth / 8) / 1.0e6);
    }


    if(minerLogProcess) {
        minerLogProcess->deleteLater();
        minerLogProcess = NULL;
    }
    printf("I PRESSED\n");
    minerLogProcess = new QProcess(this);
    connect(minerLogProcess, SIGNAL(readyReadStandardOutput()),
            this, SLOT( ReadOut() ));
    connect(minerLogProcess, SIGNAL(readyReadStandardError()),
            this, SLOT( ReadErr() ));
    minerLogProcess->start("ccminer",QStringList() << "--benchmark");

    // For debugging: Wait until the process has finished.
    //minerLogProcess->waitForFinished();


    //QProcess sh;
    //sh.start("sh");

    //sh.start("ccminer",QStringList() << "--benchmark");
    //sh.closeWriteChannel();

    //sh.waitForStarted();
    //QByteArray output = sh.readAll();
    //sh.close();
    //connect( &sh, SIGNAL(readyReadStandardOutput()), this, SLOT(ReadOut()) );
    //connect( &sh, SIGNAL(readyReadStandardError()), this, SLOT(ReadErr()) );
    //printf("%s \n", output.data());
}


void MiningDialog::run_mining()
{
    ui->startButton->setEnabled(false);
    ui->stopButton->setEnabled(true);

    printf("I PRESSED\n");
    minerLogProcess = new QProcess(this);
    connect(minerLogProcess, SIGNAL(readyReadStandardOutput()),
            this, SLOT(ReadOut()));
    connect(minerLogProcess, SIGNAL(readyReadStandardError()),
            this, SLOT(ReadErr()));
    minerLogProcess->start("src/qt/start.sh");

}

void MiningDialog::stop_mining()
{
    ui->stopButton->setEnabled(false);
    ui->startButton->setEnabled(true);
    printf("I PRESSED\n");
    if(minerLogProcess) {
        minerLogProcess->deleteLater();
        minerLogProcess = NULL;
    }

}

void MiningDialog::ReadOut()
{
    QProcess *p = dynamic_cast<QProcess *>( sender() );
    printf("LALALALALALALALALA\n");
    if (p) {
        //ui->textBrowser->append(p->readAllStandardOutput());
        setTextTermFormatting(ui->textBrowser, p->readAllStandardOutput());
    }
}

void MiningDialog::ReadErr()
{
    QProcess *p = dynamic_cast<QProcess *>( sender() );

    if (p) {
        ui->textBrowser->append("ERROR: ");
        //ui->textBrowser->append(p->readAllStandardError());
        setTextTermFormatting(ui->textBrowser, p->readAllStandardError());
    }
    printf("LALALALALALALALALA54354353\n");
}


MiningDialog::~MiningDialog()
{
    delete ui;
}

void MiningDialog::parseEscapeSequence(int attribute, QListIterator< QString > & i, QTextCharFormat & textCharFormat, QTextCharFormat const & defaultTextCharFormat)
{
    switch (attribute) {
        case 0 : { // Normal/Default (reset all attributes)
            textCharFormat = defaultTextCharFormat;
            break;
        }
        case 1 : { // Bold/Bright (bold or increased intensity)
            textCharFormat.setFontWeight(QFont::Bold);
            break;
        }
        case 2 : { // Dim/Faint (decreased intensity)
            textCharFormat.setFontWeight(QFont::Light);
            break;
        }
        case 3 : { // Italicized (italic on)
            textCharFormat.setFontItalic(true);
            break;
        }
        case 4 : { // Underscore (single underlined)
            textCharFormat.setUnderlineStyle(QTextCharFormat::SingleUnderline);
            textCharFormat.setFontUnderline(true);
            break;
        }
        case 5 : { // Blink (slow, appears as Bold)
            textCharFormat.setFontWeight(QFont::Bold);
            break;
        }
        case 6 : { // Blink (rapid, appears as very Bold)
            textCharFormat.setFontWeight(QFont::Black);
            break;
        }
        case 7 : { // Reverse/Inverse (swap foreground and background)
            QBrush foregroundBrush = textCharFormat.foreground();
            textCharFormat.setForeground(textCharFormat.background());
            textCharFormat.setBackground(foregroundBrush);
            break;
        }
        case 8 : { // Concealed/Hidden/Invisible (usefull for passwords)
            textCharFormat.setForeground(textCharFormat.background());
            break;
        }
        case 9 : { // Crossed-out characters
            textCharFormat.setFontStrikeOut(true);
            break;
        }
        case 10 : { // Primary (default) font
            textCharFormat.setFont(defaultTextCharFormat.font());
            break;
        }
        case 11 ... 19 : {
            QFontDatabase fontDatabase;
            QString fontFamily = textCharFormat.fontFamily();
            QStringList fontStyles = fontDatabase.styles(fontFamily);
            int fontStyleIndex = attribute - 11;
            if (fontStyleIndex < fontStyles.length()) {
                textCharFormat.setFont(fontDatabase.font(fontFamily, fontStyles.at(fontStyleIndex), textCharFormat.font().pointSize()));
            }
            break;
        }
        case 20 : { // Fraktur (unsupported)
            break;
        }
        case 21 : { // Set Bold off
            textCharFormat.setFontWeight(QFont::Normal);
            break;
        }
        case 22 : { // Set Dim off
            textCharFormat.setFontWeight(QFont::Normal);
            break;
        }
        case 23 : { // Unset italic and unset fraktur
            textCharFormat.setFontItalic(false);
            break;
        }
        case 24 : { // Unset underlining
            textCharFormat.setUnderlineStyle(QTextCharFormat::NoUnderline);
            textCharFormat.setFontUnderline(false);
            break;
        }
        case 25 : { // Unset Blink/Bold
            textCharFormat.setFontWeight(QFont::Normal);
            break;
        }
        case 26 : { // Reserved
            break;
        }
        case 27 : { // Positive (non-inverted)
            QBrush backgroundBrush = textCharFormat.background();
            textCharFormat.setBackground(textCharFormat.foreground());
            textCharFormat.setForeground(backgroundBrush);
            break;
        }
        case 28 : {
            textCharFormat.setForeground(defaultTextCharFormat.foreground());
            textCharFormat.setBackground(defaultTextCharFormat.background());
            break;
        }
        case 29 : {
            textCharFormat.setUnderlineStyle(QTextCharFormat::NoUnderline);
            textCharFormat.setFontUnderline(false);
            break;
        }
        case 30 ... 37 : {
            int colorIndex = attribute - 30;
            QColor color;
            if (QFont::Normal < textCharFormat.fontWeight()) {
                switch (colorIndex) {
                    case 0 : {
                        color = Qt::darkGray;
                        break;
                    }
                    case 1 : {
                        color = Qt::red;
                        break;
                    }
                    case 2 : {
                        color = Qt::green;
                        break;
                    }
                    case 3 : {
                        color = Qt::yellow;
                        break;
                    }
                    case 4 : {
                        color = Qt::blue;
                        break;
                    }
                    case 5 : {
                        color = Qt::magenta;
                        break;
                    }
                    case 6 : {
                        color = Qt::cyan;
                        break;
                    }
                    case 7 : {
                        color = Qt::white;
                        break;
                    }
                    default : {
                        Q_ASSERT(false);
                    }
                }
            } else {
                switch (colorIndex) {
                    case 0 : {
                        color = Qt::black;
                        break;
                    }
                    case 1 : {
                        color = Qt::darkRed;
                        break;
                    }
                    case 2 : {
                        color = Qt::darkGreen;
                        break;
                    }
                    case 3 : {
                        color = Qt::darkYellow;
                        break;
                    }
                    case 4 : {
                        color = Qt::darkBlue;
                        break;
                    }
                    case 5 : {
                        color = Qt::darkMagenta;
                        break;
                    }
                    case 6 : {
                        color = Qt::darkCyan;
                        break;
                    }
                    case 7 : {
                        color = Qt::lightGray;
                        break;
                    }
                    default : {
                        Q_ASSERT(false);
                    }
                }
            }
            textCharFormat.setForeground(color);
            break;
        }
        case 38 : {
            if (i.hasNext()) {
                bool ok = false;
                int selector = i.next().toInt(&ok);
                Q_ASSERT(ok);
                QColor color;
                switch (selector) {
                    case 2 : {
                        if (!i.hasNext()) {
                            break;
                        }
                        int red = i.next().toInt(&ok);
                        Q_ASSERT(ok);
                        if (!i.hasNext()) {
                            break;
                        }
                        int green = i.next().toInt(&ok);
                        Q_ASSERT(ok);
                        if (!i.hasNext()) {
                            break;
                        }
                        int blue = i.next().toInt(&ok);
                        Q_ASSERT(ok);
                        color.setRgb(red, green, blue);
                        break;
                    }
                    case 5 : {
                        if (!i.hasNext()) {
                            break;
                        }
                        int index = i.next().toInt(&ok);
                        Q_ASSERT(ok);
                        switch (index) {
                            case 0x00 ... 0x07 : { // 0x00-0x07:  standard colors (as in ESC [ 30..37 m)
                                return parseEscapeSequence(index - 0x00 + 30, i, textCharFormat, defaultTextCharFormat);
                            }
                            case 0x08 ... 0x0F : { // 0x08-0x0F:  high intensity colors (as in ESC [ 90..97 m)
                                return parseEscapeSequence(index - 0x08 + 90, i, textCharFormat, defaultTextCharFormat);
                            }
                            case 0x10 ... 0xE7 : { // 0x10-0xE7:  6*6*6=216 colors: 16 + 36*r + 6*g + b (0≤r,g,b≤5)
                                index -= 0x10;
                                int red = index % 6;
                                index /= 6;
                                int green = index % 6;
                                index /= 6;
                                int blue = index % 6;
                                index /= 6;
                                Q_ASSERT(index == 0);
                                color.setRgb(red, green, blue);
                                break;
                            }
                            case 0xE8 ... 0xFF : { // 0xE8-0xFF:  grayscale from black to white in 24 steps
                                qreal intensity = qreal(index - 0xE8) / (0xFF - 0xE8);
                                color.setRgbF(intensity, intensity, intensity);
                                break;
                            }
                        }
                        textCharFormat.setForeground(color);
                        break;
                    }
                    default : {
                        break;
                    }
                }
            }
            break;
        }
        case 39 : {
            textCharFormat.setForeground(defaultTextCharFormat.foreground());
            break;
        }
        case 40 ... 47 : {
            int colorIndex = attribute - 40;
            QColor color;
            switch (colorIndex) {
                case 0 : {
                    color = Qt::darkGray;
                    break;
                }
                case 1 : {
                    color = Qt::red;
                    break;
                }
                case 2 : {
                    color = Qt::green;
                    break;
                }
                case 3 : {
                    color = Qt::yellow;
                    break;
                }
                case 4 : {
                    color = Qt::blue;
                    break;
                }
                case 5 : {
                    color = Qt::magenta;
                    break;
                }
                case 6 : {
                    color = Qt::cyan;
                    break;
                }
                case 7 : {
                    color = Qt::white;
                    break;
                }
                default : {
                    Q_ASSERT(false);
                }
            }
            textCharFormat.setBackground(color);
            break;
        }
        case 48 : {
            if (i.hasNext()) {
                bool ok = false;
                int selector = i.next().toInt(&ok);
                Q_ASSERT(ok);
                QColor color;
                switch (selector) {
                    case 2 : {
                        if (!i.hasNext()) {
                            break;
                        }
                        int red = i.next().toInt(&ok);
                        Q_ASSERT(ok);
                        if (!i.hasNext()) {
                            break;
                        }
                        int green = i.next().toInt(&ok);
                        Q_ASSERT(ok);
                        if (!i.hasNext()) {
                            break;
                        }
                        int blue = i.next().toInt(&ok);
                        Q_ASSERT(ok);
                        color.setRgb(red, green, blue);
                        break;
                    }
                    case 5 : {
                        if (!i.hasNext()) {
                            break;
                        }
                        int index = i.next().toInt(&ok);
                        Q_ASSERT(ok);
                        switch (index) {
                            case 0x00 ... 0x07 : { // 0x00-0x07:  standard colors (as in ESC [ 40..47 m)
                                return parseEscapeSequence(index - 0x00 + 40, i, textCharFormat, defaultTextCharFormat);
                            }
                            case 0x08 ... 0x0F : { // 0x08-0x0F:  high intensity colors (as in ESC [ 100..107 m)
                                return parseEscapeSequence(index - 0x08 + 100, i, textCharFormat, defaultTextCharFormat);
                            }
                            case 0x10 ... 0xE7 : { // 0x10-0xE7:  6*6*6=216 colors: 16 + 36*r + 6*g + b (0≤r,g,b≤5)
                                index -= 0x10;
                                int red = index % 6;
                                index /= 6;
                                int green = index % 6;
                                index /= 6;
                                int blue = index % 6;
                                index /= 6;
                                Q_ASSERT(index == 0);
                                color.setRgb(red, green, blue);
                                break;
                            }
                            case 0xE8 ... 0xFF : { // 0xE8-0xFF:  grayscale from black to white in 24 steps
                                qreal intensity = qreal(index - 0xE8) / (0xFF - 0xE8);
                                color.setRgbF(intensity, intensity, intensity);
                                break;
                            }
                        }
                        textCharFormat.setBackground(color);
                        break;
                    }
                    default : {
                        break;
                    }
                }
            }
            break;
        }
        case 49 : {
            textCharFormat.setBackground(defaultTextCharFormat.background());
            break;
        }
        case 90 ... 97 : {
            int colorIndex = attribute - 90;
            QColor color;
            switch (colorIndex) {
                case 0 : {
                    color = Qt::darkGray;
                    break;
                }
                case 1 : {
                    color = Qt::red;
                    break;
                }
                case 2 : {
                    color = Qt::green;
                    break;
                }
                case 3 : {
                    color = Qt::yellow;
                    break;
                }
                case 4 : {
                    color = Qt::blue;
                    break;
                }
                case 5 : {
                    color = Qt::magenta;
                    break;
                }
                case 6 : {
                    color = Qt::cyan;
                    break;
                }
                case 7 : {
                    color = Qt::white;
                    break;
                }
                default : {
                    Q_ASSERT(false);
                }
            }
            color.setRedF(color.redF() * 0.8);
            color.setGreenF(color.greenF() * 0.8);
            color.setBlueF(color.blueF() * 0.8);
            textCharFormat.setForeground(color);
            break;
        }
        case 100 ... 107 : {
            int colorIndex = attribute - 100;
            QColor color;
            switch (colorIndex) {
                case 0 : {
                    color = Qt::darkGray;
                    break;
                }
                case 1 : {
                    color = Qt::red;
                    break;
                }
                case 2 : {
                    color = Qt::green;
                    break;
                }
                case 3 : {
                    color = Qt::yellow;
                    break;
                }
                case 4 : {
                    color = Qt::blue;
                    break;
                }
                case 5 : {
                    color = Qt::magenta;
                    break;
                }
                case 6 : {
                    color = Qt::cyan;
                    break;
                }
                case 7 : {
                    color = Qt::white;
                    break;
                }
                default : {
                    Q_ASSERT(false);
                }
            }
            color.setRedF(color.redF() * 0.8);
            color.setGreenF(color.greenF() * 0.8);
            color.setBlueF(color.blueF() * 0.8);
            textCharFormat.setBackground(color);
            break;
        }
        default : {
            break;
        }
    }
}

void MiningDialog::setTextTermFormatting(QTextBrowser * textEdit, QString const & text)
{

    QTextDocument * document = textEdit->document();
    QRegExp const escapeSequenceExpression(R"(\x1B\[([\d;]+)m)");
    QTextCursor cursor(document);
    cursor.movePosition(QTextCursor::End);
    /*QTextCharFormat blockFormat = cursor.blockFormat();
    blockFormat.setBackground(QColor("yellow"));
    cursor.setCharFormat(blockFormat);*/
    QTextCharFormat const defaultTextCharFormat = cursor.charFormat();
    cursor.beginEditBlock();
    int offset = escapeSequenceExpression.indexIn(text);
    cursor.insertText(text.mid(0, offset));
    QTextCharFormat textCharFormat = defaultTextCharFormat;
    while (!(offset < 0)) {
        int previousOffset = offset + escapeSequenceExpression.matchedLength();
        QStringList capturedTexts = escapeSequenceExpression.capturedTexts().back().split(';');
        QListIterator< QString > i(capturedTexts);
        while (i.hasNext()) {
            bool ok = false;
            int attribute = i.next().toInt(&ok);
            Q_ASSERT(ok);
            parseEscapeSequence(attribute, i, textCharFormat, defaultTextCharFormat);
        }
        offset = escapeSequenceExpression.indexIn(text, previousOffset);
        if (offset < 0) {
            cursor.insertText(text.mid(previousOffset), textCharFormat);
        } else {
            cursor.insertText(text.mid(previousOffset, offset - previousOffset), textCharFormat);
        }
    }
    cursor.setCharFormat(defaultTextCharFormat);
    cursor.endEditBlock();
    cursor.movePosition(QTextCursor::End);
    textEdit->setTextCursor(cursor);
}

