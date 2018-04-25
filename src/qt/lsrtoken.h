#ifndef LSRTOKEN_H
#define LSRTOKEN_H

#include "sendtokenpage.h"
#include "receivetokenpage.h"
#include "addtokenpage.h"

#include <QWidget>
#include <QModelIndex>

class TokenViewDelegate;
class WalletModel;
class QStandardItemModel;

namespace Ui {
class LSRToken;
}

class LSRToken : public QWidget
{
    Q_OBJECT

public:
    explicit LSRToken(QWidget *parent = 0);
    ~LSRToken();

    void setModel(WalletModel *_model);

Q_SIGNALS:

public Q_SLOTS:
    void on_sendButton_clicked();
    void on_receiveButton_clicked();
    void on_addTokenButton_clicked();
    void on_addToken(QString address, QString name, QString symbol, int decimals, double balance);

private:
    Ui::LSRToken *ui;
    SendTokenPage* m_sendTokenPage;
    ReceiveTokenPage* m_receiveTokenPage;
    AddTokenPage* m_addTokenPage;
    WalletModel* m_model;
    TokenViewDelegate* m_tokenDelegate;
    QStandardItemModel *m_tokenModel;
};

#endif // LSRTOKEN_H
