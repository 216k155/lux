#include "receivetokenpage.h"
#include "ui_receivetokenpage.h"
#include "guiconstants.h"
#include "receiverequestdialog.h"

ReceiveTokenPage::ReceiveTokenPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ReceiveTokenPage)
{
    ui->setupUi(this);
    SendCoinsRecipient info;
    info.address = "LgFDgoVVpzxmcm7UkwPoAPGvsVuun48mjR";
    if(ReceiveRequestDialog::createQRCode(ui->lblQRCode, info))
    {
        ui->lblQRCode->setScaledContents(true);
    }
}

ReceiveTokenPage::~ReceiveTokenPage()
{
    delete ui;
}
