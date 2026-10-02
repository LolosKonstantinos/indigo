#include "login_dialog.h"
#include "ui_login_dialog.h"

Login_dialog::Login_dialog(QWidget *parent) : QDialog(parent), ui(new Ui::Login_dialog) { ui->setupUi(this); }

Login_dialog::~Login_dialog() { delete ui; }
