#include "LoginDialog.h"
#include <QVBoxLayout>
#include <QFormLayout>
#include <QMessageBox>
#include <QRegularExpression>

LoginDialog::LoginDialog(UserAuth& auth, QWidget* parent)
	: QDialog(parent), auth(auth) {
	setupUI();
	connect(&auth, &UserAuth::loginFailed, this, &LoginDialog::handleLoginError);
}

void LoginDialog::setupUI() {
	setWindowTitle("�û���¼");
	setMinimumWidth(300);

	// �û�������
	usernameEdit = new QLineEdit(this);
	usernameEdit->setPlaceholderText("�û���");

	// ��������
	passwordEdit = new QLineEdit(this);
	passwordEdit->setPlaceholderText("����");
	passwordEdit->setEchoMode(QLineEdit::Password);

	// MFA ���루��ʼ���أ�
	mfaEdit = new QLineEdit(this);
	mfaEdit->setPlaceholderText("��̬��֤�루6λ��");
	mfaEdit->setVisible(false);

	// ������ʾ
	errorLabel = new QLabel(this);
	errorLabel->setStyleSheet("color: red;");

	// ��¼��ť
	loginBtn = new QPushButton("��¼", this);
	connect(loginBtn, &QPushButton::clicked, this, &LoginDialog::onLoginClicked);

	// ����ȡ����ť
	btnCancel = new QPushButton("ȡ��", this);
	connect(btnCancel, &QPushButton::clicked, this, &LoginDialog::onCancelClicked);

	// ������֤�ź�
	connect(usernameEdit, &QLineEdit::textChanged, this, &LoginDialog::updateInputValidation);
	connect(passwordEdit, &QLineEdit::textChanged, this, &LoginDialog::updateInputValidation);
	connect(mfaEdit, &QLineEdit::textChanged, this, &LoginDialog::updateInputValidation);

	// ��ť���֣�ˮƽ���У�
	QHBoxLayout* buttonLayout = new QHBoxLayout;
	buttonLayout->addWidget(btnCancel);
	buttonLayout->addWidget(btnLogin);

	// ����
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	QFormLayout* formLayout = new QFormLayout();

	formLayout->addRow("�û���:", usernameEdit);
	formLayout->addRow("����:", passwordEdit);
	formLayout->addRow("��̬��:", mfaEdit); // ��ʼ����

	mainLayout->addLayout(formLayout);
	mainLayout->addWidget(errorLabel);
	mainLayout->addWidget(buttonLayout);
}

void LoginDialog::onLoginClicked() {
	QString username = usernameEdit->text();
	QString password = passwordEdit->text();
	QString otp = mfaRequired ? mfaEdit->text() : "";

	// ������¼����
	bool success = auth.login(username, password, otp);
	if (success) {
		accept(); // �رնԻ���
		emit loginSuccess();
	}
}

void LoginDialog::onCancelClicked() {
	this->reject(); // �� this->close();
}

void LoginDialog::handleLoginError(int errorCode, const QString& message) {
	switch (errorCode) {
	case UserAuth::MFARequired:
		showMFAField(true);
		errorLabel->setText("�����붯̬��֤��");
		break;
	case UserAuth::AccountLocked:
		errorLabel->setText("�˻�������������ϵ����Ա");
		loginBtn->setEnabled(false);
		break;
	default:
		errorLabel->setText(message);
	}
}

void LoginDialog::showMFAField(bool show) {
	mfaRequired = show;
	mfaEdit->setVisible(show);
	adjustSize(); // ��̬�����Ի����С
}

void LoginDialog::updateInputValidation() {
	bool isValid = true;

	// �û�����ʽ���
	if (!auth.isInputValid(usernameEdit->text())) {
		usernameEdit->setStyleSheet("background-color: #FFE4E1;");
		isValid = false;
	}
	else {
		usernameEdit->setStyleSheet("");
	}

	// ����ǿռ��
	if (passwordEdit->text().isEmpty()) {
		passwordEdit->setStyleSheet("background-color: #FFE4E1;");
		isValid = false;
	}
	else {
		passwordEdit->setStyleSheet("");
	}

	// MFA ��ʽ��飨6λ���֣�
	if (mfaRequired && !QRegularExpression("^\\d{6}$").match(mfaEdit->text()).hasMatch()) {
		mfaEdit->setStyleSheet("background-color: #FFE4E1;");
		isValid = false;
	}
	else {
		mfaEdit->setStyleSheet("");
	}

	loginBtn->setEnabled(isValid);
}

QString LoginDialog::getUsername() const {
	return usernameEdit->text();
}

QString LoginDialog::getPassword() const {
	return passwordEdit->text();
}
