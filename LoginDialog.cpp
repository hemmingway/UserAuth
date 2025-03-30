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
	setWindowTitle("用户登录");
	setMinimumWidth(300);

	// 用户名输入
	usernameEdit = new QLineEdit(this);
	usernameEdit->setPlaceholderText("用户名");

	// 密码输入
	passwordEdit = new QLineEdit(this);
	passwordEdit->setPlaceholderText("密码");
	passwordEdit->setEchoMode(QLineEdit::Password);

	// MFA 输入（初始隐藏）
	mfaEdit = new QLineEdit(this);
	mfaEdit->setPlaceholderText("动态验证码（6位）");
	mfaEdit->setVisible(false);

	// 错误提示
	errorLabel = new QLabel(this);
	errorLabel->setStyleSheet("color: red;");

	// 登录按钮
	loginBtn = new QPushButton("登录", this);
	connect(loginBtn, &QPushButton::clicked, this, &LoginDialog::onLoginClicked);

	// 新增取消按钮
	btnCancel = new QPushButton("取消", this);
	connect(btnCancel, &QPushButton::clicked, this, &LoginDialog::onCancelClicked);

	// 输入验证信号
	connect(usernameEdit, &QLineEdit::textChanged, this, &LoginDialog::updateInputValidation);
	connect(passwordEdit, &QLineEdit::textChanged, this, &LoginDialog::updateInputValidation);
	connect(mfaEdit, &QLineEdit::textChanged, this, &LoginDialog::updateInputValidation);

	// 按钮布局（水平排列）
	QHBoxLayout* buttonLayout = new QHBoxLayout;
	buttonLayout->addWidget(btnCancel);
	buttonLayout->addWidget(btnLogin);

	// 布局
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	QFormLayout* formLayout = new QFormLayout();

	formLayout->addRow("用户名:", usernameEdit);
	formLayout->addRow("密码:", passwordEdit);
	formLayout->addRow("动态码:", mfaEdit); // 初始隐藏

	mainLayout->addLayout(formLayout);
	mainLayout->addWidget(errorLabel);
	mainLayout->addWidget(buttonLayout);
}

void LoginDialog::onLoginClicked() {
	QString username = usernameEdit->text();
	QString password = passwordEdit->text();
	QString otp = mfaRequired ? mfaEdit->text() : "";

	// 触发登录操作
	bool success = auth.login(username, password, otp);
	if (success) {
		accept(); // 关闭对话框
		emit loginSuccess();
	}
}

void LoginDialog::onCancelClicked() {
	this->reject(); // 或 this->close();
}

void LoginDialog::handleLoginError(int errorCode, const QString& message) {
	switch (errorCode) {
	case UserAuth::MFARequired:
		showMFAField(true);
		errorLabel->setText("请输入动态验证码");
		break;
	case UserAuth::AccountLocked:
		errorLabel->setText("账户已锁定，请联系管理员");
		loginBtn->setEnabled(false);
		break;
	default:
		errorLabel->setText(message);
	}
}

void LoginDialog::showMFAField(bool show) {
	mfaRequired = show;
	mfaEdit->setVisible(show);
	adjustSize(); // 动态调整对话框大小
}

void LoginDialog::updateInputValidation() {
	bool isValid = true;

	// 用户名格式检查
	if (!auth.isInputValid(usernameEdit->text())) {
		usernameEdit->setStyleSheet("background-color: #FFE4E1;");
		isValid = false;
	}
	else {
		usernameEdit->setStyleSheet("");
	}

	// 密码非空检查
	if (passwordEdit->text().isEmpty()) {
		passwordEdit->setStyleSheet("background-color: #FFE4E1;");
		isValid = false;
	}
	else {
		passwordEdit->setStyleSheet("");
	}

	// MFA 格式检查（6位数字）
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
