#include "AddUserDialog.h"
#include <QVBoxLayout>
#include <QFormLayout>
#include <QPushButton>
#include <QMessageBox>
#include "UserAuth.h"

AddUserDialog::AddUserDialog(QWidget* parent) : QDialog(parent) {
	setupUI();
	validateInputs(); // 初始验证
}

void AddUserDialog::setupUI() {
	setWindowTitle("添加用户");
	setMinimumWidth(300);

	// 用户名输入
	usernameEdit = new QLineEdit(this);
	usernameEdit->setPlaceholderText("输入用户名（4-32字符）");

	// 角色选择
	roleCombo = new QComboBox(this);
	roleCombo->addItem("访客", UserAuth::Guest);
	roleCombo->addItem("操作员", UserAuth::Operator);
	roleCombo->addItem("管理员", UserAuth::Admin);

	// 密码输入
	passwordEdit = new QLineEdit(this);
	passwordEdit->setPlaceholderText("至少8位，含大小写字母、数字及符号");
	passwordEdit->setEchoMode(QLineEdit::Password);

	// 确认密码
	confirmPasswordEdit = new QLineEdit(this);
	confirmPasswordEdit->setPlaceholderText("再次输入密码");
	confirmPasswordEdit->setEchoMode(QLineEdit::Password);

	// 错误提示标签
	errorLabel = new QLabel(this);
	errorLabel->setStyleSheet("color: red;");

	// 按钮
	QPushButton* btnOk = new QPushButton("确认", this);
	QPushButton* btnCancel = new QPushButton("取消", this);
	connect(btnOk, &QPushButton::clicked, this, &QDialog::accept);
	connect(btnCancel, &QPushButton::clicked, this, &QDialog::reject);

	// 输入验证信号
	connect(usernameEdit, &QLineEdit::textChanged, this, &AddUserDialog::validateInputs);
	connect(passwordEdit, &QLineEdit::textChanged, this, &AddUserDialog::validateInputs);
	connect(confirmPasswordEdit, &QLineEdit::textChanged, this, &AddUserDialog::validateInputs);

	// 布局
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	QFormLayout* formLayout = new QFormLayout();

	formLayout->addRow("用户名:", usernameEdit);
	formLayout->addRow("角色:", roleCombo);
	formLayout->addRow("密码:", passwordEdit);
	formLayout->addRow("确认密码:", confirmPasswordEdit);

	mainLayout->addLayout(formLayout);
	mainLayout->addWidget(errorLabel);

	QHBoxLayout* buttonLayout = new QHBoxLayout();
	buttonLayout->addWidget(btnOk);
	buttonLayout->addWidget(btnCancel);
	mainLayout->addLayout(buttonLayout);
}

void AddUserDialog::validateInputs() {
	UserAuth auth; // 假设 UserAuth 单例或通过依赖注入传递
	bool isValid = true;
	QString errorMsg;

	// 用户名验证
	QString username = usernameEdit->text();
	if (username.isEmpty()) {
		errorMsg = "用户名不能为空";
		isValid = false;
	}
	else if (!auth.isInputValid(username)) {
		errorMsg = "用户名包含非法字符";
		isValid = false;
	}

	// 密码复杂度验证
	QString password = passwordEdit->text();
	if (password.isEmpty()) {
		errorMsg = "密码不能为空";
		isValid = false;
	}
	else if (!auth.isPasswordValid(password)) {
		errorMsg = "密码不符合复杂度要求";
		isValid = false;
	}

	// 密码一致性验证
	if (password != confirmPasswordEdit->text()) {
		errorMsg = "两次输入的密码不一致";
		isValid = false;
	}

	// 更新输入框样式和错误提示
	updateValidationStyle(usernameEdit, auth.isInputValid(username));
	updateValidationStyle(passwordEdit, auth.isPasswordValid(password));
	updateValidationStyle(confirmPasswordEdit, (password == confirmPasswordEdit->text()));

	errorLabel->setText(errorMsg);
	findChild<QPushButton*>("btnOk")->setEnabled(isValid);
}

void AddUserDialog::updateValidationStyle(QLineEdit* edit, bool isValid) {
	edit->setStyleSheet(isValid ? "" : "background-color: #FFE4E1;");
}

QString AddUserDialog::getUsername() const {
	return usernameEdit->text();
}

UserAuth::Role AddUserDialog::getRole() const {
	return static_cast<UserAuth::Role>(roleCombo->currentData().toInt());
}

QString AddUserDialog::getPassword() const {
	return passwordEdit->text();
}
