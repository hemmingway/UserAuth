#include "AddUserDialog.h"
#include <QVBoxLayout>
#include <QFormLayout>
#include <QPushButton>
#include <QMessageBox>
#include "UserAuth.h"

AddUserDialog::AddUserDialog(QWidget* parent) : QDialog(parent) {
	setupUI();
	validateInputs(); // ��ʼ��֤
}

void AddUserDialog::setupUI() {
	setWindowTitle("����û�");
	setMinimumWidth(300);

	// �û�������
	usernameEdit = new QLineEdit(this);
	usernameEdit->setPlaceholderText("�����û�����4-32�ַ���");

	// ��ɫѡ��
	roleCombo = new QComboBox(this);
	roleCombo->addItem("�ÿ�", UserAuth::Guest);
	roleCombo->addItem("����Ա", UserAuth::Operator);
	roleCombo->addItem("����Ա", UserAuth::Admin);

	// ��������
	passwordEdit = new QLineEdit(this);
	passwordEdit->setPlaceholderText("����8λ������Сд��ĸ�����ּ�����");
	passwordEdit->setEchoMode(QLineEdit::Password);

	// ȷ������
	confirmPasswordEdit = new QLineEdit(this);
	confirmPasswordEdit->setPlaceholderText("�ٴ���������");
	confirmPasswordEdit->setEchoMode(QLineEdit::Password);

	// ������ʾ��ǩ
	errorLabel = new QLabel(this);
	errorLabel->setStyleSheet("color: red;");

	// ��ť
	QPushButton* btnOk = new QPushButton("ȷ��", this);
	QPushButton* btnCancel = new QPushButton("ȡ��", this);
	connect(btnOk, &QPushButton::clicked, this, &QDialog::accept);
	connect(btnCancel, &QPushButton::clicked, this, &QDialog::reject);

	// ������֤�ź�
	connect(usernameEdit, &QLineEdit::textChanged, this, &AddUserDialog::validateInputs);
	connect(passwordEdit, &QLineEdit::textChanged, this, &AddUserDialog::validateInputs);
	connect(confirmPasswordEdit, &QLineEdit::textChanged, this, &AddUserDialog::validateInputs);

	// ����
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	QFormLayout* formLayout = new QFormLayout();

	formLayout->addRow("�û���:", usernameEdit);
	formLayout->addRow("��ɫ:", roleCombo);
	formLayout->addRow("����:", passwordEdit);
	formLayout->addRow("ȷ������:", confirmPasswordEdit);

	mainLayout->addLayout(formLayout);
	mainLayout->addWidget(errorLabel);

	QHBoxLayout* buttonLayout = new QHBoxLayout();
	buttonLayout->addWidget(btnOk);
	buttonLayout->addWidget(btnCancel);
	mainLayout->addLayout(buttonLayout);
}

void AddUserDialog::validateInputs() {
	UserAuth auth; // ���� UserAuth ������ͨ������ע�봫��
	bool isValid = true;
	QString errorMsg;

	// �û�����֤
	QString username = usernameEdit->text();
	if (username.isEmpty()) {
		errorMsg = "�û�������Ϊ��";
		isValid = false;
	}
	else if (!auth.isInputValid(username)) {
		errorMsg = "�û��������Ƿ��ַ�";
		isValid = false;
	}

	// ���븴�Ӷ���֤
	QString password = passwordEdit->text();
	if (password.isEmpty()) {
		errorMsg = "���벻��Ϊ��";
		isValid = false;
	}
	else if (!auth.isPasswordValid(password)) {
		errorMsg = "���벻���ϸ��Ӷ�Ҫ��";
		isValid = false;
	}

	// ����һ������֤
	if (password != confirmPasswordEdit->text()) {
		errorMsg = "������������벻һ��";
		isValid = false;
	}

	// �����������ʽ�ʹ�����ʾ
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
