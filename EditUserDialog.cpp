#include "EditUserDialog.h"
#include <QVBoxLayout>
#include <QLabel>

EditUserDialog::EditUserDialog(QWidget* parent) : QDialog(parent) {
	QVBoxLayout* layout = new QVBoxLayout(this);

	// �û��������ɱ༭��
	usernameEdit = new QLineEdit(this);
	usernameEdit->setReadOnly(true);
	layout->addWidget(new QLabel("�û���:", this));
	layout->addWidget(usernameEdit);

	// ��ɫѡ��
	roleCombo = new QComboBox(this);
	roleCombo->addItem("�ÿ�", UserAuth::Guest);
	roleCombo->addItem("����Ա", UserAuth::Operator);
	roleCombo->addItem("����Ա", UserAuth::Admin);
	layout->addWidget(new QLabel("��ɫ:", this));
	layout->addWidget(roleCombo);

	// MFA״̬
	mfaCheckBox = new QCheckBox("���ö�������֤ (MFA)", this);
	layout->addWidget(mfaCheckBox);

	// �˻�����״̬
	lockCheckBox = new QCheckBox("�����˻�", this);
	layout->addWidget(lockCheckBox);

	// ȷ��/ȡ����ť
	buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
	connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
	connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
	layout->addWidget(buttonBox);
}

// ���ó�ʼֵ
void EditUserDialog::setUsername(const QString& username) {
	usernameEdit->setText(username);
}

void EditUserDialog::setRole(UserAuth::Role role) {
	int index = roleCombo->findData(role);
	if (index >= 0) roleCombo->setCurrentIndex(index);
}

void EditUserDialog::setMFAEnabled(bool enabled) {
	mfaCheckBox->setChecked(enabled);
}

void EditUserDialog::setAccountLocked(bool locked) {
	lockCheckBox->setChecked(locked);
}

void EditUserDialog::lockRoleSelection(bool locked) {
	roleCombo->setEnabled(!locked);
}

// ��ȡ�޸ĺ��ֵ
UserAuth::Role EditUserDialog::getSelectedRole() const {
	return static_cast<UserAuth::Role>(roleCombo->currentData().toInt());
}

bool EditUserDialog::isMFAEnabled() const {
	return mfaCheckBox->isChecked();
}

bool EditUserDialog::isAccountLocked() const {
	return lockCheckBox->isChecked();
}
