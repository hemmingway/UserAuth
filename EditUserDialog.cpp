#include "EditUserDialog.h"
#include <QVBoxLayout>
#include <QLabel>

EditUserDialog::EditUserDialog(QWidget* parent) : QDialog(parent) {
	QVBoxLayout* layout = new QVBoxLayout(this);

	// 用户名（不可编辑）
	usernameEdit = new QLineEdit(this);
	usernameEdit->setReadOnly(true);
	layout->addWidget(new QLabel("用户名:", this));
	layout->addWidget(usernameEdit);

	// 角色选择
	roleCombo = new QComboBox(this);
	roleCombo->addItem("访客", UserAuth::Guest);
	roleCombo->addItem("操作员", UserAuth::Operator);
	roleCombo->addItem("管理员", UserAuth::Admin);
	layout->addWidget(new QLabel("角色:", this));
	layout->addWidget(roleCombo);

	// MFA状态
	mfaCheckBox = new QCheckBox("启用多因素认证 (MFA)", this);
	layout->addWidget(mfaCheckBox);

	// 账户锁定状态
	lockCheckBox = new QCheckBox("锁定账户", this);
	layout->addWidget(lockCheckBox);

	// 确认/取消按钮
	buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
	connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
	connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
	layout->addWidget(buttonBox);
}

// 设置初始值
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

// 获取修改后的值
UserAuth::Role EditUserDialog::getSelectedRole() const {
	return static_cast<UserAuth::Role>(roleCombo->currentData().toInt());
}

bool EditUserDialog::isMFAEnabled() const {
	return mfaCheckBox->isChecked();
}

bool EditUserDialog::isAccountLocked() const {
	return lockCheckBox->isChecked();
}
