#ifndef EDITUSERDIALOG_H
#define EDITUSERDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QDialogButtonBox>
#include "UserAuth.h"

class EditUserDialog : public QDialog {
	Q_OBJECT
public:
	explicit EditUserDialog(QWidget* parent = nullptr);

	// 设置初始值
	void setUsername(const QString& username);
	void setRole(UserAuth::Role role);
	void setMFAEnabled(bool enabled);
	void setAccountLocked(bool locked);
	void lockRoleSelection(bool locked = true);

	// 获取修改后的值
	UserAuth::Role getSelectedRole() const;
	bool isMFAEnabled() const;
	bool isAccountLocked() const;

private:
	QLineEdit* usernameEdit;
	QComboBox* roleCombo;
	QCheckBox* mfaCheckBox;
	QCheckBox* lockCheckBox;
	QDialogButtonBox* buttonBox;
};

#endif // EDITUSERDIALOG_H
