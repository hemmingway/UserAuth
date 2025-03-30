#ifndef ADDUSERDIALOG_H
#define ADDUSERDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include "UserAuth.h"

class AddUserDialog : public QDialog {
	Q_OBJECT

public:
	explicit AddUserDialog(QWidget* parent = nullptr);
	QString getUsername() const;
	UserAuth::Role getRole() const;
	QString getPassword() const;

private slots:
	void validateInputs();

private:
	void setupUI();
	void updateValidationStyle(QLineEdit* edit, bool isValid);

	// UI ×é¼þ
	QLineEdit* usernameEdit;
	QComboBox* roleCombo;
	QLineEdit* passwordEdit;
	QLineEdit* confirmPasswordEdit;
	QLabel* errorLabel;
};

#endif // ADDUSERDIALOG_H
