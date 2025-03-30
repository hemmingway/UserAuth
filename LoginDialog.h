#ifndef LOGINDIALOG_H
#define LOGINDIALOG_H

#include <QDialog>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QSpacerItem>
#include "UserAuth.h"

class LoginDialog : public QDialog {
	Q_OBJECT

public:
	explicit LoginDialog(UserAuth& auth, QWidget* parent = nullptr);
	QString getUsername() const;
	QString getPassword() const;

signals:
	void loginSuccess(); // ��¼�ɹ��ź�

private slots:
	void onLoginClicked();
	void onCancelClicked(); // ����ȡ����ť�Ĳۺ���
	void handleLoginError(int errorCode, const QString& message);

private:
	void setupUI();
	void showMFAField(bool show);
	void updateInputValidation();

	// UI ���
	QLineEdit* usernameEdit;
	QLineEdit* passwordEdit;
	QLineEdit* mfaEdit;
	QLabel* errorLabel;
	QPushButton* loginBtn;
	QPushButton* btnCancel; // ����ȡ����ť

	// ҵ���߼�����
	UserAuth& auth;
	bool mfaRequired = false;
};

#endif // LOGINDIALOG_H
