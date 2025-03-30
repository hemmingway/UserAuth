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
	void loginSuccess(); // 登录成功信号

private slots:
	void onLoginClicked();
	void onCancelClicked(); // 新增取消按钮的槽函数
	void handleLoginError(int errorCode, const QString& message);

private:
	void setupUI();
	void showMFAField(bool show);
	void updateInputValidation();

	// UI 组件
	QLineEdit* usernameEdit;
	QLineEdit* passwordEdit;
	QLineEdit* mfaEdit;
	QLabel* errorLabel;
	QPushButton* loginBtn;
	QPushButton* btnCancel; // 新增取消按钮

	// 业务逻辑依赖
	UserAuth& auth;
	bool mfaRequired = false;
};

#endif // LOGINDIALOG_H
