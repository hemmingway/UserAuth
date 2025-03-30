// Copyright (C) 2020 ~ 2024 MicroPort Urocare (Shanghai) Co., Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef USERAUTH_H
#define USERAUTH_H

#include <QObject>
#include <QMap>
#include <QString>
#include <QCryptographicHash>
#include <QSettings>
#include <QDateTime>
#include <QMutex>
#include <QTimer>
#include <QRegularExpression>
#include <QMessageAuthenticationCode>

class UserAuth : public QObject
{
	Q_OBJECT

public:
	// 用户角色定义
	enum Role {
		Guest = 0,
		Operator = 1,
		Admin = 2
	};

	// 错误码枚举
	enum LoginError {
		EmptyCredentials = 0,
		InvalidCredentials,
		AccountLocked,
		MFARequired,
		InvalidInput,
		ForcePasswordReset
	};

	// 扩展的用户信息结构体（只读视图）
	struct UserInfoEx {
		Role role;                      // 用户角色
		bool requiresMFA;               // MFA 启用状态
		bool isLocked;                  // 账户是否锁定
		bool forcePasswordReset;        // 是否需要强制重置密码
		QDateTime lastLoginTime;        // 最后登录时间
		QDateTime accountCreatedTime;   // 账户创建时间
		QDateTime passwordLastChanged;  // 密码最后修改时间
	};



	explicit UserAuth(QObject* parent = nullptr);
	~UserAuth();

	// 用户登录（支持MFA）
	bool login(const QString& username, const QString& password, const QString& otp = "");
	void logout();
	bool hasPermission(Role requiredRole) const;
	QString currentUser() const;
	Role currentRole() const;
	QList<QString> getAllUsers() const;

	// 新增方法声明
	UserInfoEx getUserInfoEx(const QString& username) const;
	void recordLoginTime(const QString& username);  // 记录登录时间

	QList<QString> getUsers(int page, int pageSize, const QString& keyword = "") const;
	int getUserCount(const QString& keyword = "") const;

	// 用户管理接口（仅管理员可调用）
	bool createUser(const QString& user, Role role, const QString& tempPassword);
	bool deleteUser(const QString& user);
	bool unlockUser(const QString& username);
	bool resetPassword(const QString& user, const QString& newPassword);
	bool setUserRole(const QString& username, Role newRole);
	bool updateUser(const QString& username, Role newRole, bool mfaEnabled, bool isLocked);

	// 配置接口
	void setPasswordPolicy(const QString& regex);
	void enableMFA(const QString& user, bool enable);

	// 审计日志接口
	void logActivity(const QString& action);

signals:
	void loginSuccess();
	void loginFailed(int errorCode, const QString& errorMessage);
	void userActivityLogged(const QString& logEntry);
	void accountLocked(const QString& username);
	void passwordResetRequired(const QString& username);

private:
	struct UserInfo {
		QString hashedPassword;
		QString salt;
		Role role;
		bool requiresMFA;
		bool forcePasswordReset;
		bool isLocked;
	};

	// 内部方法
	void loadUserDatabase();
	QString encryptPassword(const QString& password, const QString& salt) const;
	QString generateSecureSalt() const;
	QString generateRandomPassword() const;
	bool validateOTP(const QString& username, const QString& otp) const;
	bool isPasswordValid(const QString& password) const;
	bool isInputValid(const QString& input) const;
	QString signLogEntry(const QString& log) const;
	void resetSessionTimer(); // 新增会话重置方法
	QByteArray getOrCreateHMACKey() const; // 密钥管理
	void initializeUserCreationTime(const QString& username);


	// 数据成员
	QMap<QString, UserInfo> m_users;
	QString m_currentUser;
	Role m_currentRole;
	QSettings m_secureStorage;
	QTimer m_sessionTimer;
	QMap<QString, int> m_failedAttempts;
	mutable QMutex m_userMutex; // 用户数据锁
	mutable QMutex m_logMutex;  // 日志锁
};

#endif // USERAUTH_H

