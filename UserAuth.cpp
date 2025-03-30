// Copyright (C) 2020 ~ 2024 MicroPort Urocare (Shanghai) Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "UserAuth.h"
#include "TOTPGenerator.h"
#include "SecureKeyStorage.h"
#include <QMessageAuthenticationCode>
#include <QRandomGenerator>
#include <QCryptographicHash>
#include <QPasswordDigestor>
#include <QRegularExpression>
#include <QDebug>


UserAuth::UserAuth(QObject* parent)
	: QObject(parent), m_secureStorage("MedicalCorp", "EndoscopeAuth")
{
	loadUserDatabase();
	connect(&m_sessionTimer, &QTimer::timeout, this, &UserAuth::logout);
}

UserAuth::~UserAuth()
{
	m_currentUser.clear();
	m_users.clear();
}

//--- 用户登录验证（含MFA）---
bool UserAuth::login(const QString& username, const QString& password, const QString& otp)
{
	QMutexLocker locker(&m_userMutex);

	// 输入验证
	if (!isInputValid(username) || !isInputValid(password)) {
		emit loginFailed(LoginError::InvalidInput, tr("输入包含非法字符"));
		return false;
	}

	if (username.isEmpty() || password.isEmpty()) {
		emit loginFailed(LoginError::EmptyCredentials, tr("用户名或密码不能为空"));
		return false;
	}

	// 新增显式锁定检查
	if (info.isLocked) {
		emit loginFailed(LoginError::AccountLocked, tr("账户已锁定"));
		return false;
	}

	// 检查账户锁定
	if (m_failedAttempts.value(username, 0) >= 5) {
		emit loginFailed(LoginError::AccountLocked, tr("账户已锁定"));
		return false;
	}

	auto it = m_users.find(username);
	if (it == m_users.end()) {
		emit loginFailed(LoginError::InvalidCredentials, tr("用户名或密码错误"));
		return false;
	}

	// 验证密码
	const UserInfo& info = it.value();
	QString calculatedHash = encryptPassword(password, info.salt);
	if (calculatedHash != info.hashedPassword) {
		m_failedAttempts[username]++;
		emit loginFailed(LoginError::InvalidCredentials, tr("用户名或密码错误"));
		return false;
	}

	// 验证MFA
	if (info.requiresMFA && !validateOTP(username, otp)) {
		emit loginFailed(LoginError::MFARequired, tr("需要动态验证码"));
		return false;
	}

	// 强制密码重置
	if (info.forcePasswordReset) {
		emit passwordResetRequired(username);
		return false;
	}

	// 登录成功
	m_currentUser = username;
	m_currentRole = info.role;
	m_failedAttempts.remove(username);
	m_sessionTimer.start(30 * 60 * 1000); // 30分钟超时

	logActivity("用户登录成功");
	emit loginSuccess();
	return true;
}

//--- 用户注销 ---
void UserAuth::logout()
{
	QMutexLocker locker(&m_userMutex);
	logActivity("用户注销");
	m_currentUser.clear();
	m_currentRole = Guest;
	m_sessionTimer.stop();
}

//--- 修复1：会话超时重置 ---
void UserAuth::resetSessionTimer() {
	QMutexLocker locker(&m_userMutex);
	if (m_sessionTimer.isActive()) {
		m_sessionTimer.start(30 * 60 * 1000); // 重置为30分钟
	}
}

//--- 权限检查 ---
bool UserAuth::hasPermission(Role requiredRole) const
{
	QMutexLocker locker(&m_userMutex);
	const_cast<UserAuth*>(this)->resetSessionTimer(); // 关键操作重置计时器
	return (m_currentRole >= requiredRole);
}

//--- 获取当前用户 ---
QString UserAuth::currentUser() const {
	QMutexLocker locker(&m_userMutex);
	return m_currentUser;
}

//--- 获取当前角色 ---
UserAuth::Role UserAuth::currentRole() const {
	QMutexLocker locker(&m_userMutex);
	return m_currentRole;
}

//--- 获取所有用户列表 ---
QList<QString> UserAuth::getAllUsers() const
{
	QMutexLocker locker(&m_userMutex);
	return m_users.keys();
}

//--- 获取扩展用户信息 ---
UserAuth::UserInfoEx UserAuth::getUserInfoEx(const QString& username) const {
	QMutexLocker locker(&m_userMutex);
	UserInfoEx infoEx;

	auto it = m_users.constFind(username);
	if (it == m_users.constEnd()) {
		qWarning() << "用户不存在：" << username;
		return infoEx;
	}

	// 一次性读取所有元数据键值对
	m_secureStorage.beginGroup("Users/" + username);
	QMap<QString, QVariant> metadata = m_secureStorage.value("metadata").toMap();
	m_secureStorage.endGroup();

	// 基础信息
	const UserInfo& info = it.value();
	infoEx.role = info.role;
	infoEx.requiresMFA = info.requiresMFA;
	infoEx.forcePasswordReset = info.forcePasswordReset;
	infoEx.isLocked = (m_failedAttempts.value(username, 0) >= 5);

	// 从元数据中提取时间字段
	infoEx.lastLoginTime = metadata.value("lastLogin").toDateTime();
	infoEx.accountCreatedTime = metadata.value("createdTime").toDateTime();
	infoEx.passwordLastChanged = metadata.value("pwdChangedTime").toDateTime();

	return infoEx;
}

QList<QString> UserAuth::getUsers(int page, int pageSize, const QString& keyword) const {
	QMutexLocker locker(&m_userMutex);
	QList<QString> filteredUsers;
	int start = (page - 1) * pageSize;
	int count = 0;

	foreach(const QString & user, m_users.keys()) {
		UserInfoEx info = getUserInfoEx(user);
		bool match = keyword.isEmpty()
			|| user.contains(keyword, Qt::CaseInsensitive)
			|| roleToString(info.role).contains(keyword, Qt::CaseInsensitive);

		if (match) {
			if (count >= start && count < start + pageSize) {
				filteredUsers.append(user);
			}
			count++;
		}
	}
	return filteredUsers;
}

int UserAuth::getUserCount(const QString& keyword) const {
	QMutexLocker locker(&m_userMutex);
	if (keyword.isEmpty()) return m_users.size();

	int count = 0;
	foreach(const QString & user, m_users.keys()) {
		UserInfoEx info = getUserInfoEx(user);
		if (user.contains(keyword, Qt::CaseInsensitive)
			|| roleToString(info.role).contains(keyword, Qt::CaseInsensitive)) {
			count++;
		}
	}
	return count;
}

//--- 记录登录时间 ---
void UserAuth::recordLoginTime(const QString& username) {
	QMutexLocker locker(&m_userMutex);
	if (!m_users.contains(username)) return;

	QDateTime currentTime = QDateTime::currentDateTime();
	m_secureStorage.beginGroup("Users/" + username);
	m_secureStorage.setValue("lastLogin", currentTime);
	m_secureStorage.endGroup();
}

//--- 初始化账户创建时间（在创建用户时调用）---
void UserAuth::initializeUserMetadata(const QString& username) {
	QMutexLocker locker(&m_userMutex);
	m_secureStorage.beginGroup("Users/" + username);

	QMap<QString, QVariant> metadata;
	if (!m_secureStorage.contains("metadata")) {
		QDateTime now = QDateTime::currentDateTime();
		metadata["createdTime"] = now;
		metadata["pwdChangedTime"] = now; // 初始密码时间
		m_secureStorage.setValue("metadata", metadata);
	}

	m_secureStorage.endGroup();
}

//--- 设置用户角色（仅管理员）---
bool UserAuth::setUserRole(const QString& username, Role newRole)
{
	QMutexLocker locker(&m_userMutex);

	// 权限验证
	if (!hasPermission(Admin)) {
		qWarning() << "权限不足，无法修改角色";
		return false;
	}

	// 用户存在性检查
	auto it = m_users.find(username);
	if (it == m_users.end()) {
		qWarning() << "用户不存在：" << username;
		return false;
	}

	// 更新角色
	UserInfo& info = it.value();
	if (info.role == newRole) {
		return true; // 角色未变化直接返回成功
	}
	info.role = newRole;

	// 持久化存储
	m_secureStorage.beginGroup("Users");
	m_secureStorage.setValue(username + "/role", static_cast<int>(newRole));
	if (m_secureStorage.status() != QSettings::NoError) {
		qCritical() << "角色存储失败：" << m_secureStorage.status();
		m_users.remove(username); // 回滚内存修改
		return false;
	}
	m_secureStorage.endGroup();

	emit userUpdated(username); // 触发更新信号
	logActivity(QString("修改用户角色：%1 -> %2").arg(username).arg(newRole));
	return true;
}

bool UserAuth::updateUser(const QString& username, Role newRole, bool mfaEnabled, bool isLocked) {
	QMutexLocker locker(&m_userMutex);

	// 1. 权限检查：仅管理员可操作
	if (!hasPermission(Admin)) {
		qWarning() << "权限不足，需要管理员权限";
		return false;
	}

	// 2. 用户存在性检查
	if (!m_users.contains(username)) {
		qWarning() << "用户不存在：" << username;
		return false;
	}

	// 3. 获取用户信息并更新
	UserInfo& userInfo = m_users[username];
	bool changed = false;

	// 更新角色
	if (userInfo.role != newRole) {
		userInfo.role = newRole;
		changed = true;
	}

	// 更新MFA状态
	if (userInfo.requiresMFA != mfaEnabled) {
		userInfo.requiresMFA = mfaEnabled;
		changed = true;
	}

	// 更新锁定状态
	if (userInfo.isLocked != isLocked) {
		userInfo.isLocked = isLocked;
		changed = true;
		// 若解锁，清空失败次数
		if (!isLocked) m_failedAttempts.remove(username);
	}

	// 4. 若没有实际修改，直接返回
	if (!changed) {
		qInfo() << "用户信息未发生变化";
		return true;
	}

	// 5. 持久化存储更新
	m_secureStorage.beginGroup("Users");
	m_secureStorage.beginGroup(username);
	m_secureStorage.setValue("role", static_cast<int>(userInfo.role));
	m_secureStorage.setValue("mfa", userInfo.requiresMFA);
	m_secureStorage.setValue("locked", userInfo.isLocked);
	m_secureStorage.endGroup(); // username
	m_secureStorage.endGroup(); // Users

	// 6. 记录审计日志
	QString log = QString("更新用户[%1]: 角色=%2, MFA=%3, 锁定=%4")
		.arg(username)
		.arg(newRole)
		.arg(mfaEnabled ? "启用" : "禁用")
		.arg(isLocked ? "是" : "否");
	logActivity(log);

	return true;
}

//--- 创建用户（管理员）---
bool UserAuth::createUser(const QString& user, Role role, const QString& tempPassword)
{
	QMutexLocker locker(&m_userMutex);
	if (!hasPermission(Admin))
		return false;

	if (m_users.contains(user))
		return false;

	if (!isPasswordValid(tempPassword))
		return false;

	QString salt = generateSecureSalt();
	UserInfo info;
	info.hashedPassword = encryptPassword(tempPassword, salt);
	info.salt = salt;
	info.role = role;
	info.forcePasswordReset = true;

	m_secureStorage.beginGroup("Users");
	bool success =
		m_secureStorage.isWritable() &&
		m_secureStorage.status() == QSettings::NoError;

	if (success)
	{
		m_secureStorage.setValue(user + "/hash", info.hashedPassword);
		m_secureStorage.setValue(user + "/salt", info.salt);
		m_secureStorage.setValue(user + "/role", static_cast<int>(info.role));
		m_secureStorage.setValue(user + "/forceReset", info.forcePasswordReset);
	}

	m_secureStorage.endGroup();

	if (!success) {
		qCritical() << "用户存储失败！磁盘可能写保护";
		m_users.remove(user);
		return false;
	}
	else {
		//
		initializeUserCreationTime(user);
	}

	m_users[user] = info;
	return true;
}

//--- 删除用户（仅管理员）---
bool UserAuth::deleteUser(const QString& user)
{
	QMutexLocker locker(&m_userMutex);
	if (!hasPermission(Admin)) {
		qWarning() << "权限不足，删除用户失败";
		return false;
	}

	if (!m_users.contains(user)) {
		qWarning() << "用户不存在：" << user;
		return false;
	}

	// 从内存中移除
	m_users.remove(user);

	// 从持久化存储中删除
	m_secureStorage.beginGroup("Users");
	m_secureStorage.remove(user);
	m_secureStorage.endGroup();

	logActivity("删除用户：" + user);
	return true;
}

//--- 管理员解锁账户 ---
bool UserAuth::unlockUser(const QString& username) {
	QMutexLocker locker(&m_userMutex);
	if (!hasPermission(Admin)) {
		qWarning() << "权限不足，无法解锁账户";
		return false;
	}

	if (m_failedAttempts.contains(username)) {
		m_failedAttempts.remove(username);
		logActivity("管理员解锁账户: " + username);
		return true;
	}
	return false;
}

//--- 重置密码 ---
bool UserAuth::resetPassword(const QString& user, const QString& newPassword)
{
	QMutexLocker locker(&m_userMutex);
	if (!(hasPermission(Admin) || (m_currentUser == user))) {
		qWarning() << "无权修改密码";
		return false;
	}

	if (!m_users.contains(user)) {
		qWarning() << "用户不存在：" << user;
		return false;
	}

	if (!isPasswordValid(newPassword)) {
		emit loginFailed(tr("密码不符合复杂度要求"));
		return false;
	}

	// 生成新盐并更新密码
	UserInfo& info = m_users[user];
	info.salt = generateSecureSalt();
	info.hashedPassword = encryptPassword(newPassword, info.salt);
	info.forcePasswordReset = false; // 重置后关闭强制修改标志

	// 更新持久化存储
	m_secureStorage.beginGroup("Users");
	m_secureStorage.setValue(user + "/hash", info.hashedPassword);
	m_secureStorage.setValue(user + "/salt", info.salt);
	m_secureStorage.setValue(user + "/forceReset", info.forcePasswordReset);

	QMap<QString, QVariant> metadata = m_secureStorage.value("metadata").toMap();
	metadata["pwdChangedTime"] = QDateTime::currentDateTime();
	m_secureStorage.setValue("metadata", metadata);

	m_secureStorage.endGroup();

	logActivity("用户密码重置：" + user);
	return true;
}

//--- 加密密码（PBKDF2-SHA256）---
QString UserAuth::encryptPassword(const QString& password, const QString& salt) const
{
	QByteArray key = QPasswordDigestor::deriveKeyPbkdf2(
		QCryptographicHash::Sha256,
		password.toUtf8(),
		salt.toUtf8(),
		10000,  // 迭代次数
		32      // 输出长度
	);
	return QString(key.toHex());
}

//--- 生成安全盐（16字节随机数）---
QString UserAuth::generateSecureSalt() const
{
	QByteArray saltBytes(16, 0);
	QRandomGenerator::global()->fillRange(reinterpret_cast<quint32*>(saltBytes.data()), saltBytes.size() / sizeof(quint32));
	return saltBytes.toBase64();
}

//--- 设置密码策略 ---
void UserAuth::setPasswordPolicy(const QString& regex)
{
	// 防御性正则校验：防止复杂度过高
	static const QRegularExpression dangerPattern(R"((\\*|\+|\{[\d,]+\}))");
	if (regex.contains(dangerPattern)) {
		qWarning() << "拒绝潜在危险的正则表达式";
		return;
	}

	try {
		QRegularExpression test(regex);
		if (!test.isValid()) {
			qWarning() << "无效的正则表达式：" << test.errorString();
			return;
		}
	}
	catch (...) {
		qWarning() << "异常的正则表达式输入";
		return;
	}

	m_secureStorage.beginGroup("Security");
	m_secureStorage.setValue("PasswordPolicy", regex);
	m_secureStorage.endGroup();
}

//--- 密码复杂度检查 ---
bool UserAuth::isPasswordValid(const QString& password) const
{
	m_secureStorage.beginGroup("Security");
	QString regexPattern = m_secureStorage.value("PasswordPolicy", "^(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*]).{8,}$").toString();
	m_secureStorage.endGroup();

	return QRegularExpression(regexPattern).match(password).hasMatch();
}

//--- 输入验证（防注入）---
bool UserAuth::isInputValid(const QString& input) const
{
	// 医疗设备严格模式：只允许字母数字和有限符号
	static QRegularExpression sanitizer("^[a-zA-Z0-9_@\\-]+$");
	return input.length() >= 4 &&
		input.length() <= 32 &&
		sanitizer.match(input).hasMatch();
}

//--- 启用/禁用MFA ---
void UserAuth::enableMFA(const QString& user, bool enable)
{
	QMutexLocker locker(&m_userMutex);
	if (!m_users.contains(user)) return;

	m_users[user].requiresMFA = enable;
	m_secureStorage.beginGroup("Users");
	m_secureStorage.setValue(user + "/mfa", enable);
	m_secureStorage.endGroup();
}

//--- 审计日志（带HMAC签名）---
void UserAuth::logActivity(const QString& action)
{
	QMutexLocker locker(&m_logMutex);
	QString timestamp = QDateTime::currentDateTime().toString(Qt::ISODate);
	QString user = m_currentUser.isEmpty() ? "Anonymous" : m_currentUser;
	QString logEntry = QString("[%1][%2] %3").arg(timestamp).arg(user).arg(action);

	// 签名并存储日志
	QString signedLog = signLogEntry(logEntry);
	m_secureStorage.beginGroup("AuditLogs");
	QStringList logs = m_secureStorage.value("entries").toStringList();
	logs.append(signedLog);
	m_secureStorage.setValue("entries", logs);
	m_secureStorage.endGroup();

	emit userActivityLogged(signedLog);
}

//--- 修复2：HMAC密钥管理 ---
QByteArray UserAuth::getOrCreateHMACKey() const {
	m_secureStorage.beginGroup("Security");
	QByteArray key = m_secureStorage.value("HMACKey").toByteArray();

	if (key.isEmpty()) {
		// 生成256位随机密钥
		key.resize(32);
		QRandomGenerator::global()->fillRange(reinterpret_cast<quint32*>(key.data()), key.size() / sizeof(quint32));
		m_secureStorage.setValue("HMACKey", key);
		qInfo() << "Generated new HMAC key";
	}

	m_secureStorage.endGroup();
	return key;
}


//--- 日志签名（使用系统密钥）---
QString UserAuth::signLogEntry(const QString& log) const
{
	QByteArray key = SecureKeyStorage::getKey();
	if (key.isEmpty()) {
		key = getOrCreateHMACKey(); // 不再使用硬编码
	}

	QMessageAuthenticationCode hmac(QCryptographicHash::Sha256);
	hmac.setKey(key);
	hmac.addData(log.toUtf8());
	return log + "|SIG:" + hmac.result().toHex();
}

//--- 加载用户数据库 ---
void UserAuth::loadUserDatabase()
{
	QMutexLocker locker(&m_userMutex);
	m_secureStorage.beginGroup("Users");

	// 初始化默认管理员账户（若不存在）
	if (!m_secureStorage.contains("admin")) {
		UserInfo adminInfo;
		adminInfo.salt = generateSecureSalt();
		QString tempPassword = generateRandomPassword();
		adminInfo.hashedPassword = encryptPassword(tempPassword, adminInfo.salt);
		adminInfo.role = Admin;
		adminInfo.requiresMFA = false;
		adminInfo.forcePasswordReset = true;

		m_secureStorage.setValue("admin/hash", adminInfo.hashedPassword);
		m_secureStorage.setValue("admin/salt", adminInfo.salt);
		m_secureStorage.setValue("admin/role", static_cast<int>(adminInfo.role));
		m_secureStorage.setValue("admin/mfa", adminInfo.requiresMFA);
		m_secureStorage.setValue("admin/forceReset", adminInfo.forcePasswordReset);
		m_secureStorage.setValue("admin/locked", adminInfo.isLocked);

		m_users["admin"] = adminInfo;
#ifndef PRODUCTION_BUILD // 仅开发环境输出临时密码
		qInfo() << "初始管理员密码：" << tempPassword;
#endif
	}

	// 加载所有用户
	foreach(const QString & user, m_secureStorage.childGroups()) {
		m_secureStorage.beginGroup(user);
		UserInfo info;
		info.hashedPassword = m_secureStorage.value("hash").toString();
		info.salt = m_secureStorage.value("salt").toString();
		info.role = static_cast<Role>(m_secureStorage.value("role", Guest).toInt());
		info.requiresMFA = m_secureStorage.value("mfa", false).toBool();
		info.forcePasswordReset = m_secureStorage.value("forceReset", false).toBool();
		info.isLocked = m_secureStorage.value("locked", false).toBool();
		m_secureStorage.endGroup();

		m_users[user] = info;
	}

	m_secureStorage.endGroup();
}

//--- 生成随机密码 ---
QString UserAuth::generateRandomPassword() const
{
	const QString chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
	const int length = 12;
	QString password;
	QRandomGenerator* rng = QRandomGenerator::system();

	do {
		password.clear();
		for (int i = 0; i < length; ++i) {
			int index = rng->bounded(chars.length());
			password.append(chars.at(index));
		}
	} while (!isPasswordValid(password)); // 循环直到生成有效密码

	return password;
}

//--- 验证动态OTP ---
bool UserAuth::validateOTP(const QString& username, const QString& otp) const {
	if (!m_users.contains(username) || !m_users[username].requiresMFA) {
		return true; // 未启用MFA直接通过
	}

	m_secureStorage.beginGroup("MFASecrets");
	QByteArray secretKey = m_secureStorage.value(username).toByteArray();
	m_secureStorage.endGroup();

	if (secretKey.isEmpty()) {
		qWarning() << "MFA密钥未配置：" << username;
		return false;
	}

	QString expectedOTP = TOTPGenerator::generateTOTP(secretKey);
	return (otp == expectedOTP);
}

