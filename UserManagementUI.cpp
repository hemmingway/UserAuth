#include "UserManagementUI.h"
#include <QHeaderView>
#include <QHBoxLayout>
#include <QVBoxLayout>       // 新增
#include <QMessageBox>
#include <QInputDialog>
#include <QDebug>

UserManagementUI::UserManagementUI(UserAuth& auth, QWidget* parent)
	: QWidget(parent), auth(auth) {
	setupUI();
	setupConnections();
	refreshUserList();
}

void UserManagementUI::setupUI() {
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(5, 5, 5, 5);
	mainLayout->setSpacing(5);

	setupToolbar();
	setupTable();
	setupStatusLabel();

	// 将工具栏、表格、状态标签添加到主布局
	mainLayout->addWidget(toolBar);
	mainLayout->addWidget(userTable, 1); // 表格占据剩余空间
	mainLayout->addWidget(statusLabel, 0, Qt::AlignRight);
}

void UserManagementUI::setupToolbar() {
	toolBar = new QToolBar(this);
	toolBar->setMovable(false);

	// 搜索框
	searchEdit = new QLineEdit(this);
	searchEdit->setPlaceholderText("搜索用户名或角色...");
	searchEdit->setFixedWidth(200);

	// 分页控件
	pageSpin = new QSpinBox(this);
	pageSpin->setRange(1, 1);
	pageLabel = new QLabel("/ 共 1 页", this);
	btnPrevPage = new QPushButton("上一页", this);
	btnNextPage = new QPushButton("下一页", this);

	// 角色批量操作
	roleCombo = new QComboBox(this);
	roleCombo->addItem("访客", UserAuth::Guest);
	roleCombo->addItem("操作员", UserAuth::Operator);
	roleCombo->addItem("管理员", UserAuth::Admin);

	// 应用角色按钮
	btnApplyRole = new QPushButton("应用角色", this);

	// 操作按钮
	btnAddUser = new QPushButton(QIcon(":/icons/add_user.png"), "添加用户", this);
	btnRefresh = new QPushButton(QIcon(":/icons/refresh.png"), "刷新", this);
	btnDeleteSelected = new QPushButton(QIcon(":/icons/delete.png"), "删除选中", this);

	// 工具栏布局
	toolBar->addWidget(searchEdit);
	toolBar->addWidget(btnAddUser);
	toolBar->addWidget(btnDeleteSelected);
	toolBar->addWidget(btnRefresh);
	toolBar->addSeparator();
	toolBar->addWidget(btnPrevPage);
	toolBar->addWidget(pageSpin);
	toolBar->addWidget(pageLabel);
	toolBar->addWidget(btnNextPage);
	toolBar->addSeparator();
	toolBar->addWidget(new QLabel("批量角色:"));
	toolBar->addWidget(roleCombo);
	toolBar->addWidget(btnApplyRole);
}

void UserManagementUI::setupTable() {
	userTable = new QTableWidget(this);
	userTable->setColumnCount(6);
	userTable->setHorizontalHeaderLabels({ "用户名", "角色", "MFA状态", "账户状态", "最后登录", "操作" });
	userTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
	userTable->verticalHeader()->setVisible(false);
	userTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
	userTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
	userTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	userTable->setColumnWidth(5, 200); // 固定操作列宽度
}

void UserManagementUI::setupStatusLabel() {
	statusLabel = new QLabel("就绪", this);
	statusLabel->setAlignment(Qt::AlignRight);
	statusLabel->setStyleSheet(
		"QLabel {"
		"  color: #666666;"
		"  font: 9pt '微软雅黑';"
		"  padding: 2px 8px;"
		"  background: #f0f0f0;"
		"  border-radius: 4px;"
		"}"
	);
}

void UserManagementUI::setupConnections() {
	connect(searchEdit, &QLineEdit::textChanged, this, &UserManagementUI::onSearchTextChanged);
	connect(btnAddUser, &QPushButton::clicked, this, &UserManagementUI::onAddUser);
	connect(btnDeleteSelected, &QPushButton::clicked, this, &UserManagementUI::onDeleteSelected);
	connect(btnApplyRole, &QPushButton::clicked, this, &UserManagementUI::onApplyRole);
	connect(btnRefresh, &QPushButton::clicked, this, &UserManagementUI::refreshUserList);

	connect(pageSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, &UserManagementUI::onPageChanged);
	connect(btnPrevPage, &QPushButton::clicked, [this] { pageSpin->setValue(pageSpin->value() - 1); });
	connect(btnNextPage, &QPushButton::clicked, [this] { pageSpin->setValue(pageSpin->value() + 1); });

	connect(&auth, &UserAuth::userAdded, this, &UserManagementUI::refreshUserList);
	connect(&auth, &UserAuth::userRemoved, this, &UserManagementUI::refreshUserList);
	connect(&auth, &UserAuth::userUpdated, this, &UserManagementUI::refreshUserList);

}

void UserManagementUI::refreshUserList() {
	userTable->setRowCount(0);
	bool isAdmin = auth.hasPermission(UserAuth::Admin);
	QString currentUser = auth.currentUser();
	QString keyword = searchEdit->text().trimmed();
	int currentPage = pageSpin->value();

	// 获取分页数据
	QList<QString> users = auth.getUsers(currentPage, PAGE_SIZE, keyword);
	int totalUsers = auth.getUserCount(keyword);
	int totalPages = (totalUsers + PAGE_SIZE - 1) / PAGE_SIZE;

	// 更新分页控件
	pageSpin->blockSignals(true);
	pageSpin->setRange(1, totalPages > 0 ? totalPages : 1);
	pageLabel->setText(QString("/ 共 %1 页").arg(totalPages));
	pageSpin->blockSignals(false);

	// 填充表格数据
	foreach(const QString & username, users) {
		UserAuth::UserInfoEx info = auth.getUserInfoEx(username);
		int row = userTable->rowCount();
		userTable->insertRow(row);

		// 用户名
		userTable->setItem(row, 0, new QTableWidgetItem(username));

		// 角色
		userTable->setItem(row, 1, new QTableWidgetItem(roleToString(info.role)));

		// MFA状态
		userTable->setItem(row, 2, new QTableWidgetItem(info.requiresMFA ? "已启用" : "未启用"));

		// 账户状态
		QTableWidgetItem* statusItem = new QTableWidgetItem(info.isLocked ? "锁定" : "正常");
		statusItem->setForeground(info.isLocked ? Qt::red : Qt::darkGreen);
		userTable->setItem(row, 3, statusItem);

		// 最后登录时间
		QString lastLogin = info.lastLoginTime.isValid()
			? info.lastLoginTime.toString("yyyy-MM-dd hh:mm")
			: "从未登录";
		userTable->setItem(row, 4, new QTableWidgetItem(lastLogin));

		// 操作列按钮
		QWidget* btnContainer = new QWidget();
		QHBoxLayout* layout = new QHBoxLayout(btnContainer);
		layout->setContentsMargins(5, 2, 5, 2);
		layout->setSpacing(3);

		// 编辑按钮（所有用户可见）
		QPushButton* editBtn = new QPushButton("编辑", btnContainer);
		editBtn->setStyleSheet(
			"QPushButton {"
			"  background: #4CAF50;"
			"  color: white;"
			"  padding: 3px 8px;"
			"  border-radius: 3px;"
			"}"
			"QPushButton:hover { background: #45a049; }"
		);
		connect(editBtn, &QPushButton::clicked, [this, username] { onEditUser(username); });

		// 删除按钮（仅管理员可见）
		QPushButton* deleteBtn = new QPushButton("删除", btnContainer);
		deleteBtn->setStyleSheet(
			"QPushButton {"
			"  background: #f44336;"
			"  color: white;"
			"  padding: 3px 8px;"
			"  border-radius: 3px;"
			"}"
			"QPushButton:hover { background: #d32f2f; }"
		);
		deleteBtn->setVisible(isAdmin);
		connect(deleteBtn, &QPushButton::clicked, [this, username] { onDeleteUser(username); });

		// 重置密码按钮（管理员或当前用户可用）
		QPushButton* resetPwdBtn = new QPushButton("重置密码", btnContainer);
		resetPwdBtn->setStyleSheet(
			"QPushButton {"
			"  background: #2196F3;"
			"  color: white;"
			"  padding: 3px 8px;"
			"  border-radius: 3px;"
			"}"
			"QPushButton:hover { background: #1976D2; }"
		);
		bool canReset = isAdmin || (username == currentUser);
		resetPwdBtn->setEnabled(canReset);
		if (!canReset) resetPwdBtn->setToolTip("需要管理员权限或当前用户");
		connect(resetPwdBtn, &QPushButton::clicked, [this, username] { onResetPassword(username); });

		layout->addWidget(editBtn);
		layout->addWidget(deleteBtn);
		layout->addWidget(resetPwdBtn);
		userTable->setCellWidget(row, 5, btnContainer);
	}

	statusLabel->setText(QString("共加载 %1 条用户，当前第 %2/%3 页").arg(users.size()).arg(currentPage).arg(totalPages));
}

void UserManagementUI::onSearchTextChanged(const QString& text) {
	pageSpin->setValue(1); // 搜索时重置到第一页
	refreshUserList();
}

void UserManagementUI::onAddUser() {
	if (!auth.hasPermission(UserAuth::Admin)) {
		QMessageBox::warning(this, "权限不足", "只有管理员可以添加用户！");
		return;
	}

	AddUserDialog dialog(this);
	if (dialog.exec() == QDialog::Accepted) {
		bool success = auth.createUser(
			dialog.getUsername(),
			dialog.getRole(),
			dialog.getPassword()
		);
		if (success) {
			statusLabel->showMessage("用户添加成功", 3000);
		}
		else {
			QMessageBox::critical(this, "错误", "添加失败：用户名已存在或密码无效！");
		}
	}
}

void UserManagementUI::onEditUser(const QString& username) {
	// 权限验证：非管理员只能编辑自己的信息
	bool isAdmin = auth.hasPermission(UserAuth::Admin);
	QString currentUser = auth.currentUser();

	if (!isAdmin && username != currentUser) {
		QMessageBox::warning(this, "权限不足", "您只能编辑自己的账户信息！");
		return;
	}

	// 获取用户详细信息
	UserAuth::UserInfoEx userInfo = auth.getUserInfoEx(username);
	if (userInfo.username.isEmpty()) {
		QMessageBox::critical(this, "错误", "用户信息获取失败！");
		return;
	}

	// 创建并初始化编辑对话框
	EditUserDialog dialog(this);
	dialog.setWindowTitle("编辑用户 - " + username);
	dialog.setUsername(username);                    // 用户名不可编辑
	dialog.setRole(userInfo.role);                   // 当前角色
	dialog.setMFAEnabled(userInfo.requiresMFA);      // MFA状态
	dialog.setAccountLocked(userInfo.isLocked);      // 账户锁定状态

	// 如果是普通用户编辑自己，禁用角色修改
	if (!isAdmin) {
		dialog.lockRoleSelection();
	}

	// 显示对话框并等待用户操作
	if (dialog.exec() == QDialog::Accepted) {
		// 获取修改后的数据
		UserAuth::Role newRole = dialog.getSelectedRole();
		bool newMFAStatus = dialog.isMFAEnabled();
		bool newLockStatus = dialog.isAccountLocked();

		// 调用后端更新用户信息
		if (auth.updateUser(username, newRole, newMFAStatus, newLockStatus)) {
			statusLabel->setText(QString("用户 [%1] 信息已更新").arg(username));
			refreshUserList();  // 刷新列表或使用 handleUserUpdate 局部更新
		}
		else {
			QMessageBox::critical(this, "错误", "用户信息更新失败！");
		}
	}
}

void UserManagementUI::onDeleteUser(const QString& username) {
	if (!auth.hasPermission(UserAuth::Admin)) {
		QMessageBox::warning(this, "权限不足", "只有管理员可以删除用户！");
		return;
	}

	if (QMessageBox::question(this, "确认删除", QString("确定删除用户 [%1] 吗？此操作不可恢复！").arg(username)) == QMessageBox::Yes)
	{
		if (auth.deleteUser(username)) {
			statusLabel->showMessage("用户已删除", 3000);
		}
		else {
			QMessageBox::critical(this, "错误", "删除失败：用户不存在或权限不足！");
		}
	}
}

void UserManagementUI::onResetPassword(const QString& username) {
	if (!auth.hasPermission(UserAuth::Admin) && username != auth.currentUser()) {
		QMessageBox::warning(this, "权限不足", "您无权重置其他用户的密码！");
		return;
	}

	// 弹出密码重置对话框
	QString newPassword = QInputDialog::getText(
		this,
		"重置密码",
		QString("请输入用户 [%1] 的新密码：").arg(username),
		QLineEdit::Password
	);

	if (!newPassword.isEmpty()) {
		if (auth.resetPassword(username, newPassword)) {
			statusLabel->setText("密码已重置");
		}
		else {
			QMessageBox::critical(this, "错误", "密码重置失败！");
		}
	}
}

void UserManagementUI::onDeleteSelected() {
	if (!auth.hasPermission(UserAuth::Admin)) {
		QMessageBox::warning(this, "权限不足", "只有管理员可以批量删除用户！");
		return;
	}

	QList<QString> selectedUsers = getSelectedUsers();
	if (selectedUsers.isEmpty()) {
		QMessageBox::information(this, "提示", "请先在表格中选择要删除的用户！");
		return;
	}

	if (QMessageBox::question(this, "确认删除",
		QString("确定删除选中的 %1 个用户吗？").arg(selectedUsers.size()))
		!= QMessageBox::Yes)
	{
		return;
	}

	int successCount = 0;
	foreach(const QString & username, selectedUsers) {
		if (auth.deleteUser(username)) {
			successCount++;
		}
		else {
			qWarning() << "删除用户失败:" << username;
		}
	}

	statusLabel->showMessage(QString("成功删除 %1/%2 个用户").arg(successCount).arg(selectedUsers.size()), 5000);
	refreshUserList();
}

QList<QString> UserManagementUI::getSelectedUsers() const {
	QList<QString> users;
	foreach(QModelIndex index, userTable->selectionModel()->selectedRows(0)) {
		QString username = userTable->item(index.row(), 0)->text();
		if (username == auth.currentUser()) {
			QMessageBox::warning(this, "错误", "不能删除当前登录用户！");
			return QList<QString>(); // 直接返回空列表，中止操作
		}
		users.append(username);
	}
	return users;
}

void UserManagementUI::onPageChanged(int page) {
	refreshUserList();
}

void UserManagementUI::handleUserUpdate(const QString& username) {
	for (int row = 0; row < userTable->rowCount(); ++row) {
		if (userTable->item(row, 0)->text() == username) {
			UserAuth::UserInfoEx info = auth.getUserInfoEx(username);
			userTable->item(row, 1)->setText(roleToString(info.role));
			userTable->item(row, 2)->setText(info.requiresMFA ? "已启用" : "未启用");
			userTable->item(row, 3)->setText(info.isLocked ? "锁定" : "正常");
			userTable->item(row, 4)->setText(info.lastLoginTime.toString("yyyy-MM-dd hh:mm"));
			break;
		}
	}
}

QString UserManagementUI::roleToString(UserAuth::Role role) const {
	switch (role) {
	case UserAuth::Admin:    return "管理员";
	case UserAuth::Operator: return "操作员";
	default:                 return "访客";
	}
}

void UserManagementUI::onApplyRole() {
	if (!auth.hasPermission(UserAuth::Admin)) {
		QMessageBox::warning(this, "权限不足", "只有管理员可以修改角色！");
		return;
	}

	QList<QString> selectedUsers = getSelectedUsers();
	if (selectedUsers.isEmpty()) {
		QMessageBox::information(this, "提示", "请先选择要修改的用户！");
		return;
	}

	UserAuth::Role newRole = static_cast<UserAuth::Role>(roleCombo->currentData().toInt());
	int successCount = 0;

	foreach(const QString & username, selectedUsers) {
		if (auth.setUserRole(username, newRole)) {
			successCount++;
		}
		else {
			qWarning() << "修改角色失败:" << username;
		}
	}

	statusLabel->showMessage(QString("成功修改%1/%2个用户的角色").arg(successCount).arg(selectedUsers.size()), 5000);
	refreshUserList();
}
