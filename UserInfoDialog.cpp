#include "UserInfoDialog.h"
#include <QHeaderView>
#include <QIcon>
#include <QDateTime>
#include <QBrush>
#include <QDebug>

UserInfoDialog::UserInfoDialog(UserAuth& auth, QWidget* parent)
	: QDialog(parent), auth(auth) {
	setupUI();
}

void UserInfoDialog::setupUI() {
	// 窗口基础设置
	setWindowTitle("用户信息详情");
	setFixedSize(400, 400);
	setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);

	// ======================== 获取用户数据 ========================
	UserAuth::UserInfoEx info = auth.getUserInfoEx(auth.currentUser());

	// ======================== UI 组件初始化 ========================
	// 用户图标（居中显示）
	iconLabel = new QLabel(this);
	iconLabel->setPixmap(QIcon(":/icons/user.png").pixmap(80, 80));
	iconLabel->setAlignment(Qt::AlignCenter);

	// 用户名（主标题样式）
	lblUsername = new QLabel(this);
	lblUsername->setText(info.username.isEmpty() ? "未知用户" : info.username);
	lblUsername->setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;");
	lblUsername->setAlignment(Qt::AlignCenter);

	// 详细信息表格
	infoTable = new QTableWidget(this);
	infoTable->setColumnCount(2);
	infoTable->setRowCount(6);
	infoTable->setHorizontalHeaderLabels({ "属性", "值" });
	infoTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
	infoTable->verticalHeader()->setVisible(false);
	infoTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
	infoTable->setSelectionMode(QAbstractItemView::NoSelection);
	infoTable->setShowGrid(false);

	// 填充表格数据
	auto addTableRow = [&](int row, const QString& key, const QString& value, bool isWarning = false) {
		QTableWidgetItem* keyItem = new QTableWidgetItem(key);
		QTableWidgetItem* valueItem = new QTableWidgetItem(value);

		keyItem->setForeground(QBrush(Qt::gray));
		if (isWarning) {
			valueItem->setForeground(QBrush(Qt::red));
		}

		infoTable->setItem(row, 0, keyItem);
		infoTable->setItem(row, 1, valueItem);
	};

	addTableRow(0, "角色", roleToString(info.role));
	addTableRow(1, "MFA 状态", info.requiresMFA ? "已启用" : "未启用");
	addTableRow(2, "账户状态", info.isLocked ? "锁定" : "正常", info.isLocked);
	addTableRow(3, "最后登录", info.lastLoginTime.isValid() ? info.lastLoginTime.toString("yyyy-MM-dd hh:mm") : "从未登录");
	addTableRow(4, "创建时间", info.accountCreatedTime.toString("yyyy-MM-dd"));
	addTableRow(5, "密码修改时间", info.passwordLastChanged.toString("yyyy-MM-dd"));

	// ======================== 布局管理 ========================
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->addWidget(iconLabel);
	mainLayout->addSpacing(10);
	mainLayout->addWidget(lblUsername);
	mainLayout->addSpacing(15);
	mainLayout->addWidget(infoTable);
	mainLayout->addStretch();

	// 调整表格行高
	for (int i = 0; i < infoTable->rowCount(); ++i) {
		infoTable->setRowHeight(i, 30);
	}
}

QString UserInfoDialog::roleToString(UserAuth::Role role) const {
	switch (role) {
	case UserAuth::Admin:    return "管理员";
	case UserAuth::Operator: return "操作员";
	default:                 return "访客";
	}
}
