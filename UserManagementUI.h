#ifndef USERMANAGEMENTUI_H
#define USERMANAGEMENTUI_H

#include <QWidget>
#include <QTableWidget>
#include <QToolBar>
#include <QLineEdit>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include "UserAuth.h"
#include "AddUserDialog.h"
#include "EditUserDialog.h"

class UserManagementUI : public QWidget {
	Q_OBJECT

public:
	explicit UserManagementUI(UserAuth& auth, QWidget* parent = nullptr);

private slots:
	void onAddUser();
	void onDeleteUser(const QString& username);
	void onDeleteSelected();
	void onEditUser(const QString& username);
	void onResetPassword(const QString& username); // 新增重置密码槽函数


	void onSearchTextChanged(const QString& text);
	void onPageChanged(int page);
	void refreshUserList();
	void handleUserUpdate(const QString& username);

private:
	void setupUI();
	void setupToolbar();
	void setupTable();
	void setupStatusLabel();
	void setupConnections();
	QList<QString> getSelectedUsers() const;
	QString roleToString(UserAuth::Role role) const;
	void onApplyRole();


	// UI 组件
	QTableWidget* userTable;
	QToolBar* toolBar;
	QLineEdit* searchEdit;
	QSpinBox* pageSpin;
	QLabel* pageLabel;
	QLabel* statusLabel;      // 新增：替代状态栏的标签
	QPushButton* btnAddUser;
	QPushButton* btnRefresh;
	QPushButton* btnDeleteSelected;
	QPushButton* btnPrevPage;
	QPushButton* btnNextPage;
	QComboBox* roleCombo;
	QPushButton* btnApplyRole;

	// 业务逻辑
	UserAuth& auth;
	const int PAGE_SIZE = 20; // 每页显示20条数据
};

#endif // USERMANAGEMENTUI_H
