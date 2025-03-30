#ifndef USERINFODIALOG_H
#define USERINFODIALOG_H

#include <QDialog>
#include <QLabel>
#include <QTableWidget>
#include <QVBoxLayout>
#include "UserAuth.h"

class UserInfoDialog : public QDialog {
	Q_OBJECT

public:
	explicit UserInfoDialog(UserAuth& auth, QWidget* parent = nullptr);

private:
	void setupUI();
	QString roleToString(UserAuth::Role role) const;

	// UI ���
	QLabel* iconLabel;
	QLabel* lblUsername;
	QTableWidget* infoTable;

	// ҵ���߼�����
	UserAuth& auth;
};

#endif // USERINFODIALOG_H
