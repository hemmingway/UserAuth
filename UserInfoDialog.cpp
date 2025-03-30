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
	// ���ڻ�������
	setWindowTitle("�û���Ϣ����");
	setFixedSize(400, 400);
	setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);

	// ======================== ��ȡ�û����� ========================
	UserAuth::UserInfoEx info = auth.getUserInfoEx(auth.currentUser());

	// ======================== UI �����ʼ�� ========================
	// �û�ͼ�꣨������ʾ��
	iconLabel = new QLabel(this);
	iconLabel->setPixmap(QIcon(":/icons/user.png").pixmap(80, 80));
	iconLabel->setAlignment(Qt::AlignCenter);

	// �û�������������ʽ��
	lblUsername = new QLabel(this);
	lblUsername->setText(info.username.isEmpty() ? "δ֪�û�" : info.username);
	lblUsername->setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;");
	lblUsername->setAlignment(Qt::AlignCenter);

	// ��ϸ��Ϣ���
	infoTable = new QTableWidget(this);
	infoTable->setColumnCount(2);
	infoTable->setRowCount(6);
	infoTable->setHorizontalHeaderLabels({ "����", "ֵ" });
	infoTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
	infoTable->verticalHeader()->setVisible(false);
	infoTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
	infoTable->setSelectionMode(QAbstractItemView::NoSelection);
	infoTable->setShowGrid(false);

	// ���������
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

	addTableRow(0, "��ɫ", roleToString(info.role));
	addTableRow(1, "MFA ״̬", info.requiresMFA ? "������" : "δ����");
	addTableRow(2, "�˻�״̬", info.isLocked ? "����" : "����", info.isLocked);
	addTableRow(3, "����¼", info.lastLoginTime.isValid() ? info.lastLoginTime.toString("yyyy-MM-dd hh:mm") : "��δ��¼");
	addTableRow(4, "����ʱ��", info.accountCreatedTime.toString("yyyy-MM-dd"));
	addTableRow(5, "�����޸�ʱ��", info.passwordLastChanged.toString("yyyy-MM-dd"));

	// ======================== ���ֹ��� ========================
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->addWidget(iconLabel);
	mainLayout->addSpacing(10);
	mainLayout->addWidget(lblUsername);
	mainLayout->addSpacing(15);
	mainLayout->addWidget(infoTable);
	mainLayout->addStretch();

	// ��������и�
	for (int i = 0; i < infoTable->rowCount(); ++i) {
		infoTable->setRowHeight(i, 30);
	}
}

QString UserInfoDialog::roleToString(UserAuth::Role role) const {
	switch (role) {
	case UserAuth::Admin:    return "����Ա";
	case UserAuth::Operator: return "����Ա";
	default:                 return "�ÿ�";
	}
}
