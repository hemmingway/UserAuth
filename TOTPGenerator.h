
#include <QString>
#include <QDateTime>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QtEndian> // ���ڴ����ת��

class TOTPGenerator {
public:
	static QString generateTOTP(const QByteArray& secretKey, quint64 timestamp = 0, int windowOffset = 0) {
		if (timestamp == 0) {
			timestamp = QDateTime::currentSecsSinceEpoch();
		}
		quint64 timeStep = (timestamp / 30) + windowOffset; // ֧��ʱ�䴰��ƫ��

		// ��ʱ�䲽��ת��Ϊ8�ֽڴ���������
		quint64 timeStepBigEndian = qToBigEndian<quint64>(timeStep);
		QByteArray msg(reinterpret_cast<const char*>(&timeStepBigEndian), sizeof(timeStepBigEndian));

		// ����HMAC-SHA1
		QByteArray hmac = QMessageAuthenticationCode::hash(
			msg,        // ��ȷ��ʱ�䲽������������
			secretKey,  // ֱ��ʹ�ö�������Կ
			QCryptographicHash::Sha1
		);

		// ��̬����ȡ��RFC 6238��׼��
		if (hmac.size() < 20) {
			return QString(); // ��ֹԽ��
		}

		int offset = hmac[hmac.length() - 1] & 0xF;
		quint32 code =
			((hmac[offset] & 0x7F) << 24) |
			((hmac[offset + 1] & 0xFF) << 16) |
			((hmac[offset + 2] & 0xFF) << 8) |
			((hmac[offset + 3] & 0xFF));

		code %= 1000000; // 6λ����
		return QString("%1").arg(code, 6, 10, QLatin1Char('0'));
	}

	// ֧�ִ����ݴ�Ĭ�������1���ڣ�
	static bool validateTOTP(const QByteArray& secretKey, const QString& otp, int allowedWindows = 1) {
		for (int i = -allowedWindows; i <= allowedWindows; i++) {
			if (generateTOTP(secretKey, 0, i) == otp) {
				return true;
			}
		}
		return false;
	}
};
