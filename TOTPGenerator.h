
#include <QString>
#include <QDateTime>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QtEndian> // 用于大端序转换

class TOTPGenerator {
public:
	static QString generateTOTP(const QByteArray& secretKey, quint64 timestamp = 0, int windowOffset = 0) {
		if (timestamp == 0) {
			timestamp = QDateTime::currentSecsSinceEpoch();
		}
		quint64 timeStep = (timestamp / 30) + windowOffset; // 支持时间窗口偏移

		// 将时间步长转换为8字节大端序二进制
		quint64 timeStepBigEndian = qToBigEndian<quint64>(timeStep);
		QByteArray msg(reinterpret_cast<const char*>(&timeStepBigEndian), sizeof(timeStepBigEndian));

		// 计算HMAC-SHA1
		QByteArray hmac = QMessageAuthenticationCode::hash(
			msg,        // 正确的时间步长二进制输入
			secretKey,  // 直接使用二进制密钥
			QCryptographicHash::Sha1
		);

		// 动态码提取（RFC 6238标准）
		if (hmac.size() < 20) {
			return QString(); // 防止越界
		}

		int offset = hmac[hmac.length() - 1] & 0xF;
		quint32 code =
			((hmac[offset] & 0x7F) << 24) |
			((hmac[offset + 1] & 0xFF) << 16) |
			((hmac[offset + 2] & 0xFF) << 8) |
			((hmac[offset + 3] & 0xFF));

		code %= 1000000; // 6位数字
		return QString("%1").arg(code, 6, 10, QLatin1Char('0'));
	}

	// 支持窗口容错（默认允许±1窗口）
	static bool validateTOTP(const QByteArray& secretKey, const QString& otp, int allowedWindows = 1) {
		for (int i = -allowedWindows; i <= allowedWindows; i++) {
			if (generateTOTP(secretKey, 0, i) == otp) {
				return true;
			}
		}
		return false;
	}
};
