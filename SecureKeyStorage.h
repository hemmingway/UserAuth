
#include <QOperatingSystemVersion>
#ifdef Q_OS_WIN
#include <windows.h>
#include <wincrypt.h>
#elif defined(Q_OS_LINUX)
#include <libsecret/secret.h>
#endif

class SecureKeyStorage {
public:
	static QByteArray getKey() {
		QByteArray encryptedData = loadEncryptedKey(); // 需实现密钥加载逻辑

#ifdef Q_OS_WIN
		// Windows DPAPI 实现
		DATA_BLOB dataIn = { 0 }, dataOut = { 0 };
		dataIn.pbData = reinterpret_cast<BYTE*>(encryptedData.data());
		dataIn.cbData = encryptedData.size();

		if (CryptUnprotectData(&dataIn, nullptr, nullptr, nullptr, nullptr, 0, &dataOut)) {
			QByteArray result(reinterpret_cast<char*>(dataOut.pbData), dataOut.cbData);
			SecureZeroMemory(dataOut.pbData, dataOut.cbData); // 安全擦除内存
			LocalFree(dataOut.pbData);
			return result;
		}
		else {
			SecureZeroMemory(dataIn.pbData, dataIn.cbData); // 清理输入数据
			return QByteArray();
		}

#elif defined(Q_OS_LINUX)
		// Linux libsecret 实现
		const SecretSchema schema = { "com.medical.auth", SECRET_SCHEMA_NONE };
		GError* error = nullptr;
		gchar* password = secret_password_lookup_sync(&schema, nullptr, &error,
			"key", "auth-key", nullptr);

		QByteArray result;
		if (error) {
			g_error_free(error); // 释放错误对象
			return result;
		}

		if (password) {
			result = QByteArray(password);
			secret_password_free(password);
		}
		return result;

#else
		// 其他平台处理（如 macOS Keychain）
#error "SecureKeyStorage not implemented for this platform"
#endif
	}

private:
	static QByteArray loadEncryptedKey() {
		// 从安全位置（如注册表、加密文件）加载密钥
		// 示例：返回硬编码数据（实际需替换为安全加载逻辑）
		return QByteArray::fromHex("...");
	}
};
