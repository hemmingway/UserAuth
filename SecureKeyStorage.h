
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
		QByteArray encryptedData = loadEncryptedKey(); // ��ʵ����Կ�����߼�

#ifdef Q_OS_WIN
		// Windows DPAPI ʵ��
		DATA_BLOB dataIn = { 0 }, dataOut = { 0 };
		dataIn.pbData = reinterpret_cast<BYTE*>(encryptedData.data());
		dataIn.cbData = encryptedData.size();

		if (CryptUnprotectData(&dataIn, nullptr, nullptr, nullptr, nullptr, 0, &dataOut)) {
			QByteArray result(reinterpret_cast<char*>(dataOut.pbData), dataOut.cbData);
			SecureZeroMemory(dataOut.pbData, dataOut.cbData); // ��ȫ�����ڴ�
			LocalFree(dataOut.pbData);
			return result;
		}
		else {
			SecureZeroMemory(dataIn.pbData, dataIn.cbData); // ������������
			return QByteArray();
		}

#elif defined(Q_OS_LINUX)
		// Linux libsecret ʵ��
		const SecretSchema schema = { "com.medical.auth", SECRET_SCHEMA_NONE };
		GError* error = nullptr;
		gchar* password = secret_password_lookup_sync(&schema, nullptr, &error,
			"key", "auth-key", nullptr);

		QByteArray result;
		if (error) {
			g_error_free(error); // �ͷŴ������
			return result;
		}

		if (password) {
			result = QByteArray(password);
			secret_password_free(password);
		}
		return result;

#else
		// ����ƽ̨������ macOS Keychain��
#error "SecureKeyStorage not implemented for this platform"
#endif
	}

private:
	static QByteArray loadEncryptedKey() {
		// �Ӱ�ȫλ�ã���ע��������ļ���������Կ
		// ʾ��������Ӳ�������ݣ�ʵ�����滻Ϊ��ȫ�����߼���
		return QByteArray::fromHex("...");
	}
};
