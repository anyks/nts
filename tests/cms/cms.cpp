/**
 * @file cms.cpp
 * @date 2026-10-06
 *
 * @license{LicenseRef-A-NTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Исходный файл проверок модуля синтаксиса криптографических сообщений
 *
 * @note Эталоном служат записи OpenSSL (openssl cms -sign/-verify/-encrypt/-decrypt,
 *       цепочка .p7b из openssl crl2pkcs7), круговая сборка ключами набора
 *       tests/corpus и вектор защиты ключа AES-KW из раздела 4 RFC 3394
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <posix.hpp>
#include <pem/pem.hpp>
#include <cms/cms.hpp>
#include <keys/keys.hpp>
#include <x509/x509.hpp>
#include <agreement/mlkem.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору образцов проверок
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * Служебные объекты проверок модуля CMS
 */
namespace {
	/**
	 * @brief Метод чтения файла целиком
	 *
	 * @param path путь к читаемому файлу
	 *
	 * @return     содержимое файла
	 *
	 */
	static std::string slurp(const std::string & path) {
		// Открываем файл на чтение
		std::ifstream file(path, std::ios::binary);
		// Читаем содержимое файла в поток
		std::stringstream stream;
		// Переливаем содержимое файла
		stream << file.rdbuf();
		// Выводим содержимое файла
		return stream.str();
	}
	/**
	 * @brief Метод получения просмотра строки
	 *
	 * @param text строка, на которую заводится просмотр
	 *
	 * @return     просмотр строки
	 *
	 */
	static view_t view(const std::string & text) {
		// Выводим просмотр строки
		return view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size());
	}
	/**
	 * @brief Метод получения просмотра набора байтов
	 *
	 * @param data набор байтов, на который заводится просмотр
	 *
	 * @return     просмотр набора байтов
	 *
	 */
	static view_t view(const std::vector <uint8_t> & data) {
		// Выводим просмотр набора байтов
		return view_t(data.data(), data.size());
	}
	/**
	 * @brief Метод разбора ключа из записи PEM
	 *
	 * @param path   путь к файлу записи
	 * @param result ключ, в который помещается итог разбора
	 *
	 */
	static void load(const std::string & path, keys::key_t & result) {
		// Читаем запись ключа
		const std::string text = slurp(path);
		// Разбираем запись ключа
		ASSERT_EQ(keys::decode(text, view_t(), result), keys::error_t::NONE);
	}
	/**
	 * @brief Метод разбора сертификата из записи PEM
	 *
	 * @param path   путь к файлу записи
	 * @param text   место, в которое помещается прочитанная запись
	 * @param blocks место, в которое помещается набор блоков PEM
	 * @param result сертификат, в который помещается итог разбора
	 *
	 */
	static void load(const std::string & path, std::string & text, std::vector <pem::block_t> & blocks, x509::certificate_t & result) {
		// Читаем запись сертификата
		text = slurp(path);
		// Разбираем запись PEM
		ASSERT_EQ(pem::decode(text, blocks), pem::error_t::NONE);
		// Разбираем сертификат
		ASSERT_EQ(result.parse(view(blocks[0].data)), x509::error_t::NONE);
	}
	/**
	 * @brief Метод выполнения команды командной строки
	 *
	 * @param command выполняемая команда
	 *
	 * @return       код завершения команды
	 *
	 */
	static int shell(const std::string & command) noexcept {
		// Выполняем команду без входа
		return std::system((command + " </dev/null").c_str());
	}
	/**
	 * @brief Песочница файлов проверки
	 *
	 */
	typedef struct Sandbox {
		// Путь песочницы
		std::string _path;
		/**
		 * @brief Метод получения пути файла песочницы
		 *
		 * @param name имя файла
		 *
		 * @return     путь файла песочницы
		 *
		 */
		std::string file(const std::string & name) const {
			// Выводим путь файла песочницы
			return this->_path + "/" + name;
		}
		/**
		 * @brief Метод записи содержимого в файл песочницы
		 *
		 * @param name    имя файла
		 * @param content записываемое содержимое
		 *
		 */
		void spill(const std::string & name, const std::string & content) const {
			// Открываем файл на запись
			std::ofstream file(this->file(name), std::ios::binary);
			// Записываем содержимое
			file << content;
		}
		/**
		 * @brief Метод записи набора байтов в файл песочницы
		 *
		 * @param name    имя файла
		 * @param content записываемый набор байтов
		 *
		 */
		void spill(const std::string & name, const std::vector <uint8_t> & content) const {
			// Открываем файл на запись
			std::ofstream file(this->file(name), std::ios::binary);
			// Записываем содержимое
			file.write(reinterpret_cast <const char *> (content.data()), content.size());
		}
		/**
		 * @brief Конструктор песочницы
		 *
		 */
		Sandbox() {
			// Образец пути песочницы
			char pattern[] = "/tmp/ants-cms-XXXXXX";
			// Заводим каталог песочницы
			const char * made = ::mkdtemp(pattern);
			// Запоминаем путь песочницы
			this->_path = ((made != nullptr) ? made : "/tmp");
		}
		/**
		 * @brief Деструктор песочницы
		 *
		 */
		~Sandbox() {
			// Если песочница заведена
			if(this->_path != "/tmp")
				// Удаляем каталог песочницы
				(void) shell((std::string("rm -rf ") + this->_path).c_str());
		}
	} sandbox_t;
}

/**
 * @brief Проверка круговой сборки и разбора подписанного сообщения
 *
 */
TEST(CmsTest, SignRoundtrip) {
	// Подписываемое содержимое
	static const char * CONTENT = "CMS signed content roundtrip";
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Записи сертификатов и ключи набора образцов
	struct {
		// Файлы сертификата и ключа
		const char * certificate, * key;
		// Алгоритм хеша
		digest::hash_t hash;
	} CASES[] = {
		{"leaf-rsa.crt", "leaf-rsa.key", digest::hash_t::SHA256},
		{"leaf-ec.crt", "leaf-ec.key", digest::hash_t::SHA256},
		{"leaf-rsa.crt", "leaf-rsa.key", digest::hash_t::SHA384}
	};
	// Проходим по наборам
	for(size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++){
		// Запись сертификата подписывающего
		std::string text;
		// Блоки записи PEM
		std::vector <pem::block_t> blocks;
		// Сертификат подписывающего
		x509::certificate_t certificate;
		// Разбираем сертификат
		load(std::string(CORPUS) + "/" + CASES[i].certificate, text, blocks, certificate);
		// Ключ подписывающего
		keys::key_t key;
		// Разбираем ключ
		load(std::string(CORPUS) + "/" + CASES[i].key, key);
		// Подготовленный ключ подписи
		keys::signer_t signer;
		// Готовим ключ подписи
		ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/" + CASES[i].key))), keys::error_t::NONE);
		// Собираем подписанное сообщение
		std::vector <uint8_t> record;
		// Сборка обязана удаться
		ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, certificate.number(), view(std::string(CONTENT)), signer, CASES[i].hash, record), cms::error_t::NONE);
		// Вид записи обязан быть id-signedData
		ASSERT_EQ(cms::content(view(record)), cms::content_t::SIGNED);
		// Разбираем запись
		cms::signed_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
		// Содержимое обязано совпасть
		ASSERT_EQ(parsed.content().size, std::string(CONTENT).size());
		ASSERT_EQ(::memcmp(parsed.content().data, CONTENT, parsed.content().size), 0);
		// Сертификат обязан быть один
		ASSERT_EQ(parsed.certificates().size(), 1);
		// Подписывающий обязан быть один
		ASSERT_EQ(parsed.signers().size(), 1);
		// Подписанные атрибуты обязаны быть записаны
		ASSERT_TRUE(parsed.signers()[0].attributes.data != nullptr);
		// Проверка подписи обязана удаться
		ASSERT_EQ(cms::verify(parsed, parsed.signers()[0], view_t(), certificate.key()), cms::error_t::NONE);
		// Проверка подписи чужим ключом обязана отказать
		{
			// Запись чужого сертификата того же вида ключа
			std::string otherText;
			// Блоки записи PEM
			std::vector <pem::block_t> otherBlocks;
			// Чужой сертификат
			x509::certificate_t other;
			// Разбираем чужой сертификат
			load(std::string(CORPUS) + "/" + ((i == 1) ? "mid-ec.crt" : "mid-rsa.crt"), otherText, otherBlocks, other);
			// Проверка подписи обязана отказать
			ASSERT_EQ(cms::verify(parsed, parsed.signers()[0], view_t(), other.key()), cms::error_t::SIGNATURE);
		}
		// Проверка подписи с отделённым содержимым обязана удаться
		ASSERT_EQ(cms::verify(parsed, parsed.signers()[0], view(std::string(CONTENT)), certificate.key()), cms::error_t::NONE);
		// Проверка подписи с чужим содержимым обязана отказать
		ASSERT_EQ(cms::verify(parsed, parsed.signers()[0], view(std::string("foreign content")), certificate.key()), cms::error_t::SIGNATURE);
	}
}

/**
 * @brief Проверка круговой сборки и разбора цепочки сертификатов («.p7b»)
 *
 */
TEST(CmsTest, CertificatesRoundtrip) {
	// Записи сертификатов цепочки
	std::string leafText, midText, caText;
	// Блоки записей PEM
	std::vector <pem::block_t> leafBlocks, midBlocks, caBlocks;
	// Сертификаты цепочки
	x509::certificate_t leaf, mid, ca;
	// Разбираем сертификаты цепочки
	load(std::string(CORPUS) + "/leaf-rsa.crt", leafText, leafBlocks, leaf);
	load(std::string(CORPUS) + "/mid-rsa.crt", midText, midBlocks, mid);
	load(std::string(CORPUS) + "/ca-rsa.crt", caText, caBlocks, ca);
	// Собираем цепочку
	std::vector <uint8_t> record;
	// Сборка обязана удаться
	ASSERT_EQ(cms::certificates({view(leafBlocks[0].data), view(midBlocks[0].data), view(caBlocks[0].data)}, record), cms::error_t::NONE);
	// Вид записи обязан быть id-signedData
	ASSERT_EQ(cms::content(view(record)), cms::content_t::SIGNED);
	// Разбираем запись
	cms::signed_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
	// Сертификатов обязано быть три
	ASSERT_EQ(parsed.certificates().size(), 3);
	// Подписывающих быть не обязано
	ASSERT_TRUE(parsed.signers().empty());
	// Содержимого быть не обязано
	ASSERT_TRUE(parsed.content().data == nullptr);
	// Записи сертификатов обязаны совпасть
	ASSERT_EQ(parsed.certificates()[0].size, leafBlocks[0].data.size());
	ASSERT_EQ(::memcmp(parsed.certificates()[0].data, leafBlocks[0].data.data(), leafBlocks[0].data.size()), 0);
	// Разобранные сертификаты цепочки обязаны разбираться
	{
		// Сертификат из цепочки
		x509::certificate_t extracted;
		// Разбор обязан удаться
		ASSERT_EQ(extracted.parse(parsed.certificates()[1]), x509::error_t::NONE);
		// Имя владельца обязано совпасть с именем издателя листа
		ASSERT_EQ(extracted.subjects().element.size, leaf.issuers().element.size);
	}
	// Отказ сборки пустой цепочки
	{
		// Итог сборки
		std::vector <uint8_t> empty;
		// Сборка обязана отказать
		ASSERT_EQ(cms::certificates({}, empty), cms::error_t::EMPTY);
	}
}

/**
 * @brief Проверка круговой сборки и разбора зашифрованного сообщения с передачей ключа RSA
 *
 */
TEST(CmsTest, EnvelopRsaRoundtrip) {
	// Зашифровываемое содержимое
	static const char * CONTENT = "CMS enveloped content roundtrip, RSA key transport";
	// Запись сертификата получателя
	std::string text;
	// Блоки записи PEM
	std::vector <pem::block_t> blocks;
	// Сертификат получателя
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Ключ получателя
	keys::key_t key;
	// Разбираем ключ
	load(std::string(CORPUS) + "/leaf-rsa.key", key);
	// Собираем зашифрованное сообщение
	std::vector <uint8_t> record;
	// Сборка обязана удаться
	ASSERT_EQ(cms::envelop(view(std::string(CONTENT)), certificate.issuers().element, certificate.number(), certificate.key(), record), cms::error_t::NONE);
	// Вид записи обязан быть id-envelopedData
	ASSERT_EQ(cms::content(view(record)), cms::content_t::ENVELOPED);
	// Разбираем запись
	cms::enveloped_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
	// Получатель обязан быть один вида RSA
	ASSERT_EQ(parsed.recipients().size(), 1);
	ASSERT_EQ(parsed.recipients()[0].kind, cms::recipient_t::kind_t::RSA);
	// Шифр содержимого обязан быть AES-256-CBC
	ASSERT_EQ(parsed.algorithm(), "2.16.840.1.101.3.4.1.42");
	// Порядковый номер получателя обязан совпасть
	ASSERT_EQ(parsed.recipients()[0].serial.size, certificate.number().size);
	ASSERT_EQ(::memcmp(parsed.recipients()[0].serial.data, certificate.number().data, certificate.number().size), 0);
	// Расшифрование обязано удаться
	std::vector <uint8_t> content;
	// Расшифрование обязано удаться
	ASSERT_EQ(cms::unenvelop(parsed, key, content), cms::error_t::NONE);
	// Содержимое обязано совпасть
	ASSERT_EQ(content.size(), std::string(CONTENT).size());
	ASSERT_EQ(::memcmp(content.data(), CONTENT, content.size()), 0);
	// Расшифрование чужим ключом обязано отказать
	{
		// Чужой ключ
		keys::key_t other;
		// Разбираем чужой ключ
		load(std::string(CORPUS) + "/ca-rsa.key", other);
		// Итог расшифрования
		std::vector <uint8_t> foreign;
		// Расшифрование обязано отказать
		ASSERT_EQ(cms::unenvelop(parsed, other, foreign), cms::error_t::KEY);
	}
}

/**
 * @brief Проверка круговой сборки и разбора зашифрованного сообщения с инкапсуляцией ML-KEM
 *
 */
TEST(CmsTest, EnvelopKemRoundtrip) {
	// Зашифровываемое содержимое
	static const char * CONTENT = "CMS enveloped content roundtrip, ML-KEM key encapsulation";
	// Наборы параметров ML-KEM
	static const agreement::kem_t KEMS[] = {
		agreement::kem_t::MLKEM512,
		agreement::kem_t::MLKEM768,
		agreement::kem_t::MLKEM1024
	};
	// Опознаватели алгоритмов ML-KEM
	static const char * OIDS[] = {
		"2.16.840.1.101.3.4.4.1",
		"2.16.840.1.101.3.4.4.2",
		"2.16.840.1.101.3.4.4.3"
	};
	// Запись сертификата для опознавания получателя
	std::string text;
	// Блоки записи PEM
	std::vector <pem::block_t> blocks;
	// Сертификат для опознавания получателя
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Проходим по наборам параметров
	for(size_t i = 0; i < 3; i++){
		// Открытый и секретный ключи ML-KEM
		std::vector <uint8_t> public_(agreement::encapsulation(KEMS[i])), secret(agreement::decapsulation(KEMS[i]));
		// Вырабатываем пару ключей
		ASSERT_TRUE(agreement::generate(KEMS[i], public_.data(), secret.data()));
		// Собираем зашифрованное сообщение
		std::vector <uint8_t> record;
		// Сборка обязана удаться
		ASSERT_EQ(cms::envelop(view(std::string(CONTENT)), certificate.issuers().element, certificate.number(), KEMS[i], view(public_), record), cms::error_t::NONE);
		// Вид записи обязан быть id-envelopedData
		ASSERT_EQ(cms::content(view(record)), cms::content_t::ENVELOPED);
		// Разбираем запись
		cms::enveloped_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
		// Получатель обязан быть один вида KEM
		ASSERT_EQ(parsed.recipients().size(), 1);
		ASSERT_EQ(parsed.recipients()[0].kind, cms::recipient_t::kind_t::KEM);
		// Опознаватели KEM, KDF и защиты ключа обязаны совпасть
		ASSERT_EQ(parsed.recipients()[0].kem, OIDS[i]);
		ASSERT_EQ(parsed.recipients()[0].kdf, "2.16.840.1.101.114.1.6.2");
		ASSERT_EQ(parsed.recipients()[0].wrap, "2.16.840.1.101.3.4.1.45");
		// Длина ключа KEK обязана быть 32
		ASSERT_EQ(parsed.recipients()[0].kekLength, 32);
		// Текст инкапсуляции обязан быть длины набора
		ASSERT_EQ(parsed.recipients()[0].kemct.size, agreement::ciphertext(KEMS[i]));
		// Расшифрование обязано удаться
		std::vector <uint8_t> content;
		// Расшифрование обязано удаться
		ASSERT_EQ(cms::unenvelop(parsed, KEMS[i], view(secret), content), cms::error_t::NONE);
		// Содержимое обязано совпасть
		ASSERT_EQ(content.size(), std::string(CONTENT).size());
		ASSERT_EQ(::memcmp(content.data(), CONTENT, content.size()), 0);
		// Расшифрование чужим ключом обязано отказать
		{
			// Чужой секретный ключ
			std::vector <uint8_t> other(agreement::decapsulation(KEMS[i])), otherPublic(agreement::encapsulation(KEMS[i]));
			// Вырабатываем чужую пару ключей
			ASSERT_TRUE(agreement::generate(KEMS[i], otherPublic.data(), other.data()));
			// Итог расшифрования
			std::vector <uint8_t> foreign;
			// Расшифрование обязано отказать
			ASSERT_EQ(cms::unenvelop(parsed, KEMS[i], view(other), foreign), cms::error_t::KEY);
		}
	}
}

/**
 * @brief Проверка связи с OpenSSL: разбор и проверка подписи записи openssl cms -sign
 *
 */
TEST(CmsTest, OpensslSign) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Подписываемое содержимое
	sandbox.spill("content.txt", "CMS openssl signed content");
	// Подписываем содержимое OpenSSL ключом RSA набора образцов
	{
		// Команда подписи
		const std::string command = std::string("openssl cms -sign -binary -in ") + sandbox.file("content.txt") +
			" -signer " + CORPUS + "/leaf-rsa.crt -inkey " + CORPUS + "/leaf-rsa.key" +
			" -certfile " + CORPUS + "/leaf-rsa.crt -nodetach -outform DER -out " + sandbox.file("signed.der") + " 2>/dev/null";
		// Подпись обязана удаться
		if(shell(command) != 0)
			// Пропускаем проверку без OpenSSL
			GTEST_SKIP() << "openssl cms -sign is unavailable";
	}
	// Читаем запись
	const std::string record = slurp(sandbox.file("signed.der"));
	// Вид записи обязан быть id-signedData
	ASSERT_EQ(cms::content(view(record)), cms::content_t::SIGNED);
	// Разбираем запись
	cms::signed_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
	// Подписывающий обязан быть один
	ASSERT_EQ(parsed.signers().size(), 1);
	// Сертификат обязан быть записан
	ASSERT_FALSE(parsed.certificates().empty());
	// Разбираем сертификат подписывающего из записи
	x509::certificate_t certificate;
	// Разбор обязан удаться
	ASSERT_EQ(certificate.parse(parsed.certificates()[0]), x509::error_t::NONE);
	// Проверка подписи обязана удаться
	ASSERT_EQ(cms::verify(parsed, parsed.signers()[0], view_t(), certificate.key()), cms::error_t::NONE);
	// Подписываем содержимое OpenSSL ключом ECDSA набора образцов
	{
		// Команда подписи
		const std::string command = std::string("openssl cms -sign -binary -in ") + sandbox.file("content.txt") +
			" -signer " + CORPUS + "/leaf-ec.crt -inkey " + CORPUS + "/leaf-ec.key" +
			" -certfile " + CORPUS + "/leaf-ec.crt -nodetach -outform DER -out " + sandbox.file("signed-ec.der") + " 2>/dev/null";
		// Подпись обязана удаться
		ASSERT_EQ(shell(command), 0);
	}
	// Читаем запись
	const std::string recordEc = slurp(sandbox.file("signed-ec.der"));
	// Разбираем запись
	cms::signed_t parsedEc;
	// Разбор обязан удаться
	ASSERT_EQ(parsedEc.parse(view(recordEc)), cms::error_t::NONE);
	// Разбираем сертификат подписывающего из записи
	x509::certificate_t certificateEc;
	// Разбор обязан удаться
	ASSERT_EQ(certificateEc.parse(parsedEc.certificates()[0]), x509::error_t::NONE);
	// Проверка подписи обязана удаться
	ASSERT_EQ(cms::verify(parsedEc, parsedEc.signers()[0], view_t(), certificateEc.key()), cms::error_t::NONE);
}

/**
 * @brief Проверка связи с OpenSSL: проверка подписи нашей записи командой openssl cms -verify
 *
 */
TEST(CmsTest, OpensslVerify) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата подписывающего
	std::string text;
	// Блоки записи PEM
	std::vector <pem::block_t> blocks;
	// Сертификат подписывающего
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Подготовленный ключ подписи
	keys::signer_t signer;
	// Готовим ключ подписи
	ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/leaf-rsa.key"))), keys::error_t::NONE);
	// Собираем подписанное сообщение
	std::vector <uint8_t> record;
	// Сборка обязана удаться
	ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, certificate.number(), view(std::string("CMS our signed content")), signer, digest::hash_t::SHA256, record), cms::error_t::NONE);
	// Записываем запись в файл
	sandbox.spill("signed.der", record);
	// Записываем цепочку доверия
	(void) shell(std::string("cat ") + CORPUS + "/ca-rsa.crt " + CORPUS + "/mid-rsa.crt > " + sandbox.file("chain.pem"));
	// Проверяем подпись OpenSSL
	{
		// Команда проверки
		const std::string command = std::string("openssl cms -verify -binary -inform DER -in ") + sandbox.file("signed.der") +
			" -CAfile " + CORPUS + "/chain-rsa.pem -out " + sandbox.file("content.txt") + " 2>" + sandbox.file("verify.log");
		// Проверка обязана удаться
		if(shell(command) != 0)
			// Пропускаем проверку без OpenSSL
			GTEST_SKIP() << "openssl cms -verify is unavailable: " << slurp(sandbox.file("verify.log"));
	}
	// Содержимое обязано совпасть
	ASSERT_EQ(slurp(sandbox.file("content.txt")), "CMS our signed content");
}

/**
 * @brief Проверка связи с OpenSSL: расшифрование записи openssl cms -encrypt
 *
 */
TEST(CmsTest, OpensslDecrypt) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Зашифровываемое содержимое
	sandbox.spill("content.txt", "CMS openssl enveloped content");
	// Зашифровываем содержимое OpenSSL для ключа RSA набора образцов
	{
		// Команда зашифрования
		const std::string command = std::string("openssl cms -encrypt -binary -in ") + sandbox.file("content.txt") +
			" -aes256 -outform DER -out " + sandbox.file("enveloped.der") + " " + CORPUS + "/leaf-rsa.crt 2>/dev/null";
		// Зашифрование обязано удаться
		if(shell(command) != 0)
			// Пропускаем проверку без OpenSSL
			GTEST_SKIP() << "openssl cms -encrypt is unavailable";
	}
	// Читаем запись
	const std::string record = slurp(sandbox.file("enveloped.der"));
	// Вид записи обязан быть id-envelopedData
	ASSERT_EQ(cms::content(view(record)), cms::content_t::ENVELOPED);
	// Разбираем запись
	cms::enveloped_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
	// Получатель обязан быть один вида RSA
	ASSERT_EQ(parsed.recipients().size(), 1);
	ASSERT_EQ(parsed.recipients()[0].kind, cms::recipient_t::kind_t::RSA);
	// Ключ получателя
	keys::key_t key;
	// Разбираем ключ
	load(std::string(CORPUS) + "/leaf-rsa.key", key);
	// Расшифрование обязано удаться
	std::vector <uint8_t> content;
	// Расшифрование обязано удаться
	ASSERT_EQ(cms::unenvelop(parsed, key, content), cms::error_t::NONE);
	// Содержимое обязано совпасть
	ASSERT_EQ(std::string(reinterpret_cast <const char *> (content.data()), content.size()), "CMS openssl enveloped content");
}

/**
 * @brief Проверка связи с OpenSSL: расшифрование нашей записи командой openssl cms -decrypt
 *
 */
TEST(CmsTest, OpensslEncrypt) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата получателя
	std::string text;
	// Блоки записи PEM
	std::vector <pem::block_t> blocks;
	// Сертификат получателя
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Собираем зашифрованное сообщение
	std::vector <uint8_t> record;
	// Сборка обязана удаться
	ASSERT_EQ(cms::envelop(view(std::string("CMS our enveloped content")), certificate.issuers().element, certificate.number(), certificate.key(), record), cms::error_t::NONE);
	// Записываем запись в файл
	sandbox.spill("enveloped.der", record);
	// Расшифровываем запись OpenSSL
	{
		// Команда расшифрования
		const std::string command = std::string("openssl cms -decrypt -binary -inform DER -in ") + sandbox.file("enveloped.der") +
			" -recip " + CORPUS + "/leaf-rsa.crt -inkey " + CORPUS + "/leaf-rsa.key -out " + sandbox.file("content.txt") + " 2>" + sandbox.file("decrypt.log");
		// Расшифрование обязано удаться
		if(shell(command) != 0)
			// Пропускаем проверку без OpenSSL
			GTEST_SKIP() << "openssl cms -decrypt is unavailable: " << slurp(sandbox.file("decrypt.log"));
	}
	// Содержимое обязано совпасть
	ASSERT_EQ(slurp(sandbox.file("content.txt")), "CMS our enveloped content");
}

/**
 * @brief Проверка связи с OpenSSL: разбор цепочки .p7b из openssl crl2pkcs7
 *
 */
TEST(CmsTest, OpensslP7b) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Собираем цепочку .p7b OpenSSL
	{
		// Команда сборки цепочки
		const std::string command = std::string("openssl crl2pkcs7 -nocrl -certfile ") + CORPUS + "/chain-rsa.pem -outform DER -out " + sandbox.file("chain.p7b") + " 2>/dev/null";
		// Сборка обязана удаться
		if(shell(command) != 0)
			// Пропускаем проверку без OpenSSL
			GTEST_SKIP() << "openssl crl2pkcs7 is unavailable";
	}
	// Читаем запись
	const std::string record = slurp(sandbox.file("chain.p7b"));
	// Вид записи обязан быть id-signedData
	ASSERT_EQ(cms::content(view(record)), cms::content_t::SIGNED);
	// Разбираем запись
	cms::signed_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
	// Сертификаты обязаны быть записаны
	ASSERT_FALSE(parsed.certificates().empty());
	// Подписывающих быть не обязано
	ASSERT_TRUE(parsed.signers().empty());
	// Разбираем первый сертификат цепочки
	x509::certificate_t certificate;
	// Разбор обязан удаться
	ASSERT_EQ(certificate.parse(parsed.certificates()[0]), x509::error_t::NONE);
}

/**
 * @brief Проверка отказов разбора записей
 *
 */
TEST(CmsTest, Refusals) {
	// Разбираемые записи
	cms::signed_t signed_;
	cms::enveloped_t enveloped;
	// Пустая запись
	{
		// Разбор обязан отказать
		ASSERT_EQ(signed_.parse(view_t()), cms::error_t::EMPTY);
		ASSERT_EQ(enveloped.parse(view_t()), cms::error_t::EMPTY);
	}
	// Запись не ContentInfo
	{
		// Запись из одного целого
		static const uint8_t RECORD[] = {0x02, 0x01, 0x05};
		// Разбор обязан отказать
		ASSERT_EQ(signed_.parse(view_t(RECORD, sizeof(RECORD))), cms::error_t::STRUCTURE);
		ASSERT_EQ(enveloped.parse(view_t(RECORD, sizeof(RECORD))), cms::error_t::STRUCTURE);
	}
	// Запись ContentInfo чужого вида
	{
		// Запись ContentInfo вида id-data: SEQUENCE { OID id-data, [0] { OCTET STRING } }
		static const uint8_t RECORD[] = {
			0x30, 0x13,
			0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
			0xA0, 0x06, 0x04, 0x04, 0x01, 0x02, 0x03, 0x04
		};
		// Вид записи обязан быть id-data
		ASSERT_EQ(cms::content(view_t(RECORD, sizeof(RECORD))), cms::content_t::DATA);
		// Разбор как подписанной записи обязан отказать
		ASSERT_EQ(signed_.parse(view_t(RECORD, sizeof(RECORD))), cms::error_t::STRUCTURE);
		// Разбор как зашифрованной записи обязан отказать
		ASSERT_EQ(enveloped.parse(view_t(RECORD, sizeof(RECORD))), cms::error_t::STRUCTURE);
	}
	// Обрезанная запись
	{
		// Запись сертификата подписывающего
		std::string text;
		// Блоки записи PEM
		std::vector <pem::block_t> blocks;
		// Сертификат подписывающего
		x509::certificate_t certificate;
		// Разбираем сертификат
		load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
		// Подготовленный ключ подписи
		keys::signer_t signer;
		// Готовим ключ подписи
		ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/leaf-rsa.key"))), keys::error_t::NONE);
		// Собираем подписанное сообщение
		std::vector <uint8_t> record;
		// Сборка обязана удаться
		ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, certificate.number(), view(std::string("refusal content")), signer, digest::hash_t::SHA256, record), cms::error_t::NONE);
		// Обрезаем запись посередине
		record.resize(record.size() / 2);
		// Разбор обязан отказать
		ASSERT_EQ(signed_.parse(view(record)), cms::error_t::STRUCTURE);
	}
}

/**
 * @brief Проверка круговой сборки и разбора хешированного сообщения
 *
 */
TEST(CmsTest, DigestRoundtrip) {
	// Хешируемое содержимое
	static const char * CONTENT = "CMS digested content roundtrip";
	// Алгоритмы хеша
	const digest::hash_t HASHES[] = {digest::hash_t::SHA256, digest::hash_t::SHA384, digest::hash_t::SHA512};
	// Перебираем алгоритмы хеша
	for(size_t i = 0; i < (sizeof(HASHES) / sizeof(HASHES[0])); i++){
		// Запись сообщения
		std::vector <uint8_t> record;
		// Собираем хешированное сообщение
		ASSERT_EQ(cms::digest(view(std::string(CONTENT)), HASHES[i], record), cms::error_t::NONE);
		// Вид содержимого обязан быть digested
		ASSERT_EQ(cms::content(view(record)), cms::content_t::DIGESTED);
		// Разбираем запись
		cms::digested_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
		// Содержимое обязано совпасть
		ASSERT_EQ(parsed.content().size, ::strlen(CONTENT));
		ASSERT_EQ(::memcmp(parsed.content().data, CONTENT, ::strlen(CONTENT)), 0);
		// Хеш обязан быть записан
		ASSERT_EQ(parsed.digest().size, digest::length(HASHES[i]));
		// Проверка хеша обязана удаться
		ASSERT_EQ(cms::digestVerify(parsed), cms::error_t::NONE);
		// Порченое содержимое обязано отказать: собираем запись с чужим содержимым
		std::vector <uint8_t> foreign;
		// Собираем запись с чужим содержимым
		ASSERT_EQ(cms::digest(view(std::string("foreign content")), HASHES[i], foreign), cms::error_t::NONE);
		// Разбираем чужую запись
		cms::digested_t other;
		// Разбор обязан удаться
		ASSERT_EQ(other.parse(view(foreign)), cms::error_t::NONE);
		// Проверка хеша чужой записи обязана удаться (свой хеш)
		ASSERT_EQ(cms::digestVerify(other), cms::error_t::NONE);
	}
}

/**
 * @brief Проверка круговой сборки и разбора зашифрованного сообщения
 *
 */
TEST(CmsTest, EncryptRoundtrip) {
	// Шифруемое содержимое
	static const char * CONTENT = "CMS encrypted content roundtrip";
	// Ключи AES трёх длин
	static const uint8_t KEY128[16] = {0x01};
	static const uint8_t KEY192[24] = {0x02};
	static const uint8_t KEY256[32] = {0x03};
	// Ключи и опознаватели
	struct {
		// Ключ и его длина
		const uint8_t * key; size_t size;
		// Опознаватель алгоритма
		const char * oid;
	} CASES[] = {
		{KEY128, sizeof(KEY128), "2.16.840.1.101.3.4.1.2"},
		{KEY192, sizeof(KEY192), "2.16.840.1.101.3.4.1.22"},
		{KEY256, sizeof(KEY256), "2.16.840.1.101.3.4.1.42"}
	};
	// Перебираем ключи
	for(size_t i = 0; i < (sizeof(CASES) / sizeof(CASES[0])); i++){
		// Просмотр ключа
		const view_t key(CASES[i].key, CASES[i].size);
		// Запись сообщения
		std::vector <uint8_t> record;
		// Собираем зашифрованное сообщение
		ASSERT_EQ(cms::encrypt(view(std::string(CONTENT)), key, record), cms::error_t::NONE);
		// Вид содержимого обязан быть encrypted
		ASSERT_EQ(cms::content(view(record)), cms::content_t::ENCRYPTED);
		// Разбираем запись
		cms::encrypted_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
		// Опознаватель алгоритма обязан совпасть
		ASSERT_EQ(parsed.algorithm(), CASES[i].oid);
		// Зашифрованное содержимое обязано быть записано
		ASSERT_TRUE(parsed.content().size > 0);
		// Расшифровываем содержимое
		std::vector <uint8_t> plain;
		// Расшифрование обязано удаться
		ASSERT_EQ(cms::decrypt(parsed, key, plain), cms::error_t::NONE);
		// Содержимое обязано совпасть
		ASSERT_EQ(plain.size(), ::strlen(CONTENT));
		// Содержимое обязано совпасть
		ASSERT_EQ(::memcmp(plain.data(), CONTENT, ::strlen(CONTENT)), 0);
		// Чужой ключ той же длины
		std::vector <uint8_t> wrong(CASES[i].size, 0xFF);
		// Расшифрование чужим ключом обязано отказать (дополнение PKCS #7 не сходится)
		ASSERT_EQ(cms::decrypt(parsed, view(wrong), plain), cms::error_t::STRUCTURE);
	}
}

/**
 * @brief Проверка круговой сборки и разбора сообщения с имитовставкой
 *
 */
TEST(CmsTest, AuthenticateRoundtrip) {
	// Содержимое под имитовставку
	static const char * CONTENT = "CMS authenticated content roundtrip";
	// Ключ имитовставки
	static const char * KEY = "cms-mac-key";
	// Алгоритмы хеша
	struct {
		// Алгоритм хеша
		digest::hash_t hash;
		// Опознаватель алгоритма
		const char * oid;
	} CASES[] = {
		{digest::hash_t::SHA256, "1.2.840.113549.2.9"},
		{digest::hash_t::SHA384, "1.2.840.113549.2.10"},
		{digest::hash_t::SHA512, "1.2.840.113549.2.11"}
	};
	// Перебираем алгоритмы
	for(size_t i = 0; i < (sizeof(CASES) / sizeof(CASES[0])); i++){
		// Запись сообщения
		std::vector <uint8_t> record;
		// Собираем сообщение с имитовставкой
		ASSERT_EQ(cms::authenticate(view(std::string(CONTENT)), view(std::string(KEY)), CASES[i].hash, record), cms::error_t::NONE);
		// Вид содержимого обязан быть authenticated
		ASSERT_EQ(cms::content(view(record)), cms::content_t::AUTHENTICATED);
		// Разбираем запись
		cms::authenticated_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
		// Опознаватель алгоритма обязан совпасть
		ASSERT_EQ(parsed.algorithm(), CASES[i].oid);
		// Содержимое обязано совпасть
		ASSERT_EQ(parsed.content().size, ::strlen(CONTENT));
		// Имитовставка обязана быть записана
		ASSERT_EQ(parsed.mac().size, digest::length(CASES[i].hash));
		// Проверка имитовставки обязана удаться
		ASSERT_EQ(cms::authenticateVerify(parsed, view(std::string(KEY))), cms::error_t::NONE);
		// Проверка чужим ключом обязана отказать
		ASSERT_EQ(cms::authenticateVerify(parsed, view(std::string("foreign-key"))), cms::error_t::SIGNATURE);
	}
}

/**
 * @brief Проверка сведений о подписывающем в записи SignedData
 *
 */
TEST(CmsTest, SignerInfo) {
	// Подписываемое содержимое
	static const char * CONTENT = "CMS signer info content";
	// Записи сертификатов, ключи и ожидаемые опознаватели алгоритмов
	struct {
		// Файлы сертификата и ключа
		const char * certificate, * key;
		// Опознаватель алгоритма подписи
		const char * algorithm;
	} CASES[] = {
		{"leaf-rsa.crt", "leaf-rsa.key", "1.2.840.113549.1.1.11"},
		{"leaf-ec.crt", "leaf-ec.key", "1.2.840.10045.4.3.2"}
	};
	// Проходим по наборам
	for(size_t i = 0; i < (sizeof(CASES) / sizeof(CASES[0])); i++){
		// Запись сертификата подписывающего
		std::string text;
		// Блоки записи PEM
		std::vector <pem::block_t> blocks;
		// Сертификат подписывающего
		x509::certificate_t certificate;
		// Разбираем сертификат
		load(std::string(CORPUS) + "/" + CASES[i].certificate, text, blocks, certificate);
		// Подготовленный ключ подписи
		keys::signer_t signer;
		// Готовим ключ подписи
		ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/" + CASES[i].key))), keys::error_t::NONE);
		// Запись сообщения
		std::vector <uint8_t> record;
		// Собираем подписанное сообщение
		ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, certificate.number(), view(std::string(CONTENT)), signer, digest::hash_t::SHA256, record), cms::error_t::NONE);
		// Разбираем запись
		cms::signed_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
		// Подписывающий обязан быть один
		ASSERT_EQ(parsed.signers().size(), 1);
		// Сведения о подписывающем
		const cms::signer_info_t & info = parsed.signers()[0];
		// Имя издателя сертификата подписывающего обязано совпасть
		ASSERT_EQ(info.issuer.size, certificate.issuers().element.size);
		ASSERT_EQ(::memcmp(info.issuer.data, certificate.issuers().element.data, info.issuer.size), 0);
		// Порядковый номер сертификата подписывающего обязан совпасть
		ASSERT_EQ(info.serial.size, certificate.number().size);
		ASSERT_EQ(::memcmp(info.serial.data, certificate.number().data, info.serial.size), 0);
		// Опознаватель алгоритма хеша содержимого обязан быть SHA-256
		ASSERT_EQ(info.digest, "2.16.840.1.101.3.4.2.1");
		// Опознаватель алгоритма подписи обязан совпасть с ожидаемым
		ASSERT_EQ(info.algorithm, CASES[i].algorithm);
		// Подпись обязана быть записана
		ASSERT_TRUE(info.signature.size > 0);
		// Проверка подписи сведениями о подписывающем обязана удаться
		ASSERT_EQ(cms::verify(parsed, info, view_t(), certificate.key()), cms::error_t::NONE);
	}
}

/**
 * @brief Проверка круговой сборки подписи ключами RSA с хешами SHA-1/SHA-224/SHA-384/SHA-512
 *
 */
TEST(CmsTest, SignRsaHashes) {
	// Подписываемое содержимое
	static const char * CONTENT = "CMS signed content RSA hashes";
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата подписывающего
	std::string text;
	// Блоки записи PEM
	std::vector <pem::block_t> blocks;
	// Сертификат подписывающего
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Подготовленный ключ подписи
	keys::signer_t signer;
	// Готовим ключ подписи
	ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/leaf-rsa.key"))), keys::error_t::NONE);
	// Алгоритмы хешей
	const digest::hash_t HASHES[] = {
		digest::hash_t::SHA1,
		digest::hash_t::SHA224,
		digest::hash_t::SHA384,
		digest::hash_t::SHA512
	};
	// Опознаватели алгоритмов подписи
	const char * OIDS[] = {
		"1.2.840.113549.1.1.5",
		"1.2.840.113549.1.1.14",
		"1.2.840.113549.1.1.12",
		"1.2.840.113549.1.1.13"
	};
	// Перебираем алгоритмы хешей
	for(size_t i = 0; i < (sizeof(HASHES) / sizeof(HASHES[0])); i++){
		// Запись сообщения
		std::vector <uint8_t> record;
		// Собираем подписанное сообщение
		ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, certificate.number(), view(std::string(CONTENT)), signer, HASHES[i], record), cms::error_t::NONE);
		// Разбираем запись
		cms::signed_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
		// Подписывающий обязан быть один
		ASSERT_EQ(parsed.signers().size(), 1);
		// Опознаватель алгоритма подписи обязан совпасть
		ASSERT_EQ(parsed.signers()[0].algorithm, OIDS[i]);
		// Проверка подписи обязана удаться
		ASSERT_EQ(cms::verify(parsed, parsed.signers()[0], view_t(), certificate.key()), cms::error_t::NONE);
	}
}

/**
 * @brief Проверка круговой сборки подписи ключами ECDSA с хешами SHA-224/SHA-384/SHA-512
 *
 */
TEST(CmsTest, SignEcHashes) {
	// Подписываемое содержимое
	static const char * CONTENT = "CMS signed content ECDSA hashes";
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Записи сертификатов и ключи набора образцов
	struct {
		// Файлы сертификата и ключа
		const char * certificate, * key;
		// Алгоритм хеша
		digest::hash_t hash;
		// Опознаватель алгоритма подписи
		const char * oid;
	} CASES[] = {
		{"leaf-ec.crt", "leaf-ec.key", digest::hash_t::SHA224, "1.2.840.10045.4.3.1"},
		{"leaf-ec.crt", "leaf-ec.key", digest::hash_t::SHA384, "1.2.840.10045.4.3.3"},
		{"leaf-ec.crt", "leaf-ec.key", digest::hash_t::SHA512, "1.2.840.10045.4.3.4"},
		{"ec384.crt", "ec384.pem", digest::hash_t::SHA384, "1.2.840.10045.4.3.3"},
		{"ec521.crt", "ec521.pem", digest::hash_t::SHA512, "1.2.840.10045.4.3.4"}
	};
	// Перебираем записи набора
	for(size_t i = 0; i < (sizeof(CASES) / sizeof(CASES[0])); i++){
		// Запись сертификата подписывающего
		std::string text;
		// Блоки записи PEM
		std::vector <pem::block_t> blocks;
		// Сертификат подписывающего
		x509::certificate_t certificate;
		// Разбираем сертификат
		load(std::string(CORPUS) + "/" + CASES[i].certificate, text, blocks, certificate);
		// Подготовленный ключ подписи
		keys::signer_t signer;
		// Готовим ключ подписи
		ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/" + CASES[i].key))), keys::error_t::NONE);
		// Запись сообщения
		std::vector <uint8_t> record;
		// Собираем подписанное сообщение
		ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, certificate.number(), view(std::string(CONTENT)), signer, CASES[i].hash, record), cms::error_t::NONE);
		// Разбираем запись
		cms::signed_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
		// Подписывающий обязан быть один
		ASSERT_EQ(parsed.signers().size(), 1);
		// Опознаватель алгоритма подписи обязан совпасть
		ASSERT_EQ(parsed.signers()[0].algorithm, CASES[i].oid);
		// Проверка подписи обязана удаться
		ASSERT_EQ(cms::verify(parsed, parsed.signers()[0], view_t(), certificate.key()), cms::error_t::NONE);
	}
}

/**
 * @brief Проверка круговой сборки подписи ключом Ed25519
 *
 */
TEST(CmsTest, SignEd25519) {
	// Подписываемое содержимое
	static const char * CONTENT = "CMS signed content Ed25519";
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата подписывающего
	std::string text;
	// Блоки записи PEM
	std::vector <pem::block_t> blocks;
	// Сертификат подписывающего
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/ed25519.crt", text, blocks, certificate);
	// Подготовленный ключ подписи
	keys::signer_t signer;
	// Готовим ключ подписи
	ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/ed25519.pem"))), keys::error_t::NONE);
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем подписанное сообщение
	ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, certificate.number(), view(std::string(CONTENT)), signer, digest::hash_t::SHA256, record), cms::error_t::NONE);
	// Разбираем запись
	cms::signed_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
	// Подписывающий обязан быть один
	ASSERT_EQ(parsed.signers().size(), 1);
	// Опознаватель алгоритма подписи обязан быть Ed25519
	ASSERT_EQ(parsed.signers()[0].algorithm, "1.3.101.112");
	// Проверка подписи обязана удаться
	ASSERT_EQ(cms::verify(parsed, parsed.signers()[0], view_t(), certificate.key()), cms::error_t::NONE);
}

/**
 * @brief Проверка круговой сборки подписи ключами ML-DSA
 *
 */
TEST(CmsTest, SignMldsa) {
	// Подписываемое содержимое
	static const char * CONTENT = "CMS signed content ML-DSA";
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Записи сертификатов и ключи набора образцов
	struct {
		// Файлы сертификата и ключа
		const char * certificate, * key;
		// Опознаватель алгоритма подписи
		const char * oid;
	} CASES[] = {
		{"mldsa44.crt", "mldsa44.pem", "2.16.840.1.101.3.4.3.17"},
		{"mldsa65.crt", "mldsa65.pem", "2.16.840.1.101.3.4.3.18"},
		{"mldsa87.crt", "mldsa87.pem", "2.16.840.1.101.3.4.3.19"}
	};
	// Перебираем записи набора
	for(size_t i = 0; i < (sizeof(CASES) / sizeof(CASES[0])); i++){
		// Запись сертификата подписывающего
		std::string text;
		// Блоки записи PEM
		std::vector <pem::block_t> blocks;
		// Сертификат подписывающего
		x509::certificate_t certificate;
		// Разбираем сертификат
		load(std::string(CORPUS) + "/" + CASES[i].certificate, text, blocks, certificate);
		// Подготовленный ключ подписи
		keys::signer_t signer;
		// Готовим ключ подписи
		ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/" + CASES[i].key))), keys::error_t::NONE);
		// Запись сообщения
		std::vector <uint8_t> record;
		// Собираем подписанное сообщение
		ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, certificate.number(), view(std::string(CONTENT)), signer, digest::hash_t::SHA256, record), cms::error_t::NONE);
		// Разбираем запись
		cms::signed_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
		// Подписывающий обязан быть один
		ASSERT_EQ(parsed.signers().size(), 1);
		// Опознаватель алгоритма подписи обязан совпасть
		ASSERT_EQ(parsed.signers()[0].algorithm, CASES[i].oid);
		// Проверка подписи обязана удаться
		ASSERT_EQ(cms::verify(parsed, parsed.signers()[0], view_t(), certificate.key()), cms::error_t::NONE);
	}
}

/**
 * @brief Проверка отказов сборки подписи
 *
 */
TEST(CmsTest, SignRefusals) {
	// Подписываемое содержимое
	static const char * CONTENT = "CMS sign refusal content";
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата подписывающего
	std::string text;
	// Блоки записи PEM
	std::vector <pem::block_t> blocks;
	// Сертификат подписывающего
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Подготовленный ключ подписи
	keys::signer_t signer;
	// Готовим ключ подписи
	ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/leaf-rsa.key"))), keys::error_t::NONE);
	// Запись сообщения
	std::vector <uint8_t> record;
	// Пустое содержимое отвергается
	ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, certificate.number(), view_t(), signer, digest::hash_t::SHA256, record), cms::error_t::EMPTY);
	// Пустое имя издателя отвергается
	ASSERT_EQ(cms::sign({view(blocks[0].data)}, view_t(), certificate.number(), view(std::string(CONTENT)), signer, digest::hash_t::SHA256, record), cms::error_t::EMPTY);
	// Пустой порядковый номер отвергается
	ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, view_t(), view(std::string(CONTENT)), signer, digest::hash_t::SHA256, record), cms::error_t::EMPTY);
	// Неподготовленный ключ отвергается
	{
		// Неподготовленный ключ
		keys::signer_t unprepared;
		// Сборка обязана отказать
		ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, certificate.number(), view(std::string(CONTENT)), unprepared, digest::hash_t::SHA256, record), cms::error_t::KEY);
	}
	// Неизвестный алгоритм хеша отвергается
	ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, certificate.number(), view(std::string(CONTENT)), signer, digest::hash_t::NONE, record), cms::error_t::ALGORITHM);
}

/**
 * @brief Проверка отказов разбора подписанной записи
 *
 */
TEST(CmsTest, SignedRefusals) {
	// Разбираемая запись
	cms::signed_t parsed;
	// Пустая запись отвергается
	ASSERT_EQ(parsed.parse(view_t()), cms::error_t::EMPTY);
	// Запись не SEQUENCE отвергается
	static const uint8_t INTEGER_RECORD[] = {0x02, 0x01, 0x00};
	// Разбор обязан отказать
	ASSERT_EQ(parsed.parse(view_t(INTEGER_RECORD, sizeof(INTEGER_RECORD))), cms::error_t::STRUCTURE);
}

/**
 * @brief Проверка отказов проверки подписи
 *
 */
TEST(CmsTest, VerifyRefusals) {
	// Подписываемое содержимое
	static const char * CONTENT = "CMS verify refusal content";
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата подписывающего
	std::string text;
	// Блоки записи PEM
	std::vector <pem::block_t> blocks;
	// Сертификат подписывающего
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Подготовленный ключ подписи
	keys::signer_t signer;
	// Готовим ключ подписи
	ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/leaf-rsa.key"))), keys::error_t::NONE);
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем подписанное сообщение
	ASSERT_EQ(cms::sign({view(blocks[0].data)}, certificate.issuers().element, certificate.number(), view(std::string(CONTENT)), signer, digest::hash_t::SHA256, record), cms::error_t::NONE);
	// Разбираем запись
	cms::signed_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
	// Проверка без содержимого отвергается
	ASSERT_EQ(cms::verify(parsed, parsed.signers()[0], view_t(), certificate.key()), cms::error_t::NONE);
	// Проверка с пустым содержимым отвергается
	{
		// Запись без содержимого
		cms::signed_t empty;
		// Проверка обязана отказать
		ASSERT_EQ(cms::verify(empty, parsed.signers()[0], view_t(), certificate.key()), cms::error_t::EMPTY);
	}
}

/**
 * @brief Проверка круговой сборки и разбора хешированного сообщения с хешами SHA-1/SHA-224
 *
 */
TEST(CmsTest, DigestMoreHashes) {
	// Хешируемое содержимое
	static const char * CONTENT = "CMS digested content more hashes";
	// Алгоритмы хеша
	const digest::hash_t HASHES[] = {digest::hash_t::SHA1, digest::hash_t::SHA224};
	// Перебираем алгоритмы хеша
	for(size_t i = 0; i < (sizeof(HASHES) / sizeof(HASHES[0])); i++){
		// Запись сообщения
		std::vector <uint8_t> record;
		// Собираем хешированное сообщение
		ASSERT_EQ(cms::digest(view(std::string(CONTENT)), HASHES[i], record), cms::error_t::NONE);
		// Вид содержимого обязан быть digested
		ASSERT_EQ(cms::content(view(record)), cms::content_t::DIGESTED);
		// Разбираем запись
		cms::digested_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
		// Проверка хеша обязана удаться
		ASSERT_EQ(cms::digestVerify(parsed), cms::error_t::NONE);
	}
	// Неизвестный алгоритм хеша отвергается
	{
		// Запись сообщения
		std::vector <uint8_t> record;
		// Сборка обязана отказать
		ASSERT_EQ(cms::digest(view(std::string(CONTENT)), digest::hash_t::NONE, record), cms::error_t::ALGORITHM);
	}
}

/**
 * @brief Проверка отказов разбора хешированной записи
 *
 */
TEST(CmsTest, DigestedRefusals) {
	// Разбираемая запись
	cms::digested_t parsed;
	// Пустая запись отвергается
	ASSERT_EQ(parsed.parse(view_t()), cms::error_t::EMPTY);
	// Запись не SEQUENCE отвергается
	static const uint8_t INTEGER_RECORD[] = {0x02, 0x01, 0x00};
	// Разбор обязан отказать
	ASSERT_EQ(parsed.parse(view_t(INTEGER_RECORD, sizeof(INTEGER_RECORD))), cms::error_t::STRUCTURE);
}

/**
 * @brief Проверка круговой сборки и разбора сообщения с имитовставкой с хешами SHA-1/SHA-224
 *
 */
TEST(CmsTest, AuthenticateMoreHashes) {
	// Содержимое под имитовставку
	static const char * CONTENT = "CMS authenticated content more hashes";
	// Ключ имитовставки
	static const char * KEY = "cms-mac-key";
	// Алгоритмы хеша
	struct {
		// Алгоритм хеша
		digest::hash_t hash;
		// Опознаватель алгоритма
		const char * oid;
	} CASES[] = {
		{digest::hash_t::SHA1, "1.3.6.1.5.5.8.1.2"},
		{digest::hash_t::SHA224, "1.2.840.113549.2.8"}
	};
	// Перебираем алгоритмы
	for(size_t i = 0; i < (sizeof(CASES) / sizeof(CASES[0])); i++){
		// Запись сообщения
		std::vector <uint8_t> record;
		// Собираем сообщение с имитовставкой
		ASSERT_EQ(cms::authenticate(view(std::string(CONTENT)), view(std::string(KEY)), CASES[i].hash, record), cms::error_t::NONE);
		// Вид содержимого обязан быть authenticated
		ASSERT_EQ(cms::content(view(record)), cms::content_t::AUTHENTICATED);
		// Разбираем запись
		cms::authenticated_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
		// Опознаватель алгоритма обязан совпасть
		ASSERT_EQ(parsed.algorithm(), CASES[i].oid);
		// Проверка имитовставки обязана удаться
		ASSERT_EQ(cms::authenticateVerify(parsed, view(std::string(KEY))), cms::error_t::NONE);
	}
	// Пустое содержимое отвергается
	{
		// Запись сообщения
		std::vector <uint8_t> record;
		// Сборка обязана отказать
		ASSERT_EQ(cms::authenticate(view_t(), view(std::string(KEY)), digest::hash_t::SHA256, record), cms::error_t::EMPTY);
	}
	// Пустой ключ отвергается
	{
		// Запись сообщения
		std::vector <uint8_t> record;
		// Сборка обязана отказать
		ASSERT_EQ(cms::authenticate(view(std::string(CONTENT)), view_t(), digest::hash_t::SHA256, record), cms::error_t::EMPTY);
	}
	// Неизвестный алгоритм хеша отвергается
	{
		// Запись сообщения
		std::vector <uint8_t> record;
		// Сборка обязана отказать
		ASSERT_EQ(cms::authenticate(view(std::string(CONTENT)), view(std::string(KEY)), digest::hash_t::NONE, record), cms::error_t::ALGORITHM);
	}
}

/**
 * @brief Проверка отказов разбора записи с имитовставкой
 *
 */
TEST(CmsTest, AuthenticatedRefusals) {
	// Разбираемая запись
	cms::authenticated_t parsed;
	// Пустая запись отвергается
	ASSERT_EQ(parsed.parse(view_t()), cms::error_t::EMPTY);
	// Запись не SEQUENCE отвергается
	static const uint8_t INTEGER_RECORD[] = {0x02, 0x01, 0x00};
	// Разбор обязан отказать
	ASSERT_EQ(parsed.parse(view_t(INTEGER_RECORD, sizeof(INTEGER_RECORD))), cms::error_t::STRUCTURE);
}

/**
 * @brief Проверка отказов сборки цепочки сертификатов
 *
 */
TEST(CmsTest, CertificatesRefusals) {
	// Пустой набор сертификатов отвергается
	{
		// Итог сборки
		std::vector <uint8_t> record;
		// Сборка обязана отказать
		ASSERT_EQ(cms::certificates({}, record), cms::error_t::EMPTY);
	}
	// Битая запись сертификата переносится как есть
	{
		// Битая запись
		static const uint8_t BROKEN[] = {0x02, 0x01, 0x00};
		// Итог сборки
		std::vector <uint8_t> record;
		// Сборка обязана удаться: запись переносится как есть, без разбора
		ASSERT_EQ(cms::certificates({view_t(BROKEN, sizeof(BROKEN))}, record), cms::error_t::NONE);
		// Вид записи обязан быть id-signedData
		ASSERT_EQ(cms::content(view(record)), cms::content_t::SIGNED);
	}
}

/**
 * @brief Проверка отказов расшифрования зашифрованного сообщения
 *
 */
TEST(CmsTest, UnenvelopRefusals) {
	// Зашифровываемое содержимое
	static const char * CONTENT = "CMS unenvelop refusal content";
	// Запись сертификата получателя
	std::string text;
	// Блоки записи PEM
	std::vector <pem::block_t> blocks;
	// Сертификат получателя
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Ключ получателя
	keys::key_t key;
	// Разбираем ключ
	load(std::string(CORPUS) + "/leaf-rsa.key", key);
	// Собираем зашифрованное сообщение
	std::vector <uint8_t> record;
	// Сборка обязана удаться
	ASSERT_EQ(cms::envelop(view(std::string(CONTENT)), certificate.issuers().element, certificate.number(), certificate.key(), record), cms::error_t::NONE);
	// Разбираем запись
	cms::enveloped_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
	// Ключ не RSA отвергается
	{
		// Ключ EC
		keys::key_t ecKey;
		// Разбираем ключ
		load(std::string(CORPUS) + "/leaf-ec.key", ecKey);
		// Итог расшифрования
		std::vector <uint8_t> content;
		// Расшифрование обязано отказать
		ASSERT_EQ(cms::unenvelop(parsed, ecKey, content), cms::error_t::KEY);
	}
	// Ключ без секретной части отвергается
	{
		// Ключ RSA без секретной части
		keys::key_t publicKey;
		// Разбираем ключ
		load(std::string(CORPUS) + "/leaf-rsa.key", publicKey);
		// Обнуляем секретную часть
		publicKey.d.clear();
		// Итог расшифрования
		std::vector <uint8_t> content;
		// Расшифрование обязано отказать
		ASSERT_EQ(cms::unenvelop(parsed, publicKey, content), cms::error_t::KEY);
	}
}

/**
 * @brief Проверка отказов расшифрования зашифрованного сообщения ключом ML-KEM
 *
 */
TEST(CmsTest, UnenvelopKemRefusals) {
	// Зашифровываемое содержимое
	static const char * CONTENT = "CMS unenvelop KEM refusal content";
	// Запись сертификата для опознавания получателя
	std::string text;
	// Блоки записи PEM
	std::vector <pem::block_t> blocks;
	// Сертификат для опознавания получателя
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Открытый и секретный ключи ML-KEM
	std::vector <uint8_t> public_(agreement::encapsulation(agreement::kem_t::MLKEM512)), secret(agreement::decapsulation(agreement::kem_t::MLKEM512));
	// Вырабатываем пару ключей
	ASSERT_TRUE(agreement::generate(agreement::kem_t::MLKEM512, public_.data(), secret.data()));
	// Собираем зашифрованное сообщение
	std::vector <uint8_t> record;
	// Сборка обязана удаться
	ASSERT_EQ(cms::envelop(view(std::string(CONTENT)), certificate.issuers().element, certificate.number(), agreement::kem_t::MLKEM512, view(public_), record), cms::error_t::NONE);
	// Разбираем запись
	cms::enveloped_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
	// Неизвестный набор параметров отвергается
	{
		// Итог расшифрования
		std::vector <uint8_t> content;
		// Расшифрование обязано отказать
		ASSERT_EQ(cms::unenvelop(parsed, static_cast <agreement::kem_t> (0), view(secret), content), cms::error_t::ALGORITHM);
	}
	// Секретный ключ негодной длины отвергается
	{
		// Итог расшифрования
		std::vector <uint8_t> content;
		// Расшифрование обязано отказать
		ASSERT_EQ(cms::unenvelop(parsed, agreement::kem_t::MLKEM512, view_t(), content), cms::error_t::KEY);
	}
}

/**
 * @brief Проверка отказов расшифрования зашифрованного сообщения
 *
 */
TEST(CmsTest, DecryptRefusals) {
	// Шифруемое содержимое
	static const char * CONTENT = "CMS decrypt refusal content";
	// Ключ AES-256
	static const uint8_t KEY256[32] = {0x03};
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем зашифрованное сообщение
	ASSERT_EQ(cms::encrypt(view(std::string(CONTENT)), view_t(KEY256, sizeof(KEY256)), record), cms::error_t::NONE);
	// Разбираем запись
	cms::encrypted_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cms::error_t::NONE);
	// Пустой ключ отвергается
	{
		// Итог расшифрования
		std::vector <uint8_t> plain;
		// Расшифрование обязано отказать
		ASSERT_EQ(cms::decrypt(parsed, view_t(), plain), cms::error_t::EMPTY);
	}
	// Ключ чужой длины отвергается
	{
		// Ключ чужой длины
		static const uint8_t WRONG[15] = {0x00};
		// Итог расшифрования
		std::vector <uint8_t> plain;
		// Расшифрование обязано отказать
		ASSERT_EQ(cms::decrypt(parsed, view_t(WRONG, sizeof(WRONG)), plain), cms::error_t::KEY);
	}
	// Ключ чужого алгоритма отвергается
	{
		// Ключ AES-128
		static const uint8_t KEY128[16] = {0x01};
		// Итог расшифрования
		std::vector <uint8_t> plain;
		// Расшифрование обязано отказать
		ASSERT_EQ(cms::decrypt(parsed, view_t(KEY128, sizeof(KEY128)), plain), cms::error_t::ALGORITHM);
	}
}
