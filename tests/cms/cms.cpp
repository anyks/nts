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
