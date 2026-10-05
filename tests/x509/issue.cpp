/**
 * @file issue.cpp
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
 * @brief Исходный файл проверок модуля выпуска сертификатов X.509
 *
 * @note Выпущенные сертификаты разбираются обратно модулем сертификатов, подпись
 *       сличется с ключом издателя модулем проверки подписи, а приём записи
 *       проверяется системным openssl (verify и x509 -text)
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
#include <asn1/asn1.hpp>
#include <keys/keys.hpp>
#include <x509/x509.hpp>
#include <x509/request.hpp>
#include <x509/signature.hpp>
#include <x509/issue.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору образцов проверок
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * Служебные объекты проверок выпуска сертификатов
 */
namespace {
	/**
	 * @brief Метод запуска команды оболочки без консоли на входе
	 *
	 * @param command запускаемая команда
	 *
	 * @return        код возврата команды
	 *
	 */
	static int shell(const std::string & command) noexcept {
		// Запускаем команды с пустым входом
		return ::system((command + " </dev/null").c_str());
	}
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
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла в наборе
	 *
	 * @return     содержимое файла
	 *
	 */
	static std::string corpus(const std::string & name) {
		// Выводим содержимое файла набора
		return slurp(std::string(CORPUS) + "/" + name);
	}
	/**
	 * @brief Метод перевода строки в набор байтов
	 *
	 * @param text переводимая строка
	 *
	 * @return     набор байтов
	 *
	 */
	static std::vector <uint8_t> bytes(const std::string & text) {
		// Выводим набор байтов строки
		return std::vector <uint8_t> (text.begin(), text.end());
	}
	/**
	 * @brief Метод получения просмотра набора байтов
	 *
	 * @param data просматриваемый набор байтов
	 *
	 * @return     просмотр набора байтов
	 *
	 */
	static view_t view(const std::vector <uint8_t> & data) {
		// Выводим просмотр набора байтов
		return view_t(data.data(), data.size());
	}
	/**
	 * @brief Метод записи файла целиком
	 *
	 * @param path путь к записываемому файлу
	 * @param data записываемое содержимое
	 *
	 * @return     признак успешности записи
	 *
	 */
	static bool spill(const std::string & path, const std::vector <uint8_t> & data) {
		// Открываем файл на запись
		std::ofstream file(path, std::ios::binary);
		// Записываем содержимое
		file.write(reinterpret_cast <const char *> (data.data()), static_cast <std::streamsize> (data.size()));
		// Выводим успешность записи
		return file.good();
	}
	/**
	 * @brief Метод извлечения тела первой записи PEM
	 *
	 * @param text разбираемый текст
	 *
	 * @return     тело первой записи в кодировке DER
	 *
	 */
	static std::vector <uint8_t> body(const std::string & text) {
		// Разобранные записи текста
		std::vector <pem::block_t> blocks;
		// Если записи разобрать не удалось либо их нет
		if((pem::decode(text, blocks) != pem::error_t::NONE) || blocks.empty())
			// Выводим пустое тело
			return std::vector <uint8_t> ();
		// Выводим тело первой записи
		return blocks.front().data;
	}
	/**
	 * @brief Обёртка временного каталога проверок
	 *
	 */
	typedef class Sandbox {
		private:
			// Путь к временному каталогу
			std::string _path;
		public:
			/**
			 * @brief Метод получения пути к файлу внутри каталога
			 *
			 * @param name имя файла
			 *
			 * @return     путь к файлу
			 *
			 */
			std::string file(const std::string & name) const {
				// Выводим путь к файлу
				return (this->_path + "/" + name);
			}
			/**
			 * @brief Метод проверки готовности каталога
			 *
			 * @return признак готовности каталога
			 *
			 */
			bool ready() const {
				// Выводим готовность каталога
				return !this->_path.empty();
			}
		public:
			/**
			 * @brief Конструктор
			 *
			 */
			Sandbox() {
				// Образец имени временного каталога
				char pattern[] = "/tmp/ants-issue-XXXXXX";
				// Если временный каталог создан
				if(::mkdtemp(pattern) != nullptr)
					// Запоминаем путь к каталогу
					this->_path = pattern;
			}
			/**
			 * @brief Деструктор
			 *
			 */
			~Sandbox() {
				// Если каталог создан
				if(!this->_path.empty())
					// Удаляем каталог со всем содержимым
					(void) shell((std::string("rm -rf ") + this->_path).c_str());
			}
	} sandbox_t;
	/**
	 * @brief Метод извлечения значения признака CN из имени
	 *
	 * @param name разбираемое имя
	 *
	 * @return     значение признака CN либо пустая строка
	 *
	 */
	static std::string common(const x509::name_t & name) {
		// Признак CN имени
		const x509::attribute_t * attribute = x509::attribute(name, "2.5.4.3");
		// Выводим значение признака либо пустую строку
		return ((attribute != nullptr) ? attribute->value : std::string());
	}
	/**
	 * @brief Метод разбора сертификата набора
	 *
	 * @param name        имя файла сертификата в наборе
	 * @param der         место, в которое помещается тело записи сертификата
	 * @param certificate объект разбираемого сертификата
	 *
	 * @return            признак успешности разбора
	 *
	 */
	static bool certificate(const std::string & name, std::vector <uint8_t> & der, x509::certificate_t & certificate) {
		// Тело записи сертификата в кодировке DER
		der = body(corpus(name));
		// Если записи нет
		if(der.empty())
			// Выводим отказ
			return false;
		// Выводим итог разбора сертификата
		return (certificate.parse(view(der)) == x509::error_t::NONE);
	}
};

/**
 * Проверка выпуска самоподписанного сертификата: запись разбирается обратно,
 * поля сходятся с выданными, подпись сходится с ключом самого владельца
 */
TEST(IssueTest, SelfSigned){
	// Тело записи эталонного сертификата владельца
	std::vector <uint8_t> der;
	// Эталонный сертификат владельца
	x509::certificate_t reference;
	// Проверяем разбор эталонного сертификата
	ASSERT_TRUE(certificate("leaf-rsa.crt", der, reference));
	// Подготовленный секретный ключ владельца
	keys::signer_t signer;
	// Проверяем подготовку ключа из записи набора
	ASSERT_EQ(signer.prepare(view(bytes(corpus("leaf-rsa.key")))), keys::error_t::NONE);
	// Порядковый номер выдаваемого сертификата
	const uint8_t serial[] = {0x01, 0x02, 0x03, 0x04};
	// Расширение основных ограничений: владелец не издатель
	x509::extension_t constraints;
	// Устанавливаем опознаватель основных ограничений
	constraints.oid = "2.5.29.19";
	// Содержимое расширения: пустой набор
	const uint8_t empty[] = {0x30, 0x00};
	// Устанавливаем содержимое расширения
	constraints.value = view_t(empty, sizeof(empty));
	// Набор расширений выдаваемого сертификата
	const std::vector <x509::extension_t> extensions(1, constraints);
	// Выпущенный сертификат
	std::vector <uint8_t> issued;
	// Проверяем выпуск самоподписанного сертификата сроком с 2026-01-01 по 2030-01-01
	ASSERT_EQ(x509::issueSelfSigned(reference.subjects(), reference.key(), signer, digest::hash_t::SHA256, view_t(serial, sizeof(serial)), 1767225600, 1893456000, extensions, issued), x509::error_t::NONE);
	// Разбираемый выпущенный сертификат
	x509::certificate_t certificate;
	// Проверяем разбор выпущенного сертификата
	ASSERT_EQ(certificate.parse(view(issued)), x509::error_t::NONE);
	// Проверяем издание выпущенного сертификата: расширения есть - издание третье
	ASSERT_EQ(certificate.release(), x509::version_t::V3);
	// Проверяем порядковый номер выпущенного сертификата
	ASSERT_EQ(certificate.number().size, sizeof(serial));
	ASSERT_EQ(::memcmp(certificate.number().data, serial, sizeof(serial)), 0);
	// Проверяем совпадение имени издателя с именем владельца: сертификат самоподписанный
	ASSERT_EQ(common(certificate.issuers()), "test.anyks.com");
	// Проверяем имя владельца выпущенного сертификата
	ASSERT_EQ(common(certificate.subjects()), "test.anyks.com");
	// Срок действия выпущенного сертификата
	int64_t before = 0, after = 0;
	// Извлекаем срок действия
	certificate.validity(before, after);
	// Проверяем срок действия выпущенного сертификата
	ASSERT_EQ(before, 1767225600);
	ASSERT_EQ(after, 1893456000);
	// Проверяем опознаватель алгоритма подписи выпущенного сертификата
	ASSERT_EQ(certificate.algorithms(), "1.2.840.113549.1.1.11");
	// Проверяем подпись выпущенного сертификата сведениями об открытом ключе самого сертификата
	ASSERT_EQ(x509::verify(certificate, certificate.key()), x509::error_t::NONE);
	// Проверяем совпадение открытого ключа выпущенного сертификата с эталонным байт в байт
	ASSERT_EQ(certificate.key().key.size, reference.key().key.size);
	ASSERT_EQ(::memcmp(certificate.key().key.data, reference.key().key.data, certificate.key().key.size), 0);
}

/**
 * Проверка выпуска сертификата без расширений: издание первое, запись
 * разбирается, подпись сходится
 */
TEST(IssueTest, FirstRelease){
	// Тело записи эталонного сертификата владельца
	std::vector <uint8_t> der;
	// Эталонный сертификат владельца
	x509::certificate_t reference;
	// Проверяем разбор эталонного сертификата
	ASSERT_TRUE(certificate("leaf-ec.crt", der, reference));
	// Подготовленный секретный ключ владельца
	keys::signer_t signer;
	// Проверяем подготовку ключа из записи набора
	ASSERT_EQ(signer.prepare(view(bytes(corpus("leaf-ec.key")))), keys::error_t::NONE);
	// Порядковый номер выдаваемого сертификата
	const uint8_t serial[] = {0x2A};
	// Выпущенный сертификат
	std::vector <uint8_t> issued;
	// Проверяем выпуск самоподписанного сертификата без расширений
	ASSERT_EQ(x509::issueSelfSigned(reference.subjects(), reference.key(), signer, digest::hash_t::SHA256, view_t(serial, sizeof(serial)), 1767225600, 1893456000, std::vector <x509::extension_t> (), issued), x509::error_t::NONE);
	// Разбираемый выпущенный сертификат
	x509::certificate_t certificate;
	// Проверяем разбор выпущенного сертификата
	ASSERT_EQ(certificate.parse(view(issued)), x509::error_t::NONE);
	// Проверяем издание выпущенного сертификата: расширений нет - издание первое
	ASSERT_EQ(certificate.release(), x509::version_t::V1);
	// Проверяем опознаватель алгоритма подписи выпущенного сертификата
	ASSERT_EQ(certificate.algorithms(), "1.2.840.10045.4.3.2");
	// Проверяем подпись выпущенного сертификата сведениями об открытом ключе самого сертификата
	ASSERT_EQ(x509::verify(certificate, certificate.key()), x509::error_t::NONE);
}

/**
 * Проверка выпуска сертификата по запросу подписью издателя: имя и ключ
 * владельца берутся из запроса, имя издателя - из сертификата издателя,
 * подпись сходится с ключом издателя
 */
TEST(IssueTest, ByCA){
	// Тело записи запроса владельца
	const std::vector <uint8_t> requestDer = body(corpus("leaf-rsa.csr"));
	// Проверяем наличие записи запроса
	ASSERT_FALSE(requestDer.empty());
	// Разбираемый запрос владельца
	x509::request_t request;
	// Проверяем разбор запроса владельца
	ASSERT_EQ(request.parse(view(requestDer)), x509::error_t::NONE);
	// Проверяем подпись запроса сведениями об открытом ключе самого запроса
	ASSERT_EQ(x509::verify(request, request.key()), x509::error_t::NONE);
	// Тело записи сертификата издателя
	std::vector <uint8_t> caDer;
	// Сертификат издателя
	x509::certificate_t ca;
	// Проверяем разбор сертификата издателя
	ASSERT_TRUE(certificate("ca-rsa.crt", caDer, ca));
	// Подготовленный секретный ключ издателя
	keys::signer_t signer;
	// Проверяем подготовку ключа издателя из записи набора
	ASSERT_EQ(signer.prepare(view(bytes(corpus("ca-rsa.key")))), keys::error_t::NONE);
	// Порядковый номер выдаваемого сертификата
	const uint8_t serial[] = {0x0A, 0x0B};
	// Выпущенный сертификат
	std::vector <uint8_t> issued;
	// Проверяем выпуск сертификата по запросу подписью издателя
	ASSERT_EQ(x509::issueByCA(request, ca.subjects(), signer, digest::hash_t::SHA256, view_t(serial, sizeof(serial)), 1767225600, 1893456000, std::vector <x509::extension_t> (), issued), x509::error_t::NONE);
	// Разбираемый выпущенный сертификат
	x509::certificate_t certificate;
	// Проверяем разбор выпущенного сертификата
	ASSERT_EQ(certificate.parse(view(issued)), x509::error_t::NONE);
	// Проверяем имя издателя выпущенного сертификата
	ASSERT_EQ(common(certificate.issuers()), "ANYKS Root rsa");
	// Проверяем имя владельца выпущенного сертификата: из запроса
	ASSERT_EQ(common(certificate.subjects()), "test.anyks.com");
	// Проверяем подпись выпущенного сертификата сведениями об открытом ключе издателя
	ASSERT_EQ(x509::verify(certificate, ca.key()), x509::error_t::NONE);
	// Проверяем отказ проверки подписи чужим ключом: владельца, не издателя
	ASSERT_EQ(x509::verify(certificate, request.key()), x509::error_t::SIGNATURE);
	// Проверяем совпадение открытого ключа выпущенного сертификата с ключом запроса байт в байт
	ASSERT_EQ(certificate.key().key.size, request.key().key.size);
	ASSERT_EQ(::memcmp(certificate.key().key.data, request.key().key.data, certificate.key().key.size), 0);
}

/**
 * Проверка отказов выпуска: ключ не подготовлен, порядковый номер пуст
 * либо длиннее двадцати байтов, срок действия перевёрнут
 */
TEST(IssueTest, Refusal){
	// Тело записи эталонного сертификата владельца
	std::vector <uint8_t> der;
	// Эталонный сертификат владельца
	x509::certificate_t reference;
	// Проверяем разбор эталонного сертификата
	ASSERT_TRUE(certificate("leaf-rsa.crt", der, reference));
	// Подготовленный секретный ключ владельца
	keys::signer_t signer;
	// Проверяем подготовку ключа из записи набора
	ASSERT_EQ(signer.prepare(view(bytes(corpus("leaf-rsa.key")))), keys::error_t::NONE);
	// Порядковый номер выдаваемого сертификата
	const uint8_t serial[] = {0x01};
	// Выпущенный сертификат
	std::vector <uint8_t> issued;
	// Неподготовленный ключ
	keys::signer_t idle;
	// Проверяем отказ выпуска неподготовленным ключом
	ASSERT_NE(x509::issueSelfSigned(reference.subjects(), reference.key(), idle, digest::hash_t::SHA256, view_t(serial, sizeof(serial)), 1767225600, 1893456000, std::vector <x509::extension_t> (), issued), x509::error_t::NONE);
	// Проверяем отказ выпуска с пустым порядковым номером
	ASSERT_NE(x509::issueSelfSigned(reference.subjects(), reference.key(), signer, digest::hash_t::SHA256, view_t(), 1767225600, 1893456000, std::vector <x509::extension_t> (), issued), x509::error_t::NONE);
	// Порядковый номер длиннее двадцати байтов: раздел 4.1.2.2 RFC 5280
	const uint8_t prolonged[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
	// Проверяем отказ выпуска с порядковым номером длиннее двадцати байтов
	ASSERT_NE(x509::issueSelfSigned(reference.subjects(), reference.key(), signer, digest::hash_t::SHA256, view_t(prolonged, sizeof(prolonged)), 1767225600, 1893456000, std::vector <x509::extension_t> (), issued), x509::error_t::NONE);
	// Проверяем отказ выпуска с перевёрнутым сроком действия
	ASSERT_NE(x509::issueSelfSigned(reference.subjects(), reference.key(), signer, digest::hash_t::SHA256, view_t(serial, sizeof(serial)), 1893456000, 1767225600, std::vector <x509::extension_t> (), issued), x509::error_t::NONE);
}

/**
 * Проверка приёма выпущенных сертификатов системным openssl: самоподписанный
 * подтверждается своим именем, выданный издателем - цепочкой до издателя
 */
TEST(IssueTest, Openssl){
	// Если openssl недоступен
	if(shell("openssl version >/dev/null 2>&1") != 0)
		// Пропускаем проверку
		GTEST_SKIP() << "openssl недоступен";
	// Временный каталог
	sandbox_t sandbox;
	// Проверяем готовность временного каталога
	ASSERT_TRUE(sandbox.ready());
	// Тело записи эталонного сертификата владельца
	std::vector <uint8_t> der;
	// Эталонный сертификат владельца
	x509::certificate_t reference;
	// Проверяем разбор эталонного сертификата
	ASSERT_TRUE(certificate("leaf-ec.crt", der, reference));
	// Подготовленный секретный ключ владельца
	keys::signer_t signer;
	// Проверяем подготовку ключа из записи набора
	ASSERT_EQ(signer.prepare(view(bytes(corpus("leaf-ec.key")))), keys::error_t::NONE);
	// Порядковый номер выдаваемого сертификата
	const uint8_t serial[] = {0x07};
	// Выпущенный самоподписанный сертификат
	std::vector <uint8_t> self;
	// Проверяем выпуск самоподписанного сертификата
	ASSERT_EQ(x509::issueSelfSigned(reference.subjects(), reference.key(), signer, digest::hash_t::SHA256, view_t(serial, sizeof(serial)), 1767225600, 1893456000, std::vector <x509::extension_t> (), self), x509::error_t::NONE);
	// Путь к самоподписанному сертификату в кодировке DER
	const std::string selfDer = sandbox.file("self.der");
	// Проверяем запись файла сертификата
	ASSERT_TRUE(spill(selfDer, self));
	// Путь к самоподписанному сертификату в кодировке PEM
	const std::string selfPem = sandbox.file("self.pem");
	// Проверяем, что openssl разбирает выпущенный сертификат и переписывает его в PEM
	ASSERT_EQ(shell(std::string("openssl x509 -in ") + selfDer + " -inform DER -outform PEM -out " + selfPem + " >/dev/null 2>&1"), 0);
	// Проверяем, что openssl подтверждает самоподписанный сертификат его же записью
	ASSERT_EQ(shell(std::string("openssl verify -CAfile ") + selfPem + " " + selfPem + " >/dev/null 2>&1"), 0);
	// Тело записи запроса владельца
	const std::vector <uint8_t> requestDer = body(corpus("leaf-rsa.csr"));
	// Проверяем наличие записи запроса
	ASSERT_FALSE(requestDer.empty());
	// Разбираемый запрос владельца
	x509::request_t request;
	// Проверяем разбор запроса владельца
	ASSERT_EQ(request.parse(view(requestDer)), x509::error_t::NONE);
	// Тело записи сертификата издателя
	std::vector <uint8_t> caDer;
	// Сертификат издателя
	x509::certificate_t ca;
	// Проверяем разбор сертификата издателя
	ASSERT_TRUE(certificate("ca-rsa.crt", caDer, ca));
	// Подготовленный секретный ключ издателя
	keys::signer_t caSigner;
	// Проверяем подготовку ключа издателя из записи набора
	ASSERT_EQ(caSigner.prepare(view(bytes(corpus("ca-rsa.key")))), keys::error_t::NONE);
	// Выпущенный издателем сертификат
	std::vector <uint8_t> signed_;
	// Проверяем выпуск сертификата по запросу подписью издателя
	ASSERT_EQ(x509::issueByCA(request, ca.subjects(), caSigner, digest::hash_t::SHA256, view_t(serial, sizeof(serial)), 1767225600, 1893456000, std::vector <x509::extension_t> (), signed_), x509::error_t::NONE);
	// Путь к выданному издателем сертификату в кодировке DER
	const std::string signedDer = sandbox.file("signed.der");
	// Проверяем запись файла сертификата
	ASSERT_TRUE(spill(signedDer, signed_));
	// Путь к выданному издателем сертификату в кодировке PEM
	const std::string signedPem = sandbox.file("signed.pem");
	// Проверяем, что openssl разбирает выданный сертификат и переписывает его в PEM
	ASSERT_EQ(shell(std::string("openssl x509 -in ") + signedDer + " -inform DER -outform PEM -out " + signedPem + " >/dev/null 2>&1"), 0);
	// Путь к сертификату издателя в кодировке PEM
	const std::string caPem = sandbox.file("ca.pem");
	// Проверяем запись файла сертификата издателя
	ASSERT_TRUE(spill(caPem, bytes(corpus("ca-rsa.crt"))));
	// Проверяем, что openssl подтверждает выданный сертификат цепочкой до издателя
	ASSERT_EQ(shell(std::string("openssl verify -CAfile ") + caPem + " " + signedPem + " >/dev/null 2>&1"), 0);
}
