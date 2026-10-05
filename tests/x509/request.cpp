/**
 * @file request.cpp
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
 * @brief Исходный файл проверок модуля запросов на сертификат PKCS #10
 *
 * @note Эталоном служат запросы набора tests/corpus, выработанные openssl:
 *       разбор сличется с ними по полям, а запись проверяется обратным разбором
 *       и приёмом её системным openssl (req -verify)
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

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору образцов проверок
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * Служебные объекты проверок запросов на сертификат
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
				char pattern[] = "/tmp/ants-request-XXXXXX";
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
	 * @brief Метод составления имени владельца с единственным признаком CN
	 *
	 * @param cn значение признака CN
	 *
	 * @return   составленное имя
	 *
	 */
	static x509::name_t named(const std::string & cn) {
		// Составляемое имя
		x509::name_t result;
		// Признак CN
		x509::attribute_t attribute;
		// Устанавливаем опознаватель признака CN
		attribute.oid = "2.5.4.3";
		// Устанавливаем вид записи значения признака
		attribute.type = asn1::tag_t::UTF8_STRING;
		// Устанавливаем значение признака
		attribute.value = cn;
		// Составляющая имени из единственного признака
		result.parts.push_back(std::vector <x509::attribute_t> (1, attribute));
		// Выводим составленное имя
		return result;
	}
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
};

/**
 * Проверка разбора запросов набора, выработанных openssl: имя владельца,
 * алгоритмы ключа и подписи сходятся с записью, подпись сходится с ключом запроса
 */
TEST(RequestTest, Corpus){
	// Записи запросов набора
	const char * names[] = {"leaf-rsa", "leaf-ec", "mid-rsa", "mid-ec", "expired"};
	// Имена владельцев запросов набора
	const char * subjects[] = {"test.anyks.com", "test.anyks.com", "ANYKS Mid rsa", "ANYKS Mid ec", "expired.anyks.com"};
	// Опознаватели алгоритмов ключей запросов набора
	const char * keys[] = {
		// RSA, EC, RSA, EC, EC
		"1.2.840.113549.1.1.1", "1.2.840.10045.2.1", "1.2.840.113549.1.1.1", "1.2.840.10045.2.1", "1.2.840.10045.2.1"
	};
	// Опознаватели алгоритмов подписи запросов набора
	const char * signatures[] = {
		// sha256WithRSAEncryption, ecdsa-with-SHA256
		"1.2.840.113549.1.1.11", "1.2.840.10045.4.3.2", "1.2.840.113549.1.1.11", "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.2"
	};
	/**
	 * Выполняем перебор запросов набора
	 */
	for(size_t i = 0; i < 5; i++){
		// Тело записи запроса в кодировке DER
		const std::vector <uint8_t> der = body(corpus(std::string(names[i]) + ".csr"));
		// Проверяем наличие записи
		ASSERT_FALSE(der.empty()) << "Запрос: " << names[i];
		// Разбираемый запрос
		x509::request_t request;
		// Проверяем разбор записи запроса
		ASSERT_EQ(request.parse(view(der)), x509::error_t::NONE) << "Запрос: " << names[i];
		// Проверяем имя владельца запроса
		ASSERT_EQ(common(request.subjects()), subjects[i]) << "Запрос: " << names[i];
		// Проверяем опознаватель алгоритма ключа запроса
		ASSERT_EQ(request.key().algorithm, keys[i]) << "Запрос: " << names[i];
		// Проверяем опознаватель алгоритма подписи запроса
		ASSERT_EQ(request.algorithms(), signatures[i]) << "Запрос: " << names[i];
		// Проверяем отсутствие запрошенных расширений: запросы набора их не несут
		ASSERT_TRUE(request.extension().empty()) << "Запрос: " << names[i];
		// Проверяем подпись запроса сведениями об открытом ключе самого запроса
		ASSERT_EQ(x509::verify(request, request.key()), x509::error_t::NONE) << "Запрос: " << names[i];
	}
}

/**
 * Проверка отказа разбора при порче записи запроса: подпись перевёрнута,
 * запись обрезана, издание запроса заменено
 */
TEST(RequestTest, Refusal){
	// Тело записи запроса в кодировке DER
	const std::vector <uint8_t> der = body(corpus("leaf-rsa.csr"));
	// Проверяем наличие записи
	ASSERT_FALSE(der.empty());
	// Разбираемый запрос
	x509::request_t request;
	// Проверяем разбор записи запроса
	ASSERT_EQ(request.parse(view(der)), x509::error_t::NONE);
	// Порченая запись: последний байт подписи перевёрнут
	std::vector <uint8_t> damaged(der);
	damaged[damaged.size() - 1] = static_cast <uint8_t> (damaged[damaged.size() - 1] ^ 0xFF);
	// Разбор порченой записи проходит: подпись не проверяется разбором
	ASSERT_EQ(request.parse(view(damaged)), x509::error_t::NONE);
	// Проверяем отказ проверки порченой подписи
	ASSERT_EQ(x509::verify(request, request.key()), x509::error_t::SIGNATURE);
	// Обрезанная запись: без последних восьми байтов подписи
	const std::vector <uint8_t> cut(der.begin(), der.end() - 8);
	// Проверяем отказ разбора обрезанной записи
	ASSERT_NE(request.parse(view(cut)), x509::error_t::NONE);
	// Проверяем отказ разбора пустой записи
	ASSERT_NE(request.parse(view_t()), x509::error_t::NONE);
	// Проверяем отказ разбора чужой записи: сертификат не запрос
	ASSERT_NE(request.parse(view(body(corpus("leaf-rsa.crt")))), x509::error_t::NONE);
}

/**
 * Проверка круговой записи запроса: записанный модулем запрос разбирается
 * обратно, поля сходятся с исходными, подпись сходится с ключом
 */
TEST(RequestTest, Roundtrip){
	// Тело записи эталонного запроса
	const std::vector <uint8_t> der = body(corpus("leaf-rsa.csr"));
	// Проверяем наличие записи
	ASSERT_FALSE(der.empty());
	// Эталонный запрос
	x509::request_t reference;
	// Проверяем разбор эталонного запроса
	ASSERT_EQ(reference.parse(view(der)), x509::error_t::NONE);
	// Подготовленный секретный ключ владельца запроса
	keys::signer_t signer;
	// Проверяем подготовку ключа из записи набора
	ASSERT_EQ(signer.prepare(view(bytes(corpus("leaf-rsa.key")))), keys::error_t::NONE);
	// Запрошенное расширение: основные ограничения, необязательное
	x509::extension_t extension;
	// Устанавливаем опознаватель основных ограничений
	extension.oid = "2.5.29.19";
	// Содержимое расширения: пустой набор - владелец не издатель
	const uint8_t constraints[] = {0x30, 0x00};
	// Устанавливаем содержимое расширения
	extension.value = view_t(constraints, sizeof(constraints));
	// Набор запрашиваемых расширений
	const std::vector <x509::extension_t> extensions(1, extension);
	// Записанный запрос
	std::vector <uint8_t> encoded;
	// Проверяем запись запроса
	ASSERT_EQ(x509::encode(reference.subjects(), reference.key(), extensions, signer, digest::hash_t::SHA256, encoded), x509::error_t::NONE);
	// Разбираемый записанный запрос
	x509::request_t request;
	// Проверяем разбор записанного запроса
	ASSERT_EQ(request.parse(view(encoded)), x509::error_t::NONE);
	// Проверяем совпадение имени владельца с исходным
	ASSERT_EQ(common(request.subjects()), "test.anyks.com");
	// Проверяем опознаватель алгоритма ключа записанного запроса
	ASSERT_EQ(request.key().algorithm, "1.2.840.113549.1.1.1");
	// Проверяем опознаватель алгоритма подписи записанного запроса
	ASSERT_EQ(request.algorithms(), "1.2.840.113549.1.1.11");
	// Проверяем число запрошенных расширений
	ASSERT_EQ(request.extension().size(), static_cast <size_t> (1));
	// Проверяем опознаватель запрошенного расширения
	ASSERT_EQ(request.extension().front().oid, "2.5.29.19");
	// Проверяем подпись записанного запроса сведениями об открытом ключе самого запроса
	ASSERT_EQ(x509::verify(request, request.key()), x509::error_t::NONE);
	// Проверяем совпадение открытого ключа записанного запроса с эталонным байт в байт
	ASSERT_EQ(request.key().key.size, reference.key().key.size);
	ASSERT_EQ(::memcmp(request.key().key.data, reference.key().key.data, request.key().key.size), 0);
}

/**
 * Проверка записи запросов ключами всех семейств набора: системный openssl
 * принимает записанный запрос и подтверждает его подпись (req -verify)
 */
TEST(RequestTest, Openssl){
	// Если openssl недоступен
	if(shell("openssl version >/dev/null 2>&1") != 0)
		// Пропускаем проверку
		GTEST_SKIP() << "openssl недоступен";
	// Временный каталог
	sandbox_t sandbox;
	// Проверяем готовность временного каталога
	ASSERT_TRUE(sandbox.ready());
	// Записи запросов набора и их ключи
	const char * names[] = {"leaf-rsa", "leaf-ec"};
	/**
	 * Выполняем перебор запросов набора
	 */
	for(size_t i = 0; i < 2; i++){
		// Тело записи эталонного запроса
		const std::vector <uint8_t> der = body(corpus(std::string(names[i]) + ".csr"));
		// Проверяем наличие записи
		ASSERT_FALSE(der.empty()) << "Запрос: " << names[i];
		// Эталонный запрос
		x509::request_t reference;
		// Проверяем разбор эталонного запроса
		ASSERT_EQ(reference.parse(view(der)), x509::error_t::NONE) << "Запрос: " << names[i];
		// Подготовленный секретный ключ владельца запроса
		keys::signer_t signer;
		// Проверяем подготовку ключа из записи набора
		ASSERT_EQ(signer.prepare(view(bytes(corpus(std::string(names[i]) + ".key")))), keys::error_t::NONE) << "Запрос: " << names[i];
		// Записанный запрос
		std::vector <uint8_t> encoded;
		// Проверяем запись запроса без расширений
		ASSERT_EQ(x509::encode(reference.subjects(), reference.key(), std::vector <x509::extension_t> (), signer, digest::hash_t::SHA256, encoded), x509::error_t::NONE) << "Запрос: " << names[i];
		// Путь к записанному запросу
		const std::string path = sandbox.file(std::string(names[i]) + ".der");
		// Проверяем запись файла запроса
		ASSERT_TRUE(spill(path, encoded)) << "Запрос: " << names[i];
		// Проверяем, что openssl принимает записанный запрос и подтверждает его подпись
		ASSERT_EQ(shell(std::string("openssl req -in ") + path + " -inform DER -verify -noout >/dev/null 2>&1"), 0) << "Запрос: " << names[i];
	}
}
