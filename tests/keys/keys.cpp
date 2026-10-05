/**
 * @file keys.cpp
 * @date 2026-09-04
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
 * @brief Исходный файл проверок модуля кодеков ключей
 *
 * @note Эталоном служит набор tests/corpus, выработанный openssl 3.6.3, и сам
 *       системный openssl: записи без пароля сличаются с набором байт в байт, а
 *       зашифрованные записи и подписи - обменом с openssl в обе стороны
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
#include <posix.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <keys/keys.hpp>
#include <sign/gost.hpp>
#include <pem/pem.hpp>
#include <asn1/asn1.hpp>
#include <digest/hash.hpp>
#include <curve/parameters.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Метод запуска команды оболочки без консоли на входе
 *
 * @details stdin подаётся из /dev/null: у оболочки инструмента разработки он бывает
 *          сокетом, tcgetattr на нём отвечает EOPNOTSUPP, и консольный слой openssl
 *          валит разбор даже при пароле, заданном доводом
 *
 * @param command запускаемая команда
 *
 * @return        код возврата команды
 *
 */
static int shell(const std::string & command) {
	// Запускаем команду с пустым входом
	return ::system((command + " </dev/null").c_str());
}
/**
 * Пароль ко всем зашифрованным ключам набора: кириллица в UTF-8, десять октетов
 * при семи буквах, в выработку ключа идёт последовательностью октетов
 */
static const char * PASSWORD_CORPUS = "Пароль-123";

/**
 * Путь к набору ключей для сличения
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * Опознаватель кривой P-256
 */
static const char * P256 = "1.2.840.10045.3.1.7";

/**
 * Опознаватель кривой P-384
 */
static const char * P384 = "1.3.132.0.34";

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * @brief Описание ключа набора
	 *
	 */
	typedef struct Entry {
		// Имя ключа в наборе
		const char * name;
		// Вид ключа
		keys::kind_t kind;
		// Размер ключа в байтах
		size_t size;
		// Опознаватель кривой у ключей EC
		const char * oid;
	} entry_t;

	/**
	 * Ключи набора
	 */
	static const entry_t ENTRIES[] = {
		{"rsa2048", keys::kind_t::RSA, 256, ""},
		{"ec256", keys::kind_t::EC, 32, P256},
		{"ec384", keys::kind_t::EC, 48, P384},
		{"ed25519", keys::kind_t::ED25519, 32, ""},
		{"x25519", keys::kind_t::X25519, 32, ""}
	};

	/**
	 * Длины ключей шифра зашифрованных записей набора
	 */
	static const size_t BITS[] = {128, 192, 256};

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
	 * @brief Метод получения просмотра строки знаков
	 *
	 * @param text просматриваемая строка знаков
	 *
	 * @return     просмотр строки знаков
	 *
	 */
	static view_t view(const char * text) {
		// Выводим просмотр строки знаков
		return view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text));
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
	static bool spill(const std::string & path, const std::string & data) {
		// Открываем файл на запись
		std::ofstream file(path, std::ios::binary);
		// Записываем содержимое
		file.write(data.data(), static_cast <std::streamsize> (data.size()));
		// Выводим успешность записи
		return file.good();
	}
	/**
	 * @brief Метод записи набора байтов в файл
	 *
	 * @param path путь к записываемому файлу
	 * @param data записываемый набор байтов
	 *
	 * @return     признак успешности записи
	 *
	 */
	static bool spill(const std::string & path, const std::vector <uint8_t> & data) {
		// Выводим итог записи набора байтов строкой
		return spill(path, std::string(data.begin(), data.end()));
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
	 * @brief Метод хеширования набора байтов
	 *
	 * @param algorithm алгоритм хеширования
	 * @param data      хешируемый набор байтов
	 *
	 * @return          хеш набора байтов
	 *
	 */
	static std::vector <uint8_t> digested(const digest::hash_t algorithm, const std::vector <uint8_t> & data) {
		// Хеш набора байтов
		std::vector <uint8_t> result(digest::length(algorithm), 0);
		// Выполняем хеширование
		digest::hash(algorithm, view(data), result.data(), result.size());
		// Выводим хеш
		return result;
	}
	/**
	 * @brief Метод сличения открытых частей двух ключей
	 *
	 * @param first  первый ключ
	 * @param second второй ключ
	 *
	 * @return       признак совпадения открытых частей
	 *
	 */
	static bool alike(const keys::key_t & first, const keys::key_t & second) {
		// Выводим итог сличения вида и открытых составляющих
		return (
			(first.kind == second.kind) && (first.oid == second.oid) &&
			(first.n == second.n) && (first.e == second.e) &&
			(first.x == second.x) && (first.y == second.y) && (first.key == second.key)
		);
	}
	/**
	 * @brief Метод выработки подписи данных разобранным ключом
	 *
	 * @param key    ключ подписи
	 * @param data   подписываемые данные
	 * @param result место, в которое помещается подпись в виде, понятном openssl
	 *
	 * @return       признак успешности выработки подписи
	 *
	 */
	static bool produce(const keys::key_t & key, const std::vector <uint8_t> & data, std::vector <uint8_t> & result) {
		/**
		 * Выполняем определение вида ключа
		 */
		switch(static_cast <uint8_t> (key.kind)){
			// Если ключ RSA
			case static_cast <uint8_t> (keys::kind_t::RSA): {
				// Примитив RSA
				sign::rsa_t rsa;
				// Если ключ установить не удалось
				if(!key.load(rsa))
					// Выводим отказ
					return false;
				// Хеш данных
				const std::vector <uint8_t> digest = digested(digest::hash_t::SHA256, data);
				// Выделяем место под подпись
				result.assign(rsa.size(), 0);
				// Выводим итог выработки подписи PKCS #1 v1.5
				return rsa.make(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view(digest), result.data());
			}
			// Если ключ EC
			case static_cast <uint8_t> (keys::kind_t::EC): {
				// Кривая ключа
				curve::curve_t curve;
				// Примитив ECDSA
				sign::ecdsa_t ecdsa;
				// Если ключ установить не удалось
				if(!key.load(ecdsa, curve))
					// Выводим отказ
					return false;
				// Алгоритм хеширования по размеру кривой
				const digest::hash_t algorithm = ((curve.size() == 32) ? digest::hash_t::SHA256 : digest::hash_t::SHA384);
				// Хеш данных
				const std::vector <uint8_t> digest = digested(algorithm, data);
				// Подпись парой чисел
				std::vector <uint8_t> raw(curve.size() * 2, 0);
				// Если подпись выработать не удалось
				if(!ecdsa.make(algorithm, view(digest), raw.data()))
					// Выводим отказ
					return false;
				// Выводим итог записи подписи в кодировке DER
				return sign::encode(view(raw), result);
			}
			// Если ключ Ed25519
			case static_cast <uint8_t> (keys::kind_t::ED25519): {
				// Примитив Ed25519
				sign::ed25519_t ed25519;
				// Если ключ установить не удалось
				if(!key.load(ed25519))
					// Выводим отказ
					return false;
				// Выделяем место под подпись
				result.assign(sign::ed25519_t::SIGNATURE_SIZE, 0);
				// Выводим итог выработки подписи
				return ed25519.make(view(data), result.data());
			}
		}
		// Выводим отказ: ключ подписи не вырабатывает
		return false;
	}
	/**
	 * @brief Метод проверки подписи данных разобранным ключом
	 *
	 * @param key       ключ проверки подписи
	 * @param data      подписанные данные
	 * @param signature проверяемая подпись в виде, понятном openssl
	 *
	 * @return          признак того, что подпись сошлась
	 *
	 */
	static bool verify(const keys::key_t & key, const std::vector <uint8_t> & data, const std::vector <uint8_t> & signature) {
		/**
		 * Выполняем определение вида ключа
		 */
		switch(static_cast <uint8_t> (key.kind)){
			// Если ключ RSA
			case static_cast <uint8_t> (keys::kind_t::RSA): {
				// Примитив RSA
				sign::rsa_t rsa;
				// Если ключ установить не удалось
				if(!key.load(rsa))
					// Выводим отказ
					return false;
				// Хеш данных
				const std::vector <uint8_t> digest = digested(digest::hash_t::SHA256, data);
				// Выводим итог проверки подписи PKCS #1 v1.5
				return rsa.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view(digest), view(signature));
			}
			// Если ключ EC
			case static_cast <uint8_t> (keys::kind_t::EC): {
				// Кривая ключа
				curve::curve_t curve;
				// Примитив ECDSA
				sign::ecdsa_t ecdsa;
				// Если ключ установить не удалось
				if(!key.load(ecdsa, curve))
					// Выводим отказ
					return false;
				// Алгоритм хеширования по размеру кривой
				const digest::hash_t algorithm = ((curve.size() == 32) ? digest::hash_t::SHA256 : digest::hash_t::SHA384);
				// Хеш данных
				const std::vector <uint8_t> digest = digested(algorithm, data);
				// Подпись парой чисел
				std::vector <uint8_t> raw(curve.size() * 2, 0);
				// Если подпись из кодировки DER разобрать не удалось
				if(!sign::decode(view(signature), raw.data(), raw.size()))
					// Выводим отказ
					return false;
				// Выводим итог проверки подписи
				return ecdsa.check(view(digest), view(raw));
			}
			// Если ключ Ed25519
			case static_cast <uint8_t> (keys::kind_t::ED25519): {
				// Примитив Ed25519
				sign::ed25519_t ed25519;
				// Если ключ установить не удалось
				if(!key.load(ed25519))
					// Выводим отказ
					return false;
				// Выводим итог проверки подписи
				return ed25519.check(view(data), view(signature));
			}
		}
		// Выводим отказ: ключ подписи не проверяет
		return false;
	}
	/**
	 * @brief Метод выработки ключа ГОСТ на заданной кривой средствами библиотеки
	 *
	 * @param oid       опознаватель кривой
	 * @param algorithm опознаватель алгоритма ключа
	 * @param result    место, в которое помещается выработанный ключ
	 *
	 * @return          признак успешности выработки ключа
	 *
	 */
	static bool gost(const char * oid, const char * algorithm, keys::key_t & result) {
		// Кривая ключа
		curve::curve_t curve;
		// Если кривую установить не удалось
		if(!curve::parameters(oid, curve))
			// Выводим отказ
			return false;
		// Объект модуля электронной подписи ГОСТ
		sign::gost_t signer;
		// Если кривую подписи установить не удалось
		if(!signer.start(curve))
			// Выводим отказ
			return false;
		// Выделяем место под секретный скаляр
		result.d.assign(curve.size(), 0);
		// Если секретный скаляр выработать библиотекой не удалось
		if(!signer.generate(result.d.data(), result.d.size()))
			// Выводим отказ
			return false;
		// Устанавливаем вид ключа
		result.kind = keys::kind_t::GOST;
		// Устанавливаем опознаватель кривой
		result.oid = oid;
		// Устанавливаем опознаватель алгоритма
		result.algorithm = algorithm;
		// Устанавливаем опознаватель хеша по размеру кривой
		result.digest = ((curve.size() == 32) ? "1.2.643.7.1.1.2.2" : "1.2.643.7.1.1.2.3");
		// Выводим успешность выработки
		return true;
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
				char pattern[] = "/tmp/ants-keys-XXXXXX";
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
};

/**
 * Проверка разбора каждого ключа набора: вид, размеры и согласие открытых частей
 */
TEST(KeysTest, Corpus){
	/**
	 * Выполняем перебор ключей набора
	 */
	for(const entry_t & entry : ENTRIES){
		// Секретный ключ из обёртки PEM
		keys::key_t secret;
		// Проверяем разбор секретного ключа из обёртки PEM
		ASSERT_EQ(keys::decode(corpus(std::string(entry.name) + ".pem"), view_t(), secret), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Проверяем вид ключа
		ASSERT_EQ(secret.kind, entry.kind) << "Ключ: " << entry.name;
		// Проверяем наличие секретной части
		ASSERT_TRUE(secret.secret()) << "Ключ: " << entry.name;
		// Проверяем размер ключа
		ASSERT_EQ(secret.size(), entry.size) << "Ключ: " << entry.name;
		// Проверяем опознаватель кривой
		ASSERT_EQ(secret.oid, std::string(entry.oid)) << "Ключ: " << entry.name;
		// Секретный ключ из кодировки DER
		keys::key_t direct;
		// Проверяем разбор секретного ключа из кодировки DER
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(bytes(corpus(std::string(entry.name) + ".der"))), direct), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Проверяем совпадение открытых частей
		ASSERT_TRUE(alike(secret, direct)) << "Ключ: " << entry.name;
		// Проверяем совпадение секретных частей
		ASSERT_EQ(secret.d, direct.d) << "Ключ: " << entry.name;
		// Открытый ключ из обёртки PEM
		keys::key_t opened;
		// Проверяем разбор открытого ключа из обёртки PEM
		ASSERT_EQ(keys::decode(corpus(std::string(entry.name) + ".pub.pem"), view_t(), opened), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Проверяем отсутствие секретной части
		ASSERT_FALSE(opened.secret()) << "Ключ: " << entry.name;
		// Проверяем размер ключа
		ASSERT_EQ(opened.size(), entry.size) << "Ключ: " << entry.name;
		// Проверяем совпадение открытых частей секретного и открытого ключей
		ASSERT_TRUE(alike(secret, opened)) << "Ключ: " << entry.name;
		// Открытый ключ из кодировки DER
		keys::key_t plain;
		// Проверяем разбор открытого ключа из кодировки DER
		ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(bytes(corpus(std::string(entry.name) + ".pub.der"))), plain), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Проверяем совпадение открытых частей
		ASSERT_TRUE(alike(opened, plain)) << "Ключ: " << entry.name;
		// Если ключ RSA
		if(entry.kind == keys::kind_t::RSA){
			// Проверяем размеры составляющих секретного ключа
			ASSERT_EQ(secret.n.size(), static_cast <size_t> (256));
			// Проверяем открытый показатель
			ASSERT_EQ(secret.e, (std::vector <uint8_t> {0x01, 0x00, 0x01}));
			// Проверяем размеры сомножителей
			ASSERT_EQ(secret.p.size(), static_cast <size_t> (128));
			// Проверяем размеры сомножителей
			ASSERT_EQ(secret.q.size(), static_cast <size_t> (128));
			// Проверяем пустоту секретных составляющих открытого ключа
			ASSERT_TRUE(opened.d.empty() && opened.p.empty() && opened.q.empty() && opened.dP.empty() && opened.dQ.empty() && opened.qInv.empty());
		}
		// Если ключ EC
		if(entry.kind == keys::kind_t::EC){
			// Проверяем размеры координат
			ASSERT_EQ(secret.x.size(), entry.size) << "Ключ: " << entry.name;
			// Проверяем размеры координат
			ASSERT_EQ(secret.y.size(), entry.size) << "Ключ: " << entry.name;
			// Проверяем размер скаляра
			ASSERT_EQ(secret.d.size(), entry.size) << "Ключ: " << entry.name;
		}
		// Если ключ Ed25519 либо X25519
		if((entry.kind == keys::kind_t::ED25519) || (entry.kind == keys::kind_t::X25519)){
			// Проверяем размер зерна
			ASSERT_EQ(secret.d.size(), static_cast <size_t> (32)) << "Ключ: " << entry.name;
			// Проверяем размер открытого ключа
			ASSERT_EQ(secret.key.size(), static_cast <size_t> (32)) << "Ключ: " << entry.name;
		}
	}
}

/**
 * Проверка совпадения записи байт в байт с набором: openssl пишет канонично
 */
TEST(KeysTest, Canonical){
	/**
	 * Выполняем перебор ключей набора
	 */
	for(const entry_t & entry : ENTRIES){
		// Секретный ключ набора
		keys::key_t secret;
		// Проверяем разбор секретного ключа
		ASSERT_EQ(keys::decode(corpus(std::string(entry.name) + ".pem"), view_t(), secret), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Запись PrivateKeyInfo
		std::vector <uint8_t> der;
		// Проверяем запись PrivateKeyInfo
		ASSERT_EQ(keys::encodePrivateKeyInfo(secret, der), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Проверяем совпадение записи с набором байт в байт
		ASSERT_EQ(der, bytes(corpus(std::string(entry.name) + ".der"))) << "Ключ: " << entry.name;
		// Проверяем запись SubjectPublicKeyInfo из секретного ключа
		ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(secret, der), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Проверяем совпадение записи с набором байт в байт
		ASSERT_EQ(der, bytes(corpus(std::string(entry.name) + ".pub.der"))) << "Ключ: " << entry.name;
		// Открытый ключ набора
		keys::key_t opened;
		// Проверяем разбор открытого ключа
		ASSERT_EQ(keys::decode(corpus(std::string(entry.name) + ".pub.pem"), view_t(), opened), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Проверяем запись SubjectPublicKeyInfo из открытого ключа
		ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(opened, der), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Проверяем совпадение записи с набором байт в байт
		ASSERT_EQ(der, bytes(corpus(std::string(entry.name) + ".pub.der"))) << "Ключ: " << entry.name;
		// Проверяем, что секретной записи у открытого ключа нет
		ASSERT_EQ(keys::encodePrivateKeyInfo(opened, der), keys::error_t::EMPTY) << "Ключ: " << entry.name;
	}
}

/**
 * Проверка круга PEM → DER → PEM: текст выходит тем же, что у openssl
 */
TEST(KeysTest, Roundtrip){
	/**
	 * Выполняем перебор ключей набора
	 */
	for(const entry_t & entry : ENTRIES){
		// Текст секретного ключа набора
		const std::string secret = corpus(std::string(entry.name) + ".pem");
		// Разобранный ключ
		keys::key_t key;
		// Проверяем разбор секретного ключа
		ASSERT_EQ(keys::decode(secret, view_t(), key), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Текст записи
		std::string text;
		// Проверяем запись секретного ключа
		ASSERT_EQ(keys::encode(key, keys::container_t::PRIVATE, text), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Проверяем совпадение текста с набором
		ASSERT_EQ(text, secret) << "Ключ: " << entry.name;
		// Текст открытого ключа набора
		const std::string opened = corpus(std::string(entry.name) + ".pub.pem");
		// Проверяем запись открытого ключа из секретного
		ASSERT_EQ(keys::encode(key, keys::container_t::PUBLIC, text), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Проверяем совпадение текста с набором
		ASSERT_EQ(text, opened) << "Ключ: " << entry.name;
		// Разобранный вновь ключ
		keys::key_t again;
		// Проверяем разбор записанного текста
		ASSERT_EQ(keys::decode(text, view_t(), again), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Проверяем совпадение открытых частей
		ASSERT_TRUE(alike(key, again)) << "Ключ: " << entry.name;
	}
}

/**
 * Проверка записей вне обёртки: ECPrivateKey по SEC 1 и RSAPrivateKey по PKCS #1
 */
TEST(KeysTest, Bare){
	// Ключ EC из записи SEC 1
	keys::key_t sec1;
	// Текст записи SEC 1
	const std::string ec = corpus("ec256.sec1.pem");
	// Проверяем разбор записи SEC 1 из обёртки PEM
	ASSERT_EQ(keys::decode(ec, view_t(), sec1), keys::error_t::NONE);
	// Ключ EC из обёртки PrivateKeyInfo
	keys::key_t wrapped;
	// Проверяем разбор обёртки PrivateKeyInfo
	ASSERT_EQ(keys::decode(corpus("ec256.pem"), view_t(), wrapped), keys::error_t::NONE);
	// Проверяем совпадение открытых частей
	ASSERT_TRUE(alike(sec1, wrapped));
	// Проверяем совпадение секретных частей
	ASSERT_EQ(sec1.d, wrapped.d);
	// Запись в кодировке DER
	std::vector <uint8_t> der;
	// Проверяем запись ECPrivateKey
	ASSERT_EQ(keys::encodeECPrivateKey(wrapped, der), keys::error_t::NONE);
	// Проверяем совпадение записи с телом записи набора байт в байт
	ASSERT_EQ(der, body(ec));
	// Ключ из голой записи
	keys::key_t direct;
	// Проверяем разбор голой записи ECPrivateKey
	ASSERT_EQ(keys::decodeECPrivateKey(view(der), direct), keys::error_t::NONE);
	// Проверяем совпадение открытых частей
	ASSERT_TRUE(alike(direct, wrapped));
	// Ключ RSA из записи PKCS #1
	keys::key_t pkcs1;
	// Текст записи PKCS #1
	const std::string rsa = corpus("rsa2048.pkcs1.pem");
	// Проверяем разбор записи PKCS #1 из обёртки PEM
	ASSERT_EQ(keys::decode(rsa, view_t(), pkcs1), keys::error_t::NONE);
	// Проверяем разбор обёртки PrivateKeyInfo
	ASSERT_EQ(keys::decode(corpus("rsa2048.pem"), view_t(), wrapped), keys::error_t::NONE);
	// Проверяем совпадение открытых частей
	ASSERT_TRUE(alike(pkcs1, wrapped));
	// Проверяем совпадение секретных частей
	ASSERT_TRUE((pkcs1.d == wrapped.d) && (pkcs1.p == wrapped.p) && (pkcs1.q == wrapped.q) && (pkcs1.dP == wrapped.dP) && (pkcs1.dQ == wrapped.dQ) && (pkcs1.qInv == wrapped.qInv));
	// Проверяем запись RSAPrivateKey
	ASSERT_EQ(keys::encodeRSAPrivateKey(wrapped, der), keys::error_t::NONE);
	// Проверяем совпадение записи с телом записи набора байт в байт
	ASSERT_EQ(der, body(rsa));
	// Проверяем разбор голой записи RSAPrivateKey
	ASSERT_EQ(keys::decodeRSAPrivateKey(view(der), direct), keys::error_t::NONE);
	// Проверяем совпадение открытых частей
	ASSERT_TRUE(alike(direct, wrapped));
	// Проверяем запись RSAPublicKey
	ASSERT_EQ(keys::encodeRSAPublicKey(wrapped, der), keys::error_t::NONE);
	// Проверяем разбор голой записи RSAPublicKey
	ASSERT_EQ(keys::decodeRSAPublicKey(view(der), direct), keys::error_t::NONE);
	// Проверяем совпадение открытых частей
	ASSERT_TRUE(alike(direct, wrapped));
	// Проверяем отсутствие секретной части
	ASSERT_FALSE(direct.secret());
	// Проверяем отказ разбора RSAPrivateKey как RSAPublicKey
	ASSERT_EQ(keys::encodeRSAPrivateKey(wrapped, der), keys::error_t::NONE);
	// Проверяем отказ разбора: полей девять, а не два
	ASSERT_EQ(keys::decodeRSAPublicKey(view(der), direct), keys::error_t::STRUCTURE);
}

/**
 * Проверка зашифрованных ключей набора: пароль набора подходит, чужой - нет
 */
TEST(KeysTest, Encrypted){
	/**
	 * Выполняем перебор ключей набора
	 */
	for(const entry_t & entry : ENTRIES){
		// Эталонная запись PrivateKeyInfo
		const std::vector <uint8_t> reference = bytes(corpus(std::string(entry.name) + ".der"));
		/**
		 * Выполняем перебор длин ключа шифра
		 */
		for(const size_t bits : BITS){
			// Имя зашифрованного файла набора
			const std::string name = (std::string(entry.name) + ".aes-" + std::to_string(bits) + "-cbc.enc.pem");
			// Текст зашифрованного ключа
			const std::string text = corpus(name);
			// Проверяем наличие файла набора
			ASSERT_FALSE(text.empty()) << "Файл: " << name;
			// Разобранный ключ
			keys::key_t key;
			// Проверяем разбор зашифрованного ключа паролем набора
			ASSERT_EQ(keys::decode(text, view(PASSWORD_CORPUS), key), keys::error_t::NONE) << "Файл: " << name;
			// Проверяем вид ключа
			ASSERT_EQ(key.kind, entry.kind) << "Файл: " << name;
			// Запись расшифрованного ключа
			std::vector <uint8_t> der;
			// Проверяем запись расшифрованного ключа
			ASSERT_EQ(keys::encodePrivateKeyInfo(key, der), keys::error_t::NONE) << "Файл: " << name;
			// Проверяем совпадение расшифрованного ключа с эталоном байт в байт
			ASSERT_EQ(der, reference) << "Файл: " << name;
			// Проверяем отказ по чужому паролю
			ASSERT_EQ(keys::decode(text, view("Пароль-124"), key), keys::error_t::PASSWORD) << "Файл: " << name;
			// Проверяем отказ по пустому паролю
			ASSERT_EQ(keys::decode(text, view_t(), key), keys::error_t::PASSWORD) << "Файл: " << name;
			// Проверяем, что после отказа ключ сброшен
			ASSERT_EQ(key.kind, keys::kind_t::NONE) << "Файл: " << name;
			// Проверяем отказ по паролю в местной кодировке: те же буквы в CP1251 не подходят
			ASSERT_EQ(keys::decode(text, view("\xCF\xE0\xF0\xEE\xEB\xFC-123"), key), keys::error_t::PASSWORD) << "Файл: " << name;
		}
	}
}

/**
 * Проверка круга зашифрованной записи своими средствами во всех длинах ключа шифра
 */
TEST(KeysTest, Sealed){
	/**
	 * Выполняем перебор ключей набора
	 */
	for(const entry_t & entry : ENTRIES){
		// Секретный ключ набора
		keys::key_t secret;
		// Проверяем разбор секретного ключа
		ASSERT_EQ(keys::decode(corpus(std::string(entry.name) + ".pem"), view_t(), secret), keys::error_t::NONE) << "Ключ: " << entry.name;
		/**
		 * Выполняем перебор длин ключа шифра
		 */
		for(const size_t bits : BITS){
			// Зашифрованная запись
			std::vector <uint8_t> der;
			// Проверяем запись зашифрованного ключа с малым числом оборотов
			ASSERT_EQ(keys::encodeEncryptedPrivateKeyInfo(secret, view(PASSWORD_CORPUS), der, bits, 100), keys::error_t::NONE) << "Ключ: " << entry.name;
			// Разобранный ключ
			keys::key_t key;
			// Проверяем разбор зашифрованного ключа
			ASSERT_EQ(keys::decodeEncryptedPrivateKeyInfo(view(der), view(PASSWORD_CORPUS), key), keys::error_t::NONE) << "Ключ: " << entry.name;
			// Проверяем совпадение открытых частей
			ASSERT_TRUE(alike(secret, key)) << "Ключ: " << entry.name;
			// Проверяем совпадение секретных частей
			ASSERT_EQ(secret.d, key.d) << "Ключ: " << entry.name;
			// Проверяем отказ по чужому паролю
			ASSERT_EQ(keys::decodeEncryptedPrivateKeyInfo(view(der), view("другой"), key), keys::error_t::PASSWORD) << "Ключ: " << entry.name;
			// Вторая зашифрованная запись того же ключа
			std::vector <uint8_t> other;
			// Проверяем повторную запись
			ASSERT_EQ(keys::encodeEncryptedPrivateKeyInfo(secret, view(PASSWORD_CORPUS), other, bits, 100), keys::error_t::NONE) << "Ключ: " << entry.name;
			// Проверяем, что соль и синхропосылка случайны: записи различны
			ASSERT_NE(der, other) << "Ключ: " << entry.name;
			// Текст зашифрованной записи
			std::string text;
			// Проверяем запись зашифрованного ключа в обёртке PEM
			ASSERT_EQ(keys::encode(secret, keys::container_t::ENCRYPTED, text, view(PASSWORD_CORPUS), bits, 100), keys::error_t::NONE) << "Ключ: " << entry.name;
			// Проверяем метку записи
			ASSERT_NE(text.find("-----BEGIN ENCRYPTED PRIVATE KEY-----"), std::string::npos) << "Ключ: " << entry.name;
			// Проверяем разбор зашифрованного ключа из обёртки PEM
			ASSERT_EQ(keys::decode(text, view(PASSWORD_CORPUS), key), keys::error_t::NONE) << "Ключ: " << entry.name;
			// Проверяем совпадение секретных частей
			ASSERT_EQ(secret.d, key.d) << "Ключ: " << entry.name;
		}
		// Зашифрованная запись
		std::vector <uint8_t> der;
		// Проверяем отказ по неизвестной длине ключа шифра
		ASSERT_EQ(keys::encodeEncryptedPrivateKeyInfo(secret, view(PASSWORD_CORPUS), der, 64, 100), keys::error_t::CIPHER) << "Ключ: " << entry.name;
		// Проверяем отказ по нулевому числу оборотов
		ASSERT_EQ(keys::encodeEncryptedPrivateKeyInfo(secret, view(PASSWORD_CORPUS), der, 256, 0), keys::error_t::CIPHER) << "Ключ: " << entry.name;
	}
}

/**
 * Проверка разбора записи PKCS #12, выработанной openssl: ключ и цепочка
 * сертификатов сходятся с исходными, чужой пароль отвергается имитовставкой
 */
TEST(KeysTest, Pkcs12){
	// Запись PKCS #12 набора
	const std::vector <uint8_t> der = bytes(corpus("test.p12"));
	// Проверяем наличие записи
	ASSERT_FALSE(der.empty());
	// Разобранный ключ
	keys::key_t key;
	// Разобранная цепочка сертификатов
	std::vector <std::vector <uint8_t>> chain;
	// Проверяем разбор записи паролем набора
	ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::NONE);
	// Проверяем вид ключа: EC на кривой P-256
	ASSERT_EQ(key.kind, keys::kind_t::EC);
	// Проверяем опознаватель кривой ключа
	ASSERT_EQ(key.oid, P256);
	// Проверяем наличие секретной части ключа
	ASSERT_TRUE(key.secret());
	// Эталонный ключ набора
	keys::key_t reference;
	// Проверяем разбор эталонного ключа
	ASSERT_EQ(keys::decode(corpus("p12key.pem"), view_t(), reference), keys::error_t::NONE);
	// Проверяем совпадение секретных частей ключей
	ASSERT_EQ(key.d, reference.d);
	// Проверяем совпадение открытых частей ключей
	ASSERT_EQ(key.x, reference.x);
	// Проверяем совпадение открытых частей ключей
	ASSERT_EQ(key.y, reference.y);
	// Проверяем число сертификатов цепочки
	ASSERT_EQ(chain.size(), static_cast <size_t> (1));
	// Эталонный сертификат набора
	const std::string pem = corpus("p12crt.pem");
	// Проверяем наличие эталонного сертификата
	ASSERT_FALSE(pem.empty());
	// Цепочка эталонного сертификата
	std::vector <std::vector <uint8_t>> expected;
	// Разбираем эталонный сертификат из записи PEM
	ASSERT_EQ(pem::certificates(pem, expected), pem::error_t::NONE);
	// Проверяем совпадение сертификата цепочки с эталоном байт в байт
	ASSERT_EQ(chain[0], expected[0]);
	// Проверяем отказ по чужому паролю: имитовставка записи не сходится
	ASSERT_EQ(keys::decodePkcs12(view(der), view("другой"), key, chain), keys::error_t::PASSWORD);
	// Проверяем, что после отказа ключ и цепочка сброшены
	ASSERT_EQ(key.kind, keys::kind_t::NONE);
	// Проверяем, что цепочка пуста
	ASSERT_TRUE(chain.empty());
	// Порченая запись: последний байт перевёрнут
	std::vector <uint8_t> damaged(der);
	damaged[damaged.size() - 1] = static_cast <uint8_t> (damaged[damaged.size() - 1] ^ 0xFF);
	// Проверяем отказ разбора порченой записи
	ASSERT_NE(keys::decodePkcs12(view(damaged), view("secret"), key, chain), keys::error_t::NONE);
	// Проверяем отказ разбора пустой записи
	ASSERT_NE(keys::decodePkcs12(view_t(), view("secret"), key, chain), keys::error_t::NONE);
}

/**
 * Проверка подписей набора: подпись openssl по data.bin сходится с загруженным ключом
 */
TEST(KeysTest, Signatures){
	// Подписанные данные
	const std::vector <uint8_t> data = bytes(corpus("data.bin"));
	// Проверяем наличие данных
	ASSERT_FALSE(data.empty());
	// Имена ключей и подписей
	const char * pairs[][2] = {
		{"rsa2048", "sig.rsa.sha256"},
		{"ec256", "sig.ec256.sha256"},
		{"ec384", "sig.ec384.sha384"},
		{"ed25519", "sig.ed25519"}
	};
	/**
	 * Выполняем перебор пар ключ и подпись
	 */
	for(const auto & pair : pairs){
		// Подпись набора
		const std::vector <uint8_t> signature = bytes(corpus(pair[1]));
		// Проверяем наличие подписи
		ASSERT_FALSE(signature.empty()) << "Подпись: " << pair[1];
		// Открытый ключ набора
		keys::key_t opened;
		// Проверяем разбор открытого ключа
		ASSERT_EQ(keys::decode(corpus(std::string(pair[0]) + ".pub.pem"), view_t(), opened), keys::error_t::NONE) << "Ключ: " << pair[0];
		// Проверяем подпись открытым ключом
		ASSERT_TRUE(verify(opened, data, signature)) << "Подпись: " << pair[1];
		// Секретный ключ набора
		keys::key_t secret;
		// Проверяем разбор секретного ключа
		ASSERT_EQ(keys::decode(corpus(std::string(pair[0]) + ".pem"), view_t(), secret), keys::error_t::NONE) << "Ключ: " << pair[0];
		// Проверяем подпись секретным ключом: открытая часть выведена из секретной
		ASSERT_TRUE(verify(secret, data, signature)) << "Подпись: " << pair[1];
		// Испорченные данные
		std::vector <uint8_t> spoiled = data;
		// Портим первый байт данных
		spoiled[0] ^= 0x01;
		// Проверяем, что подпись испорченных данных не сходится
		ASSERT_FALSE(verify(opened, spoiled, signature)) << "Подпись: " << pair[1];
		// Своя подпись данных
		std::vector <uint8_t> own;
		// Проверяем выработку своей подписи
		ASSERT_TRUE(produce(secret, data, own)) << "Ключ: " << pair[0];
		// Проверяем свою подпись открытым ключом
		ASSERT_TRUE(verify(opened, data, own)) << "Ключ: " << pair[0];
	}
	// Ключ X25519
	keys::key_t x25519;
	// Проверяем разбор ключа X25519
	ASSERT_EQ(keys::decode(corpus("x25519.pem"), view_t(), x25519), keys::error_t::NONE);
	// Своя подпись данных
	std::vector <uint8_t> own;
	// Проверяем, что ключ согласования подписи не вырабатывает
	ASSERT_FALSE(produce(x25519, data, own));
}

/**
 * Проверка обмена с openssl: наши зашифрованные записи и подписи принимаются им, его - нами
 */
TEST(KeysTest, Openssl){
	// Если openssl недоступен
	if(shell("openssl version >/dev/null 2>&1") != 0)
		// Пропускаем проверку
		GTEST_SKIP() << "openssl недоступен";
	// Если openssl не умеет Ed25519 (старше 1.1.1), обмен по набору невозможен
	if(shell("openssl genpkey -algorithm ed25519 -out /dev/null >/dev/null 2>&1") != 0)
		// Объявляем пропуск проверки вслух
		GTEST_SKIP() << "openssl старше 1.1.1: нет Ed25519";
	// Признак того, что openssl умеет PBES2 с выбором имитовставки и числа оборотов (у LibreSSL нет)
	const bool tunable = (shell((std::string("openssl pkcs8 -topk8 -in ") + CORPUS + "/ec256.pem -v2 aes-128-cbc -v2prf hmacWithSHA256 -iter 1 -passout pass:x -out /dev/null >/dev/null 2>&1").c_str()) == 0);
	// Признак того, что openssl умеет подписывать и проверять сообщение целиком (у LibreSSL нет -rawin)
	const bool rawin = (shell((std::string("openssl pkeyutl -sign -inkey ") + CORPUS + "/ed25519.pem -rawin -in " + CORPUS + "/data.bin -out /dev/null >/dev/null 2>&1").c_str()) == 0);
	// Если подписи сообщения целиком нет, говорим об этом вслух
	if(!rawin)
		// Выводим сообщение о пропуске части проверки
		std::cout << "openssl без pkeyutl -rawin: сличение подписей пропущено" << std::endl;
	// Если выбора имитовставки нет, говорим об этом вслух
	if(!tunable)
		// Выводим сообщение о пропуске части проверки
		std::cout << "openssl без -v2prf и -iter: сличение имитовставок PBES2 пропущено" << std::endl;
	// Временный каталог
	sandbox_t sandbox;
	// Проверяем готовность временного каталога
	ASSERT_TRUE(sandbox.ready());
	// Путь к подписанным данным
	const std::string message = (std::string(CORPUS) + "/data.bin");
	// Подписанные данные
	const std::vector <uint8_t> data = bytes(corpus("data.bin"));
	// Пароль обмена: не тот, что у набора
	const char * password = "Обмен-с-openssl-2026";
	/**
	 * Выполняем перебор ключей набора
	 */
	for(const entry_t & entry : ENTRIES){
		// Эталонная запись PrivateKeyInfo
		const std::vector <uint8_t> reference = bytes(corpus(std::string(entry.name) + ".der"));
		// Секретный ключ набора
		keys::key_t secret;
		// Проверяем разбор секретного ключа
		ASSERT_EQ(keys::decode(corpus(std::string(entry.name) + ".pem"), view_t(), secret), keys::error_t::NONE) << "Ключ: " << entry.name;
		/**
		 * Выполняем перебор длин ключа шифра
		 */
		for(const size_t bits : BITS){
			// Текст зашифрованной записи
			std::string text;
			// Проверяем запись зашифрованного ключа
			ASSERT_EQ(keys::encode(secret, keys::container_t::ENCRYPTED, text, view(password), bits), keys::error_t::NONE) << "Ключ: " << entry.name;
			// Путь к зашифрованной записи
			const std::string sealed = sandbox.file(std::string(entry.name) + "-" + std::to_string(bits) + ".enc.pem");
			// Путь к расшифрованной записи openssl
			const std::string unsealed = sandbox.file(std::string(entry.name) + "-" + std::to_string(bits) + ".pem");
			// Проверяем запись файла
			ASSERT_TRUE(spill(sealed, text)) << "Ключ: " << entry.name;
			// Проверяем, что openssl читает нашу зашифрованную запись
			ASSERT_EQ(shell((std::string("openssl pkey -in ") + sealed + " -passin pass:" + password + " -out " + unsealed).c_str()), 0) << "Ключ: " << entry.name << ", разрядов: " << bits;
			// Ключ, расшифрованный openssl
			keys::key_t unsealedKey;
			// Проверяем разбор расшифрованной openssl записи: издания openssl расходятся в необязательных полях и в самом виде записи (у 3.0 старый вид), оттого сличать её с набором байт в байт нельзя
			ASSERT_EQ(keys::decode(slurp(unsealed), view_t(), unsealedKey), keys::error_t::NONE) << "Ключ: " << entry.name << ", разрядов: " << bits;
			// Каноническая запись расшифрованного openssl ключа
			std::vector <uint8_t> canonical;
			// Проверяем каноническую запись расшифрованного ключа
			ASSERT_EQ(keys::encodePrivateKeyInfo(unsealedKey, canonical), keys::error_t::NONE) << "Ключ: " << entry.name << ", разрядов: " << bits;
			// Проверяем совпадение расшифрованного openssl ключа с эталоном в канонической записи
			ASSERT_EQ(canonical, reference) << "Ключ: " << entry.name << ", разрядов: " << bits;
			// Проверяем, что openssl отвергает чужой пароль
			ASSERT_NE(shell((std::string("openssl pkey -in ") + sealed + " -passin pass:" + password + "1 -noout 2>/dev/null").c_str()), 0) << "Ключ: " << entry.name;
		}
		// Имитовставки, которыми openssl шифрует ключ
		const char * prfs[] = {"hmacWithSHA1", "hmacWithSHA224", "hmacWithSHA256", "hmacWithSHA384", "hmacWithSHA512"};
		/**
		 * Выполняем перебор имитовставок
		 */
		for(const char * prf : prfs){
			// Если выбора имитовставки у openssl нет, перебор не нужен
			if(!tunable)
				// Прерываем перебор
				break;
			// Путь к зашифрованной openssl записи
			const std::string sealed = sandbox.file(std::string(entry.name) + "-" + prf + ".enc.pem");
			// Проверяем, что openssl зашифровал ключ с заданной имитовставкой и числом оборотов
			ASSERT_EQ(shell((std::string("openssl pkcs8 -topk8 -in ") + CORPUS + "/" + entry.name + ".pem -v2 aes-192-cbc -v2prf " + prf + " -iter 777 -passout pass:" + password + " -out " + sealed + " 2>/dev/null").c_str()), 0) << "Ключ: " << entry.name << ", имитовставка: " << prf;
			// Разобранный ключ
			keys::key_t key;
			// Проверяем разбор зашифрованной openssl записи
			ASSERT_EQ(keys::decode(slurp(sealed), view(password), key), keys::error_t::NONE) << "Ключ: " << entry.name << ", имитовставка: " << prf;
			// Запись расшифрованного ключа
			std::vector <uint8_t> der;
			// Проверяем запись расшифрованного ключа
			ASSERT_EQ(keys::encodePrivateKeyInfo(key, der), keys::error_t::NONE) << "Ключ: " << entry.name;
			// Проверяем совпадение расшифрованного ключа с эталоном байт в байт
			ASSERT_EQ(der, reference) << "Ключ: " << entry.name << ", имитовставка: " << prf;
		}
		// Путь к записи, зашифрованной старой схемой PBES1
		const std::string legacy = sandbox.file(std::string(entry.name) + "-legacy.enc.pem");
		// Если openssl зашифровал ключ старой схемой: у новых видов ключей она недоступна
		if(shell((std::string("openssl pkcs8 -topk8 -in ") + CORPUS + "/" + entry.name + ".pem -v1 PBE-SHA1-3DES -passout pass:" + password + " -out " + legacy + " 2>/dev/null").c_str()) == 0){
			// Разобранный ключ
			keys::key_t key;
			// Проверяем отказ схемы: PBES1 не поддерживается намеренно
			ASSERT_EQ(keys::decode(slurp(legacy), view(password), key), keys::error_t::CIPHER) << "Ключ: " << entry.name;
		}
		// Текст открытого ключа
		std::string text;
		// Проверяем запись открытого ключа
		ASSERT_EQ(keys::encode(secret, keys::container_t::PUBLIC, text), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Путь к открытому ключу
		const std::string opened = sandbox.file(std::string(entry.name) + ".pub.pem");
		// Проверяем запись файла
		ASSERT_TRUE(spill(opened, text)) << "Ключ: " << entry.name;
		// Проверяем, что openssl читает наш открытый ключ
		ASSERT_EQ(shell((std::string("openssl pkey -pubin -in ") + opened + " -noout 2>/dev/null").c_str()), 0) << "Ключ: " << entry.name;
		// Если ключ подписи не вырабатывает
		if(entry.kind == keys::kind_t::X25519)
			// Переходим к следующему ключу
			continue;
		// Своя подпись данных
		std::vector <uint8_t> own;
		// Проверяем выработку своей подписи
		ASSERT_TRUE(produce(secret, data, own)) << "Ключ: " << entry.name;
		// Путь к своей подписи
		const std::string signature = sandbox.file(std::string(entry.name) + ".sig");
		// Проверяем запись файла подписи
		ASSERT_TRUE(spill(signature, own)) << "Ключ: " << entry.name;
		// Довод хеша для openssl
		const std::string digest = ((entry.kind == keys::kind_t::ED25519) ? "" : ((entry.size == 48) ? " -digest sha384" : " -digest sha256"));
			// Если openssl умеет проверять сообщение целиком
			if(rawin){
				// Проверяем, что openssl принимает нашу подпись нашим открытым ключом
				ASSERT_EQ(shell((std::string("openssl pkeyutl -verify -pubin -inkey ") + opened + " -rawin" + digest + " -in " + message + " -sigfile " + signature + " >/dev/null 2>&1").c_str()), 0) << "Ключ: " << entry.name;
			}
	}
	// Путь к записи RSAPublicKey
	const std::string rsa = sandbox.file("rsa.pkcs1.pub.pem");
	// Проверяем, что openssl записал открытый ключ RSA по PKCS #1
	ASSERT_EQ(shell((std::string("openssl rsa -in ") + CORPUS + "/rsa2048.pem -RSAPublicKey_out -out " + rsa + " 2>/dev/null").c_str()), 0);
	// Разобранный ключ
	keys::key_t key;
	// Проверяем разбор записи под меткой «RSA PUBLIC KEY»
	ASSERT_EQ(keys::decode(slurp(rsa), view_t(), key), keys::error_t::NONE);
	// Открытый ключ набора
	keys::key_t opened;
	// Проверяем разбор открытого ключа набора
	ASSERT_EQ(keys::decode(corpus("rsa2048.pub.pem"), view_t(), opened), keys::error_t::NONE);
	// Проверяем совпадение открытых частей
	ASSERT_TRUE(alike(key, opened));
}

/**
 * Проверка ключей ГОСТ Р 34.10-2012: круг записи и подпись загруженным ключом
 */
TEST(KeysTest, Gost){
	// Кривые и алгоритмы ключей
	const char * sets[][2] = {
		{"1.2.643.7.1.2.1.1.1", "1.2.643.7.1.1.1.1"},
		{"1.2.643.7.1.2.1.2.1", "1.2.643.7.1.1.1.2"},
		{"1.2.643.2.2.35.1", "1.2.643.2.2.19"}
	};
	/**
	 * Выполняем перебор наборов параметров
	 */
	for(const auto & set : sets){
		// Выработанный ключ
		keys::key_t made;
		// Проверяем выработку ключа
		ASSERT_TRUE(gost(set[0], set[1], made)) << "Кривая: " << set[0];
		// Проверяем, что открытой части у выработанного ключа нет
		ASSERT_TRUE(made.x.empty());
		// Запись секретного ключа
		std::vector <uint8_t> der;
		// Проверяем запись PrivateKeyInfo: открытая часть выводится при записи
		ASSERT_EQ(keys::encodePrivateKeyInfo(made, der), keys::error_t::NONE) << "Кривая: " << set[0];
		// Разобранный секретный ключ
		keys::key_t secret;
		// Проверяем разбор PrivateKeyInfo
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), secret), keys::error_t::NONE) << "Кривая: " << set[0];
		// Проверяем вид ключа
		ASSERT_EQ(secret.kind, keys::kind_t::GOST);
		// Проверяем опознаватели
		ASSERT_TRUE((secret.oid == set[0]) && (secret.algorithm == set[1]) && (secret.digest == made.digest)) << "Кривая: " << set[0];
		// Проверяем совпадение секретных частей
		ASSERT_EQ(secret.d, made.d) << "Кривая: " << set[0];
		// Проверяем размер ключа
		ASSERT_EQ(secret.size(), made.d.size()) << "Кривая: " << set[0];
		// Запись открытого ключа
		std::vector <uint8_t> spki;
		// Проверяем запись SubjectPublicKeyInfo
		ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(secret, spki), keys::error_t::NONE) << "Кривая: " << set[0];
		// Разобранный открытый ключ
		keys::key_t opened;
		// Проверяем разбор SubjectPublicKeyInfo
		ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(spki), opened), keys::error_t::NONE) << "Кривая: " << set[0];
		// Проверяем совпадение открытых частей
		ASSERT_TRUE(alike(secret, opened) && (secret.algorithm == opened.algorithm) && (secret.digest == opened.digest)) << "Кривая: " << set[0];
		// Проверяем отсутствие секретной части
		ASSERT_FALSE(opened.secret());
		// Кривая подписи
		curve::curve_t curve;
		// Примитив подписи
		sign::gost_t signer;
		// Проверяем установку секретного ключа
		ASSERT_TRUE(secret.load(signer, curve)) << "Кривая: " << set[0];
		// Хеш подписываемых данных размером в координату
		std::vector <uint8_t> digest(curve.size(), 0x5A);
		// Подпись
		std::vector <uint8_t> signature(curve.order().size() * 2, 0);
		// Проверяем выработку подписи
		ASSERT_TRUE(signer.make(view(digest), signature.data())) << "Кривая: " << set[0];
		// Кривая проверки
		curve::curve_t other;
		// Примитив проверки
		sign::gost_t verifier;
		// Проверяем установку открытого ключа
		ASSERT_TRUE(opened.load(verifier, other)) << "Кривая: " << set[0];
		// Проверяем подпись открытым ключом
		ASSERT_TRUE(verifier.check(view(digest), view(signature))) << "Кривая: " << set[0];
		// Текст записей
		std::string text;
		// Проверяем запись в обёртке PEM
		ASSERT_EQ(keys::encode(secret, keys::container_t::PRIVATE, text), keys::error_t::NONE) << "Кривая: " << set[0];
		// Проверяем разбор из обёртки PEM
		ASSERT_EQ(keys::decode(text, view_t(), opened), keys::error_t::NONE) << "Кривая: " << set[0];
		// Проверяем совпадение секретных частей
		ASSERT_EQ(opened.d, secret.d) << "Кривая: " << set[0];
		// Проверяем запись зашифрованной обёртки PEM
		ASSERT_EQ(keys::encode(secret, keys::container_t::ENCRYPTED, text, view(PASSWORD_CORPUS), 256, 100), keys::error_t::NONE) << "Кривая: " << set[0];
		// Проверяем разбор зашифрованной обёртки PEM
		ASSERT_EQ(keys::decode(text, view(PASSWORD_CORPUS), opened), keys::error_t::NONE) << "Кривая: " << set[0];
		// Проверяем совпадение секретных частей
		ASSERT_EQ(opened.d, secret.d) << "Кривая: " << set[0];
		// Если openssl доступен
		if(shell("openssl version >/dev/null 2>&1") == 0){
			// Временный каталог
			sandbox_t sandbox;
			// Проверяем готовность временного каталога
			ASSERT_TRUE(sandbox.ready());
			// Проверяем запись файла
			ASSERT_TRUE(spill(sandbox.file("gost.der"), der));
			// Проверяем, что устройство записи разбирается openssl
			ASSERT_EQ(shell((std::string("openssl asn1parse -inform DER -in ") + sandbox.file("gost.der") + " >/dev/null 2>&1").c_str()), 0) << "Кривая: " << set[0];
		}
	}
	// Ключ с несогласованным алгоритмом: кривая 256 разрядов при алгоритме 512
	keys::key_t wrong;
	// Проверяем выработку ключа
	ASSERT_TRUE(gost("1.2.643.7.1.2.1.1.1", "1.2.643.7.1.1.1.2", wrong));
	// Запись ключа
	std::vector <uint8_t> der;
	// Проверяем запись PrivateKeyInfo: запись согласованности не проверяет
	ASSERT_EQ(keys::encodePrivateKeyInfo(wrong, der), keys::error_t::NONE);
	// Разобранный ключ
	keys::key_t key;
	// Проверяем отказ разбора: алгоритм с кривой не согласован
	ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), key), keys::error_t::ALGORITHM);
}

/**
 * Проверка отказов: хвост, неминимальная длина, чужие опознаватели, негодные значения
 */
TEST(KeysTest, Refusal){
	// Разобранный ключ
	keys::key_t key;
	// Проверяем отказ разбора пустой записи
	ASSERT_EQ(keys::decodePrivateKeyInfo(view_t(), key), keys::error_t::STRUCTURE);
	// Проверяем отказ разбора пустой записи
	ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view_t(), key), keys::error_t::STRUCTURE);
	// Проверяем отказ разбора пустой записи
	ASSERT_EQ(keys::decodeEncryptedPrivateKeyInfo(view_t(), view_t(), key), keys::error_t::STRUCTURE);
	/**
	 * Выполняем перебор ключей набора
	 */
	for(const entry_t & entry : ENTRIES){
		// Записи набора
		const std::vector <uint8_t> secret = bytes(corpus(std::string(entry.name) + ".der"));
		// Записи набора
		const std::vector <uint8_t> opened = bytes(corpus(std::string(entry.name) + ".pub.der"));
		// Запись с хвостом
		std::vector <uint8_t> trailing = secret;
		// Дописываем хвост
		trailing.push_back(0x00);
		// Проверяем отказ разбора записи с хвостом
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(trailing), key), keys::error_t::STRUCTURE) << "Ключ: " << entry.name;
		// Проверяем, что после отказа ключ сброшен
		ASSERT_EQ(key.kind, keys::kind_t::NONE) << "Ключ: " << entry.name;
		// Запись с хвостом
		trailing = opened;
		// Дописываем хвост
		trailing.push_back(0x00);
		// Проверяем отказ разбора записи с хвостом
		ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(trailing), key), keys::error_t::STRUCTURE) << "Ключ: " << entry.name;
		// Оборванная запись
		std::vector <uint8_t> truncated(secret.begin(), secret.end() - 1);
		// Проверяем отказ разбора оборванной записи
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(truncated), key), keys::error_t::STRUCTURE) << "Ключ: " << entry.name;
		// Запись с длиной не кратчайшего вида: у открытого ключа длина умещается в один байт с признаком длинного вида
		std::vector <uint8_t> excessive;
		// Записываем метку набора
		excessive.push_back(0x30);
		// Записываем признак длинного вида с одним байтом длины
		excessive.push_back(0x81);
		// Если длина набора умещается в короткий вид
		if(opened[1] < 0x80){
			// Записываем длину набора длинным видом
			excessive.push_back(opened[1]);
			// Дописываем содержимое набора
			excessive.insert(excessive.end(), opened.begin() + 2, opened.end());
			// Проверяем отказ разбора записи с длиной не кратчайшего вида
			ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(excessive), key), keys::error_t::STRUCTURE) << "Ключ: " << entry.name;
		}
		// Разборщик записи открытого ключа
		asn1::reader_t reader(view(opened));
		// Элементы записи
		asn1::element_t sequence, algorithm, oid;
		// Проверяем разбор набора
		ASSERT_TRUE(reader.next(asn1::tag_t::SEQUENCE, sequence));
		// Разборщик содержимого набора
		asn1::reader_t fields = reader.enter(sequence);
		// Проверяем разбор набора алгоритма
		ASSERT_TRUE(fields.next(asn1::tag_t::SEQUENCE, algorithm));
		// Разборщик содержимого набора алгоритма
		asn1::reader_t items = fields.enter(algorithm);
		// Проверяем разбор опознавателя алгоритма
		ASSERT_TRUE(items.next(asn1::tag_t::OBJECT, oid));
		// Смещение последнего байта опознавателя алгоритма
		const size_t last = static_cast <size_t> ((oid.content.data + oid.content.size - 1) - opened.data());
		// Запись с чужим опознавателем алгоритма
		std::vector <uint8_t> foreign = opened;
		// Портим последний байт опознавателя: кодировка остаётся годной, алгоритм становится чужим
		foreign[last] ^= 0x01;
		// Проверяем отказ разбора записи с чужим алгоритмом
		ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(foreign), key), keys::error_t::ALGORITHM) << "Ключ: " << entry.name;
		// Запись секретного ключа с чужим опознавателем: устройство обёртки то же, опознаватель лежит по тому же смещению
		foreign = secret;
		// Разборщик записи секретного ключа
		asn1::reader_t inner(view(secret));
		// Проверяем разбор набора
		ASSERT_TRUE(inner.next(asn1::tag_t::SEQUENCE, sequence));
		// Разборщик содержимого набора
		asn1::reader_t parts = inner.enter(sequence);
		// Проверяем разбор издания записи
		ASSERT_TRUE(parts.next(asn1::tag_t::INTEGER, algorithm));
		// Проверяем разбор набора алгоритма
		ASSERT_TRUE(parts.next(asn1::tag_t::SEQUENCE, algorithm));
		// Разборщик содержимого набора алгоритма
		asn1::reader_t names = parts.enter(algorithm);
		// Проверяем разбор опознавателя алгоритма
		ASSERT_TRUE(names.next(asn1::tag_t::OBJECT, oid));
		// Портим последний байт опознавателя
		foreign[static_cast <size_t> ((oid.content.data + oid.content.size - 1) - secret.data())] ^= 0x01;
		// Проверяем отказ разбора записи с чужим алгоритмом
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(foreign), key), keys::error_t::ALGORITHM) << "Ключ: " << entry.name;
		// Если ключ EC
		if(entry.kind == keys::kind_t::EC){
			// Проверяем разбор опознавателя кривой
			ASSERT_TRUE(items.next(asn1::tag_t::OBJECT, oid));
			// Запись с чужой кривой
			std::vector <uint8_t> curve = opened;
			// Портим последний байт опознавателя кривой: маска 0x40, а не 0x01 - иначе у ec384 «1.3.132.0.34» флип
			// младшего разряда дал бы «...35» = secp521r1, кривую теперь ведомую, и отказа кривой бы не было
			curve[static_cast <size_t> ((oid.content.data + oid.content.size - 1) - opened.data())] ^= 0x40;
			// Проверяем отказ разбора записи с чужой кривой
			ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(curve), key), keys::error_t::CURVE) << "Ключ: " << entry.name;
			// Запись с точкой вне кривой
			std::vector <uint8_t> outside = opened;
			// Портим последний байт второй координаты
			outside.back() ^= 0x01;
			// Проверяем отказ разбора записи с точкой вне кривой
			ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(outside), key), keys::error_t::CURVE) << "Ключ: " << entry.name;
			// Запись секретного ключа с точкой вне кривой: открытый ключ лежит в самом конце ECPrivateKey
			outside = secret;
			// Портим последний байт второй координаты
			outside.back() ^= 0x01;
			// Проверяем отказ разбора записи с точкой вне кривой
			ASSERT_EQ(keys::decodePrivateKeyInfo(view(outside), key), keys::error_t::CURVE) << "Ключ: " << entry.name;
			// Ключ с открытой частью от другого ключа той же кривой
			keys::key_t mixed;
			// Проверяем разбор секретного ключа
			ASSERT_EQ(keys::decodePrivateKeyInfo(view(secret), mixed), keys::error_t::NONE) << "Ключ: " << entry.name;
			// Ключ EC, чья открытая часть подменяется
			keys::key_t donor;
			// Проверяем разбор SubjectPublicKeyInfo этого же ключа
			ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(opened), donor), keys::error_t::NONE) << "Ключ: " << entry.name;
			// Обмениваем координаты местами: точка симметричной кривой ей не принадлежит либо не отвечает скаляру
			mixed.x.swap(mixed.y);
			// Запись ключа с подменённой открытой частью
			std::vector <uint8_t> der;
			// Проверяем запись ключа: запись согласия не проверяет
			ASSERT_EQ(keys::encodePrivateKeyInfo(mixed, der), keys::error_t::NONE) << "Ключ: " << entry.name;
			// Проверяем отказ разбора: открытая часть не сошлась с выведенной либо вне кривой
			ASSERT_NE(keys::decodePrivateKeyInfo(view(der), key), keys::error_t::NONE) << "Ключ: " << entry.name;
			// Голая запись без кривой: снимаем обёртку и опознаватель кривой
			asn1::writer_t writer;
			// Открываем набор записи
			writer.open(asn1::tag_t::SEQUENCE);
			// Записываем издание записи
			writer.integer(1);
			// Записываем секретный скаляр
			writer.octets(view(donor.x));
			// Закрываем набор записи
			writer.close();
			// Проверяем отказ разбора голой записи без кривой
			ASSERT_EQ(keys::decodeECPrivateKey(writer.data(), key), keys::error_t::CURVE) << "Ключ: " << entry.name;
		}
		// Если ключ Ed25519 либо X25519
		if((entry.kind == keys::kind_t::ED25519) || (entry.kind == keys::kind_t::X25519)){
			// Запись с ключом длиной в тридцать один байт
			asn1::writer_t writer;
			// Открываем набор записи
			writer.open(asn1::tag_t::SEQUENCE);
			// Открываем набор алгоритма
			writer.open(asn1::tag_t::SEQUENCE);
			// Записываем опознаватель алгоритма
			writer.oid((entry.kind == keys::kind_t::ED25519) ? "1.3.101.112" : "1.3.101.110");
			// Закрываем набор алгоритма
			writer.close();
			// Записываем усечённый открытый ключ
			writer.bits(view_t(opened.data() + opened.size() - 31, 31));
			// Закрываем набор записи
			writer.close();
			// Проверяем отказ разбора записи с ключом чужой длины
			ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(writer.data(), key), keys::error_t::VALUE) << "Ключ: " << entry.name;
			// Запись зерна длиной в тридцать три байта
			std::vector <uint8_t> longer = secret;
			// Удлиняем зерно
			longer.push_back(0x00);
			// Удлиняем строку байтов зерна
			longer[longer.size() - 34] += 1;
			// Удлиняем обёртку зерна
			longer[longer.size() - 36] += 1;
			// Удлиняем набор записи
			longer[1] += 1;
			// Проверяем отказ разбора записи с зерном чужой длины
			ASSERT_EQ(keys::decodePrivateKeyInfo(view(longer), key), keys::error_t::VALUE) << "Ключ: " << entry.name;
			// Запись с настройками алгоритма: раздел 3 RFC 8410 их запрещает
			writer.clear();
			// Открываем набор записи
			writer.open(asn1::tag_t::SEQUENCE);
			// Открываем набор алгоритма
			writer.open(asn1::tag_t::SEQUENCE);
			// Записываем опознаватель алгоритма
			writer.oid((entry.kind == keys::kind_t::ED25519) ? "1.3.101.112" : "1.3.101.110");
			// Записываем пустые настройки
			writer.nothing();
			// Закрываем набор алгоритма
			writer.close();
			// Записываем открытый ключ
			writer.bits(view_t(opened.data() + opened.size() - 32, 32));
			// Закрываем набор записи
			writer.close();
			// Проверяем отказ разбора записи с настройками
			ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(writer.data(), key), keys::error_t::ALGORITHM) << "Ключ: " << entry.name;
		}
		// Если ключ Ed25519
		if(entry.kind == keys::kind_t::ED25519){
			// Запись с открытым ключом, не отвечающим зерну
			std::vector <uint8_t> mismatched = secret;
			// Ключ из записи
			keys::key_t parsed;
			// Проверяем разбор секретного ключа
			ASSERT_EQ(keys::decodePrivateKeyInfo(view(secret), parsed), keys::error_t::NONE);
			// Портим открытый ключ
			parsed.key[0] ^= 0x01;
			// Запись SubjectPublicKeyInfo с испорченным ключом: точка вправе оказаться годной, но чужой
			std::vector <uint8_t> spki;
			// Проверяем запись открытого ключа
			ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(parsed, spki), keys::error_t::NONE);
			// Разобранный чужой ключ
			keys::key_t stranger;
			// Итог разбора: либо точка не разбирается, либо это годный чужой ключ
			const keys::error_t outcome = keys::decodeSubjectPublicKeyInfo(view(spki), stranger);
			// Проверяем, что итог один из двух
			ASSERT_TRUE((outcome == keys::error_t::NONE) || (outcome == keys::error_t::VALUE));
		}
		// Если ключ RSA
		if(entry.kind == keys::kind_t::RSA){
			// Ключ из записи
			keys::key_t parsed;
			// Проверяем разбор секретного ключа
			ASSERT_EQ(keys::decodePrivateKeyInfo(view(secret), parsed), keys::error_t::NONE);
			// Портим секретный показатель
			parsed.d.back() ^= 0x01;
			// Запись ключа с испорченным показателем
			std::vector <uint8_t> der;
			// Проверяем запись ключа: запись согласия не проверяет
			ASSERT_EQ(keys::encodePrivateKeyInfo(parsed, der), keys::error_t::NONE);
			// Проверяем отказ разбора: составляющие не согласованы
			ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), key), keys::error_t::VALUE);
			// Проверяем запись голой записи: запись согласия не проверяет
			ASSERT_EQ(keys::encodeRSAPrivateKey(parsed, der), keys::error_t::NONE);
			// Проверяем отказ разбора голой записи
			ASSERT_EQ(keys::decodeRSAPrivateKey(view(der), key), keys::error_t::VALUE);
			// Меняем сомножители местами: показатели по ним перестают сходиться
			parsed.d.back() ^= 0x01;
			// Обмениваем сомножители
			parsed.p.swap(parsed.q);
			// Проверяем запись ключа
			ASSERT_EQ(keys::encodePrivateKeyInfo(parsed, der), keys::error_t::NONE);
			// Проверяем отказ разбора: составляющие не согласованы
			ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), key), keys::error_t::VALUE);
			// Запись открытого ключа без пустых настроек
			asn1::writer_t writer;
			// Открываем набор записи
			writer.open(asn1::tag_t::SEQUENCE);
			// Открываем набор алгоритма
			writer.open(asn1::tag_t::SEQUENCE);
			// Записываем опознаватель алгоритма без настроек
			writer.oid("1.2.840.113549.1.1.1");
			// Закрываем набор алгоритма
			writer.close();
			// Запись RSAPublicKey
			std::vector <uint8_t> body;
			// Проверяем запись RSAPublicKey
			ASSERT_EQ(keys::encodeRSAPublicKey(parsed, body), keys::error_t::NONE);
			// Записываем открытый ключ
			writer.bits(view(body));
			// Закрываем набор записи
			writer.close();
			// Проверяем отказ разбора: раздел 2.3.1 RFC 3279 велит писать NULL
			ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(writer.data(), key), keys::error_t::ALGORITHM);
			// Запись с ненулевым числом неиспользуемых разрядов
			std::vector <uint8_t> ragged = opened;
			// Разборщик записи
			asn1::reader_t scan(view(opened));
			// Элементы записи
			asn1::element_t top, alg, bits;
			// Проверяем разбор набора
			ASSERT_TRUE(scan.next(asn1::tag_t::SEQUENCE, top));
			// Разборщик содержимого набора
			asn1::reader_t members = scan.enter(top);
			// Проверяем разбор набора алгоритма
			ASSERT_TRUE(members.next(asn1::tag_t::SEQUENCE, alg));
			// Проверяем разбор строки битов
			ASSERT_TRUE(members.next(asn1::tag_t::BIT_STRING, bits));
			// Выставляем число неиспользуемых разрядов
			ragged[static_cast <size_t> (bits.content.data - opened.data())] = 0x01;
			// Проверяем отказ разбора: разряды заняты не целиком либо запись не кратчайшая
			ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(ragged), key), keys::error_t::STRUCTURE);
		}
	}
	// Зашифрованная запись набора
	const std::vector <uint8_t> sealed = body(corpus("ec256.aes-256-cbc.enc.pem"));
	// Проверяем наличие записи
	ASSERT_FALSE(sealed.empty());
	// Испорченный шифртекст
	std::vector <uint8_t> spoiled = sealed;
	// Портим последний байт шифртекста: дополнение перестаёт сходиться
	spoiled.back() ^= 0x01;
	// Проверяем отказ по паролю: испорченный шифртекст от негодного пароля неотличим
	ASSERT_EQ(keys::decodeEncryptedPrivateKeyInfo(view(spoiled), view(PASSWORD_CORPUS), key), keys::error_t::PASSWORD);
	// Портим первый байт шифртекста: дополнение сходится, а разобранный ключ - нет
	spoiled = sealed;
	// Портим первый байт шифртекста
	spoiled[spoiled.size() - 144] ^= 0x01;
	// Проверяем отказ по паролю
	ASSERT_EQ(keys::decodeEncryptedPrivateKeyInfo(view(spoiled), view(PASSWORD_CORPUS), key), keys::error_t::PASSWORD);
	// Запись с хвостом
	spoiled = sealed;
	// Дописываем хвост
	spoiled.push_back(0x00);
	// Проверяем отказ разбора записи с хвостом
	ASSERT_EQ(keys::decodeEncryptedPrivateKeyInfo(view(spoiled), view(PASSWORD_CORPUS), key), keys::error_t::STRUCTURE);
	// Проверяем отказ разбора текста без записей известного вида
	ASSERT_EQ(keys::decode("-----BEGIN CERTIFICATE-----\nQU5ZS1M=\n-----END CERTIFICATE-----\n", view_t(), key), keys::error_t::LABEL);
	// Проверяем отказ разбора пустого текста
	ASSERT_EQ(keys::decode("", view_t(), key), keys::error_t::LABEL);
	// Проверяем отказ разбора оборванной обёртки
	ASSERT_EQ(keys::decode("-----BEGIN PRIVATE KEY-----\nQU5ZS1M=\n", view_t(), key), keys::error_t::STRUCTURE);
	// Проверяем отказ разбора записи с негодным телом под известной меткой
	ASSERT_EQ(keys::decode("-----BEGIN PRIVATE KEY-----\nQU5ZS1M=\n-----END PRIVATE KEY-----\n", view_t(), key), keys::error_t::STRUCTURE);
	// Проверяем отказ разбора незашифрованного ключа зашифрованным: на месте схемы лежит издание записи
	ASSERT_EQ(keys::decodeEncryptedPrivateKeyInfo(view(bytes(corpus("ec256.der"))), view(PASSWORD_CORPUS), key), keys::error_t::STRUCTURE);
	// Проверяем отказ разбора открытого ключа зашифрованным: на месте схемы лежит чужой алгоритм
	ASSERT_EQ(keys::decodeEncryptedPrivateKeyInfo(view(bytes(corpus("ec256.pub.der"))), view(PASSWORD_CORPUS), key), keys::error_t::CIPHER);
	// Пустой ключ
	keys::key_t empty;
	// Запись пустого ключа
	std::vector <uint8_t> der;
	// Проверяем отказ записи пустого ключа
	ASSERT_EQ(keys::encodePrivateKeyInfo(empty, der), keys::error_t::EMPTY);
	// Проверяем отказ записи пустого ключа
	ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(empty, der), keys::error_t::EMPTY);
	// Проверяем отказ записи пустого ключа
	ASSERT_EQ(keys::encodeECPrivateKey(empty, der), keys::error_t::EMPTY);
	// Проверяем отказ записи пустого ключа
	ASSERT_EQ(keys::encodeRSAPrivateKey(empty, der), keys::error_t::EMPTY);
	// Проверяем отказ записи пустого ключа
	ASSERT_EQ(keys::encodeRSAPublicKey(empty, der), keys::error_t::EMPTY);
	// Проверяем отказ записи пустого ключа
	ASSERT_EQ(keys::encodeEncryptedPrivateKeyInfo(empty, view(PASSWORD_CORPUS), der), keys::error_t::EMPTY);
	// Текст записи
	std::string text;
	// Проверяем отказ записи пустого ключа
	ASSERT_EQ(keys::encode(empty, keys::container_t::PRIVATE, text), keys::error_t::EMPTY);
	// Проверяем отказ записи неизвестного вида
	ASSERT_EQ(keys::encode(empty, static_cast <keys::container_t> (0x7F), text), keys::error_t::STRUCTURE);
	// Проверяем размер пустого ключа
	ASSERT_EQ(empty.size(), static_cast <size_t> (0));
	// Проверяем отсутствие секретной части
	ASSERT_FALSE(empty.secret());
	// Примитивы, в которые пустой ключ не устанавливается
	sign::rsa_t rsa;
	// Проверяем отказ установки пустого ключа
	ASSERT_FALSE(empty.load(rsa));
	// Кривая
	curve::curve_t curve;
	// Примитив ECDSA
	sign::ecdsa_t ecdsa;
	// Проверяем отказ установки пустого ключа
	ASSERT_FALSE(empty.load(ecdsa, curve));
	// Примитив Ed25519
	sign::ed25519_t ed25519;
	// Проверяем отказ установки пустого ключа
	ASSERT_FALSE(empty.load(ed25519));
	// Примитив ГОСТ
	sign::gost_t gost;
	// Проверяем отказ установки пустого ключа
	ASSERT_FALSE(empty.load(gost, curve));
}

/**
 * Проверка названий отказов
 */
TEST(KeysTest, Naming){
	// Проверяем название отказа
	EXPECT_STREQ(keys::name(keys::error_t::NONE), "NONE");
	// Проверяем название отказа
	EXPECT_STREQ(keys::name(keys::error_t::EMPTY), "EMPTY");
	// Проверяем название отказа
	EXPECT_STREQ(keys::name(keys::error_t::STRUCTURE), "STRUCTURE");
	// Проверяем название отказа
	EXPECT_STREQ(keys::name(keys::error_t::ALGORITHM), "ALGORITHM");
	// Проверяем название отказа
	EXPECT_STREQ(keys::name(keys::error_t::CURVE), "CURVE");
	// Проверяем название отказа
	EXPECT_STREQ(keys::name(keys::error_t::VALUE), "VALUE");
	// Проверяем название отказа
	EXPECT_STREQ(keys::name(keys::error_t::CIPHER), "CIPHER");
	// Проверяем название отказа
	EXPECT_STREQ(keys::name(keys::error_t::PASSWORD), "PASSWORD");
	// Проверяем название отказа
	EXPECT_STREQ(keys::name(keys::error_t::LABEL), "LABEL");
	// Проверяем название отказа
	EXPECT_STREQ(keys::name(keys::error_t::RANDOM), "RANDOM");
	// Проверяем название отказа
	EXPECT_STREQ(keys::name(keys::error_t::MEMORY), "MEMORY");
	// Проверяем имя отказа, ни одному из известных не отвечающего
	EXPECT_STREQ(keys::name(static_cast <keys::error_t> (0xFF)), "UNKNOWN");
}

/**
 * Проверка затирания секретов при сбросе ключа
 */
TEST(KeysTest, Wiped){
	// Разобранный ключ
	keys::key_t key;
	// Проверяем разбор секретного ключа
	ASSERT_EQ(keys::decode(corpus("rsa2048.pem"), view_t(), key), keys::error_t::NONE);
	// Проверяем наличие секретной части
	ASSERT_TRUE(key.secret());
	// Выполняем сброс ключа
	key.clear();
	// Проверяем, что все составляющие освобождены
	ASSERT_TRUE(key.d.empty() && key.p.empty() && key.q.empty() && key.n.empty() && key.oid.empty());
	// Проверяем, что память составляющих отдана
	ASSERT_EQ(key.d.capacity(), static_cast <size_t> (0));
	// Проверяем вид ключа
	ASSERT_EQ(key.kind, keys::kind_t::NONE);
}

/**
 * Проверка разбора и записи при нехватке памяти
 */
TEST(KeysTest, Starved){
	// Тексты записей набора
	const std::string secret = corpus("ec256.pem");
	// Записи набора
	const std::vector <uint8_t> sealed = body(corpus("rsa2048.aes-256-cbc.enc.pem"));
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе разбор обязан ответить
	 * либо успехом, либо отказом памяти, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 96; budget++){
		// Разобранный ключ
		keys::key_t key;
		// Итог разбора при отмеренном запасе
		keys::error_t outcome = keys::error_t::NONE;
		{
			// Отмеряем запас выделений на время разбора
			starve::ration_t ration(budget);
			// Выполняем разбор текста при отмеренном запасе
			outcome = keys::decode(secret, view_t(), key);
		}
		// Проверяем, что разбор ответил успехом либо отказом памяти
		ASSERT_TRUE((outcome == keys::error_t::NONE) || (outcome == keys::error_t::MEMORY)) << "запас " << budget << ", отказ " << keys::name(outcome);
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == keys::error_t::MEMORY));
		// Если ключ разобран
		if(outcome == keys::error_t::NONE){
			// Текст записи
			std::string text;
			{
				// Отмеряем запас выделений на время записи
				starve::ration_t ration(budget);
				// Выполняем запись зашифрованного ключа при отмеренном запасе
				outcome = keys::encode(key, keys::container_t::ENCRYPTED, text, view(PASSWORD_CORPUS), 256, 10);
			}
			// Проверяем, что запись ответила успехом либо отказом памяти
			ASSERT_TRUE((outcome == keys::error_t::NONE) || (outcome == keys::error_t::MEMORY)) << "запас " << budget << ", отказ " << keys::name(outcome);
			// Запоминаем объявленный отказ памяти
			starved = (starved || (outcome == keys::error_t::MEMORY));
		}
		{
			// Отмеряем запас выделений на время разбора
			starve::ration_t ration(budget);
			// Выполняем разбор зашифрованной записи при отмеренном запасе
			outcome = keys::decodeEncryptedPrivateKeyInfo(view(sealed), view(PASSWORD_CORPUS), key);
		}
		// Проверяем, что разбор ответил успехом либо отказом памяти
		ASSERT_TRUE((outcome == keys::error_t::NONE) || (outcome == keys::error_t::MEMORY)) << "запас " << budget << ", отказ " << keys::name(outcome);
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == keys::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}

/**
 * Проверка подготовленного ключа: разбор один раз, подпись и сличение всеми видами ключей
 */
TEST(KeysTest, Signer){
	// Хеш подписываемого содержимого
	uint8_t digest[32];
	// Вырабатываем хеш подписываемого содержимого
	ASSERT_TRUE(digest::hash(digest::hash_t::SHA256, view("prepared key"), digest, sizeof(digest)));
	// Просмотр текста записи
	const auto text = [](const std::string & data) noexcept -> view_t {
		// Выводим просмотр текста
		return view_t(reinterpret_cast <const uint8_t *> (data.data()), data.size());
	};
	/**
	 * Выполняем перебор ключей набора
	 */
	for(const entry_t & entry : ENTRIES){
		// Запись ключа в PEM
		const std::string pem = corpus(std::string(entry.name) + ".pem");
		// Запись ключа в DER
		const std::vector <uint8_t> der = bytes(corpus(std::string(entry.name) + ".der"));
		// Подготовленный ключ
		keys::signer_t signer;
		// Неподготовленный ключ не готов
		ASSERT_FALSE(signer.ready());
		ASSERT_EQ(signer.kind(), keys::kind_t::NONE);
		// Ключ согласования подписи не выполняет
		if(entry.kind == keys::kind_t::X25519){
			ASSERT_EQ(signer.prepare(text(pem)), keys::error_t::ALGORITHM) << "Ключ: " << entry.name;
			ASSERT_FALSE(signer.ready());
			continue;
		}
		// Готовим ключ по записи PEM
		ASSERT_EQ(signer.prepare(text(pem)), keys::error_t::NONE) << "Ключ: " << entry.name;
		ASSERT_TRUE(signer.ready()) << "Ключ: " << entry.name;
		ASSERT_EQ(signer.kind(), entry.kind) << "Ключ: " << entry.name;
		// Готовим ключ по записи DER
		keys::signer_t direct;
		ASSERT_EQ(direct.prepare(view(der)), keys::error_t::NONE) << "Ключ: " << entry.name;
		ASSERT_EQ(direct.kind(), entry.kind) << "Ключ: " << entry.name;
		// Открытый ключ для сличения подписей
		keys::key_t opened;
		ASSERT_EQ(keys::decode(corpus(std::string(entry.name) + ".pub.pem"), view_t(), opened), keys::error_t::NONE) << "Ключ: " << entry.name;
		/**
		 * Определяем вид ключа
		 */
		switch(entry.kind){
			// Ключ RSA
			case keys::kind_t::RSA: {
				// Подпись RSA-PSS
				uint8_t signature[512];
				// Модуль сличения по открытому ключу
				sign::rsa_t verifier;
				ASSERT_TRUE(opened.load(verifier));
				ASSERT_EQ(signer.rsa().size(), verifier.size());
				// Подписи подготовленных ключей сличаются открытым ключом
				ASSERT_TRUE(signer.rsa().make(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(digest, sizeof(digest)), signature));
				ASSERT_TRUE(verifier.check(sign::scheme_t::PSS, digest::hash_t::SHA256, view_t(digest, sizeof(digest)), view_t(signature, verifier.size())));
				ASSERT_TRUE(direct.rsa().make(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(digest, sizeof(digest)), signature));
				ASSERT_TRUE(verifier.check(sign::scheme_t::PKCS1, digest::hash_t::SHA256, view_t(digest, sizeof(digest)), view_t(signature, verifier.size())));
				// Модули иных видов пусты
				ASSERT_FALSE(signer.ecdsa().ready());
				ASSERT_FALSE(signer.curve().ready());
			} break;
			// Ключ на кривой Вейерштрасса
			case keys::kind_t::EC: {
				// Сырая подпись r ‖ s
				uint8_t raw[math::NUMBER_SIZE * 2];
				// Кривая и модуль сличения по открытому ключу
				curve::curve_t curve;
				sign::ecdsa_t verifier;
				ASSERT_TRUE(opened.load(verifier, curve));
				ASSERT_TRUE(signer.curve().ready());
				ASSERT_EQ(signer.curve().size(), entry.size);
				ASSERT_TRUE(signer.ecdsa().make(digest::hash_t::SHA256, view_t(digest, sizeof(digest)), raw));
				ASSERT_TRUE(verifier.check(view_t(digest, sizeof(digest)), view_t(raw, verifier.size())));
				ASSERT_TRUE(direct.ecdsa().make(digest::hash_t::SHA256, view_t(digest, sizeof(digest)), raw));
				ASSERT_TRUE(verifier.check(view_t(digest, sizeof(digest)), view_t(raw, verifier.size())));
				ASSERT_FALSE(signer.rsa().ready());
			} break;
			// Ключ Ed25519
			case keys::kind_t::ED25519: {
				// Подпись Ed25519
				uint8_t signature[64];
				// Модуль сличения по открытому ключу
				sign::ed25519_t verifier;
				ASSERT_TRUE(opened.load(verifier));
				ASSERT_TRUE(signer.ed25519().make(view("prepared key"), signature));
				ASSERT_TRUE(verifier.check(view("prepared key"), view_t(signature, sizeof(signature))));
				ASSERT_TRUE(direct.ed25519().make(view("prepared key"), signature));
				ASSERT_TRUE(verifier.check(view("prepared key"), view_t(signature, sizeof(signature))));
				ASSERT_FALSE(signer.rsa().ready());
			} break;
			// Прочие виды здесь не встречаются
			default: FAIL() << "Ключ: " << entry.name;
		}
		// Сброс ключа снимает готовность
		signer.clear();
		ASSERT_FALSE(signer.ready());
		ASSERT_EQ(signer.kind(), keys::kind_t::NONE);
	}
	// Ключ ГОСТ по записи PKCS #8
	keys::key_t made;
	ASSERT_TRUE(gost("1.2.643.7.1.2.1.1.1", "1.2.643.7.1.1.1.1", made));
	std::vector <uint8_t> der;
	ASSERT_EQ(keys::encodePrivateKeyInfo(made, der), keys::error_t::NONE);
	keys::signer_t packed;
	ASSERT_EQ(packed.prepare(view(der)), keys::error_t::NONE);
	ASSERT_EQ(packed.kind(), keys::kind_t::GOST);
	ASSERT_EQ(packed.curve().size(), static_cast <size_t> (32));
	// Тот же ключ голым скаляром по кривой
	curve::curve_t curve;
	ASSERT_TRUE(curve::parameters("1.2.643.7.1.2.1.1.1", curve));
	keys::signer_t bare;
	ASSERT_EQ(bare.prepare(view(made.d), curve), keys::error_t::NONE);
	ASSERT_EQ(bare.kind(), keys::kind_t::GOST);
	ASSERT_EQ(bare.curve().size(), static_cast <size_t> (32));
	// Подпись голого скаляра сличается ключом из записи и наоборот
	uint8_t signature[128];
	ASSERT_TRUE(bare.gost().make(view_t(digest, sizeof(digest)), signature));
	ASSERT_TRUE(packed.gost().check(view_t(digest, sizeof(digest)), view_t(signature, packed.gost().size())));
	ASSERT_TRUE(packed.gost().make(view_t(digest, sizeof(digest)), signature));
	ASSERT_TRUE(bare.gost().check(view_t(digest, sizeof(digest)), view_t(signature, bare.gost().size())));
	// Отказы подготовки
	keys::signer_t refused;
	// Пустой скаляр
	ASSERT_EQ(refused.prepare(view_t(), curve), keys::error_t::EMPTY);
	// Незаведённая кривая
	curve::curve_t blank;
	ASSERT_EQ(refused.prepare(view(made.d), blank), keys::error_t::CURVE);
	ASSERT_FALSE(refused.ready());
	// Нулевой скаляр
	const std::vector <uint8_t> zero(32, 0);
	ASSERT_EQ(refused.prepare(view(zero), curve), keys::error_t::VALUE);
	ASSERT_FALSE(refused.ready());
	ASSERT_FALSE(refused.curve().ready());
	// Пустая запись
	ASSERT_EQ(refused.prepare(view_t()), keys::error_t::EMPTY);
	// Мусор вместо записи
	ASSERT_NE(refused.prepare(view("garbage instead of a key")), keys::error_t::NONE);
	ASSERT_FALSE(refused.ready());
	// Открытый ключ без секретной части
	ASSERT_EQ(refused.prepare(text(corpus("ec256.pub.pem"))), keys::error_t::EMPTY);
	ASSERT_FALSE(refused.ready());
	// Подготовка после отказа возможна
	ASSERT_EQ(refused.prepare(text(corpus("ec256.pem"))), keys::error_t::NONE);
	ASSERT_EQ(refused.kind(), keys::kind_t::EC);
}

/**
 * @brief Проверка подготовки ключей ML-DSA по записям всех видов из набора
 *
 * @note Записи ключа: зерно с меткой [0], развёрнутый ключ, оба вида набором, голые
 *       зерно и развёрнутый ключ издания v1 и запись oqsprovider с открытой частью
 *       следом (набор tests/corpus/mldsa из 15-test_ml_dsa_codecs_data OpenSSL)
 *
 */
TEST(KeysTest, Mldsa){
	// Виды записей ключа ML-DSA в наборе
	static const char * FORMS[] = {"seed-only", "priv-only", "seed-priv", "bare-seed", "bare-priv", "oqskeypair"};
	// Наборы параметров и размеры их подписей
	static const struct Suit {
		// Запись набора
		const char * name;
		// Набор параметров
		sign::mldsa_t::set_t set;
	} SUITS[] = {
		{"44", sign::mldsa_t::set_t::DSA44},
		{"65", sign::mldsa_t::set_t::DSA65},
		{"87", sign::mldsa_t::set_t::DSA87}
	};
	// Просмотр текста записи
	const auto text = [](const std::string & data) noexcept -> view_t {
		// Выводим просмотр текста
		return view_t(reinterpret_cast <const uint8_t *> (data.data()), data.size());
	};
	/**
	 * Выполняем перебор наборов параметров
	 */
	for(const Suit & suit : SUITS){
		// Открытый ключ набора в записи PEM
		keys::key_t opened;
		ASSERT_EQ(keys::decode(corpus(std::string("mldsa/") + "mldsa" + suit.name + "-pub.pem"), view_t(), opened), keys::error_t::NONE) << "Набор: " << suit.name;
		ASSERT_EQ(opened.kind, keys::kind_t::MLDSA) << "Набор: " << suit.name;
		// Модуль сличения по открытому ключу
		sign::mldsa_t verifier;
		ASSERT_TRUE(opened.load(verifier)) << "Набор: " << suit.name;
		ASSERT_EQ(verifier.set(), suit.set);
		/**
		 * Выполняем перебор видов записей ключа
		 */
		for(const char * form : FORMS){
			// Запись ключа очередного вида
			const std::string pem = corpus(std::string("mldsa/") + "mldsa" + suit.name + "-" + form + ".pem");
			// Подготовленный ключ
			keys::signer_t signer;
			// Готовим ключ по записи PEM
			ASSERT_EQ(signer.prepare(text(pem)), keys::error_t::NONE) << "Ключ: mldsa" << suit.name << "-" << form;
			ASSERT_TRUE(signer.ready()) << "Ключ: mldsa" << suit.name << "-" << form;
			ASSERT_EQ(signer.kind(), keys::kind_t::MLDSA) << "Ключ: mldsa" << suit.name << "-" << form;
			ASSERT_EQ(signer.mldsa().set(), suit.set) << "Ключ: mldsa" << suit.name << "-" << form;
			// Место подписи набора
			std::vector <uint8_t> signature(sign::mldsa_t::signatureSize(suit.set));
			// Подпись подготовленного ключа сличается открытым ключом
			ASSERT_TRUE(signer.mldsa().make(view("prepared key"), view_t(nullptr, 0), signature.data())) << "Ключ: mldsa" << suit.name << "-" << form;
			ASSERT_TRUE(verifier.check(view("prepared key"), view_t(nullptr, 0), view_t(signature.data(), signature.size()))) << "Ключ: mldsa" << suit.name << "-" << form;
			// Модули иных видов пусты
			ASSERT_FALSE(signer.rsa().ready());
			ASSERT_FALSE(signer.curve().ready());
			// Сброс ключа снимает готовность
			signer.clear();
			ASSERT_FALSE(signer.ready());
		}
	}
}

/**
 * @brief Проверка круга записи и чтения ключей ML-DSA по RFC 9881
 *
 * @note Запись секретного ключа: развёрнутый ключ строкой байтов из записей набора,
 *       зерно с неявной меткой [0]; открытый ключ - SubjectPublicKeyInfo без настроек
 *
 */
TEST(KeysTest, MldsaRoundtrip){
	// Наборы параметров и опознаватели их алгоритмов
	static const struct Suit {
		// Запись набора
		const char * name;
		// Опознаватель алгоритма
		const char * oid;
	} SUITS[] = {
		{"44", "2.16.840.1.101.3.4.3.17"},
		{"65", "2.16.840.1.101.3.4.3.18"},
		{"87", "2.16.840.1.101.3.4.3.19"}
	};
	/**
	 * Выполняем перебор наборов параметров
	 */
	for(const Suit & suit : SUITS){
		// Разобранный ключ набора
		keys::key_t key;
		// Проверяем разбор секретного ключа набора
		ASSERT_EQ(keys::decode(corpus(std::string("mldsa") + suit.name + ".pem"), view_t(), key), keys::error_t::NONE) << "Набор: " << suit.name;
		ASSERT_EQ(key.kind, keys::kind_t::MLDSA) << "Набор: " << suit.name;
		// Текст записи
		std::string text;
		// Проверяем запись секретного ключа в обёртке PEM
		ASSERT_EQ(keys::encode(key, keys::container_t::PRIVATE, text), keys::error_t::NONE) << "Набор: " << suit.name;
		// Разобранный вновь ключ
		keys::key_t again;
		// Проверяем разбор записанного текста
		ASSERT_EQ(keys::decode(text, view_t(), again), keys::error_t::NONE) << "Набор: " << suit.name;
		// Проверяем совпадение частей ключа
		ASSERT_TRUE(alike(key, again)) << "Набор: " << suit.name;
		ASSERT_EQ(again.d, key.d) << "Набор: " << suit.name;
		// Проверяем запись открытого ключа в обёртке PEM
		ASSERT_EQ(keys::encode(key, keys::container_t::PUBLIC, text), keys::error_t::NONE) << "Набор: " << suit.name;
		// Разобранный вновь открытый ключ
		keys::key_t reopened;
		// Проверяем разбор записанного текста
		ASSERT_EQ(keys::decode(text, view_t(), reopened), keys::error_t::NONE) << "Набор: " << suit.name;
		// Проверяем совпадение частей ключа
		ASSERT_TRUE(alike(key, reopened)) << "Набор: " << suit.name;
		// Проверяем запись секретного ключа в кодировке DER без обёртки
		std::vector <uint8_t> der;
		ASSERT_EQ(keys::encodePrivateKeyInfo(key, der), keys::error_t::NONE) << "Набор: " << suit.name;
		// Разобранный вновь ключ из DER
		keys::key_t direct;
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), direct), keys::error_t::NONE) << "Набор: " << suit.name;
		// Проверяем совпадение частей ключа
		ASSERT_TRUE(alike(key, direct)) << "Набор: " << suit.name;
		ASSERT_EQ(direct.d, key.d) << "Набор: " << suit.name;
		// Проверяем запись открытого ключа в кодировке DER без обёртки
		ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(key, der), keys::error_t::NONE) << "Набор: " << suit.name;
		// Разобранный вновь открытый ключ из DER
		keys::key_t subject;
		ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(der), subject), keys::error_t::NONE) << "Набор: " << suit.name;
		// Проверяем совпадение частей ключа
		ASSERT_TRUE(alike(key, subject)) << "Набор: " << suit.name;
	}
	{
		// Ключ ML-DSA-44 с зерном в секретной части
		keys::key_t seeded;
		// Устанавливаем вид ключа и опознаватель алгоритма
		seeded.kind = keys::kind_t::MLDSA;
		seeded.algorithm = "2.16.840.1.101.3.4.3.17";
		// Зерно ключа
		seeded.d.assign(32, 0);
		for(size_t i = 0; i < 32; i++)
			seeded.d[i] = static_cast <uint8_t> (i);
		// Запись секретного ключа в кодировке DER
		std::vector <uint8_t> der;
		// Проверяем запись зерна
		ASSERT_EQ(keys::encodePrivateKeyInfo(seeded, der), keys::error_t::NONE);
		// Признак неявной метки зерна в записи
		bool tagged = false;
		// Проверяем наличие метки [0] зерна в записи
		for(size_t i = 0; i + 1 < der.size(); i++)
			tagged = (tagged || ((der[i] == 0x80) && (der[i + 1] == 0x20)));
		ASSERT_TRUE(tagged);
		// Разобранный вновь ключ из записи зерна
		keys::key_t again;
		// Проверяем разбор записи зерна
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), again), keys::error_t::NONE);
		// Проверяем вид ключа и размер развёрнутого секрета из зерна
		ASSERT_EQ(again.kind, keys::kind_t::MLDSA);
		ASSERT_EQ(again.d.size(), static_cast <size_t> (2560));
	}
}
