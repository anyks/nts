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
 * @brief Функция запуска команды оболочки без консоли на входе
 *
 * @details stdin подаётся из /dev/null: у оболочки инструмента разработки он бывает
 *          сокетом, tcgetattr на нём отвечает EOPNOTSUPP, и консольный слой openssl
 *          валит разбор даже при пароле, заданном доводом
 *
 * @param command запускаемая команда
 * @return        код возврата команды
 *
 */
static int shell(const std::string & command) {
	// Запускаем команду с пустым входом
	/**
	 * Для cmd.exe пустое устройство называется NUL
	 */
	#if defined(_WIN32)
		// Пустое устройство cmd.exe называется NUL
		return ::system((command + " <NUL").c_str());
	/**
	 * Для POSIX пустое устройство называется /dev/null
	 */
	#else
		// Пустое устройство POSIX называется /dev/null
		return ::system((command + " </dev/null").c_str());
	#endif
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
		// RSA-2048: буфер ключа 256 байтов, параметры не нужны
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
	 * @brief Функция чтения файла целиком
	 *
	 * @param path путь к читаемому файлу
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
	 * @brief Функция чтения файла набора целиком
	 *
	 * @param name имя файла в наборе
	 * @return     содержимое файла
	 *
	 */
	static std::string corpus(const std::string & name) {
		// Выводим содержимое файла набора
		return slurp(std::string(CORPUS) + "/" + name);
	}
	/**
	 * @brief Функция перевода строки в набор байтов
	 *
	 * @param text переводимая строка
	 * @return     набор байтов
	 *
	 */
	static std::vector <uint8_t> bytes(const std::string & text) {
		// Выводим набор байтов строки
		return std::vector <uint8_t> (text.begin(), text.end());
	}
	/**
	 * @brief Функция получения просмотра набора байтов
	 *
	 * @param data просматриваемый набор байтов
	 * @return     просмотр набора байтов
	 *
	 */
	static view_t view(const std::vector <uint8_t> & data) {
		// Выводим просмотр набора байтов
		return view_t(data.data(), data.size());
	}
	/**
	 * @brief Функция получения просмотра строки знаков
	 *
	 * @param text просматриваемая строка знаков
	 * @return     просмотр строки знаков
	 *
	 */
	static view_t view(const char * text) {
		// Выводим просмотр строки знаков
		return view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text));
	}
	/**
	 * @brief Функция записи файла целиком
	 *
	 * @param path путь к записываемому файлу
	 * @param data записываемое содержимое
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
	 * @brief Функция записи набора байтов в файл
	 *
	 * @param path путь к записываемому файлу
	 * @param data записываемый набор байтов
	 * @return     признак успешности записи
	 *
	 */
	static bool spill(const std::string & path, const std::vector <uint8_t> & data) {
		// Выводим итог записи набора байтов строкой
		return spill(path, std::string(data.begin(), data.end()));
	}
	/**
	 * @brief Функция извлечения тела первой записи PEM
	 *
	 * @param text разбираемый текст
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
	 * @brief Функция хеширования набора байтов
	 *
	 * @param algorithm алгоритм хеширования
	 * @param data      хешируемый набор байтов
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
	 * @brief Функция сличения открытых частей двух ключей
	 *
	 * @param first  первый ключ
	 * @param second второй ключ
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
	 * @brief Функция выработки подписи данных разобранным ключом
	 *
	 * @param key    ключ подписи
	 * @param data   подписываемые данные
	 * @param result место, в которое помещается подпись в виде, понятном openssl
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
					// Выводим отрицательный результат - ключ RSA не установлен
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
					// Выводим отрицательный результат - ключ ECDSA не установлен
					return false;
				// Алгоритм хеширования по размеру кривой
				const digest::hash_t algorithm = ((curve.size() == 32) ? digest::hash_t::SHA256 : digest::hash_t::SHA384);
				// Хеш данных
				const std::vector <uint8_t> digest = digested(algorithm, data);
				// Подпись парой чисел
				std::vector <uint8_t> raw(curve.size() * 2, 0);
				// Если подпись выработать не удалось
				if(!ecdsa.make(algorithm, view(digest), raw.data()))
					// Выводим отрицательный результат - подпись не выработана
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
					// Выводим отрицательный результат - ключ Ed25519 не установлен
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
	 * @brief Функция проверки подписи данных разобранным ключом
	 *
	 * @param key       ключ проверки подписи
	 * @param data      подписанные данные
	 * @param signature проверяемая подпись в виде, понятном openssl
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
					// Выводим отрицательный результат - ключ RSA не установлен
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
					// Выводим отрицательный результат - ключ ECDSA не установлен
					return false;
				// Алгоритм хеширования по размеру кривой
				const digest::hash_t algorithm = ((curve.size() == 32) ? digest::hash_t::SHA256 : digest::hash_t::SHA384);
				// Хеш данных
				const std::vector <uint8_t> digest = digested(algorithm, data);
				// Подпись парой чисел
				std::vector <uint8_t> raw(curve.size() * 2, 0);
				// Если подпись из кодировки DER разобрать не удалось
				if(!sign::decode(view(signature), raw.data(), raw.size()))
					// Выводим отрицательный результат - подпись не разобрана
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
					// Выводим отрицательный результат - ключ Ed25519 не установлен
					return false;
				// Выводим итог проверки подписи
				return ed25519.check(view(data), view(signature));
			}
		}
		// Выводим отказ: ключ подписи не проверяет
		return false;
	}
	/**
	 * @brief Функция выработки ключа ГОСТ на заданной кривой средствами библиотеки
	 *
	 * @param oid       опознаватель кривой
	 * @param algorithm опознаватель алгоритма ключа
	 * @param result    место, в которое помещается выработанный ключ
	 * @return          признак успешности выработки ключа
	 *
	 */
	static bool gost(const char * oid, const char * algorithm, keys::key_t & result) {
		// Кривая ключа
		curve::curve_t curve;
		// Если кривую установить не удалось
		if(!curve::parameters(oid, curve))
			// Выводим отрицательный результат - кривая не установлена
			return false;
		// Объект модуля электронной подписи ГОСТ
		sign::gost_t signer;
		// Если кривую подписи установить не удалось
		if(!signer.start(curve))
			// Выводим отрицательный результат - кривая подписи не установлена
			return false;
		// Выделяем место под секретный скаляр
		result.d.assign(curve.size(), 0);
		// Если секретный скаляр выработать библиотекой не удалось
		if(!signer.generate(result.d.data(), result.d.size()))
			// Выводим отрицательный результат - секретный скаляр не выработан
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
				/**
				 * Для Windows путь виден одинаково из CRT и родного OpenSSL
				 */
				#if defined(_WIN32)
					// Каталог, одинаково видимый из CRT и родного OpenSSL
					char pattern[] = "C:/Windows/Temp/ants-keys-XXXXXX";
				/**
				 * Для остальных систем используется каталог POSIX
				 */
				#else
					// Каталог временных файлов POSIX
					char pattern[] = "/tmp/ants-keys-XXXXXX";
				#endif
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
	// Инвертируем последний байт записи
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
		// Подпись SHA-256 под ключом RSA-2048
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
		// Пропускаем проверку без системного эталона
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
 * @brief Проверка совместного отвержения порченых записей с OpenSSL
 *
 */
TEST(KeysTest, OpensslRefusals){
	// Временный каталог порченых записей
	sandbox_t sandbox;
	// Проверяем создание временного каталога
	ASSERT_TRUE(sandbox.ready());
	// Эталонный OpenSSL из родной среды исполнения
	const std::string tool("openssl");
	// Пустое устройство для подавления вывода эталона
	/**
	 * Для cmd.exe пустое устройство называется NUL
	 */
	#if defined(_WIN32)
		// Пустое устройство cmd.exe
		const std::string nullDevice("NUL");
	/**
	 * Для POSIX пустое устройство называется /dev/null
	 */
	#else
		// Пустое устройство POSIX
		const std::string nullDevice("/dev/null");
	#endif
	// Секретный ключ Ed448
	keys::key_t secret;
	// Проверяем разбор секретного ключа Ed448
	ASSERT_EQ(keys::decode(corpus("ed448.key"), view_t(), secret), keys::error_t::NONE);
	// Разобранный ключ для отказов
	keys::key_t key;
	// Запись PrivateKeyInfo Ed448 с запрещёнными настройками алгоритма
	asn1::writer_t writer;
	// Открываем набор PrivateKeyInfo
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем издание записи
	writer.integer(0);
	// Открываем набор алгоритма
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель Ed448
	writer.oid("1.3.101.113");
	// Записываем запрещённые пустые настройки
	writer.nothing();
	// Закрываем набор алгоритма
	writer.close();
	// Записываем зерно во внутренней строке байтов
	asn1::writer_t seed;
	// Записываем зерно Ed448
	seed.octets(view(secret.d));
	// Записываем CurvePrivateKey во внешней строке байтов
	writer.octets(seed.data());
	// Закрываем набор PrivateKeyInfo
	writer.close();
	// Путь к записи с настройками
	const std::string parameters = sandbox.file("parameters.der");
	// Записываем порченую запись
	ASSERT_TRUE(spill(parameters, std::vector <uint8_t> (writer.data().data, writer.data().data + writer.data().size)));
	// Проверяем отказ нашего разборщика
	ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::ALGORITHM);
	// Проверяем отказ OpenSSL на тех же настройках
	ASSERT_NE(shell(tool + " pkey -inform DER -in " + parameters + " -noout >" + nullDevice + " 2>&1"), 0);
	// Годная запись PrivateKeyInfo Ed448
	std::vector <uint8_t> der;
	// Записываем годный секретный ключ
	ASSERT_EQ(keys::encodePrivateKeyInfo(secret, der), keys::error_t::NONE);
	// Оборванная запись ровно половинной длины
	const std::vector <uint8_t> truncated(der.begin(), der.begin() + (der.size() / 2));
	// Путь к оборванной записи
	const std::string shorty = sandbox.file("truncated.der");
	// Записываем оборванную запись
	ASSERT_TRUE(spill(shorty, truncated));
	// Проверяем отказ нашего разборщика на обрезке
	ASSERT_NE(keys::decodePrivateKeyInfo(view(truncated), key), keys::error_t::NONE);
	// Проверяем отказ OpenSSL на той же обрезке
	ASSERT_NE(shell(tool + " pkey -inform DER -in " + shorty + " -noout >" + nullDevice + " 2>&1"), 0);
	// Запись PKCS #12 с чужим видом содержимого
	std::vector <uint8_t> foreign = bytes(corpus("test.p12"));
	// Опознаватель данных PKCS #7
	const uint8_t data[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01};
	// Смещение опознавателя данных
	size_t at = std::string::npos;
	/**
	 * Выполняем поиск опознавателя данных в записи
	 */
	for(size_t i = 0; (i + sizeof(data)) <= foreign.size(); i++){
		// Если опознаватель найден
		if(::memcmp(foreign.data() + i, data, sizeof(data)) == 0){
			// Запоминаем смещение опознавателя
			at = i;
			// Завершаем поиск
			break;
		}
	}
	// Проверяем наличие опознавателя
	ASSERT_NE(at, std::string::npos);
	// Портим последний байт опознавателя данных
	foreign[at + sizeof(data) - 1] = 0x02;
	// Путь к записи с чужим видом содержимого
	const std::string alien = sandbox.file("foreign.p12");
	// Записываем порченую запись PKCS #12
	ASSERT_TRUE(spill(alien, foreign));
	// Цепочка сертификатов
	std::vector <std::vector <uint8_t>> chain;
	// Проверяем отказ нашего разборщика на чужом виде содержимого
	ASSERT_EQ(keys::decodePkcs12(view(foreign), view("secret"), key, chain), keys::error_t::STRUCTURE);
	// Проверяем отказ OpenSSL на той же записи PKCS #12
	ASSERT_NE(shell(tool + " pkcs12 -in " + alien + " -passin pass:secret -noout >" + nullDevice + " 2>&1"), 0);
}

/**
 * Проверка ключей ГОСТ Р 34.10-2012: круг записи и подпись загруженным ключом
 */
TEST(KeysTest, Gost){
	// Кривые и алгоритмы ключей
	const char * sets[][2] = {
		// Кривая tc26 paramSetA 256 битов и подпись ГОСТ на ней
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
		// Портим предпоследний байт опознавателя: кодировка остаётся годной, алгоритм становится чужим
		foreign[last - 1] ^= 0x01;
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
		// Портим предпоследний байт опознавателя
		foreign[static_cast <size_t> ((oid.content.data + oid.content.size - 2) - secret.data())] ^= 0x01;
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
		// Вид ключа не определён
		ASSERT_EQ(signer.kind(), keys::kind_t::NONE);
		// Ключ согласования подписи не выполняет
		if(entry.kind == keys::kind_t::X25519){
			// Согласование подписи для X25519 отказывает
			ASSERT_EQ(signer.prepare(text(pem)), keys::error_t::ALGORITHM) << "Ключ: " << entry.name;
			// Готовность не появляется
			ASSERT_FALSE(signer.ready());
			continue;
		}
		// Готовим ключ по записи PEM
		ASSERT_EQ(signer.prepare(text(pem)), keys::error_t::NONE) << "Ключ: " << entry.name;
		// Ключ готов к подписи
		ASSERT_TRUE(signer.ready()) << "Ключ: " << entry.name;
		// Вид ключа совпадает с эталоном набора
		ASSERT_EQ(signer.kind(), entry.kind) << "Ключ: " << entry.name;
		// Готовим ключ по записи DER
		keys::signer_t direct;
		// Готовим ключ по записи DER
		ASSERT_EQ(direct.prepare(view(der)), keys::error_t::NONE) << "Ключ: " << entry.name;
		ASSERT_EQ(direct.kind(), entry.kind) << "Ключ: " << entry.name;
		// Открытый ключ для сличения подписей
		keys::key_t opened;
		// Разбираем открытый ключ для сличения подписей
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
				// Загружаем открытый ключ в модуль сличения
				ASSERT_TRUE(opened.load(verifier));
				// Размеры модулей совпадают
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
				// Модуль сличения по открытому ключу
				sign::ecdsa_t verifier;
				// Загружаем открытый ключ в кривую и модуль
				ASSERT_TRUE(opened.load(verifier, curve));
				ASSERT_TRUE(signer.curve().ready());
				// Размер кривой совпадает с эталоном набора
				ASSERT_EQ(signer.curve().size(), entry.size);
				// Подпись подготовленного ключа сличается открытым ключом
				ASSERT_TRUE(signer.ecdsa().make(digest::hash_t::SHA256, view_t(digest, sizeof(digest)), raw));
				ASSERT_TRUE(verifier.check(view_t(digest, sizeof(digest)), view_t(raw, verifier.size())));
				ASSERT_TRUE(direct.ecdsa().make(digest::hash_t::SHA256, view_t(digest, sizeof(digest)), raw));
				ASSERT_TRUE(verifier.check(view_t(digest, sizeof(digest)), view_t(raw, verifier.size())));
				// Модуль RSA пуст
				ASSERT_FALSE(signer.rsa().ready());
			} break;
			// Ключ Ed25519
			case keys::kind_t::ED25519: {
				// Подпись Ed25519
				uint8_t signature[64];
				// Модуль сличения по открытому ключу
				sign::ed25519_t verifier;
				// Загружаем открытый ключ в модуль сличения
				ASSERT_TRUE(opened.load(verifier));
				ASSERT_TRUE(signer.ed25519().make(view("prepared key"), signature));
				ASSERT_TRUE(verifier.check(view("prepared key"), view_t(signature, sizeof(signature))));
				ASSERT_TRUE(direct.ed25519().make(view("prepared key"), signature));
				ASSERT_TRUE(verifier.check(view("prepared key"), view_t(signature, sizeof(signature))));
				// Модуль RSA пуст
				ASSERT_FALSE(signer.rsa().ready());
			} break;
			// Прочие виды здесь не встречаются
			default: FAIL() << "Ключ: " << entry.name;
		}
		// Сброс ключа снимает готовность
		signer.clear();
		// Готовность снята
		ASSERT_FALSE(signer.ready());
		// Вид ключа не определён
		ASSERT_EQ(signer.kind(), keys::kind_t::NONE);
	}
	// Ключ ГОСТ по записи PKCS #8
	keys::key_t made;
	// Создаём ключ ГОСТ по опознавателям алгоритмов
	ASSERT_TRUE(gost("1.2.643.7.1.2.1.1.1", "1.2.643.7.1.1.1.1", made));
	// Запись ключа в кодировке DER
	std::vector <uint8_t> der;
	// Записываем секретный ключ в запись PKCS #8
	ASSERT_EQ(keys::encodePrivateKeyInfo(made, der), keys::error_t::NONE);
	// Подписывающий ключ из записи
	keys::signer_t packed;
	// Готовим ключ по записи DER
	ASSERT_EQ(packed.prepare(view(der)), keys::error_t::NONE);
	ASSERT_EQ(packed.kind(), keys::kind_t::GOST);
	ASSERT_EQ(packed.curve().size(), static_cast <size_t> (32));
	// Тот же ключ голым скаляром по кривой
	curve::curve_t curve;
	// Заводим кривую по опознавателю набора
	ASSERT_TRUE(curve::parameters("1.2.643.7.1.2.1.1.1", curve));
	// Подписывающий ключ голого скаляра
	keys::signer_t bare;
	// Готовим ключ по голому скаляру
	ASSERT_EQ(bare.prepare(view(made.d), curve), keys::error_t::NONE);
	ASSERT_EQ(bare.kind(), keys::kind_t::GOST);
	ASSERT_EQ(bare.curve().size(), static_cast <size_t> (32));
	// Подпись голого скаляра сличается ключом из записи и наоборот
	uint8_t signature[128];
	// Подписываем эталон голым скаляром
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
	// Подготовка по незаведённой кривой отказывает
	ASSERT_EQ(refused.prepare(view(made.d), blank), keys::error_t::CURVE);
	// Готовность не появляется
	ASSERT_FALSE(refused.ready());
	// Нулевой скаляр
	const std::vector <uint8_t> zero(32, 0);
	// Подготовка по нулевому скаляру отказывает
	ASSERT_EQ(refused.prepare(view(zero), curve), keys::error_t::VALUE);
	// Готовность не появляется
	ASSERT_FALSE(refused.ready());
	ASSERT_FALSE(refused.curve().ready());
	// Пустая запись
	ASSERT_EQ(refused.prepare(view_t()), keys::error_t::EMPTY);
	// Мусор вместо записи
	ASSERT_NE(refused.prepare(view("garbage instead of a key")), keys::error_t::NONE);
	// Готовность не появляется
	ASSERT_FALSE(refused.ready());
	// Открытый ключ без секретной части
	ASSERT_EQ(refused.prepare(text(corpus("ec256.pub.pem"))), keys::error_t::EMPTY);
	// Готовность не появляется
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
		// ML-DSA-44: самый слабый из трёх наборов FIPS 204
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
		// Разбираем открытый ключ набора
		ASSERT_EQ(keys::decode(corpus(std::string("mldsa/") + "mldsa" + suit.name + "-pub.pem"), view_t(), opened), keys::error_t::NONE) << "Набор: " << suit.name;
		ASSERT_EQ(opened.kind, keys::kind_t::MLDSA) << "Набор: " << suit.name;
		// Модуль сличения по открытому ключу
		sign::mldsa_t verifier;
		// Загружаем открытый ключ в модуль сличения
		ASSERT_TRUE(opened.load(verifier)) << "Набор: " << suit.name;
		// Набор параметров совпадает с эталоном
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
			// Ключ готов к подписи
			ASSERT_TRUE(signer.ready()) << "Ключ: mldsa" << suit.name << "-" << form;
			// Вид ключа совпадает с эталоном
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
			// Готовность снята
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
		// ML-DSA-44: опознаватель подписи FIPS 204
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
		// Секретная часть совпадает байт в байт
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
		// Записываем секретный ключ в запись PKCS #8
		ASSERT_EQ(keys::encodePrivateKeyInfo(key, der), keys::error_t::NONE) << "Набор: " << suit.name;
		// Разобранный вновь ключ из DER
		keys::key_t direct;
		// Разбираем запись ключа из DER
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), direct), keys::error_t::NONE) << "Набор: " << suit.name;
		// Проверяем совпадение частей ключа
		ASSERT_TRUE(alike(key, direct)) << "Набор: " << suit.name;
		// Секретная часть совпадает байт в байт
		ASSERT_EQ(direct.d, key.d) << "Набор: " << suit.name;
		// Проверяем запись открытого ключа в кодировке DER без обёртки
		ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(key, der), keys::error_t::NONE) << "Набор: " << suit.name;
		// Разобранный вновь открытый ключ из DER
		keys::key_t subject;
		// Разбираем открытый ключ из DER
		ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(der), subject), keys::error_t::NONE) << "Набор: " << suit.name;
		// Проверяем совпадение частей ключа
		ASSERT_TRUE(alike(key, subject)) << "Набор: " << suit.name;
	}
	{
		// Ключ ML-DSA-44 с зерном в секретной части
		keys::key_t seeded;
		// Устанавливаем вид ключа и опознаватель алгоритма
		seeded.kind = keys::kind_t::MLDSA;
		// Устанавливаем опознаватель алгоритма
		seeded.algorithm = "2.16.840.1.101.3.4.3.17";
		// Зерно ключа
		seeded.d.assign(32, 0);
		/**
		 * Заполняем зерно порядковыми номерами байтов
		 */
		for(size_t i = 0; i < 32; i++){
			// Заполняем очередной байт зерна
			seeded.d[i] = static_cast <uint8_t> (i);
		}
		// Запись секретного ключа в кодировке DER
		std::vector <uint8_t> der;
		// Проверяем запись зерна
		ASSERT_EQ(keys::encodePrivateKeyInfo(seeded, der), keys::error_t::NONE);
		// Признак неявной метки зерна в записи
		bool tagged = false;
		/**
		 * Проверяем наличие метки [0] зерна в записи
		 */
		for(size_t i = 0; i + 1 < der.size(); i++){
			// Ищем признак неявной метки зерна
			tagged = (tagged || ((der[i] == 0x80) && (der[i + 1] == 0x20)));
		}
		// Признак метки зерна найден
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

/**
 * @brief Проверка отказов разбора мешков записи PKCS #12
 *
 * @note Мутации валидной записи test.p12: порча опознавателя вида мешка, порча
 *       опознавателя вида сертификата, подмена мешка сертификата вторым мешком ключа,
 *       обрезка записи; отдельно прогон разбора при отмеренном запасе выделений
 *
 */
TEST(KeysTest, Pkcs12Bags){
	// Запись PKCS #12 набора
	const std::vector <uint8_t> der = bytes(corpus("test.p12"));
	// Проверяем наличие записи
	ASSERT_FALSE(der.empty());
	// Разобранный ключ
	keys::key_t key;
	// Разобранная цепочка сертификатов
	std::vector <std::vector <uint8_t>> chain;
	// Опознаватель данных PKCS #7 в кодировке DER
	const uint8_t data[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01};
	// Опознаватель хеша SHA-256 в кодировке DER
	const uint8_t sha256[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
	// Смещение опознавателя данных PKCS #7 в записи
	size_t atData = std::string::npos;
	// Смещение опознавателя хеша в записи
	size_t atSha256 = std::string::npos;
	/**
	 * Выполняем поиск опознавателей в записи
	 */
	for(size_t i = 0; (i + sizeof(sha256)) <= der.size(); i++){
		// Если опознаватель данных PKCS #7 найден
		if((atData == std::string::npos) && (::memcmp(der.data() + i, data, sizeof(data)) == 0))
			// Запоминаем смещение опознавателя данных
			atData = i;
		// Если опознаватель хеша найден
		if((atSha256 == std::string::npos) && (::memcmp(der.data() + i, sha256, sizeof(sha256)) == 0))
			// Запоминаем смещение опознавателя хеша
			atSha256 = i;
	}
	// Проверяем, что опознаватель данных найден
	ASSERT_NE(atData, std::string::npos);
	// Проверяем, что опознаватель хеша найден
	ASSERT_NE(atSha256, std::string::npos);
	{
		// Запись с чужим видом содержимого верхней записи: опознаватель данных порчен
		std::vector <uint8_t> foreign = der;
		// Портим последний байт опознавателя данных: 0x01 становится 0x7F
		foreign[atData + sizeof(data) - 1] = 0x7F;
		// Проверяем отказ разбора записи с чужим видом содержимого
		ASSERT_EQ(keys::decodePkcs12(view(foreign), view("secret"), key, chain), keys::error_t::STRUCTURE);
	}
	{
		// Запись с чужим алгоритмом имитовставки: опознаватель SHA-256 порчен
		std::vector <uint8_t> foreign = der;
		// Портим последний байт опознавателя хеша имитовставки
		foreign[atSha256 + sizeof(sha256) - 1] = 0x7F;
		// Проверяем отказ разбора записи с чужим алгоритмом имитовставки
		ASSERT_EQ(keys::decodePkcs12(view(foreign), view("secret"), key, chain), keys::error_t::CIPHER);
	}
	{
		// Запись с порченой имитовставкой: байт имитовставки перевёрнут
		std::vector <uint8_t> damaged = der;
		// Портим байт имитовставки записи: она лежит внутри сведений MacData ближе к концу записи
		damaged[damaged.size() - 45] ^= 0x01;
		// Проверяем отказ разбора: имитовставка записи не сходится
		ASSERT_EQ(keys::decodePkcs12(view(damaged), view("secret"), key, chain), keys::error_t::PASSWORD);
	}
	{
		// Запись с изданием 2: издания выше третьего не дозволены
		std::vector <uint8_t> edition = der;
		// Портим издание записи: 3 становится 2
		edition[8] = 0x02;
		// Проверяем отказ разбора записи с изданием 2
		ASSERT_EQ(keys::decodePkcs12(view(edition), view("secret"), key, chain), keys::error_t::STRUCTURE);
	}
	{
		// Оборванная запись: половины записи не хватает даже на сведения о содержимом
		const std::vector <uint8_t> truncated(der.begin(), der.begin() + (der.size() / 2));
		// Проверяем отказ разбора оборванной записи
		ASSERT_NE(keys::decodePkcs12(view(truncated), view("secret"), key, chain), keys::error_t::NONE);
	}
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе разбор обязан ответить
	 * либо успехом, либо отказом памяти, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 96; budget++){
		// Итог разбора при отмеренном запасе
		keys::error_t outcome = keys::error_t::NONE;
		{
			// Отмеряем запас выделений на время разбора
			starve::ration_t ration(budget);
			// Выполняем разбор записи при отмеренном запасе
			outcome = keys::decodePkcs12(view(der), view("secret"), key, chain);
		}
		// Проверяем, что разбор ответил успехом либо отказом, но не прерыванием исполнения: нехватка памяти в выработке ключа имитовставки отдаётся отказом схемы
		ASSERT_TRUE((outcome == keys::error_t::NONE) || (outcome == keys::error_t::MEMORY) || (outcome == keys::error_t::CIPHER)) << "запас " << budget << ", отказ " << keys::name(outcome);
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == keys::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}

/**
 * @brief Проверка отказов разбора PrivateKeyInfo: чужой алгоритм, обрезка, порча метки
 *
 * @note Мутации валидных записей набора во всех видах ключей: RSA, EC, Ed25519, X25519
 *
 */
TEST(KeysTest, PrivateKeyInfoRefusal){
	/**
	 * Выполняем перебор ключей набора
	 */
	for(const entry_t & entry : ENTRIES){
		// Запись секретного ключа набора
		const std::vector <uint8_t> secret = bytes(corpus(std::string(entry.name) + ".der"));
		// Проверяем наличие записи
		ASSERT_FALSE(secret.empty()) << "Ключ: " << entry.name;
		// Разобранный ключ
		keys::key_t key;
		// Разборщик записи секретного ключа
		asn1::reader_t reader(view(secret));
		// Элементы записи
		asn1::element_t sequence, version, algorithm, oid;
		// Проверяем разбор набора записи
		ASSERT_TRUE(reader.next(asn1::tag_t::SEQUENCE, sequence)) << "Ключ: " << entry.name;
		// Разборщик содержимого набора
		asn1::reader_t fields = reader.enter(sequence);
		// Проверяем разбор издания записи
		ASSERT_TRUE(fields.next(asn1::tag_t::INTEGER, version)) << "Ключ: " << entry.name;
		// Проверяем разбор набора алгоритма
		ASSERT_TRUE(fields.next(asn1::tag_t::SEQUENCE, algorithm)) << "Ключ: " << entry.name;
		// Разборщик содержимого набора алгоритма
		asn1::reader_t items = fields.enter(algorithm);
		// Проверяем разбор опознавателя алгоритма
		ASSERT_TRUE(items.next(asn1::tag_t::OBJECT, oid)) << "Ключ: " << entry.name;
		{
			// Запись с чужим алгоритмом: последний байт опознавателя порчен
			std::vector <uint8_t> foreign = secret;
			// Портим последний байт опознавателя алгоритма
			foreign[static_cast <size_t> ((oid.content.data + oid.content.size - 1) - secret.data())] ^= 0x7F;
			// Проверяем отказ разбора записи с чужим алгоритмом
			ASSERT_EQ(keys::decodePrivateKeyInfo(view(foreign), key), keys::error_t::ALGORITHM) << "Ключ: " << entry.name;
		}
		{
			// Запись с порченой меткой набора алгоритма: SEQUENCE заменён на SET
			std::vector <uint8_t> tagged = secret;
			// Портим метку набора алгоритма
			tagged[static_cast <size_t> (algorithm.element.data - secret.data())] = 0x31;
			// Проверяем отказ разбора записи с порченой меткой
			ASSERT_NE(keys::decodePrivateKeyInfo(view(tagged), key), keys::error_t::NONE) << "Ключ: " << entry.name;
		}
		{
			// Оборванная запись: отрезано всё содержимое набора алгоритма
			const std::vector <uint8_t> truncated(secret.begin(), secret.begin() + static_cast <size_t> (algorithm.element.data - secret.data()));
			// Проверяем отказ разбора оборванной записи
			ASSERT_EQ(keys::decodePrivateKeyInfo(view(truncated), key), keys::error_t::STRUCTURE) << "Ключ: " << entry.name;
		}
		{
			// Запись с изданием 2: издания выше второго не дозволены
			std::vector <uint8_t> edition = secret;
			// Портим издание записи: 0 становится 2
			edition[static_cast <size_t> ((version.content.data + version.content.size - 1) - secret.data())] = 0x02;
			// Проверяем отказ разбора записи с изданием 2
			ASSERT_EQ(keys::decodePrivateKeyInfo(view(edition), key), keys::error_t::STRUCTURE) << "Ключ: " << entry.name;
		}
	}
}

/**
 * @brief Проверка выведения открытой части ключа из секретной всеми видами ключей
 *
 * @note Круг разбора и записи ключей корпуса: EC на кривой P-521, Ed448, ML-DSA
 *       всех наборов, SM2 и ГОСТ; у EC и Ed448 сличение открытой части с записанной
 *
 */
TEST(KeysTest, Derive){
	// Секретный ключ EC на кривой P-521
	keys::key_t ec521;
	// Проверяем разбор секретного ключа
	ASSERT_EQ(keys::decode(corpus("ec521.pem"), view_t(), ec521), keys::error_t::NONE);
	// Проверяем вид ключа
	ASSERT_EQ(ec521.kind, keys::kind_t::EC);
	// Проверяем опознаватель кривой
	ASSERT_EQ(ec521.oid, "1.3.132.0.35");
	// Проверяем размер ключа
	ASSERT_EQ(ec521.size(), static_cast <size_t> (66));
	// Запись секретного ключа
	std::vector <uint8_t> der;
	// Проверяем запись PrivateKeyInfo
	ASSERT_EQ(keys::encodePrivateKeyInfo(ec521, der), keys::error_t::NONE);
	// Разобранный вновь ключ
	keys::key_t again;
	// Проверяем разбор записанного ключа
	ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), again), keys::error_t::NONE);
	// Проверяем совпадение открытых частей
	ASSERT_TRUE(alike(ec521, again));
	// Проверяем совпадение секретных частей
	ASSERT_EQ(ec521.d, again.d);
	// Запись открытого ключа
	std::vector <uint8_t> spki;
	// Проверяем запись SubjectPublicKeyInfo
	ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(ec521, spki), keys::error_t::NONE);
	// Разобранный открытый ключ
	keys::key_t opened;
	// Проверяем разбор SubjectPublicKeyInfo
	ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(spki), opened), keys::error_t::NONE);
	// Проверяем совпадение открытых частей
	ASSERT_TRUE(alike(ec521, opened));
	// Секретный ключ Ed448
	keys::key_t ed448;
	// Проверяем разбор секретного ключа Ed448
	ASSERT_EQ(keys::decode(corpus("ed448.key"), view_t(), ed448), keys::error_t::NONE);
	// Проверяем вид ключа
	ASSERT_EQ(ed448.kind, keys::kind_t::ED448);
	// Проверяем размер ключа
	ASSERT_EQ(ed448.size(), static_cast <size_t> (57));
	// Проверяем наличие секретной части
	ASSERT_TRUE(ed448.secret());
	// Проверяем размер зерна
	ASSERT_EQ(ed448.d.size(), static_cast <size_t> (57));
	// Проверяем размер открытого ключа
	ASSERT_EQ(ed448.key.size(), static_cast <size_t> (57));
	// Секретный ключ SM2
	keys::key_t sm2;
	// Проверяем разбор секретного ключа SM2
	ASSERT_EQ(keys::decode(corpus("sm2.pem"), view_t(), sm2), keys::error_t::NONE);
	// Проверяем вид ключа
	ASSERT_EQ(sm2.kind, keys::kind_t::SM2);
	// Проверяем опознаватель кривой
	ASSERT_EQ(sm2.oid, "1.2.156.10197.1.301");
	// Проверяем наличие секретной части
	ASSERT_TRUE(sm2.secret());
	// Проверяем размер секретного скаляра
	ASSERT_EQ(sm2.d.size(), static_cast <size_t> (32));
	// Наборы параметров ML-DSA
	static const char * MLDSA[] = {"mldsa44", "mldsa65", "mldsa87"};
	/**
	 * Выполняем перебор наборов параметров ML-DSA
	 */
	for(const char * name : MLDSA){
		// Секретный ключ набора
		keys::key_t secret;
		// Проверяем разбор секретного ключа
		ASSERT_EQ(keys::decode(corpus(std::string(name) + ".pem"), view_t(), secret), keys::error_t::NONE) << "Ключ: " << name;
		// Проверяем вид ключа
		ASSERT_EQ(secret.kind, keys::kind_t::MLDSA) << "Ключ: " << name;
		// Запись секретного ключа
		std::vector <uint8_t> record;
		// Проверяем запись PrivateKeyInfo
		ASSERT_EQ(keys::encodePrivateKeyInfo(secret, record), keys::error_t::NONE) << "Ключ: " << name;
		// Разобранный вновь ключ
		keys::key_t direct;
		// Проверяем разбор записанного ключа
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(record), direct), keys::error_t::NONE) << "Ключ: " << name;
		// Проверяем совпадение открытых частей
		ASSERT_TRUE(alike(secret, direct)) << "Ключ: " << name;
		// Проверяем совпадение секретных частей
		ASSERT_EQ(secret.d, direct.d) << "Ключ: " << name;
		// Запись открытого ключа
		std::vector <uint8_t> subject;
		// Проверяем запись SubjectPublicKeyInfo
		ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(secret, subject), keys::error_t::NONE) << "Ключ: " << name;
		// Разобранный открытый ключ
		keys::key_t plain;
		// Проверяем разбор SubjectPublicKeyInfo
		ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(subject), plain), keys::error_t::NONE) << "Ключ: " << name;
		// Проверяем совпадение открытых частей
		ASSERT_TRUE(alike(secret, plain)) << "Ключ: " << name;
	}
}

/**
 * @brief Проверка отказов разбора настроек PBES2 зашифрованных записей
 *
 * @note Мутации валидной зашифрованной записи набора: порча опознавателя выработки
 *       ключа, порча опознавателя имитовставки, порча опознавателя шифра, обрезка
 *       настроек; разбор записей со всеми сочетаниями длин ключа шифра
 *
 */
TEST(KeysTest, Pbes2Refusal){
	// Зашифрованная запись набора
	const std::vector <uint8_t> sealed = body(corpus("ec256.aes-256-cbc.enc.pem"));
	// Проверяем наличие записи
	ASSERT_FALSE(sealed.empty());
	// Разобранный ключ
	keys::key_t key;
	// Опознаватель PBES2 в кодировке DER
	const uint8_t pbes2[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D};
	// Опознаватель PBKDF2 в кодировке DER
	const uint8_t pbkdf2[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C};
	// Опознаватель имитовставки HMAC-SHA256 в кодировке DER
	const uint8_t hmac[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09};
	// Опознаватель шифра AES-256-CBC в кодировке DER
	const uint8_t aes[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A};
	// Смещения опознавателей в записи
	size_t atPbes2 = std::string::npos, atPbkdf2 = std::string::npos, atHmac = std::string::npos, atAes = std::string::npos;
	/**
	 * Выполняем поиск опознавателей в записи
	 */
	for(size_t i = 0; (i + sizeof(pbes2)) <= sealed.size(); i++){
		// Если опознаватель PBES2 найден
		if((atPbes2 == std::string::npos) && (::memcmp(sealed.data() + i, pbes2, sizeof(pbes2)) == 0))
			// Запоминаем смещение опознавателя PBES2
			atPbes2 = i;
		// Если опознаватель PBKDF2 найден
		if((atPbkdf2 == std::string::npos) && (::memcmp(sealed.data() + i, pbkdf2, sizeof(pbkdf2)) == 0))
			// Запоминаем смещение опознавателя PBKDF2
			atPbkdf2 = i;
		// Если опознаватель имитовставки найден
		if((atHmac == std::string::npos) && (::memcmp(sealed.data() + i, hmac, sizeof(hmac)) == 0))
			// Запоминаем смещение опознавателя имитовставки
			atHmac = i;
		// Если опознаватель шифра найден
		if((atAes == std::string::npos) && (::memcmp(sealed.data() + i, aes, sizeof(aes)) == 0))
			// Запоминаем смещение опознавателя шифра
			atAes = i;
	}
	// Проверяем, что опознаватель PBES2 найден
	ASSERT_NE(atPbes2, std::string::npos);
	// Проверяем, что опознаватель PBKDF2 найден
	ASSERT_NE(atPbkdf2, std::string::npos);
	// Проверяем, что опознаватель имитовставки найден
	ASSERT_NE(atHmac, std::string::npos);
	// Проверяем, что опознаватель шифра найден
	ASSERT_NE(atAes, std::string::npos);
	{
		// Запись с чужой схемой защиты: опознаватель PBES2 порчен
		std::vector <uint8_t> foreign = sealed;
		// Портим последний байт опознавателя схемы защиты
		foreign[atPbes2 + sizeof(pbes2) - 1] ^= 0x7F;
		// Проверяем отказ разбора записи с чужой схемой
		ASSERT_EQ(keys::decodeEncryptedPrivateKeyInfo(view(foreign), view(PASSWORD_CORPUS), key), keys::error_t::CIPHER);
	}
	{
		// Запись с чужой выработкой ключа: опознаватель PBKDF2 порчен
		std::vector <uint8_t> foreign = sealed;
		// Портим последний байт опознавателя выработки ключа
		foreign[atPbkdf2 + sizeof(pbkdf2) - 1] ^= 0x7F;
		// Проверяем отказ разбора записи с чужой выработкой ключа
		ASSERT_EQ(keys::decodeEncryptedPrivateKeyInfo(view(foreign), view(PASSWORD_CORPUS), key), keys::error_t::CIPHER);
	}
	{
		// Запись с чужой имитовставкой: опознаватель HMAC-SHA256 порчен
		std::vector <uint8_t> foreign = sealed;
		// Портим последний байт опознавателя имитовставки
		foreign[atHmac + sizeof(hmac) - 1] ^= 0x7F;
		// Проверяем отказ разбора записи с чужой имитовставкой
		ASSERT_EQ(keys::decodeEncryptedPrivateKeyInfo(view(foreign), view(PASSWORD_CORPUS), key), keys::error_t::CIPHER);
	}
	{
		// Запись с чужим шифром: опознаватель AES-256-CBC порчен
		std::vector <uint8_t> foreign = sealed;
		// Портим последний байт опознавателя шифра
		foreign[atAes + sizeof(aes) - 1] ^= 0x7F;
		// Проверяем отказ разбора записи с чужим шифром
		ASSERT_EQ(keys::decodeEncryptedPrivateKeyInfo(view(foreign), view(PASSWORD_CORPUS), key), keys::error_t::CIPHER);
	}
	{
		// Оборванная запись: настройки схемы отрезаны на середине
		const std::vector <uint8_t> truncated(sealed.begin(), sealed.begin() + atHmac);
		// Проверяем отказ разбора оборванной записи
		ASSERT_NE(keys::decodeEncryptedPrivateKeyInfo(view(truncated), view(PASSWORD_CORPUS), key), keys::error_t::NONE);
	}
	// Имена зашифрованных записей набора всех видов ключей и длин ключа шифра
	static const char * NAMES[] = {"rsa2048", "ec256", "ec384", "ed25519", "x25519"};
	/**
	 * Выполняем перебор видов ключей
	 */
	for(const char * name : NAMES){
		/**
		 * Выполняем перебор длин ключа шифра
		 */
		for(const size_t bits : BITS){
			// Имя зашифрованного файла набора
			const std::string file = (std::string(name) + ".aes-" + std::to_string(bits) + "-cbc.enc.pem");
			// Текст зашифрованного ключа
			const std::string text = corpus(file);
			// Проверяем наличие файла набора
			ASSERT_FALSE(text.empty()) << "Файл: " << file;
			// Разобранный ключ
			keys::key_t parsed;
			// Проверяем разбор зашифрованного ключа паролем набора
			ASSERT_EQ(keys::decode(text, view(PASSWORD_CORPUS), parsed), keys::error_t::NONE) << "Файл: " << file;
			// Проверяем наличие секретной части
			ASSERT_TRUE(parsed.secret()) << "Файл: " << file;
		}
	}
}

/**
 * @brief Проверка видов записи секретного ключа ГОСТ: строка байтов, целое число, набор
 *
 * @note Ключ вырабатывается библиотекой, записи трёх видов собираются вручную
 *       по разделу 6 RFC 9215 и разбираются обратно; отказы - порченые записи
 *
 */
TEST(KeysTest, GostForms){
	// Выработанный ключ ГОСТ на кривой 256 разрядов
	keys::key_t made;
	// Проверяем выработку ключа
	ASSERT_TRUE(gost("1.2.643.7.1.2.1.1.1", "1.2.643.7.1.1.1.1", made));
	// Запись секретного ключа
	std::vector <uint8_t> der;
	// Проверяем запись PrivateKeyInfo
	ASSERT_EQ(keys::encodePrivateKeyInfo(made, der), keys::error_t::NONE);
	// Разобранный секретный ключ
	keys::key_t secret;
	// Проверяем разбор PrivateKeyInfo
	ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), secret), keys::error_t::NONE);
	// Проверяем вид ключа
	ASSERT_EQ(secret.kind, keys::kind_t::GOST);
	// Развёрнутый скаляр ключа порядком от младшего байта к старшему
	std::vector <uint8_t> reversed(secret.d.rbegin(), secret.d.rend());
	{
		// Запись ключа целым числом порядком от старшего байта к младшему
		asn1::writer_t body;
		// Байты целого числа с местом под ведущий ноль знака
		std::vector <uint8_t> number;
		// Если старший разряд скаляра выставлен
		if((secret.d[0] & 0x80) != 0)
			// Заводим ведущий ноль знака
			number.push_back(0x00);
		// Дописываем скаляр порядком от старшего байта к младшему
		number.insert(number.end(), secret.d.begin(), secret.d.end());
		// Записываем целое число ключа
		body.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), view(number));
		// Запись PrivateKeyInfo с телом целым числом
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(0);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("1.2.643.7.1.1.1.1");
		// Открываем настройки ключа
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель кривой
		writer.oid("1.2.643.7.1.2.1.1.1");
		// Записываем опознаватель хеша
		writer.oid("1.2.643.7.1.1.2.2");
		// Закрываем настройки ключа
		writer.close();
		// Закрываем набор алгоритма
		writer.close();
		// Записываем тело ключа строкой байтов
		writer.octets(body.data());
		// Закрываем набор записи
		writer.close();
		// Разобранный ключ
		keys::key_t key;
		// Проверяем разбор записи с ключом целым числом
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::NONE);
		// Проверяем вид ключа
		ASSERT_EQ(key.kind, keys::kind_t::GOST);
		// Проверяем совпадение секретных частей
		ASSERT_EQ(key.d, secret.d);
	}
	{
		// Запись ключа набором из издания и строки байтов порядком от старшего байта
		asn1::writer_t body;
		// Открываем набор записи ключа
		body.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи ключа
		body.integer(0);
		// Записываем скаляр строкой байтов порядком от старшего байта
		body.octets(view(secret.d));
		// Закрываем набор записи ключа
		body.close();
		// Запись PrivateKeyInfo с телом набором
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(0);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("1.2.643.7.1.1.1.1");
		// Открываем настройки ключа
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель кривой
		writer.oid("1.2.643.7.1.2.1.1.1");
		// Записываем опознаватель хеша
		writer.oid("1.2.643.7.1.1.2.2");
		// Закрываем настройки ключа
		writer.close();
		// Закрываем набор алгоритма
		writer.close();
		// Записываем тело ключа строкой байтов
		writer.octets(body.data());
		// Закрываем набор записи
		writer.close();
		// Разобранный ключ
		keys::key_t key;
		// Проверяем разбор записи с ключом набором
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::NONE);
		// Проверяем вид ключа
		ASSERT_EQ(key.kind, keys::kind_t::GOST);
		// Проверяем совпадение секретных частей
		ASSERT_EQ(key.d, secret.d);
	}
	{
		// Запись ключа строкой байтов с хвостом
		asn1::writer_t body;
		// Записываем скаляр строкой байтов порядком от младшего байта
		body.octets(view(reversed));
		// Записываем хвост строкой байтов
		body.octets(view(reversed));
		// Запись PrivateKeyInfo с телом с хвостом
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(0);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("1.2.643.7.1.1.1.1");
		// Открываем настройки ключа
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель кривой
		writer.oid("1.2.643.7.1.2.1.1.1");
		// Закрываем настройки ключа
		writer.close();
		// Закрываем набор алгоритма
		writer.close();
		// Записываем тело ключа строкой байтов
		writer.octets(body.data());
		// Закрываем набор записи
		writer.close();
		// Разобранный ключ
		keys::key_t key;
		// Проверяем отказ разбора записи с хвостом
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::STRUCTURE);
	}
	{
		// Запись ключа пустой строкой байтов
		asn1::writer_t body;
		// Записываем пустую строку байтов
		body.octets(view_t());
		// Запись PrivateKeyInfo с пустым телом
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(0);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("1.2.643.7.1.1.1.1");
		// Открываем настройки ключа
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель кривой
		writer.oid("1.2.643.7.1.2.1.1.1");
		// Закрываем настройки ключа
		writer.close();
		// Закрываем набор алгоритма
		writer.close();
		// Записываем тело ключа строкой байтов
		writer.octets(body.data());
		// Закрываем набор записи
		writer.close();
		// Разобранный ключ
		keys::key_t key;
		// Проверяем отказ разбора записи с пустым ключом
		ASSERT_NE(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::NONE);
	}
	// Запись открытого ключа
	std::vector <uint8_t> spki;
	// Проверяем запись SubjectPublicKeyInfo
	ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(secret, spki), keys::error_t::NONE);
	{
		// Запись открытого ключа с порченой строкой координат: длина не двух координат
		std::vector <uint8_t> damaged = spki;
		// Портим последний байт записи: строка координат обрывается
		damaged.pop_back();
		// Разобранный ключ
		keys::key_t key;
		// Проверяем отказ разбора порченой записи
		ASSERT_NE(keys::decodeSubjectPublicKeyInfo(view(damaged), key), keys::error_t::NONE);
	}
	{
		// Запись открытого ключа с точкой вне кривой
		std::vector <uint8_t> outside = spki;
		// Портим последний байт второй координаты
		outside.back() ^= 0x01;
		// Разобранный ключ
		keys::key_t key;
		// Проверяем отказ разбора записи с точкой вне кривой
		ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(outside), key), keys::error_t::CURVE);
	}
}

/**
 * @brief Проверка отказов разбора ECPrivateKey: издание, пустой скаляр, хвост
 *
 * @note Мутации валидной записи SEC 1 набора и записи, собранные вручную
 *
 */
TEST(KeysTest, EcSecretRefusal){
	// Текст записи SEC 1
	const std::string sec1 = corpus("ec256.sec1.pem");
	// Проверяем наличие записи
	ASSERT_FALSE(sec1.empty());
	// Тело записи SEC 1
	const std::vector <uint8_t> der = body(sec1);
	// Проверяем наличие тела
	ASSERT_FALSE(der.empty());
	// Разобранный ключ
	keys::key_t key;
	{
		// Запись с изданием 2: издания выше первого не дозволены
		std::vector <uint8_t> edition = der;
		// Разборщик записи
		asn1::reader_t reader(view(der));
		// Набор записи
		asn1::element_t sequence;
		// Проверяем разбор набора
		ASSERT_TRUE(reader.next(asn1::tag_t::SEQUENCE, sequence));
		// Разборщик содержимого набора
		asn1::reader_t fields = reader.enter(sequence);
		// Издание записи
		asn1::element_t version;
		// Проверяем разбор издания записи
		ASSERT_TRUE(fields.next(asn1::tag_t::INTEGER, version));
		// Портим издание записи: 1 становится 2
		edition[static_cast <size_t> ((version.content.data + version.content.size - 1) - der.data())] = 0x02;
		// Проверяем отказ разбора записи с изданием 2
		ASSERT_EQ(keys::decodeECPrivateKey(view(edition), key), keys::error_t::STRUCTURE);
	}
	{
		// Оборванная запись: отрезан последний байт
		const std::vector <uint8_t> truncated(der.begin(), der.end() - 1);
		// Проверяем отказ разбора оборванной записи
		ASSERT_NE(keys::decodeECPrivateKey(view(truncated), key), keys::error_t::NONE);
	}
	{
		// Запись с пустым секретным скаляром
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(1);
		// Записываем пустой секретный скаляр
		writer.octets(view_t());
		// Закрываем набор записи
		writer.close();
		// Проверяем отказ разбора записи с пустым скаляром
		ASSERT_EQ(keys::decodeECPrivateKey(writer.data(), key), keys::error_t::VALUE);
	}
	{
		// Запись с хвостом после скаляра: поле не опознано
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(1);
		// Записываем секретный скаляр
		writer.octets(view_t(der.data(), 1));
		// Записываем поле неведомого вида
		writer.integer(7);
		// Закрываем набор записи
		writer.close();
		// Проверяем отказ разбора записи с полем неведомого вида
		ASSERT_EQ(keys::decodeECPrivateKey(writer.data(), key), keys::error_t::STRUCTURE);
	}
	// Ключ из записи SEC 1
	keys::key_t parsed;
	// Проверяем разбор записи SEC 1
	ASSERT_EQ(keys::decodeECPrivateKey(view(der), parsed), keys::error_t::NONE);
	// Проверяем вид ключа
	ASSERT_EQ(parsed.kind, keys::kind_t::EC);
	// Проверяем опознаватель кривой
	ASSERT_EQ(parsed.oid, P256);
}

/**
 * @brief Проверка отказов разбора секретного ключа ML-DSA
 *
 * @note Мутации валидных записей набора: чужой опознаватель алгоритма, хвост
 *       после разновидности, несогласованный развёрнутый ключ при зерне
 *
 */
TEST(KeysTest, MldsaRefusal){
	// Разобранный ключ
	keys::key_t key;
	{
		// Запись ключа ML-DSA-44 с зерном
		const std::string pem = corpus("mldsa/mldsa44-seed-only.pem");
		// Проверяем наличие записи
		ASSERT_FALSE(pem.empty());
		// Тело записи
		const std::vector <uint8_t> der = body(pem);
		// Проверяем наличие тела
		ASSERT_FALSE(der.empty());
		// Запись с чужим опознавателем алгоритма: ML-DSA-44 становится ML-DSA-65
		std::vector <uint8_t> foreign = der;
		// Разборщик записи
		asn1::reader_t reader(view(der));
		// Элементы записи
		asn1::element_t sequence, version, algorithm, oid;
		// Проверяем разбор набора записи
		ASSERT_TRUE(reader.next(asn1::tag_t::SEQUENCE, sequence));
		// Разборщик содержимого набора
		asn1::reader_t fields = reader.enter(sequence);
		// Проверяем разбор издания записи
		ASSERT_TRUE(fields.next(asn1::tag_t::INTEGER, version));
		// Проверяем разбор набора алгоритма
		ASSERT_TRUE(fields.next(asn1::tag_t::SEQUENCE, algorithm));
		// Разборщик содержимого набора алгоритма
		asn1::reader_t items = fields.enter(algorithm);
		// Проверяем разбор опознавателя алгоритма
		ASSERT_TRUE(items.next(asn1::tag_t::OBJECT, oid));
		// Портим последний байт опознавателя: 17 становится неведомым 0x7F
		foreign[static_cast <size_t> ((oid.content.data + oid.content.size - 1) - der.data())] = 0x7F;
		// Проверяем отказ разбора записи с чужим алгоритмом
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(foreign), key), keys::error_t::ALGORITHM);
	}
	{
		// Запись ключа ML-DSA-44 с зерном и хвостом после разновидности
		const std::string pem = corpus("mldsa/mldsa44-seed-only.pem");
		// Тело записи
		std::vector <uint8_t> der = body(pem);
		// Разборщик записи
		asn1::reader_t reader(view(der));
		// Элементы записи
		asn1::element_t sequence, body_element;
		// Проверяем разбор набора записи
		ASSERT_TRUE(reader.next(asn1::tag_t::SEQUENCE, sequence));
		// Разборщик содержимого набора
		asn1::reader_t fields = reader.enter(sequence);
		// Издание записи
		asn1::element_t version;
		// Проверяем разбор издания записи
		ASSERT_TRUE(fields.next(asn1::tag_t::INTEGER, version));
		// Набор алгоритма
		asn1::element_t algorithm;
		// Проверяем разбор набора алгоритма
		ASSERT_TRUE(fields.next(asn1::tag_t::SEQUENCE, algorithm));
		// Строка байтов тела ключа
		asn1::element_t octets;
		// Проверяем разбор строки байтов тела ключа
		ASSERT_TRUE(fields.next(asn1::tag_t::OCTET_STRING, octets));
		// Смещение содержимого тела ключа в записи
		const size_t at = static_cast <size_t> (octets.content.data - der.data());
		// Собираем запись с хвостом внутри тела ключа: зерно с меткой [0] и лишний байт
		std::vector <uint8_t> spoiled = der;
		// Удлиняем тело ключа на байт
		spoiled.insert(spoiled.begin() + at + octets.content.size, 0x00);
		// Поправляем длину строки байтов тела ключа
		spoiled[static_cast <size_t> (octets.element.data - der.data()) + 1] += 1;
		// Поправляем длину набора записи
		spoiled[1] += 1;
		// Проверяем отказ разбора записи с хвостом внутри тела
		ASSERT_NE(keys::decodePrivateKeyInfo(view(spoiled), key), keys::error_t::NONE);
	}
	{
		// Запись ключа ML-DSA-44 с зерном и развёрнутым ключом, не согласованным с зерном
		const std::string pem = corpus("mldsa/mldsa44-seed-priv.pem");
		// Проверяем наличие записи
		ASSERT_FALSE(pem.empty());
		// Тело записи
		const std::vector <uint8_t> der = body(pem);
		// Проверяем наличие тела
		ASSERT_FALSE(der.empty());
		// Запись с порченым развёрнутым ключом: последний байт тела перевёрнут
		std::vector <uint8_t> spoiled = der;
		// Портим последний байт развёрнутого ключа
		spoiled.back() ^= 0x01;
		// Проверяем отказ разбора: развёрнутый ключ с зерном не сошёлся
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(spoiled), key), keys::error_t::VALUE);
	}
	{
		// Запись ключа ML-DSA-44 с настройками алгоритма: раздел 5 RFC 9881 их запрещает
		const std::string pem = corpus("mldsa/mldsa44-seed-only.pem");
		// Тело записи
		const std::vector <uint8_t> der = body(pem);
		// Разборщик записи
		asn1::reader_t reader(view(der));
		// Элементы записи
		asn1::element_t sequence, algorithm;
		// Проверяем разбор набора записи
		ASSERT_TRUE(reader.next(asn1::tag_t::SEQUENCE, sequence));
		// Разборщик содержимого набора
		asn1::reader_t fields = reader.enter(sequence);
		// Издание записи
		asn1::element_t version;
		// Проверяем разбор издания записи
		ASSERT_TRUE(fields.next(asn1::tag_t::INTEGER, version));
		// Проверяем разбор набора алгоритма
		ASSERT_TRUE(fields.next(asn1::tag_t::SEQUENCE, algorithm));
		// Собираем запись с пустыми настройками алгоритма
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(0);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("2.16.840.1.101.3.4.3.17");
		// Записываем пустые настройки
		writer.nothing();
		// Закрываем набор алгоритма
		writer.close();
		// Разборщик содержимого набора записи для тела ключа
		asn1::reader_t rest = reader.enter(sequence);
		// Пропускаем издание записи
		rest.next(version);
		// Пропускаем набор алгоритма
		rest.next(algorithm);
		// Строка байтов тела ключа
		asn1::element_t octets;
		// Проверяем разбор строки байтов тела ключа
		ASSERT_TRUE(rest.next(asn1::tag_t::OCTET_STRING, octets));
		// Записываем тело ключа
		writer.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::OCTET_STRING), octets.content);
		// Закрываем набор записи
		writer.close();
		// Проверяем отказ разбора записи с настройками алгоритма
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::ALGORITHM);
	}
}

/**
 * @brief Проверка ключа Ed448: круг записи и отказы разбора
 *
 * @note Ключ набора ed448.key; круги DER/PEM, OneAsymmetricKey второго издания,
 *       обмен с OpenSSL и PKCS #12; отказы - зерно чужой длины, настройки алгоритма,
 *       хвост после зерна
 *
 */
TEST(KeysTest, Ed448){
	// Секретный ключ Ed448
	keys::key_t secret;
	// Проверяем разбор секретного ключа
	ASSERT_EQ(keys::decode(corpus("ed448.key"), view_t(), secret), keys::error_t::NONE);
	// Проверяем вид ключа
	ASSERT_EQ(secret.kind, keys::kind_t::ED448);
	// Проверяем размер зерна
	ASSERT_EQ(secret.d.size(), static_cast <size_t> (57));
	// Проверяем размер открытого ключа
	ASSERT_EQ(secret.key.size(), static_cast <size_t> (57));
	// Разобранный ключ
	keys::key_t key;
	// Запись PrivateKeyInfo в кодировке DER
	std::vector <uint8_t> der;
	// Проверяем запись секретного ключа
	ASSERT_EQ(keys::encodePrivateKeyInfo(secret, der), keys::error_t::NONE);
	// Проверяем побайтовое совпадение с эталоном OpenSSL
	ASSERT_EQ(der, body(corpus("ed448.key")));
	// Проверяем разбор записанного секретного ключа
	ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), key), keys::error_t::NONE);
	// Проверяем совпадение открытых частей после круга
	ASSERT_TRUE(alike(secret, key));
	// Проверяем совпадение секретных частей после круга
	ASSERT_EQ(key.d, secret.d);
	// Запись SubjectPublicKeyInfo в кодировке DER
	std::vector <uint8_t> spki;
	// Проверяем запись открытого ключа
	ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(secret, spki), keys::error_t::NONE);
	// Проверяем разбор записанного открытого ключа
	ASSERT_EQ(keys::decodeSubjectPublicKeyInfo(view(spki), key), keys::error_t::NONE);
	// Проверяем совпадение открытых частей после круга
	ASSERT_TRUE(alike(secret, key));
	// Проверяем отсутствие секретной части у открытого ключа
	ASSERT_FALSE(key.secret());
	// Текст записи в обёртке PEM
	std::string text;
	// Проверяем запись PrivateKeyInfo в обёртке PEM
	ASSERT_EQ(keys::encode(secret, keys::container_t::PRIVATE, text, view_t()), keys::error_t::NONE);
	// Проверяем совпадение тела PEM с записью DER
	ASSERT_EQ(body(text), der);
	// Проверяем разбор секретного ключа из обёртки PEM
	ASSERT_EQ(keys::decode(text, view_t(), key), keys::error_t::NONE);
	// Проверяем совпадение открытых частей после круга PEM
	ASSERT_TRUE(alike(secret, key));
	// Проверяем запись SubjectPublicKeyInfo в обёртке PEM
	ASSERT_EQ(keys::encode(secret, keys::container_t::PUBLIC, text, view_t()), keys::error_t::NONE);
	// Проверяем совпадение тела PEM с записью DER
	ASSERT_EQ(body(text), spki);
	// Проверяем разбор открытого ключа из обёртки PEM
	ASSERT_EQ(keys::decode(text, view_t(), key), keys::error_t::NONE);
	// Проверяем совпадение открытых частей после круга PEM
	ASSERT_TRUE(alike(secret, key));
	{
		// Запись OneAsymmetricKey второго издания с открытым ключом
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем второе издание, обязательное при наличии publicKey
		writer.integer(1);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель Ed448
		writer.oid("1.3.101.113");
		// Закрываем набор алгоритма
		writer.close();
		// Записываем зерно во внутренней строке байтов
		asn1::writer_t seed;
		// Записываем зерно Ed448
		seed.octets(view(secret.d));
		// Записываем CurvePrivateKey во внешней строке байтов
		writer.octets(seed.data());
		// Строка битов открытого ключа с нулевым числом неиспользуемых разрядов
		std::vector <uint8_t> bits(1, 0);
		// Дописываем открытый ключ Ed448
		bits.insert(bits.end(), secret.key.begin(), secret.key.end());
		// Записываем открытый ключ неявной меткой [1]
		writer.element(asn1::cls_t::CONTEXT, false, 1, view(bits));
		// Закрываем набор записи
		writer.close();
		// Проверяем разбор OneAsymmetricKey с согласованной открытой частью
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::NONE);
		// Проверяем совпадение открытых частей
		ASSERT_TRUE(alike(secret, key));
		// Проверяем совпадение секретных частей
		ASSERT_EQ(key.d, secret.d);
	}
	{
		// Временный каталог обмена с OpenSSL
		sandbox_t sandbox;
		// Проверяем создание временного каталога
		ASSERT_TRUE(sandbox.ready());
		// Эталонный OpenSSL из родной среды исполнения
		const std::string tool("openssl");
		// Путь к изданию эталона
		const std::string edition = sandbox.file("openssl.version");
		// Снимаем издание эталона
		ASSERT_EQ(shell(tool + " version > " + edition + " 2>&1"), 0);
		// Читаем издание эталона
		const std::string version = slurp(edition);
		// Если эталон строит PKCS #12 на устаревших RC2/3DES вместо PBES2/AES
		if(version.find("OpenSSL 1.") == 0)
			// Пропускаем интероп со старой схемой защиты PKCS #12
			GTEST_SKIP() << "openssl с устаревшей схемой PKCS #12: " << version;
		// Проверяем запись нашего секретного ключа DER
		ASSERT_TRUE(spill(sandbox.file("secret.der"), der));
		// Проверяем запись нашего открытого ключа DER
		ASSERT_TRUE(spill(sandbox.file("public.der"), spki));
		// Проверяем принятие нашего секретного ключа OpenSSL
		ASSERT_EQ(shell(tool + " pkey -inform DER -in " + sandbox.file("secret.der") + " -noout"), 0);
		// Проверяем принятие нашего открытого ключа OpenSSL
		ASSERT_EQ(shell(tool + " pkey -pubin -inform DER -in " + sandbox.file("public.der") + " -noout"), 0);
		// Проверяем запись нашего секретного ключа PEM для упаковки PKCS #12
		ASSERT_EQ(keys::encode(secret, keys::container_t::PRIVATE, text, view_t()), keys::error_t::NONE);
		// Записываем наш секретный ключ PEM
		ASSERT_TRUE(spill(sandbox.file("secret.pem"), text));
		// Вырабатываем эталонный открытый ключ OpenSSL из нашего секретного
		ASSERT_EQ(shell(tool + " pkey -in " + sandbox.file("secret.pem") + " -pubout -outform DER -out " + sandbox.file("openssl.der")), 0);
		// Проверяем побайтовое совпадение открытого ключа с OpenSSL
		ASSERT_EQ(spki, bytes(slurp(sandbox.file("openssl.der"))));
		// Упаковываем наш ключ и сертификат Ed448 в PKCS #12 средствами OpenSSL
		ASSERT_EQ(shell(tool + " pkcs12 -export -inkey " + sandbox.file("secret.pem") + " -in " + std::string(CORPUS) + "/ed448.crt -passout pass:secret -out " + sandbox.file("ed448.p12")), 0);
		// Цепочка сертификатов из PKCS #12
		std::vector <std::vector <uint8_t>> chain;
		// Проверяем разбор нашего ключа из PKCS #12
		ASSERT_EQ(keys::decodePkcs12(view(bytes(slurp(sandbox.file("ed448.p12")))), view("secret"), key, chain), keys::error_t::NONE);
		// Проверяем совпадение открытых частей ключа из PKCS #12
		ASSERT_TRUE(alike(secret, key));
		// Проверяем совпадение секретных частей ключа из PKCS #12
		ASSERT_EQ(key.d, secret.d);
		// Проверяем число сертификатов цепочки
		ASSERT_EQ(chain.size(), static_cast <size_t> (1));
		// Проверяем совпадение сертификата Ed448 с исходным
		ASSERT_EQ(chain.front(), body(corpus("ed448.crt")));
	}
	{
		// Секретный ключ Ed448 с зерном чужой длины
		keys::key_t shorty;
		// Устанавливаем вид ключа
		shorty.kind = keys::kind_t::ED448;
		// Устанавливаем зерно чужой длины
		shorty.d.assign(56, 0);
		// Запись секретного ключа
		std::vector <uint8_t> wrong;
		// Проверяем отказ записи зерна чужой длины
		ASSERT_EQ(keys::encodePrivateKeyInfo(shorty, wrong), keys::error_t::VALUE);
	}
	{
		// Запись с зерном чужой длины: 56 байтов вместо 57
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(0);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("1.3.101.113");
		// Закрываем набор алгоритма
		writer.close();
		// Тело ключа: зерно строкой байтов
		asn1::writer_t body;
		// Записываем зерно чужой длины строкой байтов
		body.octets(view_t(secret.d.data(), 56));
		// Записываем тело ключа
		writer.octets(body.data());
		// Закрываем набор записи
		writer.close();
		// Проверяем отказ разбора записи с зерном чужой длины
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::VALUE);
	}
	{
		// Запись с настройками алгоритма: раздел 3 RFC 8410 их запрещает
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(0);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("1.3.101.113");
		// Записываем пустые настройки
		writer.nothing();
		// Закрываем набор алгоритма
		writer.close();
		// Тело ключа: зерно строкой байтов
		asn1::writer_t body;
		// Записываем зерно строкой байтов
		body.octets(view(secret.d));
		// Записываем тело ключа
		writer.octets(body.data());
		// Закрываем набор записи
		writer.close();
		// Проверяем отказ разбора записи с настройками алгоритма
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::ALGORITHM);
	}
	{
		// Запись с хвостом после зерна
		asn1::writer_t body;
		// Записываем зерно строкой байтов
		body.octets(view(secret.d));
		// Записываем хвост строкой байтов
		body.octets(view(secret.d));
		// Запись PrivateKeyInfo с телом с хвостом
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(0);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("1.3.101.113");
		// Закрываем набор алгоритма
		writer.close();
		// Записываем тело ключа строкой байтов
		writer.octets(body.data());
		// Закрываем набор записи
		writer.close();
		// Проверяем отказ разбора записи с хвостом после зерна
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::STRUCTURE);
	}
	{
		// Открытый ключ Ed448 чужой длины
		keys::key_t shorty;
		// Устанавливаем вид ключа
		shorty.kind = keys::kind_t::ED448;
		// Устанавливаем открытый ключ чужой длины
		shorty.key.assign(56, 0);
		// Запись открытого ключа
		std::vector <uint8_t> der;
		// Проверяем отказ записи открытого ключа чужой длины
		ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(shorty, der), keys::error_t::EMPTY);
	}
}

/**
 * @brief Проверка разбора PrivateKeyInfo второго издания с необязательными полями
 *
 * @note Поля записи по RFC 5958: набор свойств [0] пропускается, открытый ключ [1]
 *       сличается с выведенным из секретной части; собраны вручную из ключей набора
 *
 */
TEST(KeysTest, PrivateKeyInfoV1){
	// Разобранный ключ
	keys::key_t key;
	// Секретный ключ набора EC
	keys::key_t secret;
	// Проверяем разбор секретного ключа
	ASSERT_EQ(keys::decode(corpus("ec256.pem"), view_t(), secret), keys::error_t::NONE);
	// Тело ECPrivateKey ключа
	std::vector <uint8_t> ecbody;
	// Проверяем запись ECPrivateKey без кривой внутри
	ASSERT_EQ(keys::encodeECPrivateKey(secret, ecbody), keys::error_t::NONE);
	// Несжатая точка открытого ключа
	std::vector <uint8_t> point;
	// Заводим признак несжатой записи точки
	point.push_back(0x04);
	// Дописываем первую координату
	point.insert(point.end(), secret.x.begin(), secret.x.end());
	// Дописываем вторую координату
	point.insert(point.end(), secret.y.begin(), secret.y.end());
	{
		// Запись второго издания с набором свойств и открытым ключом
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(1);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("1.2.840.10045.2.1");
		// Записываем опознаватель кривой
		writer.oid(P256);
		// Закрываем набор алгоритма
		writer.close();
		// Записываем тело ключа строкой байтов
		writer.octets(view(ecbody));
		// Открываем набор свойств
		writer.open(asn1::cls_t::CONTEXT, 0);
		// Закрываем набор свойств
		writer.close();
		// Строка битов открытого ключа: нулевое число неиспользуемых разрядов и точка
		std::vector <uint8_t> bits;
		// Заводим нулевое число неиспользуемых разрядов
		bits.push_back(0x00);
		// Дописываем точку
		bits.insert(bits.end(), point.begin(), point.end());
		// Записываем открытый ключ неявной меткой [1]
		writer.element(asn1::cls_t::CONTEXT, false, 1, view(bits));
		// Закрываем набор записи
		writer.close();
		// Проверяем разбор записи второго издания
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::NONE);
		// Проверяем вид ключа
		ASSERT_EQ(key.kind, keys::kind_t::EC);
		// Проверяем совпадение секретных частей
		ASSERT_EQ(key.d, secret.d);
	}
	{
		// Запись второго издания с открытым ключом, не согласованным с секретным
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(1);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("1.2.840.10045.2.1");
		// Записываем опознаватель кривой
		writer.oid(P256);
		// Закрываем набор алгоритма
		writer.close();
		// Записываем тело ключа строкой байтов
		writer.octets(view(ecbody));
		// Порченая точка открытого ключа: координаты обменены местами
		std::vector <uint8_t> swapped;
		// Заводим признак несжатой записи точки
		swapped.push_back(0x04);
		// Дописываем вторую координату на место первой
		swapped.insert(swapped.end(), secret.y.begin(), secret.y.end());
		// Дописываем первую координату на место второй
		swapped.insert(swapped.end(), secret.x.begin(), secret.x.end());
		// Строка битов открытого ключа: нулевое число неиспользуемых разрядов и точка
		std::vector <uint8_t> bits;
		// Заводим нулевое число неиспользуемых разрядов
		bits.push_back(0x00);
		// Дописываем точку
		bits.insert(bits.end(), swapped.begin(), swapped.end());
		// Записываем открытый ключ неявной меткой [1]
		writer.element(asn1::cls_t::CONTEXT, false, 1, view(bits));
		// Закрываем набор записи
		writer.close();
		// Проверяем отказ разбора: точка с обменянными координатами кривой не принадлежит
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::CURVE);
	}
	{
		// Запись первого издания с открытым ключом: он дозволен лишь второму изданию
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(0);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("1.2.840.10045.2.1");
		// Записываем опознаватель кривой
		writer.oid(P256);
		// Закрываем набор алгоритма
		writer.close();
		// Записываем тело ключа строкой байтов
		writer.octets(view(ecbody));
		// Строка битов открытого ключа: нулевое число неиспользуемых разрядов и точка
		std::vector <uint8_t> bits;
		// Заводим нулевое число неиспользуемых разрядов
		bits.push_back(0x00);
		// Дописываем точку
		bits.insert(bits.end(), point.begin(), point.end());
		// Записываем открытый ключ неявной меткой [1]
		writer.element(asn1::cls_t::CONTEXT, false, 1, view(bits));
		// Закрываем набор записи
		writer.close();
		// Проверяем отказ разбора: открытый ключ при первом издании
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::STRUCTURE);
	}
	{
		// Запись второго издания с полем неведомого вида после тела ключа
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(1);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("1.2.840.10045.2.1");
		// Записываем опознаватель кривой
		writer.oid(P256);
		// Закрываем набор алгоритма
		writer.close();
		// Записываем тело ключа строкой байтов
		writer.octets(view(ecbody));
		// Записываем поле неведомого вида: неявная метка [3]
		writer.element(asn1::cls_t::CONTEXT, false, 3, view(point));
		// Закрываем набор записи
		writer.close();
		// Проверяем отказ разбора: поле не опознано
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::STRUCTURE);
	}
	{
		// Запись второго издания ключа Ed25519 с открытым ключом в обёртке
		keys::key_t ed;
		// Проверяем разбор секретного ключа Ed25519
		ASSERT_EQ(keys::decode(corpus("ed25519.pem"), view_t(), ed), keys::error_t::NONE);
		// Запись второго издания с открытым ключом
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(1);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("1.3.101.112");
		// Закрываем набор алгоритма
		writer.close();
		// Тело ключа: зерно строкой байтов
		asn1::writer_t seed;
		// Записываем зерно строкой байтов
		seed.octets(view(ed.d));
		// Записываем тело ключа строкой байтов
		writer.octets(seed.data());
		// Строка битов открытого ключа: нулевое число неиспользуемых разрядов и ключ
		std::vector <uint8_t> bits;
		// Заводим нулевое число неиспользуемых разрядов
		bits.push_back(0x00);
		// Дописываем открытый ключ
		bits.insert(bits.end(), ed.key.begin(), ed.key.end());
		// Записываем открытый ключ неявной меткой [1]
		writer.element(asn1::cls_t::CONTEXT, false, 1, view(bits));
		// Закрываем набор записи
		writer.close();
		// Проверяем разбор записи второго издания
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::NONE);
		// Проверяем вид ключа
		ASSERT_EQ(key.kind, keys::kind_t::ED25519);
		// Проверяем совпадение открытых частей
		ASSERT_EQ(key.key, ed.key);
		// Запись с открытым ключом, не согласованным с зерном
		asn1::writer_t spoiled;
		// Открываем набор записи
		spoiled.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		spoiled.integer(1);
		// Открываем набор алгоритма
		spoiled.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		spoiled.oid("1.3.101.112");
		// Закрываем набор алгоритма
		spoiled.close();
		// Записываем тело ключа строкой байтов
		spoiled.octets(seed.data());
		// Порченый открытый ключ
		std::vector <uint8_t> wrong = ed.key;
		// Портим первый байт открытого ключа
		wrong[0] ^= 0x01;
		// Строка битов порченого открытого ключа: нулевое число неиспользуемых разрядов и ключ
		std::vector <uint8_t> wrongbits;
		// Заводим нулевое число неиспользуемых разрядов
		wrongbits.push_back(0x00);
		// Дописываем порченый открытый ключ
		wrongbits.insert(wrongbits.end(), wrong.begin(), wrong.end());
		// Записываем порченый открытый ключ неявной меткой [1]
		spoiled.element(asn1::cls_t::CONTEXT, false, 1, view(wrongbits));
		// Закрываем набор записи
		spoiled.close();
		// Проверяем отказ разбора: открытый ключ не сошёлся с выведенным из зерна
		ASSERT_EQ(keys::decodePrivateKeyInfo(spoiled.data(), key), keys::error_t::VALUE);
	}
	{
		// Запись ключа SM2 с опознавателем алгоритма SM2 без настроек
		keys::key_t sm2;
		// Проверяем разбор секретного ключа SM2
		ASSERT_EQ(keys::decode(corpus("sm2.pem"), view_t(), sm2), keys::error_t::NONE);
		// Тело ECPrivateKey ключа SM2
		std::vector <uint8_t> record;
		// Собираем тело ECPrivateKey вручную: издание, скаляр, открытый ключ
		asn1::writer_t inner;
		// Открываем набор записи ключа
		inner.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи ключа
		inner.integer(1);
		// Записываем секретный скаляр
		inner.octets(view(sm2.d));
		// Открываем открытый ключ
		inner.open(asn1::cls_t::CONTEXT, 1);
		// Несжатая точка открытого ключа SM2
		std::vector <uint8_t> sm2point;
		// Заводим признак несжатой записи точки
		sm2point.push_back(0x04);
		// Дописываем первую координату
		sm2point.insert(sm2point.end(), sm2.x.begin(), sm2.x.end());
		// Дописываем вторую координату
		sm2point.insert(sm2point.end(), sm2.y.begin(), sm2.y.end());
		// Записываем несжатую точку
		inner.bits(view(sm2point));
		// Закрываем открытый ключ
		inner.close();
		// Закрываем набор записи ключа
		inner.close();
		// Запись PrivateKeyInfo с алгоритмом SM2
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(0);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма SM2
		writer.oid("1.2.156.10197.1.301");
		// Закрываем набор алгоритма
		writer.close();
		// Записываем тело ключа строкой байтов
		writer.octets(inner.data());
		// Закрываем набор записи
		writer.close();
		// Проверяем разбор записи с алгоритмом SM2
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::NONE);
		// Проверяем вид ключа
		ASSERT_EQ(key.kind, keys::kind_t::SM2);
		// Проверяем совпадение секретных частей
		ASSERT_EQ(key.d, sm2.d);
		// Запись с настройками алгоритма SM2: GB/T 32918 их не несёт
		asn1::writer_t present;
		// Открываем набор записи
		present.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		present.integer(0);
		// Открываем набор алгоритма
		present.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма SM2
		present.oid("1.2.156.10197.1.301");
		// Записываем пустые настройки
		present.nothing();
		// Закрываем набор алгоритма
		present.close();
		// Записываем тело ключа строкой байтов
		present.octets(inner.data());
		// Закрываем набор записи
		present.close();
		// Проверяем отказ разбора записи с настройками алгоритма SM2
		ASSERT_EQ(keys::decodePrivateKeyInfo(present.data(), key), keys::error_t::ALGORITHM);
	}
	{
		// Запись ключа ML-DSA-44 второго издания с открытым ключом, не согласованным с зерном
		keys::key_t mldsa;
		// Проверяем разбор секретного ключа ML-DSA-44
		ASSERT_EQ(keys::decode(corpus("mldsa44.pem"), view_t(), mldsa), keys::error_t::NONE);
		// Запись зерна из набора: читаем запись зерна из набора
		const std::vector <uint8_t> seedonly = body(corpus("mldsa/mldsa44-seed-only.pem"));
		// Проверяем наличие записи зерна
		ASSERT_FALSE(seedonly.empty());
		// Разборщик записи зерна
		asn1::reader_t scan(view(seedonly));
		// Элементы записи
		asn1::element_t sequence, version, algorithm, octets;
		// Проверяем разбор набора записи
		ASSERT_TRUE(scan.next(asn1::tag_t::SEQUENCE, sequence));
		// Разборщик содержимого набора
		asn1::reader_t fields = scan.enter(sequence);
		// Проверяем разбор издания записи
		ASSERT_TRUE(fields.next(asn1::tag_t::INTEGER, version));
		// Проверяем разбор набора алгоритма
		ASSERT_TRUE(fields.next(asn1::tag_t::SEQUENCE, algorithm));
		// Проверяем разбор строки байтов тела ключа
		ASSERT_TRUE(fields.next(asn1::tag_t::OCTET_STRING, octets));
		// Запись второго издания с открытым ключом
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(1);
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма
		writer.oid("2.16.840.1.101.3.4.3.17");
		// Закрываем набор алгоритма
		writer.close();
		// Записываем тело ключа строкой байтов
		writer.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::OCTET_STRING), octets.content);
		// Порченый открытый ключ
		std::vector <uint8_t> wrong = mldsa.key;
		// Портим первый байт открытого ключа
		wrong[0] ^= 0x01;
		// Строка битов порченого открытого ключа: нулевое число неиспользуемых разрядов и ключ
		std::vector <uint8_t> wrongbits;
		// Заводим нулевое число неиспользуемых разрядов
		wrongbits.push_back(0x00);
		// Дописываем порченый открытый ключ
		wrongbits.insert(wrongbits.end(), wrong.begin(), wrong.end());
		// Записываем порченый открытый ключ неявной меткой [1]
		writer.element(asn1::cls_t::CONTEXT, false, 1, view(wrongbits));
		// Закрываем набор записи
		writer.close();
		// Проверяем отказ разбора: открытый ключ не сошёлся с выведенным из зерна
		ASSERT_EQ(keys::decodePrivateKeyInfo(writer.data(), key), keys::error_t::VALUE);
	}
}

/**
 * @brief Проверка глубоких веток разбора мешков PKCS #12 и обёртки PFX
 *
 * @note Мешки собираются вручную: второй keyBag, неведомый вид, certBag не X.509,
 *       порча явных меток, EncryptedData не с данными и не с PBES2, предел оборотов
 *
 */
TEST(KeysTest, Pkcs12Deep){
	// Разобранный ключ донора
	keys::key_t donor;
	// Проверяем разбор донора
	ASSERT_EQ(keys::decodePrivateKeyInfo(view(bytes(corpus("ec256.der"))), donor), keys::error_t::NONE);
	// Запись PrivateKeyInfo донора
	std::vector <uint8_t> pki;
	// Проверяем запись PrivateKeyInfo донора
	ASSERT_EQ(keys::encodePrivateKeyInfo(donor, pki), keys::error_t::NONE);
	// Запись сертификата донора
	const std::vector <uint8_t> cert = bytes(corpus("ec256.crt.der"));
	// Проверяем наличие сертификата
	ASSERT_FALSE(cert.empty());
	// Запись EncryptedPrivateKeyInfo донора
	std::vector <uint8_t> epi;
	// Проверяем запись EncryptedPrivateKeyInfo донора
	ASSERT_EQ(keys::encodeEncryptedPrivateKeyInfo(donor, view("secret"), epi, 256, 1000), keys::error_t::NONE);
	// Сборка мешка SafeBag по виду и значению
	auto bag = [](const char * kind, const std::vector <uint8_t> & value){
		// Записываем мешок: опознаватель вида и явное значение [0]
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель вида
		writer.oid(kind);
		// Открываем явную метку [0]
		writer.open(asn1::cls_t::CONTEXT, 0);
		// Разборщик готового значения мешка
		asn1::reader_t reader(view(value));
		// Элемент готового значения мешка
		asn1::element_t element;
		// Разбираем метку и содержимое значения мешка
		reader.next(element);
		// Переносим значение мешка с его собственной меткой
		writer.element(element.cls, element.constructed, element.tag, element.content);
		// Закрываем набор записи
		writer.close();
		// Закрываем набор записи
		writer.close();
		// Выводим собранную запись
		return std::vector <uint8_t> (writer.data().data, writer.data().data + writer.data().size);
	};
	// Сборка сведений о содержимом по виду и телу
	auto content = [](const char * kind, const std::vector <uint8_t> & body, const bool octets = true){
		// Записываем сведения: опознаватель вида и явное тело
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель вида
		writer.oid(kind);
		// Открываем явную метку [0]
		writer.open(asn1::cls_t::CONTEXT, 0);
		// Если тело переносится строкой байтов
		if(octets)
			// Записываем тело строкой байтов
			writer.octets(view(body));
		// Иначе тело является готовой записью
		else {
			// Разборщик готового тела содержимого
			asn1::reader_t reader(view(body));
			// Элемент готового тела содержимого
			asn1::element_t element;
			// Разбираем метку и содержимое готового тела
			reader.next(element);
			// Переносим тело с его собственной меткой
			writer.element(element.cls, element.constructed, element.tag, element.content);
		}
		// Закрываем набор записи
		writer.close();
		// Закрываем набор записи
		writer.close();
		// Выводим собранную запись
		return std::vector <uint8_t> (writer.data().data, writer.data().data + writer.data().size);
	};
	// Сборка SafeContents из набора сведений о содержимом
	auto safe = [](const std::vector <std::vector <uint8_t>> & items){
		// Записываем набор сведений о содержимом мешков
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		/**
		 * Перебираем сведения о содержимом мешков
		 */
		for(const std::vector <uint8_t> & item : items){
			// Разборщик готовых сведений о содержимом
			asn1::reader_t reader(view(item));
			// Элемент готовых сведений о содержимом
			asn1::element_t element;
			// Разбираем метку и содержимое, чтобы не вложить набор повторно
			reader.next(element);
			// Переносим сведения о содержимом с их собственной меткой
			writer.element(element.cls, element.constructed, element.tag, element.content);
		}
		// Закрываем набор записи
		writer.close();
		// Выводим собранную запись
		return std::vector <uint8_t> (writer.data().data, writer.data().data + writer.data().size);
	};
	// Сборка записи PFX: издание 3, AuthenticatedSafe, необязательные MacData и хвост
	auto pfx = [](const std::vector <uint8_t> & safeBytes, const std::vector <uint8_t> & mac, const bool trailing){
		// Записываем PFX: издание, сведения о содержимом, мак если задан, хвост если порчен
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(3);
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель данных PKCS #7
		writer.oid("1.2.840.113549.1.7.1");
		// Открываем явную метку [0]
		writer.open(asn1::cls_t::CONTEXT, 0);
		// Записываем AuthenticatedSafe строкой байтов
		writer.octets(view(safeBytes));
		// Закрываем набор записи
		writer.close();
		// Закрываем набор записи
		writer.close();
		// Если имитовставка задана
		if(!mac.empty()){
			// Разборщик готовых сведений имитовставки
			asn1::reader_t reader(view(mac));
			// Элемент готовых сведений имитовставки
			asn1::element_t element;
			// Разбираем метку и содержимое, чтобы не вложить набор повторно
			reader.next(element);
			// Переносим сведения имитовставки с их собственной меткой
			writer.element(element.cls, element.constructed, element.tag, element.content);
		}
		// Если запись порчена хвостом
		if(trailing)
			// Дописываем лишний элемент хвоста
			writer.integer(1);
		// Закрываем набор записи
		writer.close();
		// Выводим собранную запись
		return std::vector <uint8_t> (writer.data().data, writer.data().data + writer.data().size);
	};
	// Сборка сведений имитовставки MacData
	auto macdata = [](const std::vector <uint8_t> & mac, const std::vector <uint8_t> & salt, const int64_t iterations, const bool extra){
		// Записываем MacData: DigestInfo, соль, обороты и лишний элемент если порчен
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель SHA-256
		writer.oid("2.16.840.1.101.3.4.2.1");
		// Закрываем набор записи
		writer.close();
		// Записываем имитовставку строкой байтов
		writer.octets(view(mac));
		// Закрываем набор записи
		writer.close();
		// Записываем соль строкой байтов
		writer.octets(view(salt));
		// Записываем число оборотов
		writer.integer(iterations);
		// Если сведения порчены хвостом
		if(extra)
			// Дописываем лишнюю строку байтов хвоста MacData
			writer.octets(view(salt));
		// Закрываем набор записи
		writer.close();
		// Выводим собранную запись
		return std::vector <uint8_t> (writer.data().data, writer.data().data + writer.data().size);
	};
	// Сборка EncryptedData с выбранными видом содержимого и схемой
	auto encrypted = [](const char * viewOid, const char * schemeOid, const std::vector <uint8_t> & body){
		// Записываем EncryptedData: издание, вид содержимого, алгоритм и шифртекст [0]
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание зашифрованного содержимого
		writer.integer(0);
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем вид содержимого
		writer.oid(viewOid);
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем схему защиты
		writer.oid(schemeOid);
		// Закрываем набор записи
		writer.close();
		// Открываем явную метку [0]
		writer.open(asn1::cls_t::CONTEXT, 0);
		// Записываем тело строкой байтов
		writer.octets(view(body));
		// Закрываем набор записи
		writer.close();
		// Закрываем набор записи
		writer.close();
		// Закрываем набор записи
		writer.close();
		// Выводим собранную запись
		return std::vector <uint8_t> (writer.data().data, writer.data().data + writer.data().size);
	};
	// Опознаватели видов мешков и содержимого
	// Опознаватель мешка keyBag
	const char * keybag = "1.2.840.113549.1.12.10.1.1";
	// Опознаватель мешка shroudedKeyBag
	const char * shrouded = "1.2.840.113549.1.12.10.1.2";
	// Опознаватель мешка certBag
	const char * certbag = "1.2.840.113549.1.12.10.1.3";
	// Опознаватель сертификата X.509
	const char * x509 = "1.2.840.113549.1.9.22.1";
	// Опознаватель данных PKCS #7
	const char * data = "1.2.840.113549.1.7.1";
	// Опознаватель зашифрованных данных PKCS #7
	const char * encryptedOid = "1.2.840.113549.1.7.6";
	// Опознаватель схемы PBES2
	const char * pbes2 = "1.2.840.113549.1.5.13";
	// Сборка сведений данных с одним мешком внутри SafeContents
	auto dataContent = [&](const std::vector <uint8_t> & value){
		// Оборачиваем мешок в набор SafeContents и кладём в сведения данных
		return content(data, safe({value}));
	};
	// Запись certBag годного вида: X.509 и строка байтов сертификата
	auto certbagValue = [&](const char * certOid, const std::vector <uint8_t> & record){
		// Записываем значение certBag: вид сертификата и явная строка байтов записи
		asn1::writer_t writer;
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем вид сертификата
		writer.oid(certOid);
		// Открываем явную метку [0]
		writer.open(asn1::cls_t::CONTEXT, 0);
		// Записываем сертификат строкой байтов
		writer.octets(view(record));
		// Закрываем набор записи
		writer.close();
		// Закрываем набор записи
		writer.close();
		// Выводим собранную запись
		return std::vector <uint8_t> (writer.data().data, writer.data().data + writer.data().size);
	};
	// Перевод просмотра записи в набор байтов
	auto toBytes = [](const view_t & data){
		// Выводим набор байтов просмотра
		return std::vector <uint8_t> (data.data, data.data + data.size);
	};
	// Разобранные ключ и цепочка для прогонов
	keys::key_t key;
	// Цепочка сертификатов
	std::vector <std::vector <uint8_t>> chain;
	{
		// Два мешка keyBag подряд: второй ключ записи недопустим
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(keybag, pki)), dataContent(bag(keybag, pki))}), {}, false);
		// Проверяем отказ устройства записи с двумя ключами
		ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::STRUCTURE);
	}
	{
		// Мешок keyBag с гнилым значением: вместо PrivateKeyInfo целое число
		asn1::writer_t wrong;
		// Записываем целое число
		wrong.integer(1);
		// Собираем запись с гнилым значением keyBag
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(keybag, toBytes(wrong.data())))}), {}, false);
		// Проверяем отказ разбора гнилого значения
		ASSERT_NE(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::NONE);
	}
	{
		// Мешок keyBag с пустым PrivateKeyInfo: набор пуст
		asn1::writer_t wrong;
		// Открываем набор записи
		wrong.open(asn1::tag_t::SEQUENCE);
		// Закрываем набор записи
		wrong.close();
		// Собираем запись с пустым PrivateKeyInfo
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(keybag, toBytes(wrong.data())))}), {}, false);
		// Проверяем отказ разбора пустого PrivateKeyInfo
		ASSERT_NE(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::NONE);
	}
	{
		// Мешок без явного значения [0]: опознаватель есть, значения нет
		asn1::writer_t wrong;
		// Открываем набор записи
		wrong.open(asn1::tag_t::SEQUENCE);
		// Записываем вид мешка keyBag
		wrong.oid(keybag);
		// Закрываем набор записи
		wrong.close();
		// Собираем запись с мешком без явного значения
		const std::vector <uint8_t> der = pfx(safe({dataContent(toBytes(wrong.data()))}), {}, false);
		// Проверяем отказ разбора мешка без явного значения
		ASSERT_NE(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::NONE);
	}
	{
		// Мешок с целым числом вместо опознавателя вида
		asn1::writer_t wrong;
		// Открываем набор записи
		wrong.open(asn1::tag_t::SEQUENCE);
		// Записываем целое число
		wrong.integer(1);
		// Закрываем набор записи
		wrong.close();
		// Собираем запись с гнилым опознавателем мешка
		const std::vector <uint8_t> der = pfx(safe({dataContent(toBytes(wrong.data()))}), {}, false);
		// Проверяем отказ разбора гнилого опознавателя
		ASSERT_NE(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::NONE);
	}
	{
		// Мешок certBag с видом не X.509
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(certbag, certbagValue("1.2.840.113549.1.9.22.2", cert)))}), {}, false);
		// Проверяем отказ устройства записи с чужим видом сертификата
		ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::STRUCTURE);
	}
	{
		// Мешок certBag без явной строки байтов сертификата: после вида нет [0]
		asn1::writer_t wrong;
		// Открываем набор записи
		wrong.open(asn1::tag_t::SEQUENCE);
		// Записываем вид сертификата X.509
		wrong.oid(x509);
		// Закрываем набор записи
		wrong.close();
		// Собираем запись с certBag без явной строки байтов
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(certbag, toBytes(wrong.data())))}), {}, false);
		// Проверяем отказ разбора certBag без явной строки байтов
		ASSERT_NE(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::NONE);
	}
	{
		// Мешок certBag с целым числом вместо строки байтов сертификата
		asn1::writer_t wrong;
		// Открываем набор записи
		wrong.open(asn1::tag_t::SEQUENCE);
		// Записываем вид сертификата X.509
		wrong.oid(x509);
		// Открываем явную метку [0]
		wrong.open(asn1::cls_t::CONTEXT, 0);
		// Записываем целое число
		wrong.integer(1);
		// Закрываем набор записи
		wrong.close();
		// Закрываем набор записи
		wrong.close();
		// Собираем запись с гнилой строкой байтов сертификата
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(certbag, toBytes(wrong.data())))}), {}, false);
		// Проверяем отказ разбора гнилой строкой байтов
		ASSERT_NE(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::NONE);
	}
	{
		// Мешок неведомого вида пропускается, годный keyBag читается
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag("1.2.840.113549.1.12.10.1.99", pki)), dataContent(bag(keybag, pki))}), {}, false);
		// Проверяем успешный разбор: неведомый мешок пропущен, ключ разобран
		ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::NONE);
	}
	{
		// Только certBag без keyBag: ключа записи нет
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(certbag, certbagValue(x509, cert)))}), {}, false);
		// Проверяем отказ пустой записи
		ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::EMPTY);
	}
	{
		// Мешок keyBag, затем shroudedKeyBag: второй ключ недопустим
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(keybag, pki)), dataContent(bag(shrouded, epi))}), {}, false);
		// Проверяем отказ устройства записи с двумя ключами разных видов
		ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::STRUCTURE);
	}
	{
		// Мешок shroudedKeyBag с гнилым значением: вместо EncryptedPrivateKeyInfo целое число
		asn1::writer_t wrong;
		// Записываем целое число
		wrong.integer(1);
		// Собираем запись с гнилым значением shroudedKeyBag
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(shrouded, toBytes(wrong.data())))}), {}, false);
		// Проверяем отказ разбора гнилого значения shroudedKeyBag
		ASSERT_NE(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::NONE);
	}
	{
		// Мешок shroudedKeyBag с пустым EncryptedPrivateKeyInfo: набор пуст
		asn1::writer_t wrong;
		// Открываем набор записи
		wrong.open(asn1::tag_t::SEQUENCE);
		// Закрываем набор записи
		wrong.close();
		// Собираем запись с пустым EncryptedPrivateKeyInfo
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(shrouded, toBytes(wrong.data())))}), {}, false);
		// Проверяем отказ разбора пустого EncryptedPrivateKeyInfo
		ASSERT_NE(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::NONE);
	}
	{
		// MacData с нулевым числом оборотов: схема не дозволена
		const std::vector <uint8_t> mac = macdata(std::vector <uint8_t> (32, 0), std::vector <uint8_t> (8, 0), 0, false);
		// Собираем запись с нулевым числом оборотов
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(keybag, pki))}), mac, false);
		// Проверяем отказ схемы по числу оборотов
		ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::CIPHER);
	}
	{
		// MacData с числом оборотов выше предела: схема не дозволена
		const std::vector <uint8_t> mac = macdata(std::vector <uint8_t> (32, 0), std::vector <uint8_t> (8, 0), 10000001, false);
		// Собираем запись с числом оборотов выше предела
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(keybag, pki))}), mac, false);
		// Проверяем отказ схемы по числу оборотов
		ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::CIPHER);
	}
	{
		// MacData с лишним элементом после оборотов: устройство записи не дозволено
		const std::vector <uint8_t> mac = macdata(std::vector <uint8_t> (32, 0), std::vector <uint8_t> (8, 0), 1000, true);
		// Собираем запись с лишним элементом MacData
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(keybag, pki))}), mac, false);
		// Проверяем отказ устройства записи
		ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::STRUCTURE);
	}
	{
		// Лишний элемент после MacData: устройство записи не дозволено
		const std::vector <uint8_t> mac = macdata(std::vector <uint8_t> (32, 0), std::vector <uint8_t> (8, 0), 1000, false);
		// Собираем запись с хвостом после MacData
		const std::vector <uint8_t> der = pfx(safe({dataContent(bag(keybag, pki))}), mac, true);
		// Проверяем отказ устройства записи
		ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::STRUCTURE);
	}
	{
		// Сведения о содержимом неведомого вида: не данные и не зашифрованные данные
		const std::vector <uint8_t> der = pfx(safe({content(pbes2, bag(keybag, pki))}), {}, false);
		// Проверяем отказ устройства записи с чужим видом содержимого
		ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::STRUCTURE);
	}
	{
		// EncryptedData с видом содержимого не данные: устройство записи не дозволено
		const std::vector <uint8_t> body = encrypted(pbes2, pbes2, std::vector <uint8_t> (16, 0));
		// Собираем запись с EncryptedData не с данными
		const std::vector <uint8_t> der = pfx(safe({content(encryptedOid, body, false)}), {}, false);
		// Проверяем отказ устройства записи
		ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::STRUCTURE);
	}
	{
		// EncryptedData со схемой не PBES2: схема не дозволена
		const std::vector <uint8_t> body = encrypted(data, data, std::vector <uint8_t> (16, 0));
		// Собираем запись с EncryptedData со схемой не PBES2
		const std::vector <uint8_t> der = pfx(safe({content(encryptedOid, body, false)}), {}, false);
		// Проверяем отказ схемы
		ASSERT_EQ(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::CIPHER);
	}
	{
		// AuthenticatedSafe не является набором: целое число вместо набора
		asn1::writer_t wrong;
		// Записываем целое число
		wrong.integer(1);
		// Собираем запись с AuthenticatedSafe не набором
		const std::vector <uint8_t> der = pfx(toBytes(wrong.data()), {}, false);
		// Проверяем отказ разбора AuthenticatedSafe не набором
		ASSERT_NE(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::NONE);
	}
	{
		// SafeContents с целым числом вместо сведений о содержимом: набор не читается
		asn1::writer_t wrong;
		// Записываем целое число
		wrong.integer(1);
		// Собираем запись с гнилыми сведениями о содержимом
		const std::vector <uint8_t> der = pfx(safe({toBytes(wrong.data())}), {}, false);
		// Проверяем отказ разбора гнилых сведений о содержимом
		ASSERT_NE(keys::decodePkcs12(view(der), view("secret"), key, chain), keys::error_t::NONE);
	}
}

/**
 * @brief Проверка веток выведения открытой части: несовпадение и восполнение
 *
 * @note Открытая часть специально портится либо убирается из записи: derive обязан
 *       ответить VALUE при несовпадении и NONE с восполнением при отсутствии
 *
 */
TEST(KeysTest, DeriveMismatch){
	// Сборка OneAsymmetricKey с необязательной открытой частью
	auto openKey = [](const keys::key_t & donor, const std::vector <uint8_t> & opened){
		// Опознаватель алгоритма ключа по RFC 8410
		const char * algorithm = nullptr;
		// Если записывается ключ Ed25519
		if(donor.kind == keys::kind_t::ED25519)
			// Устанавливаем опознаватель Ed25519
			algorithm = "1.3.101.112";
		// Если записывается ключ X25519
		else if(donor.kind == keys::kind_t::X25519)
			// Устанавливаем опознаватель X25519
			algorithm = "1.3.101.110";
		// Иначе записывается ключ Ed448
		else
			// Устанавливаем опознаватель Ed448
			algorithm = "1.3.101.113";
		// Записываем CurvePrivateKey: зерно во внутренней строке байтов
		asn1::writer_t body;
		// Записываем зерно донора
		body.octets(view(donor.d));
		// Содержимое неявной строки битов: нуль неиспользуемых разрядов и открытый ключ
		std::vector <uint8_t> bits(1, 0);
		// Дописываем открытый ключ после счётчика неиспользуемых разрядов
		bits.insert(bits.end(), opened.begin(), opened.end());
		// Записываем OneAsymmetricKey с открытой частью
		asn1::writer_t writer;
		// Открываем набор OneAsymmetricKey
		writer.open(asn1::tag_t::SEQUENCE);
		// Издание 1 обязательно при наличии поля publicKey, без него пишется издание 0
		writer.integer(opened.empty() ? 0 : 1);
		// Открываем набор AlgorithmIdentifier
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма без параметров
		writer.oid(algorithm);
		// Закрываем набор AlgorithmIdentifier
		writer.close();
		// Записываем CurvePrivateKey во внешней строке байтов
		writer.octets(body.data());
		// Если открытая часть записывается
		if(!opened.empty())
			// Записываем открытый ключ неявной строкой битов [1]
			writer.element(asn1::cls_t::CONTEXT, false, 1, view(bits));
		// Закрываем набор OneAsymmetricKey
		writer.close();
		// Выводим собранную запись
		return std::vector <uint8_t> (writer.data().data, writer.data().data + writer.data().size);
	};
	// Донор EC: открытая часть портится и убирается
	{
		// Разобранный ключ донора
		keys::key_t donor;
		// Проверяем разбор донора
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(bytes(corpus("ec256.der"))), donor), keys::error_t::NONE);
		// Ключ с другим скаляром и прежней годной точкой: выведенная точка не совпадёт с записанной
		keys::key_t mixed = donor;
		// Меняем младший разряд скаляра, сохраняя его в дозволенном диапазоне кривой
		mixed.d.back() ^= 1;
		// Запись с несовпадающей открытой частью
		std::vector <uint8_t> der;
		// Записываем ключ с порченой открытой частью
		ASSERT_EQ(keys::encodePrivateKeyInfo(mixed, der), keys::error_t::NONE);
		// Проверяем отказ: открытая часть не сошлась с выведенной
		keys::key_t key;
		// Проверяем отказ несовпадения открытой части
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), key), keys::error_t::VALUE);
		// Полная запись донора, из которой убирается необязательная открытая точка
		std::vector <uint8_t> full;
		// Записываем донора перед удалением поля publicKey
		ASSERT_EQ(keys::encodePrivateKeyInfo(donor, full), keys::error_t::NONE);
		// Разборщик верхней записи PrivateKeyInfo
		asn1::reader_t top(view(full));
		// Верхний набор PrivateKeyInfo
		asn1::element_t pki;
		// Разбираем верхний набор PrivateKeyInfo
		ASSERT_TRUE(top.next(asn1::tag_t::SEQUENCE, pki));
		// Разборщик полей PrivateKeyInfo
		asn1::reader_t fields(pki.content);
		// Поля PrivateKeyInfo, которые переносятся без изменений
		asn1::element_t version, algorithm, secret;
		// Разбираем издание PrivateKeyInfo
		ASSERT_TRUE(fields.next(asn1::tag_t::INTEGER, version));
		// Разбираем алгоритм PrivateKeyInfo
		ASSERT_TRUE(fields.next(asn1::tag_t::SEQUENCE, algorithm));
		// Разбираем секретную запись ECPrivateKey
		ASSERT_TRUE(fields.next(asn1::tag_t::OCTET_STRING, secret));
		// Разборщик записи ECPrivateKey
		asn1::reader_t embedded(secret.content);
		// Набор записи ECPrivateKey
		asn1::element_t eckey;
		// Разбираем набор ECPrivateKey
		ASSERT_TRUE(embedded.next(asn1::tag_t::SEQUENCE, eckey));
		// Записываем ECPrivateKey без необязательного поля publicKey
		asn1::writer_t shortened;
		// Открываем набор ECPrivateKey
		shortened.open(asn1::tag_t::SEQUENCE);
		// Разборщик полей ECPrivateKey
		asn1::reader_t inner(eckey.content);
		// Признак удалённого поля publicKey
		bool stripped = false;
		/**
		 * Перебираем поля ECPrivateKey
		 */
		while(!inner.empty()){
			// Очередное поле ECPrivateKey
			asn1::element_t element;
			// Разбираем очередное поле ECPrivateKey
			ASSERT_TRUE(inner.next(element));
			// Если встретилось необязательное поле publicKey
			if((element.cls == asn1::cls_t::CONTEXT) && (element.tag == 1)){
				// Отмечаем удаление открытой точки
				stripped = true;
				// Пропускаем поле publicKey, остальные поля сохраняем
				continue;
			}
			// Переносим поле с его собственной меткой
			shortened.element(element.cls, element.constructed, element.tag, element.content);
		}
		// Проверяем, что донор действительно нёс открытую точку
		ASSERT_TRUE(stripped);
		// Закрываем укороченный набор ECPrivateKey
		shortened.close();
		// Запись PrivateKeyInfo без открытой части
		std::vector <uint8_t> open;
		// Записываем PrivateKeyInfo с укороченным ECPrivateKey
		asn1::writer_t writer;
		// Открываем набор PrivateKeyInfo
		writer.open(asn1::tag_t::SEQUENCE);
		// Переносим издание записи
		writer.element(version.cls, version.constructed, version.tag, version.content);
		// Переносим алгоритм записи
		writer.element(algorithm.cls, algorithm.constructed, algorithm.tag, algorithm.content);
		// Записываем укороченный ECPrivateKey строкой байтов
		writer.octets(shortened.data());
		// Закрываем набор PrivateKeyInfo
		writer.close();
		// Переносим собранную запись в набор байтов
		open.assign(writer.data().data, writer.data().data + writer.data().size);
		// Проверяем успешный разбор с восполнением открытой части
		// Проверяем успешное восполнение открытой части
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(open), key), keys::error_t::NONE);
		// Проверяем, что открытая часть восполнена
		ASSERT_FALSE(key.x.empty());
		// Проверяем восполнение координаты y
		ASSERT_FALSE(key.y.empty());
	}
	// Доноры Ed25519 и X25519: открытый ключ портится и убирается
	/**
	 * Перебираем доноров Ed25519 и X25519
	 */
	for(const char * name : {"ed25519", "x25519"}){
		// Разобранный ключ донора
		keys::key_t donor;
		// Проверяем разбор донора
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(bytes(corpus(std::string(name) + ".der"))), donor), keys::error_t::NONE) << name;
		// Открытый ключ с нулевыми байтами: заведомо не совпадает с выведенным
		keys::key_t mixed = donor;
		// Обнуляем открытый ключ
		mixed.key.assign(donor.key.size(), 0);
		// Запись OneAsymmetricKey с несовпадающим открытым ключом
		const std::vector <uint8_t> der = openKey(donor, mixed.key);
		// Проверяем отказ: открытый ключ не сошёлся с выведенным
		keys::key_t key;
		// Проверяем отказ несовпадения открытой части
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), key), keys::error_t::VALUE) << name;
		// Запись без открытого ключа: derive восполняет его из зерна
		const std::vector <uint8_t> open = openKey(donor, {});
		// Проверяем успешный разбор с восполнением открытого ключа
		// Проверяем успешное восполнение открытой части
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(open), key), keys::error_t::NONE) << name;
		// Проверяем, что открытый ключ восполнен
		// Проверяем восполнение открытого ключа
		ASSERT_FALSE(key.key.empty()) << name;
	}
	// Донор Ed448: открытый ключ портится и убирается
	{
		// Разобранный ключ донора
		keys::key_t donor;
		// Проверяем разбор донора
		ASSERT_EQ(keys::decode(corpus("ed448.key"), view_t(), donor), keys::error_t::NONE);
		// Открытый ключ с нулевыми байтами: заведомо не совпадает с выведенным
		keys::key_t mixed = donor;
		// Обнуляем открытый ключ
		mixed.key.assign(donor.key.size(), 0);
		// Запись OneAsymmetricKey с несовпадающим открытым ключом
		const std::vector <uint8_t> der = openKey(donor, mixed.key);
		// Проверяем отказ: открытый ключ не сошёлся с выведенным
		keys::key_t key;
		// Проверяем отказ несовпадения открытой части
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(der), key), keys::error_t::VALUE);
		// Запись без открытого ключа: derive восполняет его из зерна
		const std::vector <uint8_t> open = openKey(donor, {});
		// Проверяем успешный разбор с восполнением открытого ключа
		// Проверяем успешное восполнение открытой части
		ASSERT_EQ(keys::decodePrivateKeyInfo(view(open), key), keys::error_t::NONE);
		// Проверяем, что открытый ключ восполнен
		// Проверяем восполнение открытого ключа
		ASSERT_FALSE(key.key.empty());
	}
}

/**
 * @brief Проверка разборщиков ключей на обрезках и порче каждого байта записей
 *
 */
TEST(KeysTest, DeepRefusals){
	// Проверка обрезков и побайтовых мутаций записи переданным разборщиком
	auto refuse = [](const std::vector <uint8_t> & record, auto && decode){
		/**
		 * Перебираем строго укороченные формы записи
		 */
		for(size_t cut = 0; cut < record.size(); cut++)
			// Обрезанная запись обязана быть отвергнута
			ASSERT_NE(decode(view_t(record.data(), cut)), keys::error_t::NONE) << "Обрезка: " << cut;
		// Число отвергнутых порченых форм
		size_t rejected = 0;
		/**
		 * Перебираем байты записи, сохраняя её длину
		 */
		for(size_t at = 0; at < record.size(); at++){
			// Порченая запись с изменённым байтом
			std::vector <uint8_t> damaged = record;
			// Переворачиваем очередной байт
			damaged[at] ^= 0xFF;
			// Учитываем отвергнутую порченую форму
			if(decode(view(damaged)) != keys::error_t::NONE)
				// Увеличиваем число отказов
				rejected++;
		}
		// Хотя бы часть порченых форм обязана быть отвергнута
		ASSERT_GT(rejected, static_cast <size_t> (0));
	};
	// Разобранный ключ и цепочка сертификатов
	keys::key_t key;
	// Цепочка сертификатов PKCS #12
	std::vector <std::vector <uint8_t>> chain;
	// Разборщик PrivateKeyInfo
	auto secret = [&](const view_t & data){
		// Выводим итог разбора PrivateKeyInfo
		return keys::decodePrivateKeyInfo(data, key);
	};
	// Разборщик SubjectPublicKeyInfo
	auto opened = [&](const view_t & data){
		// Выводим итог разбора SubjectPublicKeyInfo
		return keys::decodeSubjectPublicKeyInfo(data, key);
	};
	/**
	 * Перебираем ключи набора
	 */
	for(const entry_t & entry : ENTRIES){
		// Проверяем обрезки и мутации секретного ключа
		refuse(bytes(corpus(std::string(entry.name) + ".der")), secret);
		// Проверяем обрезки и мутации открытого ключа
		refuse(bytes(corpus(std::string(entry.name) + ".pub.der")), opened);
	}
	// Проверяем обрезки и мутации секретного ключа Ed448
	refuse(body(corpus("ed448.key")), secret);
	// Секретный ключ Ed448 для записи открытой части
	keys::key_t ed448;
	// Разбираем секретный ключ Ed448
	ASSERT_EQ(keys::decode(corpus("ed448.key"), view_t(), ed448), keys::error_t::NONE);
	// Запись SubjectPublicKeyInfo Ed448
	std::vector <uint8_t> spki;
	// Записываем открытый ключ Ed448
	ASSERT_EQ(keys::encodeSubjectPublicKeyInfo(ed448, spki), keys::error_t::NONE);
	// Проверяем обрезки и мутации открытого ключа Ed448
	refuse(spki, opened);
	// Разборщик PKCS #12
	auto pkcs12 = [&](const view_t & data){
		// Выводим итог разбора PKCS #12
		return keys::decodePkcs12(data, view("secret"), key, chain);
	};
	// Проверяем обрезки и мутации записи PKCS #12
	refuse(bytes(corpus("test.p12")), pkcs12);
}
