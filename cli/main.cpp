/**
 * @file main.cpp
 * @date 2026-11-19
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
 * @brief Точка входа консольной утилиты a-nts — аналога OpenSSL на библиотеке A-NTS
 *
 * @details Утилита повторяет устройство командной строки OpenSSL: первым параметром
 *          идёт имя подкоманды, дальше её флаги; данные принимаются из файла либо со
 *          стандартного ввода, итог пишется в файл либо на стандартный вывод
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstdlib>
#include <cstring>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include "common.hpp"
#include "enc.hpp"
#include "keys.hpp"
#include "x509.hpp"
#include "digest/hash.hpp"
#include "digest/hmac.hpp"
#include "codec/base64.hpp"
#include "entropy/entropy.hpp"
#include "sys/version.hpp"

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён модуля
	 */
	using namespace nts::cli;

	/**
	 * @brief Функция печати справки утилиты
	 *
	 */
	void __nts_usage__() noexcept {
		// Печатаем перечень подкоманд утилиты
		cout << "A-NTS: аналог OpenSSL на библиотеке A-NTS" << endl;
		// Печатаем назначение утилиты
		cout << "применение: a-nts команда [флаги] [параметры]" << endl;
		// Печатаем список подкоманд
		cout << "команды: version, rand, base64, dgst, enc, genpkey, genrsa, genec, pkey, rsa, ec, req, x509, ca, crl, pkcs12" << endl;
	}

	/**
	 * @brief Функция печати издания библиотеки
	 *
	 * @param argc длина списка параметров
	 * @param argv список параметров
	 * @return     код выхода из команды
	 *
	 */
	int __nts_version__(const int argc, const char * const argv[]) noexcept {
		// Не используем параметры команды
		(void) argc;
		// Не используем параметры команды
		(void) argv;
		// Печатаем название и издание библиотеки
		cout << "A-NTS " << sys::version() << endl;
		// Сообщаем об успешности команды
		return EXIT_SUCCESS;
	}

	/**
	 * @brief Функция выработки случайных байтов
	 *
	 * @param argc длина списка параметров
	 * @param argv список параметров
	 * @return     код выхода из команды
	 *
	 */
	int __nts_rand__(const int argc, const char * const argv[]) noexcept {
		// Число вырабатываемых байтов
		size_t count = 0;
		/**
		 * Перебираем параметры команды в поисках числа байтов
		 */
		for(int i = 2; i < argc; i++){
			// Если очередной параметр является флагом
			if(argv[i][0] == '-'){
				// Если флаг несёт значение, пропускаем и его значение
				if(::strcmp(argv[i], "-out") == 0)
					// Пропускаем значение флага
					i++;
				// Переходим к следующему параметру
				continue;
			}
			// Запоминаем число вырабатываемых байтов
			count = static_cast <size_t> (::strtoul(argv[i], nullptr, 10));
			// Прерываем перебор
			break;
		}
		// Если число байтов не задано
		if(count == 0){
			// Печатаем подсказку команды
			cout << "применение: a-nts rand [-hex] [-out файл] число" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Область выработанных байтов
		vector <uint8_t> bytes(count);
		// Если случайные байты выработать не удалось
		if(!entropy::bytes(bytes.data(), bytes.size())){
			// Печатаем сообщение об отказе выработки
			cout << "Выработать случайные байты не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Признак шестнадцатеричного вывода
		const bool hexOut = flag(argc, argv, "-hex");
		// Имя файла вывода
		const char * out = value(argc, argv, "-out");
		// Если вывод шестнадцатеричный
		if(hexOut){
			// Шестнадцатеричная строка байтов
			const string text = hex(bytes.data(), bytes.size());
			// Если записать строку не удалось
			if(!writeBytes(out, reinterpret_cast <const uint8_t *> (text.data()), text.size())){
				// Печатаем сообщение об отказе записи
				cout << "Записать случайные байты не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Если вывод шёл на стандартный вывод, дописываем перевод строки
			if((out == nullptr) || (out[0] == '\0'))
				// Дописываем перевод строки
				cout << endl;
		// Иначе выводим байты как есть
		} else if(!writeBytes(out, bytes.data(), bytes.size())){
			// Печатаем сообщение об отказе записи
			cout << "Записать случайные байты не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Сообщаем об успешности команды
		return EXIT_SUCCESS;
	}

	/**
	 * @brief Функция перевода строки в кодирование base64
	 *
	 * @param argc длина списка параметров
	 * @param argv список параметров
	 * @return     код выхода из команды
	 *
	 */
	int __nts_base64__(const int argc, const char * const argv[]) noexcept {
		// Признак раскодирования
		const bool decode = flag(argc, argv, "-d");
		// Признак вывода одной строкой
		const bool single = flag(argc, argv, "-A");
		// Имя файла ввода
		const char * in = value(argc, argv, "-in");
		// Имя файла вывода
		const char * out = value(argc, argv, "-out");
		// Область прочитанных байтов
		vector <uint8_t> bytes;
		// Если ввод прочитать не удалось
		if(!readBytes(in, bytes)){
			// Печатаем сообщение об отказе чтения
			cout << "Прочитать ввод не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Если запрошено раскодирование
		if(decode){
			// Область раскодированных байтов
			vector <uint8_t> plain;
			// Если текст раскодировать не удалось
			if(!codec::decode(view_t(bytes.data(), bytes.size()), plain, codec::alphabet_t::STANDARD, true)){
				// Печатаем сообщение об отказе раскодирования
				cout << "Раскодировать base64 не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Если вывод записать не удалось
			if(!writeBytes(out, plain.data(), plain.size())){
				// Печатаем сообщение об отказе записи
				cout << "Записать итог не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
		// Иначе запрошено кодирование
		} else {
			// Строка кодирования
			string text;
			// Если область закодировать не удалось
			if(!codec::encode(view_t(bytes.data(), bytes.size()), text)){
				// Печатаем сообщение об отказе кодирования
				cout << "Закодировать в base64 не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Если вывод идёт на стандартный вывод либо файл и требуется разбиение строк
			if(!single){
				// Строка с разбиением на строки по шестьдесят четыре знака
				string wrapped;
				/**
				 * Разбиваем кодированный текст на строки
				 */
				for(size_t i = 0; i < text.size(); i += 64){
					// Приписываем очередную строку
					wrapped.append(text, i, 64);
					// Дописываем перевод строки
					wrapped.push_back('\n');
				}
				// Заменяем текст разбитым
				text = wrapped;
			}
			// Если вывод записать не удалось
			if(!writeBytes(out, reinterpret_cast <const uint8_t *> (text.data()), text.size())){
				// Печатаем сообщение об отказе записи
				cout << "Записать итог не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
		}
		// Сообщаем об успешности команды
		return EXIT_SUCCESS;
	}

	/**
	 * @brief Функция подбора алгоритма хеширования по флагу командной строки
	 *
	 * @param argc длина списка параметров
	 * @param argv список параметров
	 * @return     алгоритм хеширования, SHA-256 по умолчанию
	 *
	 */
	digest::hash_t __nts_digest_kind__(const int argc, const char * const argv[]) noexcept {
		// Если запрошен MD5
		if(flag(argc, argv, "-md5"))
			// Выводим алгоритм MD5
			return digest::hash_t::MD5;
		// Если запрошен SHA-1
		if(flag(argc, argv, "-sha1"))
			// Выводим алгоритм SHA-1
			return digest::hash_t::SHA1;
		// Если запрошен SHA-224
		if(flag(argc, argv, "-sha224"))
			// Выводим алгоритм SHA-224
			return digest::hash_t::SHA224;
		// Если запрошен SHA-384
		if(flag(argc, argv, "-sha384"))
			// Выводим алгоритм SHA-384
			return digest::hash_t::SHA384;
		// Если запрошен SHA-512
		if(flag(argc, argv, "-sha512"))
			// Выводим алгоритм SHA-512
			return digest::hash_t::SHA512;
		// Если запрошен SM3
		if(flag(argc, argv, "-sm3"))
			// Выводим алгоритм SM3
			return digest::hash_t::SM3;
		// Если запрошен RIPEMD-160
		if(flag(argc, argv, "-ripemd160"))
			// Выводим алгоритм RIPEMD-160
			return digest::hash_t::RIPEMD160;
		// Если запрошен BLAKE2s
		if(flag(argc, argv, "-blake2s256"))
			// Выводим алгоритм BLAKE2s
			return digest::hash_t::BLAKE2S256;
		// Если запрошен BLAKE2b
		if(flag(argc, argv, "-blake2b512"))
			// Выводим алгоритм BLAKE2b
			return digest::hash_t::BLAKE2B512;
		// Если запрошен «Стрибог» 256
		if(flag(argc, argv, "-streebog256"))
			// Выводим алгоритм «Стрибог» 256
			return digest::hash_t::STREEBOG256;
		// Если запрошен «Стрибог» 512
		if(flag(argc, argv, "-streebog512"))
			// Выводим алгоритм «Стрибог» 512
			return digest::hash_t::STREEBOG512;
		// Выводим алгоритм по умолчанию SHA-256
		return digest::hash_t::SHA256;
	}

	/**
	 * @brief Функция получения имени алгоритма хеширования
	 *
	 * @param algorithm алгоритм хеширования
	 * @return          имя алгоритма заглавными буквами
	 *
	 */
	const char * __nts_digest_name__(const digest::hash_t algorithm) noexcept {
		/**
		 * Подбираем имя по значению алгоритма
		 */
		switch(static_cast <uint8_t> (algorithm)){
			// MD5 по RFC 1321
			case static_cast <uint8_t> (digest::hash_t::MD5): return "MD5";
			// SHA-1 по FIPS 180-4
			case static_cast <uint8_t> (digest::hash_t::SHA1): return "SHA1";
			// SHA-224 по FIPS 180-4
			case static_cast <uint8_t> (digest::hash_t::SHA224): return "SHA224";
			// SHA-384 по FIPS 180-4
			case static_cast <uint8_t> (digest::hash_t::SHA384): return "SHA384";
			// SHA-512 по FIPS 180-4
			case static_cast <uint8_t> (digest::hash_t::SHA512): return "SHA512";
			// SM3 по GB/T 32905-2016
			case static_cast <uint8_t> (digest::hash_t::SM3): return "SM3";
			// RIPEMD-160
			case static_cast <uint8_t> (digest::hash_t::RIPEMD160): return "RIPEMD160";
			// BLAKE2s по RFC 7693
			case static_cast <uint8_t> (digest::hash_t::BLAKE2S256): return "BLAKE2S256";
			// BLAKE2b по RFC 7693
			case static_cast <uint8_t> (digest::hash_t::BLAKE2B512): return "BLAKE2B512";
			// «Стрибог» 256
			case static_cast <uint8_t> (digest::hash_t::STREEBOG256): return "STREEBOG256";
			// «Стрибог» 512
			case static_cast <uint8_t> (digest::hash_t::STREEBOG512): return "STREEBOG512";
			// Прочие алгоритмы
			default: return "SHA256";
		}
	}

	/**
	 * @brief Функция вывода хеша области байтов
	 *
	 * @param algorithm алгоритм хеширования
	 * @param key       ключ имитовставки, пустой для простого хеша
	 * @param label     подпись выводимого хеша
	 * @param data      хешируемая область байтов
	 * @return          признак успешности вывода
	 *
	 */
	bool __nts_digest_print__(const digest::hash_t algorithm, const char * key, const char * label, const vector <uint8_t> & data) noexcept {
		// Длина хеша алгоритма
		const size_t size = digest::length(algorithm);
		// Если длина хеша не задана
		if(size == 0)
			// Сообщаем об отказе вывода
			return false;
		// Область выработанного хеша
		vector <uint8_t> result(size);
		// Признак успешности выработки
		bool ok = false;
		// Если задан ключ имитовставки
		if((key != nullptr) && (key[0] != '\0'))
			// Вырабатываем имитовставку области байтов
			ok = digest::hmac(algorithm, view_t(reinterpret_cast <const uint8_t *> (key), ::strlen(key)), view_t(data.data(), data.size()), result.data(), result.size());
		// Иначе вырабатываем простой хеш
		else ok = digest::hash(algorithm, view_t(data.data(), data.size()), result.data(), result.size());
		// Если хеш выработать не удалось
		if(!ok)
			// Сообщаем об отказе вывода
			return false;
		// Если подпись задана
		if((label != nullptr) && (label[0] != '\0'))
			// Печатаем подпись перед хешем
			cout << __nts_digest_name__(algorithm) << "(" << label << ")= ";
		// Печатаем шестнадцатеричный хеш
		cout << hex(result.data(), result.size()) << endl;
		// Сообщаем об успешности вывода
		return true;
	}

	/**
	 * @brief Функция выработки хешей сообщений
	 *
	 * @param argc длина списка параметров
	 * @param argv список параметров
	 * @return     код выхода из команды
	 *
	 */
	int __nts_dgst__(const int argc, const char * const argv[]) noexcept {
		// Алгоритм хеширования
		const digest::hash_t algorithm = __nts_digest_kind__(argc, argv);
		// Ключ имитовставки
		const char * key = value(argc, argv, "-hmac");
		// Признак наличия файлов в параметрах
		bool hasFiles = false;
		/**
		 * Перебираем параметры команды
		 */
		for(int i = 2; i < argc; i++){
			// Если очередной параметр является флагом
			if(argv[i][0] == '-'){
				// Если флаг несёт значение, пропускаем и его значение
				if(::strcmp(argv[i], "-hmac") == 0)
					// Пропускаем значение флага
					i++;
				// Переходим к следующему параметру
				continue;
			}
			// Отмечаем, что файлы в параметрах есть
			hasFiles = true;
			// Область прочитанного файла
			vector <uint8_t> data;
			// Если файл прочитать не удалось
			if(!readBytes(argv[i], data)){
				// Печатаем сообщение об отказе чтения файла
				cout << "Прочитать файл " << argv[i] << " не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Если хеш вывести не удалось
			if(!__nts_digest_print__(algorithm, key, argv[i], data)){
				// Печатаем сообщение об отказе выработки хеша
				cout << "Выработать хеш не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
		}
		// Если файлы в параметрах не заданы, читаем стандартный ввод
		if(!hasFiles){
			// Область прочитанного ввода
			vector <uint8_t> data;
			// Если ввод прочитать не удалось
			if(!readBytes(nullptr, data)){
				// Печатаем сообщение об отказе чтения
				cout << "Прочитать ввод не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Если хеш вывести не удалось
			if(!__nts_digest_print__(algorithm, key, nullptr, data)){
				// Печатаем сообщение об отказе выработки хеша
				cout << "Выработать хеш не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
		}
		// Сообщаем об успешности команды
		return EXIT_SUCCESS;
	}
}

/**
 * @brief Функция запуска приложения
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из приложения
 *
 */
int main(const int argc, const char * const argv[]) noexcept {
	// Если имя подкоманды не задано
	if(argc < 2){
		// Печатаем справку утилиты
		__nts_usage__();
		// Сообщаем об отказе приложения
		return EXIT_FAILURE;
	}
	// Если запрошено издание библиотеки
	if(::strcmp(argv[1], "version") == 0)
		// Выводим издание библиотеки
		return __nts_version__(argc, argv);
	// Если запрошена выработка случайных байтов
	if(::strcmp(argv[1], "rand") == 0)
		// Вырабатываем случайные байты
		return __nts_rand__(argc, argv);
	// Если запрошено кодирование base64
	if(::strcmp(argv[1], "base64") == 0)
		// Кодируем либо раскодируем base64
		return __nts_base64__(argc, argv);
	// Если запрошена выработка хешей
	if(::strcmp(argv[1], "dgst") == 0)
		// Вырабатываем хеши сообщений
		return __nts_dgst__(argc, argv);
	// Если запрошено зашифрование либо расшифрование
	if(::strcmp(argv[1], "enc") == 0)
		// Зашифровываем либо расшифровываем данные
		return cli::enc(argc, argv);
	// Если запрошена универсальная выработка ключа
	if(::strcmp(argv[1], "genpkey") == 0)
		// Вырабатываем ключ
		return cli::genpkey(argc, argv);
	// Если запрошена выработка ключа RSA
	if(::strcmp(argv[1], "genrsa") == 0)
		// Вырабатываем ключ RSA
		return cli::genrsa(argc, argv);
	// Если запрошена выработка ключа EC
	if(::strcmp(argv[1], "genec") == 0)
		// Вырабатываем ключ EC
		return cli::genec(argc, argv);
	// Если запрошены действия над ключом
	if(::strcmp(argv[1], "pkey") == 0)
		// Преобразуем ключ
		return cli::pkey(argc, argv);
	// Если запрошены действия над ключом RSA
	if(::strcmp(argv[1], "rsa") == 0)
		// Преобразуем ключ RSA
		return cli::rsa(argc, argv);
	// Если запрошены действия над ключом EC
	if(::strcmp(argv[1], "ec") == 0)
		// Преобразуем ключ EC
		return cli::ecKey(argc, argv);
	// Если запрошено создание запроса на сертификат
	if(::strcmp(argv[1], "req") == 0)
		// Создаём запрос на сертификат
		return cli::req(argc, argv);
	// Если запрошены действия над сертификатом
	if(::strcmp(argv[1], "x509") == 0)
		// Преобразуем сертификат
		return cli::x509(argc, argv);
	// Если запрошен выпуск сертификата центром
	if(::strcmp(argv[1], "ca") == 0)
		// Выпускаем сертификат центром
		return cli::issueCa(argc, argv);
	// Если запрошены действия над списком отзыва
	if(::strcmp(argv[1], "crl") == 0)
		// Преобразуем список отзыва
		return cli::crl(argc, argv);
	// Если запрошены действия над контейнером PKCS #12
	if(::strcmp(argv[1], "pkcs12") == 0)
		// Преобразуем контейнер PKCS #12
		return cli::pkcs12(argc, argv);
	// Печатаем справку утилиты
	__nts_usage__();
	// Сообщаем об отказе приложения
	return EXIT_FAILURE;
}
