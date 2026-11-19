/**
 * @file keys.cpp
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
 * @brief Команды ключей консольной утилиты a-nts — выработка и действия над ключами
 *
 * @details Команды повторяют устройство openssl: genpkey, genrsa, genec, pkey, rsa и ec.
 *          Ключ вырабатывается примитивами подписи (rsa_t, ecdsa_t, ed25519_t, ed448_t),
 *          записывается и разбирается кодеком keys в обёртку PEM байт в байт с openssl:
 *          PrivateKeyInfo под меткой PRIVATE KEY, SubjectPublicKeyInfo под меткой
 *          PUBLIC KEY, зашифрованная запись PBES2 под меткой ENCRYPTED PRIVATE KEY
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
#include "keys.hpp"
#include "sys/wipe.hpp"
#include "keys/keys.hpp"
#include "pem/pem.hpp"
#include "sign/rsa.hpp"
#include "sign/ecdsa.hpp"
#include "sign/ed25519.hpp"
#include "sign/ed448.hpp"
#include "curve/parameters.hpp"

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
	 * @brief Функция получения опознавателя кривой по имени openssl
	 *
	 * @param name имя кривой openssl
	 * @return     опознаватель кривой через точку, пустой у неизвестной
	 *
	 */
	const char * __nts_curve_oid__(const char * name) noexcept {
		// Если имя кривой не задано
		if(name == nullptr)
			// Опознавателя нет
			return "";
		// Имя кривой P-256
		if((::strcmp(name, "P-256") == 0) || (::strcmp(name, "prime256v1") == 0) || (::strcmp(name, "secp256r1") == 0))
			// Опознаватель P-256
			return "1.2.840.10045.3.1.7";
		// Имя кривой P-384
		if((::strcmp(name, "P-384") == 0) || (::strcmp(name, "secp384r1") == 0))
			// Опознаватель P-384
			return "1.3.132.0.34";
		// Имя кривой P-521
		if((::strcmp(name, "P-521") == 0) || (::strcmp(name, "secp521r1") == 0))
			// Опознаватель P-521
			return "1.3.132.0.35";
		// Имя кривой curveSM2
		if(::strcmp(name, "SM2") == 0)
			// Опознаватель curveSM2
			return "1.2.156.10197.1.301";
		// Опознавателя нет
		return "";
	}

	/**
	 * @brief Функция выработки ключа RSA
	 *
	 * @param bits   количество разрядов модуля
	 * @param result ключ, в который помещается итог выработки
	 * @return       признак успешности выработки ключа
	 *
	 */
	bool __nts_make_rsa__(const size_t bits, keys::key_t & result) noexcept {
		// Примитив RSA, вырабатывающий ключевую пару
		sign::rsa_t rsa;
		// Если ключевую пару выработать не удалось
		if(!rsa.generate(bits))
			// Выводим отказ выработки
			return false;
		// Вид ключа
		result.kind = keys::kind_t::RSA;
		// Размер модуля
		const size_t modulusSize = rsa.length(sign::part_t::MODULUS);
		// Размер открытого показателя
		const size_t publicSize = rsa.length(sign::part_t::PUBLIC);
		// Размер секретного показателя
		const size_t secretSize = rsa.length(sign::part_t::SECRET);
		// Размер первого сомножителя
		const size_t prime1Size = rsa.length(sign::part_t::PRIME1);
		// Размер второго сомножителя
		const size_t prime2Size = rsa.length(sign::part_t::PRIME2);
		// Размер первого показателя
		const size_t exponent1Size = rsa.length(sign::part_t::EXPONENT1);
		// Размер второго показателя
		const size_t exponent2Size = rsa.length(sign::part_t::EXPONENT2);
		// Размер коэффициента
		const size_t coefficientSize = rsa.length(sign::part_t::COEFFICIENT);
		// Отводим места под составляющие ключа
		result.n.assign(modulusSize, 0);
		// Отводим места под составляющие ключа
		result.e.assign(publicSize, 0);
		// Отводим места под составляющие ключа
		result.d.assign(secretSize, 0);
		// Отводим места под составляющие ключа
		result.p.assign(prime1Size, 0);
		// Отводим места под составляющие ключа
		result.q.assign(prime2Size, 0);
		// Отводим места под составляющие ключа
		result.dP.assign(exponent1Size, 0);
		// Отводим места под составляющие ключа
		result.dQ.assign(exponent2Size, 0);
		// Отводим места под составляющие ключа
		result.qInv.assign(coefficientSize, 0);
		// Если составляющие ключа снять не удалось
		if(!rsa.part(sign::part_t::MODULUS, result.n.data(), result.n.size()) || !rsa.part(sign::part_t::PUBLIC, result.e.data(), result.e.size()) || !rsa.part(sign::part_t::SECRET, result.d.data(), result.d.size()) || !rsa.part(sign::part_t::PRIME1, result.p.data(), result.p.size()) || !rsa.part(sign::part_t::PRIME2, result.q.data(), result.q.size()) || !rsa.part(sign::part_t::EXPONENT1, result.dP.data(), result.dP.size()) || !rsa.part(sign::part_t::EXPONENT2, result.dQ.data(), result.dQ.size()) || !rsa.part(sign::part_t::COEFFICIENT, result.qInv.data(), result.qInv.size()))
			// Выводим отказ снятия составляющих
			return false;
		// Выводим успешность выработки
		return true;
	}

	/**
	 * @brief Функция выработки ключа EC
	 *
	 * @param oid    опознаватель кривой через точку
	 * @param result ключ, в который помещается итог выработки
	 * @return       признак успешности выработки ключа
	 *
	 */
	bool __nts_make_ec__(const char * oid, keys::key_t & result) noexcept {
		// Кривая ключа
		curve::curve_t curve;
		// Если кривую по опознавателю завести не удалось
		if(!curve::parameters(oid, curve))
			// Выводим отказ выработки
			return false;
		// Примитив подписи, вырабатывающий ключевую пару
		sign::ecdsa_t signer;
		// Если кривую примитиву установить не удалось
		if(!signer.start(curve))
			// Выводим отказ выработки
			return false;
		// Занимаем место под секретный скаляр
		result.d.assign(curve.size(), 0);
		// Если ключевую пару выработать не удалось
		if(!signer.generate(result.d.data(), result.d.size()))
			// Выводим отказ выработки
			return false;
		// Занимаем места под координаты открытой точки
		result.x.assign(curve.size(), 0);
		// Вторая координата
		result.y.assign(curve.size(), 0);
		// Если открытую точку получить не удалось
		if(!signer.key(result.x.data(), result.y.data(), curve.size()))
			// Выводим отказ выработки
			return false;
		// Вид ключа
		result.kind = keys::kind_t::EC;
		// Опознаватель кривой
		result.oid = oid;
		// Выводим успешность выработки
		return true;
	}

	/**
	 * @brief Функция выработки ключа Ed25519
	 *
	 * @param result ключ, в который помещается итог выработки
	 * @return       признак успешности выработки ключа
	 *
	 */
	bool __nts_make_ed25519__(keys::key_t & result) noexcept {
		// Примитив подписи Ed25519
		sign::ed25519_t signer;
		// Занимаем место под зерно ключа
		result.d.assign(sign::ed25519_t::KEY_SIZE, 0);
		// Если зерно выработать не удалось
		if(!signer.generate(result.d.data(), result.d.size()))
			// Выводим отказ выработки
			return false;
		// Вид ключа
		result.kind = keys::kind_t::ED25519;
		// Выводим успешность выработки
		return true;
	}

	/**
	 * @brief Функция выработки ключа Ed448
	 *
	 * @param result ключ, в который помещается итог выработки
	 * @return       признак успешности выработки ключа
	 *
	 */
	bool __nts_make_ed448__(keys::key_t & result) noexcept {
		// Примитив подписи Ed448
		sign::ed448_t signer;
		// Занимаем место под зерно ключа
		result.d.assign(sign::ed448_t::KEY_SIZE, 0);
		// Если зерно выработать не удалось
		if(!signer.generate(result.d.data(), result.d.size()))
			// Выводим отказ выработки
			return false;
		// Вид ключа
		result.kind = keys::kind_t::ED448;
		// Выводим успешность выработки
		return true;
	}

	/**
	 * @brief Функция получения пароля из источника openssl
	 *
	 * @param source источник пароля вида pass:... либо file:..., пустой без пароля
	 * @param result место, в которое помещается пароль
	 * @return       признак успешности получения пароля
	 *
	 */
	bool __nts_password__(const char * source, string & result) noexcept {
		// Если источника пароля нет
		if((source == nullptr) || (source[0] == '\0'))
			// Пароля нет
			return true;
		// Если пароль задан прямо
		if(::strncmp(source, "pass:", 5) == 0){
			// Запоминаем пароль
			result = (source + 5);
			// Выводим успешность получения пароля
			return true;
		}
		// Если пароль задан файлом
		if(::strncmp(source, "file:", 5) == 0){
			// Область прочитанного файла
			vector <uint8_t> bytes;
			// Если файл прочитать не удалось
			if(!cli::readBytes(source + 5, bytes))
				// Выводим отказ получения пароля
				return false;
			// Пароль из прочитанных байтов
			result.assign(reinterpret_cast <const char *> (bytes.data()), bytes.size());
			// Убираем завершающий перевод строки
			if(!result.empty() && (result.back() == '\n'))
				// Убираем перевод строки
				result.pop_back();
			// Выводим успешность получения пароля
			return true;
		}
		// Иначе пароль задан прямо
		result = source;
		// Выводим успешность получения пароля
		return true;
	}

	/**
	 * @brief Функция чтения ключа из файла либо стандартного ввода
	 *
	 * @param path     путь к файлу, пустой для стандартного ввода
	 * @param password пароль зашифрованного ключа
	 * @param result   ключ, в который помещается итог разбора
	 * @return         признак успешности чтения и разбора
	 *
	 */
	bool __nts_read_key__(const char * path, const string & password, keys::key_t & result) noexcept {
		// Область прочитанного файла
		vector <uint8_t> bytes;
		// Если ввод прочитать не удалось
		if(!cli::readBytes(path, bytes))
			// Выводим отказ чтения
			return false;
		// Текст записи ключа
		const string text(reinterpret_cast <const char *> (bytes.data()), bytes.size());
		// Пароль последовательностью октетов
		const view_t secret(reinterpret_cast <const uint8_t *> (password.data()), password.size());
		// Выводим итог разбора ключа
		return keys::decode(text, secret, result) == keys::error_t::NONE;
	}

	/**
	 * @brief Функция записи ключа в файл либо на стандартный вывод
	 *
	 * @param path      путь к файлу, пустой для стандартного вывода
	 * @param key       записываемый ключ
	 * @param container вид записи ключа
	 * @param password  пароль зашифрованной записи, пустой без шифрования
	 * @return          признак успешности записи
	 *
	 */
	bool __nts_write_key__(const char * path, const keys::key_t & key, const keys::container_t container, const string & password) noexcept {
		// Текст записи ключа
		string text;
		// Пароль последовательностью октетов
		const view_t secret(reinterpret_cast <const uint8_t *> (password.data()), password.size());
		// Если ключ записать не удалось
		if(keys::encode(key, container, text, secret) != keys::error_t::NONE)
			// Выводим отказ записи
			return false;
		// Выводим итог записи текста
		return cli::writeBytes(path, reinterpret_cast <const uint8_t *> (text.data()), text.size());
	}

	/**
	 * @brief Функция вывода составляющей ключа шестнадцатерично
	 *
	 * @param title название составляющей
	 * @param data  выводимая составляющая
	 *
	 */
	void __nts_print_part__(const char * title, const vector <uint8_t> & data) noexcept {
		// Выводим название составляющей
		cout << title << ":" << endl;
		/**
		 * Выводим составляющую строками по пятнадцать байтов
		 */
		for(size_t i = 0; i < data.size(); i += 15){
			// Отступ строки вывода
			cout << "    ";
			/**
			 * Выводим байты текущей строки
			 */
			for(size_t j = i; (j < (i + 15)) && (j < data.size()); j++)
				// Выводим очередной байт пары разрядов
				cout << cli::hex(data.data() + j, 1) << ((j + 1 < data.size()) && (j + 1 < (i + 15)) ? ":" : "");
			// Завершаем строку двоеточием
			cout << ":" << endl;
		}
	}

	/**
	 * @brief Функция вывода ключа RSA в текстовом виде openssl
	 *
	 * @param key выводимый ключ
	 *
	 */
	void __nts_print_rsa__(const keys::key_t & key) noexcept {
		// Выводим заголовок ключа
		cout << (key.secret() ? "Private-Key: (" : "Public-Key: (") << (key.n.size() * 8) << " bit)" << endl;
		// Если ключ секретный
		if(key.secret())
			// Выводим модуль
			__nts_print_part__("modulus", key.n);
		// Иначе выводим модуль с заглавной буквы
		else __nts_print_part__("Modulus", key.n);
		// Выводим открытый показатель
		cout << (key.secret() ? "publicExponent: " : "Exponent: ") << "65537 (0x10001)" << endl;
		// Если ключ секретный
		if(key.secret()){
			// Выводим секретный показатель
			__nts_print_part__("privateExponent", key.d);
			// Выводим первый сомножитель
			__nts_print_part__("prime1", key.p);
			// Выводим второй сомножитель
			__nts_print_part__("prime2", key.q);
			// Выводим первый показатель
			__nts_print_part__("exponent1", key.dP);
			// Выводим второй показатель
			__nts_print_part__("exponent2", key.dQ);
			// Выводим коэффициент
			__nts_print_part__("coefficient", key.qInv);
		}
	}

	/**
	 * @brief Функция вывода ключа EC в текстовом виде openssl
	 *
	 * @param key выводимый ключ
	 *
	 */
	void __nts_print_ec__(const keys::key_t & key) noexcept {
		// Выводим заголовок ключа
		cout << (key.secret() ? "Private-Key: (" : "Public-Key: (") << (key.d.size() * 8) << " bit)" << endl;
		// Если ключ секретный
		if(key.secret())
			// Выводим секретный скаляр
			__nts_print_part__("priv", key.d);
		// Открытая точка с префиксом несжатой точки
		vector <uint8_t> point;
		// Приписываем префикс несжатой точки
		point.push_back(0x04);
		// Приписываем первую координату
		point.insert(point.end(), key.x.begin(), key.x.end());
		// Приписываем вторую координату
		point.insert(point.end(), key.y.begin(), key.y.end());
		// Выводим открытую точку
		__nts_print_part__("pub", point);
		// Имя кривой openssl
		const char * curveName = "unknown";
		// Имя кривой по NIST
		const char * nistName = nullptr;
		// Если кривая P-256
		if(key.oid == "1.2.840.10045.3.1.7"){
			// Имя кривой
			curveName = "prime256v1";
			// Имя кривой по NIST
			nistName = "P-256";
		// Иначе если кривая P-384
		} else if(key.oid == "1.3.132.0.34")
			// Имя кривой
			curveName = "secp384r1";
		// Иначе если кривая P-521
		else if(key.oid == "1.3.132.0.35")
			// Имя кривой
			curveName = "secp521r1";
		// Иначе если кривая curveSM2
		else if(key.oid == "1.2.156.10197.1.301")
			// Имя кривой
			curveName = "curveSM2";
		// Выводим имя кривой
		cout << "ASN1 OID: " << curveName << endl;
		// Если имя кривой по NIST есть
		if(nistName != nullptr)
			// Выводим имя кривой по NIST
			cout << "NIST CURVE: " << nistName << endl;
	}

	/**
	 * @brief Функция вывода ключа в текстовом виде openssl
	 *
	 * @param key выводимый ключ
	 *
	 */
	void __nts_print_key__(const keys::key_t & key) noexcept {
		/**
		 * Выбираем вид ключа
		 */
		switch(static_cast <uint8_t> (key.kind)){
			// Ключ RSA
			case static_cast <uint8_t> (keys::kind_t::RSA):
				// Выводим ключ RSA
				__nts_print_rsa__(key);
				// Прерываем вывод
				break;
			// Ключ EC
			case static_cast <uint8_t> (keys::kind_t::EC):
				// Выводим ключ EC
				__nts_print_ec__(key);
				// Прерываем вывод
				break;
			// Ключ Ed25519
			case static_cast <uint8_t> (keys::kind_t::ED25519): {
				// Выводим заголовок ключа
				cout << "ED25519 " << (key.secret() ? "Private-Key:" : "Public-Key:") << endl;
				// Если ключ секретный
				if(key.secret())
					// Выводим зерно ключа
					__nts_print_part__("priv", key.d);
				// Выводим открытый ключ
				__nts_print_part__("pub", key.key);
				// Прерываем вывод
				break;
			}
			// Ключ Ed448
			case static_cast <uint8_t> (keys::kind_t::ED448): {
				// Выводим заголовок ключа
				cout << "ED448 " << (key.secret() ? "Private-Key:" : "Public-Key:") << endl;
				// Если ключ секретный
				if(key.secret())
					// Выводим зерно ключа
					__nts_print_part__("priv", key.d);
				// Выводим открытый ключ
				__nts_print_part__("pub", key.key);
				// Прерываем вывод
				break;
			}
			// Прочие ключи
			default:
				// Прерываем вывод
				break;
		}
	}
};

/**
 * @brief Функция универсальной выработки ключа
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::genpkey(const int argc, const char * const argv[]) noexcept {
	// Алгоритм выработки ключа
	const char * algorithm = cli::value(argc, argv, "-algorithm");
	// Имя файла вывода
	const char * out = cli::value(argc, argv, "-out");
	// Признак вывода ключа текстом
	const bool text = cli::flag(argc, argv, "-text");
	// Пароль шифрования вывода
	string password;
	// Источник пароля
	const char * pass = cli::value(argc, argv, "-pass");
	// Если пароль получить не удалось
	if(!__nts_password__(pass, password)){
		// Печатаем сообщение об отказе получения пароля
		cout << "Получить пароль не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Если алгоритм не задан
	if((algorithm == nullptr) || (algorithm[0] == '\0')){
		// Печатаем подсказку команды
		cout << "применение: a-nts genpkey -algorithm RSA|EC|ED25519|ED448 [-pkeyopt имя:значение] [-out файл] [-pass пароль]" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Выработанный ключ
	keys::key_t key;
	// Признак успешности выработки
	bool ok = false;
	// Если запрошен алгоритм RSA
	if(::strcmp(algorithm, "RSA") == 0){
		// Разрядность модуля RSA
		size_t bits = 2048;
		// Значение настройки rsa_keygen_bits
		const char * opt = cli::value(argc, argv, "-pkeyopt");
		// Если настройка задана
		if((opt != nullptr) && (::strncmp(opt, "rsa_keygen_bits:", 16) == 0))
			// Запоминаем разрядность модуля
			bits = static_cast <size_t> (::strtoul(opt + 16, nullptr, 10));
		// Если разрядность нулевая
		if(bits == 0)
			// Разрядность по умолчанию
			bits = 2048;
		// Вырабатываем ключ RSA
		ok = __nts_make_rsa__(bits, key);
	// Иначе если запрошен алгоритм EC
	} else if(::strcmp(algorithm, "EC") == 0){
		// Имя кривой EC
		const char * curveName = "P-256";
		// Значение настройки ec_paramgen_curve
		const char * opt = cli::value(argc, argv, "-pkeyopt");
		// Если настройка задана
		if((opt != nullptr) && (::strncmp(opt, "ec_paramgen_curve:", 18) == 0))
			// Запоминаем имя кривой
			curveName = opt + 18;
		// Вырабатываем ключ EC
		ok = __nts_make_ec__(__nts_curve_oid__(curveName), key);
	// Иначе если запрошен алгоритм Ed25519
	} else if(::strcmp(algorithm, "ED25519") == 0)
		// Вырабатываем ключ Ed25519
		ok = __nts_make_ed25519__(key);
	// Иначе если запрошен алгоритм Ed448
	else if(::strcmp(algorithm, "ED448") == 0)
		// Вырабатываем ключ Ed448
		ok = __nts_make_ed448__(key);
	// Если ключ выработать не удалось
	if(!ok){
		// Печатаем сообщение об отказе выработки
		cout << "Выработать ключ не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Если запрошен вывод ключа текстом
	if(text)
		// Выводим ключ текстом
		__nts_print_key__(key);
	// Вид записи ключа
	const keys::container_t container = (password.empty() ? keys::container_t::PRIVATE : keys::container_t::ENCRYPTED);
	// Если ключ записать не удалось
	if(!__nts_write_key__(out, key, container, password)){
		// Печатаем сообщение об отказе записи
		cout << "Записать ключ не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Затираем пароль
	sys::wipe(password);
	// Сообщаем об успешности команды
	return EXIT_SUCCESS;
}

/**
 * @brief Функция выработки ключа RSA
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::genrsa(const int argc, const char * const argv[]) noexcept {
	// Имя файла вывода
	const char * out = cli::value(argc, argv, "-out");
	// Разрядность модуля RSA
	size_t bits = 0;
	/**
	 * Перебираем параметры команды в поисках разрядности
	 */
	for(int i = 2; i < argc; i++){
		// Если очередной параметр является флагом
		if(argv[i][0] == '-'){
			// Если флаг несёт значение, пропускаем и его значение
			if((::strcmp(argv[i], "-out") == 0) || (::strcmp(argv[i], "-passout") == 0))
				// Пропускаем значение флага
				i++;
			// Переходим к следующему параметру
			continue;
		}
		// Запоминаем разрядность модуля
		bits = static_cast <size_t> (::strtoul(argv[i], nullptr, 10));
		// Прерываем перебор
		break;
	}
	// Если разрядность не задана
	if(bits == 0)
		// Разрядность по умолчанию
		bits = 2048;
	// Пароль шифрования вывода
	string password;
	// Если пароль получить не удалось
	if(!__nts_password__(cli::value(argc, argv, "-passout"), password)){
		// Печатаем сообщение об отказе получения пароля
		cout << "Получить пароль не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Выработанный ключ
	keys::key_t key;
	// Если ключ выработать не удалось
	if(!__nts_make_rsa__(bits, key)){
		// Печатаем сообщение об отказе выработки
		cout << "Выработать ключ не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Вид записи ключа
	const keys::container_t container = (password.empty() ? keys::container_t::PRIVATE : keys::container_t::ENCRYPTED);
	// Если ключ записать не удалось
	if(!__nts_write_key__(out, key, container, password)){
		// Печатаем сообщение об отказе записи
		cout << "Записать ключ не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Затираем пароль
	sys::wipe(password);
	// Сообщаем об успешности команды
	return EXIT_SUCCESS;
}

/**
 * @brief Функция выработки ключа EC
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::genec(const int argc, const char * const argv[]) noexcept {
	// Имя файла вывода
	const char * out = cli::value(argc, argv, "-out");
	// Имя кривой EC
	const char * curveName = cli::value(argc, argv, "-name");
	// Если имя кривой не задано
	if((curveName == nullptr) || (curveName[0] == '\0'))
		// Имя кривой по умолчанию
		curveName = "P-256";
	// Пароль шифрования вывода
	string password;
	// Если пароль получить не удалось
	if(!__nts_password__(cli::value(argc, argv, "-passout"), password)){
		// Печатаем сообщение об отказе получения пароля
		cout << "Получить пароль не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Выработанный ключ
	keys::key_t key;
	// Если ключ выработать не удалось
	if(!__nts_make_ec__(__nts_curve_oid__(curveName), key)){
		// Печатаем сообщение об отказе выработки
		cout << "Выработать ключ не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Вид записи ключа
	const keys::container_t container = (password.empty() ? keys::container_t::PRIVATE : keys::container_t::ENCRYPTED);
	// Если ключ записать не удалось
	if(!__nts_write_key__(out, key, container, password)){
		// Печатаем сообщение об отказе записи
		cout << "Записать ключ не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Затираем пароль
	sys::wipe(password);
	// Сообщаем об успешности команды
	return EXIT_SUCCESS;
}

/**
 * @brief Функция действий над ключом произвольного вида
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::pkey(const int argc, const char * const argv[]) noexcept {
	// Имя файла ввода
	const char * in = cli::value(argc, argv, "-in");
	// Имя файла вывода
	const char * out = cli::value(argc, argv, "-out");
	// Признак вывода открытого ключа
	const bool pubout = cli::flag(argc, argv, "-pubout");
	// Признак вывода ключа текстом
	const bool text = cli::flag(argc, argv, "-text");
	// Признак отказа от вывода ключа
	const bool noout = cli::flag(argc, argv, "-noout");
	// Пароль чтения ключа
	string passin;
	// Если пароль чтения получить не удалось
	if(!__nts_password__(cli::value(argc, argv, "-passin"), passin)){
		// Печатаем сообщение об отказе получения пароля
		cout << "Получить пароль не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Пароль записи ключа
	string passout;
	// Если пароль записи получить не удалось
	if(!__nts_password__(cli::value(argc, argv, "-passout"), passout)){
		// Печатаем сообщение об отказе получения пароля
		cout << "Получить пароль не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Разобранный ключ
	keys::key_t key;
	// Если ключ прочитать не удалось
	if(!__nts_read_key__(in, passin, key)){
		// Печатаем сообщение об отказе чтения
		cout << "Прочитать ключ не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Если запрошен вывод ключа текстом
	if(text)
		// Выводим ключ текстом
		__nts_print_key__(key);
	// Если вывод ключа не запрещён
	if(!noout){
		// Вид записи ключа
		const keys::container_t container = (pubout ? keys::container_t::PUBLIC : (passout.empty() ? keys::container_t::PRIVATE : keys::container_t::ENCRYPTED));
		// Если ключ записать не удалось
		if(!__nts_write_key__(out, key, container, passout)){
			// Печатаем сообщение об отказе записи
			cout << "Записать ключ не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
	}
	// Затираем пароли
	sys::wipe(passin);
	// Затираем пароль вывода
	sys::wipe(passout);
	// Сообщаем об успешности команды
	return EXIT_SUCCESS;
}

/**
 * @brief Функция действий над ключом RSA
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::rsa(const int argc, const char * const argv[]) noexcept {
	// Действия над ключом едины с командой pkey
	return nts::cli::pkey(argc, argv);
}

/**
 * @brief Функция действий над ключом EC
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::ecKey(const int argc, const char * const argv[]) noexcept {
	// Имя файла ввода
	const char * in = cli::value(argc, argv, "-in");
	// Имя файла вывода
	const char * out = cli::value(argc, argv, "-out");
	// Признак вывода открытого ключа
	const bool pubout = cli::flag(argc, argv, "-pubout");
	// Признак вывода ключа текстом
	const bool text = cli::flag(argc, argv, "-text");
	// Признак отказа от вывода ключа
	const bool noout = cli::flag(argc, argv, "-noout");
	// Пароль чтения ключа
	string passin;
	// Если пароль чтения получить не удалось
	if(!__nts_password__(cli::value(argc, argv, "-passin"), passin)){
		// Печатаем сообщение об отказе получения пароля
		cout << "Получить пароль не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Разобранный ключ
	keys::key_t key;
	// Если ключ прочитать не удалось
	if(!__nts_read_key__(in, passin, key)){
		// Печатаем сообщение об отказе чтения
		cout << "Прочитать ключ не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Если запрошен вывод ключа текстом
	if(text)
		// Выводим ключ текстом
		__nts_print_key__(key);
	// Если вывод ключа не запрещён
	if(!noout){
		// Если запрошен вывод открытого ключа
		if(pubout){
			// Если открытый ключ записать не удалось
			if(!__nts_write_key__(out, key, keys::container_t::PUBLIC, string())){
				// Печатаем сообщение об отказе записи
				cout << "Записать ключ не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
		// Иначе выводим секретный ключ в записи ECPrivateKey по RFC 5915
		} else {
			// Запись ключа в кодировке DER
			vector <uint8_t> der;
			// Если ключ в DER записать не удалось
			if(keys::encodeECPrivateKey(key, der) != keys::error_t::NONE){
				// Печатаем сообщение об отказе записи
				cout << "Записать ключ не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Запись PEM с меткой EC PRIVATE KEY
			pem::block_t block;
			// Метка записи
			block.label = "EC PRIVATE KEY";
			// Тело записи
			block.data = der;
			// Текст записи PEM
			string text;
			// Если запись PEM составить не удалось
			if(pem::encode(block, text) != pem::error_t::NONE){
				// Печатаем сообщение об отказе записи
				cout << "Записать ключ не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Если текст записать не удалось
			if(!cli::writeBytes(out, reinterpret_cast <const uint8_t *> (text.data()), text.size())){
				// Печатаем сообщение об отказе записи
				cout << "Записать ключ не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
		}
	}
	// Затираем пароль
	sys::wipe(passin);
	// Сообщаем об успешности команды
	return EXIT_SUCCESS;
}
