/**
 * @file signature.cpp
 * @date 2026-08-29
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
 * @brief Исходный файл модуля проверки подписи сертификата X.509
 *
 * @note Записи величин в сертификате и внутри криптографии расходятся, и расхождение
 *       это - самое частое место ошибок. Координаты открытого ключа ГОСТ лежат в
 *       сертификате от младшего байта к старшему, тогда как арифметика ждёт обратного
 *       порядка. Части подписи ГОСТ лежат в порядке s, r, тогда как выработка даёт r, s.
 *       Хеш же передаётся подписи как есть, безо всякого разворота. Всё это
 *       установлено не рассуждением, а сличением с сертификатами приложения D RFC 9215.
 *       У классических подписей всё наоборот: координаты ключа ECDSA лежат от старшего
 *       байта к младшему за байтом 0x04 (раздел 2.2 RFC 5480), подпись ECDSA записана
 *       набором SEQUENCE {r, s} (раздел 3.2 RFC 5758), ключ RSA - записью RSAPublicKey
 *       внутри строки разрядов (раздел 2.3.1 RFC 3279), а ключ и подпись Ed25519 -
 *       сырыми байтами (RFC 8410)
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/rsa.hpp>
#include <sign/gost.hpp>
#include <sign/ecdsa.hpp>
#include <sign/sm2.hpp>
#include <sign/ed25519.hpp>
#include <sign/ed448.hpp>
#include <sign/mldsa.hpp>
#include <sign/slhdsa.hpp>
#include <asn1/asn1.hpp>
#include <digest/hash.hpp>
#include <digest/streebog.hpp>
#include <x509/signature.hpp>
#include <curve/parameters.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * @brief Семейство алгоритма подписи
	 *
	 */
	enum class family_t : uint8_t {
		GOST    = 0x00, // Подпись по ГОСТ Р 34.10-2012 с хешем «Стрибог»
		ECDSA   = 0x01, // Подпись ECDSA с хешем SHA-2
		PKCS1   = 0x02, // Подпись RSA по схеме PKCS #1 v1.5
		PSS     = 0x03, // Подпись RSA по схеме RSASSA-PSS
		ED25519 = 0x04, // Подпись Ed25519
		MLDSA   = 0x05, // Подпись ML-DSA по FIPS 204
		SLHDSA  = 0x06, // Подпись SLH-DSA по FIPS 205
		ED448   = 0x07  // Подпись Ed448
	};

	/**
	 * @brief Соответствие опознавателя алгоритма подписи виду и хешу
	 *
	 */
	typedef struct Record {
		// Опознаватель алгоритма подписи в записи через точку
		const char * oid;
		// Семейство алгоритма подписи
		family_t kind;
		// Алгоритм хеша подписываемой записи
		digest::hash_t hash;
	} record_t;

	/**
	 * @brief Соответствие опознавателя алгоритма хеша самому хешу
	 *
	 */
	typedef struct Hash {
		// Опознаватель алгоритма хеша в записи через точку
		const char * oid;
		// Алгоритм хеша
		digest::hash_t hash;
	} hash_t;

	/**
	 * Известные алгоритмы подписи
	 */
	static const record_t ALGORITHMS[] = {
		// Подпись ГОСТ Р 34.10-2012 с ключом длиной 256 разрядов и хешем той же длины
		{"1.2.643.7.1.1.3.2", family_t::GOST, digest::hash_t::STREEBOG256},
		// Подпись ГОСТ Р 34.10-2012 с ключом длиной 512 разрядов и хешем той же длины
		{"1.2.643.7.1.1.3.3", family_t::GOST, digest::hash_t::STREEBOG512},
		// Подпись ECDSA с хешем SHA-224: раздел 3.2 RFC 5758
		{"1.2.840.10045.4.3.1", family_t::ECDSA, digest::hash_t::SHA224},
		// Подпись ECDSA с хешем SHA-256
		{"1.2.840.10045.4.3.2", family_t::ECDSA, digest::hash_t::SHA256},
		// Подпись ECDSA с хешем SHA-384
		{"1.2.840.10045.4.3.3", family_t::ECDSA, digest::hash_t::SHA384},
		// Подпись ECDSA с хешем SHA-512
		{"1.2.840.10045.4.3.4", family_t::ECDSA, digest::hash_t::SHA512},
		// Подпись RSA PKCS #1 v1.5 с хешем SHA-1: раздел 2.2.1 RFC 3279
		{"1.2.840.113549.1.1.5", family_t::PKCS1, digest::hash_t::SHA1},
		// Подпись RSA PKCS #1 v1.5 с хешем SHA-256: раздел 5 RFC 4055
		{"1.2.840.113549.1.1.11", family_t::PKCS1, digest::hash_t::SHA256},
		// Подпись RSA PKCS #1 v1.5 с хешем SHA-384
		{"1.2.840.113549.1.1.12", family_t::PKCS1, digest::hash_t::SHA384},
		// Подпись RSA PKCS #1 v1.5 с хешем SHA-512
		{"1.2.840.113549.1.1.13", family_t::PKCS1, digest::hash_t::SHA512},
		// Подпись RSA PKCS #1 v1.5 с хешем SHA-224
		{"1.2.840.113549.1.1.14", family_t::PKCS1, digest::hash_t::SHA224},
		// Подпись RSASSA-PSS: хеш задаётся настройками алгоритма, раздел 3.1 RFC 4055
		{"1.2.840.113549.1.1.10", family_t::PSS, digest::hash_t::NONE},
		// Подпись Ed25519: хеша нет, подписывается само сообщение, раздел 3 RFC 8410
		{"1.3.101.112", family_t::ED25519, digest::hash_t::NONE},
		// Подпись Ed448: хеша нет, подписывается само сообщение, раздел 3 RFC 8410
		{"1.3.101.113", family_t::ED448, digest::hash_t::NONE},
		// Подпись ML-DSA-44: хеша нет, подписывается само сообщение, раздел 4 RFC 9881
		{"2.16.840.1.101.3.4.3.17", family_t::MLDSA, digest::hash_t::NONE},
		// Подпись ML-DSA-65
		{"2.16.840.1.101.3.4.3.18", family_t::MLDSA, digest::hash_t::NONE},
		// Подпись ML-DSA-87
		{"2.16.840.1.101.3.4.3.19", family_t::MLDSA, digest::hash_t::NONE},
		// Подпись SLH-DSA-SHA2-128s: хеша нет, подписывается само сообщение, раздел 4 RFC 9909
		{"2.16.840.1.101.3.4.3.20", family_t::SLHDSA, digest::hash_t::NONE},
		// Подпись SLH-DSA-SHA2-128f
		{"2.16.840.1.101.3.4.3.21", family_t::SLHDSA, digest::hash_t::NONE},
		// Подпись SLH-DSA-SHAKE-128s
		{"2.16.840.1.101.3.4.3.22", family_t::SLHDSA, digest::hash_t::NONE},
		// Подпись SLH-DSA-SHAKE-128f
		{"2.16.840.1.101.3.4.3.23", family_t::SLHDSA, digest::hash_t::NONE},
		// Подпись SLH-DSA-SHA2-192s
		{"2.16.840.1.101.3.4.3.24", family_t::SLHDSA, digest::hash_t::NONE},
		// Подпись SLH-DSA-SHA2-192f
		{"2.16.840.1.101.3.4.3.25", family_t::SLHDSA, digest::hash_t::NONE},
		// Подпись SLH-DSA-SHAKE-192s
		{"2.16.840.1.101.3.4.3.26", family_t::SLHDSA, digest::hash_t::NONE},
		// Подпись SLH-DSA-SHAKE-192f
		{"2.16.840.1.101.3.4.3.27", family_t::SLHDSA, digest::hash_t::NONE},
		// Подпись SLH-DSA-SHA2-256s
		{"2.16.840.1.101.3.4.3.28", family_t::SLHDSA, digest::hash_t::NONE},
		// Подпись SLH-DSA-SHA2-256f
		{"2.16.840.1.101.3.4.3.29", family_t::SLHDSA, digest::hash_t::NONE},
		// Подпись SLH-DSA-SHAKE-256s
		{"2.16.840.1.101.3.4.3.30", family_t::SLHDSA, digest::hash_t::NONE},
		// Подпись SLH-DSA-SHAKE-256f
		{"2.16.840.1.101.3.4.3.31", family_t::SLHDSA, digest::hash_t::NONE}
	};

	/**
	 * Известные алгоритмы хеша в настройках подписи RSASSA-PSS
	 */
	static const hash_t HASHES[] = {
		// Хеш SHA-1: раздел 2.1 RFC 4055
		{"1.3.14.3.2.26", digest::hash_t::SHA1},
		// Хеш SHA-224
		{"2.16.840.1.101.3.4.2.4", digest::hash_t::SHA224},
		// Хеш SHA-256
		{"2.16.840.1.101.3.4.2.1", digest::hash_t::SHA256},
		// Хеш SHA-384
		{"2.16.840.1.101.3.4.2.2", digest::hash_t::SHA384},
		// Хеш SHA-512
		{"2.16.840.1.101.3.4.2.3", digest::hash_t::SHA512}
	};

	/**
	 * Известные алгоритмы открытого ключа подписи ГОСТ Р 34.10-2012
	 */
	static const char * KEYS[] = {
		// Открытый ключ по ГОСТ Р 34.10-2012 длиной 256 разрядов
		"1.2.643.7.1.1.1.1",
		// Открытый ключ по ГОСТ Р 34.10-2012 длиной 512 разрядов
		"1.2.643.7.1.1.1.2",
		/**
		 * Открытый ключ по ГОСТ Р 34.10-2001: раздел 2 RFC 9215 велит проверять такие
		 * ключи алгоритмом издания 2012 года, кривые у них те же самые
		 */
		"1.2.643.2.2.19"
	};

	/**
	 * Опознаватель алгоритма открытого ключа RSA: раздел 2.3.1 RFC 3279
	 */
	static const char * RSA_KEY = "1.2.840.113549.1.1.1";

	/**
	 * Опознаватель алгоритма открытого ключа RSA, назначенного одной подписи
	 * RSASSA-PSS: раздел 3.1 RFC 4055
	 */
	static const char * PSS_KEY = "1.2.840.113549.1.1.10";

	/**
	 * Опознаватель алгоритма порождения маски MGF1: раздел 2.2 RFC 4055
	 */
	static const char * MGF1 = "1.2.840.113549.1.1.8";

	/**
	 * Опознаватель алгоритма открытого ключа эллиптической кривой: раздел 2.1.1 RFC 5480
	 */
	static const char * EC_KEY = "1.2.840.10045.2.1";

	/**
	 * Опознаватель алгоритма открытого ключа Ed25519: раздел 3 RFC 8410
	 */
	static const char * ED_KEY = "1.3.101.112";

	/**
	 * Опознаватель алгоритма открытого ключа Ed448: раздел 3 RFC 8410
	 */
	static const char * ED448_KEY = "1.3.101.113";

	/**
	 * Опознаватель алгоритма открытого ключа SM2: GB/T 32918 и RFC 8998
	 */
	static const char * SM2_KEY = "1.2.156.10197.1.301";

	/**
	 * Опознаватель алгоритма открытого ключа ML-DSA-44: раздел 5 RFC 9881
	 */
	static const char * MLDSA44_KEY = "2.16.840.1.101.3.4.3.17";

	/**
	 * Опознаватель алгоритма открытого ключа ML-DSA-65: раздел 5 RFC 9881
	 */
	static const char * MLDSA65_KEY = "2.16.840.1.101.3.4.3.18";

	/**
	 * Опознаватель алгоритма открытого ключа ML-DSA-87: раздел 5 RFC 9881
	 */
	static const char * MLDSA87_KEY = "2.16.840.1.101.3.4.3.19";

	/**
	 * Опознаватели алгоритмов открытых ключей SLH-DSA: раздел 4 RFC 9909
	 */
	static const char * SLHDSA_KEYS[12] = {
		"2.16.840.1.101.3.4.3.20", "2.16.840.1.101.3.4.3.21",
		"2.16.840.1.101.3.4.3.22", "2.16.840.1.101.3.4.3.23",
		"2.16.840.1.101.3.4.3.24", "2.16.840.1.101.3.4.3.25",
		"2.16.840.1.101.3.4.3.26", "2.16.840.1.101.3.4.3.27",
		"2.16.840.1.101.3.4.3.28", "2.16.840.1.101.3.4.3.29",
		"2.16.840.1.101.3.4.3.30", "2.16.840.1.101.3.4.3.31"
	};

	/**
	 * Наборы SLH-DSA по месту опознавателя: сперва SHA2, затем SHAKE (раздел 4 RFC 9909)
	 */
	static const sign::slhdsa_t::set_t SLHDSA_SETS[12] = {
		sign::slhdsa_t::set_t::SHA2_128S, sign::slhdsa_t::set_t::SHA2_128F,
		sign::slhdsa_t::set_t::SHA2_192S, sign::slhdsa_t::set_t::SHA2_192F,
		sign::slhdsa_t::set_t::SHA2_256S, sign::slhdsa_t::set_t::SHA2_256F,
		sign::slhdsa_t::set_t::SHAKE_128S, sign::slhdsa_t::set_t::SHAKE_128F,
		sign::slhdsa_t::set_t::SHAKE_192S, sign::slhdsa_t::set_t::SHAKE_192F,
		sign::slhdsa_t::set_t::SHAKE_256S, sign::slhdsa_t::set_t::SHAKE_256F
	};

	/**
	 * Длина соли подписи RSASSA-PSS по умолчанию: раздел 3.1 RFC 4055
	 */
	static constexpr size_t PSS_SALT = 20;

	/**
	 * @brief Метод розыска алгоритма подписи по опознавателю
	 *
	 * @param algorithm опознаватель алгоритма подписи
	 *
	 * @return          запись известного алгоритма либо нулевой указатель
	 *
	 */
	static const record_t * lookup(const string & algorithm) noexcept {
		/**
		 * Выполняем перебор известных алгоритмов подписи
		 */
		for(size_t i = 0; i < (sizeof(ALGORITHMS) / sizeof(record_t)); i++){
			// Если опознаватель алгоритма подписи совпал с искомым
			if(algorithm.compare(ALGORITHMS[i].oid) == 0)
				// Выводим запись известного алгоритма подписи
				return &ALGORITHMS[i];
		}
		// Выводим нулевой указатель: алгоритм подписи неизвестен
		return nullptr;
	}
	/**
	 * @brief Метод розыска алгоритма хеша по опознавателю
	 *
	 * @param oid    опознаватель алгоритма хеша
	 * @param result место, в которое помещается алгоритм хеша
	 *
	 * @return       признак того, что алгоритм хеша известен
	 *
	 */
	static bool hashing(const string & oid, digest::hash_t & result) noexcept {
		/**
		 * Выполняем перебор известных алгоритмов хеша
		 */
		for(size_t i = 0; i < (sizeof(HASHES) / sizeof(hash_t)); i++){
			// Если опознаватель алгоритма хеша совпал с искомым
			if(oid.compare(HASHES[i].oid) == 0){
				// Запоминаем алгоритм хеша
				result = HASHES[i].hash;
				// Выводим признак известности алгоритма хеша
				return true;
			}
		}
		// Выводим признак неизвестности алгоритма хеша
		return false;
	}
	/**
	 * @brief Метод проверки пригодности алгоритма открытого ключа подписи ГОСТ
	 *
	 * @param algorithm опознаватель алгоритма открытого ключа
	 *
	 * @return          признак пригодности алгоритма открытого ключа
	 *
	 */
	static bool suitable(const string & algorithm) noexcept {
		/**
		 * Выполняем перебор известных алгоритмов открытого ключа
		 */
		for(size_t i = 0; i < (sizeof(KEYS) / sizeof(const char *)); i++){
			// Если опознаватель алгоритма открытого ключа совпал с искомым
			if(algorithm.compare(KEYS[i]) == 0)
				// Выводим пригодность алгоритма открытого ключа
				return true;
		}
		// Выводим непригодность алгоритма открытого ключа
		return false;
	}
	/**
	 * @brief Метод извлечения опознавателя набора параметров кривой ключа ГОСТ
	 *
	 * @details Настройки алгоритма ключа записаны набором из опознавателя набора
	 *          параметров кривой и, необязательно, опознавателя хеша: раздел 2.1
	 *          RFC 9215
	 *
	 * @param parameters разбираемая запись настроек алгоритма ключа
	 * @param result     место, в которое помещается опознаватель набора параметров
	 *
	 * @return           отказ извлечения опознавателя
	 *
	 */
	static nts::x509::error_t identifier(const view_t & parameters, string & result) noexcept {
		// Выполняем сброс извлекаемого опознавателя
		result.clear();
		// Если запись настроек алгоритма ключа не передана
		if((parameters.data == nullptr) || (parameters.size == 0))
			// Выводим отказ извлечения опознавателя
			return nts::x509::error_t::KEY;
		// Разборщик записи настроек алгоритма ключа
		asn1::Reader reader(parameters);
		// Разбираемый элемент записи настроек
		asn1::element_t element;
		// Если набор настроек алгоритма ключа разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, element))
			// Выводим отказ извлечения опознавателя
			return nts::x509::error_t::KEY;
		// Разборщик содержимого набора настроек
		asn1::Reader items = reader.enter(element);
		// Если опознаватель набора параметров кривой разобрать не удалось
		if(!items.next(asn1::tag_t::OBJECT, element))
			// Выводим отказ извлечения опознавателя
			return nts::x509::error_t::KEY;
		// Итог извлечения опознавателя набора параметров
		const asn1::error_t outcome = asn1::oid(element, result);
		// Если памяти под опознаватель не хватило
		if(outcome == asn1::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return nts::x509::error_t::MEMORY;
		// Выводим отказ извлечения опознавателя, если он есть
		return ((outcome == asn1::error_t::NONE) ? nts::x509::error_t::NONE : nts::x509::error_t::KEY);
	}
	/**
	 * @brief Метод извлечения координат открытого ключа ГОСТ
	 *
	 * @details Раздел 4 RFC 9215: разряды открытого ключа несут запись строки байтов, а
	 *          в ней подряд лежат координаты, записанные от младшего байта к старшему
	 *
	 * @param data разбираемая запись открытого ключа
	 * @param size размер координаты точки кривой в байтах
	 * @param x    место, в которое помещается первая координата
	 * @param y    место, в которое помещается вторая координата
	 *
	 * @return     признак успешности извлечения координат открытого ключа
	 *
	 */
	static bool coordinates(const view_t & data, const size_t size, uint8_t * x, uint8_t * y) noexcept {
		// Если запись открытого ключа не передана
		if((data.data == nullptr) || (data.size == 0))
			// Выводим отказ извлечения координат открытого ключа
			return false;
		// Разборщик записи открытого ключа
		asn1::Reader reader(data);
		// Разбираемый элемент записи открытого ключа
		asn1::element_t element;
		// Если строку байтов открытого ключа разобрать не удалось
		if(!reader.next(asn1::tag_t::OCTET_STRING, element))
			// Выводим отказ извлечения координат открытого ключа
			return false;
		// Если строка байтов не занимает двух координат точки кривой
		if(element.content.size != (size * 2))
			// Выводим отказ извлечения координат открытого ключа
			return false;
		/**
		 * Выполняем разворот записи координат: в сертификате они лежат от младшего
		 * байта к старшему, а арифметика ждёт обратного порядка
		 */
		for(size_t i = 0; i < size; i++){
			// Переносим очередной байт первой координаты
			x[i] = element.content.data[size - i - 1];
			// Переносим очередной байт второй координаты
			y[i] = element.content.data[(size * 2) - i - 1];
		}
		// Выводим успешность извлечения координат открытого ключа
		return true;
	}
	/**
	 * @brief Метод заведения подписи ГОСТ по открытому ключу
	 *
	 * @param key   сведения об открытом ключе подписавшей стороны
	 * @param curve кривая, в которую помещается набор параметров ключа
	 * @param gost  объект подписи, в который устанавливается открытый ключ
	 *
	 * @return      отказ заведения подписи
	 *
	 */
	static nts::x509::error_t establish(const nts::x509::key_t & key, curve::curve_t & curve, sign::gost_t & gost) noexcept {
		// Если алгоритм открытого ключа непригоден
		if(!suitable(key.algorithm))
			// Выводим отказ ключа чужого алгоритма
			return nts::x509::error_t::KEY;
		// Опознаватель набора параметров кривой
		string oid;
		// Итог извлечения опознавателя набора параметров кривой
		const nts::x509::error_t extracted = ::identifier(key.parameters, oid);
		// Если опознаватель набора параметров кривой извлечь не удалось
		if(extracted != nts::x509::error_t::NONE)
			// Выводим отказ извлечения опознавателя
			return extracted;
		// Если кривую по опознавателю набора параметров установить не удалось
		if(!curve::parameters(oid, curve))
			// Выводим отказ заведения подписи
			return nts::x509::error_t::SIGNATURE;
		// Места, в которые помещаются координаты открытого ключа
		uint8_t x[math::NUMBER_SIZE], y[math::NUMBER_SIZE];
		// Если координаты открытого ключа извлечь не удалось
		if(!coordinates(key.key, curve.size(), x, y))
			// Выводим отказ заведения подписи
			return nts::x509::error_t::SIGNATURE;
		/**
		 * Заслон этот недостижим извне: кривая приходит сюда из набора известных, заведённого
		 * самим составом библиотеки, и установка её отказом ответить не может. Стоит он ради
		 * связности: молчаливый счёт подписи на незаведённой кривой был бы хуже
		 */
		// Если эллиптическую кривую установить не удалось
		if(!gost.start(curve))
			// Выводим отказ заведения подписи
			return nts::x509::error_t::SIGNATURE;
		// Если открытый ключ подписавшей стороны установить не удалось
		if(!gost.key(view_t(x, curve.size()), view_t(y, curve.size())))
			// Выводим отказ заведения подписи
			return nts::x509::error_t::SIGNATURE;
		// Выводим успешность заведения подписи
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Метод проверки подписи записи по ГОСТ Р 34.10-2012
	 *
	 * @param body      подписанная запись
	 * @param signature проверяемая подпись в записи сертификата
	 * @param size      длина хеша подписанной записи в байтах
	 * @param key       сведения об открытом ключе подписавшей стороны
	 *
	 * @return          отказ проверки подписи
	 *
	 */
	static nts::x509::error_t gost(const view_t & body, const view_t & signature, const size_t size, const nts::x509::key_t & key) noexcept {
		// Эллиптическая кривая проверки подписи
		curve::curve_t curve;
		// Объект модуля электронной подписи
		sign::gost_t gost;
		// Итог заведения подписи по открытому ключу
		const nts::x509::error_t established = establish(key, curve, gost);
		// Если подпись по открытому ключу завести не удалось
		if(established != nts::x509::error_t::NONE)
			// Выводим отказ заведения подписи
			return established;
		// Если длина хеша не совпала с размером координаты точки кривой
		if(size != curve.size())
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Если подпись не занимает двух чисел длиной в порядок подгруппы точек кривой
		if(signature.size != (curve.order().size() * 2))
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Место, в которое помещается хеш подписанной записи
		uint8_t digest[64];
		/**
		 * Выполняем выработку хеша подписанной записи: длина хеша задана самим
		 * опознавателем алгоритма подписи
		 */
		const digest::type_t type = (size == 32 ? digest::type_t::SHORT : digest::type_t::LONG);
		/**
		 * Хеш берётся записью вектором: подпись по ГОСТ Р 34.10-2012 толкует его числом,
		 * а не строкой байтов, и запись эта задана самим стандартом
		 */
		/**
		 * Заслон этот недостижим извне: длина хеша взята размером координаты кривой и
		 * выработке отвечает, а иных причин отказать у неё нет
		 */
		if(!digest::streebog(type, body, digest, size, digest::order_t::VECTOR))
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Место, в которое помещается подпись в порядке выработки
		uint8_t buffer[math::NUMBER_SIZE * 2];
		// Определяем длину всякой части подписи
		const size_t half = (signature.size / 2);
		/**
		 * Выполняем перестановку частей подписи: раздел 2 RFC 9215 велит записывать в
		 * сертификат сперва s, а затем r, тогда как выработка даёт их в обратном порядке
		 */
		::memcpy(buffer, signature.data + half, half);
		// Переносим вторую часть подписи
		::memcpy(buffer + half, signature.data, half);
		// Выводим итог проверки подписи записи
		return (gost.check(view_t(digest, size), view_t(buffer, signature.size)) ? nts::x509::error_t::NONE : nts::x509::error_t::SIGNATURE);
	}
	/**
	 * @brief Метод разбора записи опознавателя алгоритма
	 *
	 * @details Запись AlgorithmIdentifier раздела 4.1.1.2 RFC 5280: набор из опознавателя
	 *          и, необязательно, настроек алгоритма
	 *
	 * @param data   разбираемая запись опознавателя алгоритма
	 * @param oid    место, в которое помещается опознаватель алгоритма
	 * @param params место, в которое помещается запись настроек алгоритма целиком
	 *
	 * @return       отказ разбора записи опознавателя алгоритма
	 *
	 */
	static nts::x509::error_t algorithm(const view_t & data, string & oid, view_t & params) noexcept {
		// Выполняем сброс записи настроек алгоритма
		params = view_t();
		// Разборщик записи опознавателя алгоритма
		asn1::Reader reader(data);
		// Разбираемый элемент записи
		asn1::element_t element;
		// Если набор записи опознавателя алгоритма разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, element))
			// Выводим отказ разбора записи
			return nts::x509::error_t::SIGNATURE;
		// Разборщик содержимого набора
		asn1::Reader items = reader.enter(element);
		// Если опознаватель алгоритма разобрать не удалось
		if(!items.next(asn1::tag_t::OBJECT, element))
			// Выводим отказ разбора записи
			return nts::x509::error_t::SIGNATURE;
		// Итог извлечения опознавателя алгоритма
		const asn1::error_t outcome = asn1::oid(element, oid);
		// Если памяти под опознаватель не хватило
		if(outcome == asn1::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return nts::x509::error_t::MEMORY;
		// Если опознаватель алгоритма извлечь не удалось
		if(outcome != asn1::error_t::NONE)
			// Выводим отказ разбора записи
			return nts::x509::error_t::SIGNATURE;
		// Если настройки алгоритма записаны
		if(!items.empty()){
			// Если настройки алгоритма разобрать не удалось
			if(!items.next(element))
				// Выводим отказ разбора записи
				return nts::x509::error_t::SIGNATURE;
			// Запоминаем запись настроек алгоритма
			params = element.element;
			// Если после настроек алгоритма остались лишние поля
			if(!items.empty())
				// Выводим отказ разбора записи
				return nts::x509::error_t::SIGNATURE;
		}
		// Выводим успешность разбора записи
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Метод проверки отсутствия настроек алгоритма
	 *
	 * @details Настройки алгоритма ключа RSA записываются значением NULL (раздел 2.3.1
	 *          RFC 3279), а у ключа Ed25519 отсутствуют вовсе (раздел 3 RFC 8410);
	 *          и то и другое считается отсутствием настроек
	 *
	 * @param parameters запись настроек алгоритма
	 *
	 * @return           признак того, что настроек алгоритма нет
	 *
	 */
	static bool absent(const view_t & parameters) noexcept {
		// Если запись настроек алгоритма не передана
		if((parameters.data == nullptr) || (parameters.size == 0))
			// Выводим признак отсутствия настроек
			return true;
		// Разборщик записи настроек алгоритма
		asn1::Reader reader(parameters);
		// Разбираемый элемент записи настроек
		asn1::element_t element;
		// Если запись настроек не есть значение NULL без содержимого
		if(!reader.next(asn1::tag_t::NOTHING, element) || (element.content.size != 0))
			// Выводим признак присутствия настроек
			return false;
		// Выводим признак отсутствия настроек
		return reader.empty();
	}
	/**
	 * @brief Метод заведения открытого ключа RSA
	 *
	 * @details Раздел 2.3.1 RFC 3279: разряды открытого ключа несут запись RSAPublicKey.
	 *          Ключ, объявленный алгоритмом id-RSASSA-PSS, устроен так же (раздел 3.1
	 *          RFC 4055), а ограничения его настроек на подпись здесь не рассматриваются
	 *
	 * @param key сведения об открытом ключе подписавшей стороны
	 * @param rsa объект подписи, в который устанавливается открытый ключ
	 *
	 * @return    отказ заведения открытого ключа
	 *
	 */
	static nts::x509::error_t rsa(const nts::x509::key_t & key, sign::rsa_t & rsa, const bool pss) noexcept {
		// Если алгоритм открытого ключа не есть RSA
		if((key.algorithm.compare(RSA_KEY) != 0) && (key.algorithm.compare(PSS_KEY) != 0))
			// Выводим отказ ключа чужого алгоритма
			return nts::x509::error_t::KEY;
		// Раздел 1.2 RFC 4055: ключ id-RSASSA-PSS применим лишь к подписи RSASSA-PSS - под PKCS #1 v1.5 он негоден
		if((key.algorithm.compare(PSS_KEY) == 0) && !pss)
			// Выводим отказ ключа чужого алгоритма
			return nts::x509::error_t::KEY;
		// Если ключ RSA несёт настройки, отличные от NULL
		if((key.algorithm.compare(RSA_KEY) == 0) && !absent(key.parameters))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если запись открытого ключа занимает неполное число байтов
		if((key.unused != 0) || (key.key.data == nullptr) || (key.key.size == 0))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		/**
		 * Отказ разбора записи ключа нехваткой памяти от отказа устройством записи
		 * модуль RSA не отличает: и то и другое он отвечает одним признаком
		 */
		if(!rsa.decode(key.key))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если разобранная запись несла секретный ключ, открытым ключом она не служит
		if(!rsa.ready() || rsa.secret())
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Выводим успешность заведения открытого ключа
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Метод заведения открытого ключа эллиптической кривой
	 *
	 * @details Раздел 2.1.1 RFC 5480: настройки ключа несут опознаватель именованной
	 *          кривой, а разряды ключа - точку в несжатой записи 0x04 || x || y
	 *          (раздел 2.2). Сжатая запись точки не поддерживается: раздел 2.2 велит
	 *          её лишь принимать по возможности, а издатели её не выпускают
	 *
	 * @param key   сведения об открытом ключе подписавшей стороны
	 * @param curve кривая, в которую помещается набор параметров ключа
	 * @param ecdsa объект подписи, в который устанавливается открытый ключ
	 *
	 * @return      отказ заведения открытого ключа
	 *
	 */
	static nts::x509::error_t ecdsa(const nts::x509::key_t & key, curve::curve_t & curve, sign::ecdsa_t & ecdsa) noexcept {
		// Если алгоритм открытого ключа не есть ключ эллиптической кривой
		if(key.algorithm.compare(EC_KEY) != 0)
			// Выводим отказ ключа чужого алгоритма
			return nts::x509::error_t::KEY;
		// Если запись настроек алгоритма ключа не передана
		if((key.parameters.data == nullptr) || (key.parameters.size == 0))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Разборщик записи настроек алгоритма ключа
		asn1::Reader reader(key.parameters);
		// Разбираемый элемент записи настроек
		asn1::element_t element;
		// Если опознаватель именованной кривой разобрать не удалось
		if(!reader.next(asn1::tag_t::OBJECT, element))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Опознаватель именованной кривой
		string oid;
		// Итог извлечения опознавателя именованной кривой
		const asn1::error_t outcome = asn1::oid(element, oid);
		// Если памяти под опознаватель не хватило
		if(outcome == asn1::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return nts::x509::error_t::MEMORY;
		// Если опознаватель именованной кривой извлечь не удалось
		if(outcome != asn1::error_t::NONE)
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если кривую по опознавателю установить не удалось
		if(!curve::parameters(oid, curve))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если запись открытого ключа занимает неполное число байтов
		if((key.unused != 0) || (key.key.data == nullptr))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если запись точки не несжатая либо не занимает двух координат
		if((key.key.size != ((curve.size() * 2) + 1)) || (key.key.data[0] != 0x04))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		/**
		 * Заслон этот недостижим извне: кривая приходит сюда из набора известных, заведённого
		 * самим составом библиотеки, и установка её отказом ответить не может. Стоит он ради
		 * связности: молчаливый счёт подписи на незаведённой кривой был бы хуже
		 */
		// Если эллиптическую кривую установить не удалось
		if(!ecdsa.start(curve))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если открытый ключ подписавшей стороны установить не удалось
		if(!ecdsa.key(view_t(key.key.data + 1, curve.size()), view_t(key.key.data + 1 + curve.size(), curve.size())))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Выводим успешность заведения открытого ключа
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Метод заведения открытого ключа Ed25519
	 *
	 * @details Раздел 4 RFC 8410: настроек у алгоритма нет, разряды ключа несут сжатую
	 *          точку в тридцать два байта
	 *
	 * @param key     сведения об открытом ключе подписавшей стороны
	 * @param ed25519 объект подписи, в который устанавливается открытый ключ
	 *
	 * @return        отказ заведения открытого ключа
	 *
	 */
	static nts::x509::error_t ed25519(const nts::x509::key_t & key, sign::ed25519_t & ed25519) noexcept {
		// Если алгоритм открытого ключа не есть Ed25519
		if(key.algorithm.compare(ED_KEY) != 0)
			// Выводим отказ ключа чужого алгоритма
			return nts::x509::error_t::KEY;
		// Если ключ несёт настройки, которых у алгоритма нет
		if((key.parameters.data != nullptr) && (key.parameters.size != 0))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если запись открытого ключа занимает неполное число байтов либо не той длины
		if((key.unused != 0) || (key.key.data == nullptr) || (key.key.size != sign::ed25519_t::KEY_SIZE))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если открытый ключ подписавшей стороны установить не удалось
		if(!ed25519.key(key.key))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Выводим успешность заведения открытого ключа
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Метод заведения открытого ключа Ed448 в примитив
	 *
	 * @param key   сведения об открытом ключе подписавшей стороны
	 * @param ed448 примитив, в который заводится открытый ключ
	 *
	 * @return      отказ заведения открытого ключа
	 *
	 */
	static nts::x509::error_t ed448(const nts::x509::key_t & key, sign::ed448_t & ed448) noexcept {
		// Если алгоритм открытого ключа не есть Ed448
		if(key.algorithm.compare(ED448_KEY) != 0)
			// Выводим отказ ключа чужого алгоритма
			return nts::x509::error_t::KEY;
		// Если ключ несёт настройки, которых у алгоритма нет
		if((key.parameters.data != nullptr) && (key.parameters.size != 0))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если запись открытого ключа занимает неполное число байтов либо не той длины
		if((key.unused != 0) || (key.key.data == nullptr) || (key.key.size != sign::ed448_t::KEY_SIZE))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если открытый ключ подписавшей стороны установить не удалось
		if(!ed448.key(key.key))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Выводим успешность заведения открытого ключа
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Метод разбора настроек подписи RSASSA-PSS
	 *
	 * @details Запись RSASSA-PSS-params раздела 3.1 RFC 4055: четыре необязательных
	 *          поля с метками места употребления от нулевой до третьей - алгоритм
	 *          хеша, алгоритм порождения маски с алгоритмом хеша в настройках, длина
	 *          соли и хвостовое поле. Умолчания: SHA-1, MGF1 с SHA-1, двадцать байтов
	 *          соли и хвостовое поле единица. Хеш порождения маски обязан совпадать с
	 *          хешем подписи: того требует раздел 4.2.3 RFC 8446, а раздел 3.1 RFC 4055
	 *          настоятельно советует, - иного сочетания никто не выпускает
	 *
	 * @param parameters запись настроек алгоритма подписи целиком либо пустой просмотр
	 * @param hash       место, в которое помещается алгоритм хеша подписи
	 * @param salt       место, в которое помещается длина соли в байтах
	 *
	 * @return           отказ разбора настроек подписи
	 *
	 */
	static nts::x509::error_t settings(const view_t & parameters, digest::hash_t & hash, size_t & salt) noexcept {
		// Устанавливаем умолчание алгоритма хеша подписи
		hash = digest::hash_t::SHA1;
		// Устанавливаем умолчание длины соли
		salt = PSS_SALT;
		// Если запись настроек алгоритма подписи не передана
		if((parameters.data == nullptr) || (parameters.size == 0))
			// Выводим успешность разбора: действуют умолчания
			return nts::x509::error_t::NONE;
		// Алгоритм хеша порождения маски
		digest::hash_t mask = digest::hash_t::SHA1;
		// Разборщик записи настроек алгоритма подписи
		asn1::Reader reader(parameters);
		// Разбираемый элемент записи настроек
		asn1::element_t element;
		// Если набор настроек разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, element))
			// Выводим отказ разбора настроек
			return nts::x509::error_t::SIGNATURE;
		// Разборщик содержимого набора настроек
		asn1::Reader items = reader.enter(element);
		// Номер метки последнего разобранного поля: поля идут по возрастанию меток
		int32_t last = -1;
		/**
		 * Выполняем перебор полей настроек подписи
		 */
		while(!items.empty()){
			// Если очередное поле разобрать не удалось
			if(!items.next(element))
				// Выводим отказ разбора настроек
				return nts::x509::error_t::SIGNATURE;
			// Если поле не помечено меткой места употребления составного вида
			if((element.cls != asn1::cls_t::CONTEXT) || !element.constructed)
				// Выводим отказ разбора настроек
				return nts::x509::error_t::SIGNATURE;
			// Если метки полей идут не по возрастанию либо метка неизвестна
			if((static_cast <int32_t> (element.tag) <= last) || (element.tag > 3))
				// Выводим отказ разбора настроек
				return nts::x509::error_t::SIGNATURE;
			// Запоминаем метку разобранного поля
			last = static_cast <int32_t> (element.tag);
			// Разборщик содержимого поля
			asn1::Reader inner = items.enter(element);
			/**
			 * Выполняем разбор поля по его метке
			 */
			switch(element.tag){
				// Алгоритм хеша подписи
				case 0: {
					// Запись опознавателя алгоритма хеша
					asn1::element_t identifier;
					// Если запись опознавателя алгоритма хеша внутри обёртки не прочиталась
					if(!inner.next(asn1::tag_t::SEQUENCE, identifier))
						// Выводим отказ разбора настроек
						return nts::x509::error_t::SIGNATURE;
					// Опознаватель алгоритма хеша
					string oid;
					// Запись настроек алгоритма хеша, которая не рассматривается
					view_t params;
					// Итог разбора записи опознавателя алгоритма хеша
					const nts::x509::error_t outcome = algorithm(identifier.element, oid, params);
					// Если запись опознавателя алгоритма хеша разобрать не удалось
					if(outcome != nts::x509::error_t::NONE)
						// Выводим отказ разбора настроек
						return outcome;
					// Если алгоритм хеша неизвестен
					if(!hashing(oid, hash))
						// Выводим отказ разбора настроек
						return nts::x509::error_t::SIGNATURE;
				} break;
				// Алгоритм порождения маски
				case 1: {
					// Запись опознавателя алгоритма порождения маски
					asn1::element_t identifier;
					// Если запись опознавателя алгоритма порождения маски внутри обёртки не прочиталась
					if(!inner.next(asn1::tag_t::SEQUENCE, identifier))
						// Выводим отказ разбора настроек
						return nts::x509::error_t::SIGNATURE;
					// Опознаватель алгоритма порождения маски
					string oid;
					// Запись настроек алгоритма порождения маски: опознаватель хеша
					view_t params;
					// Итог разбора записи опознавателя алгоритма порождения маски
					const nts::x509::error_t outcome = algorithm(identifier.element, oid, params);
					// Если запись опознавателя алгоритма порождения маски разобрать не удалось
					if(outcome != nts::x509::error_t::NONE)
						// Выводим отказ разбора настроек
						return outcome;
					// Если алгоритм порождения маски не есть MGF1
					if(oid.compare(MGF1) != 0)
						// Выводим отказ разбора настроек
						return nts::x509::error_t::SIGNATURE;
					// Запись настроек алгоритма хеша маски, которая не рассматривается
					view_t nested;
					// Итог разбора записи опознавателя алгоритма хеша маски
					const nts::x509::error_t hashed = algorithm(params, oid, nested);
					// Если запись опознавателя алгоритма хеша маски разобрать не удалось
					if(hashed != nts::x509::error_t::NONE)
						// Выводим отказ разбора настроек
						return hashed;
					// Если алгоритм хеша маски неизвестен
					if(!hashing(oid, mask))
						// Выводим отказ разбора настроек
						return nts::x509::error_t::SIGNATURE;
				} break;
				// Длина соли
				case 2: {
					// Если число длины соли разобрать не удалось
					if(!inner.next(asn1::tag_t::INTEGER, element))
						// Выводим отказ разбора настроек
						return nts::x509::error_t::SIGNATURE;
					// Длина соли числом
					int64_t value = 0;
					// Если длину соли извлечь не удалось либо она отрицательна
					if((asn1::integer(element, value) != asn1::error_t::NONE) || (value < 0) || (value > INT32_MAX))
						// Выводим отказ разбора настроек
						return nts::x509::error_t::SIGNATURE;
					// Запоминаем длину соли
					salt = static_cast <size_t> (value);
				} break;
				// Хвостовое поле
				case 3: {
					// Если число хвостового поля разобрать не удалось
					if(!inner.next(asn1::tag_t::INTEGER, element))
						// Выводим отказ разбора настроек
						return nts::x509::error_t::SIGNATURE;
					// Хвостовое поле числом
					int64_t value = 0;
					// Если хвостовое поле не единица, иных значений раздел 3.1 RFC 4055 не знает
					if((asn1::integer(element, value) != asn1::error_t::NONE) || (value != 1))
						// Выводим отказ разбора настроек
						return nts::x509::error_t::SIGNATURE;
				} break;
			}
			// Если внутри явной обёртки поля остались лишние данные: у всех четырёх полей ровно одна запись
			if(!inner.empty())
				// Выводим отказ разбора настроек
				return nts::x509::error_t::SIGNATURE;
		}
		// Если хеш порождения маски с хешем подписи разошёлся
		if(mask != hash)
			// Выводим отказ разбора настроек
			return nts::x509::error_t::SIGNATURE;
		// Выводим успешность разбора настроек
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Метод извлечения настроек алгоритма подписи из тела сертификата
	 *
	 * @details Раздел 4.1.2.3 RFC 5280: тело сертификата само несёт опознаватель
	 *          алгоритма подписи с настройками третьим полем, за изданием и порядковым
	 *          номером, и разбор сертификата уже сверил его с внешним. Извлечение
	 *          идёт из тела, поскольку разобранный сертификат наружу отдаёт один лишь
	 *          опознаватель
	 *
	 * @param body       тело сертификата
	 * @param parameters место, в которое помещается запись настроек алгоритма целиком
	 *
	 * @return           признак успешности извлечения настроек
	 *
	 */
	static bool declared(const view_t & body, view_t & parameters) noexcept {
		// Выполняем сброс извлекаемой записи настроек
		parameters = view_t();
		// Разборщик тела сертификата
		asn1::Reader reader(body);
		// Разбираемый элемент тела сертификата
		asn1::element_t element;
		// Если набор тела сертификата разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, element))
			// Выводим отказ извлечения настроек
			return false;
		// Разборщик содержимого тела сертификата
		asn1::Reader items = reader.enter(element);
		// Если первое поле тела разобрать не удалось
		if(!items.next(element))
			// Выводим отказ извлечения настроек
			return false;
		// Если первым полем записано издание сертификата, порядковый номер идёт за ним
		if((element.cls == asn1::cls_t::CONTEXT) && (element.tag == 0) && !items.next(asn1::tag_t::INTEGER, element))
			// Выводим отказ извлечения настроек
			return false;
		// Если запись опознавателя алгоритма подписи разобрать не удалось
		if(!items.next(asn1::tag_t::SEQUENCE, element))
			// Выводим отказ извлечения настроек
			return false;
		// Разборщик содержимого записи опознавателя алгоритма подписи
		asn1::Reader inner = items.enter(element);
		// Если опознаватель алгоритма подписи разобрать не удалось
		if(!inner.next(asn1::tag_t::OBJECT, element))
			// Выводим отказ извлечения настроек
			return false;
		// Если настроек у алгоритма подписи нет
		if(inner.empty())
			// Выводим успешность извлечения: настроек нет
			return true;
		// Если настройки алгоритма подписи разобрать не удалось
		if(!inner.next(element))
			// Выводим отказ извлечения настроек
			return false;
		// Запоминаем запись настроек алгоритма подписи
		parameters = element.element;
		// Выводим успешность извлечения настроек
		return true;
	}
	/**
	 * @brief Метод проверки подписи ECDSA
	 *
	 * @param hash      алгоритм хеша подписанного содержимого
	 * @param content   подписанное содержимое
	 * @param signature проверяемая подпись в записи SEQUENCE {r, s}
	 * @param key       сведения об открытом ключе подписавшей стороны
	 *
	 * @return          отказ проверки подписи
	 *
	 */
	/**
	 * @brief Метод проверки подписи SM2 содержимого открытым ключом
	 *
	 * @param content   подписанное содержимое
	 * @param signature подпись в записи протокола: SEQUENCE {INTEGER r, INTEGER s}
	 * @param key       сведения об открытом ключе подписавшей стороны
	 * @param id        опознаватель подписывающего для выработки Z_A
	 *
	 * @return          отказ проверки подписи
	 *
	 * @details Подписываемое значение e = SM3(Z_A ‖ M): Z_A вяжет подпись с
	 *          опознавателем, параметрами кривой и ключом; хеш считается самим
	 *          модулем, отдельного хеширования содержимого здесь не ведётся
	 *
	 */
	static nts::x509::error_t sm2(const view_t & content, const view_t & signature, const nts::x509::key_t & key, const view_t & id) noexcept {
		// Если ключ не эллиптической кривой: ключ SM2 идёт записью id-ecPublicKey с кривой curveSM2
		if(key.algorithm.compare(EC_KEY) != 0)
			// Выводим отказ ключа чужого алгоритма
			return nts::x509::error_t::KEY;
		// Эллиптическая кривая проверки подписи
		curve::curve_t curve;
		// Если запись настроек алгоритма ключа не передана
		if((key.parameters.data == nullptr) || (key.parameters.size == 0))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Разборщик записи настроек алгоритма ключа
		asn1::Reader reader(key.parameters);
		// Разбираемый элемент записи настроек
		asn1::element_t element;
		// Если опознаватель именованной кривой разобрать не удалось
		if(!reader.next(asn1::tag_t::OBJECT, element))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Опознаватель именованной кривой
		string oid;
		// Итог извлечения опознавателя именованной кривой
		const asn1::error_t outcome = asn1::oid(element, oid);
		// Если памяти под опознаватель не хватило
		if(outcome == asn1::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return nts::x509::error_t::MEMORY;
		// Если опознаватель именованной кривой извлечь не удалось
		if(outcome != asn1::error_t::NONE)
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если кривая ключа - не curveSM2
		if(oid.compare(SM2_KEY) != 0)
			// Выводим отказ ключа чужой кривой
			return nts::x509::error_t::KEY;
		// Если кривую curveSM2 установить не удалось
		if(!curve::parameters(oid, curve))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если запись открытого ключа занимает неполное число байтов
		if((key.unused != 0) || (key.key.data == nullptr))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если запись точки не несжатая либо не занимает двух координат
		if((key.key.size != ((curve.size() * 2) + 1)) || (key.key.data[0] != 0x04))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Объект модуля электронной подписи
		sign::sm2_t sm2;
		// Если кривую в модуль установить не удалось
		if(!sm2.start(curve))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если открытый ключ подписавшей стороны установить не удалось
		if(!sm2.key(view_t(key.key.data + 1, curve.size()), view_t(key.key.data + 1 + curve.size(), curve.size()), id))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Место, в которое помещается подпись в сыром виде
		uint8_t raw[64];
		// Если запись подписи разобрать не удалось
		if(!sign::decode(signature, raw, sizeof(raw)))
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Выводим итог проверки подписи
		return (sm2.check(content, view_t(raw, sizeof(raw))) ? nts::x509::error_t::NONE : nts::x509::error_t::SIGNATURE);
	}
	/**
	 * @brief Метод проверки подписи ECDSA содержимого открытым ключом
	 *
	 * @param hash      алгоритм хеша подписанного содержимого
	 * @param content   подписанное содержимое
	 * @param signature подпись в записи протокола
	 * @param key       сведения об открытом ключе подписавшей стороны
	 *
	 * @return          отказ проверки подписи
	 *
	 */
	static nts::x509::error_t ecdsa(const digest::hash_t hash, const view_t & content, const view_t & signature, const nts::x509::key_t & key) noexcept {
		// Если алгоритм хеша не установлен
		if(hash == digest::hash_t::NONE)
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Эллиптическая кривая проверки подписи
		curve::curve_t curve;
		// Объект модуля электронной подписи
		sign::ecdsa_t ecdsa;
		// Итог заведения открытого ключа
		const nts::x509::error_t established = ::ecdsa(key, curve, ecdsa);
		// Если открытый ключ завести не удалось
		if(established != nts::x509::error_t::NONE)
			// Выводим отказ заведения открытого ключа
			return established;
		// Место, в которое помещается подпись в сыром виде
		uint8_t raw[math::NUMBER_SIZE * 2];
		// Определяем длину подписи в сыром виде
		const size_t size = (curve.order().size() * 2);
		// Если запись подписи разобрать не удалось
		if(!sign::decode(signature, raw, size))
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Место, в которое помещается хеш подписанного содержимого
		uint8_t digest[64];
		// Определяем длину хеша подписанного содержимого
		const size_t length = digest::length(hash);
		/**
		 * Заслон этот недостижим извне: алгоритм хеша приходит сюда из набора известных,
		 * а длина взята из него же. Стоит он ради связности
		 */
		if(!digest::hash(hash, content, digest, length))
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Выводим итог проверки подписи
		return (ecdsa.check(view_t(digest, length), view_t(raw, size)) ? nts::x509::error_t::NONE : nts::x509::error_t::SIGNATURE);
	}
	/**
	 * @brief Метод суда настроек ключа id-RSASSA-PSS над хешем и солью подписи
	 *
	 * @param key  сведения об открытом ключе подписавшей стороны
	 * @param hash алгоритм хеша проверяемой подписи
	 * @param salt длина соли проверяемой подписи
	 *
	 * @return     признак того, что настройки ключа подпись дозволяют
	 *
	 * @details Раздел 3.3 RFC 4055: ключ id-RSASSA-PSS с настройками ограничивает подпись
	 *          тем же хешем и солью не короче заданной. Суд един для подписи сертификата
	 *          и для подписи содержимого открытым ключом (CertificateVerify TLS 1.3):
	 *          политика ключа, объявленная издателем, не зависит от места проверки
	 *
	 */
	static bool bounded(const nts::x509::key_t & key, const digest::hash_t hash, const size_t salt) noexcept {
		// Если ключ не id-RSASSA-PSS либо настроек у него нет - ограничений нет
		if((key.algorithm.compare(PSS_KEY) != 0) || absent(key.parameters))
			// Выводим признак дозволенной подписи
			return true;
		// Настройки ключа
		digest::hash_t bound = digest::hash_t::NONE;
		// Наименьшая соль по ключу
		size_t least = 0;
		// Если настройки ключа разобрать не удалось
		if(settings(key.parameters, bound, least) != nts::x509::error_t::NONE)
			// Выводим отказ: неразбираемые настройки ключа подписи не дозволяют
			return false;
		// Выводим признак того, что хеш подписи тот же, а соль не короче заданной ключом
		return ((bound == hash) && (salt >= least));
	}
	/**
	 * @brief Метод проверки подписи RSA
	 *
	 * @param scheme    схема подписи: PKCS #1 v1.5 либо RSASSA-PSS
	 * @param hash      алгоритм хеша подписанного содержимого
	 * @param salt      длина соли подписи RSASSA-PSS в байтах
	 * @param content   подписанное содержимое
	 * @param signature проверяемая подпись размером в модуль
	 * @param key       сведения об открытом ключе подписавшей стороны
	 *
	 * @return          отказ проверки подписи
	 *
	 */
	static nts::x509::error_t rsa(const sign::scheme_t scheme, const digest::hash_t hash, const size_t salt, const view_t & content, const view_t & signature, const nts::x509::key_t & key) noexcept {
		// Если алгоритм хеша не установлен
		if(hash == digest::hash_t::NONE)
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Объект модуля электронной подписи
		sign::rsa_t rsa;
		// Итог заведения открытого ключа: ключ id-RSASSA-PSS годен лишь схеме PSS
		const nts::x509::error_t established = ::rsa(key, rsa, (scheme == sign::scheme_t::PSS));
		// Если открытый ключ завести не удалось
		if(established != nts::x509::error_t::NONE)
			// Выводим отказ заведения открытого ключа
			return established;
		// Если подпись не занимает размера модуля
		if(signature.size != rsa.size())
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Место, в которое помещается хеш подписанного содержимого
		uint8_t digest[64];
		// Определяем длину хеша подписанного содержимого
		const size_t length = digest::length(hash);
		/**
		 * Заслон этот недостижим извне: алгоритм хеша приходит сюда из набора известных,
		 * а длина взята из него же. Стоит он ради связности
		 */
		if(!digest::hash(hash, content, digest, length))
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Выводим итог проверки подписи
		return (rsa.check(scheme, hash, view_t(digest, length), signature, salt) ? nts::x509::error_t::NONE : nts::x509::error_t::SIGNATURE);
	}
	/**
	 * @brief Метод проверки подписи Ed25519
	 *
	 * @param content   подписанное содержимое
	 * @param signature проверяемая подпись в шестьдесят четыре байта
	 * @param key       сведения об открытом ключе подписавшей стороны
	 *
	 * @return          отказ проверки подписи
	 *
	 */
	static nts::x509::error_t ed25519(const view_t & content, const view_t & signature, const nts::x509::key_t & key) noexcept {
		// Объект модуля электронной подписи
		sign::ed25519_t ed25519;
		// Итог заведения открытого ключа
		const nts::x509::error_t established = ::ed25519(key, ed25519);
		// Если открытый ключ завести не удалось
		if(established != nts::x509::error_t::NONE)
			// Выводим отказ заведения открытого ключа
			return established;
		// Если подпись не занимает положенной длины
		if(signature.size != sign::ed25519_t::SIGNATURE_SIZE)
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Выводим итог проверки подписи: хеша нет, подписано само содержимое
		return (ed25519.check(content, signature) ? nts::x509::error_t::NONE : nts::x509::error_t::SIGNATURE);
	}
	/**
	 * @brief Метод проверки подписи Ed448 содержимого
	 *
	 * @param content   подписанное содержимое
	 * @param signature подпись содержимого
	 * @param key       сведения об открытом ключе подписавшей стороны
	 *
	 * @return          отказ проверки подписи
	 *
	 */
	static nts::x509::error_t ed448(const view_t & content, const view_t & signature, const nts::x509::key_t & key) noexcept {
		// Объект модуля электронной подписи
		sign::ed448_t ed448;
		// Итог заведения открытого ключа
		const nts::x509::error_t established = ::ed448(key, ed448);
		// Если открытый ключ завести не удалось
		if(established != nts::x509::error_t::NONE)
			// Выводим отказ заведения открытого ключа
			return established;
		// Если подпись не занимает положенной длины
		if(signature.size != sign::ed448_t::SIGNATURE_SIZE)
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Выводим итог проверки подписи: хеша нет, подписано само содержимое
		return (ed448.check(content, signature) ? nts::x509::error_t::NONE : nts::x509::error_t::SIGNATURE);
	}
	/**
	 * @brief Метод заведения открытого ключа ML-DSA в примитив
	 *
	 * @param key   сведения об открытом ключе подписавшей стороны
	 * @param mldsa примитив, в который заводится открытый ключ
	 *
	 * @return      отказ заведения открытого ключа
	 *
	 */
	static nts::x509::error_t mldsa(const nts::x509::key_t & key, sign::mldsa_t & mldsa) noexcept {
		// Набор параметров по опознавателю алгоритма
		sign::mldsa_t::set_t set = sign::mldsa_t::set_t::NONE;
		// Если алгоритм открытого ключа ML-DSA-44
		if(key.algorithm.compare(MLDSA44_KEY) == 0)
			// Устанавливаем набор ML-DSA-44
			set = sign::mldsa_t::set_t::DSA44;
		// Если алгоритм открытого ключа ML-DSA-65
		else if(key.algorithm.compare(MLDSA65_KEY) == 0)
			// Устанавливаем набор ML-DSA-65
			set = sign::mldsa_t::set_t::DSA65;
		// Если алгоритм открытого ключа ML-DSA-87
		else if(key.algorithm.compare(MLDSA87_KEY) == 0)
			// Устанавливаем набор ML-DSA-87
			set = sign::mldsa_t::set_t::DSA87;
		// Если алгоритм открытого ключа не ML-DSA
		else return nts::x509::error_t::KEY;
		// Если ключ несёт настройки, которых у алгоритма нет: раздел 5 RFC 9881
		if((key.parameters.data != nullptr) && (key.parameters.size != 0))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если запись открытого ключа занимает неполное число байтов либо не той длины
		if((key.unused != 0) || (key.key.data == nullptr) || (key.key.size != sign::mldsa_t::publicSize(set)))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Выводим итог установки открытого ключа подписавшей стороны
		return (mldsa.key(set, key.key) ? nts::x509::error_t::NONE : nts::x509::error_t::SIGNATURE);
	}
	/**
	 * @brief Метод проверки подписи ML-DSA
	 *
	 * @param content   подписанное содержимое
	 * @param signature проверяемая подпись c~ ‖ z ‖ h по набору
	 * @param key       сведения об открытом ключе подписавшей стороны
	 *
	 * @return          отказ проверки подписи
	 *
	 */
	static nts::x509::error_t mldsa(const view_t & content, const view_t & signature, const nts::x509::key_t & key) noexcept {
		// Объект модуля электронной подписи
		sign::mldsa_t mldsa;
		// Итог заведения открытого ключа
		const nts::x509::error_t established = ::mldsa(key, mldsa);
		// Если открытый ключ завести не удалось
		if(established != nts::x509::error_t::NONE)
			// Выводим отказ заведения открытого ключа
			return established;
		// Если подпись не занимает положенной набором длины
		if(signature.size != sign::mldsa_t::signatureSize(mldsa.set()))
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Выводим итог проверки подписи: хеша нет, подписано само содержимое, контекст пуст
		return (mldsa.check(content, view_t(nullptr, 0), signature) ? nts::x509::error_t::NONE : nts::x509::error_t::SIGNATURE);
	}
	/**
	 * @brief Метод заведения открытого ключа SLH-DSA в примитив
	 *
	 * @param key    сведения об открытом ключе подписавшей стороны
	 * @param slhdsa примитив, в который заводится открытый ключ
	 *
	 * @return       отказ заведения открытого ключа
	 *
	 */
	static nts::x509::error_t slhdsa(const nts::x509::key_t & key, sign::slhdsa_t & slhdsa) noexcept {
		// Набор параметров по опознавателю алгоритма
		sign::slhdsa_t::set_t set = sign::slhdsa_t::set_t::NONE;
		// Перебор опознавателей наборов SLH-DSA
		for(size_t i = 0; i < (sizeof(SLHDSA_KEYS) / sizeof(SLHDSA_KEYS[0])); i++){
			if(key.algorithm.compare(SLHDSA_KEYS[i]) == 0){
				// Устанавливаем набор по месту опознавателя
				set = SLHDSA_SETS[i];
				break;
			}
		}
		// Если алгоритм открытого ключа не SLH-DSA
		if(set == sign::slhdsa_t::set_t::NONE)
			// Выводим отказ ключа чужого алгоритма
			return nts::x509::error_t::KEY;
		// Если ключ несёт настройки, которых у алгоритма нет: раздел 4 RFC 9909
		if((key.parameters.data != nullptr) && (key.parameters.size != 0))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Если запись открытого ключа занимает неполное число байтов либо не той длины
		if((key.unused != 0) || (key.key.data == nullptr) || (key.key.size != sign::slhdsa_t::publicSize(set)))
			// Выводим отказ заведения открытого ключа
			return nts::x509::error_t::SIGNATURE;
		// Выводим итог установки открытого ключа подписавшей стороны
		return (slhdsa.key(set, key.key) ? nts::x509::error_t::NONE : nts::x509::error_t::SIGNATURE);
	}
	/**
	 * @brief Метод проверки подписи SLH-DSA
	 *
	 * @param content   подписанное содержимое
	 * @param signature проверяемая подпись R ‖ FORS ‖ HT по набору
	 * @param key       сведения об открытом ключе подписавшей стороны
	 *
	 * @return          отказ проверки подписи
	 *
	 */
	static nts::x509::error_t slhdsa(const view_t & content, const view_t & signature, const nts::x509::key_t & key) noexcept {
		// Объект модуля электронной подписи
		sign::slhdsa_t slhdsa;
		// Итог заведения открытого ключа
		const nts::x509::error_t established = ::slhdsa(key, slhdsa);
		// Если открытый ключ завести не удалось
		if(established != nts::x509::error_t::NONE)
			// Выводим отказ заведения открытого ключа
			return established;
		// Если подпись не занимает положенной набором длины
		if(signature.size != sign::slhdsa_t::signatureSize(slhdsa.set()))
			// Выводим отказ проверки подписи
			return nts::x509::error_t::SIGNATURE;
		// Выводим итог проверки подписи: хеша нет, подписано само содержимое, контекст пуст
		return (slhdsa.check(content, view_t(nullptr, 0), signature) ? nts::x509::error_t::NONE : nts::x509::error_t::SIGNATURE);
	}
};

/**
 * @brief Метод проверки подписи записи с настройками алгоритма подписи
 *
 * @param body       подписанная запись
 * @param signature  проверяемая подпись
 * @param algorithm  опознаватель алгоритма подписи
 * @param parameters запись настроек алгоритма подписи целиком либо пустой просмотр
 * @param key        сведения об открытом ключе подписавшей стороны
 *
 * @return           признак того, что подпись записи сошлась
 *
 */
nts::x509::error_t nts::x509::verify(const view_t & body, const view_t & signature, const string & algorithm, const view_t & parameters, const key_t & key) noexcept {
	// Если подписанная запись либо подпись не переданы
	if((body.data == nullptr) || (body.size == 0) || (signature.data == nullptr))
		// Выводим отказ проверки подписи
		return nts::x509::error_t::SIGNATURE;
	// Разыскиваем алгоритм подписи по опознавателю
	const record_t * record = lookup(algorithm);
	// Если алгоритм подписи неизвестен
	if(record == nullptr)
		// Выводим отказ проверки подписи
		return nts::x509::error_t::SIGNATURE;
	/**
	 * Выполняем проверку подписи по виду её алгоритма
	 */
	switch(record->kind){
		// Подпись по ГОСТ Р 34.10-2012
		case family_t::GOST:
			// Выводим итог проверки подписи ГОСТ: длина хеша задана алгоритмом
			return ::gost(body, signature, digest::length(record->hash), key);
		// Подпись ECDSA
		case family_t::ECDSA:
			// Выводим итог проверки подписи ECDSA
			return ::ecdsa(record->hash, body, signature, key);
		// Подпись RSA по схеме PKCS #1 v1.5
		case family_t::PKCS1:
			// Выводим итог проверки подписи RSA: соль схемой не используется
			return ::rsa(sign::scheme_t::PKCS1, record->hash, 0, body, signature, key);
		// Подпись RSA по схеме RSASSA-PSS
		case family_t::PSS: {
			// Алгоритм хеша подписи
			digest::hash_t hash = digest::hash_t::NONE;
			// Длина соли подписи
			size_t salt = 0;
			// Итог разбора настроек подписи
			const nts::x509::error_t outcome = settings(parameters, hash, salt);
			// Если настройки подписи разобрать не удалось
			if(outcome != nts::x509::error_t::NONE)
				// Выводим отказ разбора настроек подписи
				return outcome;
			// Если настройки ключа id-RSASSA-PSS подписи не дозволяют
			if(!bounded(key, hash, salt))
				// Выводим отказ проверки подписи
				return nts::x509::error_t::SIGNATURE;
			// Выводим итог проверки подписи RSA по схеме RSASSA-PSS
			return ::rsa(sign::scheme_t::PSS, hash, salt, body, signature, key);
		}
		// Подпись Ed25519
		case family_t::ED25519:
			// Выводим итог проверки подписи Ed25519
			return ::ed25519(body, signature, key);
		// Подпись Ed448
		case family_t::ED448:
			// Выводим итог проверки подписи Ed448
			return ::ed448(body, signature, key);
		// Подпись ML-DSA
		case family_t::MLDSA:
			// Выводим итог проверки подписи ML-DSA
			return ::mldsa(body, signature, key);
		// Подпись SLH-DSA
		case family_t::SLHDSA:
			// Выводим итог проверки подписи SLH-DSA
			return ::slhdsa(body, signature, key);
	}
	// Выводим отказ проверки подписи: вид алгоритма неизвестен
	return nts::x509::error_t::SIGNATURE;
}
/**
 * @brief Метод проверки голой подписи RSA PKCS #1 v1.5 над готовым хешем (TLS 1.1)
 *
 * @param digest    готовый хеш: 36 байтов MD5 ‖ SHA-1
 * @param signature проверяемая подпись
 * @param key       открытый ключ RSA из сертификата
 *
 * @return          отказ проверки подписи
 *
 */
nts::x509::error_t nts::x509::verify(const view_t & digest, const view_t & signature, const key_t & key) noexcept {
	// Если хеш либо подпись не переданы
	if((digest.data == nullptr) || (digest.size == 0) || (signature.data == nullptr) || (signature.size == 0))
		// Выводим отказ подписи
		return error_t::SIGNATURE;
	// Объект подписи RSA
	sign::rsa_t rsa;
	// Отказ заведения ключа: сырая подпись PKCS #1 v1.5 - ключ id-RSASSA-PSS негоден
	const error_t failure = ::rsa(key, rsa, false);
	// Если ключ завести не удалось
	if(failure != error_t::NONE)
		// Выводим отказ
		return failure;
	// Если длина подписи не равна модулю
	if(signature.size != rsa.size())
		// Выводим отказ подписи
		return error_t::SIGNATURE;
	// Выводим итог проверки голой подписи PKCS #1 v1.5
	return (rsa.check(sign::scheme_t::PKCS1, digest::hash_t::NONE, digest, signature, SIZE_MAX) ? error_t::NONE : error_t::SIGNATURE);
}
/**
 * @brief Метод проверки подписи записи
 *
 * @param body      подписанная запись
 * @param signature проверяемая подпись
 * @param algorithm опознаватель алгоритма подписи
 * @param key       сведения об открытом ключе подписавшей стороны
 *
 * @return          признак того, что подпись записи сошлась
 *
 */
nts::x509::error_t nts::x509::verify(const view_t & body, const view_t & signature, const string & algorithm, const key_t & key) noexcept {
	// Выводим итог проверки подписи записи без настроек алгоритма
	return nts::x509::verify(body, signature, algorithm, view_t(), key);
}
/**
 * @brief Метод извлечения опознавателя набора параметров кривой ключа
 *
 * @param key    сведения об открытом ключе, набор параметров которого извлекается
 * @param result строка, в которую помещается опознаватель набора параметров
 *
 * @return       отказ извлечения опознавателя
 *
 */
nts::x509::error_t nts::x509::identifier(const key_t & key, string & result) noexcept {
	// Если алгоритм ключа модулем не поддержан
	if(!suitable(key.algorithm))
		// Выводим отказ ключа чужого алгоритма
		return error_t::KEY;
	// Выводим итог извлечения опознавателя набора параметров
	return ::identifier(key.parameters, result);
}
/**
 * @brief Метод заведения кривой открытого ключа
 *
 * @param key    сведения об открытом ключе, кривая которого заводится
 * @param result кривая, в которую помещается набор параметров ключа
 *
 * @return       отказ заведения кривой открытого ключа
 *
 */
nts::x509::error_t nts::x509::parameters(const key_t & key, curve::curve_t & result) noexcept {
	// Если алгоритм ключа модулем не поддержан
	if(!suitable(key.algorithm))
		// Выводим отказ ключа чужого алгоритма
		return error_t::KEY;
	// Опознаватель набора параметров кривой ключа
	string oid;
	// Итог извлечения опознавателя набора параметров
	const error_t outcome = nts::x509::identifier(key, oid);
	// Если опознаватель набора параметров извлечь не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ извлечения опознавателя
		return outcome;
	// Выводим итог заведения кривой по опознавателю набора параметров
	return (curve::parameters(oid, result) ? error_t::NONE : error_t::KEY);
}
/**
 * @brief Метод проверки подписи содержимого открытым ключом
 *
 * @param key       сведения об открытом ключе подписавшей стороны
 * @param content   подписанное содержимое
 * @param signature проверяемая подпись, записанная числами r и s подряд
 *
 * @return          отказ проверки подписи содержимого
 *
 */
nts::x509::error_t nts::x509::check(const key_t & key, const view_t & content, const view_t & signature) noexcept {
	// Если подписанное содержимое либо подпись не переданы
	if((content.data == nullptr) || (content.size == 0) || (signature.data == nullptr))
		// Выводим отказ проверки подписи содержимого
		return nts::x509::error_t::SIGNATURE;
	// Эллиптическая кривая проверки подписи
	curve::curve_t curve;
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Итог заведения подписи по открытому ключу
	const nts::x509::error_t established = establish(key, curve, gost);
	// Если подпись по открытому ключу завести не удалось
	if(established != nts::x509::error_t::NONE)
		// Выводим отказ заведения подписи
		return established;
	// Если подпись не занимает двух чисел длиной в порядок подгруппы точек кривой
	if(signature.size != (curve.order().size() * 2))
		// Выводим отказ проверки подписи содержимого
		return nts::x509::error_t::SIGNATURE;
	// Место, в которое помещается хеш подписанного содержимого
	uint8_t digest[64];
	/**
	 * Длина хеша содержимого берётся размером координаты кривой открытого ключа:
	 * ключу длиной 256 разрядов отвечает хеш той же длины
	 */
	const digest::type_t type = (curve.size() == 32 ? digest::type_t::SHORT : digest::type_t::LONG);
	/**
	 * Хеш берётся записью вектором: подпись по ГОСТ Р 34.10-2012 толкует его числом,
	 * а не строкой байтов, и запись эта задана самим стандартом
	 */
	/**
	 * Заслон этот недостижим извне: длина хеша взята размером координаты кривой и
	 * выработке отвечает, а иных причин отказать у неё нет
	 */
	if(!digest::streebog(type, content, digest, curve.size(), digest::order_t::VECTOR))
		// Выводим отказ проверки подписи содержимого
		return nts::x509::error_t::SIGNATURE;
	// Выводим итог проверки подписи содержимого
	return (gost.check(view_t(digest, curve.size()), signature) ? nts::x509::error_t::NONE : nts::x509::error_t::SIGNATURE);
}
/**
 * @brief Метод проверки подписи содержимого открытым ключом с заданным хешем
 *
 * @param key       сведения об открытом ключе подписавшей стороны
 * @param algorithm алгоритм хеша подписанного содержимого
 * @param content   подписанное содержимое
 * @param signature проверяемая подпись в записи, отвечающей алгоритму ключа
 *
 * @return          отказ проверки подписи содержимого
 *
 */
nts::x509::error_t nts::x509::check(const key_t & key, const digest::hash_t algorithm, const view_t & content, const view_t & signature) noexcept {
	// Если подписанное содержимое либо подпись не переданы
	if((content.data == nullptr) || (content.size == 0) || (signature.data == nullptr))
		// Выводим отказ проверки подписи содержимого
		return nts::x509::error_t::SIGNATURE;
	// Если ключ подписи по ГОСТ Р 34.10-2012, алгоритм хеша задан самим ключом
	if(suitable(key.algorithm))
		// Выводим итог проверки подписи содержимого ключом ГОСТ
		return nts::x509::check(key, content, signature);
	// Если ключ эллиптической кривой, подпись записана набором SEQUENCE {r, s}
	if(key.algorithm.compare(EC_KEY) == 0){
		// Если хеш подписи - SM3: ключ на кривой curveSM2, и подпись идёт с опознавателем владения ключом по RFC 8998
		if(algorithm == digest::hash_t::SM3){
			// Опознаватель подписи владения ключом по RFC 8998
			static const char * ID = "TLSv1.3+GM+Cipher+Suite";
			// Выводим итог проверки подписи SM2
			return ::sm2(content, signature, key, view_t(reinterpret_cast <const uint8_t *> (ID), 22));
		}
		// Выводим итог проверки подписи ECDSA
		return ::ecdsa(algorithm, content, signature, key);
	}
	// Если ключ SM2, подпись идёт с опознавателем владения ключом по RFC 8998
	if(key.algorithm.compare(SM2_KEY) == 0){
		// Опознаватель подписи владения ключом по RFC 8998
		static const char * ID = "TLSv1.3+GM+Cipher+Suite";
		// Выводим итог проверки подписи SM2
		return ::sm2(content, signature, key, view_t(reinterpret_cast <const uint8_t *> (ID), 22));
	}
	// Если ключ RSA, подпись по схеме RSASSA-PSS с солью длиной в хеш: раздел 4.2.3 RFC 8446
	if((key.algorithm.compare(RSA_KEY) == 0) || (key.algorithm.compare(PSS_KEY) == 0)){
		// Если настройки ключа id-RSASSA-PSS подписи не дозволяют (раздел 3.3 RFC 4055)
		if(!bounded(key, algorithm, digest::length(algorithm)))
			// Выводим отказ проверки подписи содержимого
			return nts::x509::error_t::SIGNATURE;
		// Выводим итог проверки подписи RSA по схеме RSASSA-PSS
		return ::rsa(sign::scheme_t::PSS, algorithm, digest::length(algorithm), content, signature, key);
	}
	// Если ключ Ed25519, подпись сырая, а хеш не считается вовсе
	if(key.algorithm.compare(ED_KEY) == 0)
		// Выводим итог проверки подписи Ed25519
		return ::ed25519(content, signature, key);
	// Если ключ Ed448, подпись сырая, а хеш не считается вовсе
	if(key.algorithm.compare(ED448_KEY) == 0)
		// Выводим итог проверки подписи Ed448
		return ::ed448(content, signature, key);
	// Если ключ ML-DSA, подпись сырая, а хеш не считается вовсе
	if((key.algorithm.compare(MLDSA44_KEY) == 0) || (key.algorithm.compare(MLDSA65_KEY) == 0) || (key.algorithm.compare(MLDSA87_KEY) == 0))
		// Выводим итог проверки подписи ML-DSA: контекст пуст
		return ::mldsa(content, signature, key);
	// Выводим отказ ключа чужого алгоритма
	return nts::x509::error_t::KEY;
}
/**
 * @brief Метод проверки подписи сертификата
 *
 * @param certificate сертификат, подпись которого проверяется
 * @param key         сведения об открытом ключе издателя сертификата
 *
 * @return            признак того, что подпись сертификата сошлась
 *
 */
nts::x509::error_t nts::x509::verify(const certificate_t & certificate, const key_t & key) noexcept {
	// Число неиспользуемых разрядов последнего байта подписи
	uint8_t unused = 0;
	// Получаем подпись проверяемого сертификата
	const view_t & signature = certificate.sign(unused);
	// Если подпись сертификата занимает неполное число байтов
	if(unused != 0)
		// Выводим отказ проверки подписи сертификата
		return nts::x509::error_t::SIGNATURE;
	// Запись настроек алгоритма подписи сертификата
	view_t parameters;
	/**
	 * Заслон этот недостижим извне: тело сертификата уже разобрано разбором сертификата,
	 * и опознаватель алгоритма подписи в нём сверен с внешним. Стоит он ради связности
	 */
	if(!declared(certificate.body(), parameters))
		// Выводим отказ проверки подписи сертификата
		return nts::x509::error_t::SIGNATURE;
	// Выводим итог проверки подписи тела сертификата
	return nts::x509::verify(certificate.body(), signature, certificate.algorithms(), parameters, key);
}
