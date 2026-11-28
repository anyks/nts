/**
 * @file request.cpp
 * @date 2026-10-05
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
 * @brief Исходный файл модуля запроса на сертификат PKCS #10 —
 *        разбор и запись CertificationRequest по RFC 2986
 *
 * @note Запись подписи у запроса та же, что и у сертификата: подписываемая
 *       часть, опознаватель алгоритма и строка битов подписи. Проверка
 *       подписи переупотребляет модуль проверки подписи сертификата.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <string>
#include <vector>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include "sys/wipe.hpp"
#include "asn1/asn1.hpp"
#include "sign/rsa.hpp"
#include "sign/sm2.hpp"
#include "sign/gost.hpp"
#include "sign/ecdsa.hpp"
#include "sign/mldsa.hpp"
#include "sign/ed25519.hpp"
#include "entropy/entropy.hpp"
#include "x509/signature.hpp"

/**
 * Подключаем заголовочный файл модуля
 */
#include "x509/request.hpp"

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
	 * Пространство имён модуля
	 */
	using namespace nts::x509;

	/**
	 * Опознаватель алгоритма открытого ключа Ed25519: раздел 3 RFC 8410
	 */
	static constexpr const char * OID_ED25519 = "1.3.101.112";
	/**
	 * Опознаватель алгоритма открытого ключа эллиптической кривой: раздел 2.1.1 RFC 5480
	 */
	static constexpr const char * OID_EC = "1.2.840.10045.2.1";
	/**
	 * Опознаватель алгоритма открытого ключа ГОСТ Р 34.10-2001
	 */
	static constexpr const char * OID_GOST2001 = "1.2.643.2.2.19";
	/**
	 * Опознаватель алгоритма открытого ключа SM2: GB/T 32918 и RFC 8998
	 */
	static constexpr const char * OID_SM2 = "1.2.156.10197.1.301";
	/**
	 * Опознаватель алгоритма подписи Ed25519: раздел 3 RFC 8410
	 */
	static constexpr const char * OID_ED25519_SIGN = "1.3.101.112";
	/**
	 * Опознаватель алгоритма открытого ключа RSA: раздел 2.3.1 RFC 3279
	 */
	static constexpr const char * OID_RSA = "1.2.840.113549.1.1.1";
	/**
	 * Опознаватель алгоритма открытого ключа ГОСТ Р 34.10-2012 длиной 256 разрядов
	 */
	static constexpr const char * OID_GOST256 = "1.2.643.7.1.1.1.1";
	/**
	 * Опознаватель алгоритма открытого ключа ГОСТ Р 34.10-2012 длиной 512 разрядов
	 */
	static constexpr const char * OID_GOST512 = "1.2.643.7.1.1.1.2";
	/**
	 * Опознаватель алгоритма подписи SM2 с хешем SM3: RFC 8998
	 */
	static constexpr const char * OID_SM2_SIGN = "1.2.156.10197.1.501";
	/**
	 * Опознаватель алгоритма подписи RSA PKCS #1 v1.5 с хешем SHA-1: раздел 2.2.1 RFC 3279
	 */
	static constexpr const char * OID_SHA1_RSA = "1.2.840.113549.1.1.5";
	/**
	 * Опознаватель алгоритма подписи ГОСТ Р 34.10-2012 с хешем 256 разрядов
	 */
	static constexpr const char * OID_GOST256_SIGN = "1.2.643.7.1.1.3.2";
	/**
	 * Опознаватель алгоритма подписи ГОСТ Р 34.10-2012 с хешем 512 разрядов
	 */
	static constexpr const char * OID_GOST512_SIGN = "1.2.643.7.1.1.3.3";
	/**
	 * Опознаватель алгоритма открытого ключа ML-DSA-44: раздел 5 RFC 9881
	 */
	static constexpr const char * OID_MLDSA44 = "2.16.840.1.101.3.4.3.17";
	/**
	 * Опознаватель алгоритма открытого ключа ML-DSA-65: раздел 5 RFC 9881
	 */
	static constexpr const char * OID_MLDSA65 = "2.16.840.1.101.3.4.3.18";
	/**
	 * Опознаватель алгоритма открытого ключа ML-DSA-87: раздел 5 RFC 9881
	 */
	static constexpr const char * OID_MLDSA87 = "2.16.840.1.101.3.4.3.19";
	/**
	 * Опознаватель алгоритма подписи ECDSA с хешем SHA-384
	 */
	static constexpr const char * OID_SHA384_ECDSA = "1.2.840.10045.4.3.3";
	/**
	 * Опознаватель алгоритма подписи ECDSA с хешем SHA-512
	 */
	static constexpr const char * OID_SHA512_ECDSA = "1.2.840.10045.4.3.4";
	/**
	 * Опознаватель алгоритма подписи ECDSA с хешем SHA-256
	 */
	static constexpr const char * OID_SHA256_ECDSA = "1.2.840.10045.4.3.2";
	/**
	 * Опознаватель алгоритма подписи RSA PKCS #1 v1.5 с хешем SHA-256: раздел 5 RFC 4055
	 */
	static constexpr const char * OID_SHA256_RSA = "1.2.840.113549.1.1.11";
	/**
	 * Опознаватель алгоритма подписи RSA PKCS #1 v1.5 с хешем SHA-384
	 */
	static constexpr const char * OID_SHA384_RSA = "1.2.840.113549.1.1.12";
	/**
	 * Опознаватель алгоритма подписи RSA PKCS #1 v1.5 с хешем SHA-512
	 */
	static constexpr const char * OID_SHA512_RSA = "1.2.840.113549.1.1.13";
	/**
	 * Опознаватель алгоритма подписи RSA PKCS #1 v1.5 с хешем SHA-224
	 */
	static constexpr const char * OID_SHA224_RSA = "1.2.840.113549.1.1.14";
	/**
	 * Опознаватель алгоритма подписи ECDSA с хешем SHA-224: раздел 3.2 RFC 5758
	 */
	static constexpr const char * OID_SHA224_ECDSA = "1.2.840.10045.4.3.1";
	/**
	 * Опознаватель алгоритма подписи ML-DSA-44: раздел 4 RFC 9881
	 */
	static constexpr const char * OID_MLDSA44_SIGN = "2.16.840.1.101.3.4.3.17";
	/**
	 * Опознаватель алгоритма подписи ML-DSA-65
	 */
	static constexpr const char * OID_MLDSA65_SIGN = "2.16.840.1.101.3.4.3.18";
	/**
	 * Опознаватель алгоритма подписи ML-DSA-87
	 */
	static constexpr const char * OID_MLDSA87_SIGN = "2.16.840.1.101.3.4.3.19";
	/**
	 * Опознаватель атрибута extensionRequest: раздел 5.4.2 RFC 2985
	 */
	static constexpr const char * OID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14";

	/**
	 * @brief Функция перевода отказа разборщика ASN.1 в отказ модуля
	 *
	 * @param error отказ разборщика ASN.1
	 * @return      отказ модуля
	 *
	 */
	static constexpr nts::x509::error_t __nts_translate__(const asn1::error_t error) noexcept {
		// Выводим отказ модуля: нехватка памяти отдаётся своим отказом, всё прочее - отказом устройства
		return ((error == asn1::error_t::MEMORY) ? nts::x509::error_t::MEMORY : nts::x509::error_t::STRUCTURE);
	}
	/**
	 * @brief Функция разбора опознавателя объекта
	 *
	 * @param element разбираемый элемент
	 * @param result  место, в которое помещается опознаватель
	 * @return        отказ разбора опознавателя
	 *
	 */
	static __NTS_INLINE__ nts::x509::error_t __nts_oid_of__(const asn1::element_t & element, string & result) noexcept {
		// Итог разбора опознавателя
		const asn1::error_t outcome = asn1::oid(element, result);
		// Выводим переведённый отказ разбора, если он есть
		return ((outcome == asn1::error_t::NONE) ? nts::x509::error_t::NONE : __nts_translate__(outcome));
	}
	/**
	 * @brief Функция разбора малого целого числа
	 *
	 * @param element разбираемый элемент
	 * @param result  место, в которое помещается число
	 * @return        отказ разбора числа
	 *
	 */
	static __NTS_INLINE__ nts::x509::error_t __nts_small_integer__(const asn1::element_t & element, int64_t & result) noexcept {
		// Итог разбора целого числа
		const asn1::error_t outcome = asn1::integer(element, result);
		// Выводим переведённый отказ разбора, если он есть
		return ((outcome == asn1::error_t::NONE) ? nts::x509::error_t::NONE : __nts_translate__(outcome));
	}
	/**
	 * @brief Функция разбора записи опознавателя алгоритма
	 *
	 * @param reader разборщик, из которого читается запись
	 * @param oid    место, в которое помещается опознаватель алгоритма
	 * @param params место, в которое помещается запись настроек алгоритма
	 * @param present место, в которое помещается признак наличия настроек
	 * @return       отказ разбора записи
	 *
	 */
	static __NTS_INLINE__ nts::x509::error_t __nts_algorithm_identifier__(asn1::reader_t & reader, string & oid, asn1::element_t & params, bool & present) noexcept {
		// Сбрасываем признак наличия настроек
		present = false;
		// Набор алгоритма
		asn1::element_t element;
		// Если набор алгоритма разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, element) || !element.constructed)
			// Выводим переведённый отказ разбора
			return __nts_translate__(reader.err());
		// Разборщик содержимого набора алгоритма
		asn1::reader_t items = reader.enter(element);
		// Если опознаватель алгоритма разобрать не удалось
		if(!items.next(asn1::tag_t::OBJECT, element))
			// Выводим переведённый отказ разбора
			return __nts_translate__(items.err());
		// Итог разбора опознавателя алгоритма
		const nts::x509::error_t outcome = __nts_oid_of__(element, oid);
		// Если опознаватель алгоритма разобрать не удалось
		if(outcome != nts::x509::error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Если настройки алгоритма записаны
		if(!items.empty()){
			// Если настройки алгоритма разобрать не удалось
			if(!items.next(params))
				// Выводим переведённый отказ разбора
				return __nts_translate__(items.err());
			// Устанавливаем признак наличия настроек
			present = true;
			// Если после настроек остался хвост
			if(!items.empty())
				// Выводим отказ устройства записи
				return nts::x509::error_t::STRUCTURE;
		}
		// Выводим успешность разбора опознавателя алгоритма
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Функция записи опознавателя объекта из строки знаков
	 *
	 * @param writer записчик, в который помещается опознаватель
	 * @param value  записываемый опознаватель строкой знаков
	 * @return       отказ записи опознавателя
	 *
	 */
	static __NTS_INLINE__ nts::x509::error_t __nts_object__(asn1::writer_t & writer, const char * value) noexcept {
		// Опознаватель строкой
		string oid;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Копирование опознавателя
			oid.assign(value);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return nts::x509::error_t::MEMORY;
		}
		// Записываем опознаватель объекта
		writer.oid(oid);
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? nts::x509::error_t::NONE : __nts_translate__(writer.err()));
	}
	/**
	 * @brief Функция записи набора алгоритма ключа
	 *
	 * @param writer записчик, в который помещается набор алгоритма
	 * @param key    записываемый ключ
	 * @return       отказ записи набора алгоритма
	 *
	 */
	static __NTS_INLINE__ nts::x509::error_t __nts_key_algorithm__(asn1::writer_t & writer, const nts::x509::key_t & key) noexcept {
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Если ключ RSA
		if(key.algorithm.compare(OID_RSA) == 0){
			// Записываем опознаватель алгоритма
			__nts_object__(writer, OID_RSA);
			// Записываем пустые настройки: раздел 2.3.1 RFC 3279
			writer.nothing();
		// Если ключ EC
		} else if(key.algorithm.compare(OID_EC) == 0) {
			// Записываем опознаватель алгоритма
			__nts_object__(writer, OID_EC);
			// Записываем именованную кривую из настроек ключа
			if((key.parameters.data != nullptr) && (key.parameters.size != 0)){
				// Разборщик настроек ключа
				asn1::reader_t reader(key.parameters);
				// Элемент настроек
				asn1::element_t element;
				// Если опознаватель кривой разобрать не удалось
				if(!reader.next(asn1::tag_t::OBJECT, element))
					// Выводим отказ ключа
					return nts::x509::error_t::KEY;
				// Опознаватель кривой
				string oid = "";
				// Итог разбора опознавателя кривой
				const nts::x509::error_t outcome = __nts_oid_of__(element, oid);
				// Если опознаватель кривой разобрать не удалось
				if(outcome != nts::x509::error_t::NONE)
					// Выводим отказ разбора
					return outcome;
				// Записываем опознаватель кривой
				writer.oid(oid);
			// Если настроек нет
			} else return nts::x509::error_t::KEY;
		// Если ключ Ed25519
		} else if(key.algorithm.compare(OID_ED25519) == 0)
			// Записываем опознаватель алгоритма: настроек у него нет
			__nts_object__(writer, OID_ED25519);
		// Если ключ SM2
		else if(key.algorithm.compare(OID_SM2) == 0)
			// Записываем опознаватель алгоритма: настроек у него нет
			__nts_object__(writer, OID_SM2);
		// Если ключ ML-DSA
		else if((key.algorithm.compare(OID_MLDSA44) == 0) || (key.algorithm.compare(OID_MLDSA65) == 0) || (key.algorithm.compare(OID_MLDSA87) == 0))
			// Записываем опознаватель алгоритма ключа: настроек у него нет
			writer.oid(key.algorithm);
		// Если ключ ГОСТ
		else if((key.algorithm.compare(OID_GOST256) == 0) || (key.algorithm.compare(OID_GOST512) == 0) || (key.algorithm.compare(OID_GOST2001) == 0)){
			// Записываем опознаватель алгоритма
			writer.oid(key.algorithm);
			// Открываем набор настроек
			writer.open(asn1::tag_t::SEQUENCE);
			// Записываем опознаватель кривой из настроек ключа
			if((key.parameters.data != nullptr) && (key.parameters.size != 0)){
				// Разборщик настроек ключа
				asn1::reader_t reader(key.parameters);
				// Элемент настроек
				asn1::element_t element;
				// Если опознаватель кривой разобрать не удалось
				if(!reader.next(asn1::tag_t::OBJECT, element))
					// Выводим отказ ключа
					return nts::x509::error_t::KEY;
				// Опознаватель кривой
				string oid = "";
				// Итог разбора опознавателя кривой
				const nts::x509::error_t outcome = __nts_oid_of__(element, oid);
				// Если опознаватель кривой разобрать не удалось
				if(outcome != nts::x509::error_t::NONE)
					// Выводим отказ разбора
					return outcome;
				// Записываем опознаватель кривой
				writer.oid(oid);
				// Если опознаватель хеша записан
				if(!reader.empty()){
					// Если опознаватель хеша разобрать не удалось
					if(!reader.next(asn1::tag_t::OBJECT, element))
						// Выводим отказ ключа
						return nts::x509::error_t::KEY;
					// Опознаватель хеша
					string digest = "";
					// Итог разбора опознавателя хеша
					const nts::x509::error_t extracted = __nts_oid_of__(element, digest);
					// Если опознаватель хеша разобрать не удалось
					if(extracted != nts::x509::error_t::NONE)
						// Выводим отказ разбора
						return extracted;
					// Записываем опознаватель хеша
					writer.oid(digest);
				}
			// Если настроек нет
			} else return nts::x509::error_t::KEY;
			// Закрываем набор настроек
			writer.close();
		// Если алгоритм ключа неизвестен
		} else return nts::x509::error_t::KEY;
		// Закрываем набор алгоритма
		writer.close();
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? nts::x509::error_t::NONE : __nts_translate__(writer.err()));
	}
	/**
	 * @brief Функция записи тела открытого ключа
	 *
	 * @param key    записываемый ключ
	 * @param writer записчик, в который помещается тело ключа
	 * @return       отказ записи тела ключа
	 *
	 */
	static __NTS_INLINE__ nts::x509::error_t __nts_key_body__(const nts::x509::key_t & key, asn1::writer_t & writer) noexcept {
		// Если ключ RSA
		if(key.algorithm.compare(OID_RSA) == 0){
			// Если запись ключа не передана
			if((key.key.data == nullptr) || (key.key.size == 0))
				// Выводим отказ ключа
				return nts::x509::error_t::KEY;
			// Записываем строку битов ключа
			writer.bits(key.key);
		// Если ключ EC либо SM2
		} else if((key.algorithm.compare(OID_EC) == 0) || (key.algorithm.compare(OID_SM2) == 0)) {
			// Если запись ключа не передана
			if((key.key.data == nullptr) || (key.key.size == 0))
				// Выводим отказ ключа
				return nts::x509::error_t::KEY;
			// Записываем строку битов ключа
			writer.bits(key.key);
		// Если ключ Ed25519 либо ML-DSA
		} else if((key.algorithm.compare(OID_ED25519) == 0) || (key.algorithm.compare(OID_MLDSA44) == 0) ||
		          (key.algorithm.compare(OID_MLDSA65) == 0) || (key.algorithm.compare(OID_MLDSA87) == 0)) {
			// Если запись ключа не передана
			if((key.key.data == nullptr) || (key.key.size == 0))
				// Выводим отказ ключа
				return nts::x509::error_t::KEY;
			// Записываем строку битов ключа
			writer.bits(key.key);
		// Если ключ ГОСТ
		} else if((key.algorithm.compare(OID_GOST256) == 0) ||
		          (key.algorithm.compare(OID_GOST512) == 0) ||
				  (key.algorithm.compare(OID_GOST2001) == 0)) {
			// Если запись ключа не передана
			if((key.key.data == nullptr) || (key.key.size == 0))
				// Выводим отказ ключа
				return nts::x509::error_t::KEY;
			// Записываем строку битов ключа
			writer.bits(key.key);
		// Если алгоритм ключа неизвестен
		} else return nts::x509::error_t::KEY;
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? nts::x509::error_t::NONE : __nts_translate__(writer.err()));
	}
	/**
	 * @brief Функция разбора отличительного имени
	 *
	 * @note Разборщик повторяет разборщик имени сертификата: запрос несёт имя
	 *       по тем же правилам X.501, и негодная запись отвергается так же строго
	 *
	 * @param element разбираемый элемент записи имени
	 * @param result  объект имени, в который производится разбор
	 * @return        причина отказа либо nts::x509::error_t::NONE
	 *
	 */
	static __NTS_INLINE__ nts::x509::error_t __nts_distinguished__(const asn1::element_t & element, nts::x509::name_t & result) noexcept {
		// Если запись имени имеет простой вид метки
		if(!element.constructed)
			// Выводим причину отказа
			return nts::x509::error_t::STRUCTURE;
		// Запоминаем запись имени целиком
		result.element = element.element;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Создаём разборщик содержимого записи имени
			asn1::reader_t reader(element.content);
			/**
			 * Обходим составляющие имени
			 */
			while(!reader.empty()){
				// Объект разобранной составляющей имени
				asn1::element_t item;
				// Разбор составляющей имени
				if(!reader.next(asn1::tag_t::SET, item))
					// Выводим причину отказа
					return nts::x509::error_t::ENCODING;
				// Если составляющая имени имеет простой вид метки
				if(!item.constructed)
					// Выводим причину отказа
					return nts::x509::error_t::STRUCTURE;
				// Создаём разборщик содержимого составляющей имени
				asn1::reader_t items(item.content);
				/**
				 * Составляющая имени без единого признака устройством имени запрещена:
				 * пустая составляющая ничего не обозначает, но участвует в сличении имён
				 */
				if(items.empty())
					// Выводим причину отказа
					return nts::x509::error_t::NAME;
				// Набор признаков составляющей имени
				vector <nts::x509::attribute_t> part;
				/**
				 * Обходим признаки составляющей имени
				 */
				while(!items.empty()){
					// Объект разобранного признака
					asn1::element_t pair;
					// Разбор признака
					if(!items.next(asn1::tag_t::SEQUENCE, pair))
						// Выводим причину отказа
						return nts::x509::error_t::ENCODING;
					// Если признак имеет простой вид метки
					if(!pair.constructed)
						// Выводим причину отказа
						return nts::x509::error_t::STRUCTURE;
					// Создаём разборщик содержимого признака
					asn1::reader_t fields(pair.content);
					// Объект разобранного поля признака
					asn1::element_t field;
					// Разбираемый признак имени
					nts::x509::attribute_t attribute;
					// Разбор опознавателя признака
					if(!fields.next(asn1::tag_t::OBJECT, field))
						// Выводим причину отказа
						return nts::x509::error_t::ENCODING;
					// Итог извлечения опознавателя признака
					const asn1::error_t named = asn1::oid(field, attribute.oid);
					// Если память под опознаватель признака выделить не удалось
					if(named == asn1::error_t::MEMORY)
						// Выводим отказ нехватки памяти
						return nts::x509::error_t::MEMORY;
					// Если извлечение опознавателя признака не удалось
					if(named != asn1::error_t::NONE)
						// Выводим причину отказа
						return nts::x509::error_t::NAME;
					// Разбор значения признака
					if(!fields.next(field))
						// Выводим причину отказа
						return nts::x509::error_t::ENCODING;
					// Если значение признака записано меткой не универсального класса
					if(field.cls != asn1::cls_t::UNIVERSAL)
						// Выводим причину отказа
						return nts::x509::error_t::NAME;
					// Запоминаем вид записи значения признака
					attribute.type = static_cast <asn1::tag_t> (field.tag);
					// Итог извлечения значения признака
					const asn1::error_t valued = asn1::text(field, attribute.type, attribute.value);
					// Если память под значение признака выделить не удалось
					if(valued == asn1::error_t::MEMORY)
						// Выводим отказ нехватки памяти
						return nts::x509::error_t::MEMORY;
					// Если извлечение значения признака не удалось
					if(valued != asn1::error_t::NONE)
						// Выводим причину отказа
						return nts::x509::error_t::NAME;
					// Если после значения признака остались лишние поля
					if(!fields.empty())
						// Выводим причину отказа
						return nts::x509::error_t::STRUCTURE;
					/**
					 * Раздел 4.1.2.4 RFC 5280 и X.501: признаки одной составляющей имени
					 * различны по виду, повтор вида - оплошность записи
					 */
					for(size_t i = 0; i < part.size(); i++){
						// Если признак такого вида в составляющей уже есть
						if(part[i].oid.compare(attribute.oid) == 0)
							// Выводим отказ повторного признака
							return nts::x509::error_t::DUPLICATE;
					}
					// Добавляем признак в набор признаков составляющей
					part.push_back(attribute);
				}
				// Добавляем составляющую в набор составляющих имени
				result.parts.push_back(part);
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим причину отказа
			return nts::x509::error_t::MEMORY;
		}
		// Выводим успешность разбора
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Функция записи имени
	 *
	 * @param writer записчик, в который помещается имя
	 * @param name   записываемое имя
	 * @return       отказ записи имени
	 *
	 */
	static __NTS_INLINE__ nts::x509::error_t __nts_name_body__(asn1::writer_t & writer, const nts::x509::name_t & name) noexcept {
		// Если имя пусто
		if(name.parts.empty())
			// Выводим отказ имени
			return nts::x509::error_t::NAME;
		// Открываем набор имени
		writer.open(asn1::tag_t::SEQUENCE);
		/**
		 * Перебираем составляющие имени
		 */
		for(size_t i = 0; i < name.parts.size(); i++){
			// Если составляющая пуста
			if(name.parts[i].empty())
				// Выводим отказ имени
				return nts::x509::error_t::NAME;
			// Открываем составляющую имени
			writer.open(asn1::tag_t::SET);
			/**
			 * Перебираем признаки составляющей
			 */
			for(size_t j = 0; j < name.parts[i].size(); j++){
				// Открываем признак
				writer.open(asn1::tag_t::SEQUENCE);
				// Записываем опознаватель признака
				writer.oid(name.parts[i][j].oid);
				// Записываем значение признака
				writer.text(name.parts[i][j].type, name.parts[i][j].value);
				// Закрываем признак
				writer.close();
			}
			// Закрываем составляющую имени
			writer.close();
		}
		// Закрываем набор имени
		writer.close();
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? nts::x509::error_t::NONE : __nts_translate__(writer.err()));
	}
	/**
	 * @brief Функция записи набора расширений
	 *
	 * @param writer     записчик, в который помещается набор расширений
	 * @param extensions записываемый набор расширений
	 * @return           отказ записи набора расширений
	 *
	 */
	static __NTS_INLINE__ nts::x509::error_t __nts_extensions_body__(asn1::writer_t & writer, const vector <nts::x509::extension_t> & extensions) noexcept {
		// Открываем набор расширений
		writer.open(asn1::tag_t::SEQUENCE);
		/**
		 * Перебираем расширения
		 */
		for(size_t i = 0; i < extensions.size(); i++){
			// Открываем расширение
			writer.open(asn1::tag_t::SEQUENCE);
			// Записываем опознаватель расширения
			writer.oid(extensions[i].oid);
			// Если расширение критично
			if(extensions[i].critical)
				// Записываем признак критичности
				writer.boolean(true);
			// Записываем содержимое расширения
			writer.octets(extensions[i].value);
			// Закрываем расширение
			writer.close();
		}
		// Закрываем набор расширений
		writer.close();
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? nts::x509::error_t::NONE : __nts_translate__(writer.err()));
	}
	/**
	 * @brief Функция выработки подписи содержимого ключом
	 *
	 * @param signer    подготовленный секретный ключ подписи
	 * @param hash      алгоритм хеша подписи (для ECDSA и RSA)
	 * @param content   подписываемое содержимое
	 * @param signature место, в которое помещается подпись
	 * @return          отказ выработки подписи
	 *
	 */
	static __NTS_INLINE__ nts::x509::error_t __nts_make_signature__(const keys::signer_t & signer, const digest::hash_t hash, const view_t & content, vector <uint8_t> & signature) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			/**
			 * Определяем вид ключа подписи
			 */
			switch(static_cast <uint8_t> (signer.kind())){
				// Ключ RSA
				case static_cast <uint8_t> (keys::kind_t::RSA): {
					// Модуль подписи RSA
					const sign::rsa_t & rsa = signer.rsa();
					// Место, в которое помещается хеш содержимого
					uint8_t digest[64];
					// Если хеш содержимого выработать не удалось
					if(!digest::hash(hash, content, digest, sizeof(digest)))
						// Выводим отказ подписи
						return nts::x509::error_t::SIGNATURE;
					// Занимаем место под подпись длиною в модуль ключа
					signature.assign(rsa.size(), 0);
					// Если подпись выработать не удалось
					if(!rsa.make(sign::scheme_t::PKCS1, hash, view_t(digest, digest::length(hash)), signature.data(), SIZE_MAX))
						// Выводим отказ подписи
						return nts::x509::error_t::SIGNATURE;
				} break;
				// Ключ ECDSA
				case static_cast <uint8_t> (keys::kind_t::EC): {
					// Модуль подписи ECDSA
					const sign::ecdsa_t & ecdsa = signer.ecdsa();
					// Место, в которое помещается хеш содержимого
					uint8_t digest[64];
					// Если хеш содержимого выработать не удалось
					if(!digest::hash(hash, content, digest, sizeof(digest)))
						// Выводим отказ подписи
						return nts::x509::error_t::SIGNATURE;
					// Место, в которое помещается подпись в сыром виде
					uint8_t raw[math::NUMBER_SIZE * 2];
					// Если подпись выработать не удалось
					if(!ecdsa.make(hash, view_t(digest, digest::length(hash)), raw))
						// Выводим отказ подписи
						return nts::x509::error_t::SIGNATURE;
					// Занимаем место под запись подписи по её пределу
					signature.assign(ecdsa.limit(), 0);
					// Длина записи подписи
					size_t written = signature.size();
					// Если подпись в запись DER перевести не удалось
					if(!sign::encode(view_t(raw, ecdsa.size()), signature.data(), written))
						// Выводим отказ подписи
						return nts::x509::error_t::SIGNATURE;
					// Усекаем запись до её длины
					signature.resize(written);
				} break;
				// Ключ Ed25519
				case static_cast <uint8_t> (keys::kind_t::ED25519): {
					// Модуль подписи Ed25519
					const sign::ed25519_t & ed25519 = signer.ed25519();
					// Занимаем место под подпись Ed25519
					signature.assign(sign::ed25519_t::SIGNATURE_SIZE, 0);
					// Если подпись выработать не удалось
					if(!ed25519.make(content, signature.data()))
						// Выводим отказ подписи
						return nts::x509::error_t::SIGNATURE;
				} break;
				// Ключ ГОСТ
				case static_cast <uint8_t> (keys::kind_t::GOST): {
					// Модуль подписи ГОСТ
					const sign::gost_t & gost = signer.gost();
					// Длина числа кривой ключа
					const size_t size = signer.curve().size();
					// Место, в которое помещается хеш содержимого
					uint8_t digest[64];
					// Определяем длину хеша содержимого
					const digest::type_t type = ((size == 32) ? digest::type_t::SHORT : digest::type_t::LONG);
					// Если хеш содержимого выработать не удалось
					if(!digest::streebog(type, content, digest, size, digest::order_t::VECTOR))
						// Выводим отказ подписи
						return nts::x509::error_t::SIGNATURE;
					// Место, в которое помещается подпись в сыром виде
					uint8_t raw[math::NUMBER_SIZE * 2];
					// Если подпись выработать не удалось
					if(!gost.make(view_t(digest, size), raw))
						// Выводим отказ подписи
						return nts::x509::error_t::SIGNATURE;
					// Занимаем место под подпись: сперва s, затем r (раздел 2 RFC 9215)
					signature.assign(gost.size(), 0);
					// Переносим s
					::memcpy(signature.data(), raw + size, size);
					// Переносим r
					::memcpy(signature.data() + size, raw, size);
				} break;
				// Ключ ML-DSA
				case static_cast <uint8_t> (keys::kind_t::MLDSA): {
					// Модуль подписи ML-DSA
					const sign::mldsa_t & mldsa = signer.mldsa();
					// Занимаем место под подпись набора ключа
					signature.assign(mldsa.size(), 0);
					// Если подпись выработать не удалось: контекст пуст
					if(!mldsa.make(content, view_t(nullptr, 0), signature.data()))
						// Выводим отказ подписи
						return nts::x509::error_t::SIGNATURE;
				} break;
				// Ключ SM2
				case static_cast <uint8_t> (keys::kind_t::SM2): {
					// Модуль подписи SM2
					const sign::sm2_t & sm2ctx = signer.sm2();
					// Опознаватель подписи сертификата по RFC 8998
					static const char * ID = "1234567812345678";
					// Если опознаватель подписи установить не удалось
					if(!sm2ctx.reidentify(view_t(reinterpret_cast <const uint8_t *> (ID), 16)))
						// Выводим отказ подписи
						return nts::x509::error_t::SIGNATURE;
					// Место, в которое помещается подпись в сыром виде
					uint8_t raw[64];
					// Случайное число выработки подписи
					uint8_t random[32];
					// Признак успешности выработки подписи
					bool made = false;
					/**
					 * GB/T 32918.2: неудачный выбор случайного числа велит выбрать новое
					 */
					for(size_t attempt = 0; !made && (attempt < 128); attempt++){
						// Если случайное число выработать не удалось
						if(!entropy::bytes(random, sizeof(random)))
							// Выводим отказ подписи
							return nts::x509::error_t::SIGNATURE;
						// Выработка подписи
						made = sm2ctx.make(content, view_t(random, sizeof(random)), raw);
					}
					// Затирание случайного числа
					nts::sys::wipe(random, sizeof(random));
					// Если подпись выработать не удалось
					if(!made)
						// Выводим отказ подписи
						return nts::x509::error_t::SIGNATURE;
					// Занимаем место под запись подписи по её пределу
					signature.assign(72, 0);
					// Длина записи подписи
					size_t written = signature.size();
					// Если подпись в запись DER перевести не удалось
					if(!sign::encode(view_t(raw, sizeof(raw)), signature.data(), written))
						// Выводим отказ подписи
						return nts::x509::error_t::SIGNATURE;
					// Усекаем запись до её длины
					signature.resize(written);
				} break;
				// Ключ, подписи не выполняющий
				default:
					// Выводим отказ ключа
					return nts::x509::error_t::KEY;
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return nts::x509::error_t::MEMORY;
		}
		// Выводим успешность выработки подписи
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Функция получения опознавателя алгоритма подписи по виду ключа и хешу
	 *
	 * @param signer подготовленный секретный ключ подписи
	 * @param hash   алгоритм хеша подписи
	 * @return       опознаватель алгоритма подписи либо nullptr
	 *
	 */
	static __NTS_INLINE__ const char * __nts_signature_algorithm__(const keys::signer_t & signer, const digest::hash_t hash) noexcept {
		/**
		 * Определяем вид ключа подписи
		 */
		switch(static_cast <uint8_t> (signer.kind())){
			// Если ключ — RSA
			case static_cast <uint8_t> (keys::kind_t::RSA):
				/**
				 * Выводим опознаватель по хешу
				 */
				switch(static_cast <uint8_t> (hash)){
					// Если хеш — SHA-1
					case static_cast <uint8_t> (digest::hash_t::SHA1):
						// Выводим опознаватель подписи RSA с хешем SHA-1
						return OID_SHA1_RSA;
					// Если хеш — SHA-224
					case static_cast <uint8_t> (digest::hash_t::SHA224):
						// Выводим опознаватель подписи RSA с хешем SHA-224
						return OID_SHA224_RSA;
					// Если хеш — SHA-256
					case static_cast <uint8_t> (digest::hash_t::SHA256):
						// Выводим опознаватель подписи RSA с хешем SHA-256
						return OID_SHA256_RSA;
					// Если хеш — SHA-384
					case static_cast <uint8_t> (digest::hash_t::SHA384):
						// Выводим опознаватель подписи RSA с хешем SHA-384
						return OID_SHA384_RSA;
					// Если хеш — SHA-512
					case static_cast <uint8_t> (digest::hash_t::SHA512):
						// Выводим опознаватель подписи RSA с хешем SHA-512
						return OID_SHA512_RSA;
					// Если хеш не опознан, выводим отсутствие опознавателя
					default:
						return nullptr;
				}
			// Если ключ — ECDSA
			case static_cast <uint8_t> (keys::kind_t::EC):
				/**
				 * Выводим опознаватель по хешу
				 */
				switch(static_cast <uint8_t> (hash)){
					// Если хеш — SHA-224
					case static_cast <uint8_t> (digest::hash_t::SHA224):
						// Выводим опознаватель подписи ECDSA с хешем SHA-224
						return OID_SHA224_ECDSA;
					// Если хеш — SHA-256
					case static_cast <uint8_t> (digest::hash_t::SHA256):
						// Выводим опознаватель подписи ECDSA с хешем SHA-256
						return OID_SHA256_ECDSA;
					// Если хеш — SHA-384
					case static_cast <uint8_t> (digest::hash_t::SHA384):
						// Выводим опознаватель подписи ECDSA с хешем SHA-384
						return OID_SHA384_ECDSA;
					// Если хеш — SHA-512
					case static_cast <uint8_t> (digest::hash_t::SHA512):
						// Выводим опознаватель подписи ECDSA с хешем SHA-512
						return OID_SHA512_ECDSA;
					// Если хеш не опознан, выводим отсутствие опознавателя
					default:
						return nullptr;
				}
			// Если ключ — Ed25519
			case static_cast <uint8_t> (keys::kind_t::ED25519):
				// Выводим опознаватель подписи Ed25519
				return OID_ED25519_SIGN;
			// Если ключ — ГОСТ
			case static_cast <uint8_t> (keys::kind_t::GOST):
				// Выводим опознаватель подписи ГОСТ по размеру кривой
				return ((signer.curve().size() == 32) ? OID_GOST256_SIGN : OID_GOST512_SIGN);
			// Если ключ — ML-DSA
			case static_cast <uint8_t> (keys::kind_t::MLDSA):
				/**
				 * Выводим опознаватель по набору ключа
				 */
				switch(static_cast <uint8_t> (signer.mldsa().set())){
					// Если набор — ML-DSA-44
					case static_cast <uint8_t> (sign::mldsa_t::set_t::DSA44):
						// Выводим опознаватель подписи ML-DSA-44
						return OID_MLDSA44_SIGN;
					// Если набор — ML-DSA-65
					case static_cast <uint8_t> (sign::mldsa_t::set_t::DSA65):
						// Выводим опознаватель подписи ML-DSA-65
						return OID_MLDSA65_SIGN;
					// Если набор — ML-DSA-87
					case static_cast <uint8_t> (sign::mldsa_t::set_t::DSA87):
						// Выводим опознаватель подписи ML-DSA-87
						return OID_MLDSA87_SIGN;
					// Если набор не опознан, выводим отсутствие опознавателя
					default:
						return nullptr;
				}
			// Если ключ — SM2
			case static_cast <uint8_t> (keys::kind_t::SM2):
				// Выводим опознаватель подписи SM2
				return OID_SM2_SIGN;
			// Если ключ не из числа подписывающих, выводим отсутствие опознавателя
			default:
				return nullptr;
		}
	}
};

/**
 * @brief Метод разбора записи запроса на сертификат
 *
 * @param data просмотр разбираемой записи запроса
 * @return     причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::Request::parse(const view_t & data) noexcept {
	// Очистка разобранных сведений
	this->clear();
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Создаём разборщик записи запроса
		asn1::reader_t reader(data);
		// Объект разобранной записи запроса
		asn1::element_t request;
		// Разбор записи запроса
		if(!reader.next(asn1::tag_t::SEQUENCE, request))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если после записи остались лишние байты либо запись не составная
		if(!reader.empty() || !request.constructed)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Запоминаем запись запроса целиком
		this->_element = request.element;
		// Создаём разборщик содержимого записи запроса
		asn1::reader_t top(request.content);
		// Объект разобранной подписываемой части запроса
		asn1::element_t body;
		// Разбор подписываемой части запроса
		if(!top.next(asn1::tag_t::SEQUENCE, body))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если подписываемая часть не составная
		if(!body.constructed)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Запоминаем подписываемую часть запроса
		this->_body = body.element;
		// Объект разобранного элемента
		asn1::element_t item;
		// Просмотр записи настроек алгоритма подписи
		asn1::element_t params;
		// Признак наличия настроек алгоритма подписи
		bool present = false;
		// Извлечение опознавателя алгоритма подписи
		this->_error = ::__nts_algorithm_identifier__(top, this->_algorithm, params, present);
		// Если извлечение опознавателя алгоритма подписи не удалось
		if(this->_error != error_t::NONE)
			// Выводим причину отказа
			return this->_error;
		// Запоминаем запись настроек алгоритма подписи
		if(present)
			// Запоминаем настройки подписи
			this->_parameters = params.element;
		// Разбор подписи запроса
		if(!top.next(asn1::tag_t::BIT_STRING, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Извлечение подписи запроса
		if(asn1::bits(item, this->_signature, this->_unused) != asn1::error_t::NONE)
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если после подписи остались лишние поля
		if(!top.empty())
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Создаём разборщик содержимого подписываемой части запроса
		asn1::reader_t inner(body.content);
		// Разбор издания запроса
		if(!inner.next(asn1::tag_t::INTEGER, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Издание запроса
		int64_t version = -1;
		// Извлечение издания запроса
		if(::__nts_small_integer__(item, version) != error_t::NONE)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Если издание запроса не первое: раздел 4 RFC 2986
		if(version != 0)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Разбор имени владельца запрашиваемого сертификата
		if(!inner.next(asn1::tag_t::SEQUENCE, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Извлечение имени владельца запрашиваемого сертификата
		this->_error = ::__nts_distinguished__(item, this->_subject);
		// Если извлечение имени владельца не удалось
		if(this->_error != error_t::NONE)
			// Выводим причину отказа
			return this->_error;
		// Разбор сведений об открытом ключе
		if(!inner.next(asn1::tag_t::SEQUENCE, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если запись сведений об открытом ключе не составная
		if(!item.constructed)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Запоминаем запись сведений об открытом ключе целиком
		this->_key.element = item.element;
		{
			// Создаём разборщик содержимого записи сведений об открытом ключе
			asn1::reader_t info(item.content);
			// Объект разобранного поля сведений об открытом ключе
			asn1::element_t field;
			// Извлечение опознавателя алгоритма ключа
			this->_error = ::__nts_algorithm_identifier__(info, this->_key.algorithm, params, present);
			// Если извлечение опознавателя алгоритма ключа не удалось
			if(this->_error != error_t::NONE)
				// Выводим причину отказа
				return this->_error;
			// Запоминаем запись настроек алгоритма ключа
			if(present)
				// Запоминаем настройки ключа
				this->_key.parameters = params.element;
			// Разбор открытого ключа
			if(!info.next(asn1::tag_t::BIT_STRING, field))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Извлечение открытого ключа
			if(asn1::bits(field, this->_key.key, this->_key.unused) != asn1::error_t::NONE)
				// Запоминаем причину отказа
				return (this->_error = error_t::KEY);
			// Если после открытого ключа остались лишние поля
			if(!info.empty())
				// Запоминаем причину отказа
				return (this->_error = error_t::STRUCTURE);
		}
		// Разбор атрибутов запроса
		if(!inner.next(item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если атрибуты записаны неявным [0] составной формы: раздел 4.1 RFC 2986,
		// неявная метка наследует составной вид от SET OF, которым объявлены атрибуты
		if((item.cls != asn1::cls_t::CONTEXT) || (item.tag != 0) || !item.constructed)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Создаём разборщик содержимого атрибутов
		asn1::reader_t attrs(item.content);
		/**
		 * Перебираем атрибуты запроса
		 */
		while(!attrs.empty()){
			// Объект разобранного атрибута
			asn1::element_t attr;
			// Разбор атрибута
			if(!attrs.next(asn1::tag_t::SEQUENCE, attr))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Если атрибут не составной
			if(!attr.constructed)
				// Запоминаем причину отказа
				return (this->_error = error_t::STRUCTURE);
			// Создаём разборщик содержимого атрибута
			asn1::reader_t fields(attr.content);
			// Объект разобранного поля атрибута
			asn1::element_t field;
			// Разбор опознавателя атрибута
			if(!fields.next(asn1::tag_t::OBJECT, field))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Опознаватель атрибута
			string oid;
			// Итог извлечения опознавателя атрибута
			const error_t named = ::__nts_oid_of__(field, oid);
			// Если извлечение опознавателя атрибута не удалось
			if(named != error_t::NONE)
				// Запоминаем причину отказа
				return (this->_error = named);
			// Разбор значения атрибута
			if(!fields.next(field))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Если атрибут - extensionRequest
			if(oid.compare(OID_EXTENSION_REQUEST) == 0){
				// Если значение не набор
				if((field.cls != asn1::cls_t::UNIVERSAL) || (field.tag != static_cast <uint32_t> (asn1::tag_t::SET)) || !field.constructed)
					// Запоминаем причину отказа
					return (this->_error = error_t::STRUCTURE);
				// Создаём разборщик содержимого набора значений
				asn1::reader_t values(field.content);
				// Объект разобранного значения
				asn1::element_t value;
				// Разбор значения: Extensions
				if(!values.next(asn1::tag_t::SEQUENCE, value))
					// Запоминаем причину отказа
					return (this->_error = error_t::ENCODING);
				// Если значение не составное
				if(!value.constructed)
					// Запоминаем причину отказа
					return (this->_error = error_t::STRUCTURE);
				// Создаём разборщик содержимого Extensions
				asn1::reader_t items(value.content);
				/**
				 * Перебираем расширения
				 */
				while(!items.empty()){
					// Объект разобранного расширения
					asn1::element_t entry;
					// Разбор расширения
					if(!items.next(asn1::tag_t::SEQUENCE, entry))
						// Запоминаем причину отказа
						return (this->_error = error_t::ENCODING);
					// Если расширение не составное
					if(!entry.constructed)
						// Запоминаем причину отказа
						return (this->_error = error_t::STRUCTURE);
					// Создаём разборщик содержимого расширения
					asn1::reader_t ext(entry.content);
					// Объект разобранного поля расширения
					asn1::element_t extField;
					// Разбираемое расширение
					extension_t extension;
					// Разбор опознавателя расширения
					if(!ext.next(asn1::tag_t::OBJECT, extField))
						// Запоминаем причину отказа
						return (this->_error = error_t::ENCODING);
					// Итог извлечения опознавателя расширения
					const error_t status = ::__nts_oid_of__(extField, extension.oid);
					// Если извлечение опознавателя расширения не удалось
					if(status != error_t::NONE)
						// Запоминаем причину отказа
						return (this->_error = status);
					// Разбор следующего поля расширения
					if(!ext.next(extField))
						// Запоминаем причину отказа
						return (this->_error = error_t::ENCODING);
					// Если признак критичности записан явно
					if((extField.cls == asn1::cls_t::UNIVERSAL) && (extField.tag == static_cast <uint32_t> (asn1::tag_t::BOOLEAN))){
						// Извлечение признака критичности
						if(asn1::boolean(extField, extension.critical) != asn1::error_t::NONE)
							// Запоминаем причину отказа
							return (this->_error = error_t::EXTENSION);
						// Разбор следующего поля расширения
						if(!ext.next(extField))
							// Запоминаем причину отказа
							return (this->_error = error_t::ENCODING);
					}
					// Если содержимое расширения записано не строкой байтов
					if((extField.cls != asn1::cls_t::UNIVERSAL) || extField.constructed || (extField.tag != static_cast <uint32_t> (asn1::tag_t::OCTET_STRING)))
						// Запоминаем причину отказа
						return (this->_error = error_t::STRUCTURE);
					// Запоминаем содержимое расширения
					extension.value = extField.content;
					// Если после содержимого остались лишние поля
					if(!ext.empty())
						// Запоминаем причину отказа
						return (this->_error = error_t::STRUCTURE);
					// Добавляем расширение в набор
					this->_extensions.push_back(extension);
				}
			}
			// Иные атрибуты пропускаются: раздел 4 RFC 2986 ведёт лишь extensionRequest
		}
		// Если после атрибутов остались лишние поля
		if(!inner.empty())
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Запоминаем причину отказа
		return (this->_error = error_t::MEMORY);
	}
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Метод очистки разобранных сведений
 *
 */
void nts::x509::Request::clear() noexcept {
	// Сбрасываем количество неиспользуемых разрядов подписи
	this->_unused = 0;
	// Сбрасываем причину последнего отказа
	this->_error = error_t::NONE;
	// Сбрасываем сведения об открытом ключе
	this->_key = key_t();
	// Сбрасываем имя владельца
	this->_subject = name_t();
	// Сбрасываем просмотр подписываемой части
	this->_body = view_t();
	// Сбрасываем просмотры записи запроса
	this->_element = view_t();
	// Сбрасываем просмотр подписи
	this->_signature = view_t();
	// Сбрасываем просмотр настроек подписи
	this->_parameters = view_t();
	// Сбрасываем опознаватель алгоритма подписи
	this->_algorithm.clear();
	// Сбрасываем набор расширений
	this->_extensions.clear();
}
/**
 * @brief Метод извлечения причины последнего отказа
 *
 * @return причина последнего отказа
 *
 */
nts::x509::error_t nts::x509::Request::err() const noexcept {
	// Выводим причину последнего отказа
	return this->_error;
}
/**
 * @brief Метод извлечения подписываемой части запроса
 *
 * @return просмотр подписываемой части запроса
 *
 */
const nts::view_t & nts::x509::Request::body() const noexcept {
	// Выводим подписываемую часть запроса
	return this->_body;
}
/**
 * @brief Метод извлечения подписи запроса
 *
 * @param unused количество неиспользуемых разрядов последнего байта подписи
 * @return       просмотр записи подписи
 *
 */
const nts::view_t & nts::x509::Request::sign(uint8_t & unused) const noexcept {
	// Запоминаем количество неиспользуемых разрядов последнего байта подписи
	unused = this->_unused;
	// Выводим подпись запроса
	return this->_signature;
}
/**
 * @brief Метод извлечения опознавателя алгоритма подписи
 *
 * @return опознаватель алгоритма подписи
 *
 */
const string & nts::x509::Request::algorithms() const noexcept {
	// Выводим опознаватель алгоритма подписи
	return this->_algorithm;
}
/**
 * @brief Метод получения записи настроек алгоритма подписи
 *
 * @return просмотр записи настроек либо пустой просмотр
 *
 */
const nts::view_t & nts::x509::Request::settings() const noexcept {
	// Выводим просмотр записи настроек алгоритма подписи
	return this->_parameters;
}
/**
 * @brief Метод извлечения имени владельца запрашиваемого сертификата
 *
 * @return имя владельца запрашиваемого сертификата
 *
 */
const nts::x509::name_t & nts::x509::Request::subjects() const noexcept {
	// Выводим имя владельца запрашиваемого сертификата
	return this->_subject;
}
/**
 * @brief Метод извлечения сведений об открытом ключе запроса
 *
 * @return сведения об открытом ключе запроса
 *
 */
const nts::x509::key_t & nts::x509::Request::key() const noexcept {
	// Выводим сведения об открытом ключе запроса
	return this->_key;
}
/**
 * @brief Метод извлечения набора запрошенных расширений
 *
 * @return набор запрошенных расширений
 *
 */
const vector <nts::x509::extension_t> & nts::x509::Request::extension() const noexcept {
	// Выводим набор запрошенных расширений
	return this->_extensions;
}
/**
 * @brief Конструктор запроса
 *
 */
nts::x509::Request::Request() noexcept : _error(error_t::NONE), _unused(0) {}
/**
 * @brief Деструктор
 *
 */
nts::x509::Request::~Request() noexcept = default;

/**
 * @brief Функция записи запроса на сертификат PKCS #10
 *
 * @param subject    имя владельца запрашиваемого сертификата
 * @param key        сведения об открытом ключе запроса
 * @param extensions набор запрашиваемых расширений (пустой набор - без расширений)
 * @param signer     подготовленный секретный ключ подписи запроса
 * @param hash       алгоритм хеша подписи (для ECDSA и RSA; у Ed25519, ML-DSA, SM2 и ГОСТ не рассматривается)
 * @param result     место, в которое помещается запись запроса в кодировке DER
 * @return           отказ записи запроса
 *
 */
nts::x509::error_t nts::x509::encode(const name_t & subject, const nts::x509::key_t & key, const vector <extension_t> & extensions, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Если ключ не подготовлен
	if(!signer.ready())
		// Выводим отказ ключа
		return error_t::KEY;
	// Получаем опознаватель алгоритма подписи
	const char * algorithm = ::__nts_signature_algorithm__(signer, hash);
	// Если алгоритм подписи не определён
	if(algorithm == nullptr)
		// Выводим отказ подписи
		return error_t::SIGNATURE;
	// Записчик подписываемой части запроса
	asn1::writer_t body;
	// Открываем набор подписываемой части
	body.open(asn1::tag_t::SEQUENCE);
	// Записываем издание запроса: v1
	body.integer(0);
	// Итог записи имени владельца
	error_t outcome = ::__nts_name_body__(body, subject);
	// Если имя записать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ записи
		return outcome;
	// Открываем набор сведений об открытом ключе
	body.open(asn1::tag_t::SEQUENCE);
	// Итог записи набора алгоритма ключа
	outcome = ::__nts_key_algorithm__(body, key);
	// Если набор алгоритма записать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ записи
		return outcome;
	// Итог записи тела открытого ключа
	outcome = ::__nts_key_body__(key, body);
	// Если тело ключа записать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ записи
		return outcome;
	// Закрываем набор сведений об открытом ключе
	body.close();
	// Открываем атрибуты запроса: неявный [0] составной формы
	body.open(asn1::cls_t::CONTEXT, 0);
	// Открываем атрибут extensionRequest
	body.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель атрибута
	::__nts_object__(body, OID_EXTENSION_REQUEST);
	// Открываем набор значений атрибута
	body.open(asn1::tag_t::SET);
	// Итог записи набора расширений
	outcome = ::__nts_extensions_body__(body, extensions);
	// Если набор расширений записать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ записи
		return outcome;
	// Закрываем набор значений атрибута
	body.close();
	// Закрываем атрибут extensionRequest
	body.close();
	// Закрываем атрибуты запроса
	body.close();
	// Закрываем набор подписываемой части
	body.close();
	// Если подписываемую часть записать не удалось
	if(body.err() != asn1::error_t::NONE)
		// Выводим переведённый отказ записи
		return ::__nts_translate__(body.err());
	// Подпись запроса
	vector <uint8_t> signature;
	// Итог выработки подписи
	outcome = ::__nts_make_signature__(signer, hash, body.data(), signature);
	// Если подпись выработать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ подписи
		return outcome;
	// Записчик хвоста записи запроса: опознаватель алгоритма подписи и сама подпись
	asn1::writer_t tail;
	// Открываем набор алгоритма подписи
	tail.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель алгоритма подписи
	::__nts_object__(tail, algorithm);
	// Если алгоритм подписи несёт настройки NULL (RSA)
	if(signer.kind() == keys::kind_t::RSA)
		// Записываем пустые настройки
		tail.nothing();
	// Закрываем набор алгоритма подписи
	tail.close();
	// Записываем подпись строкой битов
	tail.bits(view_t(signature.data(), signature.size()));
	// Если хвост записи запроса записать не удалось
	if(tail.err() != asn1::error_t::NONE)
		// Выводим переведённый отказ записи
		return ::__nts_translate__(tail.err());
	// Получаем просмотр подписываемой части
	const view_t signedPart = body.data();
	// Получаем просмотр хвоста записи
	const view_t tailPart = tail.data();
	// Содержимое записи запроса: подписываемая часть и хвост
	vector <uint8_t> content;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Сборка содержимого записи запроса
		content.reserve(signedPart.size + tailPart.size);
		// Дописываем подписываемую часть
		content.insert(content.end(), signedPart.data, signedPart.data + signedPart.size);
		// Дописываем хвост записи
		content.insert(content.end(), tailPart.data, tailPart.data + tailPart.size);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Записчик записи запроса
	asn1::writer_t writer;
	// Записываем набор записи запроса с собранным содержимым
	writer.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), view_t(content.data(), content.size()));
	// Если запись запроса записать не удалось
	if(writer.err() != asn1::error_t::NONE)
		// Выводим переведённый отказ записи
		return ::__nts_translate__(writer.err());
	// Получаем просмотр собранной записи
	const view_t data = writer.data();
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Копирование записи
		result.assign(data.data, data.data + data.size);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность записи
	return error_t::NONE;
}
/**
 * @brief Функция проверки подписи запроса на сертификат
 *
 * @param request запрос, подпись которого проверяется
 * @param key     сведения об открытом ключе подписавшей стороны
 * @return        отказ проверки: NONE - подпись сошлась, SIGNATURE - не сошлась либо
 *                непригодна, KEY - ключ чужого алгоритма, MEMORY - памяти не хватило
 *
 *
 */
nts::x509::error_t nts::x509::verify(const request_t & request, const nts::x509::key_t & key) noexcept {
	// Количество неиспользуемых разрядов последнего байта подписи
	uint8_t unused = 0;
	// Получаем подпись проверяемого запроса
	const view_t & signature = request.sign(unused);
	// Если подпись запроса занимает неполное количество байтов
	if(unused != 0)
		// Выводим отказ проверки подписи запроса
		return error_t::SIGNATURE;
	// Выводим итог проверки подписи тела запроса
	return nts::x509::verify(request.body(), signature, request.algorithms(), request.settings(), key);
}
