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
#include <x509/request.hpp>
#include <x509/signature.hpp>
#include <asn1/asn1.hpp>
#include <sign/rsa.hpp>
#include <sign/ecdsa.hpp>
#include <sign/ed25519.hpp>
#include <sign/gost.hpp>
#include <sign/mldsa.hpp>
#include <sign/sm2.hpp>
#include <entropy/entropy.hpp>

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
	 * Опознаватель атрибута extensionRequest: раздел 5.4.2 RFC 2985
	 */
	static const char * OID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14";

	/**
	 * Опознаватель алгоритма открытого ключа RSA: раздел 2.3.1 RFC 3279
	 */
	static const char * OID_RSA = "1.2.840.113549.1.1.1";

	/**
	 * Опознаватель алгоритма открытого ключа эллиптической кривой: раздел 2.1.1 RFC 5480
	 */
	static const char * OID_EC = "1.2.840.10045.2.1";

	/**
	 * Опознаватель алгоритма открытого ключа Ed25519: раздел 3 RFC 8410
	 */
	static const char * OID_ED25519 = "1.3.101.112";

	/**
	 * Опознаватель алгоритма открытого ключа SM2: GB/T 32918 и RFC 8998
	 */
	static const char * OID_SM2 = "1.2.156.10197.1.301";

	/**
	 * Опознаватель алгоритма открытого ключа ГОСТ Р 34.10-2012 длиной 256 разрядов
	 */
	static const char * OID_GOST256 = "1.2.643.7.1.1.1.1";

	/**
	 * Опознаватель алгоритма открытого ключа ГОСТ Р 34.10-2012 длиной 512 разрядов
	 */
	static const char * OID_GOST512 = "1.2.643.7.1.1.1.2";

	/**
	 * Опознаватель алгоритма открытого ключа ГОСТ Р 34.10-2001
	 */
	static const char * OID_GOST2001 = "1.2.643.2.2.19";

	/**
	 * Опознаватель алгоритма открытого ключа ML-DSA-44: раздел 5 RFC 9881
	 */
	static const char * OID_MLDSA44 = "2.16.840.1.101.3.4.3.17";

	/**
	 * Опознаватель алгоритма открытого ключа ML-DSA-65: раздел 5 RFC 9881
	 */
	static const char * OID_MLDSA65 = "2.16.840.1.101.3.4.3.18";

	/**
	 * Опознаватель алгоритма открытого ключа ML-DSA-87: раздел 5 RFC 9881
	 */
	static const char * OID_MLDSA87 = "2.16.840.1.101.3.4.3.19";

	/**
	 * Опознаватель алгоритма подписи RSA PKCS #1 v1.5 с хешем SHA-1: раздел 2.2.1 RFC 3279
	 */
	static const char * OID_SHA1_RSA = "1.2.840.113549.1.1.5";

	/**
	 * Опознаватель алгоритма подписи RSA PKCS #1 v1.5 с хешем SHA-256: раздел 5 RFC 4055
	 */
	static const char * OID_SHA256_RSA = "1.2.840.113549.1.1.11";

	/**
	 * Опознаватель алгоритма подписи RSA PKCS #1 v1.5 с хешем SHA-384
	 */
	static const char * OID_SHA384_RSA = "1.2.840.113549.1.1.12";

	/**
	 * Опознаватель алгоритма подписи RSA PKCS #1 v1.5 с хешем SHA-512
	 */
	static const char * OID_SHA512_RSA = "1.2.840.113549.1.1.13";

	/**
	 * Опознаватель алгоритма подписи RSA PKCS #1 v1.5 с хешем SHA-224
	 */
	static const char * OID_SHA224_RSA = "1.2.840.113549.1.1.14";

	/**
	 * Опознаватель алгоритма подписи ECDSA с хешем SHA-224: раздел 3.2 RFC 5758
	 */
	static const char * OID_SHA224_ECDSA = "1.2.840.10045.4.3.1";

	/**
	 * Опознаватель алгоритма подписи ECDSA с хешем SHA-256
	 */
	static const char * OID_SHA256_ECDSA = "1.2.840.10045.4.3.2";

	/**
	 * Опознаватель алгоритма подписи ECDSA с хешем SHA-384
	 */
	static const char * OID_SHA384_ECDSA = "1.2.840.10045.4.3.3";

	/**
	 * Опознаватель алгоритма подписи ECDSA с хешем SHA-512
	 */
	static const char * OID_SHA512_ECDSA = "1.2.840.10045.4.3.4";

	/**
	 * Опознаватель алгоритма подписи Ed25519: раздел 3 RFC 8410
	 */
	static const char * OID_ED25519_SIGN = "1.3.101.112";

	/**
	 * Опознаватель алгоритма подписи ГОСТ Р 34.10-2012 с хешем 256 разрядов
	 */
	static const char * OID_GOST256_SIGN = "1.2.643.7.1.1.3.2";

	/**
	 * Опознаватель алгоритма подписи ГОСТ Р 34.10-2012 с хешем 512 разрядов
	 */
	static const char * OID_GOST512_SIGN = "1.2.643.7.1.1.3.3";

	/**
	 * Опознаватель алгоритма подписи SM2 с хешем SM3: RFC 8998
	 */
	static const char * OID_SM2_SIGN = "1.2.156.10197.1.501";

	/**
	 * Опознаватель алгоритма подписи ML-DSA-44: раздел 4 RFC 9881
	 */
	static const char * OID_MLDSA44_SIGN = "2.16.840.1.101.3.4.3.17";

	/**
	 * Опознаватель алгоритма подписи ML-DSA-65
	 */
	static const char * OID_MLDSA65_SIGN = "2.16.840.1.101.3.4.3.18";

	/**
	 * Опознаватель алгоритма подписи ML-DSA-87
	 */
	static const char * OID_MLDSA87_SIGN = "2.16.840.1.101.3.4.3.19";

	/**
	 * @brief Метод перевода отказа разборщика ASN.1 в отказ модуля
	 *
	 * @param error отказ разборщика ASN.1
	 *
	 * @return      отказ модуля
	 *
	 */
	static nts::x509::error_t translate(const asn1::error_t error) noexcept {
		// Выводим отказ модуля: нехватка памяти отдаётся своим отказом, всё прочее - отказом устройства
		return ((error == asn1::error_t::MEMORY) ? nts::x509::error_t::MEMORY : nts::x509::error_t::STRUCTURE);
	}
	/**
	 * @brief Метод разбора опознавателя объекта
	 *
	 * @param element разбираемый элемент
	 * @param result  место, в которое помещается опознаватель
	 *
	 * @return        отказ разбора опознавателя
	 *
	 */
	static nts::x509::error_t identifier(const asn1::element_t & element, string & result) noexcept {
		// Итог разбора опознавателя
		const asn1::error_t outcome = asn1::oid(element, result);
		// Выводим переведённый отказ разбора, если он есть
		return ((outcome == asn1::error_t::NONE) ? nts::x509::error_t::NONE : translate(outcome));
	}
	/**
	 * @brief Метод разбора малого целого числа
	 *
	 * @param element разбираемый элемент
	 * @param result  место, в которое помещается число
	 *
	 * @return        отказ разбора числа
	 *
	 */
	static nts::x509::error_t smallInteger(const asn1::element_t & element, int64_t & result) noexcept {
		// Итог разбора целого числа
		const asn1::error_t outcome = asn1::integer(element, result);
		// Выводим переведённый отказ разбора, если он есть
		return ((outcome == asn1::error_t::NONE) ? nts::x509::error_t::NONE : translate(outcome));
	}
	/**
	 * @brief Метод разбора записи опознавателя алгоритма
	 *
	 * @param reader разборщик, из которого читается запись
	 * @param oid    место, в которое помещается опознаватель алгоритма
	 * @param params место, в которое помещается запись настроек алгоритма
	 * @param present место, в которое помещается признак наличия настроек
	 *
	 * @return       отказ разбора записи
	 *
	 */
	static nts::x509::error_t algorithmIdentifier(asn1::reader_t & reader, string & oid, asn1::element_t & params, bool & present) noexcept {
		// Сбрасываем признак наличия настроек
		present = false;
		// Набор алгоритма
		asn1::element_t element;
		// Если набор алгоритма разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, element) || !element.constructed)
			// Выводим переведённый отказ разбора
			return translate(reader.err());
		// Разборщик содержимого набора алгоритма
		asn1::reader_t items = reader.enter(element);
		// Если опознаватель алгоритма разобрать не удалось
		if(!items.next(asn1::tag_t::OBJECT, element))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Итог разбора опознавателя алгоритма
		const nts::x509::error_t outcome = identifier(element, oid);
		// Если опознаватель алгоритма разобрать не удалось
		if(outcome != nts::x509::error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Если настройки алгоритма записаны
		if(!items.empty()){
			// Если настройки алгоритма разобрать не удалось
			if(!items.next(params))
				// Выводим переведённый отказ разбора
				return translate(items.err());
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
	 * @brief Метод записи опознавателя объекта из строки знаков
	 *
	 * @param writer записчик, в который помещается опознаватель
	 * @param value  записываемый опознаватель строкой знаков
	 *
	 * @return       отказ записи опознавателя
	 *
	 */
	static nts::x509::error_t object(asn1::writer_t & writer, const char * value) noexcept {
		// Опознаватель строкой
		string oid;
		/**
		 * Копирование выделяет память: нехватка её отдаётся отказом
		 */
		try {
			// Выполняем копирование опознавателя
			oid.assign(value);
		// Если памяти не хватило
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return nts::x509::error_t::MEMORY;
		}
		// Записываем опознаватель объекта
		writer.oid(oid);
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? nts::x509::error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Метод записи набора алгоритма ключа
	 *
	 * @param writer записчик, в который помещается набор алгоритма
	 * @param key    записываемый ключ
	 *
	 * @return       отказ записи набора алгоритма
	 *
	 */
	static nts::x509::error_t keyAlgorithm(asn1::writer_t & writer, const nts::x509::key_t & key) noexcept {
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Если ключ RSA
		if(key.algorithm.compare(OID_RSA) == 0){
			// Записываем опознаватель алгоритма
			object(writer, OID_RSA);
			// Записываем пустые настройки: раздел 2.3.1 RFC 3279
			writer.nothing();
		// Если ключ EC
		} else if(key.algorithm.compare(OID_EC) == 0){
			// Записываем опознаватель алгоритма
			object(writer, OID_EC);
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
				string oid;
				// Итог разбора опознавателя кривой
				const nts::x509::error_t outcome = identifier(element, oid);
				// Если опознаватель кривой разобрать не удалось
				if(outcome != nts::x509::error_t::NONE)
					// Выводим отказ разбора
					return outcome;
				// Записываем опознаватель кривой
				writer.oid(oid);
			// Если настроек нет
			} else return nts::x509::error_t::KEY;
		// Если ключ Ed25519
		} else if(key.algorithm.compare(OID_ED25519) == 0){
			// Записываем опознаватель алгоритма: настроек у него нет
			object(writer, OID_ED25519);
		// Если ключ SM2
		} else if(key.algorithm.compare(OID_SM2) == 0){
			// Записываем опознаватель алгоритма: настроек у него нет
			object(writer, OID_SM2);
		// Если ключ ML-DSA
		} else if((key.algorithm.compare(OID_MLDSA44) == 0) || (key.algorithm.compare(OID_MLDSA65) == 0) || (key.algorithm.compare(OID_MLDSA87) == 0)){
			// Записываем опознаватель алгоритма ключа: настроек у него нет
			writer.oid(key.algorithm);
		// Если ключ ГОСТ
		} else if((key.algorithm.compare(OID_GOST256) == 0) || (key.algorithm.compare(OID_GOST512) == 0) || (key.algorithm.compare(OID_GOST2001) == 0)){
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
				string oid;
				// Итог разбора опознавателя кривой
				const nts::x509::error_t outcome = identifier(element, oid);
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
					string digest;
					// Итог разбора опознавателя хеша
					const nts::x509::error_t extracted = identifier(element, digest);
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
		return ((writer.err() == asn1::error_t::NONE) ? nts::x509::error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Метод записи тела открытого ключа
	 *
	 * @param key    записываемый ключ
	 * @param writer записчик, в который помещается тело ключа
	 *
	 * @return       отказ записи тела ключа
	 *
	 */
	static nts::x509::error_t keyBody(const nts::x509::key_t & key, asn1::writer_t & writer) noexcept {
		// Если ключ RSA
		if(key.algorithm.compare(OID_RSA) == 0){
			// Если запись ключа не передана
			if((key.key.data == nullptr) || (key.key.size == 0))
				// Выводим отказ ключа
				return nts::x509::error_t::KEY;
			// Записываем строку битов ключа
			writer.bits(key.key);
		// Если ключ EC либо SM2
		} else if((key.algorithm.compare(OID_EC) == 0) || (key.algorithm.compare(OID_SM2) == 0)){
			// Если запись ключа не передана
			if((key.key.data == nullptr) || (key.key.size == 0))
				// Выводим отказ ключа
				return nts::x509::error_t::KEY;
			// Записываем строку битов ключа
			writer.bits(key.key);
		// Если ключ Ed25519 либо ML-DSA
		} else if((key.algorithm.compare(OID_ED25519) == 0) || (key.algorithm.compare(OID_MLDSA44) == 0) || (key.algorithm.compare(OID_MLDSA65) == 0) || (key.algorithm.compare(OID_MLDSA87) == 0)){
			// Если запись ключа не передана
			if((key.key.data == nullptr) || (key.key.size == 0))
				// Выводим отказ ключа
				return nts::x509::error_t::KEY;
			// Записываем строку битов ключа
			writer.bits(key.key);
		// Если ключ ГОСТ
		} else if((key.algorithm.compare(OID_GOST256) == 0) || (key.algorithm.compare(OID_GOST512) == 0) || (key.algorithm.compare(OID_GOST2001) == 0)){
			// Если запись ключа не передана
			if((key.key.data == nullptr) || (key.key.size == 0))
				// Выводим отказ ключа
				return nts::x509::error_t::KEY;
			// Записываем строку битов ключа
			writer.bits(key.key);
		// Если алгоритм ключа неизвестен
		} else return nts::x509::error_t::KEY;
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? nts::x509::error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Метод записи имени
	 *
	 * @param writer записчик, в который помещается имя
	 * @param name   записываемое имя
	 *
	 * @return       отказ записи имени
	 *
	 */
	static nts::x509::error_t nameBody(asn1::writer_t & writer, const nts::x509::name_t & name) noexcept {
		// Если имя пусто
		if(name.parts.empty())
			// Выводим отказ имени
			return nts::x509::error_t::NAME;
		// Открываем набор имени
		writer.open(asn1::tag_t::SEQUENCE);
		/**
		 * Выполняем перебор составляющих имени
		 */
		for(size_t i = 0; i < name.parts.size(); i++){
			// Если составляющая пуста
			if(name.parts[i].empty())
				// Выводим отказ имени
				return nts::x509::error_t::NAME;
			// Открываем составляющую имени
			writer.open(asn1::tag_t::SET);
			/**
			 * Выполняем перебор признаков составляющей
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
		return ((writer.err() == asn1::error_t::NONE) ? nts::x509::error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Метод записи набора расширений
	 *
	 * @param writer     записчик, в который помещается набор расширений
	 * @param extensions записываемый набор расширений
	 *
	 * @return           отказ записи набора расширений
	 *
	 */
	static nts::x509::error_t extensionsBody(asn1::writer_t & writer, const vector <nts::x509::extension_t> & extensions) noexcept {
		// Открываем набор расширений
		writer.open(asn1::tag_t::SEQUENCE);
		/**
		 * Выполняем перебор расширений
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
		return ((writer.err() == asn1::error_t::NONE) ? nts::x509::error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Метод выработки подписи содержимого ключом
	 *
	 * @param signer    подготовленный секретный ключ подписи
	 * @param hash      алгоритм хеша подписи (для ECDSA и RSA)
	 * @param content   подписываемое содержимое
	 * @param signature место, в которое помещается подпись
	 *
	 * @return          отказ выработки подписи
	 *
	 */
	static nts::x509::error_t makeSignature(const keys::signer_t & signer, const digest::hash_t hash, const view_t & content, vector <uint8_t> & signature) noexcept {
		/**
		 * Выполняем определение вида ключа подписи
		 */
		switch(signer.kind()){
			// Ключ RSA
			case keys::kind_t::RSA: {
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
			case keys::kind_t::EC: {
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
			case keys::kind_t::ED25519: {
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
			case keys::kind_t::GOST: {
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
			case keys::kind_t::MLDSA: {
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
			case keys::kind_t::SM2: {
				// Модуль подписи SM2
				const sign::sm2_t & sm2 = signer.sm2();
				// Опознаватель подписи сертификата по RFC 8998
				static const char * ID = "1234567812345678";
				// Если опознаватель подписи установить не удалось
				if(!sm2.reidentify(view_t(reinterpret_cast <const uint8_t *> (ID), 16)))
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
					// Выполняем выработку подписи
					made = sm2.make(content, view_t(random, sizeof(random)), raw);
				}
				// Выполняем затирание случайного числа
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
		// Выводим успешность выработки подписи
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Метод получения опознавателя алгоритма подписи по виду ключа и хешу
	 *
	 * @param signer подготовленный секретный ключ подписи
	 * @param hash   алгоритм хеша подписи
	 *
	 * @return       опознаватель алгоритма подписи либо nullptr
	 *
	 */
	static const char * signatureAlgorithm(const keys::signer_t & signer, const digest::hash_t hash) noexcept {
		/**
		 * Выполняем определение вида ключа подписи
		 */
		switch(signer.kind()){
			// Ключ RSA
			case keys::kind_t::RSA:
				// Выводим опознаватель по хешу
				switch(hash){
					case digest::hash_t::SHA1: return OID_SHA1_RSA;
					case digest::hash_t::SHA224: return OID_SHA224_RSA;
					case digest::hash_t::SHA256: return OID_SHA256_RSA;
					case digest::hash_t::SHA384: return OID_SHA384_RSA;
					case digest::hash_t::SHA512: return OID_SHA512_RSA;
					default: return nullptr;
				}
			// Ключ ECDSA
			case keys::kind_t::EC:
				// Выводим опознаватель по хешу
				switch(hash){
					case digest::hash_t::SHA224: return OID_SHA224_ECDSA;
					case digest::hash_t::SHA256: return OID_SHA256_ECDSA;
					case digest::hash_t::SHA384: return OID_SHA384_ECDSA;
					case digest::hash_t::SHA512: return OID_SHA512_ECDSA;
					default: return nullptr;
				}
			// Ключ Ed25519
			case keys::kind_t::ED25519:
				// Выводим опознаватель Ed25519
				return OID_ED25519_SIGN;
			// Ключ ГОСТ
			case keys::kind_t::GOST:
				// Выводим опознаватель по размеру кривой
				return ((signer.curve().size() == 32) ? OID_GOST256_SIGN : OID_GOST512_SIGN);
			// Ключ ML-DSA
			case keys::kind_t::MLDSA:
				// Выводим опознаватель по набору ключа
				switch(signer.mldsa().set()){
					case sign::mldsa_t::set_t::DSA44: return OID_MLDSA44_SIGN;
					case sign::mldsa_t::set_t::DSA65: return OID_MLDSA65_SIGN;
					case sign::mldsa_t::set_t::DSA87: return OID_MLDSA87_SIGN;
					default: return nullptr;
				}
			// Ключ SM2
			case keys::kind_t::SM2:
				// Выводим опознаватель SM2
				return OID_SM2_SIGN;
			// Ключ, подписи не выполняющий
			default:
				// Выводим отсутствие опознавателя
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
	// Выполняем очистку разобранных сведений
	this->clear();
	/**
	 * Разбор собирает имя и расширения, а значит выделяет память: нехватка её
	 * обязана дойти до вызывающего причиной отказа, а не завершить процесс
	 */
	try {
		// Создаём разборщик записи запроса
		asn1::reader_t reader(data);
		// Объект разобранной записи запроса
		asn1::element_t request;
		// Выполняем разбор записи запроса
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
		// Выполняем разбор подписываемой части запроса
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
		// Выполняем разбор опознавателя алгоритма подписи
		if(!top.next(asn1::tag_t::SEQUENCE, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Просмотр записи настроек алгоритма подписи
		asn1::element_t params;
		// Признак наличия настроек алгоритма подписи
		bool present = false;
		// Выполняем извлечение опознавателя алгоритма подписи
		this->_error = algorithmIdentifier(top, this->_algorithm, params, present);
		// Если извлечение опознавателя алгоритма подписи не удалось
		if(this->_error != error_t::NONE)
			// Выводим причину отказа
			return this->_error;
		// Запоминаем запись настроек алгоритма подписи
		if(present)
			this->_parameters = params.element;
		// Выполняем разбор подписи запроса
		if(!top.next(asn1::tag_t::BIT_STRING, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Выполняем извлечение подписи запроса
		if(asn1::bits(item, this->_signature, this->_unused) != asn1::error_t::NONE)
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если после подписи остались лишние поля
		if(!top.empty())
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Создаём разборщик содержимого подписываемой части запроса
		asn1::reader_t inner(body.content);
		// Выполняем разбор издания запроса
		if(!inner.next(asn1::tag_t::INTEGER, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Издание запроса
		int64_t version = -1;
		// Выполняем извлечение издания запроса
		if(smallInteger(item, version) != error_t::NONE)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Если издание запроса не первое: раздел 4 RFC 2986
		if(version != 0)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Выполняем разбор имени владельца запрашиваемого сертификата
		if(!inner.next(asn1::tag_t::SEQUENCE, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Выполняем извлечение имени владельца запрашиваемого сертификата
		this->_error = distinguished(item, this->_subject);
		// Если извлечение имени владельца не удалось
		if(this->_error != error_t::NONE)
			// Выводим причину отказа
			return this->_error;
		// Выполняем разбор сведений об открытом ключе
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
			// Выполняем разбор опознавателя алгоритма ключа
			if(!info.next(asn1::tag_t::SEQUENCE, field))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Выполняем извлечение опознавателя алгоритма ключа
			this->_error = algorithmIdentifier(info, this->_key.algorithm, params, present);
			// Если извлечение опознавателя алгоритма ключа не удалось
			if(this->_error != error_t::NONE)
				// Выводим причину отказа
				return this->_error;
			// Запоминаем запись настроек алгоритма ключа
			if(present)
				this->_key.parameters = params.element;
			// Выполняем разбор открытого ключа
			if(!info.next(asn1::tag_t::BIT_STRING, field))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Выполняем извлечение открытого ключа
			if(asn1::bits(field, this->_key.key, this->_key.unused) != asn1::error_t::NONE)
				// Запоминаем причину отказа
				return (this->_error = error_t::KEY);
			// Если после открытого ключа остались лишние поля
			if(!info.empty())
				// Запоминаем причину отказа
				return (this->_error = error_t::STRUCTURE);
		}
		// Выполняем разбор атрибутов запроса
		if(!inner.next(item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если атрибуты записаны неявным [0] примитивной формы: раздел 4.1 RFC 2986
		if((item.cls != asn1::cls_t::CONTEXT) || (item.tag != 0) || item.constructed)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Создаём разборщик содержимого атрибутов
		asn1::reader_t attrs(item.content);
		/**
		 * Выполняем перебор атрибутов запроса
		 */
		while(!attrs.empty()){
			// Объект разобранного атрибута
			asn1::element_t attr;
			// Выполняем разбор атрибута
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
			// Выполняем разбор опознавателя атрибута
			if(!fields.next(asn1::tag_t::OBJECT, field))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Опознаватель атрибута
			string oid;
			// Итог извлечения опознавателя атрибута
			const error_t named = identifier(field, oid);
			// Если извлечение опознавателя атрибута не удалось
			if(named != error_t::NONE)
				// Запоминаем причину отказа
				return (this->_error = named);
			// Выполняем разбор значения атрибута
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
				// Выполняем разбор значения: Extensions
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
				 * Выполняем перебор расширений
				 */
				while(!items.empty()){
					// Объект разобранного расширения
					asn1::element_t entry;
					// Выполняем разбор расширения
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
					// Выполняем разбор опознавателя расширения
					if(!ext.next(asn1::tag_t::OBJECT, extField))
						// Запоминаем причину отказа
						return (this->_error = error_t::ENCODING);
					// Итог извлечения опознавателя расширения
					const error_t status = identifier(extField, extension.oid);
					// Если извлечение опознавателя расширения не удалось
					if(status != error_t::NONE)
						// Запоминаем причину отказа
						return (this->_error = status);
					// Выполняем разбор следующего поля расширения
					if(!ext.next(extField))
						// Запоминаем причину отказа
						return (this->_error = error_t::ENCODING);
					// Если признак критичности записан явно
					if((extField.cls == asn1::cls_t::UNIVERSAL) && (extField.tag == static_cast <uint32_t> (asn1::tag_t::BOOLEAN))){
						// Выполняем извлечение признака критичности
						if(asn1::boolean(extField, extension.critical) != asn1::error_t::NONE)
							// Запоминаем причину отказа
							return (this->_error = error_t::EXTENSION);
						// Выполняем разбор следующего поля расширения
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
	 * Если память выделить не удалось
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
	// Сбрасываем причину последнего отказа
	this->_error = error_t::NONE;
	// Сбрасываем просмотры записи запроса
	this->_element = view_t();
	this->_body = view_t();
	this->_signature = view_t();
	this->_parameters = view_t();
	// Сбрасываем число неиспользуемых разрядов подписи
	this->_unused = 0;
	// Сбрасываем опознаватель алгоритма подписи
	this->_algorithm.clear();
	// Сбрасываем имя владельца
	this->_subject = name_t();
	// Сбрасываем сведения об открытом ключе
	this->_key = key_t();
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
 * @param unused число неиспользуемых разрядов последнего байта подписи
 * @return       просмотр записи подписи
 *
 */
const nts::view_t & nts::x509::Request::sign(uint8_t & unused) const noexcept {
	// Запоминаем число неиспользуемых разрядов последнего байта подписи
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
 * @brief Метод записи запроса на сертификат PKCS #10
 *
 * @param subject    имя владельца запрашиваемого сертификата
 * @param key        сведения об открытом ключе запроса
 * @param extensions набор запрашиваемых расширений
 * @param signer     подготовленный секретный ключ подписи запроса
 * @param hash       алгоритм хеша подписи
 * @param result     место, в которое помещается запись запроса в кодировке DER
 *
 * @return           отказ записи запроса
 *
 */
nts::x509::error_t nts::x509::encode(const name_t & subject, const key_t & key, const vector <extension_t> & extensions, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Если ключ не подготовлен
	if(!signer.ready())
		// Выводим отказ ключа
		return error_t::KEY;
	// Получаем опознаватель алгоритма подписи
	const char * algorithm = signatureAlgorithm(signer, hash);
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
	error_t outcome = nameBody(body, subject);
	// Если имя записать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ записи
		return outcome;
	// Открываем набор сведений об открытом ключе
	body.open(asn1::tag_t::SEQUENCE);
	// Итог записи набора алгоритма ключа
	outcome = keyAlgorithm(body, key);
	// Если набор алгоритма записать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ записи
		return outcome;
	// Итог записи тела открытого ключа
	outcome = keyBody(key, body);
	// Если тело ключа записать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ записи
		return outcome;
	// Закрываем набор сведений об открытом ключе
	body.close();
	// Открываем атрибуты запроса: неявный [0] примитивной формы
	body.open(asn1::cls_t::CONTEXT, 0);
	// Открываем атрибут extensionRequest
	body.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель атрибута
	object(body, OID_EXTENSION_REQUEST);
	// Открываем набор значений атрибута
	body.open(asn1::tag_t::SET);
	// Итог записи набора расширений
	outcome = extensionsBody(body, extensions);
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
		return translate(body.err());
	// Подпись запроса
	vector <uint8_t> signature;
	// Итог выработки подписи
	outcome = makeSignature(signer, hash, body.data(), signature);
	// Если подпись выработать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ подписи
		return outcome;
	// Записчик записи запроса
	asn1::writer_t writer;
	// Открываем набор записи запроса
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем подписываемую часть как есть
	writer.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), body.data());
	// Открываем набор алгоритма подписи
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель алгоритма подписи
	object(writer, algorithm);
	// Если алгоритм подписи несёт настройки NULL (RSA)
	if(signer.kind() == keys::kind_t::RSA)
		// Записываем пустые настройки
		writer.nothing();
	// Закрываем набор алгоритма подписи
	writer.close();
	// Записываем подпись строкой битов
	writer.bits(view_t(signature.data(), signature.size()));
	// Закрываем набор записи запроса
	writer.close();
	// Если запись запроса записать не удалось
	if(writer.err() != asn1::error_t::NONE)
		// Выводим переведённый отказ записи
		return translate(writer.err());
	// Получаем просмотр собранной записи
	const view_t data = writer.data();
	/**
	 * Копирование выделяет память: нехватка её отдаётся отказом
	 */
	try {
		// Выполняем копирование записи
		result.assign(data.data, data.data + data.size);
	// Если памяти не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность записи
	return error_t::NONE;
}

/**
 * @brief Метод проверки подписи запроса на сертификат
 *
 * @param request запрос, подпись которого проверяется
 * @param key     сведения об открытом ключе подписавшей стороны
 *
 * @return        отказ проверки подписи
 *
 */
nts::x509::error_t nts::x509::verify(const request_t & request, const key_t & key) noexcept {
	// Число неиспользуемых разрядов последнего байта подписи
	uint8_t unused = 0;
	// Получаем подпись проверяемого запроса
	const view_t & signature = request.sign(unused);
	// Если подпись запроса занимает неполное число байтов
	if(unused != 0)
		// Выводим отказ проверки подписи запроса
		return error_t::SIGNATURE;
	// Выводим итог проверки подписи тела запроса
	return nts::x509::verify(request.body(), signature, request.algorithms(), request.settings(), key);
}
