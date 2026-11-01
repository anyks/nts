/**
 * @file issue.cpp
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
 * @brief Исходный файл модуля выпуска сертификатов X.509 —
 *        сборка TBSCertificate и подпись (самоподписанный и ЦС)
 *
 * @note Подпись вырабатывается тем же механизмом, что и у запроса PKCS #10:
 *       вид ключа определяет алгоритм подписи и запись подписи.
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
#include <x509/issue.hpp>
#include <x509/signature.hpp>
#include <asn1/asn1.hpp>
#include <sign/rsa.hpp>
#include <sign/ecdsa.hpp>
#include <sign/ed25519.hpp>
#include <sign/gost.hpp>
#include <sign/mldsa.hpp>
#include <sign/sm2.hpp>
#include <sys/wipe.hpp>
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
	 * @brief Функция перевода отказа разборщика ASN.1 в отказ модуля
	 *
	 * @param error отказ разборщика ASN.1
	 * @return      отказ модуля
	 *
	 */
	static nts::x509::error_t translate(const asn1::error_t error) noexcept {
		// Выводим отказ модуля: нехватка памяти отдаётся своим отказом, всё прочее - отказом устройства
		return ((error == asn1::error_t::MEMORY) ? nts::x509::error_t::MEMORY : nts::x509::error_t::STRUCTURE);
	}
	/**
	 * @brief Функция записи опознавателя объекта из строки знаков
	 *
	 * @param writer записчик, в который помещается опознаватель
	 * @param value  записываемый опознаватель строкой знаков
	 * @return       отказ записи опознавателя
	 *
	 */
	static nts::x509::error_t object(asn1::writer_t & writer, const char * value) noexcept {
		// Опознаватель строкой
		string oid;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Выполняем копирование опознавателя
			oid.assign(value);
		// Если памяти не хватило
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
		return ((writer.err() == asn1::error_t::NONE) ? nts::x509::error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Функция записи имени
	 *
	 * @param writer записчик, в который помещается имя
	 * @param name   записываемое имя
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
	 * @brief Функция записи набора алгоритма ключа
	 *
	 * @param writer записчик, в который помещается набор алгоритма
	 * @param key    записываемый ключ
	 * @return       отказ записи набора алгоритма
	 *
	 */
	static nts::x509::error_t keyAlgorithm(asn1::writer_t & writer, const nts::x509::key_t & key) noexcept {
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		// Если ключ RSA
		if(key.algorithm.compare("1.2.840.113549.1.1.1") == 0){
			// Записываем опознаватель алгоритма
			object(writer, "1.2.840.113549.1.1.1");
			// Записываем пустые настройки: раздел 2.3.1 RFC 3279
			writer.nothing();
		// Если ключ EC
		} else if(key.algorithm.compare("1.2.840.10045.2.1") == 0){
			// Записываем опознаватель алгоритма
			object(writer, "1.2.840.10045.2.1");
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
				const asn1::error_t outcome = asn1::oid(element, oid);
				// Если опознаватель кривой разобрать не удалось
				if(outcome != asn1::error_t::NONE)
					// Выводим переведённый отказ разбора
					return translate(outcome);
				// Записываем опознаватель кривой
				writer.oid(oid);
			// Если настроек нет
			} else return nts::x509::error_t::KEY;
		// Если ключ Ed25519
		} else if(key.algorithm.compare("1.3.101.112") == 0){
			// Записываем опознаватель алгоритма: настроек у него нет
			object(writer, "1.3.101.112");
		// Если ключ SM2
		} else if(key.algorithm.compare("1.2.156.10197.1.301") == 0){
			// Записываем опознаватель алгоритма: настроек у него нет
			object(writer, "1.2.156.10197.1.301");
		// Если ключ ML-DSA
		} else if((key.algorithm.compare("2.16.840.1.101.3.4.3.17") == 0) || (key.algorithm.compare("2.16.840.1.101.3.4.3.18") == 0) || (key.algorithm.compare("2.16.840.1.101.3.4.3.19") == 0)){
			// Записываем опознаватель алгоритма ключа: настроек у него нет
			writer.oid(key.algorithm);
		// Если ключ ГОСТ
		} else if((key.algorithm.compare("1.2.643.7.1.1.1.1") == 0) || (key.algorithm.compare("1.2.643.7.1.1.1.2") == 0) || (key.algorithm.compare("1.2.643.2.2.19") == 0)){
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
				const asn1::error_t outcome = asn1::oid(element, oid);
				// Если опознаватель кривой разобрать не удалось
				if(outcome != asn1::error_t::NONE)
					// Выводим переведённый отказ разбора
					return translate(outcome);
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
					const asn1::error_t extracted = asn1::oid(element, digest);
					// Если опознаватель хеша разобрать не удалось
					if(extracted != asn1::error_t::NONE)
						// Выводим переведённый отказ разбора
						return translate(extracted);
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
	 * @brief Функция записи тела открытого ключа
	 *
	 * @param key    записываемый ключ
	 * @param writer записчик, в который помещается тело ключа
	 * @return       отказ записи тела ключа
	 *
	 */
	static nts::x509::error_t keyBody(const nts::x509::key_t & key, asn1::writer_t & writer) noexcept {
		// Если запись ключа не передана
		if((key.key.data == nullptr) || (key.key.size == 0))
			// Выводим отказ ключа
			return nts::x509::error_t::KEY;
		// Записываем строку битов ключа
		writer.bits(key.key);
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? nts::x509::error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Функция записи набора расширений
	 *
	 * @param writer     записчик, в который помещается набор расширений
	 * @param extensions записываемый набор расширений
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
	 * @brief Функция выработки подписи содержимого ключом
	 *
	 * @param signer    подготовленный секретный ключ подписи
	 * @param hash      алгоритм хеша подписи (для ECDSA и RSA)
	 * @param content   подписываемое содержимое
	 * @param signature место, в которое помещается подпись
	 * @return          отказ выработки подписи
	 *
	 */
	static nts::x509::error_t makeSignature(const keys::signer_t & signer, const digest::hash_t hash, const view_t & content, vector <uint8_t> & signature) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
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
		// Если памяти под итог не хватило
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
	static const char * signatureAlgorithm(const keys::signer_t & signer, const digest::hash_t hash) noexcept {
		/**
		 * Выполняем определение вида ключа подписи
		 */
		switch(signer.kind()){
			// Ключ RSA
			case keys::kind_t::RSA:
				/**
				 * Выводим опознаватель по хешу
				 */
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
				/**
				 * Выводим опознаватель по хешу
				 */
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
				/**
				 * Выводим опознаватель по набору ключа
				 */
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
	/**
	 * @brief Функция сборки и подписи сертификата
	 *
	 * @param issuer     имя издателя сертификата
	 * @param subject    имя владельца сертификата
	 * @param key        сведения об открытом ключе владельца
	 * @param signer     подготовленный секретный ключ подписи
	 * @param hash       алгоритм хеша подписи
	 * @param serial     порядковый номер сертификата
	 * @param before     начало срока действия
	 * @param after      окончание срока действия
	 * @param extensions набор расширений сертификата
	 * @param result     место, в которое помещается запись сертификата
	 * @return           отказ сборки и подписи сертификата
	 *
	 */
	static nts::x509::error_t build(const name_t & issuer, const name_t & subject, const nts::x509::key_t & key, const keys::signer_t & signer, const digest::hash_t hash, const view_t & serial, const int64_t before, const int64_t after, const vector <extension_t> & extensions, vector <uint8_t> & result) noexcept {
		// Если ключ не подготовлен
		if(!signer.ready())
			// Выводим отказ ключа
			return nts::x509::error_t::KEY;
		// Если порядковый номер пуст либо нулевой
		if((serial.data == nullptr) || (serial.size == 0) || (serial.size > 20))
			// Выводим отказ номера
			return nts::x509::error_t::SERIAL;
		// Если срок действия неупорядочен
		if(before >= after)
			// Выводим отказ срока
			return nts::x509::error_t::VALIDITY;
		// Получаем опознаватель алгоритма подписи
		const char * algorithm = signatureAlgorithm(signer, hash);
		// Если алгоритм подписи не определён
		if(algorithm == nullptr)
			// Выводим отказ подписи
			return nts::x509::error_t::SIGNATURE;
		// Записчик подписываемой части сертификата
		asn1::writer_t body;
		// Открываем набор подписываемой части
		body.open(asn1::tag_t::SEQUENCE);
		// Если расширения есть: сертификат третьего издания
		if(!extensions.empty()){
			// Открываем издание сертификата: явный [0]
			body.open(asn1::cls_t::CONTEXT, 0);
			// Записываем издание v3
			body.integer(2);
			// Закрываем издание сертификата
			body.close();
		}
		// Записываем порядковый номер сертификата
		body.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), serial);
		// Открываем набор алгоритма подписи
		body.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма подписи
		object(body, algorithm);
		// Если алгоритм подписи несёт настройки NULL (RSA)
		if(signer.kind() == keys::kind_t::RSA)
			// Записываем пустые настройки
			body.nothing();
		// Закрываем набор алгоритма подписи
		body.close();
		// Итог записи имени издателя
		nts::x509::error_t outcome = nameBody(body, issuer);
		// Если имя издателя записать не удалось
		if(outcome != nts::x509::error_t::NONE)
			// Выводим отказ записи
			return outcome;
		// Открываем набор срока действия
		body.open(asn1::tag_t::SEQUENCE);
		// Записываем начало срока действия
		body.time(asn1::tag_t::UTC_TIME, before);
		// Записываем окончание срока действия
		body.time(asn1::tag_t::UTC_TIME, after);
		// Закрываем набор срока действия
		body.close();
		// Итог записи имени владельца
		outcome = nameBody(body, subject);
		// Если имя владельца записать не удалось
		if(outcome != nts::x509::error_t::NONE)
			// Выводим отказ записи
			return outcome;
		// Открываем набор сведений об открытом ключе
		body.open(asn1::tag_t::SEQUENCE);
		// Итог записи набора алгоритма ключа
		outcome = keyAlgorithm(body, key);
		// Если набор алгоритма записать не удалось
		if(outcome != nts::x509::error_t::NONE)
			// Выводим отказ записи
			return outcome;
		// Итог записи тела открытого ключа
		outcome = keyBody(key, body);
		// Если тело ключа записать не удалось
		if(outcome != nts::x509::error_t::NONE)
			// Выводим отказ записи
			return outcome;
		// Закрываем набор сведений об открытом ключе
		body.close();
		// Если расширения есть: записываем их явным [3]
		if(!extensions.empty()){
			// Открываем набор расширений: явный [3]
			body.open(asn1::cls_t::CONTEXT, 3);
			// Итог записи набора расширений
			outcome = extensionsBody(body, extensions);
			// Если набор расширений записать не удалось
			if(outcome != nts::x509::error_t::NONE)
				// Выводим отказ записи
				return outcome;
			// Закрываем набор расширений
			body.close();
		}
		// Закрываем набор подписываемой части
		body.close();
		// Если подписываемую часть записать не удалось
		if(body.err() != asn1::error_t::NONE)
			// Выводим переведённый отказ записи
			return translate(body.err());
		// Подпись сертификата
		vector <uint8_t> signature;
		// Итог выработки подписи
		outcome = makeSignature(signer, hash, body.data(), signature);
		// Если подпись выработать не удалось
		if(outcome != nts::x509::error_t::NONE)
			// Выводим отказ подписи
			return outcome;
		// Записчик хвоста записи сертификата: опознаватель алгоритма подписи и сама подпись
		asn1::writer_t tail;
		// Открываем набор алгоритма подписи
		tail.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель алгоритма подписи
		object(tail, algorithm);
		// Если алгоритм подписи несёт настройки NULL (RSA)
		if(signer.kind() == keys::kind_t::RSA)
			// Записываем пустые настройки
			tail.nothing();
		// Закрываем набор алгоритма подписи
		tail.close();
		// Записываем подпись строкой битов
		tail.bits(view_t(signature.data(), signature.size()));
		// Если хвост записи сертификата записать не удалось
		if(tail.err() != asn1::error_t::NONE)
			// Выводим переведённый отказ записи
			return translate(tail.err());
		// Получаем просмотр подписываемой части
		const view_t signedPart = body.data();
		// Получаем просмотр хвоста записи
		const view_t tailPart = tail.data();
		// Содержимое записи сертификата: подписываемая часть и хвост
		vector <uint8_t> content;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Выполняем сборку содержимого записи сертификата
			content.reserve(signedPart.size + tailPart.size);
			// Дописываем подписываемую часть
			content.insert(content.end(), signedPart.data, signedPart.data + signedPart.size);
			// Дописываем хвост записи
			content.insert(content.end(), tailPart.data, tailPart.data + tailPart.size);
		// Если памяти не хватило
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return nts::x509::error_t::MEMORY;
		}
		// Записчик записи сертификата
		asn1::writer_t writer;
		// Записываем набор записи сертификата с собранным содержимым
		writer.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), view_t(content.data(), content.size()));
		// Если запись сертификата записать не удалось
		if(writer.err() != asn1::error_t::NONE)
			// Выводим переведённый отказ записи
			return translate(writer.err());
		// Получаем просмотр собранной записи
		const view_t data = writer.data();
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Выполняем копирование записи
			result.assign(data.data, data.data + data.size);
		// Если памяти не хватило
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return nts::x509::error_t::MEMORY;
		}
		// Выводим успешность сборки
		return nts::x509::error_t::NONE;
	}
};

/**
 * @brief Функция выпуска самоподписанного сертификата
 *
 * @param subject    имя владельца сертификата (оно же имя издателя)
 * @param key        сведения об открытом ключе владельца
 * @param signer     подготовленный секретный ключ подписи (тот же, что и у владельца)
 * @param hash       алгоритм хеша подписи (для ECDSA и RSA; у Ed25519, ML-DSA, SM2 и ГОСТ не рассматривается)
 * @param serial     порядковый номер сертификата (не нулевой)
 * @param before     начало срока действия в секундах от начала эпохи
 * @param after      окончание срока действия в секундах от начала эпохи
 * @param extensions набор расширений сертификата (пустой набор - без расширений, сертификат v1)
 * @param result     место, в которое помещается запись сертификата в кодировке DER
 * @return           отказ выпуска сертификата
 *
 */
nts::x509::error_t nts::x509::issueSelfSigned(const name_t & subject, const nts::x509::key_t & key, const keys::signer_t & signer, const digest::hash_t hash, const view_t & serial, const int64_t before, const int64_t after, const vector <extension_t> & extensions, vector <uint8_t> & result) noexcept {
	// Выводим итог сборки и подписи сертификата: издатель и владелец одно имя
	return build(subject, subject, key, signer, hash, serial, before, after, extensions, result);
}

/**
 * @brief Функция выпуска сертификата по запросу PKCS #10 подписью ЦС
 *
 * @param request    разобранный запрос на сертификат (подпись уже проверена вызывающим)
 * @param issuer     имя издателя сертификата (из сертификата ЦС)
 * @param signer     подготовленный секретный ключ ЦС
 * @param hash       алгоритм хеша подписи (для ECDSA и RSA; у Ed25519, ML-DSA, SM2 и ГОСТ не рассматривается)
 * @param serial     порядковый номер сертификата (не нулевой)
 * @param before     начало срока действия в секундах от начала эпохи
 * @param after      окончание срока действия в секундах от начала эпохи
 * @param extensions набор расширений сертификата (пустой набор - без расширений, сертификат v1)
 * @param result     место, в которое помещается запись сертификата в кодировке DER
 * @return           отказ выпуска сертификата
 *
 */
nts::x509::error_t nts::x509::issueByCA(const request_t & request, const name_t & issuer, const keys::signer_t & signer, const digest::hash_t hash, const view_t & serial, const int64_t before, const int64_t after, const vector <extension_t> & extensions, vector <uint8_t> & result) noexcept {
	// Выводим итог сборки и подписи сертификата: имя и ключ из запроса, издатель из ЦС
	return build(issuer, request.subjects(), request.key(), signer, hash, serial, before, after, extensions, result);
}
