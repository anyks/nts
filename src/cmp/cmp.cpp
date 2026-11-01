/**
 * @file cmp.cpp
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
 * @brief Модуль CMP — разбор и сборка сообщений управления сертификатами
 *        по RFC 4210 без применения исключений
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочный файл модуля
 */
#include <cmp/cmp.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <asn1/asn1.hpp>
#include <digest/hmac.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>
#include <x509/signature.hpp>

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>
#include <ctime>

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
	 * Опознаватель алгоритма парольной имитовставки PBM: раздел 5.1.3.1 RFC 4210
	 */
	static const char * OID_PBM = "1.2.840.113533.7.66.13";

	/**
	 * Опознаватели алгоритмов хеша
	 */
	static const char * OID_SHA1 = "1.3.14.3.2.26";
	// Опознаватель алгоритма SHA-224 (FIPS 180-4, реестр NIST CSOR)
	static const char * OID_SHA224 = "2.16.840.1.101.3.4.2.4";
	// Опознаватель алгоритма SHA-256 (FIPS 180-4, реестр NIST CSOR)
	static const char * OID_SHA256 = "2.16.840.1.101.3.4.2.1";
	// Опознаватель алгоритма SHA-384 (FIPS 180-4, реестр NIST CSOR)
	static const char * OID_SHA384 = "2.16.840.1.101.3.4.2.2";
	// Опознаватель алгоритма SHA-512 (FIPS 180-4, реестр NIST CSOR)
	static const char * OID_SHA512 = "2.16.840.1.101.3.4.2.3";

	/**
	 * Опознаватели алгоритмов имитовставки HMAC: раздел 4 RFC 4231
	 */
	static const char * OID_HMAC_SHA1 = "1.3.6.1.5.5.8.1.2";
	// Опознаватель имитовставки HMAC на SHA-224 (RFC 4231, раздел 4)
	static const char * OID_HMAC_SHA224 = "1.2.840.113549.2.8";
	// Опознаватель имитовставки HMAC на SHA-256 (RFC 4231, раздел 4)
	static const char * OID_HMAC_SHA256 = "1.2.840.113549.2.9";
	// Опознаватель имитовставки HMAC на SHA-384 (RFC 4231, раздел 4)
	static const char * OID_HMAC_SHA384 = "1.2.840.113549.2.10";
	// Опознаватель имитовставки HMAC на SHA-512 (RFC 4231, раздел 4)
	static const char * OID_HMAC_SHA512 = "1.2.840.113549.2.11";

	/**
	 * Опознаватели алгоритмов подписи
	 */
	static const char * OID_SHA1_RSA = "1.2.840.113549.1.1.5";
	// Опознаватель подписи RSA на SHA-224 (PKCS#1)
	static const char * OID_SHA224_RSA = "1.2.840.113549.1.1.14";
	// Опознаватель подписи RSA на SHA-256 (PKCS#1)
	static const char * OID_SHA256_RSA = "1.2.840.113549.1.1.11";
	// Опознаватель подписи RSA на SHA-384 (PKCS#1)
	static const char * OID_SHA384_RSA = "1.2.840.113549.1.1.12";
	// Опознаватель подписи RSA на SHA-512 (PKCS#1)
	static const char * OID_SHA512_RSA = "1.2.840.113549.1.1.13";
	// Опознаватель подписи ECDSA на SHA-224 (RFC 5480)
	static const char * OID_SHA224_ECDSA = "1.2.840.10045.4.3.1";
	// Опознаватель подписи ECDSA на SHA-256 (RFC 5480)
	static const char * OID_SHA256_ECDSA = "1.2.840.10045.4.3.2";
	// Опознаватель подписи ECDSA на SHA-384 (RFC 5480)
	static const char * OID_SHA384_ECDSA = "1.2.840.10045.4.3.3";
	// Опознаватель подписи ECDSA на SHA-512 (RFC 5480)
	static const char * OID_SHA512_ECDSA = "1.2.840.10045.4.3.4";
	// Опознаватель подписи Ed25519 (RFC 8410)
	static const char * OID_ED25519 = "1.3.101.112";
	// Опознаватель подписи ML-DSA-44 (FIPS 204)
	static const char * OID_MLDSA44 = "2.16.840.1.101.3.4.3.17";
	// Опознаватель подписи ML-DSA-65 (FIPS 204)
	static const char * OID_MLDSA65 = "2.16.840.1.101.3.4.3.18";
	// Опознаватель подписи ML-DSA-87 (FIPS 204)
	static const char * OID_MLDSA87 = "2.16.840.1.101.3.4.3.19";

	/**
	 * Число повторов односторонней функции PBM по умолчанию
	 */
	static constexpr int64_t PBM_ITERATIONS = 500;

	/**
	 * @brief Функция перевода отказа разборщика ASN.1 в отказ модуля
	 *
	 * @param error отказ разборщика ASN.1
	 * @return      отказ модуля
	 *
	 */
	static nts::cmp::error_t translate(const asn1::error_t error) noexcept {
		// Выводим отказ модуля: нехватка памяти отдаётся своим отказом, всё прочее - отказом устройства
		return ((error == asn1::error_t::MEMORY) ? nts::cmp::error_t::MEMORY : nts::cmp::error_t::STRUCTURE);
	}
	/**
	 * @brief Функция разбора опознавателя объекта
	 *
	 * @param element разбираемый элемент
	 * @param result  место, в которое помещается опознаватель
	 * @return        отказ разбора опознавателя
	 *
	 */
	static nts::cmp::error_t oidOf(const asn1::element_t & element, string & result) noexcept {
		// Итог разбора опознавателя
		const asn1::error_t outcome = asn1::oid(element, result);
		// Выводим переведённый отказ разбора, если он есть
		return ((outcome == asn1::error_t::NONE) ? nts::cmp::error_t::NONE : translate(outcome));
	}
	/**
	 * @brief Функция разбора записи опознавателя алгоритма
	 *
	 * @param element разбираемый элемент записи AlgorithmIdentifier
	 * @param oid     место, в которое помещается опознаватель алгоритма
	 * @param params  место, в которое помещается запись настроек алгоритма
	 * @return        отказ разбора записи
	 *
	 */
	static nts::cmp::error_t algorithmIdentifier(const asn1::element_t & element, string & oid, view_t & params) noexcept {
		// Если запись алгоритма не составная
		if(!element.constructed)
			// Выводим отказ устройства записи
			return nts::cmp::error_t::STRUCTURE;
		// Разборщик содержимого записи алгоритма
		asn1::reader_t items(element.content);
		// Элемент опознавателя алгоритма
		asn1::element_t item;
		// Если опознаватель алгоритма разобрать не удалось
		if(!items.next(asn1::tag_t::OBJECT, item))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Итог разбора опознавателя алгоритма
		const nts::cmp::error_t outcome = oidOf(item, oid);
		// Если опознаватель алгоритма разобрать не удалось
		if(outcome != nts::cmp::error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Если настройки алгоритма записаны
		if(!items.empty()){
			// Если настройки алгоритма разобрать не удалось
			if(!items.next(item))
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Запоминаем запись настроек целиком
			params = item.element;
			// Если после настроек остался хвост
			if(!items.empty())
				// Выводим отказ устройства записи
				return nts::cmp::error_t::STRUCTURE;
		}
		// Выводим успешность разбора опознавателя алгоритма
		return nts::cmp::error_t::NONE;
	}
	/**
	 * @brief Функция получения алгоритма хеша по его опознавателю
	 *
	 * @param oid опознаватель алгоритма хеша
	 * @return    алгоритм хеша, hash_t::NONE у неизвестного
	 *
	 */
	static digest::hash_t hashOf(const string & oid) noexcept {
		// Выводим алгоритм хеша по опознавателю
		if(oid == OID_SHA1) return digest::hash_t::SHA1;
		if(oid == OID_SHA224) return digest::hash_t::SHA224;
		if(oid == OID_SHA256) return digest::hash_t::SHA256;
		if(oid == OID_SHA384) return digest::hash_t::SHA384;
		if(oid == OID_SHA512) return digest::hash_t::SHA512;
		// Выводим отсутствие алгоритма
		return digest::hash_t::NONE;
	}
	/**
	 * @brief Функция получения опознавателя алгоритма хеша
	 *
	 * @param hash алгоритм хеша
	 * @return     опознаватель алгоритма хеша либо nullptr
	 *
	 */
	static const char * oidOf(const digest::hash_t hash) noexcept {
		/**
		 * Выводим опознаватель по алгоритму хеша
		 */
		switch(hash){
			case digest::hash_t::SHA1: return OID_SHA1;
			case digest::hash_t::SHA224: return OID_SHA224;
			case digest::hash_t::SHA256: return OID_SHA256;
			case digest::hash_t::SHA384: return OID_SHA384;
			case digest::hash_t::SHA512: return OID_SHA512;
			default: return nullptr;
		}
	}
	/**
	 * @brief Функция получения алгоритма хеша имитовставки по её опознавателю
	 *
	 * @param oid опознаватель алгоритма имитовставки HMAC
	 * @return    алгоритм хеша, hash_t::NONE у неизвестного
	 *
	 */
	static digest::hash_t hmacOf(const string & oid) noexcept {
		// Выводим алгоритм хеша по опознавателю имитовставки
		if(oid == OID_HMAC_SHA1) return digest::hash_t::SHA1;
		if(oid == OID_HMAC_SHA224) return digest::hash_t::SHA224;
		if(oid == OID_HMAC_SHA256) return digest::hash_t::SHA256;
		if(oid == OID_HMAC_SHA384) return digest::hash_t::SHA384;
		if(oid == OID_HMAC_SHA512) return digest::hash_t::SHA512;
		// Выводим отсутствие алгоритма
		return digest::hash_t::NONE;
	}
	/**
	 * @brief Функция получения опознавателя имитовставки HMAC по алгоритму хеша
	 *
	 * @param hash алгоритм хеша
	 * @return     опознаватель алгоритма имитовставки либо nullptr
	 *
	 */
	static const char * hmacOidOf(const digest::hash_t hash) noexcept {
		/**
		 * Выводим опознаватель имитовставки по алгоритму хеша
		 */
		switch(hash){
			case digest::hash_t::SHA1: return OID_HMAC_SHA1;
			case digest::hash_t::SHA224: return OID_HMAC_SHA224;
			case digest::hash_t::SHA256: return OID_HMAC_SHA256;
			case digest::hash_t::SHA384: return OID_HMAC_SHA384;
			case digest::hash_t::SHA512: return OID_HMAC_SHA512;
			default: return nullptr;
		}
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
				 * Выводим опознаватель подписи RSA по хешу
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
				 * Выводим опознаватель подписи ECDSA по хешу
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
				return OID_ED25519;
			// Ключ ML-DSA
			case keys::kind_t::MLDSA:
				/**
				 * Выводим опознаватель подписи ML-DSA по набору ключа
				 */
				switch(signer.mldsa().set()){
					case sign::mldsa_t::set_t::DSA44: return OID_MLDSA44;
					case sign::mldsa_t::set_t::DSA65: return OID_MLDSA65;
					case sign::mldsa_t::set_t::DSA87: return OID_MLDSA87;
					default: return nullptr;
				}
			// Ключ, подписи в CMP не выполняющий
			default:
				// Выводим отсутствие опознавателя
				return nullptr;
		}
	}
	/**
	 * @brief Функция выработки подписи содержимого
	 *
	 * @param signer    подготовленный секретный ключ подписи
	 * @param hash      алгоритм хеша подписи (для RSA и ECDSA)
	 * @param content   подписываемое содержимое
	 * @param signature место, в которое помещается подпись
	 * @return          отказ выработки подписи
	 *
	 */
	static nts::cmp::error_t makeSignature(const keys::signer_t & signer, const digest::hash_t hash, const view_t & content, vector <uint8_t> & signature) noexcept {
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
						return nts::cmp::error_t::PROTECTION;
					// Занимаем место под подпись длиною в модуль ключа
					signature.assign(rsa.size(), 0);
					// Если подпись выработать не удалось
					if(!rsa.make(sign::scheme_t::PKCS1, hash, view_t(digest, digest::length(hash)), signature.data(), SIZE_MAX))
						// Выводим отказ подписи
						return nts::cmp::error_t::PROTECTION;
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
						return nts::cmp::error_t::PROTECTION;
					// Место, в которое помещается подпись в сыром виде
					uint8_t raw[math::NUMBER_SIZE * 2];
					// Если подпись выработать не удалось
					if(!ecdsa.make(hash, view_t(digest, digest::length(hash)), raw))
						// Выводим отказ подписи
						return nts::cmp::error_t::PROTECTION;
					// Занимаем место под запись подписи по её пределу
					signature.assign(ecdsa.limit(), 0);
					// Длина записи подписи
					size_t written = signature.size();
					// Если подпись в запись DER перевести не удалось
					if(!sign::encode(view_t(raw, ecdsa.size()), signature.data(), written))
						// Выводим отказ подписи
						return nts::cmp::error_t::PROTECTION;
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
						return nts::cmp::error_t::PROTECTION;
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
						return nts::cmp::error_t::PROTECTION;
				} break;
				// Ключ, подписи в CMP не выполняющий
				default:
					// Выводим отказ ключа
					return nts::cmp::error_t::KEY;
			}
		// Если памяти под итог не хватило
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return nts::cmp::error_t::MEMORY;
		}
		// Выводим успешность выработки подписи
		return nts::cmp::error_t::NONE;
	}
	/**
	 * @brief Функция записи опознавателя алгоритма с пустыми настройками
	 *
	 * @param writer записчик, в который ведётся запись
	 * @param oid    опознаватель алгоритма
	 * @param empty  признак записи пустых настроек NULL
	 * @return       признак успешности записи
	 *
	 */
	static bool writeAlgorithm(asn1::writer_t & writer, const char * oid, const bool empty) noexcept {
		// Открываем запись алгоритма
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ записи
			return false;
		// Записываем опознаватель алгоритма
		if(!writer.oid(oid)){
			// Выводим отказ записи
			return false;
		}
		// Если пустые настройки велено записать
		if(empty && !writer.nothing()){
			// Выводим отказ записи
			return false;
		}
		// Закрываем запись алгоритма и выводим итог записи
		return writer.close();
	}
	/**
	 * @brief Функция переноса готовой записи в записчик как элемента
	 *
	 * @param writer записчик, в который ведётся запись
	 * @param record переносимая запись целиком, с меткой и длиной
	 * @return       признак успешности переноса
	 *
	 */
	static bool embed(asn1::writer_t & writer, const view_t & record) noexcept {
		// Разборщик переносимой записи
		asn1::reader_t reader(record);
		// Элемент переносимой записи
		asn1::element_t element;
		// Если запись разобрать не удалось
		if(!reader.next(element))
			// Выводим отказ переноса
			return false;
		// Переносим содержимое записи с её меткой и выводим итог переноса
		return writer.element(element.cls, element.constructed, element.tag, element.content);
	}
	/**
	 * @brief Функция выработки ключа имитовставки PBM по разделу 5.1.3.1 RFC 4210
	 *
	 * @param password пароль общего секрета
	 * @param salt     метка соли из настроек PBM
	 * @param hash     алгоритм хеша односторонней функции
	 * @param count    число повторов односторонней функции
	 * @param length   требуемая длина ключа имитовставки в байтах
	 * @param result   место, в которое помещается ключ
	 * @return         отказ выработки ключа
	 *
	 * @note Соль прилагается к секрету, односторонняя функция применяется count раз;
	 *       при нехватке длины итог дополняется хешами OWF("1" || BASEKEY) и далее,
	 *       как велит раздел 5.1.3.1
	 *
	 */
	static nts::cmp::error_t pbmKey(const view_t & password, const view_t & salt, const digest::hash_t hash, const int64_t count, const size_t length, vector <uint8_t> & result) noexcept {
		// Длина хеша односторонней функции
		const size_t width = digest::length(hash);
		// Если алгоритм хеша неизвестен либо повторов нет
		if((width == 0) || (count <= 0))
			// Выводим отказ алгоритма
			return nts::cmp::error_t::ALGORITHM;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Место, в которое помещается секрет с солью
			vector <uint8_t> base;
			// Занимаем место под секрет с солью
			base.reserve(password.size + salt.size);
			// Переносим секрет
			base.insert(base.end(), static_cast <const uint8_t *> (password.data), static_cast <const uint8_t *> (password.data) + password.size);
			// Переносим соль
			base.insert(base.end(), static_cast <const uint8_t *> (salt.data), static_cast <const uint8_t *> (salt.data) + salt.size);
			// Место, в которое помещается итог повтора
			uint8_t round[64];
			// Первый повтор: односторонняя функция над секретом с солью
			if(!digest::hash(hash, view_t(base.data(), base.size()), round, sizeof(round))){
				// Затираем секрет с солью
				nts::sys::wipe(base.data(), base.size());
				// Выводим отказ алгоритма
				return nts::cmp::error_t::ALGORITHM;
			}
			// Затираем секрет с солью
			nts::sys::wipe(base.data(), base.size());
			/**
			 * Прочие повторы: односторонняя функция над итогом прежнего повтора
			 */
			for(int64_t i = 1; i < count; i++){
				// Если повтор выработать не удалось
				if(!digest::hash(hash, view_t(round, width), round, sizeof(round))){
					// Затираем итог повтора
					nts::sys::wipe(round, sizeof(round));
					// Выводим отказ алгоритма
					return nts::cmp::error_t::ALGORITHM;
				}
			}
			// Занимаем место под ключ
			result.assign(length, 0);
			// Если хеша хватает на ключ целиком
			if(length <= width){
				// Переносим старшие байты итога
				::memcpy(result.data(), round, length);
			// Иначе ключ длиннее хеша: дополняем хешами OWF("N" || BASEKEY)
			} else {
				// Переносим итог в старшие байты ключа
				::memcpy(result.data(), round, width);
				// Место, в которое помещается ввод дополнения
				vector <uint8_t> extra;
				// Смещение заполненной части ключа
				size_t filled = width;
				// Номер дополнения
				uint8_t number = '1';
				/**
				 * Дополняем ключ, пока он не заполнен
				 */
				while(filled < length){
					// Собираем ввод дополнения: номер и итог
					extra.assign(1, number);
					// Переносим итог
					extra.insert(extra.end(), round, round + width);
					// Место, в которое помещается хеш дополнения
					uint8_t more[64];
					// Если хеш дополнения выработать не удалось
					if(!digest::hash(hash, view_t(extra.data(), extra.size()), more, sizeof(more))){
						// Затираем итог повтора и ввод дополнения
						nts::sys::wipe(round, sizeof(round));
						nts::sys::wipe(extra.data(), extra.size());
						// Выводим отказ алгоритма
						return nts::cmp::error_t::ALGORITHM;
					}
					// Длина переносимой части дополнения
					const size_t part = ((length - filled < width) ? (length - filled) : width);
					// Переносим часть дополнения
					::memcpy(result.data() + filled, more, part);
					// Затираем хеш дополнения
					nts::sys::wipe(more, sizeof(more));
					// Запоминаем заполненную часть
					filled += part;
					// Номер следующего дополнения
					number++;
				}
				// Затираем ввод дополнения
				nts::sys::wipe(extra.data(), extra.size());
			}
			// Затираем итог повтора
			nts::sys::wipe(round, sizeof(round));
		// Если памяти под итог не хватило
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return nts::cmp::error_t::MEMORY;
		}
		// Выводим успешность выработки ключа
		return nts::cmp::error_t::NONE;
	}
	/**
	 * @brief Функция разбора настроек PBM и выработки ключа имитовставки
	 *
	 * @param params   запись настроек PBMParameter
	 * @param password пароль общего секрета
	 * @param hash     место, в которое помещается алгоритм хеша имитовставки
	 * @param key      место, в которое помещается ключ имитовставки
	 * @return         отказ разбора настроек
	 *
	 */
	static nts::cmp::error_t pbmParameters(const view_t & params, const view_t & password, digest::hash_t & hash, vector <uint8_t> & key) noexcept {
		// Разборщик записи настроек
		asn1::reader_t reader(params);
		// Элемент записи настроек
		asn1::element_t element;
		// Если запись настроек разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, element) || !element.constructed)
			// Выводим переведённый отказ разбора
			return translate(reader.err());
		// Разборщик содержимого записи настроек
		asn1::reader_t items(element.content);
		// Элемент соли
		asn1::element_t salt;
		// Если соль разобрать не удалось
		if(!items.next(asn1::tag_t::OCTET_STRING, salt))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Элемент записи односторонней функции
		asn1::element_t owf;
		// Если запись односторонней функции разобрать не удалось
		if(!items.next(asn1::tag_t::SEQUENCE, owf))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Опознаватель односторонней функции
		string owfOid;
		// Просмотр настроек односторонней функции
		view_t owfParams;
		// Если запись односторонней функции разобрать не удалось
		if(algorithmIdentifier(owf, owfOid, owfParams) != nts::cmp::error_t::NONE)
			// Выводим отказ устройства записи
			return nts::cmp::error_t::STRUCTURE;
		// Алгоритм хеша односторонней функции
		const digest::hash_t owfHash = hashOf(owfOid);
		// Если алгоритм хеша односторонней функции неизвестен
		if(owfHash == digest::hash_t::NONE)
			// Выводим отказ алгоритма
			return nts::cmp::error_t::ALGORITHM;
		// Элемент числа повторов
		asn1::element_t iterations;
		// Если число повторов разобрать не удалось
		if(!items.next(asn1::tag_t::INTEGER, iterations))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Число повторов односторонней функции
		int64_t count = 0;
		// Если число повторов разобрать не удалось
		if(asn1::integer(iterations, count) != asn1::error_t::NONE)
			// Выводим отказ устройства записи
			return nts::cmp::error_t::STRUCTURE;
		// Элемент записи имитовставки
		asn1::element_t mac;
		// Если запись имитовставки разобрать не удалось
		if(!items.next(asn1::tag_t::SEQUENCE, mac))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Опознаватель имитовставки
		string macOid;
		// Просмотр настроек имитовставки
		view_t macParams;
		// Если запись имитовставки разобрать не удалось
		if(algorithmIdentifier(mac, macOid, macParams) != nts::cmp::error_t::NONE)
			// Выводим отказ устройства записи
			return nts::cmp::error_t::STRUCTURE;
		// Если после имитовставки остался хвост
		if(!items.empty())
			// Выводим отказ устройства записи
			return nts::cmp::error_t::STRUCTURE;
		// Алгоритм хеша имитовставки
		hash = hmacOf(macOid);
		// Если алгоритм хеша имитовставки неизвестен
		if(hash == digest::hash_t::NONE)
			// Выводим отказ алгоритма
			return nts::cmp::error_t::ALGORITHM;
		// Вырабатываем ключ имитовставки: HMAC принимает ключ любой длины, потому
		// ключом служит весь BASEKEY длиною в хеш односторонней функции, как делает
		// эталон OpenSSL, а не усечение до длины итога имитовставки
		return pbmKey(password, salt.content, owfHash, count, digest::length(owfHash), key);
	}
	/**
	 * @brief Функция сборки записи настроек PBMParameter
	 *
	 * @param salt   метка соли
	 * @param hash   алгоритм хеша односторонней функции и имитовставки
	 * @param result место, в которое помещается запись настроек
	 * @return       отказ сборки настроек
	 *
	 */
	static nts::cmp::error_t pbmWrite(const view_t & salt, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
		// Опознаватель алгоритма хеша
		const char * hashOid = oidOf(hash);
		// Опознаватель алгоритма имитовставки
		const char * macOid = hmacOidOf(hash);
		// Если алгоритм хеша либо имитовставки неизвестен
		if((hashOid == nullptr) || (macOid == nullptr))
			// Выводим отказ алгоритма
			return nts::cmp::error_t::ALGORITHM;
		// Записчик настроек
		asn1::writer_t writer;
		// Открываем запись настроек
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Записываем соль
		if(!writer.octets(salt))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Записываем одностороннюю функцию с пустыми настройками
		if(!writeAlgorithm(writer, hashOid, true))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Записываем число повторов
		if(!writer.integer(PBM_ITERATIONS))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Записываем имитовставку с пустыми настройками
		if(!writeAlgorithm(writer, macOid, true))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Закрываем запись настроек
		if(!writer.close())
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Переносим запись настроек в итог
			result.assign(writer.data().data, writer.data().data + writer.data().size);
		// Если памяти под итог не хватило
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return nts::cmp::error_t::MEMORY;
		}
		// Выводим успешность сборки настроек
		return nts::cmp::error_t::NONE;
	}
	/**
	 * @brief Функция сборки защищаемой части ProtectedPart
	 *
	 * @param header запись заголовка
	 * @param body   запись тела (с меткой вида)
	 * @param result место, в которое помещается запись защищаемой части
	 * @return       отказ сборки защищаемой части
	 *
	 */
	static nts::cmp::error_t protectedPart(const view_t & header, const view_t & body, vector <uint8_t> & result) noexcept {
		// Записчик защищаемой части
		asn1::writer_t writer;
		// Открываем запись защищаемой части
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Переносим запись заголовка
		if(!embed(writer, header))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Переносим запись тела
		if(!embed(writer, body))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Закрываем запись защищаемой части
		if(!writer.close())
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Переносим запись защищаемой части в итог
			result.assign(writer.data().data, writer.data().data + writer.data().size);
		// Если памяти под итог не хватило
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return nts::cmp::error_t::MEMORY;
		}
		// Выводим успешность сборки защищаемой части
		return nts::cmp::error_t::NONE;
	}
	/**
	 * @brief Функция сборки заголовка PKIHeader
	 *
	 * @param sender    запись GeneralName отправителя, пустая - «NULL»-имя
	 * @param recipient запись GeneralName получателя
	 * @param kid       опознаватель ключа отправителя, пустой при его отсутствии
	 * @param algorithm опознаватель алгоритма защиты, nullptr при её отсутствии
	 * @param params    запись настроек алгоритма защиты
	 * @param result    место, в которое помещается запись заголовка
	 * @return          отказ сборки заголовка
	 *
	 * @note Метки полей заголовка явные (EXPLICIT) по модулю ASN.1 RFC 4210:
	 *       messageTime, protectionAlg и senderKID несут составную метку с записью
	 *       значения внутри
	 *
	 */
	static nts::cmp::error_t buildHeader(const view_t & sender, const view_t & recipient, const view_t & kid, const char * algorithm, const view_t & params, vector <uint8_t> & result) noexcept {
		// Записчик заголовка
		asn1::writer_t writer;
		// Открываем запись заголовка
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Записываем издание протокола cmp2000
		if(!writer.integer(2))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Если имя отправителя задано
		if(sender.size > 0){
			// Переносим запись имени отправителя
			if(!embed(writer, sender))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
		// Иначе имя отправителя неизвестно: «NULL»-имя по разделу 5.1.1
		} else {
			// Открываем запись directoryName
			if(!writer.open(asn1::cls_t::CONTEXT, 4))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Открываем пустую запись имени
			if(!writer.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Закрываем запись имени и запись directoryName
			if(!writer.close() || !writer.close())
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
		}
		// Переносим запись имени получателя
		if(!embed(writer, recipient))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Записываем время создания сообщения под явной меткой [0]
		{
			// Записчик записи времени
			asn1::writer_t moment;
			// Записываем время создания
			if(!moment.time(asn1::tag_t::GENERALIZED_TIME, static_cast <int64_t> (::time(nullptr))))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Открываем явную метку [0]
			if(!writer.open(asn1::cls_t::CONTEXT, 0))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Переносим запись времени
			if(!embed(writer, moment.data()))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Закрываем явную метку [0]
			if(!writer.close())
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
		}
		// Если алгоритм защиты задан
		if(algorithm != nullptr){
			// Записчик записи алгоритма защиты
			asn1::writer_t protection;
			// Открываем запись алгоритма защиты
			if(!protection.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Записываем опознаватель алгоритма защиты
			if(!protection.oid(algorithm))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Если настройки алгоритма заданы
			if(params.size > 0){
				// Переносим запись настроек
				if(!embed(protection, params))
					// Выводим отказ сборки
					return nts::cmp::error_t::MEMORY;
			// Иначе записываем пустые настройки
			} else if(!protection.nothing()){
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			}
			// Закрываем запись алгоритма защиты
			if(!protection.close())
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Записываем алгоритм защиты под явной меткой [1]
			if(!writer.open(asn1::cls_t::CONTEXT, 1))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Переносим запись алгоритма защиты
			if(!embed(writer, protection.data()))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Закрываем явную метку [1]
			if(!writer.close())
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
		}
		// Если опознаватель ключа отправителя задан
		if(kid.size > 0){
			// Записываем опознаватель ключа под явной меткой [2]
			if(!writer.open(asn1::cls_t::CONTEXT, 2))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Записываем содержимое опознавателя строкой байтов
			if(!writer.octets(kid))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Закрываем явную метку [2]
			if(!writer.close())
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
		}
		// Закрываем запись заголовка
		if(!writer.close())
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Переносим запись заголовка в итог
			result.assign(writer.data().data, writer.data().data + writer.data().size);
		// Если памяти под итог не хватило
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return nts::cmp::error_t::MEMORY;
		}
		// Выводим успешность сборки заголовка
		return nts::cmp::error_t::NONE;
	}
	/**
	 * @brief Функция сборки сообщения из заголовка и тела с защитой подписью
	 *
	 * @param sender    запись GeneralName отправителя
	 * @param recipient запись GeneralName получателя
	 * @param body      запись тела (с меткой вида)
	 * @param signer    подготовленный секретный ключ защиты подписью
	 * @param hash      алгоритм хеша подписи
	 * @param result    место, в которое помещается запись PKIMessage
	 * @return          отказ сборки сообщения
	 *
	 */
	static nts::cmp::error_t buildSigned(const view_t & sender, const view_t & recipient, const view_t & body, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
		// Если ключ не подготовлен
		if(!signer.ready())
			// Выводим отказ ключа
			return nts::cmp::error_t::KEY;
		// Опознаватель алгоритма подписи
		const char * algorithm = signatureAlgorithm(signer, hash);
		// Если опознаватель алгоритма подписи не найден
		if(algorithm == nullptr)
			// Выводим отказ алгоритма
			return nts::cmp::error_t::ALGORITHM;
		// Место, в которое помещается запись заголовка
		vector <uint8_t> header;
		// Итог сборки заголовка
		nts::cmp::error_t outcome = buildHeader(sender, recipient, view_t(nullptr, 0), algorithm, view_t(nullptr, 0), header);
		// Если заголовок собрать не удалось
		if(outcome != nts::cmp::error_t::NONE)
			// Выводим отказ сборки
			return outcome;
		// Место, в которое помещается защищаемая часть
		vector <uint8_t> part;
		// Итог сборки защищаемой части
		outcome = protectedPart(view_t(header.data(), header.size()), body, part);
		// Если защищаемую часть собрать не удалось
		if(outcome != nts::cmp::error_t::NONE)
			// Выводим отказ сборки
			return outcome;
		// Место, в которое помещается подпись
		vector <uint8_t> signature;
		// Итог выработки подписи
		outcome = makeSignature(signer, hash, view_t(part.data(), part.size()), signature);
		// Если подпись выработать не удалось
		if(outcome != nts::cmp::error_t::NONE)
			// Выводим отказ подписи
			return outcome;
		// Записчик сообщения
		asn1::writer_t writer;
		// Открываем запись сообщения
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Переносим запись заголовка
		if(!embed(writer, view_t(header.data(), header.size())))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Переносим запись тела
		if(!embed(writer, body))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Записываем подпись под явной меткой [0]: строка битов с нулём неиспользуемых разрядов
		{
			// Записчик записи строки битов
			asn1::writer_t bits;
			// Записываем подпись строкой битов
			if(!bits.bits(view_t(signature.data(), signature.size()), 0))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Открываем явную метку [0]
			if(!writer.open(asn1::cls_t::CONTEXT, 0))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Переносим запись строки битов
			if(!embed(writer, bits.data()))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Закрываем явную метку [0]
			if(!writer.close())
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
		}
		// Закрываем запись сообщения
		if(!writer.close())
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Переносим запись сообщения в итог
			result.assign(writer.data().data, writer.data().data + writer.data().size);
		// Если памяти под итог не хватило
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return nts::cmp::error_t::MEMORY;
		}
		// Выводим успешность сборки сообщения
		return nts::cmp::error_t::NONE;
	}
	/**
	 * @brief Функция сборки сообщения из заголовка и тела с защитой PBM
	 *
	 * @param sender    запись GeneralName отправителя
	 * @param recipient запись GeneralName получателя
	 * @param body      запись тела (с меткой вида)
	 * @param kid       опознаватель ключа отправителя senderKID
	 * @param password  пароль общего секрета
	 * @param hash      алгоритм хеша односторонней функции и имитовставки
	 * @param result    место, в которое помещается запись PKIMessage
	 * @return          отказ сборки сообщения
	 *
	 */
	static nts::cmp::error_t buildProtected(const view_t & sender, const view_t & recipient, const view_t & body, const view_t & kid, const view_t & password, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
		// Если пароль не задан
		if(password.size == 0)
			// Выводим отказ ключа
			return nts::cmp::error_t::EMPTY;
		// Место, в которое помещается метка соли
		uint8_t salt[16];
		// Если метку соли выработать не удалось
		if(!entropy::bytes(salt, sizeof(salt)))
			// Выводим отказ случайности
			return nts::cmp::error_t::RANDOM;
		// Место, в которое помещается запись настроек PBM
		vector <uint8_t> params;
		// Итог сборки настроек PBM
		nts::cmp::error_t outcome = pbmWrite(view_t(salt, sizeof(salt)), hash, params);
		// Если настройки собрать не удалось
		if(outcome != nts::cmp::error_t::NONE)
			// Выводим отказ сборки
			return outcome;
		// Место, в которое помещается запись заголовка
		vector <uint8_t> header;
		// Итог сборки заголовка
		outcome = buildHeader(sender, recipient, kid, OID_PBM, view_t(params.data(), params.size()), header);
		// Если заголовок собрать не удалось
		if(outcome != nts::cmp::error_t::NONE)
			// Выводим отказ сборки
			return outcome;
		// Место, в которое помещается защищаемая часть
		vector <uint8_t> part;
		// Итог сборки защищаемой части
		outcome = protectedPart(view_t(header.data(), header.size()), body, part);
		// Если защищаемую часть собрать не удалось
		if(outcome != nts::cmp::error_t::NONE)
			// Выводим отказ сборки
			return outcome;
		// Место, в которое помещается ключ имитовставки
		vector <uint8_t> key;
		// Итог выработки ключа имитовставки
		outcome = pbmKey(password, view_t(salt, sizeof(salt)), hash, PBM_ITERATIONS, digest::length(hash), key);
		// Если ключ выработать не удалось
		if(outcome != nts::cmp::error_t::NONE){
			// Затираем метку соли
			nts::sys::wipe(salt, sizeof(salt));
			// Выводим отказ выработки
			return outcome;
		}
		// Место, в которое помещается имитовставка
		uint8_t mac[64];
		// Если имитовставку выработать не удалось
		if(!digest::hmac(hash, view_t(key.data(), key.size()), view_t(part.data(), part.size()), mac, digest::length(hash))){
			// Затираем ключ и метку соли
			nts::sys::wipe(key.data(), key.size());
			nts::sys::wipe(salt, sizeof(salt));
			// Выводим отказ защиты
			return nts::cmp::error_t::PROTECTION;
		}
		// Записчик сообщения
		asn1::writer_t writer;
		// Открываем запись сообщения
		if(!writer.open(asn1::tag_t::SEQUENCE)){
			// Затираем ключ и метку соли
			nts::sys::wipe(key.data(), key.size());
			nts::sys::wipe(salt, sizeof(salt));
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		}
		// Переносим запись заголовка
		if(!embed(writer, view_t(header.data(), header.size()))){
			// Затираем ключ и метку соли
			nts::sys::wipe(key.data(), key.size());
			nts::sys::wipe(salt, sizeof(salt));
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		}
		// Переносим запись тела
		if(!embed(writer, body)){
			// Затираем ключ и метку соли
			nts::sys::wipe(key.data(), key.size());
			nts::sys::wipe(salt, sizeof(salt));
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		}
		// Записываем имитовставку под явной меткой [0]: строка битов с нулём неиспользуемых разрядов
		{
			// Записчик записи строки битов
			asn1::writer_t bits;
			// Записываем имитовставку строкой битов
			if(!bits.bits(view_t(mac, digest::length(hash)), 0)){
				// Затираем ключ и метку соли
				nts::sys::wipe(key.data(), key.size());
				nts::sys::wipe(salt, sizeof(salt));
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			}
			// Открываем явную метку [0]
			if(!writer.open(asn1::cls_t::CONTEXT, 0)){
				// Затираем ключ и метку соли
				nts::sys::wipe(key.data(), key.size());
				nts::sys::wipe(salt, sizeof(salt));
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			}
			// Переносим запись строки битов
			if(!embed(writer, bits.data())){
				// Затираем ключ и метку соли
				nts::sys::wipe(key.data(), key.size());
				nts::sys::wipe(salt, sizeof(salt));
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			}
			// Закрываем явную метку [0]
			if(!writer.close()){
				// Затираем ключ и метку соли
				nts::sys::wipe(key.data(), key.size());
				nts::sys::wipe(salt, sizeof(salt));
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			}
		}
		// Закрываем запись сообщения
		if(!writer.close()){
			// Затираем ключ и метку соли
			nts::sys::wipe(key.data(), key.size());
			nts::sys::wipe(salt, sizeof(salt));
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		}
		// Затираем ключ и метку соли
		nts::sys::wipe(key.data(), key.size());
		nts::sys::wipe(salt, sizeof(salt));
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Переносим запись сообщения в итог
			result.assign(writer.data().data, writer.data().data + writer.data().size);
		// Если памяти под итог не хватило
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return nts::cmp::error_t::MEMORY;
		}
		// Выводим успешность сборки сообщения
		return nts::cmp::error_t::NONE;
	}
	/**
	 * @brief Функция сборки тела запросов сертификатов CertReqMessages
	 *
	 * @param kind      вид тела (ir/cr/kur/krr/ccr)
	 * @param templates записи шаблонов CertTemplate
	 * @param signer    подготовленный секретный ключ подтверждения владения
	 * @param hash      алгоритм хеша подписи подтверждения
	 * @param result    место, в которое помещается запись тела (с меткой вида)
	 * @return          отказ сборки тела
	 *
	 * @note Подтверждение владения ставится видом signature: подпись над записью
	 *       CertReq по примечанию к POPOSigningKey в RFC 4211
	 *
	 */
	static nts::cmp::error_t bodyRequests(const nts::cmp::body_t kind, const vector <view_t> & templates, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
		// Опознаватель алгоритма подписи подтверждения
		const char * algorithm = signatureAlgorithm(signer, hash);
		// Если опознаватель алгоритма подписи не найден
		if(algorithm == nullptr)
			// Выводим отказ алгоритма
			return nts::cmp::error_t::ALGORITHM;
		// Записчик содержимого тела
		asn1::writer_t content;
		// Опознаватель запроса
		int64_t id = 0;
		/**
		 * Переносим шаблоны запросов
		 */
		for(const view_t & certTemplate : templates){
			// Записчик запроса CertReq
			asn1::writer_t certReq;
			// Открываем запись CertReq
			if(!certReq.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Записываем опознаватель запроса
			if(!certReq.integer(id))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Переносим запись шаблона
			if(!embed(certReq, certTemplate))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Закрываем запись CertReq
			if(!certReq.close())
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Место, в которое помещается подпись подтверждения
			vector <uint8_t> signature;
			// Итог выработки подписи подтверждения
			const nts::cmp::error_t outcome = makeSignature(signer, hash, certReq.data(), signature);
			// Если подпись выработать не удалось
			if(outcome != nts::cmp::error_t::NONE)
				// Выводим отказ подписи
				return outcome;
			// Записчик запроса CertReqMsg
			asn1::writer_t message;
			// Открываем запись CertReqMsg
			if(!message.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Переносим запись CertReq
			if(!embed(message, certReq.data()))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Записываем подтверждение владения видом signature [1]
			{
				// Открываем метку [1] подтверждения
				if(!message.open(asn1::cls_t::CONTEXT, 1))
					// Выводим отказ сборки
					return nts::cmp::error_t::MEMORY;
				// Открываем запись POPOSigningKey
				if(!message.open(asn1::tag_t::SEQUENCE))
					// Выводим отказ сборки
					return nts::cmp::error_t::MEMORY;
				// Записываем алгоритм подписи с пустыми настройками
				if(!writeAlgorithm(message, algorithm, true))
					// Выводим отказ сборки
					return nts::cmp::error_t::MEMORY;
				// Записываем подпись строкой битов
				if(!message.bits(view_t(signature.data(), signature.size()), 0))
					// Выводим отказ сборки
					return nts::cmp::error_t::MEMORY;
				// Закрываем запись POPOSigningKey и метку [1]
				if(!message.close() || !message.close())
					// Выводим отказ сборки
					return nts::cmp::error_t::MEMORY;
			}
			// Закрываем запись CertReqMsg
			if(!message.close())
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Переносим запись CertReqMsg в содержимое тела
			if(!embed(content, message.data()))
				// Выводим отказ сборки
				return nts::cmp::error_t::MEMORY;
			// Опознаватель следующего запроса
			id++;
		}
		// Записчик тела
		asn1::writer_t body;
		// Открываем метку вида тела
		if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (kind)))
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		// Переносим содержимое тела записью SEQUENCE OF
		if(!body.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), content.data())){
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		}
		// Закрываем метку вида тела
		if(!body.close())
			// Выводим отказ сборки
			return nts::cmp::error_t::MEMORY;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Переносим запись тела в итог
			result.assign(body.data().data, body.data().data + body.data().size);
		// Если памяти под итог не хватило
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return nts::cmp::error_t::MEMORY;
		}
		// Выводим успешность сборки тела
		return nts::cmp::error_t::NONE;
	}
};

/**
 * @brief Конструктор сообщения
 *
 */
nts::cmp::Message::Message() noexcept : _error(error_t::NONE), _kind(body_t::NONE) {}

/**
 * @brief Метод разбора записи PKIMessage
 *
 * @param data просмотр разбираемой записи
 * @return     причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::Message::parse(const view_t & data) noexcept {
	// Очищаем разобранные сведения
	this->clear();
	// Если запись не установлена
	if(data.size == 0){
		// Запоминаем причину отказа
		this->_error = error_t::EMPTY;
		// Выводим причину отказа
		return this->_error;
	}
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разборщик записи сообщения
		asn1::reader_t reader(data);
		// Элемент записи сообщения
		asn1::element_t element;
		// Если запись сообщения разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, element) || !element.constructed){
			// Запоминаем причину отказа
			this->_error = translate(reader.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Если после записи сообщения остался хвост
		if(!reader.empty()){
			// Запоминаем причину отказа
			this->_error = error_t::STRUCTURE;
			// Выводим причину отказа
			return this->_error;
		}
		// Разборщик содержимого записи сообщения
		asn1::reader_t items(element.content);
		// Элемент записи заголовка
		asn1::element_t header;
		// Если запись заголовка разобрать не удалось
		if(!items.next(asn1::tag_t::SEQUENCE, header) || !header.constructed){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Запоминаем запись заголовка для защищаемой части
		const view_t headerRecord = header.element;
		// Разбор заголовка
		{
			// Разборщик содержимого записи заголовка
			asn1::reader_t fields(header.content);
			// Элемент издания протокола
			asn1::element_t field;
			// Если издание протокола разобрать не удалось
			if(!fields.next(asn1::tag_t::INTEGER, field)){
				// Запоминаем причину отказа
				this->_error = translate(fields.err());
				// Выводим причину отказа
				return this->_error;
			}
			// Если издание протокола разобрать не удалось
			if(asn1::integer(field, this->_header.pvno) != asn1::error_t::NONE){
				// Запоминаем причину отказа
				this->_error = error_t::STRUCTURE;
				// Выводим причину отказа
				return this->_error;
			}
			// Если издание протокола не поддерживается
			if((this->_header.pvno != 1) && (this->_header.pvno != 2)){
				// Запоминаем причину отказа
				this->_error = error_t::VERSION;
				// Выводим причину отказа
				return this->_error;
			}
			// Элемент имени отправителя
			asn1::element_t sender;
			// Если имя отправителя разобрать не удалось
			if(!fields.next(sender)){
				// Запоминаем причину отказа
				this->_error = translate(fields.err());
				// Выводим причину отказа
				return this->_error;
			}
			// Запоминаем запись имени отправителя
			this->_header.sender = sender.element;
			// Элемент имени получателя
			asn1::element_t recipient;
			// Если имя получателя разобрать не удалось
			if(!fields.next(recipient)){
				// Запоминаем причину отказа
				this->_error = translate(fields.err());
				// Выводим причину отказа
				return this->_error;
			}
			// Запоминаем запись имени получателя
			this->_header.recipient = recipient.element;
			/**
			 * Разбираем необязательные поля заголовка
			 */
			while(!fields.empty()){
				// Элемент очередного поля
				asn1::element_t item;
				// Если поле разобрать не удалось
				if(!fields.next(item)){
					// Запоминаем причину отказа
					this->_error = translate(fields.err());
					// Выводим причину отказа
					return this->_error;
				}
				// Если поле не контекстного класса
				if(item.cls != asn1::cls_t::CONTEXT){
					// Запоминаем причину отказа
					this->_error = error_t::STRUCTURE;
					// Выводим причину отказа
					return this->_error;
				}
				/**
				 * Выполняем определение номера метки поля
				 */
				switch(item.tag){
					// messageTime [0] GeneralizedTime
					case 0: {
						// Разборщик содержимого явной метки
						asn1::reader_t inner(item.content);
						// Элемент записи времени
						asn1::element_t moment;
						// Если запись времени разобрать не удалось
						if(!inner.next(asn1::tag_t::GENERALIZED_TIME, moment)){
							// Запоминаем причину отказа
							this->_error = translate(inner.err());
							// Выводим причину отказа
							return this->_error;
						}
						// Если время разобрать не удалось
						if(asn1::time(moment, asn1::tag_t::GENERALIZED_TIME, this->_header.messageTime) != asn1::error_t::NONE){
							// Запоминаем причину отказа
							this->_error = error_t::STRUCTURE;
							// Выводим причину отказа
							return this->_error;
						}
						// Устанавливаем признак наличия времени
						this->_header.hasTime = true;
					} break;
					// protectionAlg [1] AlgorithmIdentifier
					case 1: {
						// Разборщик содержимого явной метки
						asn1::reader_t inner(item.content);
						// Элемент записи алгоритма защиты
						asn1::element_t algorithm;
						// Если запись алгоритма защиты разобрать не удалось
						if(!inner.next(asn1::tag_t::SEQUENCE, algorithm)){
							// Запоминаем причину отказа
							this->_error = translate(inner.err());
							// Выводим причину отказа
							return this->_error;
						}
						// Итог разбора записи алгоритма защиты
						const error_t outcome = algorithmIdentifier(algorithm, this->_header.protection, this->_header.parameters);
						// Если запись алгоритма защиты разобрать не удалось
						if(outcome != error_t::NONE){
							// Запоминаем причину отказа
							this->_error = outcome;
							// Выводим причину отказа
							return this->_error;
						}
					} break;
					// senderKID [2] KeyIdentifier
					case 2: {
						// Разборщик содержимого явной метки
						asn1::reader_t inner(item.content);
						// Элемент записи опознавателя ключа
						asn1::element_t kid;
						// Если запись опознавателя ключа разобрать не удалось
						if(!inner.next(asn1::tag_t::OCTET_STRING, kid)){
							// Запоминаем причину отказа
							this->_error = translate(inner.err());
							// Выводим причину отказа
							return this->_error;
						}
						// Запоминаем содержимое опознавателя ключа
						this->_header.senderKID = kid.content;
					} break;
					// recipKID [3] KeyIdentifier
					case 3: {
						// Разборщик содержимого явной метки
						asn1::reader_t inner(item.content);
						// Элемент записи опознавателя ключа
						asn1::element_t kid;
						// Если запись опознавателя ключа разобрать не удалось
						if(!inner.next(asn1::tag_t::OCTET_STRING, kid)){
							// Запоминаем причину отказа
							this->_error = translate(inner.err());
							// Выводим причину отказа
							return this->_error;
						}
						// Запоминаем содержимое опознавателя ключа
						this->_header.recipKID = kid.content;
					} break;
					// transactionID [4] OCTET STRING
					case 4: {
						// Разборщик содержимого явной метки
						asn1::reader_t inner(item.content);
						// Элемент записи опознавателя сделки
						asn1::element_t transaction;
						// Если запись опознавателя сделки разобрать не удалось
						if(!inner.next(asn1::tag_t::OCTET_STRING, transaction)){
							// Запоминаем причину отказа
							this->_error = translate(inner.err());
							// Выводим причину отказа
							return this->_error;
						}
						// Запоминаем содержимое опознавателя сделки
						this->_header.transaction = transaction.content;
					} break;
					// senderNonce [5] OCTET STRING
					case 5: {
						// Разборщик содержимого явной метки
						asn1::reader_t inner(item.content);
						// Элемент записи метки новизны
						asn1::element_t nonce;
						// Если запись метки новизны разобрать не удалось
						if(!inner.next(asn1::tag_t::OCTET_STRING, nonce)){
							// Запоминаем причину отказа
							this->_error = translate(inner.err());
							// Выводим причину отказа
							return this->_error;
						}
						// Запоминаем содержимое метки новизны
						this->_header.senderNonce = nonce.content;
					} break;
					// recipNonce [6] OCTET STRING
					case 6: {
						// Разборщик содержимого явной метки
						asn1::reader_t inner(item.content);
						// Элемент записи метки новизны
						asn1::element_t nonce;
						// Если запись метки новизны разобрать не удалось
						if(!inner.next(asn1::tag_t::OCTET_STRING, nonce)){
							// Запоминаем причину отказа
							this->_error = translate(inner.err());
							// Выводим причину отказа
							return this->_error;
						}
						// Запоминаем содержимое метки новизны
						this->_header.recipNonce = nonce.content;
					} break;
					// freeText [7] PKIFreeText
					case 7: {
						// Разборщик содержимого явной метки
						asn1::reader_t inner(item.content);
						// Элемент записи свободного текста
						asn1::element_t text;
						// Если запись свободного текста разобрать не удалось
						if(!inner.next(asn1::tag_t::SEQUENCE, text)){
							// Запоминаем причину отказа
							this->_error = translate(inner.err());
							// Выводим причину отказа
							return this->_error;
						}
						// Разборщик строк свободного текста
						asn1::reader_t lines(text.content);
						/**
						 * Разбираем строки свободного текста
						 */
						while(!lines.empty()){
							// Элемент строки свободного текста
							asn1::element_t line;
							// Если строку разобрать не удалось
							if(!lines.next(asn1::tag_t::UTF8_STRING, line)){
								// Запоминаем причину отказа
								this->_error = translate(lines.err());
								// Выводим причину отказа
								return this->_error;
							}
							// Строка свободного текста
							string value;
							// Если строку извлечь не удалось
							if(asn1::text(line, asn1::tag_t::UTF8_STRING, value) != asn1::error_t::NONE){
								// Запоминаем причину отказа
								this->_error = error_t::STRUCTURE;
								// Выводим причину отказа
								return this->_error;
							}
							// Запоминаем строку свободного текста
							this->_header.text.push_back(value);
						}
					} break;
					// generalInfo [8] SEQUENCE OF InfoTypeAndValue
					case 8:
						// Запоминаем запись общих сведений целиком
						this->_header.info = item.element;
					break;
					// Поле неизвестного вида
					default:
						// Запоминаем причину отказа
						this->_error = error_t::STRUCTURE;
						// Выводим причину отказа
						return this->_error;
				}
			}
		}
		// Элемент записи тела
		asn1::element_t body;
		// Если запись тела разобрать не удалось
		if(!items.next(body)){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Если тело не контекстного класса либо вид тела неизвестен
		if((body.cls != asn1::cls_t::CONTEXT) || (body.tag > 26)){
			// Запоминаем причину отказа
			this->_error = error_t::STRUCTURE;
			// Выводим причину отказа
			return this->_error;
		}
		// Запоминаем вид тела
		this->_kind = static_cast <body_t> (body.tag);
		// Запоминаем содержимое тела
		this->_body = body.content;
		// Запоминаем запись защищаемой части: заголовок и тело идут подряд
		this->_protected = view_t(headerRecord.data, headerRecord.size + body.element.size);
		/**
		 * Разбираем защиту и дополнительные сертификаты
		 */
		while(!items.empty()){
			// Элемент очередного поля сообщения
			asn1::element_t item;
			// Если поле разобрать не удалось
			if(!items.next(item)){
				// Запоминаем причину отказа
				this->_error = translate(items.err());
				// Выводим причину отказа
				return this->_error;
			}
			// Если поле не контекстного класса
			if(item.cls != asn1::cls_t::CONTEXT){
				// Запоминаем причину отказа
				this->_error = error_t::STRUCTURE;
				// Выводим причину отказа
				return this->_error;
			}
			/**
			 * Выполняем определение номера метки поля
			 */
			switch(item.tag){
				// protection [0] PKIProtection
				case 0: {
					// Разборщик содержимого явной метки
					asn1::reader_t inner(item.content);
					// Элемент записи строки битов защиты
					asn1::element_t bits;
					// Если запись строки битов разобрать не удалось
					if(!inner.next(asn1::tag_t::BIT_STRING, bits)){
						// Запоминаем причину отказа
						this->_error = translate(inner.err());
						// Выводим причину отказа
						return this->_error;
					}
					// Просмотр содержимого строки битов
					view_t content;
					// Число неиспользуемых разрядов последнего байта
					uint8_t unused = 0;
					// Если строку битов разобрать не удалось
					if(asn1::bits(bits, content, unused) != asn1::error_t::NONE){
						// Запоминаем причину отказа
						this->_error = error_t::STRUCTURE;
						// Выводим причину отказа
						return this->_error;
					}
					// Если неиспользуемые разряды есть: подпись и имитовставка кратны байту
					if(unused != 0){
						// Запоминаем причину отказа
						this->_error = error_t::STRUCTURE;
						// Выводим причину отказа
						return this->_error;
					}
					// Запоминаем содержимое строки битов защиты
					this->_protection = content;
				} break;
				// extraCerts [1] SEQUENCE OF CMPCertificate
				case 1: {
					// Разборщик содержимого явной метки
					asn1::reader_t inner(item.content);
					// Элемент записи набора сертификатов
					asn1::element_t certificates;
					// Если запись набора сертификатов разобрать не удалось
					if(!inner.next(asn1::tag_t::SEQUENCE, certificates)){
						// Запоминаем причину отказа
						this->_error = translate(inner.err());
						// Выводим причину отказа
						return this->_error;
					}
					// Разборщик записей сертификатов
					asn1::reader_t records(certificates.content);
					/**
					 * Разбираем записи сертификатов
					 */
					while(!records.empty()){
						// Элемент записи сертификата
						asn1::element_t certificate;
						// Если запись сертификата разобрать не удалось
						if(!records.next(certificate)){
							// Запоминаем причину отказа
							this->_error = translate(records.err());
							// Выводим причину отказа
							return this->_error;
						}
						// Запоминаем запись сертификата
						this->_certificates.push_back(certificate.element);
					}
				} break;
				// Поле неизвестного вида
				default:
					// Запоминаем причину отказа
					this->_error = error_t::STRUCTURE;
					// Выводим причину отказа
					return this->_error;
			}
		}
	// Если памяти под сведения не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Запоминаем причину отказа
		this->_error = error_t::MEMORY;
		// Выводим причину отказа
		return this->_error;
	}
	// Запоминаем успешность разбора
	this->_error = error_t::NONE;
	// Выводим успешность разбора
	return this->_error;
}
/**
 * @brief Метод очистки разобранных сведений
 *
 */
void nts::cmp::Message::clear() noexcept {
	// Сбрасываем причину отказа
	this->_error = error_t::NONE;
	// Сбрасываем вид тела
	this->_kind = body_t::NONE;
	// Сбрасываем заголовок
	this->_header = header_t();
	// Сбрасываем просмотры
	this->_body = view_t();
	// Сбрасываем просмотр строки битов защиты
	this->_protection = view_t();
	// Сбрасываем просмотр защищаемой записи ProtectedPart (заголовок и тело)
	this->_protected = view_t();
	// Сбрасываем записи сертификатов
	this->_certificates.clear();
}
/**
 * @brief Метод извлечения причины последнего отказа
 *
 * @return причина последнего отказа
 *
 */
nts::cmp::error_t nts::cmp::Message::err() const noexcept {
	// Выводим причину последнего отказа
	return this->_error;
}
/**
 * @brief Метод извлечения вида тела сообщения
 *
 * @return вид тела, body_t::NONE у неразобранной записи
 *
 */
nts::cmp::body_t nts::cmp::Message::kind() const noexcept {
	// Выводим вид тела сообщения
	return this->_kind;
}
/**
 * @brief Метод извлечения заголовка сообщения
 *
 * @return заголовок сообщения
 *
 */
const nts::cmp::header_t & nts::cmp::Message::header() const noexcept {
	// Выводим заголовок сообщения
	return this->_header;
}
/**
 * @brief Метод извлечения содержимого тела
 *
 * @return просмотр содержимого тела (без метки вида)
 *
 */
const nts::view_t & nts::cmp::Message::body() const noexcept {
	// Выводим просмотр содержимого тела
	return this->_body;
}
/**
 * @brief Метод извлечения защиты сообщения
 *
 * @return просмотр содержимого строки битов защиты, пустой при её отсутствии
 *
 */
const nts::view_t & nts::cmp::Message::protection() const noexcept {
	// Выводим просмотр содержимого строки битов защиты
	return this->_protection;
}
/**
 * @brief Метод извлечения записей дополнительных сертификатов
 *
 * @return просмотры записей сертификатов extraCerts
 *
 */
const vector <nts::view_t> & nts::cmp::Message::certificates() const noexcept {
	// Выводим просмотры записей сертификатов
	return this->_certificates;
}

/**
 * @brief Функция разбора сведений о статусе PKIStatusInfo
 *
 * @param element разбираемый элемент записи статуса
 * @param result  место, в которое помещаются сведения
 * @return        причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::statusInfo(const asn1::element_t & element, status_info_t & result) noexcept {
	// Если запись статуса не составная
	if(!element.constructed)
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разборщик содержимого записи статуса
		asn1::reader_t items(element.content);
		// Элемент статуса
		asn1::element_t status;
		// Если статус разобрать не удалось
		if(!items.next(asn1::tag_t::INTEGER, status))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Значение статуса
		int64_t value = 0;
		// Если статус разобрать не удалось
		if(asn1::integer(status, value) != asn1::error_t::NONE)
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Запоминаем статус
		result.status = ((value >= 0) && (value <= 6)) ? static_cast <status_t> (value) : status_t::UNKNOWN;
		// Если строки статуса записаны
		if(!items.empty()){
			// Элемент записи строк статуса
			asn1::element_t strings;
			// Если запись строк статуса разобрать не удалось
			if(!items.next(asn1::tag_t::SEQUENCE, strings))
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Разборщик строк статуса
			asn1::reader_t lines(strings.content);
			/**
			 * Разбираем строки статуса
			 */
			while(!lines.empty()){
				// Элемент строки статуса
				asn1::element_t line;
				// Если строку разобрать не удалось
				if(!lines.next(asn1::tag_t::UTF8_STRING, line))
					// Выводим переведённый отказ разбора
					return translate(lines.err());
				// Строка статуса
				string text;
				// Если строку извлечь не удалось
				if(asn1::text(line, asn1::tag_t::UTF8_STRING, text) != asn1::error_t::NONE)
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				// Запоминаем строку статуса
				result.strings.push_back(text);
			}
		}
		// Если сведения об отказе записаны
		if(!items.empty()){
			// Элемент записи сведений об отказе
			asn1::element_t failure;
			// Если запись сведений об отказе разобрать не удалось
			if(!items.next(asn1::tag_t::BIT_STRING, failure))
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Просмотр содержимого строки битов
			view_t content;
			// Число неиспользуемых разрядов последнего байта
			uint8_t unused = 0;
			// Если строку битов разобрать не удалось
			if(asn1::bits(failure, content, unused) != asn1::error_t::NONE)
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Запоминаем содержимое строки битов
			result.failure.assign(content.data, content.data + content.size);
		}
		// Если после сведений остался хвост
		if(!items.empty())
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
	// Если памяти под сведения не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Функция разбора запросов сертификатов CertReqMessages
 *
 * @param body   просмотр содержимого тела (для видов ir/cr/kur/krr/ccr)
 * @param result место, в которое помещаются запросы
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::requests(const view_t & body, vector <request_t> & result) noexcept {
	// Если содержимое тела не установлено
	if(body.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разборщик записи CertReqMessages
		asn1::reader_t wrapper(body);
		// Элемент записи набора запросов
		asn1::element_t set;
		// Если запись набора запросов разобрать не удалось
		if(!wrapper.next(asn1::tag_t::SEQUENCE, set) || !set.constructed)
			// Выводим переведённый отказ разбора
			return translate(wrapper.err());
		// Разборщик записей запросов
		asn1::reader_t records(set.content);
		/**
		 * Разбираем записи запросов
		 */
		while(!records.empty()){
			// Элемент записи запроса CertReqMsg
			asn1::element_t message;
			// Если запись запроса разобрать не удалось
			if(!records.next(asn1::tag_t::SEQUENCE, message) || !message.constructed)
				// Выводим переведённый отказ разбора
				return translate(records.err());
			// Разборщик содержимого записи запроса
			asn1::reader_t items(message.content);
			// Элемент записи CertReq
			asn1::element_t certReq;
			// Если запись CertReq разобрать не удалось
			if(!items.next(asn1::tag_t::SEQUENCE, certReq) || !certReq.constructed)
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Место, в которое помещается запрос
			request_t request;
			// Разборщик содержимого записи CertReq
			asn1::reader_t fields(certReq.content);
			// Элемент опознавателя запроса
			asn1::element_t identifier;
			// Если опознаватель запроса разобрать не удалось
			if(!fields.next(asn1::tag_t::INTEGER, identifier))
				// Выводим переведённый отказ разбора
				return translate(fields.err());
			// Если опознаватель запроса разобрать не удалось
			if(asn1::integer(identifier, request.id) != asn1::error_t::NONE)
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Элемент записи шаблона сертификата
			asn1::element_t certTemplate;
			// Если запись шаблона разобрать не удалось
			if(!fields.next(asn1::tag_t::SEQUENCE, certTemplate))
				// Выводим переведённый отказ разбора
				return translate(fields.err());
			// Запоминаем запись шаблона целиком
			request.certTemplate = certTemplate.element;
			// Если подтверждение владения записано
			if(!items.empty()){
				// Элемент записи подтверждения владения
				asn1::element_t popo;
				// Если запись подтверждения владения разобрать не удалось
				if(!items.next(popo))
					// Выводим переведённый отказ разбора
					return translate(items.err());
				// Запоминаем запись подтверждения владения целиком
				request.popo = popo.element;
			}
			// Если регистрационные сведения записаны
			if(!items.empty()){
				// Элемент записи регистрационных сведений
				asn1::element_t regInfo;
				// Если запись регистрационных сведений разобрать не удалось
				if(!items.next(asn1::tag_t::SEQUENCE, regInfo))
					// Выводим переведённый отказ разбора
					return translate(items.err());
				// Запоминаем запись регистрационных сведений целиком
				request.regInfo = regInfo.element;
			}
			// Если после сведений остался хвост
			if(!items.empty())
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Запоминаем запрос
			result.push_back(request);
		}
	// Если памяти под сведения не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Функция разбора ответа о сертификатах CertRepMessage
 *
 * @param body   просмотр содержимого тела (для видов ip/cp/kup/ccp)
 * @param caPubs место, в которое помещаются просмотры записей сертификатов ЦС
 * @param result место, в которое помещаются ответы
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::response(const view_t & body, vector <view_t> & caPubs, vector <response_t> & result) noexcept {
	// Если содержимое тела не установлено
	if(body.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разборщик записи ответа CertRepMessage
		asn1::reader_t reader(body);
		// Элемент записи ответа CertRepMessage
		asn1::element_t message;
		// Если запись ответа разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, message) || !message.constructed)
			// Выводим переведённый отказ разбора
			return translate(reader.err());
		// Разборщик содержимого записи ответа
		asn1::reader_t items(message.content);
		// Элемент очередного поля
		asn1::element_t field;
		// Если поле разобрать не удалось
		if(!items.next(field))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Если первое поле - caPubs [1]
		if((field.cls == asn1::cls_t::CONTEXT) && (field.tag == 1)){
			// Разборщик записей сертификатов ЦС
			asn1::reader_t records(field.content);
			/**
			 * Разбираем записи сертификатов ЦС
			 */
			while(!records.empty()){
				// Элемент записи сертификата ЦС
				asn1::element_t certificate;
				// Если запись сертификата разобрать не удалось
				if(!records.next(certificate))
					// Выводим переведённый отказ разбора
					return translate(records.err());
				// Запоминаем запись сертификата ЦС
				caPubs.push_back(certificate.element);
			}
			// Если поле ответов разобрать не удалось
			if(!items.next(field))
				// Выводим переведённый отказ разбора
				return translate(items.err());
		}
		// Если поле ответов не набор
		if((field.cls != asn1::cls_t::UNIVERSAL) || (field.tag != static_cast <uint32_t> (asn1::tag_t::SEQUENCE)) || !field.constructed)
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Разборщик записей ответов
		asn1::reader_t records(field.content);
		/**
		 * Разбираем записи ответов
		 */
		while(!records.empty()){
			// Элемент записи ответа CertResponse
			asn1::element_t response;
			// Если запись ответа разобрать не удалось
			if(!records.next(asn1::tag_t::SEQUENCE, response) || !response.constructed)
				// Выводим переведённый отказ разбора
				return translate(records.err());
			// Разборщик содержимого записи ответа
			asn1::reader_t fields(response.content);
			// Место, в которое помещается ответ
			response_t answer;
			// Элемент опознавателя запроса
			asn1::element_t identifier;
			// Если опознаватель запроса разобрать не удалось
			if(!fields.next(asn1::tag_t::INTEGER, identifier))
				// Выводим переведённый отказ разбора
				return translate(fields.err());
			// Если опознаватель запроса разобрать не удалось
			if(asn1::integer(identifier, answer.id) != asn1::error_t::NONE)
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Элемент записи статуса
			asn1::element_t status;
			// Если запись статуса разобрать не удалось
			if(!fields.next(asn1::tag_t::SEQUENCE, status))
				// Выводим переведённый отказ разбора
				return translate(fields.err());
			// Если сведения о статусе разобрать не удалось
			if(statusInfo(status, answer.status) != error_t::NONE)
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Если сведения о сертификате записаны
			if(!fields.empty()){
				// Элемент записи сведений о сертификате CertifiedKeyPair
				asn1::element_t pair;
				// Если запись сведений разобрать не удалось
				if(!fields.next(asn1::tag_t::SEQUENCE, pair))
					// Выводим переведённый отказ разбора
					return translate(fields.err());
				// Разборщик содержимого записи сведений
				asn1::reader_t parts(pair.content);
				// Элемент выбора certOrEncCert
				asn1::element_t choice;
				// Если выбор разобрать не удалось
				if(!parts.next(choice))
					// Выводим переведённый отказ разбора
					return translate(parts.err());
				// Если выбор не контекстного класса
				if(choice.cls != asn1::cls_t::CONTEXT)
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				/**
				 * Выполняем определение вида выбора
				 */
				switch(choice.tag){
					// certificate [0] Certificate
					case 0:
						// Запоминаем запись сертификата: содержимое явной метки
						answer.certificate = choice.content;
					break;
					// encryptedCert [1] EncryptedValue
					case 1:
						// Запоминаем запись зашифрованного сертификата: содержимое явной метки
						answer.encrypted = choice.content;
					break;
					// Выбор неизвестного вида
					default:
						// Выводим отказ устройства записи
						return error_t::STRUCTURE;
				}
				// Если секретный ключ записан
				if(!parts.empty()){
					// Элемент записи секретного ключа
					asn1::element_t privateKey;
					// Если запись секретного ключа разобрать не удалось
					if(!parts.next(privateKey))
						// Выводим переведённый отказ разбора
						return translate(parts.err());
					// Если запись секретного ключа - privateKey [0]
					if((privateKey.cls == asn1::cls_t::CONTEXT) && (privateKey.tag == 0)){
						// Запоминаем запись секретного ключа: содержимое явной метки
						answer.privateKey = privateKey.content;
					// Иначе запись сведений о публикации пропускается
					}
				}
			}
			// Если запись rspInfo записана
			if(!fields.empty()){
				// Элемент записи rspInfo
				asn1::element_t info;
				// Если запись rspInfo разобрать не удалось
				if(!fields.next(asn1::tag_t::OCTET_STRING, info))
					// Выводим переведённый отказ разбора
					return translate(fields.err());
				// Запоминаем содержимое rspInfo
				answer.info = info.content;
			}
			// Если после сведений остался хвост
			if(!fields.empty())
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Запоминаем ответ
			result.push_back(answer);
		}
	// Если памяти под сведения не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Функция разбора общих сведений GenMsgContent/GenRepContent
 *
 * @param body   просмотр содержимого тела (для видов genm/genp)
 * @param result место, в которое помещаются сведения
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::infos(const view_t & body, vector <info_t> & result) noexcept {
	// Если содержимое тела не установлено
	if(body.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разборщик записи GenMsgContent/GenRepContent
		asn1::reader_t wrapper(body);
		// Элемент записи набора сведений
		asn1::element_t set;
		// Если запись набора сведений разобрать не удалось
		if(!wrapper.next(asn1::tag_t::SEQUENCE, set) || !set.constructed)
			// Выводим переведённый отказ разбора
			return translate(wrapper.err());
		// Разборщик записей сведений
		asn1::reader_t records(set.content);
		/**
		 * Разбираем записи сведений
		 */
		while(!records.empty()){
			// Элемент записи сведений InfoTypeAndValue
			asn1::element_t info;
			// Если запись сведений разобрать не удалось
			if(!records.next(asn1::tag_t::SEQUENCE, info) || !info.constructed)
				// Выводим переведённый отказ разбора
				return translate(records.err());
			// Разборщик содержимого записи сведений
			asn1::reader_t items(info.content);
			// Элемент опознавателя вида сведений
			asn1::element_t type;
			// Если опознаватель разобрать не удалось
			if(!items.next(asn1::tag_t::OBJECT, type))
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Место, в которое помещаются сведения
			info_t pair;
			// Если опознаватель разобрать не удалось
			if(oidOf(type, pair.oid) != error_t::NONE)
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Если значение записано
			if(!items.empty()){
				// Элемент записи значения
				asn1::element_t value;
				// Если запись значения разобрать не удалось
				if(!items.next(value))
					// Выводим переведённый отказ разбора
					return translate(items.err());
				// Запоминаем запись значения целиком
				pair.value = value.element;
			}
			// Запоминаем сведения
			result.push_back(pair);
		}
	// Если памяти под сведения не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}

/**
 * @brief Функция разбора вызовов подтверждения владения POPODecKeyChallContent
 *
 * @param body   просмотр содержимого тела (для вида popdecc)
 * @param result место, в которое помещаются вызовы
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::challenges(const view_t & body, vector <challenge_t> & result) noexcept {
	// Если содержимое тела не установлено
	if(body.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разборщик записи POPODecKeyChallContent
		asn1::reader_t wrapper(body);
		// Элемент записи набора вызовов
		asn1::element_t set;
		// Если запись набора вызовов разобрать не удалось
		if(!wrapper.next(asn1::tag_t::SEQUENCE, set) || !set.constructed)
			// Выводим переведённый отказ разбора
			return translate(wrapper.err());
		// Разборщик записей вызовов
		asn1::reader_t records(set.content);
		/**
		 * Разбираем записи вызовов
		 */
		while(!records.empty()){
			// Элемент записи вызова Challenge
			asn1::element_t challenge;
			// Если запись вызова разобрать не удалось
			if(!records.next(asn1::tag_t::SEQUENCE, challenge) || !challenge.constructed)
				// Выводим переведённый отказ разбора
				return translate(records.err());
			// Разборщик содержимого записи вызова
			asn1::reader_t items(challenge.content);
			// Элемент очередного поля
			asn1::element_t field;
			// Если поле разобрать не удалось
			if(!items.next(field))
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Место, в которое помещается вызов
			challenge_t entry;
			// Если первое поле - запись односторонней функции
			if((field.cls == asn1::cls_t::UNIVERSAL) && (field.tag == static_cast <uint32_t> (asn1::tag_t::SEQUENCE))){
				// Просмотр настроек односторонней функции
				view_t params;
				// Если запись односторонней функции разобрать не удалось
				if(algorithmIdentifier(field, entry.owf, params) != error_t::NONE)
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				// Если поле свидетеля разобрать не удалось
				if(!items.next(field))
					// Выводим переведённый отказ разбора
					return translate(items.err());
			}
			// Если поле свидетеля не строка байтов
			if((field.cls != asn1::cls_t::UNIVERSAL) || (field.tag != static_cast <uint32_t> (asn1::tag_t::OCTET_STRING)))
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Запоминаем содержимое свидетеля
			entry.witness = field.content;
			// Элемент вызова
			asn1::element_t value;
			// Если вызов разобрать не удалось
			if(!items.next(asn1::tag_t::OCTET_STRING, value))
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Запоминаем содержимое вызова
			entry.challenge = value.content;
			// Дописываем пару свидетеля и вызова в итог разбора
			result.push_back(entry);
		}
	// Если памяти под сведения не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Функция разбора ответов подтверждения владения POPODecKeyRespContent
 *
 * @param body   просмотр содержимого тела (для вида popdecr)
 * @param result место, в которое помещаются числа ответов
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::challengeAnswers(const view_t & body, vector <int64_t> & result) noexcept {
	// Если содержимое тела не установлено
	if(body.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разборщик записи POPODecKeyRespContent
		asn1::reader_t wrapper(body);
		// Элемент записи набора ответов
		asn1::element_t set;
		// Если запись набора ответов разобрать не удалось
		if(!wrapper.next(asn1::tag_t::SEQUENCE, set) || !set.constructed)
			// Выводим переведённый отказ разбора
			return translate(wrapper.err());
		// Разборщик чисел ответов
		asn1::reader_t records(set.content);
		/**
		 * Разбираем числа ответов
		 */
		while(!records.empty()){
			// Элемент числа ответа
			asn1::element_t answer;
			// Если число ответа разобрать не удалось
			if(!records.next(asn1::tag_t::INTEGER, answer))
				// Выводим переведённый отказ разбора
				return translate(records.err());
			// Число ответа
			int64_t value = 0;
			// Если число ответа разобрать не удалось
			if(asn1::integer(answer, value) != asn1::error_t::NONE)
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Запоминаем число ответа
			result.push_back(value);
		}
	// Если памяти под сведения не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Функция разбора ответа восстановления ключа KeyRecRepContent
 *
 * @param body   просмотр содержимого тела (для вида krp)
 * @param result место, в которое помещается ответ
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::recovery(const view_t & body, recovery_t & result) noexcept {
	// Если содержимое тела не установлено
	if(body.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разборщик записи KeyRecRepContent
		asn1::reader_t wrapper(body);
		// Элемент записи ответа
		asn1::element_t content;
		// Если запись ответа разобрать не удалось
		if(!wrapper.next(asn1::tag_t::SEQUENCE, content) || !content.constructed)
			// Выводим переведённый отказ разбора
			return translate(wrapper.err());
		// Разборщик содержимого записи ответа
		asn1::reader_t items(content.content);
		// Элемент записи статуса
		asn1::element_t status;
		// Если запись статуса разобрать не удалось
		if(!items.next(asn1::tag_t::SEQUENCE, status))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Если сведения о статусе разобрать не удалось
		if(statusInfo(status, result.status) != error_t::NONE)
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		/**
		 * Разбираем необязательные поля
		 */
		while(!items.empty()){
			// Элемент очередного поля
			asn1::element_t field;
			// Если поле разобрать не удалось
			if(!items.next(field))
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Если поле не контекстного класса
			if(field.cls != asn1::cls_t::CONTEXT)
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			/**
			 * Выполняем определение номера метки поля
			 */
			switch(field.tag){
				// newSigCert [0] Certificate
				case 0:
					// Запоминаем запись сертификата: содержимое явной метки
					result.certificate = field.content;
				break;
				// caCerts [1] SEQUENCE OF Certificate
				case 1: {
					// Разборщик записей сертификатов ЦС
					asn1::reader_t records(field.content);
					/**
					 * Разбираем записи сертификатов ЦС
					 */
					while(!records.empty()){
						// Элемент записи сертификата ЦС
						asn1::element_t certificate;
						// Если запись сертификата разобрать не удалось
						if(!records.next(certificate))
							// Выводим переведённый отказ разбора
							return translate(records.err());
						// Запоминаем запись сертификата ЦС
						result.caCertificates.push_back(certificate.element);
					}
				} break;
				// keyPairHist [2] SEQUENCE OF CertifiedKeyPair
				case 2: {
					// Разборщик записей пар ключей
					asn1::reader_t records(field.content);
					/**
					 * Разбираем записи пар ключей
					 */
					while(!records.empty()){
						// Элемент записи пары ключей
						asn1::element_t pair;
						// Если запись пары ключей разобрать не удалось
						if(!records.next(pair))
							// Выводим переведённый отказ разбора
							return translate(records.err());
						// Запоминаем запись пары ключей
						result.history.push_back(pair.element);
					}
				} break;
				// Поле неизвестного вида
				default:
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
			}
		}
	// Если памяти под сведения не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Функция разбора ответа отзыва RevRepContent
 *
 * @param body   просмотр содержимого тела (для вида rp)
 * @param result место, в которое помещается ответ
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::revoked(const view_t & body, revoked_t & result) noexcept {
	// Если содержимое тела не установлено
	if(body.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разборщик записи RevRepContent
		asn1::reader_t wrapper(body);
		// Элемент записи ответа
		asn1::element_t content;
		// Если запись ответа разобрать не удалось
		if(!wrapper.next(asn1::tag_t::SEQUENCE, content) || !content.constructed)
			// Выводим переведённый отказ разбора
			return translate(wrapper.err());
		// Разборщик содержимого записи ответа
		asn1::reader_t items(content.content);
		// Элемент записи набора статусов
		asn1::element_t statuses;
		// Если запись набора статусов разобрать не удалось
		if(!items.next(asn1::tag_t::SEQUENCE, statuses))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Разборщик записей статусов
		asn1::reader_t records(statuses.content);
		/**
		 * Разбираем записи статусов
		 */
		while(!records.empty()){
			// Элемент записи статуса
			asn1::element_t status;
			// Если запись статуса разобрать не удалось
			if(!records.next(asn1::tag_t::SEQUENCE, status))
				// Выводим переведённый отказ разбора
				return translate(records.err());
			// Место, в которое помещаются сведения о статусе
			status_info_t info;
			// Если сведения о статусе разобрать не удалось
			if(statusInfo(status, info) != error_t::NONE)
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Запоминаем сведения о статусе
			result.statuses.push_back(info);
		}
		/**
		 * Разбираем необязательные поля
		 */
		while(!items.empty()){
			// Элемент очередного поля
			asn1::element_t field;
			// Если поле разобрать не удалось
			if(!items.next(field))
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Если поле не контекстного класса
			if(field.cls != asn1::cls_t::CONTEXT)
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Разборщик записей поля
			asn1::reader_t entries(field.content);
			/**
			 * Выполняем определение номера метки поля
			 */
			switch(field.tag){
				// revCerts [0] SEQUENCE OF CertId
				case 0:
					/**
					 * Разбираем записи опознавателей сертификатов
					 */
					while(!entries.empty()){
						// Элемент записи опознавателя
						asn1::element_t certificate;
						// Если запись опознавателя разобрать не удалось
						if(!entries.next(certificate))
							// Выводим переведённый отказ разбора
							return translate(entries.err());
						// Запоминаем запись опознавателя
						result.certificates.push_back(certificate.element);
					}
				break;
				// crls [1] SEQUENCE OF CertificateList
				case 1:
					/**
					 * Разбираем записи списков отзыва
					 */
					while(!entries.empty()){
						// Элемент записи списка отзыва
						asn1::element_t crl;
						// Если запись списка отзыва разобрать не удалось
						if(!entries.next(crl))
							// Выводим переведённый отказ разбора
							return translate(entries.err());
						// Запоминаем запись списка отзыва
						result.crls.push_back(crl.element);
					}
				break;
				// Поле неизвестного вида
				default:
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
			}
		}
	// Если памяти под сведения не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Функция разбора объявления обновления ключа ЦС CAKeyUpdAnnContent
 *
 * @param body       просмотр содержимого тела (для вида ckuann)
 * @param oldWithNew место, в которое помещается запись сертификата oldWithNew
 * @param newWithOld место, в которое помещается запись сертификата newWithOld
 * @param newWithNew место, в которое помещается запись сертификата newWithNew
 * @return           причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::caKeyUpdate(const view_t & body, view_t & oldWithNew, view_t & newWithOld, view_t & newWithNew) noexcept {
	// Если содержимое тела не установлено
	if(body.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Разборщик записи CAKeyUpdAnnContent
	asn1::reader_t wrapper(body);
	// Элемент записи объявления
	asn1::element_t content;
	// Если запись объявления разобрать не удалось
	if(!wrapper.next(asn1::tag_t::SEQUENCE, content) || !content.constructed)
		// Выводим переведённый отказ разбора
		return translate(wrapper.err());
	// Разборщик содержимого записи объявления
	asn1::reader_t items(content.content);
	// Элемент записи сертификата
	asn1::element_t certificate;
	// Если запись oldWithNew разобрать не удалось
	if(!items.next(asn1::tag_t::SEQUENCE, certificate))
		// Выводим переведённый отказ разбора
		return translate(items.err());
	// Запоминаем запись oldWithNew
	oldWithNew = certificate.element;
	// Если запись newWithOld разобрать не удалось
	if(!items.next(asn1::tag_t::SEQUENCE, certificate))
		// Выводим переведённый отказ разбора
		return translate(items.err());
	// Запоминаем запись newWithOld
	newWithOld = certificate.element;
	// Если запись newWithNew разобрать не удалось
	if(!items.next(asn1::tag_t::SEQUENCE, certificate))
		// Выводим переведённый отказ разбора
		return translate(items.err());
	// Запоминаем запись newWithNew
	newWithNew = certificate.element;
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Функция разбора объявления отзыва RevAnnContent
 *
 * @param body   просмотр содержимого тела (для вида rann)
 * @param result место, в которое помещается объявление
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::announcement(const view_t & body, announcement_t & result) noexcept {
	// Если содержимое тела не установлено
	if(body.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Разборщик записи RevAnnContent
	asn1::reader_t wrapper(body);
	// Элемент записи объявления
	asn1::element_t content;
	// Если запись объявления разобрать не удалось
	if(!wrapper.next(asn1::tag_t::SEQUENCE, content) || !content.constructed)
		// Выводим переведённый отказ разбора
		return translate(wrapper.err());
	// Разборщик содержимого записи объявления
	asn1::reader_t items(content.content);
	// Элемент статуса
	asn1::element_t status;
	// Если статус разобрать не удалось
	if(!items.next(asn1::tag_t::INTEGER, status))
		// Выводим переведённый отказ разбора
		return translate(items.err());
	// Значение статуса
	int64_t value = 0;
	// Если статус разобрать не удалось
	if(asn1::integer(status, value) != asn1::error_t::NONE)
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Запоминаем статус
	result.status = ((value >= 0) && (value <= 6)) ? static_cast <status_t> (value) : status_t::UNKNOWN;
	// Элемент записи опознавателя сертификата
	asn1::element_t certificate;
	// Если запись опознавателя разобрать не удалось
	if(!items.next(asn1::tag_t::SEQUENCE, certificate))
		// Выводим переведённый отказ разбора
		return translate(items.err());
	// Запоминаем запись опознавателя сертификата
	result.certificate = certificate.element;
	// Элемент времени занесения в список отзыва
	asn1::element_t moment;
	// Если время занесения разобрать не удалось
	if(!items.next(asn1::tag_t::GENERALIZED_TIME, moment))
		// Выводим переведённый отказ разбора
		return translate(items.err());
	// Если время занесения разобрать не удалось
	if(asn1::time(moment, asn1::tag_t::GENERALIZED_TIME, result.willBeRevokedAt) != asn1::error_t::NONE)
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Элемент времени компрометации
	asn1::element_t since;
	// Если время компрометации разобрать не удалось
	if(!items.next(asn1::tag_t::GENERALIZED_TIME, since))
		// Выводим переведённый отказ разбора
		return translate(items.err());
	// Если время компрометации разобрать не удалось
	if(asn1::time(since, asn1::tag_t::GENERALIZED_TIME, result.badSinceDate) != asn1::error_t::NONE)
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Если расширения записаны
	if(!items.empty()){
		// Элемент записи расширений
		asn1::element_t extensions;
		// Если запись расширений разобрать не удалось
		if(!items.next(asn1::tag_t::SEQUENCE, extensions))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Запоминаем запись расширений
		result.crlDetails = extensions.element;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Функция разбора записей списков отзыва CRLAnnContent
 *
 * @param body   просмотр содержимого тела (для вида crlann)
 * @param result место, в которое помещаются просмотры записей CertificateList
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::crlAnnouncement(const view_t & body, vector <view_t> & result) noexcept {
	// Если содержимое тела не установлено
	if(body.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разборщик записи CRLAnnContent
		asn1::reader_t wrapper(body);
		// Элемент записи набора списков
		asn1::element_t set;
		// Если запись набора списков разобрать не удалось
		if(!wrapper.next(asn1::tag_t::SEQUENCE, set) || !set.constructed)
			// Выводим переведённый отказ разбора
			return translate(wrapper.err());
		// Разборщик записей списков отзыва
		asn1::reader_t records(set.content);
		/**
		 * Разбираем записи списков отзыва
		 */
		while(!records.empty()){
			// Элемент записи списка отзыва
			asn1::element_t crl;
			// Если запись списка отзыва разобрать не удалось
			if(!records.next(crl))
				// Выводим переведённый отказ разбора
				return translate(records.err());
			// Запоминаем запись списка отзыва
			result.push_back(crl.element);
		}
	// Если памяти под сведения не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Функция разбора вложенных сообщений NestedMessageContent
 *
 * @param body   просмотр содержимого тела (для вида nested)
 * @param result место, в которое помещаются просмотры записей PKIMessage
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::nested(const view_t & body, vector <view_t> & result) noexcept {
	// Если содержимое тела не установлено
	if(body.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разборщик записи NestedMessageContent
		asn1::reader_t wrapper(body);
		// Элемент записи набора сообщений
		asn1::element_t set;
		// Если запись набора сообщений разобрать не удалось
		if(!wrapper.next(asn1::tag_t::SEQUENCE, set) || !set.constructed)
			// Выводим переведённый отказ разбора
			return translate(wrapper.err());
		// Разборщик записей сообщений
		asn1::reader_t records(set.content);
		/**
		 * Разбираем записи сообщений
		 */
		while(!records.empty()){
			// Элемент записи сообщения
			asn1::element_t message;
			// Если запись сообщения разобрать не удалось
			if(!records.next(message))
				// Выводим переведённый отказ разбора
				return translate(records.err());
			// Запоминаем запись сообщения
			result.push_back(message.element);
		}
	// Если памяти под сведения не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Функция разбора опроса PollReqContent/PollRepContent
 *
 * @param body   просмотр содержимого тела (для видов pollReq/pollRep)
 * @param result место, в которое помещаются записи опроса
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::poll(const view_t & body, vector <poll_t> & result) noexcept {
	// Если содержимое тела не установлено
	if(body.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разборщик записи опроса
		asn1::reader_t wrapper(body);
		// Элемент записи набора опросов
		asn1::element_t set;
		// Если запись набора опросов разобрать не удалось
		if(!wrapper.next(asn1::tag_t::SEQUENCE, set) || !set.constructed)
			// Выводим переведённый отказ разбора
			return translate(wrapper.err());
		// Разборщик записей опросов
		asn1::reader_t records(set.content);
		/**
		 * Разбираем записи опросов
		 */
		while(!records.empty()){
			// Элемент записи опроса
			asn1::element_t entry;
			// Если запись опроса разобрать не удалось
			if(!records.next(asn1::tag_t::SEQUENCE, entry) || !entry.constructed)
				// Выводим переведённый отказ разбора
				return translate(records.err());
			// Разборщик содержимого записи опроса
			asn1::reader_t items(entry.content);
			// Элемент опознавателя запроса
			asn1::element_t identifier;
			// Если опознаватель запроса разобрать не удалось
			if(!items.next(asn1::tag_t::INTEGER, identifier))
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Место, в которое помещается запись опроса
			poll_t poll;
			// Если опознаватель запроса разобрать не удалось
			if(asn1::integer(identifier, poll.id) != asn1::error_t::NONE)
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Если время ожидания записано (pollRep)
			if(!items.empty()){
				// Элемент времени ожидания
				asn1::element_t checkAfter;
				// Если время ожидания разобрать не удалось
				if(!items.next(asn1::tag_t::INTEGER, checkAfter))
					// Выводим переведённый отказ разбора
					return translate(items.err());
				// Если время ожидания разобрать не удалось
				if(asn1::integer(checkAfter, poll.checkAfter) != asn1::error_t::NONE)
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				// Если причина записана
				if(!items.empty()){
					// Элемент записи причины
					asn1::element_t reason;
					// Если запись причины разобрать не удалось
					if(!items.next(asn1::tag_t::SEQUENCE, reason))
						// Выводим переведённый отказ разбора
						return translate(items.err());
					// Разборщик строк причины
					asn1::reader_t lines(reason.content);
					/**
					 * Разбираем строки причины
					 */
					while(!lines.empty()){
						// Элемент строки причины
						asn1::element_t line;
						// Если строку разобрать не удалось
						if(!lines.next(asn1::tag_t::UTF8_STRING, line))
							// Выводим переведённый отказ разбора
							return translate(lines.err());
						// Строка причины
						string text;
						// Если строку извлечь не удалось
						if(asn1::text(line, asn1::tag_t::UTF8_STRING, text) != asn1::error_t::NONE)
							// Выводим отказ устройства записи
							return error_t::STRUCTURE;
						// Запоминаем строку причины
						poll.reason.push_back(text);
					}
				}
			}
			// Запоминаем запись опроса
			result.push_back(poll);
		}
	// Если памяти под сведения не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}

/**
 * @brief Функция сборки записи GeneralName вида directoryName
 *
 * @param name   запись имени X.501 (просмотр element из name_t)
 * @param result место, в которое помещается запись GeneralName
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::directoryName(const view_t & name, vector <uint8_t> & result) noexcept {
	// Если запись имени не установлена
	if(name.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Записчик записи GeneralName
	asn1::writer_t writer;
	// Открываем запись directoryName [4]
	if(!writer.open(asn1::cls_t::CONTEXT, 4))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись имени
	if(!embed(writer, name))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем запись directoryName
	if(!writer.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Переносим запись GeneralName в итог
		result.assign(writer.data().data, writer.data().data + writer.data().size);
	// Если памяти под итог не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность сборки
	return error_t::NONE;
}
/**
 * @brief Функция сборки шаблона сертификата CertTemplate
 *
 * @param subject запись имени владельца (пустая - поле опущено)
 * @param key     запись сведений об открытом ключе SubjectPublicKeyInfo
 * @param result  место, в которое помещается запись шаблона
 * @return        причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::certTemplate(const view_t & subject, const view_t & key, vector <uint8_t> & result) noexcept {
	// Если запись ключа не установлена
	if(key.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Записчик записи шаблона
	asn1::writer_t writer;
	// Открываем запись шаблона
	if(!writer.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Если имя владельца задано
	if(subject.size > 0){
		// Разборщик записи имени
		asn1::reader_t reader(subject);
		// Элемент записи имени
		asn1::element_t element;
		// Если запись имени разобрать не удалось
		if(!reader.next(element))
			// Выводим отказ сборки
			return error_t::STRUCTURE;
		// Записываем имя владельца под неявной меткой [5]: содержимое имени под меткой [5]
		if(!writer.element(asn1::cls_t::CONTEXT, true, 5, element.content))
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Записываем сведения об открытом ключе под неявной меткой [6]
	{
		// Разборщик записи сведений о ключе
		asn1::reader_t reader(key);
		// Элемент записи сведений о ключе
		asn1::element_t element;
		// Если запись сведений о ключе разобрать не удалось
		if(!reader.next(element))
			// Выводим отказ сборки
			return error_t::STRUCTURE;
		// Записываем сведения о ключе под неявной меткой [6]: содержимое записи под меткой [6]
		if(!writer.element(asn1::cls_t::CONTEXT, true, 6, element.content))
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Закрываем запись шаблона
	if(!writer.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Переносим запись шаблона в итог
		result.assign(writer.data().data, writer.data().data + writer.data().size);
	// Если памяти под итог не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность сборки
	return error_t::NONE;
}
/**
 * @brief Функция сборки сообщения с телом запросов сертификатов
 *
 * @param kind      вид тела (ir/cr/kur/krr/ccr)
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param templates записи шаблонов CertTemplate (по одной на запрос, опознаватели 0, 1, ...)
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::request(const body_t kind, const view_t & sender, const view_t & recipient, const vector <view_t> & templates, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Если вид тела не из запросов либо шаблоны не заданы
	if(((kind != body_t::IR) && (kind != body_t::CR) && (kind != body_t::KUR) && (kind != body_t::KRR) && (kind != body_t::CCR)) || templates.empty())
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Место, в которое помещается запись тела
	vector <uint8_t> body;
	// Итог сборки тела
	const error_t outcome = bodyRequests(kind, templates, signer, hash, body);
	// Если тело собрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ сборки
		return outcome;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, view_t(body.data(), body.size()), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения с телом запросов сертификатов под защитой PBM
 *
 * @param kind      вид тела (ir/cr/kur/krr/ccr)
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param templates записи шаблонов CertTemplate (по одной на запрос, опознаватели 0, 1, ...)
 * @param kid       опознаватель ключа отправителя senderKID
 * @param password  пароль общего секрета
 * @param hash      алгоритм хеша односторонней функции и имитовставки
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::request(const body_t kind, const view_t & sender, const view_t & recipient, const vector <view_t> & templates, const view_t & kid, const view_t & password, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Если вид тела не из запросов либо шаблоны не заданы
	if(((kind != body_t::IR) && (kind != body_t::CR) && (kind != body_t::KUR) && (kind != body_t::KRR) && (kind != body_t::CCR)) || templates.empty())
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Под защитой PBM подтверждение владения подписью невозможно: ключа нет.
	// Подтверждение ставится видом raVerified, как велит раздел 4.3 RFC 4210
	// для случая, когда владение проверяет регистрационный центр
	// Записчик содержимого тела
	asn1::writer_t content;
	// Опознаватель запроса
	int64_t id = 0;
	/**
	 * Переносим шаблоны запросов
	 */
	for(const view_t & certTemplate : templates){
		// Записчик запроса CertReqMsg
		asn1::writer_t message;
		// Открываем запись CertReqMsg
		if(!message.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем запись CertReq
		if(!message.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем опознаватель запроса
		if(!message.integer(id))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Переносим запись шаблона
		if(!embed(message, certTemplate))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем запись CertReq
		if(!message.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем подтверждение владения видом raVerified [0]: NULL
		if(!message.element(asn1::cls_t::CONTEXT, false, 0, view_t(nullptr, 0)))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем запись CertReqMsg
		if(!message.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Переносим запись CertReqMsg в содержимое тела
		if(!embed(content, message.data()))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Опознаватель следующего запроса
		id++;
	}
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (kind)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим содержимое тела записью SEQUENCE OF
	if(!body.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой PBM
	return buildProtected(sender, recipient, body.data(), kid, password, hash, result);
}

/**
 * @brief Функция сборки сообщения certConf
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param hashes    хеши принимаемых сертификатов (SHA-256 записи сертификата)
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::certConfirm(const view_t & sender, const view_t & recipient, const vector <view_t> & hashes, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик содержимого тела CertConfirmContent
	asn1::writer_t content;
	// Опознаватель запроса
	int64_t id = 0;
	/**
	 * Переносим хеши сертификатов
	 */
	for(const view_t & certHash : hashes){
		// Открываем запись CertStatus
		if(!content.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем хеш сертификата
		if(!content.octets(certHash))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем опознаватель запроса
		if(!content.integer(id))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем запись CertStatus
		if(!content.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Опознаватель следующего запроса
		id++;
	}
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела certConf [24]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::CERTCONF)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим содержимое тела записью SEQUENCE OF
	if(!body.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения pkiConf
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::confirm(const view_t & sender, const view_t & recipient, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела pkiconf [19]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::PKICONF)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем содержимое NULL
	if(!body.nothing())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения rr (запрос отзыва)
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param issuer    запись имени издателя отзываемого сертификата
 * @param serial    содержимое порядкового номера отзываемого сертификата
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::revoke(const view_t & sender, const view_t & recipient, const view_t & issuer, const view_t & serial, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Если имя издателя либо номер не заданы
	if((issuer.size == 0) || (serial.size == 0))
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Разборщик записи имени издателя
	asn1::reader_t reader(issuer);
	// Элемент записи имени издателя
	asn1::element_t name;
	// Если запись имени издателя разобрать не удалось
	if(!reader.next(name))
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Записчик содержимого тела RevReqContent
	asn1::writer_t content;
	// Открываем запись RevDetails
	if(!content.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Открываем запись шаблона certDetails
	if(!content.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем порядковый номер под неявной меткой [1]
	if(!content.element(asn1::cls_t::CONTEXT, false, 1, serial))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем имя издателя под неявной меткой [3]: содержимое имени под меткой [3]
	if(!content.element(asn1::cls_t::CONTEXT, true, 3, name.content))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем запись шаблона и запись RevDetails
	if(!content.close() || !content.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела rr [11]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::RR)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим содержимое тела записью SEQUENCE OF
	if(!body.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения genm
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param infos     общие сведения (пара опознаватель и запись значения, пустая - значение опущено)
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::general(const view_t & sender, const view_t & recipient, const vector <info_t> & infos, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик содержимого тела GenMsgContent
	asn1::writer_t content;
	/**
	 * Переносим сведения
	 */
	for(const info_t & info : infos){
		// Открываем запись InfoTypeAndValue
		if(!content.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем опознаватель вида сведений
		if(!content.oid(info.oid))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Если значение задано
		if(info.value.size > 0){
			// Переносим запись значения
			if(!embed(content, info.value))
				// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Закрываем запись InfoTypeAndValue
		if(!content.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела genm [21]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::GENM)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим содержимое тела записью SEQUENCE OF
	if(!body.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения ip/cp/kup (ответ о сертификатах)
 *
 * @param kind      вид тела (ip/cp/kup/ccp)
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param responses ответы о сертификатах (статус и запись сертификата)
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::respond(const body_t kind, const view_t & sender, const view_t & recipient, const vector <response_t> & responses, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Если вид тела не из ответов либо ответы не заданы
	if(((kind != body_t::IP) && (kind != body_t::CP) && (kind != body_t::KUP) && (kind != body_t::CCP)) || responses.empty())
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Записчик содержимого ответов
	asn1::writer_t answers;
	/**
	 * Переносим ответы
	 */
	for(const response_t & response : responses){
		// Открываем запись CertResponse
		if(!answers.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем опознаватель запроса
		if(!answers.integer(response.id))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем сведения о статусе
		{
			// Открываем запись PKIStatusInfo
			if(!answers.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ сборки
				return error_t::MEMORY;
			// Записываем статус
			if(!answers.integer(static_cast <int64_t> (response.status.status)))
				// Выводим отказ сборки
				return error_t::MEMORY;
			// Если строки статуса заданы
			if(!response.status.strings.empty()){
				// Открываем запись строк статуса
				if(!answers.open(asn1::tag_t::SEQUENCE))
					// Выводим отказ сборки
					return error_t::MEMORY;
				/**
				 * Переносим строки статуса
				 */
				for(const string & line : response.status.strings){
					// Записываем строку статуса
					if(!answers.text(asn1::tag_t::UTF8_STRING, line))
						// Выводим отказ сборки
						return error_t::MEMORY;
				}
				// Закрываем запись строк статуса
				if(!answers.close())
					// Выводим отказ сборки
					return error_t::MEMORY;
			}
			// Если сведения об отказе заданы
			if(!response.status.failure.empty()){
				// Записываем сведения об отказе строкой битов
				if(!answers.bits(view_t(response.status.failure.data(), response.status.failure.size()), 0))
					// Выводим отказ сборки
					return error_t::MEMORY;
			}
			// Закрываем запись PKIStatusInfo
			if(!answers.close())
				// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Если запись сертификата задана
		if(response.certificate.size > 0){
			// Открываем запись CertifiedKeyPair
			if(!answers.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ сборки
				return error_t::MEMORY;
			// Записываем сертификат под явной меткой [0]
			if(!answers.open(asn1::cls_t::CONTEXT, 0))
				// Выводим отказ сборки
				return error_t::MEMORY;
			// Переносим запись сертификата
			if(!embed(answers, response.certificate))
				// Выводим отказ сборки
				return error_t::MEMORY;
			// Закрываем явную метку [0] и запись CertifiedKeyPair
			if(!answers.close() || !answers.close())
				// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Закрываем запись CertResponse
		if(!answers.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Записчик содержимого тела CertRepMessage
	asn1::writer_t content;
	// Открываем запись CertRepMessage
	if(!content.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим содержимое ответов
	if(!content.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), answers.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем запись CertRepMessage
	if(!content.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (kind)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись CertRepMessage
	if(!embed(body, content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения error
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param status    сведения о статусе отказа
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::failure(const view_t & sender, const view_t & recipient, const status_info_t & status, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик содержимого тела ErrorMsgContent
	asn1::writer_t content;
	// Открываем запись ErrorMsgContent
	if(!content.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем сведения о статусе
	{
		// Открываем запись PKIStatusInfo
		if(!content.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем статус
		if(!content.integer(static_cast <int64_t> (status.status)))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Если строки статуса заданы
		if(!status.strings.empty()){
			// Открываем запись строк статуса
			if(!content.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ сборки
				return error_t::MEMORY;
			/**
			 * Переносим строки статуса
			 */
			for(const string & line : status.strings){
				// Записываем строку статуса
				if(!content.text(asn1::tag_t::UTF8_STRING, line))
					// Выводим отказ сборки
					return error_t::MEMORY;
			}
			// Закрываем запись строк статуса
			if(!content.close())
				// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Если сведения об отказе заданы
		if(!status.failure.empty()){
			// Записываем сведения об отказе строкой битов
			if(!content.bits(view_t(status.failure.data(), status.failure.size()), 0))
				// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Закрываем запись PKIStatusInfo
		if(!content.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Закрываем запись ErrorMsgContent
	if(!content.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела error [23]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::ERROR)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись ErrorMsgContent
	if(!embed(body, content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}

/**
 * @brief Функция сборки сообщения p10cr (запрос PKCS #10)
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param csr       запись CertificationRequest по RFC 2986
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::requestPkcs10(const view_t & sender, const view_t & recipient, const view_t & csr, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Если запрос не задан
	if(csr.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела p10cr [4]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::P10CR)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись CertificationRequest
	if(!embed(body, csr))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения popdecc (вызовы подтверждения владения)
 *
 * @param sender     запись GeneralName отправителя
 * @param recipient  запись GeneralName получателя
 * @param challenges вызовы (свидетель и вызов)
 * @param signer     подготовленный секретный ключ защиты подписью
 * @param hash       алгоритм хеша подписи
 * @param result     место, в которое помещается запись PKIMessage
 * @return           причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::challenge(const view_t & sender, const view_t & recipient, const vector <challenge_t> & challenges, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик содержимого тела
	asn1::writer_t content;
	/**
	 * Переносим вызовы
	 */
	for(const challenge_t & entry : challenges){
		// Открываем запись Challenge
		if(!content.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Если односторонняя функция задана
		if(!entry.owf.empty()){
			// Записываем алгоритм односторонней функции с пустыми настройками
			if(!writeAlgorithm(content, entry.owf.c_str(), true))
				// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Записываем свидетеля
		if(!content.octets(entry.witness))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем вызов октетной строкой
		if(!content.octets(entry.challenge))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем запись Challenge
		if(!content.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела popdecc [5]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::POPDECC)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим содержимое тела записью SEQUENCE OF
	if(!body.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения popdecr (ответы подтверждения владения)
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param answers   числа ответов
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::challengeReply(const view_t & sender, const view_t & recipient, const vector <int64_t> & answers, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик содержимого тела
	asn1::writer_t content;
	/**
	 * Переносим числа ответов
	 */
	for(const int64_t answer : answers){
		// Записываем число ответа
		if(!content.integer(answer))
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела popdecr [6]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::POPDECR)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим содержимое тела записью SEQUENCE OF
	if(!body.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения krp (ответ восстановления ключа)
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param recovery  ответ восстановления ключа
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::recovered(const view_t & sender, const view_t & recipient, const recovery_t & recovery, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик содержимого тела KeyRecRepContent
	asn1::writer_t content;
	// Открываем запись KeyRecRepContent
	if(!content.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем сведения о статусе
	{
		// Открываем запись PKIStatusInfo
		if(!content.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем статус
		if(!content.integer(static_cast <int64_t> (recovery.status.status)))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем запись PKIStatusInfo
		if(!content.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Если сертификат задан
	if(recovery.certificate.size > 0){
		// Открываем явную метку [0]
		if(!content.open(asn1::cls_t::CONTEXT, 0))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Переносим запись сертификата
		if(!embed(content, recovery.certificate))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем явную метку [0]
		if(!content.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Если сертификаты ЦС заданы
	if(!recovery.caCertificates.empty()){
		// Открываем явную метку [1]
		if(!content.open(asn1::cls_t::CONTEXT, 1))
			// Выводим отказ сборки
			return error_t::MEMORY;
		/**
		 * Переносим записи сертификатов ЦС
		 */
		for(const view_t & certificate : recovery.caCertificates){
			// Переносим запись сертификата ЦС
			if(!embed(content, certificate))
				// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Закрываем явную метку [1]
		if(!content.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Закрываем запись KeyRecRepContent
	if(!content.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела krp [10]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::KRP)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись KeyRecRepContent
	if(!embed(body, content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения rp (ответ отзыва)
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param statuses  сведения о статусах отзыва
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::revoked(const view_t & sender, const view_t & recipient, const vector <status_info_t> & statuses, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик содержимого тела RevRepContent
	asn1::writer_t content;
	// Открываем запись RevRepContent
	if(!content.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Открываем запись набора статусов
	if(!content.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	/**
	 * Переносим сведения о статусах
	 */
	for(const status_info_t & status : statuses){
		// Открываем запись PKIStatusInfo
		if(!content.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем статус
		if(!content.integer(static_cast <int64_t> (status.status)))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем запись PKIStatusInfo
		if(!content.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Закрываем запись набора статусов и запись RevRepContent
	if(!content.close() || !content.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела rp [12]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::RP)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись RevRepContent
	if(!embed(body, content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения ckuann (объявление обновления ключа ЦС)
 *
 * @param sender     запись GeneralName отправителя
 * @param recipient  запись GeneralName получателя
 * @param oldWithNew запись сертификата oldWithNew
 * @param newWithOld запись сертификата newWithOld
 * @param newWithNew запись сертификата newWithNew
 * @param signer     подготовленный секретный ключ защиты подписью
 * @param hash       алгоритм хеша подписи
 * @param result     место, в которое помещается запись PKIMessage
 * @return           причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::caKeyUpdate(const view_t & sender, const view_t & recipient, const view_t & oldWithNew, const view_t & newWithOld, const view_t & newWithNew, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик содержимого тела CAKeyUpdAnnContent
	asn1::writer_t content;
	// Открываем запись CAKeyUpdAnnContent
	if(!content.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись oldWithNew
	if(!embed(content, oldWithNew))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись newWithOld
	if(!embed(content, newWithOld))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись newWithNew
	if(!embed(content, newWithNew))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем запись CAKeyUpdAnnContent
	if(!content.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела ckuann [15]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::CKUANN)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись CAKeyUpdAnnContent
	if(!embed(body, content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения cann (объявление сертификата)
 *
 * @param sender      запись GeneralName отправителя
 * @param recipient   запись GeneralName получателя
 * @param certificate запись сертификата
 * @param signer      подготовленный секретный ключ защиты подписью
 * @param hash        алгоритм хеша подписи
 * @param result      место, в которое помещается запись PKIMessage
 * @return            причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::announce(const view_t & sender, const view_t & recipient, const view_t & certificate, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Если сертификат не задан
	if(certificate.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела cann [16]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::CANN)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись сертификата
	if(!embed(body, certificate))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения rann (объявление отзыва)
 *
 * @param sender       запись GeneralName отправителя
 * @param recipient    запись GeneralName получателя
 * @param announcement объявление отзыва
 * @param signer       подготовленный секретный ключ защиты подписью
 * @param hash         алгоритм хеша подписи
 * @param result       место, в которое помещается запись PKIMessage
 * @return             причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::announceRevocation(const view_t & sender, const view_t & recipient, const announcement_t & announcement, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Если опознаватель сертификата не задан
	if(announcement.certificate.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Записчик содержимого тела RevAnnContent
	asn1::writer_t content;
	// Открываем запись RevAnnContent
	if(!content.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем статус
	if(!content.integer(static_cast <int64_t> (announcement.status)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись опознавателя сертификата
	if(!embed(content, announcement.certificate))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем время занесения в список отзыва
	if(!content.time(asn1::tag_t::GENERALIZED_TIME, announcement.willBeRevokedAt))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем время компрометации
	if(!content.time(asn1::tag_t::GENERALIZED_TIME, announcement.badSinceDate))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем запись RevAnnContent
	if(!content.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела rann [17]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::RANN)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим запись RevAnnContent
	if(!embed(body, content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения crlann (объявление списков отзыва)
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param crls      записи списков отзыва CertificateList
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::announceCrls(const view_t & sender, const view_t & recipient, const vector <view_t> & crls, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик содержимого тела
	asn1::writer_t content;
	/**
	 * Переносим записи списков отзыва
	 */
	for(const view_t & crl : crls){
		// Переносим запись списка отзыва
		if(!embed(content, crl))
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела crlann [18]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::CRLANN)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим содержимое тела записью SEQUENCE OF
	if(!body.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения nested (вложенные сообщения)
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param messages  записи вложенных PKIMessage
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::nest(const view_t & sender, const view_t & recipient, const vector <view_t> & messages, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик содержимого тела
	asn1::writer_t content;
	/**
	 * Переносим записи вложенных сообщений
	 */
	for(const view_t & message : messages){
		// Переносим запись сообщения
		if(!embed(content, message))
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела nested [20]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::NESTED)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим содержимое тела записью SEQUENCE OF
	if(!body.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения pollReq (запрос опроса)
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param ids       опознаватели запросов
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::pollRequest(const view_t & sender, const view_t & recipient, const vector <int64_t> & ids, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик содержимого тела
	asn1::writer_t content;
	/**
	 * Переносим опознаватели запросов
	 */
	for(const int64_t id : ids){
		// Открываем запись опроса
		if(!content.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем опознаватель запроса
		if(!content.integer(id))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем запись опроса
		if(!content.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела pollReq [25]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::POLLREQ)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим содержимое тела записью SEQUENCE OF
	if(!body.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}
/**
 * @brief Функция сборки сообщения pollRep (ответ опроса)
 *
 * @param sender    запись GeneralName отправителя
 * @param recipient запись GeneralName получателя
 * @param polls     записи опроса (опознаватель и время ожидания)
 * @param signer    подготовленный секретный ключ защиты подписью
 * @param hash      алгоритм хеша подписи
 * @param result    место, в которое помещается запись PKIMessage
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::pollReply(const view_t & sender, const view_t & recipient, const vector <poll_t> & polls, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Записчик содержимого тела
	asn1::writer_t content;
	/**
	 * Переносим записи опроса
	 */
	for(const poll_t & poll : polls){
		// Открываем запись опроса
		if(!content.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем опознаватель запроса
		if(!content.integer(poll.id))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем время ожидания
		if(!content.integer(poll.checkAfter))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Если причина задана
		if(!poll.reason.empty()){
			// Открываем запись причины
			if(!content.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ сборки
				return error_t::MEMORY;
			/**
			 * Переносим строки причины
			 */
			for(const string & line : poll.reason){
				// Записываем строку причины
				if(!content.text(asn1::tag_t::UTF8_STRING, line))
					// Выводим отказ сборки
					return error_t::MEMORY;
			}
			// Закрываем запись причины
			if(!content.close())
				// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Закрываем запись опроса
		if(!content.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Записчик тела
	asn1::writer_t body;
	// Открываем метку вида тела pollRep [26]
	if(!body.open(asn1::cls_t::CONTEXT, static_cast <uint32_t> (body_t::POLLREP)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Переносим содержимое тела записью SEQUENCE OF
	if(!body.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), content.data()))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем метку вида тела
	if(!body.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Собираем сообщение с защитой подписью
	return buildSigned(sender, recipient, body.data(), signer, hash, result);
}

/**
 * @brief Функция проверки защиты сообщения подписью
 *
 * @param message разобранное сообщение
 * @param key     сведения об открытом ключе подписи
 * @return        причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::verify(const message_t & message, const x509::key_t & key) noexcept {
	// Если сообщение не разобрано либо защита не записана
	if((message.kind() == body_t::NONE) || (message.protection().size == 0))
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Если алгоритм защиты не записан
	if(message.header().protection.empty())
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Если алгоритм защиты - PBM: проверка подписью ему не положена
	if(message.header().protection == OID_PBM)
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Записчик записи защищаемой части ProtectedPart: подпись ставится под
	// записью SEQUENCE { header, body } по разделу 5.1.3, а не под срезом полей
	asn1::writer_t part;
	// Собираем запись защищаемой части
	if(!part.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), message.part()))
		// Выводим отказ памяти
		return error_t::MEMORY;
	// Итог проверки подписи защищаемой части вызовом x509::verify
	const x509::error_t outcome = x509::verify(part.data(), message.protection(), message.header().protection, message.header().parameters, key);
	/**
	 * Выполняем определение итога проверки
	 */
	switch(outcome){
		// Подпись сошлась
		case x509::error_t::NONE:
			// Выводим успешность проверки
			return error_t::NONE;
		// Ключ чужого алгоритма
		case x509::error_t::KEY:
			// Выводим отказ ключа
			return error_t::KEY;
		// Памяти не хватило
		case x509::error_t::MEMORY:
			// Выводим отказ памяти
			return error_t::MEMORY;
		// Подпись не сошлась
		default:
			// Выводим отказ защиты
			return error_t::PROTECTION;
	}
}
/**
 * @brief Функция проверки защиты сообщения парольной имитовставкой PBM
 *
 * @param message  разобранное сообщение
 * @param password пароль общего секрета
 * @return         причина отказа либо error_t::NONE
 *
 */
nts::cmp::error_t nts::cmp::verify(const message_t & message, const view_t & password) noexcept {
	// Если сообщение не разобрано либо защита не записана
	if((message.kind() == body_t::NONE) || (message.protection().size == 0))
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Если пароль не задан
	if(password.size == 0)
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Если алгоритм защиты не PBM
	if(message.header().protection != OID_PBM)
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Алгоритм хеша имитовставки
	digest::hash_t hash = digest::hash_t::NONE;
	// Место, в которое помещается ключ имитовставки
	vector <uint8_t> key;
	// Итог разбора настроек PBM и выработки ключа
	const error_t outcome = pbmParameters(message.header().parameters, password, hash, key);
	// Если настройки разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Записчик записи защищаемой части ProtectedPart: имитовставка ставится под
	// записью SEQUENCE { header, body } по разделу 5.1.3, а не под срезом полей
	asn1::writer_t part;
	// Собираем запись защищаемой части
	if(!part.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), message.part())){
		// Затираем ключ
		nts::sys::wipe(key.data(), key.size());
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Место, в которое помещается имитовставка
	uint8_t mac[64];
	// Длина имитовставки
	const size_t width = digest::length(hash);
	// Если имитовставку выработать не удалось
	if(!digest::hmac(hash, view_t(key.data(), key.size()), part.data(), mac, width)){
		// Затираем ключ
		nts::sys::wipe(key.data(), key.size());
		// Выводим отказ защиты
		return error_t::PROTECTION;
	}
	// Затираем ключ
	nts::sys::wipe(key.data(), key.size());
	// Если длина имитовставки не та
	if(message.protection().size != width)
		// Выводим отказ защиты
		return error_t::PROTECTION;
	// Сверяем имитовставку с записанной в постоянном времени
	uint8_t difference = 0;
	/**
	 * Перебираем байты имитовставки
	 */
	for(size_t i = 0; i < width; i++)
		// Накапливаем различие
		difference |= (mac[i] ^ static_cast <const uint8_t *> (message.protection().data)[i]);
	// Выводим итог сверки
	return ((difference == 0) ? error_t::NONE : error_t::PROTECTION);
}

/**
 * @brief Метод извлечения записи защищаемой части ProtectedPart
 *
 * @return просмотр записи защищаемой части (заголовок и тело), пустой у неразобранной записи
 *
 */
const nts::view_t & nts::cmp::Message::part() const noexcept {
	// Выводим просмотр записи защищаемой части
	return this->_protected;
}

/**
 * @brief Конструктор
 *
 */
nts::cmp::Status::Status() noexcept : status(status_t::ACCEPTED) {}

/**
 * @brief Конструктор
 *
 */
nts::cmp::Header::Header() noexcept : pvno(2), messageTime(0), hasTime(false) {}

/**
 * @brief Деструктор
 *
 */
nts::cmp::Message::~Message() noexcept {}

/**
 * @brief Конструктор
 *
 */
nts::cmp::Request::Request() noexcept : id(0) {}

/**
 * @brief Конструктор
 *
 */
nts::cmp::Response::Response() noexcept : id(0) {}

/**
 * @brief Конструктор
 *
 */
nts::cmp::Announcement::Announcement() noexcept : status(status_t::ACCEPTED), willBeRevokedAt(0), badSinceDate(0) {}

/**
 * @brief Конструктор
 *
 */
nts::cmp::Poll::Poll() noexcept : id(0), checkAfter(0) {}
