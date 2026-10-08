/**
 * @file cms.cpp
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
 * \~russian
 * @brief Модуль синтаксиса криптографических сообщений —
 *        подписанные и зашифрованные сообщения по RFC 5652,
 *        сведения о получателе KEM по RFC 9629
 *
 * \~english
 * @brief The cryptographic message syntax module —
 *        the signed and enveloped messages according to RFC 5652,
 *        the KEM recipient info according to RFC 9629
 *
 * \~
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
#include <cms/cms.hpp>
#include <asn1/asn1.hpp>
#include <digest/hkdf.hpp>
#include <digest/hmac.hpp>
#include <entropy/entropy.hpp>
#include <keys/keys.hpp>
#include <sign/rsa.hpp>
#include <cipher/aes.hpp>
#include <cipher/mode.hpp>
#include <x509/signature.hpp>
#include <sys/wipe.hpp>

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
	 * Опознаватель содержимого id-data: раздел 4 RFC 5652
	 */
	static const char * OID_DATA = "1.2.840.113549.1.7.1";

	/**
	 * Опознаватель содержимого id-signedData: раздел 5 RFC 5652
	 */
	static const char * OID_SIGNED = "1.2.840.113549.1.7.2";

	/**
	 * Опознаватель содержимого id-envelopedData: раздел 6 RFC 5652
	 */
	static const char * OID_ENVELOPED = "1.2.840.113549.1.7.3";

	/**
	 * Опознаватель содержимого id-digestedData: раздел 7 RFC 5652
	 */
	static const char * OID_DIGESTED = "1.2.840.113549.1.7.5";

	/**
	 * Опознаватель содержимого id-encryptedData: раздел 8 RFC 5652
	 */
	static const char * OID_ENCRYPTED = "1.2.840.113549.1.7.6";

	/**
	 * Опознаватель содержимого id-authenticatedData: раздел 9 RFC 5652
	 */
	static const char * OID_AUTHENTICATED = "1.2.840.113549.1.9.16.1.2";

	/**
	 * Опознаватель атрибута contentType: раздел 11.1 RFC 5652
	 */
	static const char * OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";

	/**
	 * Опознаватель атрибута messageDigest: раздел 11.2 RFC 5652
	 */
	static const char * OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

	/**
	 * Опознаватель открытого ключа RSA: RFC 8017
	 */
	static const char * OID_RSA = "1.2.840.113549.1.1.1";

	/**
	 * Опознаватели алгоритмов хеша: раздел 2.1 RFC 4055 и приложение B RFC 8017
	 */
	static const char * OID_SHA1 = "1.3.14.3.2.26";
	static const char * OID_SHA224 = "2.16.840.1.101.3.4.2.4";
	static const char * OID_SHA256 = "2.16.840.1.101.3.4.2.1";
	static const char * OID_SHA384 = "2.16.840.1.101.3.4.2.2";
	static const char * OID_SHA512 = "2.16.840.1.101.3.4.2.3";

	/**
	 * Опознаватели подписи RSA PKCS #1 v1.5: раздел 5 RFC 4055
	 */
	static const char * OID_SHA1_RSA = "1.2.840.113549.1.1.5";
	static const char * OID_SHA224_RSA = "1.2.840.113549.1.1.14";
	static const char * OID_SHA256_RSA = "1.2.840.113549.1.1.11";
	static const char * OID_SHA384_RSA = "1.2.840.113549.1.1.12";
	static const char * OID_SHA512_RSA = "1.2.840.113549.1.1.13";

	/**
	 * Опознаватели подписи ECDSA: раздел 3.2 RFC 5758
	 */
	static const char * OID_SHA224_ECDSA = "1.2.840.10045.4.3.1";
	static const char * OID_SHA256_ECDSA = "1.2.840.10045.4.3.2";
	static const char * OID_SHA384_ECDSA = "1.2.840.10045.4.3.3";
	static const char * OID_SHA512_ECDSA = "1.2.840.10045.4.3.4";

	/**
	 * Опознаватель подписи Ed25519: раздел 3 RFC 8410
	 */
	static const char * OID_ED25519 = "1.3.101.112";

	/**
	 * Опознаватели подписи ML-DSA: раздел 4 RFC 9881
	 */
	static const char * OID_MLDSA44 = "2.16.840.1.101.3.4.3.17";
	static const char * OID_MLDSA65 = "2.16.840.1.101.3.4.3.18";
	static const char * OID_MLDSA87 = "2.16.840.1.101.3.4.3.19";

	/**
	 * Опознаватели шифров AES-CBC трёх длин ключа: раздел 4 RFC 8018
	 */
	static const char * OID_AES128_CBC = "2.16.840.1.101.3.4.1.2";
	static const char * OID_AES192_CBC = "2.16.840.1.101.3.4.1.22";
	static const char * OID_AES256_CBC = "2.16.840.1.101.3.4.1.42";

	/**
	 * Опознаватели шифров AES-KW трёх длин ключа: RFC 3394
	 */
	static const char * OID_AES128_WRAP = "2.16.840.1.101.3.4.1.5";
	static const char * OID_AES192_WRAP = "2.16.840.1.101.3.4.1.25";
	static const char * OID_AES256_WRAP = "2.16.840.1.101.3.4.1.45";

	/**
	 * Опознаватели HKDF с хешами SHA-2: раздел 3 RFC 8619
	 */
	static const char * OID_HKDF_SHA256 = "2.16.840.1.101.114.1.6.2";

	/**
	 * Опознаватели алгоритмов имитовставки HMAC: раздел 4 RFC 4231
	 */
	static const char * OID_HMAC_SHA1 = "1.3.6.1.5.5.8.1.2";
	static const char * OID_HMAC_SHA224 = "1.2.840.113549.2.8";
	static const char * OID_HMAC_SHA256 = "1.2.840.113549.2.9";
	static const char * OID_HMAC_SHA384 = "1.2.840.113549.2.10";
	static const char * OID_HMAC_SHA512 = "1.2.840.113549.2.11";

	/**
	 * Опознаватель сведений о получателе KEM в обёртке OtherRecipientInfo: раздел 3 RFC 9629
	 */
	static const char * OID_ORI_KEM = "1.2.840.113549.1.9.16.13.3";

	/**
	 * Опознаватели алгоритмов ML-KEM: CSOR по FIPS 203
	 */
	static const char * OID_MLKEM512 = "2.16.840.1.101.3.4.4.1";
	static const char * OID_MLKEM768 = "2.16.840.1.101.3.4.4.2";
	static const char * OID_MLKEM1024 = "2.16.840.1.101.3.4.4.3";

	/**
	 * Длина блока и синхропосылки AES-CBC
	 */
	static constexpr size_t BLOCK = cipher::AES_BLOCK;

	/**
	 * Длина ключа шифрования содержимого AES-256
	 */
	static constexpr size_t CEK = 32;

	/**
	 * @brief Метод перевода отказа разборщика ASN.1 в отказ модуля
	 *
	 * @param error отказ разборщика ASN.1
	 *
	 * @return      отказ модуля
	 *
	 */
	static nts::cms::error_t translate(const asn1::error_t error) noexcept {
		// Выводим отказ модуля: нехватка памяти отдаётся своим отказом, всё прочее - отказом устройства
		return ((error == asn1::error_t::MEMORY) ? nts::cms::error_t::MEMORY : nts::cms::error_t::STRUCTURE);
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
	static nts::cms::error_t oidOf(const asn1::element_t & element, string & result) noexcept {
		// Итог разбора опознавателя
		const asn1::error_t outcome = asn1::oid(element, result);
		// Выводим переведённый отказ разбора, если он есть
		return ((outcome == asn1::error_t::NONE) ? nts::cms::error_t::NONE : translate(outcome));
	}
	/**
	 * @brief Метод разбора записи опознавателя алгоритма
	 *
	 * @param element элемент записи опознавателя алгоритма
	 * @param oid     место, в которое помещается опознаватель алгоритма
	 * @param params  место, в которое помещается просмотр записи настроек алгоритма
	 *
	 * @return        отказ разбора записи
	 *
	 */
	static nts::cms::error_t algorithmIdentifier(const asn1::element_t & element, string & oid, view_t & params) noexcept {
		// Если запись алгоритма имеет простой вид метки
		if(!element.constructed)
			// Выводим отказ устройства записи
			return nts::cms::error_t::STRUCTURE;
		// Разборщик содержимого записи алгоритма
		asn1::reader_t items(element.content);
		// Элемент опознавателя алгоритма
		asn1::element_t field;
		// Если опознаватель алгоритма разобрать не удалось
		if(!items.next(asn1::tag_t::OBJECT, field))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Итог разбора опознавателя алгоритма
		const nts::cms::error_t outcome = oidOf(field, oid);
		// Если опознаватель алгоритма разобрать не удалось
		if(outcome != nts::cms::error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Если настройки алгоритма записаны
		if(!items.empty()){
			// Элемент настроек алгоритма
			asn1::element_t settings;
			// Если настройки алгоритма разобрать не удалось
			if(!items.next(settings))
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Запоминаем запись настроек алгоритма
			params = settings.element;
			// Если после настроек остался хвост
			if(!items.empty())
				// Выводим отказ устройства записи
				return nts::cms::error_t::STRUCTURE;
		}
		// Выводим успешность разбора записи алгоритма
		return nts::cms::error_t::NONE;
	}
	/**
	 * @brief Метод разбора записи ContentInfo
	 *
	 * @param data    просмотр разбираемой записи
	 * @param kind    место, в которое помещается опознаватель вида содержимого
	 * @param content место, в которое помещается просмотр содержимого [0]
	 *
	 * @return        отказ разбора записи
	 *
	 */
	static nts::cms::error_t contentInfo(const view_t & data, string & kind, view_t & content) noexcept {
		// Разборщик записи
		asn1::reader_t reader(data);
		// Элемент записи ContentInfo
		asn1::element_t element;
		// Если запись ContentInfo разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, element) || !element.constructed)
			// Выводим переведённый отказ разбора
			return translate(reader.err());
		// Если после записи остался хвост
		if(!reader.empty())
			// Выводим отказ устройства записи
			return nts::cms::error_t::STRUCTURE;
		// Разборщик содержимого записи ContentInfo
		asn1::reader_t items(element.content);
		// Элемент опознавателя вида содержимого
		asn1::element_t field;
		// Если опознаватель вида содержимого разобрать не удалось
		if(!items.next(asn1::tag_t::OBJECT, field))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Итог разбора опознавателя вида содержимого
		const nts::cms::error_t outcome = oidOf(field, kind);
		// Если опознаватель вида содержимого разобрать не удалось
		if(outcome != nts::cms::error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Элемент содержимого записи
		asn1::element_t body;
		// Если содержимое записи разобрать не удалось
		if(!items.next(body))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Если содержимое записи не несёт метку [0] составного вида
		if(!body.constructed || (body.cls != asn1::cls_t::CONTEXT) || (body.tag != 0))
			// Выводим отказ устройства записи
			return nts::cms::error_t::STRUCTURE;
		// Если после содержимого остался хвост
		if(!items.empty())
			// Выводим отказ устройства записи
			return nts::cms::error_t::STRUCTURE;
		// Запоминаем просмотр содержимого записи
		content = body.content;
		// Выводим успешность разбора записи
		return nts::cms::error_t::NONE;
	}
	/**
	 * @brief Метод разбора записи имени издателя и порядкового номера
	 *
	 * @param element элемент записи IssuerAndSerialNumber
	 * @param issuer  место, в которое помещается просмотр записи имени издателя
	 * @param serial  место, в которое помещается просмотр порядкового номера
	 *
	 * @return        отказ разбора записи
	 *
	 */
	static nts::cms::error_t issuerAndSerial(const asn1::element_t & element, view_t & issuer, view_t & serial) noexcept {
		// Если запись имеет простой вид метки
		if(!element.constructed)
			// Выводим отказ устройства записи
			return nts::cms::error_t::STRUCTURE;
		// Разборщик содержимого записи
		asn1::reader_t items(element.content);
		// Элемент имени издателя
		asn1::element_t name;
		// Если имя издателя разобрать не удалось
		if(!items.next(asn1::tag_t::SEQUENCE, name) || !name.constructed)
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Запоминаем запись имени издателя целиком
		issuer = name.element;
		// Элемент порядкового номера
		asn1::element_t number;
		// Если порядковый номер разобрать не удалось
		if(!items.next(asn1::tag_t::INTEGER, number))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Запоминаем содержимое порядкового номера
		serial = number.content;
		// Если после номера остался хвост
		if(!items.empty())
			// Выводим отказ устройства записи
			return nts::cms::error_t::STRUCTURE;
		// Выводим успешность разбора записи
		return nts::cms::error_t::NONE;
	}
	/**
	 * @brief Метод получения алгоритма хеша по его опознавателю
	 *
	 * @param oid опознаватель алгоритма хеша
	 *
	 * @return    алгоритм хеша, digest::hash_t::NONE у неизвестного
	 *
	 */
	static digest::hash_t hashOf(const string & oid) noexcept {
		// Выводим алгоритм хеша по его опознавателю
		if(oid == OID_SHA1) return digest::hash_t::SHA1;
		if(oid == OID_SHA224) return digest::hash_t::SHA224;
		if(oid == OID_SHA256) return digest::hash_t::SHA256;
		if(oid == OID_SHA384) return digest::hash_t::SHA384;
		if(oid == OID_SHA512) return digest::hash_t::SHA512;
		// Выводим отсутствие алгоритма
		return digest::hash_t::NONE;
	}
	/**
	 * @brief Метод получения опознавателя алгоритма хеша
	 *
	 * @param hash алгоритм хеша
	 *
	 * @return     опознаватель алгоритма хеша либо nullptr
	 *
	 */
	static const char * oidOf(const digest::hash_t hash) noexcept {
		// Выводим опознаватель по алгоритму хеша
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
	 * @brief Метод получения опознавателя алгоритма подписи RSA по опознавателю хеша
	 *
	 * @param digest опознаватель алгоритма хеша
	 *
	 * @return       опознаватель алгоритма подписи либо nullptr
	 *
	 * @note Сведения о подписывающем вправе нести rsaEncryption вместо опознавателя
	 *       подписи: хеш подписи тогда определяется алгоритмом хеша содержимого
	 *       (примечание к разделу 5.1 RFC 5652)
	 *
	 */
	static const char * rsaSignatureOf(const string & digest) noexcept {
		// Выводим опознаватель подписи по опознавателю хеша
		if(digest == OID_SHA1) return OID_SHA1_RSA;
		if(digest == OID_SHA224) return OID_SHA224_RSA;
		if(digest == OID_SHA256) return OID_SHA256_RSA;
		if(digest == OID_SHA384) return OID_SHA384_RSA;
		if(digest == OID_SHA512) return OID_SHA512_RSA;
		// Выводим отсутствие опознавателя
		return nullptr;
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
				return OID_ED25519;
			// Ключ ML-DSA
			case keys::kind_t::MLDSA:
				// Выводим опознаватель по набору ключа
				switch(signer.mldsa().set()){
					case sign::mldsa_t::set_t::DSA44: return OID_MLDSA44;
					case sign::mldsa_t::set_t::DSA65: return OID_MLDSA65;
					case sign::mldsa_t::set_t::DSA87: return OID_MLDSA87;
					default: return nullptr;
				}
			// Ключ, подписи в CMS не выполняющий
			default:
				// Выводим отсутствие опознавателя
				return nullptr;
		}
	}
	/**
	 * @brief Метод выработки подписи содержимого
	 *
	 * @param signer    подготовленный секретный ключ подписи
	 * @param hash      алгоритм хеша подписи (для RSA и ECDSA)
	 * @param content   подписываемое содержимое
	 * @param signature место, в которое помещается подпись
	 *
	 * @return          отказ выработки подписи
	 *
	 */
	static nts::cms::error_t makeSignature(const keys::signer_t & signer, const digest::hash_t hash, const view_t & content, vector <uint8_t> & signature) noexcept {
		/**
		 * Выработка подписи выделяет память: нехватка её отдаётся отказом, а не
		 * завершением процесса
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
						return nts::cms::error_t::SIGNATURE;
					// Занимаем место под подпись длиною в модуль ключа
					signature.assign(rsa.size(), 0);
					// Если подпись выработать не удалось
					if(!rsa.make(sign::scheme_t::PKCS1, hash, view_t(digest, digest::length(hash)), signature.data(), SIZE_MAX))
						// Выводим отказ подписи
						return nts::cms::error_t::SIGNATURE;
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
						return nts::cms::error_t::SIGNATURE;
					// Место, в которое помещается подпись в сыром виде
					uint8_t raw[math::NUMBER_SIZE * 2];
					// Если подпись выработать не удалось
					if(!ecdsa.make(hash, view_t(digest, digest::length(hash)), raw))
						// Выводим отказ подписи
						return nts::cms::error_t::SIGNATURE;
					// Занимаем место под запись подписи по её пределу
					signature.assign(ecdsa.limit(), 0);
					// Длина записи подписи
					size_t written = signature.size();
					// Если подпись в запись DER перевести не удалось
					if(!sign::encode(view_t(raw, ecdsa.size()), signature.data(), written))
						// Выводим отказ подписи
						return nts::cms::error_t::SIGNATURE;
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
						return nts::cms::error_t::SIGNATURE;
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
						return nts::cms::error_t::SIGNATURE;
				} break;
				// Ключ, подписи в CMS не выполняющий
				default:
					// Выводим отказ ключа
					return nts::cms::error_t::KEY;
			}
		// Если памяти под итог не хватило
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return nts::cms::error_t::MEMORY;
		}
		// Выводим успешность выработки подписи
		return nts::cms::error_t::NONE;
	}
	/**
	 * @brief Метод записи опознавателя алгоритма с пустыми настройками
	 *
	 * @param writer записчик, в который ведётся запись
	 * @param oid    опознаватель алгоритма
	 * @param empty  признак записи пустых настроек NULL
	 *
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
	 * @brief Метод переноса готовой записи в записчик как элемента
	 *
	 * @param writer записчик, в который ведётся запись
	 * @param record переносимая запись целиком, с меткой и длиной
	 *
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
	 * @brief Метод защиты ключа по схеме AES-KW (RFC 3394)
	 *
	 * @param kek    ключ защиты ключа
	 * @param plain  защищаемый ключ, длина кратна восьми байтам и не меньше шестнадцати
	 * @param result место, в которое помещается защищённый ключ
	 *
	 * @return       признак успешности защиты
	 *
	 */
	static bool aesWrap(const view_t & kek, const view_t & plain, vector <uint8_t> & result) noexcept {
		// Если длина защищаемого ключа не отвечает разделу 2 RFC 3394
		if((plain.size < 16) || ((plain.size % 8) != 0))
			// Выводим отказ защиты
			return false;
		// Число блоков защищаемого ключа
		const size_t n = plain.size / 8;
		/**
		 * Защита выделяет память: нехватка её отдаётся отказом, а не завершением процесса
		 */
		try {
			// Занимаем место под итог: полу-блок целостности и блоки ключа
			result.assign(plain.size + 8, 0);
		// Если памяти под итог не хватило
		} catch(const std::bad_alloc &) {
			// Выводим отказ защиты
			return false;
		}
		// Шифр AES
		cipher::aes_t aes;
		// Если ключ защиты установить не удалось
		if(!aes.key(kek))
			// Выводим отказ защиты
			return false;
		// Регистр целостности: начальное значение A6A6A6A6A6A6A6A6 по разделу 2.2.1 RFC 3394
		uint8_t a[8];
		// Заполняем регистр начальным значением
		::memset(a, 0xA6, sizeof(a));
		// Переносим блоки ключа в итог
		::memcpy(result.data() + 8, plain.data, plain.size);
		// Место сшивки регистра и блока
		uint8_t b[16];
		/**
		 * Шесть проходов защиты по разделу 2.2.1 RFC 3394
		 */
		for(size_t j = 0; j < 6; j++){
			// Проход по блокам ключа
			for(size_t i = 0; i < n; i++){
				// Сшиваем регистр и очередной блок
				::memcpy(b, a, 8);
				::memcpy(b + 8, result.data() + 8 + i * 8, 8);
				// Зашифровываем сшивку
				if(!aes.encrypt(b, b)){
					// Выполняем затирание сшивки
					nts::sys::wipe(b, sizeof(b));
					// Выводим отказ защиты
					return false;
				}
				// Счётчик прохода в регистре целостности: A ^ t, t = n * j + i + 1
				const uint64_t t = static_cast <uint64_t> (n * j + i + 1);
				// Обновляем регистр целостности
				for(size_t k = 0; k < 8; k++)
					// Выполняем сложение по модулю два со счётчиком
					a[k] = b[k] ^ static_cast <uint8_t> (t >> (56 - k * 8));
				// Переносим младшую половину в блок итога
				::memcpy(result.data() + 8 + i * 8, b + 8, 8);
			}
		}
		// Выполняем затирание сшивки
		nts::sys::wipe(b, sizeof(b));
		// Переносим регистр целостности в голову итога
		::memcpy(result.data(), a, 8);
		// Выводим успешность защиты
		return true;
	}
	/**
	 * @brief Метод снятия защиты ключа по схеме AES-KW (RFC 3394)
	 *
	 * @param kek    ключ защиты ключа
	 * @param wrapped защищённый ключ
	 * @param result место, в которое помещается ключ
	 *
	 * @return       признак успешности снятия защиты: ложь и при нарушении целостности
	 *
	 */
	static bool aesUnwrap(const view_t & kek, const view_t & wrapped, vector <uint8_t> & result) noexcept {
		// Если длина защищённого ключа не отвечает разделу 2 RFC 3394
		if((wrapped.size < 24) || ((wrapped.size % 8) != 0))
			// Выводим отказ снятия защиты
			return false;
		// Число блоков ключа
		const size_t n = wrapped.size / 8 - 1;
		/**
		 * Снятие защиты выделяет память: нехватка её отдаётся отказом, а не завершением процесса
		 */
		try {
			// Занимаем место под итог
			result.assign(wrapped.size - 8, 0);
		// Если памяти под итог не хватило
		} catch(const std::bad_alloc &) {
			// Выводим отказ снятия защиты
			return false;
		}
		// Шифр AES
		cipher::aes_t aes;
		// Если ключ защиты установить не удалось
		if(!aes.key(kek))
			// Выводим отказ снятия защиты
			return false;
		// Регистр целостности
		uint8_t a[8];
		// Переносим регистр из головы записи
		::memcpy(a, wrapped.data, 8);
		// Переносим блоки ключа в итог
		::memcpy(result.data(), wrapped.data + 8, result.size());
		// Место сшивки регистра и блока
		uint8_t b[16];
		/**
		 * Шесть проходов снятия защиты по разделу 2.2.2 RFC 3394
		 */
		for(size_t j = 6; j-- > 0;){
			// Проход по блокам ключа в обратном порядке
			for(size_t i = n; i-- > 0;){
				// Счётчик прохода: t = n * j + i + 1
				const uint64_t t = static_cast <uint64_t> (n * j + i + 1);
				// Сшиваем регистр со счётчиком и очередной блок
				for(size_t k = 0; k < 8; k++)
					// Выполняем сложение по модулю два со счётчиком
					b[k] = a[k] ^ static_cast <uint8_t> (t >> (56 - k * 8));
				::memcpy(b + 8, result.data() + i * 8, 8);
				// Расшифровываем сшивку
				if(!aes.decrypt(b, b)){
					// Выполняем затирание сшивки
					nts::sys::wipe(b, sizeof(b));
					// Выводим отказ снятия защиты
					return false;
				}
				// Обновляем регистр целостности
				::memcpy(a, b, 8);
				// Переносим младшую половину в блок итога
				::memcpy(result.data() + i * 8, b + 8, 8);
			}
		}
		// Выполняем затирание сшивки
		nts::sys::wipe(b, sizeof(b));
		// Сверяем регистр целостности с начальным значением A6A6A6A6A6A6A6A6
		bool sound = true;
		// Проходим по байтам регистра без раннего выхода
		for(size_t k = 0; k < 8; k++)
			// Накапливаем признак целостности
			sound = (sound && (a[k] == 0xA6));
		// Выполняем затирание регистра
		nts::sys::wipe(a, sizeof(a));
		// Если целостность нарушена
		if(!sound){
			// Выполняем затирание итога
			nts::sys::wipe(result.data(), result.size());
			// Выводим отказ снятия защиты
			return false;
		}
		// Выводим успешность снятия защиты
		return true;
	}
	/**
	 * @brief Метод получения набора параметров ML-KEM по его опознавателю
	 *
	 * @param oid опознаватель алгоритма ML-KEM
	 *
	 * @return    набор параметров, agreement::kem_t::NONE у неизвестного
	 *
	 */
	static agreement::kem_t kemOf(const string & oid) noexcept {
		// Выводим набор параметров по опознавателю
		if(oid == OID_MLKEM512) return agreement::kem_t::MLKEM512;
		if(oid == OID_MLKEM768) return agreement::kem_t::MLKEM768;
		if(oid == OID_MLKEM1024) return agreement::kem_t::MLKEM1024;
		// Выводим отсутствие набора
		return agreement::kem_t::NONE;
	}
	/**
	 * @brief Метод получения опознавателя алгоритма ML-KEM
	 *
	 * @param kem набор параметров ML-KEM
	 *
	 * @return    опознаватель алгоритма либо nullptr
	 *
	 */
	static const char * oidOf(const agreement::kem_t kem) noexcept {
		// Выводим опознаватель по набору параметров
		switch(kem){
			case agreement::kem_t::MLKEM512: return OID_MLKEM512;
			case agreement::kem_t::MLKEM768: return OID_MLKEM768;
			case agreement::kem_t::MLKEM1024: return OID_MLKEM1024;
			default: return nullptr;
		}
	}
	/**
	 * @brief Метод выработки ключа KEK по разделу 5 RFC 9629
	 *
	 * @param shared общий секрет инкапсуляции
	 * @param wrap   опознаватель алгоритма защиты ключа CEK
	 * @param length длина ключа KEK в байтах
	 * @param kek    место, в которое помещается ключ KEK
	 *
	 * @return       признак успешности выработки
	 *
	 * @details Сведения CMSORIforKEMOtherInfo собираются из алгоритма защиты и длины
	 *          ключа, поле ukm не записывается; общий секрет пропускается через
	 *          HKDF-SHA-256 с этими сведениями.
	 *
	 */
	static bool deriveKek(const view_t & shared, const char * wrap, const uint16_t length, uint8_t * kek) noexcept {
		// Записчик сведений CMSORIforKEMOtherInfo
		asn1::writer_t info;
		// Открываем набор сведений
		if(!info.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки
			return false;
		// Записываем алгоритм защиты ключа без настроек
		if(!writeAlgorithm(info, wrap, false))
			// Выводим отказ выработки
			return false;
		// Записываем длину ключа KEK
		if(!info.integer(length))
			// Выводим отказ выработки
			return false;
		// Если набор сведений закрыть не удалось
		if(!info.close())
			// Выводим отказ выработки
			return false;
		// Просмотр записи сведений
		const view_t data = info.data();
		// Вырабатываем ключ KEK по HKDF-SHA-256: соли нет, сведения - запись CMSORIforKEMOtherInfo
		return digest::hkdf(digest::hash_t::SHA256, view_t(nullptr, 0), shared, data, kek, length);
	}
	/**
	 * @brief Метод зашифрования содержимого AES-256-CBC
	 *
	 * @param content зашифровываемое содержимое
	 * @param cek     ключ шифрования содержимого
	 * @param iv      синхропосылка
	 * @param result  место, в которое помещается шифротекст
	 *
	 * @return        отказ зашифрования
	 *
	 */
	static nts::cms::error_t encryptContent(const view_t & content, const view_t & cek, const view_t & iv, vector <uint8_t> & result) noexcept {
		/**
		 * Зашифрование выделяет память: нехватка её отдаётся отказом, а не завершением процесса
		 */
		try {
			// Занимаем место под шифротекст: содержимое и дополнение до блока по PKCS #7
			const size_t padded = content.size + (BLOCK - (content.size % BLOCK));
			// Занимаем место под дополненное содержимое
			vector <uint8_t> plain(padded, static_cast <uint8_t> (BLOCK - (content.size % BLOCK)));
			// Переносим содержимое
			if(content.size > 0)
				// Выполняем копирование содержимого
				::memcpy(plain.data(), content.data, content.size);
			// Занимаем место под шифротекст
			result.assign(padded, 0);
			// Шифр AES
			cipher::aes_t aes;
			// Режим CBC
			cipher::chaining_t chaining;
			// Если ключ и режим установить не удалось
			if(!aes.key(cek) || !chaining.start(cipher::block_t(aes), iv)){
				// Выполняем затирание дополненного содержимого
				nts::sys::wipe(plain.data(), plain.size());
				// Выводим отказ зашифрования
				return nts::cms::error_t::KEY;
			}
			// Если содержимое зашифровать не удалось
			if(!chaining.encrypt(view_t(plain.data(), plain.size()), result.data())){
				// Выполняем затирание дополненного содержимого
				nts::sys::wipe(plain.data(), plain.size());
				// Выводим отказ зашифрования
				return nts::cms::error_t::KEY;
			}
			// Выполняем затирание дополненного содержимого
			nts::sys::wipe(plain.data(), plain.size());
		// Если памяти под итог не хватило
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return nts::cms::error_t::MEMORY;
		}
		// Выводим успешность зашифрования
		return nts::cms::error_t::NONE;
	}
	/**
	 * @brief Метод расшифрования содержимого AES-256-CBC
	 *
	 * @param encrypted зашифрованное содержимое
	 * @param cek       ключ шифрования содержимого
	 * @param iv        синхропосылка
	 * @param result    место, в которое помещается содержимое
	 *
	 * @return          отказ расшифрования
	 *
	 */
	static nts::cms::error_t decryptContent(const view_t & encrypted, const view_t & cek, const view_t & iv, vector <uint8_t> & result) noexcept {
		// Если длина шифротекста не кратна блоку либо пуста
		if((encrypted.size == 0) || ((encrypted.size % BLOCK) != 0))
			// Выводим отказ устройства записи
			return nts::cms::error_t::STRUCTURE;
		/**
		 * Расшифрование выделяет память: нехватка её отдаётся отказом, а не завершением процесса
		 */
		try {
			// Занимаем место под содержимое
			result.assign(encrypted.size, 0);
			// Шифр AES
			cipher::aes_t aes;
			// Режим CBC
			cipher::chaining_t chaining;
			// Если ключ и режим установить не удалось
			if(!aes.key(cek) || !chaining.start(cipher::block_t(aes), iv))
				// Выводим отказ расшифрования
				return nts::cms::error_t::KEY;
			// Если шифротекст расшифровать не удалось
			if(!chaining.decrypt(encrypted, result.data()))
				// Выводим отказ расшифрования
				return nts::cms::error_t::KEY;
			// Число байтов дополнения по PKCS #7
			const uint8_t padding = result.back();
			// Если дополнение негодно
			if((padding == 0) || (padding > BLOCK)){
				// Выполняем затирание итога
				nts::sys::wipe(result.data(), result.size());
				// Выводим отказ устройства записи
				return nts::cms::error_t::STRUCTURE;
			}
			// Сверяем байты дополнения без раннего выхода
			bool sound = true;
			// Проходим по байтам дополнения
			for(size_t i = result.size() - padding; i < result.size(); i++)
				// Накапливаем признак целостности
				sound = (sound && (result[i] == padding));
			// Если дополнение нарушено
			if(!sound){
				// Выполняем затирание итога
				nts::sys::wipe(result.data(), result.size());
				// Выводим отказ устройства записи
				return nts::cms::error_t::STRUCTURE;
			}
			// Усекаем итог до содержимого
			result.resize(result.size() - padding);
		// Если памяти под итог не хватило
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return nts::cms::error_t::MEMORY;
		}
		// Выводим успешность расшифрования
		return nts::cms::error_t::NONE;
	}
	/**
	 * @brief Метод сборки записи EncryptedContentInfo и обёртки ContentInfo
	 *
	 * @param recipient записчик, в который уже записаны сведения о получателе
	 * @param content   зашифровываемое содержимое
	 * @param result    место, в которое помещается запись ContentInfo
	 *
	 * @return          отказ сборки
	 *
	 */
	static nts::cms::error_t buildEnveloped(asn1::writer_t & recipient, const int64_t version, const view_t & content, uint8_t * cek, vector <uint8_t> & result) noexcept {
		// Синхропосылка шифрования содержимого
		uint8_t iv[BLOCK];
		// Если случайные байты выработать не удалось
		if(!entropy::bytes(iv, sizeof(iv))){
			// Выводим отказ случайности
			return nts::cms::error_t::RANDOM;
		}
		// Шифротекст содержимого
		vector <uint8_t> encrypted;
		// Итог зашифрования содержимого
		nts::cms::error_t outcome = encryptContent(content, view_t(cek, CEK), view_t(iv, sizeof(iv)), encrypted);
		// Если содержимое зашифровать не удалось
		if(outcome != nts::cms::error_t::NONE){
			// Выполняем затирание ключа
			nts::sys::wipe(cek, sizeof(cek));
			// Выводим отказ сборки
			return outcome;
		}
		/**
		 * Сборка записи выделяет память: нехватка её отдаётся отказом, а не завершением процесса
		 */
		try {
			// Записчик записи EnvelopedData
			asn1::writer_t body;
			// Открываем запись EnvelopedData
			if(!body.open(asn1::tag_t::SEQUENCE)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Записываем издание записи EnvelopedData
			if(!body.integer(version)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Просмотр записи сведений о получателе
			const view_t record = recipient.data();
			// Если запись сведений о получателе перенести не удалось
			if(record.data == nullptr){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Открываем набор сведений о получателях
			if(!body.open(asn1::tag_t::SET)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Переносим запись сведений о получателе как готовый элемент
			if(!embed(body, record)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Закрываем набор сведений о получателях
			if(!body.close()){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Открываем запись EncryptedContentInfo
			if(!body.open(asn1::tag_t::SEQUENCE)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Записываем опознаватель вида содержимого id-data
			if(!body.oid(OID_DATA)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Открываем запись алгоритма шифрования содержимого
			if(!body.open(asn1::tag_t::SEQUENCE)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Записываем опознаватель шифра AES-256-CBC
			if(!body.oid(OID_AES256_CBC)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Записываем синхропосылку
			if(!body.octets(view_t(iv, sizeof(iv)))){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Закрываем запись алгоритма шифрования содержимого
			if(!body.close()){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Записываем зашифрованное содержимое меткой [0] простого вида
			if(!body.element(asn1::cls_t::CONTEXT, false, 0, view_t(encrypted.data(), encrypted.size()))){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Закрываем запись EncryptedContentInfo
			if(!body.close()){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Закрываем запись EnvelopedData
			if(!body.close()){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Записчик обёртки ContentInfo
			asn1::writer_t wrapper;
			// Открываем запись ContentInfo
			if(!wrapper.open(asn1::tag_t::SEQUENCE)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Записываем опознаватель вида содержимого id-envelopedData
			if(!wrapper.oid(OID_ENVELOPED)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Открываем содержимое записи меткой [0]
			if(!wrapper.open(asn1::cls_t::CONTEXT, 0)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Просмотр записи EnvelopedData
			const view_t envelope = body.data();
			// Переносим запись EnvelopedData как готовый элемент
			if(!embed(wrapper, envelope)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Закрываем содержимое записи
			if(!wrapper.close()){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Закрываем запись ContentInfo
			if(!wrapper.close()){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
				// Выводим отказ сборки
				return nts::cms::error_t::MEMORY;
			}
			// Просмотр собранной записи
			const view_t data = wrapper.data();
			// Переносим запись в итог
			result.assign(data.data, data.data + data.size);
		// Если памяти под итог не хватило
		} catch(const std::bad_alloc &) {
			// Выполняем затирание ключа
			nts::sys::wipe(cek, sizeof(cek));
			// Выводим отказ памяти
			return nts::cms::error_t::MEMORY;
		}
		// Выполняем затирание ключа шифрования содержимого
		nts::sys::wipe(cek, sizeof(cek));
		// Выводим успешность сборки
		return nts::cms::error_t::NONE;
	}
};

/**
 * \~russian
 * @brief Метод разбора записи ContentInfo вида id-signedData
 *
 * @param data просмотр разбираемой записи
 * @return     причина отказа либо error_t::NONE
 *
 * \~english
 * @brief Method of parsing a ContentInfo record of the id-signedData kind
 * @param data the view of the record being parsed
 * @return     the reason of the failure or error_t::NONE
 *
 * \~
 */
nts::cms::error_t nts::cms::Signed::parse(const view_t & data) noexcept {
	// Выполняем сброс разобранных сведений
	this->clear();
	// Если запись пуста
	if((data.data == nullptr) || (data.size == 0))
	// Выводим отказ пустой записи
		return (this->_error = error_t::EMPTY);
	// Просмотр содержимого записи ContentInfo
	view_t body;
	// Итог разбора записи ContentInfo
	error_t outcome = contentInfo(data, this->_kind, body);
	// Если запись ContentInfo разобрать не удалось
	if(outcome != error_t::NONE)
	// Выводим отказ разбора
		return (this->_error = outcome);
	// Если вид содержимого не id-signedData
	if(this->_kind != OID_SIGNED)
	// Выводим отказ устройства записи
		return (this->_error = error_t::STRUCTURE);
	// Разборщик содержимого записи SignedData
	asn1::reader_t reader(body);
	// Элемент записи SignedData
	asn1::element_t element;
	// Если запись SignedData разобрать не удалось
	if(!reader.next(asn1::tag_t::SEQUENCE, element) || !element.constructed)
	// Выводим переведённый отказ разбора
		return (this->_error = translate(reader.err()));
	// Если после записи остался хвост
	if(!reader.empty())
	// Выводим отказ устройства записи
		return (this->_error = error_t::STRUCTURE);
	// Разборщик содержимого записи SignedData
	asn1::reader_t items(element.content);
	// Элемент очередного поля
	asn1::element_t field;
	// Если издание записи разобрать не удалось
	if(!items.next(asn1::tag_t::INTEGER, field))
	// Выводим переведённый отказ разбора
		return (this->_error = translate(items.err()));
	// Элемент набора алгоритмов хеша
	asn1::element_t digests;
	// Если набор алгоритмов хеша разобрать не удалось
	if(!items.next(asn1::tag_t::SET, digests) || !digests.constructed)
	// Выводим переведённый отказ разбора
		return (this->_error = translate(items.err()));
	// Элемент записи EncapsulatedContentInfo
	asn1::element_t encapsulated;
	// Если запись EncapsulatedContentInfo разобрать не удалось
	if(!items.next(asn1::tag_t::SEQUENCE, encapsulated) || !encapsulated.constructed)
	// Выводим переведённый отказ разбора
		return (this->_error = translate(items.err()));
	{
		// Разборщик содержимого записи EncapsulatedContentInfo
		asn1::reader_t content(encapsulated.content);
		// Элемент опознавателя вида содержимого
		asn1::element_t kind;
		// Если опознаватель вида содержимого разобрать не удалось
		if(!content.next(asn1::tag_t::OBJECT, kind))
		// Выводим переведённый отказ разбора
			return (this->_error = translate(content.err()));
		// Опознаватель вида содержимого
		string sort;
		// Если опознаватель вида содержимого разобрать не удалось
		if((outcome = oidOf(kind, sort)) != error_t::NONE)
		// Выводим отказ разбора
			return (this->_error = outcome);
		// Если содержимое вложено в запись
		if(!content.empty()){
			// Элемент содержимого
			asn1::element_t inside;
			// Если содержимое разобрать не удалось
			if(!content.next(inside))
			// Выводим переведённый отказ разбора
				return (this->_error = translate(content.err()));
			// Если содержимое не несёт метку [0] составного вида
			if(!inside.constructed || (inside.cls != asn1::cls_t::CONTEXT) || (inside.tag != 0))
			// Выводим отказ устройства записи
				return (this->_error = error_t::STRUCTURE);
			// Разборщик содержимого метки
			asn1::reader_t holder(inside.content);
			// Элемент строки байтов содержимого
			asn1::element_t octets;
			// Если строка байтов содержимого разобрать не удалось
			if(!holder.next(asn1::tag_t::OCTET_STRING, octets))
			// Выводим переведённый отказ разбора
				return (this->_error = translate(holder.err()));
			// Запоминаем просмотр содержимого
			this->_content = octets.content;
			// Если после содержимого остался хвост
			if(!content.empty())
			// Выводим отказ устройства записи
				return (this->_error = error_t::STRUCTURE);
		}
	}
	// Если после записи EncapsulatedContentInfo есть поля
	while(!items.empty()){
		// Элемент очередного поля
		asn1::element_t next;
		// Если очередное поле разобрать не удалось
		if(!items.next(next))
		// Выводим переведённый отказ разбора
			return (this->_error = translate(items.err()));
		// Набор сертификатов несёт метку [0]
		if(next.constructed && (next.cls == asn1::cls_t::CONTEXT) && (next.tag == 0)){
			// Разборщик содержимого набора сертификатов
			asn1::reader_t certificates(next.content);
			// Разбираем записи сертификатов
			while(!certificates.empty()){
				// Элемент записи сертификата
				asn1::element_t certificate;
				// Если запись сертификата разобрать не удалось
				if(!certificates.next(certificate))
				// Выводим переведённый отказ разбора
					return (this->_error = translate(certificates.err()));
				/**
				 * Набор сертификатов выделяет память: нехватка её отдаётся отказом,
				 * а не завершением процесса
				 */
				try {
					// Запоминаем просмотр записи сертификата целиком
					this->_certificates.push_back(certificate.element);
				// Если памяти под итог не хватило
				} catch(const std::bad_alloc &) {
				// Выводим отказ памяти
					return (this->_error = error_t::MEMORY);
				}
			}
		// Набор списков отзыва несёт метку [1]: пропускаем
		} else if(next.constructed && (next.cls == asn1::cls_t::CONTEXT) && (next.tag == 1)){
			// Списки отзыва модулем не рассматриваются
			continue;
		// Набор сведений о подписывающих
		} else if(next.constructed && (next.cls == asn1::cls_t::UNIVERSAL) && (next.tag == static_cast <uint32_t> (asn1::tag_t::SET))){
			// Разборщик содержимого набора подписывающих
			asn1::reader_t signers(next.content);
			// Разбираем записи подписывающих
			while(!signers.empty()){
				// Элемент записи SignerInfo
				asn1::element_t info;
				// Если запись SignerInfo разобрать не удалось
				if(!signers.next(asn1::tag_t::SEQUENCE, info) || !info.constructed)
				// Выводим переведённый отказ разбора
					return (this->_error = translate(signers.err()));
				// Сведения о подписывающем
				signer_info_t signer;
				{
					// Разборщик содержимого записи SignerInfo
					asn1::reader_t fields(info.content);
					// Элемент издания записи
					asn1::element_t version;
					// Если издание записи разобрать не удалось
					if(!fields.next(asn1::tag_t::INTEGER, version))
					// Выводим переведённый отказ разбора
						return (this->_error = translate(fields.err()));
					// Элемент записи IssuerAndSerialNumber
					asn1::element_t sid;
					// Если запись IssuerAndSerialNumber разобрать не удалось
					if(!fields.next(asn1::tag_t::SEQUENCE, sid))
					// Выводим переведённый отказ разбора
						return (this->_error = translate(fields.err()));
					// Если запись IssuerAndSerialNumber разобрать не удалось
					if((outcome = issuerAndSerial(sid, signer.issuer, signer.serial)) != error_t::NONE)
					// Выводим отказ разбора
						return (this->_error = outcome);
					// Элемент записи алгоритма хеша
					asn1::element_t algorithm;
					// Если запись алгоритма хеша разобрать не удалось
					if(!fields.next(asn1::tag_t::SEQUENCE, algorithm))
					// Выводим переведённый отказ разбора
						return (this->_error = translate(fields.err()));
					// Просмотр настроек алгоритма хеша
					view_t settings;
					// Если запись алгоритма хеша разобрать не удалось
					if((outcome = algorithmIdentifier(algorithm, signer.digest, settings)) != error_t::NONE)
					// Выводим отказ разбора
						return (this->_error = outcome);
					// Элемент записи алгоритма подписи
					asn1::element_t signature;
					// Если подписанные атрибуты записаны
					bool attributed = false;
					// Если очередное поле - подписанные атрибуты
					{
						// Разборщик копии для заглядывания вперёд
						asn1::reader_t ahead = fields;
						// Элемент очередного поля
						asn1::element_t peek;
						// Если очередное поле - подписанные атрибуты с меткой [0]
						if(ahead.next(peek) && peek.constructed && (peek.cls == asn1::cls_t::CONTEXT) && (peek.tag == 0)){
							// Запоминаем запись атрибутов целиком
							signer.attributes = peek.element;
							// Запоминаем признак атрибутов
							attributed = true;
							// Сдвигаем разборщик за атрибуты
							fields = ahead;
						}
					}
					// Если запись алгоритма подписи разобрать не удалось
					if(!fields.next(asn1::tag_t::SEQUENCE, signature))
					// Выводим переведённый отказ разбора
						return (this->_error = translate(fields.err()));
					// Если запись алгоритма подписи разобрать не удалось
					if((outcome = algorithmIdentifier(signature, signer.algorithm, signer.parameters)) != error_t::NONE)
					// Выводим отказ разбора
						return (this->_error = outcome);
					// Элемент подписи
					asn1::element_t value;
					// Если подпись разобрать не удалось
					if(!fields.next(asn1::tag_t::OCTET_STRING, value))
					// Выводим переведённый отказ разбора
						return (this->_error = translate(fields.err()));
					// Запоминаем просмотр подписи
					signer.signature = value.content;
					// Признак атрибутов запомнен выше; неподписанные атрибуты [1] пропускаем
					(void) attributed;
				}
				/**
				 * Набор подписывающих выделяет память: нехватка её отдаётся отказом,
				 * а не завершением процесса
				 */
				try {
					// Запоминаем сведения о подписывающем
					this->_signers.push_back(signer);
				// Если памяти под итог не хватило
				} catch(const std::bad_alloc &) {
				// Выводим отказ памяти
					return (this->_error = error_t::MEMORY);
				}
			}
		// Поле чужого вида
		} else
		// Выводим отказ устройства записи
			return (this->_error = error_t::STRUCTURE);
	}
	// Выводим успешность разбора записи
	return error_t::NONE;
}
/**
 * \~russian
 * @brief Метод очистки разобранных сведений
 *
 * \~english
 * @brief Method of clearing the parsed info
 *
 * \~
 */
void nts::cms::Signed::clear() noexcept {
	// Сбрасываем причину последнего отказа
	this->_error = error_t::NONE;
	// Сбрасываем опознаватель вида содержимого
	this->_kind.clear();
	// Сбрасываем просмотр содержимого
	this->_content = view_t();
	// Сбрасываем набор сертификатов
	this->_certificates.clear();
	// Сбрасываем набор подписывающих
	this->_signers.clear();
}
/**
 * \~russian
 * @brief Метод извлечения причины последнего отказа
 *
 * @return причина последнего отказа
 *
 * \~english
 * @brief Method of getting the reason of the last failure
 * @return the reason of the last failure
 *
 * \~
 */
nts::cms::error_t nts::cms::Signed::err() const noexcept {
	// Выводим причину последнего отказа
	return this->_error;
}
/**
 * \~russian
 * @brief Метод извлечения опознавателя вида содержимого
 *
 * @return опознаватель вида содержимого
 *
 * \~english
 * @brief Method of getting the identifier of the kind of the content
 * @return the identifier of the kind of the content
 *
 * \~
 */
const string & nts::cms::Signed::kind() const noexcept {
	// Выводим опознаватель вида содержимого
	return this->_kind;
}
/**
 * \~russian
 * @brief Метод извлечения содержимого
 *
 * @return просмотр содержимого либо пустой просмотр при отделённом содержимом
 *
 * \~english
 * @brief Method of getting the content
 * @return the view of the content or an empty view at a detached content
 *
 * \~
 */
const nts::view_t & nts::cms::Signed::content() const noexcept {
	// Выводим просмотр содержимого
	return this->_content;
}
/**
 * \~russian
 * @brief Метод извлечения набора записей сертификатов
 *
 * @return набор просмотров записей сертификатов
 *
 * \~english
 * @brief Method of getting the set of the certificate records
 * @return the set of the views of the certificate records
 *
 * \~
 */
const vector <nts::view_t> & nts::cms::Signed::certificates() const noexcept {
	// Выводим набор записей сертификатов
	return this->_certificates;
}
/**
 * \~russian
 * @brief Метод извлечения набора сведений о подписывающих
 *
 * @return набор сведений о подписывающих
 *
 * \~english
 * @brief Method of getting the set of the infos of the signers
 * @return the set of the infos of the signers
 *
 * \~
 */
const vector <nts::cms::signer_info_t> & nts::cms::Signed::signers() const noexcept {
	// Выводим набор сведений о подписывающих
	return this->_signers;
}
/**
 * \~russian
 * @brief Конструктор
 *
 * \~english
 * @brief Constructor
 *
 * \~
 */
nts::cms::Signed::Signed() noexcept : _error(error_t::NONE) {}

/**
 * \~russian
 * @brief Метод разбора записи ContentInfo вида id-envelopedData
 *
 * @param data просмотр разбираемой записи
 * @return     причина отказа либо error_t::NONE
 *
 * \~english
 * @brief Method of parsing a ContentInfo record of the id-envelopedData kind
 * @param data the view of the record being parsed
 * @return     the reason of the failure or error_t::NONE
 *
 * \~
 */
nts::cms::error_t nts::cms::Enveloped::parse(const view_t & data) noexcept {
	// Выполняем сброс разобранных сведений
	this->clear();
	// Если запись пуста
	if((data.data == nullptr) || (data.size == 0))
	// Выводим отказ пустой записи
		return (this->_error = error_t::EMPTY);
	// Просмотр содержимого записи ContentInfo
	view_t body;
	// Итог разбора записи ContentInfo
	error_t outcome = contentInfo(data, this->_kind, body);
	// Если запись ContentInfo разобрать не удалось
	if(outcome != error_t::NONE)
	// Выводим отказ разбора
		return (this->_error = outcome);
	// Если вид содержимого не id-envelopedData
	if(this->_kind != OID_ENVELOPED)
	// Выводим отказ устройства записи
		return (this->_error = error_t::STRUCTURE);
	// Разборщик содержимого записи EnvelopedData
	asn1::reader_t reader(body);
	// Элемент записи EnvelopedData
	asn1::element_t element;
	// Если запись EnvelopedData разобрать не удалось
	if(!reader.next(asn1::tag_t::SEQUENCE, element) || !element.constructed)
	// Выводим переведённый отказ разбора
		return (this->_error = translate(reader.err()));
	// Если после записи остался хвост
	if(!reader.empty())
	// Выводим отказ устройства записи
		return (this->_error = error_t::STRUCTURE);
	// Разборщик содержимого записи EnvelopedData
	asn1::reader_t items(element.content);
	// Элемент издания записи
	asn1::element_t version;
	// Если издание записи разобрать не удалось
	if(!items.next(asn1::tag_t::INTEGER, version))
	// Выводим переведённый отказ разбора
		return (this->_error = translate(items.err()));
	// Элемент набора сведений о получателях
	asn1::element_t recipients;
	// Если набор сведений о получателях разобрать не удалось
	if(!items.next(asn1::tag_t::SET, recipients) || !recipients.constructed)
	// Выводим переведённый отказ разбора
		return (this->_error = translate(items.err()));
	// Разборщик содержимого набора сведений о получателях
	asn1::reader_t infos(recipients.content);
	// Разбираем записи сведений о получателях
	while(!infos.empty()){
		// Элемент записи сведений о получателе
		asn1::element_t info;
		// Если запись сведений о получателе разобрать не удалось
		if(!infos.next(asn1::tag_t::SEQUENCE, info) || !info.constructed)
		// Выводим переведённый отказ разбора
			return (this->_error = translate(infos.err()));
		// Разборщик содержимого записи сведений
		asn1::reader_t fields(info.content);
		// Элемент первого поля записи
		asn1::element_t issue;
		// Если первое поле записи разобрать не удалось
		if(!fields.next(issue))
		// Выводим переведённый отказ разбора
			return (this->_error = translate(fields.err()));
		// Если первое поле - опознаватель: запись OtherRecipientInfo по разделу 6.2.5 RFC 5652
		if((issue.cls == asn1::cls_t::UNIVERSAL) && (issue.tag == static_cast <uint32_t> (asn1::tag_t::OBJECT))){
			// Опознаватель вида сведений
			string ori;
			// Если опознаватель вида сведений разобрать не удалось
			if((outcome = oidOf(issue, ori)) != error_t::NONE)
			// Выводим отказ разбора
				return (this->_error = outcome);
			// Если вид сведений не KEM по RFC 9629
			if(ori != OID_ORI_KEM)
			// Выводим отказ алгоритма
				return (this->_error = error_t::ALGORITHM);
			// Элемент записи KEMRecipientInfo
			asn1::element_t value;
			// Если запись KEMRecipientInfo разобрать не удалось
			if(!fields.next(asn1::tag_t::SEQUENCE, value) || !value.constructed)
			// Выводим переведённый отказ разбора
				return (this->_error = translate(fields.err()));
			// Если после записи остался хвост
			if(!fields.empty())
			// Выводим отказ устройства записи
				return (this->_error = error_t::STRUCTURE);
			// Переходим к содержимому записи KEMRecipientInfo
			fields = asn1::reader_t(value.content);
			// Если издание записи разобрать не удалось
			if(!fields.next(asn1::tag_t::INTEGER, issue))
			// Выводим переведённый отказ разбора
				return (this->_error = translate(fields.err()));
		// Иное первое поле обязано быть изданием записи KeyTransRecipientInfo
		} else if((issue.cls != asn1::cls_t::UNIVERSAL) || (issue.tag != static_cast <uint32_t> (asn1::tag_t::INTEGER)))
		// Выводим отказ устройства записи
			return (this->_error = error_t::STRUCTURE);
		// Элемент записи IssuerAndSerialNumber
		asn1::element_t rid;
		// Если запись IssuerAndSerialNumber разобрать не удалось
		if(!fields.next(asn1::tag_t::SEQUENCE, rid))
		// Выводим переведённый отказ разбора
			return (this->_error = translate(fields.err()));
		// Сведения о получателе
		recipient_t recipient;
		// Если запись IssuerAndSerialNumber разобрать не удалось
		if((outcome = issuerAndSerial(rid, recipient.issuer, recipient.serial)) != error_t::NONE)
		// Выводим отказ разбора
			return (this->_error = outcome);
		// Элемент записи алгоритма защиты ключа
		asn1::element_t algorithm;
		// Если запись алгоритма защиты ключа разобрать не удалось
		if(!fields.next(asn1::tag_t::SEQUENCE, algorithm))
		// Выводим переведённый отказ разбора
			return (this->_error = translate(fields.err()));
		// Просмотр настроек алгоритма защиты ключа
		view_t settings;
		// Если запись алгоритма защиты ключа разобрать не удалось
		if((outcome = algorithmIdentifier(algorithm, recipient.algorithm, settings)) != error_t::NONE)
		// Выводим отказ разбора
			return (this->_error = outcome);
		// Если алгоритм защиты ключа - KEM по RFC 9629
		if(kemOf(recipient.algorithm) != agreement::kem_t::NONE){
			// Запоминаем вид сведений и опознаватель KEM
			recipient.kind = recipient_t::kind_t::KEM;
			// Запоминаем опознаватель KEM
			recipient.kem = recipient.algorithm;
			// Элемент текста инкапсуляции
			asn1::element_t kemct;
			// Если текст инкапсуляции разобрать не удалось
			if(!fields.next(asn1::tag_t::OCTET_STRING, kemct))
			// Выводим переведённый отказ разбора
				return (this->_error = translate(fields.err()));
			// Запоминаем просмотр текста инкапсуляции
			recipient.kemct = kemct.content;
			// Элемент записи алгоритма выработки ключа
			asn1::element_t kdf;
			// Если запись алгоритма выработки ключа разобрать не удалось
			if(!fields.next(asn1::tag_t::SEQUENCE, kdf))
			// Выводим переведённый отказ разбора
				return (this->_error = translate(fields.err()));
			// Просмотр настроек алгоритма выработки ключа
			view_t kdfSettings;
			// Если запись алгоритма выработки ключа разобрать не удалось
			if((outcome = algorithmIdentifier(kdf, recipient.kdf, kdfSettings)) != error_t::NONE)
			// Выводим отказ разбора
				return (this->_error = outcome);
			// Элемент длины ключа KEK
			asn1::element_t length;
			// Если длину ключа KEK разобрать не удалось
			if(!fields.next(asn1::tag_t::INTEGER, length))
			// Выводим переведённый отказ разбора
				return (this->_error = translate(fields.err()));
			// Число длины ключа KEK
			int64_t number = 0;
			// Если длину ключа KEK извлечь не удалось
			if(asn1::integer(length, number) != asn1::error_t::NONE)
			// Выводим отказ устройства записи
				return (this->_error = error_t::STRUCTURE);
			// Если длина ключа KEK вне пределов раздела 3 RFC 9629
			if((number < 1) || (number > 65535))
			// Выводим отказ устройства записи
				return (this->_error = error_t::STRUCTURE);
			// Запоминаем длину ключа KEK
			recipient.kekLength = static_cast <uint16_t> (number);
			// Если записано поле ukm с меткой [0]: пропускаем его
			{
				// Разборщик копии для заглядывания вперёд
				asn1::reader_t ahead = fields;
				// Элемент очередного поля
				asn1::element_t peek;
				// Если очередное поле - ukm с меткой [0]
				if(ahead.next(peek) && (peek.cls == asn1::cls_t::CONTEXT) && (peek.tag == 0))
				// Сдвигаем разборщик за поле ukm
					fields = ahead;
			}
			// Элемент записи алгоритма защиты ключа CEK
			asn1::element_t wrap;
			// Если запись алгоритма защиты ключа CEK разобрать не удалось
			if(!fields.next(asn1::tag_t::SEQUENCE, wrap))
			// Выводим переведённый отказ разбора
				return (this->_error = translate(fields.err()));
			// Просмотр настроек алгоритма защиты ключа CEK
			view_t wrapSettings;
			// Если запись алгоритма защиты ключа CEK разобрать не удалось
			if((outcome = algorithmIdentifier(wrap, recipient.wrap, wrapSettings)) != error_t::NONE)
			// Выводим отказ разбора
				return (this->_error = outcome);
		}
		// Элемент защищённого ключа
		asn1::element_t key;
		// Если защищённый ключ разобрать не удалось
		if(!fields.next(asn1::tag_t::OCTET_STRING, key))
		// Выводим переведённый отказ разбора
			return (this->_error = translate(fields.err()));
		// Запоминаем просмотр защищённого ключа
		recipient.encryptedKey = key.content;
		/**
		 * Набор получателей выделяет память: нехватка её отдаётся отказом,
		 * а не завершением процесса
		 */
		try {
			// Запоминаем сведения о получателе
			this->_recipients.push_back(recipient);
		// Если памяти под итог не хватило
		} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
			return (this->_error = error_t::MEMORY);
		}
	}
	// Элемент записи EncryptedContentInfo
	asn1::element_t encrypted;
	// Если запись EncryptedContentInfo разобрать не удалось
	if(!items.next(asn1::tag_t::SEQUENCE, encrypted) || !encrypted.constructed)
	// Выводим переведённый отказ разбора
		return (this->_error = translate(items.err()));
	{
		// Разборщик содержимого записи EncryptedContentInfo
		asn1::reader_t content(encrypted.content);
		// Элемент опознавателя вида содержимого
		asn1::element_t kind;
		// Если опознаватель вида содержимого разобрать не удалось
		if(!content.next(asn1::tag_t::OBJECT, kind))
		// Выводим переведённый отказ разбора
			return (this->_error = translate(content.err()));
		// Опознаватель вида содержимого
		string sort;
		// Если опознаватель вида содержимого разобрать не удалось
		if((outcome = oidOf(kind, sort)) != error_t::NONE)
		// Выводим отказ разбора
			return (this->_error = outcome);
		// Элемент записи алгоритма шифрования содержимого
		asn1::element_t algorithm;
		// Если запись алгоритма шифрования содержимого разобрать не удалось
		if(!content.next(asn1::tag_t::SEQUENCE, algorithm))
		// Выводим переведённый отказ разбора
			return (this->_error = translate(content.err()));
		// Если запись алгоритма шифрования содержимого разобрать не удалось
		if((outcome = algorithmIdentifier(algorithm, this->_algorithm, this->_parameters)) != error_t::NONE)
		// Выводим отказ разбора
			return (this->_error = outcome);
		// Элемент зашифрованного содержимого
		asn1::element_t inside;
		// Если зашифрованное содержимое разобрать не удалось
		if(!content.next(inside))
		// Выводим переведённый отказ разбора
			return (this->_error = translate(content.err()));
		// Если зашифрованное содержимое не несёт метку [0] простого вида
		if(inside.constructed || (inside.cls != asn1::cls_t::CONTEXT) || (inside.tag != 0))
		// Выводим отказ устройства записи
			return (this->_error = error_t::STRUCTURE);
		// Запоминаем просмотр зашифрованного содержимого
		this->_content = inside.content;
		// Если после содержимого остался хвост
		if(!content.empty())
		// Выводим отказ устройства записи
			return (this->_error = error_t::STRUCTURE);
	}
	// Выводим успешность разбора записи
	return error_t::NONE;
}
/**
 * \~russian
 * @brief Метод очистки разобранных сведений
 *
 * \~english
 * @brief Method of clearing the parsed info
 *
 * \~
 */
void nts::cms::Enveloped::clear() noexcept {
	// Сбрасываем причину последнего отказа
	this->_error = error_t::NONE;
	// Сбрасываем опознаватель вида содержимого
	this->_kind.clear();
	// Сбрасываем опознаватель шифра содержимого
	this->_algorithm.clear();
	// Сбрасываем просмотр настроек шифра
	this->_parameters = view_t();
	// Сбрасываем просмотр зашифрованного содержимого
	this->_content = view_t();
	// Сбрасываем набор получателей
	this->_recipients.clear();
}
/**
 * \~russian
 * @brief Метод извлечения причины последнего отказа
 *
 * @return причина последнего отказа
 *
 * \~english
 * @brief Method of getting the reason of the last failure
 * @return the reason of the last failure
 *
 * \~
 */
nts::cms::error_t nts::cms::Enveloped::err() const noexcept {
	// Выводим причину последнего отказа
	return this->_error;
}
/**
 * \~russian
 * @brief Метод извлечения опознавателя вида содержимого
 *
 * @return опознаватель вида содержимого
 *
 * \~english
 * @brief Method of getting the identifier of the kind of the content
 * @return the identifier of the kind of the content
 *
 * \~
 */
const string & nts::cms::Enveloped::kind() const noexcept {
	// Выводим опознаватель вида содержимого
	return this->_kind;
}
/**
 * \~russian
 * @brief Метод извлечения опознавателя шифра содержимого
 *
 * @return опознаватель шифра содержимого
 *
 * \~english
 * @brief Method of getting the identifier of the content cipher
 * @return the identifier of the content cipher
 *
 * \~
 */
const string & nts::cms::Enveloped::algorithm() const noexcept {
	// Выводим опознаватель шифра содержимого
	return this->_algorithm;
}
/**
 * \~russian
 * @brief Метод извлечения записи настроек шифра содержимого
 *
 * @return просмотр записи настроек шифра содержимого
 *
 * \~english
 * @brief Method of getting the encoding of the settings of the content cipher
 * @return the view of the encoding of the settings of the content cipher
 *
 * \~
 */
const nts::view_t & nts::cms::Enveloped::parameters() const noexcept {
	// Выводим просмотр настроек шифра содержимого
	return this->_parameters;
}
/**
 * \~russian
 * @brief Метод извлечения зашифрованного содержимого
 *
 * @return просмотр зашифрованного содержимого
 *
 * \~english
 * @brief Method of getting the encrypted content
 * @return the view of the encrypted content
 *
 * \~
 */
const nts::view_t & nts::cms::Enveloped::content() const noexcept {
	// Выводим просмотр зашифрованного содержимого
	return this->_content;
}
/**
 * \~russian
 * @brief Метод извлечения набора сведений о получателях
 *
 * @return набор сведений о получателях
 *
 * \~english
 * @brief Method of getting the set of the infos of the recipients
 * @return the set of the infos of the recipients
 *
 * \~
 */
const vector <nts::cms::recipient_t> & nts::cms::Enveloped::recipients() const noexcept {
	// Выводим набор сведений о получателях
	return this->_recipients;
}
/**
 * \~russian
 * @brief Конструктор
 *
 * \~english
 * @brief Constructor
 *
 * \~
 */
nts::cms::Enveloped::Enveloped() noexcept : _error(error_t::NONE) {}

/**
 * \~russian
 * @brief Метод определения вида записи ContentInfo
 *
 * @param data просмотр разбираемой записи
 * @return     вид содержимого записи, content_t::NONE у записи иного вида
 *
 * \~english
 * @brief Method of determining the kind of a ContentInfo record
 * @param data the view of the record being parsed
 * @return     the kind of the content of the record, content_t::NONE at a record of a foreign kind
 *
 * \~
 */
nts::cms::content_t nts::cms::content(const view_t & data) noexcept {
	// Опознаватель вида содержимого и просмотр содержимого
	string kind;
	// Просмотр содержимого записи
	view_t body;
	// Если запись ContentInfo разобрать не удалось
	if(contentInfo(data, kind, body) != error_t::NONE)
	// Выводим отсутствие вида
		return content_t::NONE;
	// Выводим вид содержимого по опознавателю
	if(kind == OID_DATA) return content_t::DATA;
	if(kind == OID_SIGNED) return content_t::SIGNED;
	if(kind == OID_ENVELOPED) return content_t::ENVELOPED;
	if(kind == OID_DIGESTED) return content_t::DIGESTED;
	if(kind == OID_ENCRYPTED) return content_t::ENCRYPTED;
	if(kind == OID_AUTHENTICATED) return content_t::AUTHENTICATED;
	// Выводим отсутствие вида
	return content_t::NONE;
}
/**
 * \~russian
 * @brief Метод сборки подписанного сообщения
 *
 * @param certificates набор записей сертификатов (первый — сертификат подписывающего)
 * @param issuer       просмотр записи имени издателя сертификата подписывающего
 * @param serial       просмотр порядкового номера сертификата подписывающего
 * @param content      подписываемое содержимое
 * @param signer       подготовленный секретный ключ подписи
 * @param hash         алгоритм хеша содержимого (для RSA и ECDSA; не рассматривается у Ed25519 и ML-DSA)
 * @param result       место, в которое помещается запись ContentInfo
 *
 * @return             отказ сборки
 *
 * \~english
 * @brief Method of building a signed message
 * @param certificates the set of the certificate records (the first one is of the signer)
 * @param issuer       the view of the issuer name encoding of the certificate of the signer
 * @param serial       the view of the serial number of the certificate of the signer
 * @param content      the content being signed
 * @param signer       the prepared secret key of the signature
 * @param hash         the hash algorithm of the content (for RSA and ECDSA; not considered at Ed25519 and ML-DSA)
 * @param result       the place the ContentInfo record is put into
 * @return             the failure of the building
 *
 * \~
 */
nts::cms::error_t nts::cms::sign(const vector <view_t> & certificates, const view_t & issuer, const view_t & serial, const view_t & content, const keys::signer_t & signer, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Если содержимое либо опознавание подписывающего не установлены
	if((content.data == nullptr) || (issuer.data == nullptr) || (issuer.size == 0) || (serial.data == nullptr) || (serial.size == 0))
	// Выводим отказ пустых данных
		return error_t::EMPTY;
	// Если ключ не подготовлен
	if(!signer.ready())
	// Выводим отказ ключа
		return error_t::KEY;
	// Опознаватель алгоритма подписи
	const char * algorithm = signatureAlgorithm(signer, hash);
	// Если алгоритм подписи неизвестен
	if(algorithm == nullptr)
	// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Опознаватель алгоритма хеша содержимого
	const char * digestOid = oidOf(hash);
	// Если алгоритм хеша неизвестен
	if(digestOid == nullptr)
	// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Место, в которое помещается хеш содержимого
	uint8_t digest[64];
	// Если хеш содержимого выработать не удалось
	if(!digest::hash(hash, content, digest, sizeof(digest)))
	// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Длина хеша содержимого
	const size_t width = digest::length(hash);
	/**
	 * Сборка записи выделяет память: нехватка её отдаётся отказом, а не завершением процесса
	 */
	try {
		// Записчик подписанных атрибутов
		asn1::writer_t attributes;
		// Открываем набор атрибутов меткой [0]
		if(!attributes.open(asn1::cls_t::CONTEXT, 0))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем атрибут contentType
		if(!attributes.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем опознаватель атрибута contentType
		if(!attributes.oid(OID_CONTENT_TYPE))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем набор значений атрибута
		if(!attributes.open(asn1::tag_t::SET))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем вид содержимого id-data
		if(!attributes.oid(OID_DATA))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем набор значений и атрибут
		if(!attributes.close() || !attributes.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем атрибут messageDigest
		if(!attributes.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем опознаватель атрибута messageDigest
		if(!attributes.oid(OID_MESSAGE_DIGEST))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем набор значений атрибута
		if(!attributes.open(asn1::tag_t::SET))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем хеш содержимого
		if(!attributes.octets(view_t(digest, width)))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем набор значений и атрибут
		if(!attributes.close() || !attributes.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем набор атрибутов
		if(!attributes.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Просмотр записи атрибутов
		const view_t signedAttributes = attributes.data();
		// Подпись ставится под записью SET OF атрибутов с универсальной меткой SET
		// по разделу 5.4 RFC 5652: пересобираем содержимое атрибутов под меткой SET
		asn1::writer_t imprint;
		// Открываем набор атрибутов универсальной меткой SET
		if(!imprint.open(asn1::tag_t::SET))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Переносим содержимое атрибутов: разбираем элементы записи [0] и переписываем
		{
			// Разборщик записи атрибутов
			asn1::reader_t holder(signedAttributes);
			// Элемент записи атрибутов
			asn1::element_t wrapper_;
			// Если запись атрибутов разобрать не удалось
			if(!holder.next(wrapper_))
			// Выводим отказ сборки
				return error_t::MEMORY;
			// Разборщик содержимого записи атрибутов
			asn1::reader_t items(wrapper_.content);
			// Разбираем атрибуты
			while(!items.empty()){
				// Элемент атрибута
				asn1::element_t attribute;
				// Если атрибут разобрать не удалось
				if(!items.next(attribute))
				// Выводим отказ сборки
					return error_t::MEMORY;
				// Переносим атрибут как готовый элемент
				if(!imprint.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), attribute.content))
				// Выводим отказ сборки
					return error_t::MEMORY;
			}
		}
		// Закрываем набор атрибутов
		if(!imprint.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Просмотр записи атрибутов под меткой SET
		const view_t body = imprint.data();
		// Подпись записи атрибутов
		vector <uint8_t> signature;
		// Итог выработки подписи
		const error_t outcome = makeSignature(signer, hash, body, signature);
		// Если подпись выработать не удалось
		if(outcome != error_t::NONE)
		// Выводим отказ подписи
			return outcome;
		// Записчик записи SignerInfo
		asn1::writer_t info;
		// Открываем запись SignerInfo
		if(!info.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем издание записи: у sid issuerAndSerialNumber издание 1
		if(!info.integer(1))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем запись IssuerAndSerialNumber
		if(!info.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Переносим запись имени издателя как готовый элемент
		{
			// Разборщик записи имени издателя
			asn1::reader_t name(issuer);
			// Элемент записи имени издателя
			asn1::element_t element;
			// Если запись имени издателя разобрать не удалось
			if(!name.next(asn1::tag_t::SEQUENCE, element))
			// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Переносим содержимое имени издателя
			if(!info.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), element.content))
			// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Записываем порядковый номер сертификата
		if(!info.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), serial))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем запись IssuerAndSerialNumber
		if(!info.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем алгоритм хеша с пустыми настройками
		if(!writeAlgorithm(info, digestOid, true))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Переносим запись атрибутов как готовый элемент метки [0]
		if(!embed(info, signedAttributes))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем алгоритм подписи с пустыми настройками
		if(!writeAlgorithm(info, algorithm, true))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем подпись
		if(!info.octets(view_t(signature.data(), signature.size())))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем запись SignerInfo
		if(!info.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записчик записи SignedData
		asn1::writer_t signedData;
		// Открываем запись SignedData
		if(!signedData.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем издание записи: у подписанных атрибутов и сертификатов издание 3
		if(!signedData.integer(3))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем набор алгоритмов хеша
		if(!signedData.open(asn1::tag_t::SET))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем алгоритм хеша с пустыми настройками
		if(!writeAlgorithm(signedData, digestOid, true))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем набор алгоритмов хеша
		if(!signedData.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем запись EncapsulatedContentInfo
		if(!signedData.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем вид содержимого id-data
		if(!signedData.oid(OID_DATA))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем содержимое меткой [0]
		if(!signedData.open(asn1::cls_t::CONTEXT, 0))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем содержимое строкой байтов
		if(!signedData.octets(content))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем содержимое и запись EncapsulatedContentInfo
		if(!signedData.close() || !signedData.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Если сертификаты записаны
		if(!certificates.empty()){
			// Открываем набор сертификатов меткой [0]
			if(!signedData.open(asn1::cls_t::CONTEXT, 0))
			// Выводим отказ сборки
				return error_t::MEMORY;
			// Переносим записи сертификатов
			for(size_t i = 0; i < certificates.size(); i++){
				// Разборщик записи сертификата
				asn1::reader_t certificate(certificates[i]);
				// Элемент записи сертификата
				asn1::element_t element;
				// Если запись сертификата разобрать не удалось
				if(!certificate.next(element))
				// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				// Переносим запись сертификата как готовый элемент
				if(!signedData.element(element.cls, element.constructed, element.tag, element.content))
				// Выводим отказ сборки
					return error_t::MEMORY;
			}
			// Закрываем набор сертификатов
			if(!signedData.close())
			// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Открываем набор подписывающих
		if(!signedData.open(asn1::tag_t::SET))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Просмотр записи SignerInfo
		const view_t record = info.data();
		// Переносим запись SignerInfo как готовый элемент
		if(!embed(signedData, record))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем набор подписывающих
		if(!signedData.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем запись SignedData
		if(!signedData.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записчик обёртки ContentInfo
		asn1::writer_t wrapper;
		// Открываем запись ContentInfo
		if(!wrapper.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем вид содержимого id-signedData
		if(!wrapper.oid(OID_SIGNED))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем содержимое записи меткой [0]
		if(!wrapper.open(asn1::cls_t::CONTEXT, 0))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Просмотр записи SignedData
		const view_t signedRecord = signedData.data();
		// Переносим запись SignedData как готовый элемент
		if(!embed(wrapper, signedRecord))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем содержимое и запись ContentInfo
		if(!wrapper.close() || !wrapper.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Просмотр собранной записи
		const view_t data = wrapper.data();
		// Переносим запись в итог
		result.assign(data.data, data.data + data.size);
	// Если памяти под итог не хватило
	} catch(const std::bad_alloc &) {
	// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность сборки
	return error_t::NONE;
}
/**
 * \~russian
 * @brief Метод проверки подписи подписанного сообщения
 *
 * @param signed_ разобранное подписанное сообщение
 * @param signer  сведения о проверяемом подписывающем
 * @param content отделённое содержимое либо пустой просмотр, если содержимое вложено в запись
 * @param key     сведения об открытом ключе из сертификата подписывающего
 *
 * @return        отказ проверки
 *
 * \~english
 * @brief Method of the check of the signature of a signed message
 * @param signed_ the parsed signed message
 * @param signer  the info of the signer being checked
 * @param content the detached content or an empty view if the content is embedded into the record
 * @param key     the info of the public key from the certificate of the signer
 * @return        the failure of the check
 *
 * \~
 */
nts::cms::error_t nts::cms::verify(const signed_t & signed_, const signer_info_t & signer, const view_t & content, const x509::key_t & key) noexcept {
	// Просмотр содержимого: отделённое либо вложенное в запись
	view_t body = content;
	// Если содержимое не передано
	if(body.data == nullptr)
	// Берём содержимое из записи
		body = signed_.content();
	// Если содержимого нет
	if(body.data == nullptr)
	// Выводим отказ пустых данных
		return error_t::EMPTY;
	// Опознаватель алгоритма подписи: rsaEncryption заменяется опознавателем подписи по хешу
	string algorithm = signer.algorithm;
	// Если записан голый rsaEncryption
	if(algorithm == OID_RSA){
		// Опознаватель подписи по опознавателю хеша
		const char * mapped = rsaSignatureOf(signer.digest);
		// Если опознаватель подписи не найден
		if(mapped == nullptr)
		// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Запоминаем опознаватель подписи
		algorithm = mapped;
	}
	// Если подписанные атрибуты записаны
	if(signer.attributes.data != nullptr){
		// Алгоритм хеша содержимого
		const digest::hash_t hash = hashOf(signer.digest);
		// Если алгоритм хеша неизвестен
		if(hash == digest::hash_t::NONE)
		// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Место, в которое помещается хеш содержимого
		uint8_t digest[64];
		// Если хеш содержимого выработать не удалось
		if(!digest::hash(hash, body, digest, sizeof(digest)))
		// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Длина хеша содержимого
		const size_t width = digest::length(hash);
		// Разборщик записи атрибутов: метка [0] составного вида
		asn1::reader_t attributes(signer.attributes);
		// Элемент записи атрибутов
		asn1::element_t element;
		// Если запись атрибутов разобрать не удалось
		if(!attributes.next(element) || !element.constructed || (element.cls != asn1::cls_t::CONTEXT) || (element.tag != 0))
		// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Разборщик содержимого записи атрибутов
		asn1::reader_t items(element.content);
		// Признаки найденных атрибутов
		bool typed = false, digested = false;
		// Разбираем атрибуты
		while(!items.empty()){
			// Элемент атрибута
			asn1::element_t attribute;
			// Если атрибут разобрать не удалось
			if(!items.next(asn1::tag_t::SEQUENCE, attribute) || !attribute.constructed)
			// Выводим переведённый отказ разбора
				return translate(items.err());
			// Разборщик содержимого атрибута
			asn1::reader_t fields(attribute.content);
			// Элемент опознавателя атрибута
			asn1::element_t oid;
			// Если опознаватель атрибута разобрать не удалось
			if(!fields.next(asn1::tag_t::OBJECT, oid))
			// Выводим переведённый отказ разбора
				return translate(fields.err());
			// Опознаватель атрибута
			string name;
			// Если опознаватель атрибута разобрать не удалось
			if(oidOf(oid, name) != error_t::NONE)
			// Выводим отказ разбора
				return error_t::STRUCTURE;
			// Элемент набора значений атрибута
			asn1::element_t values;
			// Если набор значений атрибута разобрать не удалось
			if(!fields.next(asn1::tag_t::SET, values) || !values.constructed)
			// Выводим переведённый отказ разбора
				return translate(fields.err());
			// Разборщик содержимого набора значений
			asn1::reader_t entries(values.content);
			// Элемент значения атрибута
			asn1::element_t value;
			// Если значение атрибута разобрать не удалось
			if(!entries.next(value))
			// Выводим переведённый отказ разбора
				return translate(entries.err());
			// Атрибут contentType
			if(name == OID_CONTENT_TYPE){
				// Опознаватель вида содержимого
				string sort;
				// Если значение атрибута не опознаватель
				if(oidOf(value, sort) != error_t::NONE)
				// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				// Если вид содержимого не id-data
				if(sort != OID_DATA)
				// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				// Запоминаем признак атрибута
				typed = true;
			// Атрибут messageDigest
			} else if(name == OID_MESSAGE_DIGEST){
				// Если значение атрибута не строка байтов
				if((value.cls != asn1::cls_t::UNIVERSAL) || (value.tag != static_cast <uint32_t> (asn1::tag_t::OCTET_STRING)))
				// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				// Если хеш содержимого не сошёлся
				if((value.content.size != width) || (::memcmp(value.content.data, digest, width) != 0))
				// Выводим отказ подписи
					return error_t::SIGNATURE;
				// Запоминаем признак атрибута
				digested = true;
			}
		}
		// Если обязательные атрибуты не найдены
		if(!typed || !digested)
		// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Подпись проверяется под записью SET OF атрибутов с универсальной меткой SET
		// по разделу 5.4 RFC 5652: пересобираем содержимое атрибутов под меткой SET
		asn1::writer_t imprint;
		/**
		 * Пересборка выделяет память: нехватка её отдаётся отказом, а не завершением процесса
		 */
		try {
			// Открываем набор атрибутов универсальной меткой SET
			if(!imprint.open(asn1::tag_t::SET))
			// Выводим отказ памяти
				return error_t::MEMORY;
			// Разборщик содержимого записи атрибутов
			asn1::reader_t rest(element.content);
			// Разбираем атрибуты
			while(!rest.empty()){
				// Элемент атрибута
				asn1::element_t attribute;
				// Если атрибут разобрать не удалось
				if(!rest.next(attribute))
				// Выводим переведённый отказ разбора
					return translate(rest.err());
				// Переносим атрибут как готовый элемент
				if(!imprint.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), attribute.content))
				// Выводим отказ памяти
					return error_t::MEMORY;
			}
			// Закрываем набор атрибутов
			if(!imprint.close())
			// Выводим отказ памяти
				return error_t::MEMORY;
		// Если памяти под итог не хватило
		} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
			return error_t::MEMORY;
		}
		// Просмотр записи атрибутов под меткой SET
		const view_t record = imprint.data();
		// Проверяем подпись под записью атрибутов
		const nts::x509::error_t outcome = nts::x509::verify(record, signer.signature, algorithm, signer.parameters, key);
		// Выводим переведённый отказ проверки
		switch(outcome){
			case nts::x509::error_t::NONE: return error_t::NONE;
			case nts::x509::error_t::KEY: return error_t::KEY;
			case nts::x509::error_t::MEMORY: return error_t::MEMORY;
			default: return error_t::SIGNATURE;
		}
	}
	// Подписанных атрибутов нет: подпись проверяется под самим содержимым
	const nts::x509::error_t outcome = nts::x509::verify(body, signer.signature, algorithm, signer.parameters, key);
	// Выводим переведённый отказ проверки
	switch(outcome){
		case nts::x509::error_t::NONE: return error_t::NONE;
		case nts::x509::error_t::KEY: return error_t::KEY;
		case nts::x509::error_t::MEMORY: return error_t::MEMORY;
		default: return error_t::SIGNATURE;
	}
}
/**
 * \~russian
 * @brief Метод сборки вырожденной записи цепочки сертификатов («.p7b»)
 *
 * @param certificates набор записей сертификатов
 * @param result       место, в которое помещается запись ContentInfo
 *
 * @return             отказ сборки
 *
 * \~english
 * @brief Method of building a degenerate record of a certificate chain (".p7b")
 * @param certificates the set of the certificate records
 * @param result       the place the ContentInfo record is put into
 * @return             the failure of the building
 *
 * \~
 */
nts::cms::error_t nts::cms::certificates(const vector <view_t> & certificates, vector <uint8_t> & result) noexcept {
	// Если набор сертификатов пуст
	if(certificates.empty())
	// Выводим отказ пустых данных
		return error_t::EMPTY;
	/**
	 * Сборка записи выделяет память: нехватка её отдаётся отказом, а не завершением процесса
	 */
	try {
		// Записчик записи SignedData
		asn1::writer_t signedData;
		// Открываем запись SignedData
		if(!signedData.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем издание записи: у сертификатов издание 3
		if(!signedData.integer(3))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем пустой набор алгоритмов хеша
		if(!signedData.open(asn1::tag_t::SET) || !signedData.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем запись EncapsulatedContentInfo
		if(!signedData.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем вид содержимого id-data без содержимого
		if(!signedData.oid(OID_DATA))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем запись EncapsulatedContentInfo
		if(!signedData.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем набор сертификатов меткой [0]
		if(!signedData.open(asn1::cls_t::CONTEXT, 0))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Переносим записи сертификатов
		for(size_t i = 0; i < certificates.size(); i++){
			// Разборщик записи сертификата
			asn1::reader_t certificate(certificates[i]);
			// Элемент записи сертификата
			asn1::element_t element;
			// Если запись сертификата разобрать не удалось
			if(!certificate.next(element))
			// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Переносим запись сертификата как готовый элемент
			if(!signedData.element(element.cls, element.constructed, element.tag, element.content))
			// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Закрываем набор сертификатов
		if(!signedData.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем пустой набор подписывающих
		if(!signedData.open(asn1::tag_t::SET) || !signedData.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем запись SignedData
		if(!signedData.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записчик обёртки ContentInfo
		asn1::writer_t wrapper;
		// Открываем запись ContentInfo
		if(!wrapper.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем вид содержимого id-signedData
		if(!wrapper.oid(OID_SIGNED))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Открываем содержимое записи меткой [0]
		if(!wrapper.open(asn1::cls_t::CONTEXT, 0))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Просмотр записи SignedData
		const view_t record = signedData.data();
		// Переносим запись SignedData как готовый элемент
		if(!embed(wrapper, record))
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем содержимое и запись ContentInfo
		if(!wrapper.close() || !wrapper.close())
		// Выводим отказ сборки
			return error_t::MEMORY;
		// Просмотр собранной записи
		const view_t data = wrapper.data();
		// Переносим запись в итог
		result.assign(data.data, data.data + data.size);
	// Если памяти под итог не хватило
	} catch(const std::bad_alloc &) {
	// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность сборки
	return error_t::NONE;
}

/**
 * \~russian
 * @brief Метод сборки зашифрованного сообщения с передачей ключа по RSA
 *
 * @param content    зашифровываемое содержимое
 * @param issuer     просмотр записи имени издателя сертификата получателя
 * @param serial     просмотр порядкового номера сертификата получателя
 * @param key        сведения об открытом ключе RSA из сертификата получателя
 * @param result     место, в которое помещается запись ContentInfo
 *
 * @return           отказ сборки
 *
 * \~english
 * @brief Method of building an enveloped message with the key transport by RSA
 * @param content    the content being encrypted
 * @param issuer     the view of the issuer name encoding of the certificate of the recipient
 * @param serial     the view of the serial number of the certificate of the recipient
 * @param key        the info of the public RSA key from the certificate of the recipient
 * @param result     the place the ContentInfo record is put into
 * @return           the failure of the building
 *
 * \~
 */
nts::cms::error_t nts::cms::envelop(const view_t & content, const view_t & issuer, const view_t & serial, const x509::key_t & key, vector <uint8_t> & result) noexcept {
	// Если содержимое либо опознавание получателя не установлены
	if((content.data == nullptr) || (issuer.data == nullptr) || (issuer.size == 0) || (serial.data == nullptr) || (serial.size == 0))
	// Выводим отказ пустых данных
		return error_t::EMPTY;
	// Если ключ чужого алгоритма
	if(key.algorithm != OID_RSA)
	// Выводим отказ ключа
		return error_t::KEY;
	// Разбираем сведения об открытом ключе RSA
	keys::key_t public_;
	// Если запись SubjectPublicKeyInfo разобрать не удалось
	if(keys::decodeSubjectPublicKeyInfo(key.element, public_) != keys::error_t::NONE)
	// Выводим отказ ключа
		return error_t::KEY;
	// Ключ шифрования содержимого
	uint8_t cek[CEK];
	// Если случайные байты выработать не удалось
	if(!entropy::bytes(cek, sizeof(cek)))
	// Выводим отказ случайности
		return error_t::RANDOM;
	// Модуль подписи RSA для зашифрования ключа
	sign::rsa_t rsa;
	// Если ключ RSA установить не удалось
	if(!rsa.key(view_t(public_.n.data(), public_.n.size()), view_t(public_.e.data(), public_.e.size()))){
		// Выполняем затирание ключа
		nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ ключа
		return error_t::KEY;
	}
	// Защищённый ключ
	vector <uint8_t> wrapped;
	/**
	 * Защита ключа выделяет память: нехватка её отдаётся отказом, а не завершением процесса
	 */
	try {
		// Занимаем место под защищённый ключ длиною в модуль
		wrapped.assign(rsa.size(), 0);
	// Если памяти под итог не хватило
	} catch(const std::bad_alloc &) {
		// Выполняем затирание ключа
		nts::sys::wipe(cek, sizeof(cek));
	// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Если ключ защитить не удалось
	if(!rsa.encrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view_t(cek, sizeof(cek)), wrapped.data())){
		// Выполняем затирание ключа
		nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ ключа
		return error_t::KEY;
	}
	/**
	 * Сборка записи выделяет память: нехватка её отдаётся отказом, а не завершением процесса
	 */
	error_t outcome = error_t::NONE;
	try {
		// Записчик записи KeyTransRecipientInfo
		asn1::writer_t recipient;
		// Открываем запись KeyTransRecipientInfo
		if(!recipient.open(asn1::tag_t::SEQUENCE)){
			// Выполняем затирание ключа
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем издание записи: у rid issuerAndSerialNumber издание 0
		if(!recipient.integer(0)){
			// Выполняем затирание ключа
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Открываем запись IssuerAndSerialNumber
		if(!recipient.open(asn1::tag_t::SEQUENCE)){
			// Выполняем затирание ключа
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Переносим запись имени издателя как готовый элемент
		{
			// Разборщик записи имени издателя
			asn1::reader_t name(issuer);
			// Элемент записи имени издателя
			asn1::element_t element;
			// Если запись имени издателя разобрать не удалось
			if(!name.next(asn1::tag_t::SEQUENCE, element)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
			// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			}
			// Переносим содержимое имени издателя
			if(!recipient.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), element.content)){
				// Выполняем затирание ключа
				nts::sys::wipe(cek, sizeof(cek));
			// Выводим отказ сборки
				return error_t::MEMORY;
			}
		}
		// Записываем порядковый номер сертификата
		if(!recipient.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), serial)){
			// Выполняем затирание ключа
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Закрываем запись IssuerAndSerialNumber
		if(!recipient.close()){
			// Выполняем затирание ключа
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем алгоритм rsaEncryption с пустыми настройками
		if(!writeAlgorithm(recipient, OID_RSA, true)){
			// Выполняем затирание ключа
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем защищённый ключ
		if(!recipient.octets(view_t(wrapped.data(), wrapped.size()))){
			// Выполняем затирание ключа
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Закрываем запись KeyTransRecipientInfo
		if(!recipient.close()){
			// Выполняем затирание ключа
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Собираем запись EnvelopedData: издание 0 у сведений KeyTrans
		outcome = buildEnveloped(recipient, 0, content, cek, result);
	// Если памяти под итог не хватило
	} catch(const std::bad_alloc &) {
		// Выполняем затирание ключа
		nts::sys::wipe(cek, sizeof(cek));
	// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выполняем затирание ключа шифрования содержимого
	nts::sys::wipe(cek, sizeof(cek));
	// Выводим итог сборки
	return outcome;
}
/**
 * \~russian
 * @brief Метод сборки зашифрованного сообщения с инкапсуляцией ключа по KEM
 *
 * @param content    зашифровываемое содержимое
 * @param issuer     просмотр записи имени издателя сертификата получателя
 * @param serial     просмотр порядкового номера сертификата получателя
 * @param kem        набор параметров ML-KEM
 * @param key        открытый ключ инкапсуляции ML-KEM получателя
 * @param result     место, в которое помещается запись ContentInfo
 *
 * @return           отказ сборки
 *
 * \~english
 * @brief Method of building an enveloped message with the key encapsulation by KEM
 * @param content    the content being encrypted
 * @param issuer     the view of the issuer name encoding of the certificate of the recipient
 * @param serial     the view of the serial number of the certificate of the recipient
 * @param kem        the ML-KEM parameter set
 * @param key        the ML-KEM encapsulation key of the recipient
 * @param result     the place the ContentInfo record is put into
 * @return           the failure of the building
 *
 * \~
 */
nts::cms::error_t nts::cms::envelop(const view_t & content, const view_t & issuer, const view_t & serial, const agreement::kem_t kem, const view_t & key, vector <uint8_t> & result) noexcept {
	// Если содержимое либо опознавание получателя не установлены
	if((content.data == nullptr) || (issuer.data == nullptr) || (issuer.size == 0) || (serial.data == nullptr) || (serial.size == 0))
	// Выводим отказ пустых данных
		return error_t::EMPTY;
	// Опознаватель алгоритма ML-KEM
	const char * kemOid = oidOf(kem);
	// Если набор параметров неизвестен
	if(kemOid == nullptr)
	// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Если открытый ключ негоден
	if(!agreement::validate(kem, key))
	// Выводим отказ ключа
		return error_t::KEY;
	// Ключ шифрования содержимого
	uint8_t cek[CEK];
	// Если случайные байты выработать не удалось
	if(!entropy::bytes(cek, sizeof(cek)))
	// Выводим отказ случайности
		return error_t::RANDOM;
	// Текст инкапсуляции и общий секрет
	vector <uint8_t> kemct;
	// Общий секрет инкапсуляции
	uint8_t shared[agreement::MLKEM_SHARED];
	/**
	 * Инкапсуляция выделяет память: нехватка её отдаётся отказом, а не завершением процесса
	 */
	try {
		// Занимаем место под текст инкапсуляции
		kemct.assign(agreement::ciphertext(kem), 0);
	// Если памяти под итог не хватило
	} catch(const std::bad_alloc &) {
		// Выполняем затирание ключа
		nts::sys::wipe(cek, sizeof(cek));
	// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Если инкапсуляцию выполнить не удалось
	if(!agreement::encapsulate(kem, key, kemct.data(), shared)){
		// Выполняем затирание ключа
		nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ ключа
		return error_t::KEY;
	}
	// Ключ KEK длиною под AES-256
	uint8_t kek[32];
	// Вырабатываем ключ KEK по разделу 5 RFC 9629
	if(!deriveKek(view_t(shared, sizeof(shared)), OID_AES256_WRAP, sizeof(kek), kek)){
		// Выполняем затирание секретов
		nts::sys::wipe(shared, sizeof(shared));
		nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	}
	// Выполняем затирание общего секрета
	nts::sys::wipe(shared, sizeof(shared));
	// Защищённый ключ содержимого
	vector <uint8_t> wrapped;
	// Если ключ содержимого защитить не удалось
	if(!aesWrap(view_t(kek, sizeof(kek)), view_t(cek, sizeof(cek)), wrapped)){
		// Выполняем затирание секретов
		nts::sys::wipe(kek, sizeof(kek));
		nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ ключа
		return error_t::KEY;
	}
	/**
	 * Сборка записи выделяет память: нехватка её отдаётся отказом, а не завершением процесса
	 */
	error_t outcome = error_t::NONE;
	try {
		// Записчик записи KEMRecipientInfo
		asn1::writer_t recipient;
		// Открываем запись KEMRecipientInfo
		if(!recipient.open(asn1::tag_t::SEQUENCE)){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем издание записи: по разделу 3 RFC 9629 издание всегда 0
		if(!recipient.integer(0)){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Открываем запись IssuerAndSerialNumber
		if(!recipient.open(asn1::tag_t::SEQUENCE)){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Переносим запись имени издателя как готовый элемент
		{
			// Разборщик записи имени издателя
			asn1::reader_t name(issuer);
			// Элемент записи имени издателя
			asn1::element_t element;
			// Если запись имени издателя разобрать не удалось
			if(!name.next(asn1::tag_t::SEQUENCE, element)){
				// Выполняем затирание секретов
				nts::sys::wipe(kek, sizeof(kek));
				nts::sys::wipe(cek, sizeof(cek));
			// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			}
			// Переносим содержимое имени издателя
			if(!recipient.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), element.content)){
				// Выполняем затирание секретов
				nts::sys::wipe(kek, sizeof(kek));
				nts::sys::wipe(cek, sizeof(cek));
			// Выводим отказ сборки
				return error_t::MEMORY;
			}
		}
		// Записываем порядковый номер сертификата
		if(!recipient.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), serial)){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Закрываем запись IssuerAndSerialNumber
		if(!recipient.close()){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем алгоритм KEM без настроек
		if(!writeAlgorithm(recipient, kemOid, false)){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем текст инкапсуляции
		if(!recipient.octets(view_t(kemct.data(), kemct.size()))){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем алгоритм выработки ключа HKDF-SHA-256 без настроек
		if(!writeAlgorithm(recipient, OID_HKDF_SHA256, false)){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем длину ключа KEK
		if(!recipient.integer(static_cast <int64_t> (sizeof(kek)))){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем алгоритм защиты ключа AES-256-KW без настроек
		if(!writeAlgorithm(recipient, OID_AES256_WRAP, false)){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем защищённый ключ содержимого
		if(!recipient.octets(view_t(wrapped.data(), wrapped.size()))){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Закрываем запись KEMRecipientInfo
		if(!recipient.close()){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записчик обёртки OtherRecipientInfo по разделу 6.2.5 RFC 5652
		asn1::writer_t ori;
		// Открываем запись OtherRecipientInfo
		if(!ori.open(asn1::tag_t::SEQUENCE)){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем опознаватель сведений KEM
		if(!ori.oid(OID_ORI_KEM)){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Переносим запись KEMRecipientInfo как готовый элемент
		if(!embed(ori, recipient.data())){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Закрываем запись OtherRecipientInfo
		if(!ori.close()){
			// Выполняем затирание секретов
			nts::sys::wipe(kek, sizeof(kek));
			nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Собираем запись EnvelopedData: издание 2 у сведений OtherRecipientInfo
		outcome = buildEnveloped(ori, 2, content, cek, result);
	// Если памяти под итог не хватило
	} catch(const std::bad_alloc &) {
		// Выполняем затирание секретов
		nts::sys::wipe(kek, sizeof(kek));
		nts::sys::wipe(cek, sizeof(cek));
	// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выполняем затирание секретов
	nts::sys::wipe(kek, sizeof(kek));
	nts::sys::wipe(cek, sizeof(cek));
	// Выводим итог сборки
	return outcome;
}
/**
 * \~russian
 * @brief Метод расшифрования зашифрованного сообщения ключом RSA
 *
 * @param enveloped разобранное зашифрованное сообщение
 * @param key       секретный ключ RSA получателя
 * @param result    место, в которое помещается расшифрованное содержимое
 *
 * @return          отказ расшифрования
 *
 * \~english
 * @brief Method of the decryption of an enveloped message by an RSA key
 * @param enveloped the parsed enveloped message
 * @param key       the secret RSA key of the recipient
 * @param result    the place the decrypted content is put into
 * @return          the failure of the decryption
 *
 * \~
 */
nts::cms::error_t nts::cms::unenvelop(const enveloped_t & enveloped, const keys::key_t & key, vector <uint8_t> & result) noexcept {
	// Если ключ не RSA либо без секретной части
	if((key.kind != keys::kind_t::RSA) || !key.secret())
	// Выводим отказ ключа
		return error_t::KEY;
	// Если шифр содержимого не AES-CBC
	size_t bits = 0;
	// Определяем длину ключа шифра содержимого
	if(enveloped.algorithm() == OID_AES128_CBC) bits = 128;
	else if(enveloped.algorithm() == OID_AES192_CBC) bits = 192;
	else if(enveloped.algorithm() == OID_AES256_CBC) bits = 256;
	// Если шифр содержимого неизвестен
	if(bits == 0)
	// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Синхропосылка из настроек шифра содержимого
	view_t iv;
	{
		// Разборщик записи настроек
		asn1::reader_t settings(enveloped.parameters());
		// Элемент синхропосылки
		asn1::element_t element;
		// Если синхропосылку разобрать не удалось
		if(!settings.next(asn1::tag_t::OCTET_STRING, element))
		// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Запоминаем синхропосылку
		iv = element.content;
	}
	// Если синхропосылка негодна
	if(iv.size != BLOCK)
	// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Разыскиваем сведения KeyTrans
	const recipient_t * recipient = nullptr;
	// Проходим по набору получателей
	for(size_t i = 0; i < enveloped.recipients().size(); i++){
		// Если сведения вида RSA
		if(enveloped.recipients()[i].kind == recipient_t::kind_t::RSA){
			// Запоминаем сведения
			recipient = &enveloped.recipients()[i];
			// Поиск завершён
			break;
		}
	}
	// Если сведения KeyTrans не найдены
	if(recipient == nullptr)
	// Выводим отказ ключа
		return error_t::KEY;
	// Модуль RSA для расшифрования ключа
	sign::rsa_t rsa;
	// Если секретный ключ установить не удалось
	if(!rsa.key(view_t(key.n.data(), key.n.size()), view_t(key.e.data(), key.e.size()), view_t(key.d.data(), key.d.size()), view_t(key.p.data(), key.p.size()), view_t(key.q.data(), key.q.size()), view_t(key.dP.data(), key.dP.size()), view_t(key.dQ.data(), key.dQ.size()), view_t(key.qInv.data(), key.qInv.size())))
	// Выводим отказ ключа
		return error_t::KEY;
	// Ключ шифрования содержимого: место отводится по размеру модуля ключа
	uint8_t cek[512];
	// Длина расшифрованного ключа
	size_t size = sizeof(cek);
	// Если ключ расшифровать не удалось
	if(!rsa.decrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, recipient->encryptedKey, cek, size)){
		// Выполняем затирание ключа
		nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ ключа
		return error_t::KEY;
	}
	// Если длина ключа не отвечает шифру содержимого
	if(size != bits / 8){
		// Выполняем затирание ключа
		nts::sys::wipe(cek, sizeof(cek));
		// Выводим отказ ключа
		return error_t::KEY;
	}
	// Расшифровываем содержимое
	const error_t outcome = decryptContent(enveloped.content(), view_t(cek, size), iv, result);
	// Выполняем затирание ключа
	nts::sys::wipe(cek, sizeof(cek));
	// Выводим итог расшифрования
	return outcome;
}
/**
 * \~russian
 * @brief Метод расшифрования зашифрованного сообщения ключом ML-KEM
 *
 * @param enveloped разобранное зашифрованное сообщение
 * @param kem       набор параметров ML-KEM
 * @param secret    секретный ключ декапсуляции ML-KEM получателя
 * @param result    место, в которое помещается расшифрованное содержимое
 *
 * @return          отказ расшифрования
 *
 * \~english
 * @brief Method of the decryption of an enveloped message by an ML-KEM key
 * @param enveloped the parsed enveloped message
 * @param kem       the ML-KEM parameter set
 * @param secret    the ML-KEM decapsulation key of the recipient
 * @param result    the place the decrypted content is put into
 * @return          the failure of the decryption
 *
 * \~
 */
nts::cms::error_t nts::cms::unenvelop(const enveloped_t & enveloped, const agreement::kem_t kem, const view_t & secret, vector <uint8_t> & result) noexcept {
	// Если набор параметров неизвестен
	if(oidOf(kem) == nullptr)
	// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Если секретный ключ негоден
	if((secret.data == nullptr) || (secret.size != agreement::decapsulation(kem)))
	// Выводим отказ ключа
		return error_t::KEY;
	// Если шифр содержимого не AES-CBC
	size_t bits = 0;
	// Определяем длину ключа шифра содержимого
	if(enveloped.algorithm() == OID_AES128_CBC) bits = 128;
	else if(enveloped.algorithm() == OID_AES192_CBC) bits = 192;
	else if(enveloped.algorithm() == OID_AES256_CBC) bits = 256;
	// Если шифр содержимого неизвестен
	if(bits == 0)
	// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Синхропосылка из настроек шифра содержимого
	view_t iv;
	{
		// Разборщик записи настроек
		asn1::reader_t settings(enveloped.parameters());
		// Элемент синхропосылки
		asn1::element_t element;
		// Если синхропосылку разобрать не удалось
		if(!settings.next(asn1::tag_t::OCTET_STRING, element))
		// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Запоминаем синхропосылку
		iv = element.content;
	}
	// Если синхропосылка негодна
	if(iv.size != BLOCK)
	// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Разыскиваем сведения KEM
	const recipient_t * recipient = nullptr;
	// Проходим по набору получателей
	for(size_t i = 0; i < enveloped.recipients().size(); i++){
		// Если сведения вида KEM и набор параметров совпадает
		if((enveloped.recipients()[i].kind == recipient_t::kind_t::KEM) && (kemOf(enveloped.recipients()[i].kem) == kem)){
			// Запоминаем сведения
			recipient = &enveloped.recipients()[i];
			// Поиск завершён
			break;
		}
	}
	// Если сведения KEM не найдены
	if(recipient == nullptr)
	// Выводим отказ ключа
		return error_t::KEY;
	// Если алгоритм выработки ключа не HKDF-SHA-256
	if(recipient->kdf != OID_HKDF_SHA256)
	// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Если алгоритм защиты ключа не AES-KW
	size_t kekBits = 0;
	// Определяем длину ключа KEK
	if(recipient->wrap == OID_AES128_WRAP) kekBits = 128;
	else if(recipient->wrap == OID_AES192_WRAP) kekBits = 192;
	else if(recipient->wrap == OID_AES256_WRAP) kekBits = 256;
	// Если алгоритм защиты ключа неизвестен
	if(kekBits == 0)
	// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Если длина ключа KEK не отвечает алгоритму защиты
	if(recipient->kekLength != kekBits / 8)
	// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Если текст инкапсуляции негоден
	if(recipient->kemct.size != agreement::ciphertext(kem))
	// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Общий секрет декапсуляции
	uint8_t shared[agreement::MLKEM_SHARED];
	// Если декапсуляцию выполнить не удалось
	if(!agreement::decapsulate(kem, secret, recipient->kemct, shared)){
		// Выполняем затирание секрета
		nts::sys::wipe(shared, sizeof(shared));
		// Выводим отказ ключа
		return error_t::KEY;
	}
	// Ключ KEK
	uint8_t kek[32];
	// Вырабатываем ключ KEK по разделу 5 RFC 9629
	if(!deriveKek(view_t(shared, sizeof(shared)), recipient->wrap.c_str(), recipient->kekLength, kek)){
		// Выполняем затирание секрета
		nts::sys::wipe(shared, sizeof(shared));
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	}
	// Выполняем затирание общего секрета
	nts::sys::wipe(shared, sizeof(shared));
	// Ключ шифрования содержимого
	vector <uint8_t> cek;
	// Если ключ содержимого снять с защиты не удалось
	if(!aesUnwrap(view_t(kek, recipient->kekLength), recipient->encryptedKey, cek)){
		// Выполняем затирание ключа KEK
		nts::sys::wipe(kek, sizeof(kek));
		// Выводим отказ ключа
		return error_t::KEY;
	}
	// Выполняем затирание ключа KEK
	nts::sys::wipe(kek, sizeof(kek));
	// Если длина ключа не отвечает шифру содержимого
	if(cek.size() != bits / 8){
		// Выполняем затирание ключа
		if(!cek.empty())
			// Выполняем затирание ключа
			nts::sys::wipe(cek.data(), cek.size());
		// Выводим отказ ключа
		return error_t::KEY;
	}
	// Расшифровываем содержимое
	const error_t outcome = decryptContent(enveloped.content(), view_t(cek.data(), cek.size()), iv, result);
	// Выполняем затирание ключа
	if(!cek.empty())
		// Выполняем затирание ключа
		nts::sys::wipe(cek.data(), cek.size());
	// Выводим итог расшифрования
	return outcome;
}

/**
 * \~russian
 * @brief Конструктор
 *
 * \~english
 * @brief Constructor
 *
 * \~
 *
 */
nts::cms::Digested::Digested() noexcept : _error(error_t::NONE) {}
/**
 * \~russian
 * @brief Метод разбора записи ContentInfo вида id-digestedData
 *
 * @param data просмотр разбираемой записи
 * @return     причина отказа либо error_t::NONE
 *
 * \~english
 * @brief Method of parsing a ContentInfo record of the id-digestedData kind
 * @param data the view of the record being parsed
 * @return     the reason of the failure or error_t::NONE
 *
 * \~
 *
 */
nts::cms::error_t nts::cms::Digested::parse(const view_t & data) noexcept {
	// Очищаем разобранные сведения
	this->clear();
	// Если запись не установлена
	if(data.size == 0){
		// Запоминаем причину отказа
		this->_error = error_t::EMPTY;
		// Выводим причину отказа
		return this->_error;
	}
	// Опознаватель вида содержимого
	string kind;
	// Просмотр содержимого записи
	view_t body;
	// Если запись ContentInfo разобрать не удалось
	if(contentInfo(data, kind, body) != error_t::NONE){
		// Запоминаем причину отказа
		this->_error = error_t::STRUCTURE;
		// Выводим причину отказа
		return this->_error;
	}
	// Если вид содержимого не id-digestedData
	if(kind != OID_DIGESTED){
		// Запоминаем причину отказа
		this->_error = error_t::STRUCTURE;
		// Выводим причину отказа
		return this->_error;
	}
	/**
	 * Разбор сведений выделяет память: нехватка её отдаётся отказом, а не
	 * завершением процесса
	 */
	try {
		// Разборщик записи DigestedData
		asn1::reader_t reader(body);
		// Элемент записи DigestedData
		asn1::element_t digested;
		// Если запись разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, digested) || !digested.constructed){
			// Запоминаем причину отказа
			this->_error = translate(reader.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Разборщик содержимого записи
		asn1::reader_t items(digested.content);
		// Элемент издания
		asn1::element_t version;
		// Если издание разобрать не удалось
		if(!items.next(asn1::tag_t::INTEGER, version)){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Элемент записи алгоритма хеша
		asn1::element_t algorithm;
		// Если запись алгоритма разобрать не удалось
		if(!items.next(asn1::tag_t::SEQUENCE, algorithm)){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Просмотр настроек алгоритма
		view_t params;
		// Итог разбора записи алгоритма
		const error_t outcome = algorithmIdentifier(algorithm, this->_algorithm, params);
		// Если запись алгоритма разобрать не удалось
		if(outcome != error_t::NONE){
			// Запоминаем причину отказа
			this->_error = outcome;
			// Выводим причину отказа
			return this->_error;
		}
		// Элемент записи EncapsulatedContentInfo
		asn1::element_t encap;
		// Если запись разобрать не удалось
		if(!items.next(asn1::tag_t::SEQUENCE, encap) || !encap.constructed){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Разборщик содержимого EncapsulatedContentInfo
		asn1::reader_t fields(encap.content);
		// Элемент опознавателя вида содержимого
		asn1::element_t contentType;
		// Если опознаватель разобрать не удалось
		if(!fields.next(asn1::tag_t::OBJECT, contentType)){
			// Запоминаем причину отказа
			this->_error = translate(fields.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Элемент содержимого [0]
		asn1::element_t content;
		// Если содержимое разобрать не удалось
		if(!fields.next(content) || (content.cls != asn1::cls_t::CONTEXT) || (content.tag != 0)){
			// Запоминаем причину отказа
			this->_error = translate(fields.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Разборщик содержимого [0]
		asn1::reader_t inner(content.content);
		// Элемент строки байтов содержимого
		asn1::element_t octets;
		// Если строку байтов разобрать не удалось
		if(!inner.next(asn1::tag_t::OCTET_STRING, octets)){
			// Запоминаем причину отказа
			this->_error = translate(inner.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Запоминаем содержимое
		this->_content = octets.content;
		// Элемент хеша
		asn1::element_t digest;
		// Если хеш разобрать не удалось
		if(!items.next(asn1::tag_t::OCTET_STRING, digest)){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Запоминаем хеш
		this->_digest = digest.content;
	// Если памяти под сведения не хватило
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
 * \~russian
 * @brief Метод очистки разобранных сведений
 *
 * \~english
 * @brief Method of clearing the parsed info
 *
 * \~
 *
 */
void nts::cms::Digested::clear() noexcept {
	// Сбрасываем причину отказа
	this->_error = error_t::NONE;
	// Сбрасываем опознаватель алгоритма
	this->_algorithm.clear();
	// Сбрасываем просмотры
	this->_content = view_t();
	this->_digest = view_t();
}
/**
 * \~russian
 * @brief Метод извлечения причины последнего отказа
 *
 * @return причина последнего отказа
 *
 * \~english
 * @brief Method of getting the reason of the last failure
 * @return the reason of the last failure
 *
 * \~
 *
 */
nts::cms::error_t nts::cms::Digested::err() const noexcept {
	// Выводим причину последнего отказа
	return this->_error;
}
/**
 * \~russian
 * @brief Метод извлечения опознавателя алгоритма хеша
 *
 * @return опознаватель алгоритма хеша
 *
 * \~english
 * @brief Method of getting the hash algorithm identifier
 * @return the hash algorithm identifier
 *
 * \~
 *
 */
const std::string & nts::cms::Digested::algorithm() const noexcept {
	// Выводим опознаватель алгоритма хеша
	return this->_algorithm;
}
/**
 * \~russian
 * @brief Метод извлечения содержимого
 *
 * @return просмотр содержимого
 *
 * \~english
 * @brief Method of getting the content
 * @return the view of the content
 *
 * \~
 *
 */
const nts::view_t & nts::cms::Digested::content() const noexcept {
	// Выводим просмотр содержимого
	return this->_content;
}
/**
 * \~russian
 * @brief Метод извлечения хеша содержимого
 *
 * @return просмотр содержимого хеша
 *
 * \~english
 * @brief Method of getting the content digest
 * @return the view of the digest content
 *
 * \~
 *
 */
const nts::view_t & nts::cms::Digested::digest() const noexcept {
	// Выводим просмотр хеша
	return this->_digest;
}

/**
 * \~russian
 * @brief Конструктор
 *
 * \~english
 * @brief Constructor
 *
 * \~
 *
 */
nts::cms::Encrypted::Encrypted() noexcept : _error(error_t::NONE) {}
/**
 * \~russian
 * @brief Метод разбора записи ContentInfo вида id-encryptedData
 *
 * @param data просмотр разбираемой записи
 * @return     причина отказа либо error_t::NONE
 *
 * \~english
 * @brief Method of parsing a ContentInfo record of the id-encryptedData kind
 * @param data the view of the record being parsed
 * @return     the reason of the failure or error_t::NONE
 *
 * \~
 *
 */
nts::cms::error_t nts::cms::Encrypted::parse(const view_t & data) noexcept {
	// Очищаем разобранные сведения
	this->clear();
	// Если запись не установлена
	if(data.size == 0){
		// Запоминаем причину отказа
		this->_error = error_t::EMPTY;
		// Выводим причину отказа
		return this->_error;
	}
	// Опознаватель вида содержимого
	string kind;
	// Просмотр содержимого записи
	view_t body;
	// Если запись ContentInfo разобрать не удалось
	if(contentInfo(data, kind, body) != error_t::NONE){
		// Запоминаем причину отказа
		this->_error = error_t::STRUCTURE;
		// Выводим причину отказа
		return this->_error;
	}
	// Если вид содержимого не id-encryptedData
	if(kind != OID_ENCRYPTED){
		// Запоминаем причину отказа
		this->_error = error_t::STRUCTURE;
		// Выводим причину отказа
		return this->_error;
	}
	/**
	 * Разбор сведений выделяет память: нехватка её отдаётся отказом, а не
	 * завершением процесса
	 */
	try {
		// Разборщик записи EncryptedData
		asn1::reader_t reader(body);
		// Элемент записи EncryptedData
		asn1::element_t encrypted;
		// Если запись разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, encrypted) || !encrypted.constructed){
			// Запоминаем причину отказа
			this->_error = translate(reader.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Разборщик содержимого записи
		asn1::reader_t items(encrypted.content);
		// Элемент издания
		asn1::element_t version;
		// Если издание разобрать не удалось
		if(!items.next(asn1::tag_t::INTEGER, version)){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Элемент записи EncryptedContentInfo
		asn1::element_t encap;
		// Если запись разобрать не удалось
		if(!items.next(asn1::tag_t::SEQUENCE, encap) || !encap.constructed){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Разборщик содержимого EncryptedContentInfo
		asn1::reader_t fields(encap.content);
		// Элемент опознавателя вида содержимого
		asn1::element_t contentType;
		// Если опознаватель разобрать не удалось
		if(!fields.next(asn1::tag_t::OBJECT, contentType)){
			// Запоминаем причину отказа
			this->_error = translate(fields.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Элемент записи алгоритма шифрования
		asn1::element_t algorithm;
		// Если запись алгоритма разобрать не удалось
		if(!fields.next(asn1::tag_t::SEQUENCE, algorithm)){
			// Запоминаем причину отказа
			this->_error = translate(fields.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Итог разбора записи алгоритма
		const error_t outcome = algorithmIdentifier(algorithm, this->_algorithm, this->_parameters);
		// Если запись алгоритма разобрать не удалось
		if(outcome != error_t::NONE){
			// Запоминаем причину отказа
			this->_error = outcome;
			// Выводим причину отказа
			return this->_error;
		}
		// Элемент зашифрованного содержимого [0]
		asn1::element_t content;
		// Если содержимое разобрать не удалось
		if(!fields.next(content) || (content.cls != asn1::cls_t::CONTEXT) || (content.tag != 0)){
			// Запоминаем причину отказа
			this->_error = translate(fields.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Запоминаем зашифрованное содержимое
		this->_content = content.content;
	// Если памяти под сведения не хватило
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
 * \~russian
 * @brief Метод очистки разобранных сведений
 *
 * \~english
 * @brief Method of clearing the parsed info
 *
 * \~
 *
 */
void nts::cms::Encrypted::clear() noexcept {
	// Сбрасываем причину отказа
	this->_error = error_t::NONE;
	// Сбрасываем опознаватель алгоритма
	this->_algorithm.clear();
	// Сбрасываем просмотры
	this->_parameters = view_t();
	this->_content = view_t();
}
/**
 * \~russian
 * @brief Метод извлечения причины последнего отказа
 *
 * @return причина последнего отказа
 *
 * \~english
 * @brief Method of getting the reason of the last failure
 * @return the reason of the last failure
 *
 * \~
 *
 */
nts::cms::error_t nts::cms::Encrypted::err() const noexcept {
	// Выводим причину последнего отказа
	return this->_error;
}
/**
 * \~russian
 * @brief Метод извлечения опознавателя алгоритма шифрования
 *
 * @return опознаватель алгоритма шифрования содержимого
 *
 * \~english
 * @brief Method of getting the encryption algorithm identifier
 * @return the content encryption algorithm identifier
 *
 * \~
 *
 */
const std::string & nts::cms::Encrypted::algorithm() const noexcept {
	// Выводим опознаватель алгоритма шифрования
	return this->_algorithm;
}
/**
 * \~russian
 * @brief Метод извлечения настроек алгоритма шифрования
 *
 * @return просмотр записи настроек алгоритма (вектор инициализации)
 *
 * \~english
 * @brief Method of getting the encryption algorithm parameters
 * @return the view of the algorithm parameters record (the initialization vector)
 *
 * \~
 *
 */
const nts::view_t & nts::cms::Encrypted::parameters() const noexcept {
	// Выводим просмотр записи настроек
	return this->_parameters;
}
/**
 * \~russian
 * @brief Метод извлечения зашифрованного содержимого
 *
 * @return просмотр зашифрованного содержимого
 *
 * \~english
 * @brief Method of getting the encrypted content
 * @return the view of the encrypted content
 *
 * \~
 *
 */
const nts::view_t & nts::cms::Encrypted::content() const noexcept {
	// Выводим просмотр зашифрованного содержимого
	return this->_content;
}

/**
 * \~russian
 * @brief Конструктор
 *
 * \~english
 * @brief Constructor
 *
 * \~
 *
 */
nts::cms::Authenticated::Authenticated() noexcept : _error(error_t::NONE) {}
/**
 * \~russian
 * @brief Метод разбора записи ContentInfo вида id-authenticatedData
 *
 * @param data просмотр разбираемой записи
 * @return     причина отказа либо error_t::NONE
 *
 * \~english
 * @brief Method of parsing a ContentInfo record of the id-authenticatedData kind
 * @param data the view of the record being parsed
 * @return     the reason of the failure or error_t::NONE
 *
 * \~
 *
 */
nts::cms::error_t nts::cms::Authenticated::parse(const view_t & data) noexcept {
	// Очищаем разобранные сведения
	this->clear();
	// Если запись не установлена
	if(data.size == 0){
		// Запоминаем причину отказа
		this->_error = error_t::EMPTY;
		// Выводим причину отказа
		return this->_error;
	}
	// Опознаватель вида содержимого
	string kind;
	// Просмотр содержимого записи
	view_t body;
	// Если запись ContentInfo разобрать не удалось
	if(contentInfo(data, kind, body) != error_t::NONE){
		// Запоминаем причину отказа
		this->_error = error_t::STRUCTURE;
		// Выводим причину отказа
		return this->_error;
	}
	// Если вид содержимого не id-authenticatedData
	if(kind != OID_AUTHENTICATED){
		// Запоминаем причину отказа
		this->_error = error_t::STRUCTURE;
		// Выводим причину отказа
		return this->_error;
	}
	/**
	 * Разбор сведений выделяет память: нехватка её отдаётся отказом, а не
	 * завершением процесса
	 */
	try {
		// Разборщик записи AuthenticatedData
		asn1::reader_t reader(body);
		// Элемент записи AuthenticatedData
		asn1::element_t authenticated;
		// Если запись разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, authenticated) || !authenticated.constructed){
			// Запоминаем причину отказа
			this->_error = translate(reader.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Разборщик содержимого записи
		asn1::reader_t items(authenticated.content);
		// Элемент издания
		asn1::element_t version;
		// Если издание разобрать не удалось
		if(!items.next(asn1::tag_t::INTEGER, version)){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Элемент очередного поля
		asn1::element_t field;
		// Если поле разобрать не удалось
		if(!items.next(field)){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Если первое поле - originatorInfo [0]: пропускаем
		if((field.cls == asn1::cls_t::CONTEXT) && (field.tag == 0)){
			// Если поле recipientInfos разобрать не удалось
			if(!items.next(field)){
				// Запоминаем причину отказа
				this->_error = translate(items.err());
				// Выводим причину отказа
				return this->_error;
			}
		}
		// Если поле recipientInfos не набор
		if((field.cls != asn1::cls_t::UNIVERSAL) || (field.tag != static_cast <uint32_t> (asn1::tag_t::SET))){
			// Запоминаем причину отказа
			this->_error = error_t::STRUCTURE;
			// Выводим причину отказа
			return this->_error;
		}
		// Элемент записи алгоритма имитовставки
		asn1::element_t macAlgorithm;
		// Если запись алгоритма разобрать не удалось
		if(!items.next(asn1::tag_t::SEQUENCE, macAlgorithm)){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Просмотр настроек алгоритма имитовставки
		view_t params;
		// Итог разбора записи алгоритма
		const error_t outcome = algorithmIdentifier(macAlgorithm, this->_algorithm, params);
		// Если запись алгоритма разобрать не удалось
		if(outcome != error_t::NONE){
			// Запоминаем причину отказа
			this->_error = outcome;
			// Выводим причину отказа
			return this->_error;
		}
		// Элемент очередного поля
		asn1::element_t next;
		// Если поле разобрать не удалось
		if(!items.next(next)){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Если поле - digestAlgorithm [1]: пропускаем
		if((next.cls == asn1::cls_t::CONTEXT) && (next.tag == 1)){
			// Если поле encapContentInfo разобрать не удалось
			if(!items.next(next)){
				// Запоминаем причину отказа
				this->_error = translate(items.err());
				// Выводим причину отказа
				return this->_error;
			}
		}
		// Если поле encapContentInfo не набор
		if((next.cls != asn1::cls_t::UNIVERSAL) || (next.tag != static_cast <uint32_t> (asn1::tag_t::SEQUENCE))){
			// Запоминаем причину отказа
			this->_error = error_t::STRUCTURE;
			// Выводим причину отказа
			return this->_error;
		}
		// Разборщик содержимого EncapsulatedContentInfo
		asn1::reader_t fields(next.content);
		// Элемент опознавателя вида содержимого
		asn1::element_t contentType;
		// Если опознаватель разобрать не удалось
		if(!fields.next(asn1::tag_t::OBJECT, contentType)){
			// Запоминаем причину отказа
			this->_error = translate(fields.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Элемент содержимого [0]
		asn1::element_t content;
		// Если содержимое разобрать не удалось
		if(!fields.next(content) || (content.cls != asn1::cls_t::CONTEXT) || (content.tag != 0)){
			// Запоминаем причину отказа
			this->_error = translate(fields.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Разборщик содержимого [0]
		asn1::reader_t inner(content.content);
		// Элемент строки байтов содержимого
		asn1::element_t octets;
		// Если строку байтов разобрать не удалось
		if(!inner.next(asn1::tag_t::OCTET_STRING, octets)){
			// Запоминаем причину отказа
			this->_error = translate(inner.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Запоминаем содержимое
		this->_content = octets.content;
		// Элемент очередного поля: authAttrs [2] либо mac
		asn1::element_t mac;
		// Если поле разобрать не удалось
		if(!items.next(mac)){
			// Запоминаем причину отказа
			this->_error = translate(items.err());
			// Выводим причину отказа
			return this->_error;
		}
		// Если поле - authAttrs [2]: пропускаем, следующее - mac
		if((mac.cls == asn1::cls_t::CONTEXT) && (mac.tag == 2)){
			// Если поле mac разобрать не удалось
			if(!items.next(mac)){
				// Запоминаем причину отказа
				this->_error = translate(items.err());
				// Выводим причину отказа
				return this->_error;
			}
		}
		// Если поле mac не строка байтов
		if((mac.cls != asn1::cls_t::UNIVERSAL) || (mac.tag != static_cast <uint32_t> (asn1::tag_t::OCTET_STRING))){
			// Запоминаем причину отказа
			this->_error = error_t::STRUCTURE;
			// Выводим причину отказа
			return this->_error;
		}
		// Запоминаем имитовставку
		this->_mac = mac.content;
	// Если памяти под сведения не хватило
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
 * \~russian
 * @brief Метод очистки разобранных сведений
 *
 * \~english
 * @brief Method of clearing the parsed info
 *
 * \~
 *
 */
void nts::cms::Authenticated::clear() noexcept {
	// Сбрасываем причину отказа
	this->_error = error_t::NONE;
	// Сбрасываем опознаватель алгоритма
	this->_algorithm.clear();
	// Сбрасываем просмотры
	this->_content = view_t();
	this->_mac = view_t();
}
/**
 * \~russian
 * @brief Метод извлечения причины последнего отказа
 *
 * @return причина последнего отказа
 *
 * \~english
 * @brief Method of getting the reason of the last failure
 * @return the reason of the last failure
 *
 * \~
 *
 */
nts::cms::error_t nts::cms::Authenticated::err() const noexcept {
	// Выводим причину последнего отказа
	return this->_error;
}
/**
 * \~russian
 * @brief Метод извлечения опознавателя алгоритма имитовставки
 *
 * @return опознаватель алгоритма имитовставки
 *
 * \~english
 * @brief Method of getting the MAC algorithm identifier
 * @return the MAC algorithm identifier
 *
 * \~
 *
 */
const std::string & nts::cms::Authenticated::algorithm() const noexcept {
	// Выводим опознаватель алгоритма имитовставки
	return this->_algorithm;
}
/**
 * \~russian
 * @brief Метод извлечения содержимого
 *
 * @return просмотр содержимого
 *
 * \~english
 * @brief Method of getting the content
 * @return the view of the content
 *
 * \~
 *
 */
const nts::view_t & nts::cms::Authenticated::content() const noexcept {
	// Выводим просмотр содержимого
	return this->_content;
}
/**
 * \~russian
 * @brief Метод извлечения имитовставки
 *
 * @return просмотр содержимого имитовставки
 *
 * \~english
 * @brief Method of getting the MAC
 * @return the view of the MAC content
 *
 * \~
 *
 */
const nts::view_t & nts::cms::Authenticated::mac() const noexcept {
	// Выводим просмотр имитовставки
	return this->_mac;
}

/**
 * \~russian
 * @brief Метод сборки записи DigestedData
 *
 * @param content хешируемое содержимое
 * @param hash    алгоритм хеша
 * @param result  место, в которое помещается запись ContentInfo
 * @return        причина отказа либо error_t::NONE
 *
 * \~english
 * @brief Method of building a DigestedData record
 * @param content the content being digested
 * @param hash    the hashing algorithm
 * @param result  the place the ContentInfo record is put into
 * @return        the reason of the failure or error_t::NONE
 *
 * \~
 *
 */
nts::cms::error_t nts::cms::digest(const view_t & content, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Опознаватель алгоритма хеша
	const char * algorithm = oidOf(hash);
	// Если алгоритм хеша неизвестен
	if(algorithm == nullptr)
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Место, в которое помещается хеш содержимого
	uint8_t computed[64];
	// Если хеш содержимого выработать не удалось
	if(!digest::hash(hash, content, computed, sizeof(computed)))
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Записчик записи DigestedData
	asn1::writer_t digested;
	// Открываем запись DigestedData
	if(!digested.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем издание 0 (содержимое id-data)
	if(!digested.integer(0))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем алгоритм хеша с пустыми настройками
	if(!writeAlgorithm(digested, algorithm, true))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем EncapsulatedContentInfo
	{
		// Открываем запись EncapsulatedContentInfo
		if(!digested.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем опознаватель вида id-data
		if(!digested.oid(OID_DATA))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем содержимое под явной меткой [0]
		{
			// Записчик записи строки байтов
			asn1::writer_t octets;
			// Записываем содержимое строкой байтов
			if(!octets.octets(content))
				// Выводим отказ сборки
				return error_t::MEMORY;
			// Открываем явную метку [0]
			if(!digested.open(asn1::cls_t::CONTEXT, 0))
				// Выводим отказ сборки
				return error_t::MEMORY;
			// Переносим запись строки байтов
			if(!embed(digested, octets.data()))
				// Выводим отказ сборки
				return error_t::MEMORY;
			// Закрываем явную метку [0]
			if(!digested.close())
				// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Закрываем запись EncapsulatedContentInfo
		if(!digested.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Записываем хеш содержимого
	if(!digested.octets(view_t(computed, digest::length(hash))))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем запись DigestedData
	if(!digested.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записчик записи ContentInfo
	asn1::writer_t wrapper;
	// Открываем запись ContentInfo
	if(!wrapper.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем опознаватель вида id-digestedData
	if(!wrapper.oid(OID_DIGESTED))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем содержимое под явной меткой [0]
	{
		// Открываем явную метку [0]
		if(!wrapper.open(asn1::cls_t::CONTEXT, 0))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Переносим запись DigestedData
		if(!embed(wrapper, digested.data()))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем явную метку [0]
		if(!wrapper.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Закрываем запись ContentInfo
	if(!wrapper.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	/**
	 * Перенос записи выделяет память: нехватка её отдаётся отказом, а не
	 * завершением процесса
	 */
	try {
		// Переносим запись ContentInfo в итог
		result.assign(wrapper.data().data, wrapper.data().data + wrapper.data().size);
	// Если памяти под итог не хватило
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность сборки
	return error_t::NONE;
}
/**
 * \~russian
 * @brief Метод проверки записи DigestedData
 *
 * @param digested разобранная запись
 * @return         причина отказа либо error_t::NONE
 *
 * \~english
 * @brief Method of checking a DigestedData record
 * @param digested the parsed record
 * @return         the reason of the failure or error_t::NONE
 *
 * \~
 *
 */
nts::cms::error_t nts::cms::digestVerify(const digested_t & digested) noexcept {
	// Если запись не разобрана
	if(digested.algorithm().empty() || (digested.content().size == 0))
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Алгоритм хеша
	const digest::hash_t hash = hashOf(digested.algorithm());
	// Если алгоритм хеша неизвестен
	if(hash == digest::hash_t::NONE)
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Место, в которое помещается хеш содержимого
	uint8_t computed[64];
	// Если хеш содержимого выработать не удалось
	if(!digest::hash(hash, digested.content(), computed, sizeof(computed)))
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Длина хеша
	const size_t width = digest::length(hash);
	// Если длина хеша записи не та
	if(digested.digest().size != width)
		// Выводим отказ подписи
		return error_t::SIGNATURE;
	// Сверяем хеш с записанным в постоянном времени
	uint8_t difference = 0;
	// Перебираем байты хеша
	for(size_t i = 0; i < width; i++)
		// Накапливаем различие
		difference |= (computed[i] ^ static_cast <const uint8_t *> (digested.digest().data)[i]);
	// Выводим итог сверки
	return ((difference == 0) ? error_t::NONE : error_t::SIGNATURE);
}

/**
 * \~russian
 * @brief Метод сборки записи EncryptedData
 *
 * @param content  шифруемое содержимое
 * @param key      ключ шифрования содержимого (16/24/32 байта AES)
 * @param result   место, в которое помещается запись ContentInfo
 * @return         причина отказа либо error_t::NONE
 *
 * \~english
 * @brief Method of building an EncryptedData record
 * @param content  the content being encrypted
 * @param key      the content encryption key (16/24/32 bytes of AES)
 * @param result   the place the ContentInfo record is put into
 * @return         the reason of the failure or error_t::NONE
 *
 * \~
 *
 */
nts::cms::error_t nts::cms::encrypt(const view_t & content, const view_t & key, vector <uint8_t> & result) noexcept {
	// Если содержимое либо ключ не установлены
	if((content.size == 0) || (key.size == 0))
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Опознаватель алгоритма шифрования по длине ключа
	const char * algorithm = nullptr;
	/**
	 * Выполняем определение длины ключа
	 */
	switch(key.size){
		// AES-128
		case 16: algorithm = OID_AES128_CBC; break;
		// AES-192
		case 24: algorithm = OID_AES192_CBC; break;
		// AES-256
		case 32: algorithm = OID_AES256_CBC; break;
		// Ключ чужой длины
		default:
			// Выводим отказ ключа
			return error_t::KEY;
	}
	// Место, в которое помещается синхропосылка
	uint8_t iv[BLOCK];
	// Если синхропосылку выработать не удалось
	if(!entropy::bytes(iv, sizeof(iv)))
		// Выводим отказ случайности
		return error_t::RANDOM;
	// Место, в которое помещается шифротекст
	vector <uint8_t> encrypted;
	// Итог зашифрования содержимого
	const error_t outcome = encryptContent(content, key, view_t(iv, sizeof(iv)), encrypted);
	// Если содержимое зашифровать не удалось
	if(outcome != error_t::NONE){
		// Затираем синхропосылку
		nts::sys::wipe(iv, sizeof(iv));
		// Выводим отказ зашифрования
		return outcome;
	}
	// Записчик записи EncryptedData
	asn1::writer_t record;
	// Открываем запись EncryptedData
	if(!record.open(asn1::tag_t::SEQUENCE)){
		// Затираем синхропосылку
		nts::sys::wipe(iv, sizeof(iv));
		// Выводим отказ сборки
		return error_t::MEMORY;
	}
	// Записываем издание 0 (unprotectedAttrs нет)
	if(!record.integer(0)){
		// Затираем синхропосылку
		nts::sys::wipe(iv, sizeof(iv));
		// Выводим отказ сборки
		return error_t::MEMORY;
	}
	// Записываем EncryptedContentInfo
	{
		// Открываем запись EncryptedContentInfo
		if(!record.open(asn1::tag_t::SEQUENCE)){
			// Затираем синхропосылку
			nts::sys::wipe(iv, sizeof(iv));
			// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем опознаватель вида id-data
		if(!record.oid(OID_DATA)){
			// Затираем синхропосылку
			nts::sys::wipe(iv, sizeof(iv));
			// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Записываем алгоритм шифрования с синхропосылкой
		{
			// Открываем запись алгоритма
			if(!record.open(asn1::tag_t::SEQUENCE)){
				// Затираем синхропосылку
				nts::sys::wipe(iv, sizeof(iv));
				// Выводим отказ сборки
				return error_t::MEMORY;
			}
			// Записываем опознаватель алгоритма
			if(!record.oid(algorithm)){
				// Затираем синхропосылку
				nts::sys::wipe(iv, sizeof(iv));
				// Выводим отказ сборки
				return error_t::MEMORY;
			}
			// Записываем синхропосылку
			if(!record.octets(view_t(iv, sizeof(iv)))){
				// Затираем синхропосылку
				nts::sys::wipe(iv, sizeof(iv));
				// Выводим отказ сборки
				return error_t::MEMORY;
			}
			// Закрываем запись алгоритма
			if(!record.close()){
				// Затираем синхропосылку
				nts::sys::wipe(iv, sizeof(iv));
				// Выводим отказ сборки
				return error_t::MEMORY;
			}
		}
		// Записываем зашифрованное содержимое под неявной меткой [0] примитивной формы
		if(!record.element(asn1::cls_t::CONTEXT, false, 0, view_t(encrypted.data(), encrypted.size()))){
			// Затираем синхропосылку
			nts::sys::wipe(iv, sizeof(iv));
			// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Закрываем запись EncryptedContentInfo
		if(!record.close()){
			// Затираем синхропосылку
			nts::sys::wipe(iv, sizeof(iv));
			// Выводим отказ сборки
			return error_t::MEMORY;
		}
	}
	// Закрываем запись EncryptedData
	if(!record.close()){
		// Затираем синхропосылку
		nts::sys::wipe(iv, sizeof(iv));
		// Выводим отказ сборки
		return error_t::MEMORY;
	}
	// Записчик записи ContentInfo
	asn1::writer_t wrapper;
	// Открываем запись ContentInfo
	if(!wrapper.open(asn1::tag_t::SEQUENCE)){
		// Затираем синхропосылку
		nts::sys::wipe(iv, sizeof(iv));
		// Выводим отказ сборки
		return error_t::MEMORY;
	}
	// Записываем опознаватель вида id-encryptedData
	if(!wrapper.oid(OID_ENCRYPTED)){
		// Затираем синхропосылку
		nts::sys::wipe(iv, sizeof(iv));
		// Выводим отказ сборки
		return error_t::MEMORY;
	}
	// Записываем содержимое под явной меткой [0]
	{
		// Открываем явную метку [0]
		if(!wrapper.open(asn1::cls_t::CONTEXT, 0)){
			// Затираем синхропосылку
			nts::sys::wipe(iv, sizeof(iv));
			// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Переносим запись EncryptedData
		if(!embed(wrapper, record.data())){
			// Затираем синхропосылку
			nts::sys::wipe(iv, sizeof(iv));
			// Выводим отказ сборки
			return error_t::MEMORY;
		}
		// Закрываем явную метку [0]
		if(!wrapper.close()){
			// Затираем синхропосылку
			nts::sys::wipe(iv, sizeof(iv));
			// Выводим отказ сборки
			return error_t::MEMORY;
		}
	}
	// Закрываем запись ContentInfo
	if(!wrapper.close()){
		// Затираем синхропосылку
		nts::sys::wipe(iv, sizeof(iv));
		// Выводим отказ сборки
		return error_t::MEMORY;
	}
	// Затираем синхропосылку
	nts::sys::wipe(iv, sizeof(iv));
	/**
	 * Перенос записи выделяет память: нехватка её отдаётся отказом, а не
	 * завершением процесса
	 */
	try {
		// Переносим запись ContentInfo в итог
		result.assign(wrapper.data().data, wrapper.data().data + wrapper.data().size);
	// Если памяти под итог не хватило
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность сборки
	return error_t::NONE;
}
/**
 * \~russian
 * @brief Метод расшифрования записи EncryptedData
 *
 * @param encrypted разобранная запись
 * @param key       ключ шифрования содержимого
 * @param result    место, в которое помещается расшифрованное содержимое
 * @return          причина отказа либо error_t::NONE
 *
 * \~english
 * @brief Method of decrypting an EncryptedData record
 * @param encrypted the parsed record
 * @param key       the content encryption key
 * @param result    the place the decrypted content is put into
 * @return          the reason of the failure or error_t::NONE
 *
 * \~
 *
 */
nts::cms::error_t nts::cms::decrypt(const encrypted_t & encrypted, const view_t & key, vector <uint8_t> & result) noexcept {
	// Если запись не разобрана либо ключ не установлен
	if(encrypted.algorithm().empty() || (encrypted.content().size == 0) || (key.size == 0))
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Опознаватель алгоритма шифрования по длине ключа
	const char * algorithm = nullptr;
	/**
	 * Выполняем определение длины ключа
	 */
	switch(key.size){
		// AES-128
		case 16: algorithm = OID_AES128_CBC; break;
		// AES-192
		case 24: algorithm = OID_AES192_CBC; break;
		// AES-256
		case 32: algorithm = OID_AES256_CBC; break;
		// Ключ чужой длины
		default:
			// Выводим отказ ключа
			return error_t::KEY;
	}
	// Если алгоритм записи не отвечает ключу
	if(encrypted.algorithm() != algorithm)
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Разборщик записи настроек алгоритма (синхропосылка)
	asn1::reader_t reader(encrypted.parameters());
	// Элемент записи синхропосылки
	asn1::element_t iv;
	// Если запись синхропосылки разобрать не удалось
	if(!reader.next(asn1::tag_t::OCTET_STRING, iv))
		// Выводим переведённый отказ разбора
		return translate(reader.err());
	// Если длина синхропосылки не та
	if(iv.content.size != BLOCK)
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Расшифровываем содержимое
	return decryptContent(encrypted.content(), key, iv.content, result);
}

/**
 * \~russian
 * @brief Метод получения опознавателя имитовставки HMAC по алгоритму хеша
 *
 * @param hash алгоритм хеша
 *
 * @return     опознаватель алгоритма имитовставки либо nullptr
 *
 * \~english
 * @brief Method of getting the HMAC MAC identifier by the hashing algorithm
 * @param hash the hashing algorithm
 * @return     the MAC algorithm identifier or nullptr
 *
 * \~
 *
 */
static const char * cmsHmacOidOf(const digest::hash_t hash) noexcept {
	// Выводим опознаватель имитовставки по алгоритму хеша
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
 * \~russian
 * @brief Метод получения алгоритма хеша имитовставки по её опознавателю
 *
 * @param oid опознаватель алгоритма имитовставки HMAC
 *
 * @return    алгоритм хеша, hash_t::NONE у неизвестного
 *
 * \~english
 * @brief Method of getting the MAC hashing algorithm by its identifier
 * @param oid the HMAC MAC algorithm identifier
 * @return    the hashing algorithm, hash_t::NONE at an unknown one
 *
 * \~
 *
 */
static digest::hash_t cmsHmacOf(const string & oid) noexcept {
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
 * \~russian
 * @brief Метод сборки записи AuthenticatedData
 *
 * @param content  содержимое под имитовставку
 * @param key      ключ имитовставки
 * @param hash     алгоритм хеша имитовставки HMAC
 * @param result   место, в которое помещается запись ContentInfo
 * @return         причина отказа либо error_t::NONE
 *
 * \~english
 * @brief Method of building an AuthenticatedData record
 * @param content  the content being authenticated
 * @param key      the MAC key
 * @param hash     the hashing algorithm of the HMAC MAC
 * @param result   the place the ContentInfo record is put into
 * @return         the reason of the failure or error_t::NONE
 *
 * \~
 *
 */
nts::cms::error_t nts::cms::authenticate(const view_t & content, const view_t & key, const digest::hash_t hash, vector <uint8_t> & result) noexcept {
	// Если содержимое либо ключ не установлены
	if((content.size == 0) || (key.size == 0))
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Опознаватель алгоритма имитовставки
	const char * algorithm = cmsHmacOidOf(hash);
	// Если алгоритм имитовставки неизвестен
	if(algorithm == nullptr)
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Место, в которое помещается имитовставка
	uint8_t mac[64];
	// Если имитовставку выработать не удалось
	if(!digest::hmac(hash, key, content, mac, digest::length(hash)))
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Записчик записи AuthenticatedData
	asn1::writer_t record;
	// Открываем запись AuthenticatedData
	if(!record.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем издание 0
	if(!record.integer(0))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем набор recipientInfos: пустой набор (ключ вне записи)
	if(!record.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SET), view_t(nullptr, 0)))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем алгоритм имитовставки с пустыми настройками
	if(!writeAlgorithm(record, algorithm, true))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем EncapsulatedContentInfo
	{
		// Открываем запись EncapsulatedContentInfo
		if(!record.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем опознаватель вида id-data
		if(!record.oid(OID_DATA))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Записываем содержимое под явной меткой [0]
		{
			// Записчик записи строки байтов
			asn1::writer_t octets;
			// Записываем содержимое строкой байтов
			if(!octets.octets(content))
				// Выводим отказ сборки
				return error_t::MEMORY;
			// Открываем явную метку [0]
			if(!record.open(asn1::cls_t::CONTEXT, 0))
				// Выводим отказ сборки
				return error_t::MEMORY;
			// Переносим запись строки байтов
			if(!embed(record, octets.data()))
				// Выводим отказ сборки
				return error_t::MEMORY;
			// Закрываем явную метку [0]
			if(!record.close())
				// Выводим отказ сборки
				return error_t::MEMORY;
		}
		// Закрываем запись EncapsulatedContentInfo
		if(!record.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Записываем имитовставку
	if(!record.octets(view_t(mac, digest::length(hash))))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Закрываем запись AuthenticatedData
	if(!record.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записчик записи ContentInfo
	asn1::writer_t wrapper;
	// Открываем запись ContentInfo
	if(!wrapper.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем опознаватель вида id-authenticatedData
	if(!wrapper.oid(OID_AUTHENTICATED))
		// Выводим отказ сборки
		return error_t::MEMORY;
	// Записываем содержимое под явной меткой [0]
	{
		// Открываем явную метку [0]
		if(!wrapper.open(asn1::cls_t::CONTEXT, 0))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Переносим запись AuthenticatedData
		if(!embed(wrapper, record.data()))
			// Выводим отказ сборки
			return error_t::MEMORY;
		// Закрываем явную метку [0]
		if(!wrapper.close())
			// Выводим отказ сборки
			return error_t::MEMORY;
	}
	// Закрываем запись ContentInfo
	if(!wrapper.close())
		// Выводим отказ сборки
		return error_t::MEMORY;
	/**
	 * Перенос записи выделяет память: нехватка её отдаётся отказом, а не
	 * завершением процесса
	 */
	try {
		// Переносим запись ContentInfo в итог
		result.assign(wrapper.data().data, wrapper.data().data + wrapper.data().size);
	// Если памяти под итог не хватило
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим успешность сборки
	return error_t::NONE;
}
/**
 * \~russian
 * @brief Метод проверки записи AuthenticatedData
 *
 * @param authenticated разобранная запись
 * @param key           ключ имитовставки
 * @return              причина отказа либо error_t::NONE
 *
 * \~english
 * @brief Method of checking an AuthenticatedData record
 * @param authenticated the parsed record
 * @param key           the MAC key
 * @return              the reason of the failure or error_t::NONE
 *
 * \~
 *
 */
nts::cms::error_t nts::cms::authenticateVerify(const authenticated_t & authenticated, const view_t & key) noexcept {
	// Если запись не разобрана либо ключ не установлен
	if(authenticated.algorithm().empty() || (authenticated.content().size == 0) || (key.size == 0))
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Алгоритм хеша имитовставки
	const digest::hash_t hash = cmsHmacOf(authenticated.algorithm());
	// Если алгоритм имитовставки неизвестен
	if(hash == digest::hash_t::NONE)
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Место, в которое помещается имитовставка
	uint8_t mac[64];
	// Длина имитовставки
	const size_t width = digest::length(hash);
	// Если имитовставку выработать не удалось
	if(!digest::hmac(hash, key, authenticated.content(), mac, width))
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Если длина имитовставки записи не та
	if(authenticated.mac().size != width)
		// Выводим отказ подписи
		return error_t::SIGNATURE;
	// Сверяем имитовставку с записанной в постоянном времени
	uint8_t difference = 0;
	// Перебираем байты имитовставки
	for(size_t i = 0; i < width; i++)
		// Накапливаем различие
		difference |= (mac[i] ^ static_cast <const uint8_t *> (authenticated.mac().data)[i]);
	// Выводим итог сверки
	return ((difference == 0) ? error_t::NONE : error_t::SIGNATURE);
}
