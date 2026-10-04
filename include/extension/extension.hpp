/**
 * @file extension.hpp
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
 * \~russian
 * @brief Заголовочный файл модуля расширений приветствий протокола TLS — разбор и
 *        составление тел расширений, которыми стороны договариваются об условиях связи
 *
 * \~english
 * @brief Header file of the module of the extensions of the greetings of the TLS protocol —
 *        the parsing and the composition of the bodies of the extensions, by which the parties
 *        agree upon the conditions of the connection
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_EXTENSION__
#define __ANTS_EXTENSION__

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <digest/hash.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён расширений приветствий протокола TLS
	 *
	 * @details Раздел 4.2 RFC 8446: издание TLS 1.3 вынесло в расширения всё, чем оно
	 *          отличается от предыдущих изданий, - и выбор издания, и обмен ключами, и
	 *          схемы подписи. Тело всякого расширения разбирается по своему разделу и от
	 *          тел остальных не зависит.
	 *
	 * @note Одно и то же расширение у клиента и у сервера сложено по-разному: клиент
	 *       предлагает перечень, сервер выбирает из него одно. Оттого у таких расширений
	 *       здесь по два разборщика, а не один
	 *
	 * \~english
	 * @brief Namespace of the extensions of the greetings of the TLS protocol
	 * @details The section 4.2 of RFC 8446: the TLS 1.3 edition has moved into the extensions
	 *          everything by which it differs from the previous editions — the choice of the edition,
	 *          the exchange of the keys and the signature schemes. The body of every extension is
	 *          parsed by its own section and does not depend on the bodies of the rest.
	 * @note One and the same extension is composed differently at the client and at the server: the
	 *       client offers a list, the server chooses one from it. Hence such extensions have two
	 *       parsers here and not one
	 *
	 * \~
	 */
	namespace extension {
		/**
		 * \~russian
		 * @brief Виды расширений приветствий
		 *
		 * @details Раздел 4.2 RFC 8446: перечисление ExtensionType
		 *
		 * \~english
		 * @brief Types of the extensions of the greetings
		 * @details The section 4.2 of RFC 8446: the ExtensionType enumeration
		 *
		 * \~
		 */
		enum class type_t : uint16_t {
			NAME      = 0x0000, /*!< \~russian Имя запрашиваемого узла \~english The name of the requested host \~ */
			FRAGMENT  = 0x0001, /*!< \~russian Наибольшая длина открытого содержимого записи по разделу 4 RFC 6066 (max_fragment_length) \~english The greatest length of the plaintext content of a record by the section 4 of RFC 6066 (max_fragment_length) \~ */
			STATUS    = 0x0005, /*!< \~russian Запрос состояния сертификата OCSP (RFC 6066, раздел 4.4.2.1 RFC 8446) \~english The request of the certificate status OCSP (RFC 6066, the section 4.4.2.1 of RFC 8446) \~ */
			GROUPS    = 0x000A, /*!< \~russian Поддерживаемые группы обмена ключами \~english The supported groups of the exchange of the keys \~ */
			CLIENT_CERT_TYPE = 0x0013, /*!< \~russian Вид сертификата клиента client_certificate_type (RFC 7250) \~english The certificate type of the client client_certificate_type (RFC 7250) \~ */
			SERVER_CERT_TYPE = 0x0014, /*!< \~russian Вид сертификата сервера server_certificate_type (RFC 7250) \~english The certificate type of the server server_certificate_type (RFC 7250) \~ */
			FORMATS   = 0x000B, /*!< \~russian Записи точек кривой ec_point_formats (раздел 5.1.2 RFC 8422, TLS 1.2) \~english The ec_point_formats of the points of a curve (the section 5.1.2 of RFC 8422, TLS 1.2) \~ */
			SCHEMES   = 0x000D, /*!< \~russian Поддерживаемые схемы подписи \~english The supported signature schemes \~ */
			PROTOCOLS = 0x0010, /*!< \~russian Перечень прикладных протоколов связи \~english The list of the application protocols of a connection \~ */
			ETM       = 0x0016, /*!< \~russian Порядок «шифрование, затем имитовставка» encrypt_then_mac (RFC 7366, TLS 1.2) \~english The encrypt_then_mac order (RFC 7366, TLS 1.2) \~ */
			MASTER    = 0x0017, /*!< \~russian Расширенный главный секрет extended_master_secret (RFC 7627, TLS 1.2) \~english The extended_master_secret (RFC 7627, TLS 1.2) \~ */
			TICKET    = 0x0023, /*!< \~russian Билет сеанса session_ticket (RFC 5077, TLS 1.2) \~english The session_ticket (RFC 5077, TLS 1.2) \~ */
			COMPRESS  = 0x001B, /*!< \~russian Перечень алгоритмов сжатия цепочки сертификатов (RFC 8879) \~english The list of the algorithms of the compression of the chain of the certificates (RFC 8879) \~ */
			LIMIT     = 0x001C, /*!< \~russian Предел длины принимаемой записи по RFC 8449 (record_size_limit) \~english The limit of the length of a record being received by RFC 8449 (record_size_limit) \~ */
			TIMESTAMPS = 0x0012, /*!< \~russian Метки времени подписанного сертификата signed_certificate_timestamp (RFC 6962, раздел 4.4.2.1 RFC 8446) \~english The signed_certificate_timestamp (RFC 6962, the section 4.4.2.1 of RFC 8446) \~ */
			SECRET    = 0x0029, /*!< \~russian Заранее разделённый ключ \~english The pre-shared key \~ */
			EARLY     = 0x002A, /*!< \~russian Упреждающие данные связи \~english The early data of a connection \~ */
			COOKIE    = 0x002C, /*!< \~russian Метка возврата состояния сервера \~english The label of the return of the state of the server \~ */
			AUTHORITIES = 0x002F, /*!< \~russian Перечень доверенных удостоверяющих центров certificate_authorities (раздел 4.2.4 RFC 8446) \~english The certificate_authorities (the section 4.2.4 of RFC 8446) \~ */
			VERSIONS  = 0x002B, /*!< \~russian Поддерживаемые издания протокола \~english The supported editions of the protocol \~ */
			MODES     = 0x002D, /*!< \~russian Способы обмена с заранее разделённым ключом \~english The modes of the exchange with a pre-shared key \~ */
			SHARE     = 0x0033, /*!< \~russian Открытая часть ключа обмена \~english The public part of the key of the exchange \~ */
			SETTINGS_OLD = 0x4469, /*!< \~russian Прикладные настройки ALPS прежней точкой кода (draft-vvv-tls-alps, 17513) \~english The application settings ALPS by the former code point (draft-vvv-tls-alps, 17513) \~ */
			SETTINGS  = 0x44CD, /*!< \~russian Прикладные настройки ALPS новой точкой кода (draft-vvv-tls-alps, 17613) \~english The application settings ALPS by the new code point (draft-vvv-tls-alps, 17613) \~ */
			NEGOTIATION = 0x3374, /*!< \~russian Выработка следующего протокола next_protocol_negotiation (draft-agl-tls-nextprotoneg, TLS 1.2) \~english The next_protocol_negotiation (draft-agl-tls-nextprotoneg, TLS 1.2) \~ */
			RENEGOTIATION = 0xFF01 /*!< \~russian Признак безопасного пересогласования renegotiation_info (RFC 5746, TLS 1.2) \~english The renegotiation_info (RFC 5746, TLS 1.2) \~ */
		};

		/**
		 * \~russian
		 * @brief Группы обмена ключами
		 *
		 * @details Раздел 6.1 описания наборов шифрования TLS 1.3 на алгоритмах ГОСТ и
		 *          раздел 4.2.7 RFC 8446: перечисление NamedGroup
		 *
		 * @note Значения, здесь не перечисленные, в перечнях встречной стороны пропускаются
		 *       молча (RFC 8701); своё такое значение потребитель вправе вставить в перечень
		 *       снаружи, и доля ключа под него шлётся произвольной
		 *
		 * \~english
		 * @brief Groups of the exchange of the keys
		 * @details The section 6.1 of the description of the cipher suites of TLS 1.3 on the GOST
		 *          algorithms and the section 4.2.7 of RFC 8446: the NamedGroup enumeration
		 * @note The values not listed here are skipped silently in the lists of the peer (RFC 8701);
		 *       the consumer may insert its own such value into the list from the outside, and the
		 *       key share for it is sent arbitrary
		 *
		 * \~
		 */
		enum class group_t : uint16_t {
			NONE   = 0x0000, /*!< \~russian Группа обмена ключами не установлена \~english The group of the exchange of the keys is not set \~ */
			GC256A = 0x0022, /*!< \~russian Кривая набора параметров A длиной 256 разрядов \~english The curve of the parameter set A of a length of 256 bits \~ */
			GC256B = 0x0023, /*!< \~russian Кривая набора параметров A издания 2001 года \~english The curve of the parameter set A of the 2001 edition \~ */
			GC256C = 0x0024, /*!< \~russian Кривая набора параметров B издания 2001 года \~english The curve of the parameter set B of the 2001 edition \~ */
			GC256D = 0x0025, /*!< \~russian Кривая набора параметров C издания 2001 года \~english The curve of the parameter set C of the 2001 edition \~ */
			GC512A = 0x0026, /*!< \~russian Кривая набора параметров A длиной 512 разрядов \~english The curve of the parameter set A of a length of 512 bits \~ */
			GC512B = 0x0027, /*!< \~russian Кривая набора параметров B длиной 512 разрядов \~english The curve of the parameter set B of a length of 512 bits \~ */
			GC512C = 0x0028, /*!< \~russian Кривая набора параметров C длиной 512 разрядов \~english The curve of the parameter set C of a length of 512 bits \~ */
			SECP256R1 = 0x0017, /*!< \~russian Кривая secp256r1 (NIST P-256) по разделу 4.2.7 RFC 8446 \~english The secp256r1 (NIST P-256) curve by the section 4.2.7 of RFC 8446 \~ */
			SECP384R1 = 0x0018, /*!< \~russian Кривая secp384r1 (NIST P-384) по разделу 4.2.7 RFC 8446 \~english The secp384r1 (NIST P-384) curve by the section 4.2.7 of RFC 8446 \~ */
			X25519    = 0x001D, /*!< \~russian Кривая Curve25519 по RFC 7748 \~english The Curve25519 curve by RFC 7748 \~ */
			X448      = 0x001E, /*!< \~russian Кривая Curve448 по RFC 7748 \~english The Curve448 curve by RFC 7748 \~ */
			SECP521R1 = 0x0019, /*!< \~russian Кривая secp521r1 (NIST P-521) по разделу 4.2.7 RFC 8446 \~english The secp521r1 (NIST P-521) curve by the section 4.2.7 of RFC 8446 \~ */
			SECP256K1 = 0x0016, /*!< \~russian Кривая secp256k1 по RFC 8422: лишь TLS 1.2, изданием 1.3 не допускается \~english The secp256k1 curve by RFC 8422: TLS 1.2 only, not allowed by the edition 1.3 \~ */
			FFDHE2048 = 0x0100, /*!< \~russian Группа конечного поля ffdhe2048 по RFC 7919 \~english The ffdhe2048 finite field group by RFC 7919 \~ */
			FFDHE3072 = 0x0101, /*!< \~russian Группа конечного поля ffdhe3072 по RFC 7919 \~english The ffdhe3072 finite field group by RFC 7919 \~ */
			FFDHE4096 = 0x0102, /*!< \~russian Группа конечного поля ffdhe4096 по RFC 7919 \~english The ffdhe4096 finite field group by RFC 7919 \~ */
			FFDHE6144 = 0x0103, /*!< \~russian Группа конечного поля ffdhe6144 по RFC 7919 \~english The ffdhe6144 finite field group by RFC 7919 \~ */
			FFDHE8192 = 0x0104, /*!< \~russian Группа конечного поля ffdhe8192 по RFC 7919 \~english The ffdhe8192 finite field group by RFC 7919 \~ */
			SECP256R1MLKEM768 = 0x11EB, /*!< \~russian Гибрид secp256r1 и ML-KEM-768 по draft-ietf-tls-ecdhe-mlkem: доля кривой впереди \~english The hybrid of secp256r1 and ML-KEM-768 by draft-ietf-tls-ecdhe-mlkem: the curve share goes first \~ */
			X25519MLKEM768 = 0x11EC, /*!< \~russian Гибрид X25519 и ML-KEM-768 по draft-ietf-tls-ecdhe-mlkem \~english The hybrid of X25519 and ML-KEM-768 by draft-ietf-tls-ecdhe-mlkem \~ */
			SECP384R1MLKEM1024 = 0x11ED /*!< \~russian Гибрид secp384r1 и ML-KEM-1024 по draft-ietf-tls-ecdhe-mlkem: доля кривой впереди \~english The hybrid of secp384r1 and ML-KEM-1024 by draft-ietf-tls-ecdhe-mlkem: the curve share goes first \~ */
		};
		/**
		 * \~russian
		 * @brief Метод проверки принадлежности группы гибридам с инкапсуляцией ключа
		 *
		 * @details У гибридных групп доли сторон различны: клиент шлёт ключ инкапсуляции
		 *          с открытым ключом кривой, сервер отвечает шифртекстом с открытым ключом
		 *          кривой; изданию TLS 1.2 такие группы негодны
		 *
		 * @param group проверяемая группа обмена ключами
		 *
		 * @return      признак того, что группа есть гибрид с инкапсуляцией ключа
		 *
		 * \~english
		 * @brief Method of the check of the belonging of a group to the hybrids with a key encapsulation
		 *
		 * @details At the hybrid groups the shares of the sides differ: the client sends the
		 *          encapsulation key with the public key of the curve, the server answers by the
		 *          ciphertext with the public key of the curve; such groups are unfit for TLS 1.2
		 *
		 * @param group group of the exchange of the keys to check
		 *
		 * @return      sign that the group is a hybrid with a key encapsulation
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool hybrid(const group_t group) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения длины модуля группы конечного поля RFC 7919
		 * @param group проверяемая группа обмена ключами
		 * @return      длина модуля в байтах: 256 … 1024 у ffdhe2048 … ffdhe8192, ноль у прочих групп
		 * \~english
		 * @brief Method of getting the length of the modulus of a finite field group of RFC 7919
		 * @param group the group of the exchange of the keys being checked
		 * @return      the length of the modulus in bytes: 256 … 1024 at ffdhe2048 … ffdhe8192, zero at the other groups
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t finite(const group_t group) noexcept;

		/**
		 * \~russian
		 * @brief Схемы подписи
		 *
		 * @details Раздел 5 описания наборов шифрования TLS 1.3 на алгоритмах ГОСТ:
		 *          перечисление SignatureScheme
		 *
		 * \~english
		 * @brief Signature schemes
		 * @details The section 5 of the description of the cipher suites of TLS 1.3 on the GOST
		 *          algorithms: the SignatureScheme enumeration
		 *
		 * \~
		 */
		enum class scheme_t : uint16_t {
			NONE = 0x0000, /*!< \~russian Схема подписи не установлена \~english The signature scheme is not set \~ */
			S256A = 0x0709, /*!< \~russian Подпись на кривой GC256A \~english The signature on the GC256A curve \~ */
			S256B = 0x070A, /*!< \~russian Подпись на кривой GC256B \~english The signature on the GC256B curve \~ */
			S256C = 0x070B, /*!< \~russian Подпись на кривой GC256C \~english The signature on the GC256C curve \~ */
			S256D = 0x070C, /*!< \~russian Подпись на кривой GC256D \~english The signature on the GC256D curve \~ */
			S512A = 0x070D, /*!< \~russian Подпись на кривой GC512A \~english The signature on the GC512A curve \~ */
			S512B = 0x070E, /*!< \~russian Подпись на кривой GC512B \~english The signature on the GC512B curve \~ */
			S512C = 0x070F, /*!< \~russian Подпись на кривой GC512C \~english The signature on the GC512C curve \~ */
			RSA_PKCS1_SHA256       = 0x0401, /*!< \~russian Подпись RSASSA-PKCS1-v1_5 с хешем SHA-256 (TLS 1.2, раздел 7.4.1.4.1 RFC 5246) \~english The RSASSA-PKCS1-v1_5 signature with the SHA-256 hash (TLS 1.2, the section 7.4.1.4.1 of RFC 5246) \~ */
			ECDSA_SECP256R1_SHA256 = 0x0403, /*!< \~russian Подпись ECDSA на кривой secp256r1 с хешем SHA-256 \~english The ECDSA signature on the secp256r1 curve with the SHA-256 hash \~ */
			RSA_PKCS1_SHA384       = 0x0501, /*!< \~russian Подпись RSASSA-PKCS1-v1_5 с хешем SHA-384 (TLS 1.2) \~english The RSASSA-PKCS1-v1_5 signature with the SHA-384 hash (TLS 1.2) \~ */
			ECDSA_SECP384R1_SHA384 = 0x0503, /*!< \~russian Подпись ECDSA на кривой secp384r1 с хешем SHA-384 \~english The ECDSA signature on the secp384r1 curve with the SHA-384 hash \~ */
			RSA_PKCS1_SHA512       = 0x0601, /*!< \~russian Подпись RSASSA-PKCS1-v1_5 с хешем SHA-512 (TLS 1.2) \~english The RSASSA-PKCS1-v1_5 signature with the SHA-512 hash (TLS 1.2) \~ */
			ECDSA_SECP521R1_SHA512 = 0x0603, /*!< \~russian Подпись ECDSA на кривой secp521r1 с хешем SHA-512 \~english The ECDSA signature on the secp521r1 curve with the SHA-512 hash \~ */
			RSA_PSS_RSAE_SHA256    = 0x0804, /*!< \~russian Подпись RSASSA-PSS ключом rsaEncryption с хешем SHA-256 \~english The RSASSA-PSS signature by an rsaEncryption key with the SHA-256 hash \~ */
			RSA_PSS_RSAE_SHA384    = 0x0805, /*!< \~russian Подпись RSASSA-PSS ключом rsaEncryption с хешем SHA-384 \~english The RSASSA-PSS signature by an rsaEncryption key with the SHA-384 hash \~ */
			RSA_PSS_RSAE_SHA512    = 0x0806, /*!< \~russian Подпись RSASSA-PSS ключом rsaEncryption с хешем SHA-512 \~english The RSASSA-PSS signature by an rsaEncryption key with the SHA-512 hash \~ */
			ED25519                = 0x0807, /*!< \~russian Подпись Ed25519 по RFC 8032 \~english The Ed25519 signature by RFC 8032 \~ */
			MLDSA44                = 0x0904, /*!< \~russian Подпись ML-DSA-44 по FIPS 204 (draft-ietf-tls-mldsa-06) \~english The ML-DSA-44 signature by FIPS 204 (draft-ietf-tls-mldsa-06) \~ */
			MLDSA65                = 0x0905, /*!< \~russian Подпись ML-DSA-65 по FIPS 204 (draft-ietf-tls-mldsa-06) \~english The ML-DSA-65 signature by FIPS 204 (draft-ietf-tls-mldsa-06) \~ */
			MLDSA87                = 0x0906  /*!< \~russian Подпись ML-DSA-87 по FIPS 204 (draft-ietf-tls-mldsa-06) \~english The ML-DSA-87 signature by FIPS 204 (draft-ietf-tls-mldsa-06) \~ */
		};

		/**
		 * \~russian
		 * @brief Алгоритмы сжатия цепочки сертификатов
		 *
		 * @details Раздел 3 RFC 8879: перечисление CertificateCompressionAlgorithm. Сами
		 *          алгоритмы библиотека не несёт: их вызовы предоставляет потребитель, а
		 *          здесь названы лишь опознаватели реестра. Значения 16384…65535 отведены
		 *          частным алгоритмам и передаются числом
		 *
		 * @note Значения, встречной стороной объявленные и связи неведомые, пропускаются
		 *       молча: сжатие идёт лишь по алгоритму, который есть у обеих сторон
		 *
		 * \~english
		 * @brief Algorithms of the compression of the chain of the certificates
		 * @details The section 3 of RFC 8879: the CertificateCompressionAlgorithm enumeration. The
		 *          library does not carry the algorithms themselves: their calls are provided by the
		 *          consumer, and only the identifiers of the registry are named here. The values
		 *          16384…65535 are reserved for the private algorithms and are passed as a number
		 * @note The values announced by the peer and unknown to the connection are skipped silently:
		 *       the compression goes only by an algorithm which both sides have
		 *
		 * \~
		 */
		enum class compression_t : uint16_t {
			NONE   = 0x0000, /*!< \~russian Сжатия нет \~english There is no compression \~ */
			ZLIB   = 0x0001, /*!< \~russian Сжатие zlib по RFC 1950 \~english The zlib compression by RFC 1950 \~ */
			BROTLI = 0x0002, /*!< \~russian Сжатие Brotli по RFC 7932 \~english The Brotli compression by RFC 7932 \~ */
			ZSTD   = 0x0003  /*!< \~russian Сжатие Zstandard по RFC 8878 \~english The Zstandard compression by RFC 8878 \~ */
		};

		/**
		 * \~russian
		 * @brief Способы обмена с заранее разделённым ключом
		 *
		 * @details Раздел 4.2.9 RFC 8446: перечисление PskKeyExchangeMode
		 *
		 * \~english
		 * @brief Modes of the exchange with a pre-shared key
		 * @details The section 4.2.9 of RFC 8446: the PskKeyExchangeMode enumeration
		 *
		 * \~
		 */
		enum class regime_t : uint8_t {
			SECRET = 0x00, /*!< \~russian Обмен одним заранее разделённым ключом \~english The exchange by a pre-shared key alone \~ */
			SHARED = 0x01  /*!< \~russian Обмен заранее разделённым ключом вместе с ключом кривой \~english The exchange by a pre-shared key together with a key of a curve \~ */
		};

		/**
		 * \~russian
		 * @brief Виды сертификатов по RFC 7250
		 *
		 * @details Раздел 4.1 RFC 7250: перечисление CertificateType
		 *
		 * \~english
		 * @brief Certificate types by RFC 7250
		 * @details The section 4.1 of RFC 7250: the CertificateType enumeration
		 *
		 * \~
		 */
		enum class cert_t : uint8_t {
			X509  = 0x00, /*!< \~russian Сертификат X.509 \~english The X.509 certificate \~ */
			RAW   = 0x01  /*!< \~russian Сырой открытый ключ RawPublicKey \~english The raw public key RawPublicKey \~ */
		};

		/**
		 * \~russian
		 * @brief Отказы разбора и составления тел расширений
		 *
		 * \~english
		 * @brief Failures of the parsing and of the composition of the bodies of the extensions
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE     = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			HUNGRY   = 0x01, /*!< \~russian Тело расширения оборвано посреди поля \~english The body of the extension is cut off in the middle of a field \~ */
			EMPTY    = 0x02, /*!< \~russian Перечень тела расширения пуст \~english The list of the body of the extension is empty \~ */
			TRAILING = 0x03, /*!< \~russian За телом расширения идут лишние байты \~english There are extra bytes behind the body of the extension \~ */
			LENGTH   = 0x04, /*!< \~russian Составляемое поле в свою длину не входит \~english A field being composed does not fit into its length \~ */
			MEMORY   = 0x05, /*!< \~russian Памяти под итог не хватило \~english There was not enough memory for the outcome \~ */
			FORMAT   = 0x06  /*!< \~russian Поле негодного вида: имя узла с байтом вне печатаемого ASCII либо с точкой на конце (раздел 3 RFC 6066) \~english A field of an unfit form: a host name with a byte outside the printable ASCII or with a trailing dot (the section 3 of RFC 6066) \~ */
		};

		/**
		 * \~russian
		 * @brief Открытая часть ключа обмена одной группы
		 *
		 * @details Раздел 4.2.8 RFC 8446: запись KeyShareEntry
		 *
		 * @note Открытая часть ключа смотрит внутрь разобранного тела расширения
		 *
		 * \~english
		 * @brief Public part of the key of the exchange of a single group
		 * @details The section 4.2.8 of RFC 8446: the KeyShareEntry record
		 * @note The public part of the key looks inside the parsed body of the extension
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Share {
			// Группа обмена ключами, которой принадлежит открытая часть ключа
			group_t group;
			// Открытая часть ключа обмена
			view_t key;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Share() noexcept : group(group_t::NONE) {}
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param group группа обмена ключами
			 * @param key   открытая часть ключа обмена
			 *
			 * \~english
			 * @brief Constructor
			 * @param group the group of the exchange of the keys
			 * @param key   the public part of the key of the exchange
			 *
			 * \~
			 */
			Share(const group_t group, const view_t & key) noexcept : group(group), key(key) {}
		} share_t;

		/**
		 * \~russian
		 * @brief Опознаватель заранее разделённого ключа
		 *
		 * @details Раздел 4.2.11 RFC 8446: опознавателем ключа клиент предъявляет билет,
		 *          выданный сервером прошлой связи, а добавка к возрасту скрывает от
		 *          посторонних, давно ли билет выдан
		 *
		 * @note Опознаватель смотрит внутрь разобранного тела расширения
		 *
		 * \~english
		 * @brief Identifier of a pre-shared key
		 * @details The section 4.2.11 of RFC 8446: by the identifier of a key the client presents the
		 *          ticket issued by the server of a past connection, and the addition to the age hides
		 *          from the outsiders how long ago the ticket was issued
		 * @note The identifier looks inside the parsed body of the extension
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Identity {
			// Опознаватель заранее разделённого ключа
			view_t identity;
			// Скрытый возраст билета, выдавшего ключ
			uint32_t age;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Identity() noexcept : age(0) {}
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param identity опознаватель заранее разделённого ключа
			 * @param age      скрытый возраст билета, выдавшего ключ
			 *
			 * \~english
			 * @brief Constructor
			 * @param identity the identifier of the pre-shared key
			 * @param age      the hidden age of the ticket which issued the key
			 *
			 * \~
			 */
			Identity(const view_t & identity, const uint32_t age) noexcept : identity(identity), age(age) {}
		} identity_t;

		/**
		 * \~russian
		 * @brief Метод получения опознавателя кривой группы обмена ключами
		 *
		 * @param group группа обмена ключами
		 *
		 * @return      опознаватель кривой набора параметров либо nullptr
		 *
		 * @details Раздел 6.1 описания наборов: всякая группа обмена ключами есть кривая, и
		 *          опознаватель её набора параметров тот же, что и в сертификатах. У группы
		 *          X25519 отдаётся опознаватель ключа RFC 8410: кривая её в наборы параметров
		 *          не входит, и обмен по ней ведётся своим примитивом
		 *
		 * \~english
		 * @brief Method of getting the identifier of the curve of a group of the exchange of the keys
		 * @param group the group of the exchange of the keys
		 * @return      the identifier of the curve of the parameter set or nullptr
		 * @details The section 6.1 of the description of the suites: every group of the exchange of the
		 *          keys is a curve, and the identifier of its parameter set is the same as in the
		 *          certificates. At the X25519 group the identifier of the key of RFC 8410 is given: its
		 *          curve does not enter the parameter sets, and the exchange over it is conducted by its
		 *          own primitive
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ const char * curve(const group_t group) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения опознавателя кривой схемы подписи
		 *
		 * @param scheme схема подписи
		 *
		 * @return       опознаватель кривой набора параметров либо nullptr
		 *
		 * @details Раздел 5.2 описания наборов: схема подписи задаёт кривую наравне с
		 *          алгоритмом подписи
		 *
		 * \~english
		 * @brief Method of getting the identifier of the curve of a signature scheme
		 * @param scheme the signature scheme
		 * @return       the identifier of the curve of the parameter set or nullptr
		 * @details The section 5.2 of the description of the suites: a signature scheme sets the curve
		 *          on a par with the algorithm of the signature
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ const char * curve(const scheme_t scheme) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения длины ключа схемы подписи
		 *
		 * @param scheme схема подписи
		 *
		 * @return       длина ключа подписи в байтах, ноль у неизвестной схемы
		 *
		 * \~english
		 * @brief Method of getting the length of the key of a signature scheme
		 * @param scheme the signature scheme
		 * @return       the length of the key of the signature in bytes, a zero at an unknown scheme
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t length(const scheme_t scheme) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения длины доли ключа группы обмена ключами
		 *
		 * @param group группа обмена ключами
		 *
		 * @return      длина доли ключа в байтах, ноль у неизвестной группы
		 *
		 * @details Раздел 4.2.8.2 RFC 8446: у кривых NIST доля есть несжатая точка
		 *          0x04||X||Y, у X25519 - тридцать два байта; у групп ГОСТ доля есть две
		 *          координаты точки в обратном порядке байтов
		 *
		 * \~english
		 * @brief Method of getting the length of the key share of a group of the exchange of the keys
		 * @param group the group of the exchange of the keys
		 * @return      the length of the key share in bytes, a zero at an unknown group
		 * @details The section 4.2.8.2 of RFC 8446: at the NIST curves the share is the uncompressed
		 *          point 0x04||X||Y, at X25519 it is thirty two bytes; at the GOST groups the share is
		 *          two coordinates of a point in the reversed order of the bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t length(const group_t group) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения хеша схемы подписи
		 *
		 * @param scheme схема подписи
		 *
		 * @return       хеш, которым берётся подписываемое содержимое, NONE у Ed25519 и у неизвестной схемы
		 *
		 * @details Раздел 4.2.3 RFC 8446: хеш назван самой схемой; у схем ГОСТ он равен
		 *          «Стрибогу» длиною в ключ, у Ed25519 хеша вне подписи нет
		 *
		 * \~english
		 * @brief Method of getting the hash of a signature scheme
		 * @param scheme the signature scheme
		 * @return       the hash the content being signed is taken by, NONE at Ed25519 and at an unknown scheme
		 * @details The section 4.2.3 of RFC 8446: the hash is named by the scheme itself; at the GOST
		 *          schemes it equals «Streebog» of the length of the key, at Ed25519 there is no hash
		 *          outside the signature
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ digest::hash_t hash(const scheme_t scheme) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня поддерживаемых изданий протокола
		 *
		 * @param data   разбираемое тело расширения приветствия клиента
		 * @param result перечень, в который помещаются поддерживаемые издания протокола
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.1 RFC 8446
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the supported editions of the protocol
		 * @param data   the body of the extension of the greeting of the client being parsed
		 * @param result the list the supported editions of the protocol are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.1 of RFC 8446
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t versions(const view_t & data, vector <uint16_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня поддерживаемых изданий протокола
		 *
		 * @param versions составляемый перечень поддерживаемых изданий протокола
		 * @param result   накопитель, в конец которого дописывается тело расширения
		 *
		 * @return         отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the supported editions of the protocol
		 * @param versions the list of the supported editions of the protocol being composed
		 * @param result   the accumulator the body of the extension is appended to the end of
		 * @return         the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t versions(const vector <uint16_t> & versions, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора выбранного издания протокола
		 *
		 * @param data   разбираемое тело расширения приветствия сервера
		 * @param result число, в которое помещается выбранное издание протокола
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.1 RFC 8446: сервер отвечает единственным изданием без перечня
		 *
		 * \~english
		 * @brief Method of the parsing of the chosen edition of the protocol
		 * @param data   the body of the extension of the greeting of the server being parsed
		 * @param result the number the chosen edition of the protocol is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.1 of RFC 8446: the server answers with a single edition without a list
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t version(const view_t & data, uint16_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления выбранного издания протокола
		 *
		 * @param version составляемое выбранное издание протокола
		 * @param result  накопитель, в конец которого дописывается тело расширения
		 *
		 * @return        отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the chosen edition of the protocol
		 * @param version the chosen edition of the protocol being composed
		 * @param result  the accumulator the body of the extension is appended to the end of
		 * @return        the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t version(const uint16_t version, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня поддерживаемых групп обмена ключами
		 *
		 * @param data   разбираемое тело расширения
		 * @param result перечень, в который помещаются поддерживаемые группы
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.7 RFC 8446
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the supported groups of the exchange of the keys
		 * @param data   the body of the extension being parsed
		 * @param result the list the supported groups are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.7 of RFC 8446
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t groups(const view_t & data, vector <group_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня поддерживаемых групп обмена ключами
		 *
		 * @param groups составляемый перечень поддерживаемых групп
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the supported groups of the exchange of the keys
		 * @param groups the list of the supported groups being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t groups(const vector <group_t> & groups, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня поддерживаемых схем подписи
		 *
		 * @param data   разбираемое тело расширения
		 * @param result перечень, в который помещаются поддерживаемые схемы подписи
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.3 RFC 8446
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the supported signature schemes
		 * @param data   the body of the extension being parsed
		 * @param result the list the supported signature schemes are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.3 of RFC 8446
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t schemes(const view_t & data, vector <scheme_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня поддерживаемых схем подписи
		 *
		 * @param schemes составляемый перечень поддерживаемых схем подписи
		 * @param result  накопитель, в конец которого дописывается тело расширения
		 *
		 * @return        отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the supported signature schemes
		 * @param schemes the list of the supported signature schemes being composed
		 * @param result  the accumulator the body of the extension is appended to the end of
		 * @return        the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t schemes(const vector <scheme_t> & schemes, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня видов сертификатов certificate_type
		 *
		 * @param data   разбираемое тело расширения
		 * @param result перечень, в который помещаются объявленные виды
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.1 RFC 7250: перечень с однобайтовой длиной и однобайтовыми
		 *          записями, непустой и без лишних байтов
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the certificate types certificate_type
		 * @param data   the body of the extension being parsed
		 * @param result the list the announced types are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.1 of RFC 7250: a list with a one-byte length and one-byte entries,
		 *          non-empty and without trailing bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t certtypes(const view_t & data, vector <cert_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня видов сертификатов certificate_type
		 *
		 * @param types  составляемый перечень видов сертификатов
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the certificate types certificate_type
		 * @param types  the list of the certificate types being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t certtypes(const vector <cert_t> & types, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня записей точек кривой ec_point_formats
		 *
		 * @param data   разбираемое тело расширения
		 * @param result перечень, в который помещаются объявленные записи точек
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 5.1.2 RFC 8422: перечень с однобайтовой длиной и однобайтовыми
		 *          записями, непустой и без лишних байтов; несжатая запись uncompressed(0)
		 *          обязательна всякой стороне, и её наличие сверяет вызывающий
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the ec_point_formats of the points of a curve
		 * @param data   the body of the extension being parsed
		 * @param result the list the announced formats of the points are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 5.1.2 of RFC 8422: a list with a one-byte length and one-byte entries,
		 *          non-empty and without trailing bytes; the uncompressed(0) format is mandatory for
		 *          every side, and its presence is checked by the caller
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t formats(const view_t & data, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня записей точек кривой ec_point_formats
		 *
		 * @param formats составляемый перечень записей точек
		 * @param result  накопитель, в конец которого дописывается тело расширения
		 *
		 * @return        отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the ec_point_formats of the points of a curve
		 * @param formats the list of the formats of the points being composed
		 * @param result  the accumulator the body of the extension is appended to the end of
		 * @return        the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t formats(const vector <uint8_t> & formats, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня открытых частей ключей обмена
		 *
		 * @param data   разбираемое тело расширения приветствия клиента
		 * @param result перечень, в который помещаются открытые части ключей обмена
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.8 RFC 8446: клиент вправе предложить открытые части ключей
		 *          сразу нескольких групп, а вправе не предложить ни одной
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the public parts of the keys of the exchange
		 * @param data   the body of the extension of the greeting of the client being parsed
		 * @param result the list the public parts of the keys of the exchange are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.8 of RFC 8446: the client may offer the public parts of the keys of
		 *          several groups at once, and may offer none at all
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t shares(const view_t & data, vector <share_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня открытых частей ключей обмена
		 *
		 * @param shares составляемый перечень открытых частей ключей обмена
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the public parts of the keys of the exchange
		 * @param shares the list of the public parts of the keys of the exchange being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t shares(const vector <share_t> & shares, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора открытой части ключа обмена сервера
		 *
		 * @param data   разбираемое тело расширения приветствия сервера
		 * @param result запись, в которую помещается открытая часть ключа обмена
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.8 RFC 8446: сервер отвечает единственной открытой частью ключа
		 *          без перечня
		 *
		 * \~english
		 * @brief Method of the parsing of the public part of the key of the exchange of the server
		 * @param data   the body of the extension of the greeting of the server being parsed
		 * @param result the record the public part of the key of the exchange is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.8 of RFC 8446: the server answers with a single public part of a key
		 *          without a list
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t share(const view_t & data, share_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления открытой части ключа обмена сервера
		 *
		 * @param share  составляемая открытая часть ключа обмена
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the public part of the key of the exchange of the server
		 * @param share  the public part of the key of the exchange being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t share(const share_t & share, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора выбранной сервером группы обмена ключами
		 *
		 * @param data   разбираемое тело расширения просьбы о повторе приветствия
		 * @param result группа, в которую помещается выбранная сервером группа обмена
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.8 RFC 8446: просьбой о повторе приветствия сервер называет ту
		 *          группу, открытой части ключа которой он от клиента не дождался
		 *
		 * \~english
		 * @brief Method of the parsing of the group of the exchange of the keys chosen by the server
		 * @param data   the body of the extension of the request of a repetition of the greeting being parsed
		 * @param result the group the group of the exchange chosen by the server is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.8 of RFC 8446: by a request of a repetition of the greeting the server
		 *          names the group the public part of the key of which it did not receive from the client
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t selected(const view_t & data, group_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления выбранной сервером группы обмена ключами
		 *
		 * @param group  составляемая выбранная группа обмена ключами
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the group of the exchange of the keys chosen by the server
		 * @param group  the chosen group of the exchange of the keys being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t selected(const group_t group, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня способов обмена с заранее разделённым ключом
		 *
		 * @param data   разбираемое тело расширения
		 * @param result перечень, в который помещаются способы обмена
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.9 RFC 8446
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the modes of the exchange with a pre-shared key
		 * @param data   the body of the extension being parsed
		 * @param result the list the modes of the exchange are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.9 of RFC 8446
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t modes(const view_t & data, vector <regime_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня способов обмена с заранее разделённым ключом
		 *
		 * @param modes  составляемый перечень способов обмена
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the modes of the exchange with a pre-shared key
		 * @param modes  the list of the modes of the exchange being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t modes(const vector <regime_t> & modes, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора метки возврата состояния сервера
		 *
		 * @param data   разбираемое тело расширения
		 * @param result просмотр, в который помещается метка возврата состояния
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.2 RFC 8446: меткой сервер возвращает себе своё состояние, не
		 *          храня его у себя между приветствиями
		 *
		 * \~english
		 * @brief Method of the parsing of the label of the return of the state of the server
		 * @param data   the body of the extension being parsed
		 * @param result the view the label of the return of the state is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.2 of RFC 8446: by the label the server returns its state to itself
		 *          without storing it at itself between the greetings
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t cookie(const view_t & data, view_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления метки возврата состояния сервера
		 *
		 * @param cookie составляемая метка возврата состояния
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the label of the return of the state of the server
		 * @param cookie the label of the return of the state being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t cookie(const view_t & cookie, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора имени запрашиваемого узла
		 *
		 * @param data   разбираемое тело расширения
		 * @param result просмотр, в который помещается имя запрашиваемого узла
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 3 RFC 6066: перечень имён узлов, из которого протокол дозволяет
		 *          лишь имя вида «host_name», и лишь одно
		 *
		 * \~english
		 * @brief Method of the parsing of the name of the requested host
		 * @param data   the body of the extension being parsed
		 * @param result the view the name of the requested host is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 3 of RFC 6066: a list of the names of the hosts, of which the protocol
		 *          allows only a name of the «host_name» kind, and only one
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t name(const view_t & data, view_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления имени запрашиваемого узла
		 *
		 * @param name   составляемое имя запрашиваемого узла
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the name of the requested host
		 * @param name   the name of the requested host being composed
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t name(const view_t & name, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня прикладных протоколов
		 *
		 * @param data   разбираемое тело расширения
		 * @param result перечень, в который помещаются названия прикладных протоколов
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 3.1 RFC 7301: перечень названий прикладных протоколов, идущий от
		 *          более желаемого протокола к менее желаемому
		 *
		 * @note Пустое название протокола разделом 3.1 RFC 7301 запрещено и даёт отказ
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the application protocols
		 * @param data   the body of the extension being parsed
		 * @param result the list the names of the application protocols are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 3.1 of RFC 7301: a list of the names of the application protocols going
		 *          from a more desired protocol to a less desired one
		 * @note An empty name of a protocol is forbidden by the section 3.1 of RFC 7301 and gives a failure
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t protocols(const view_t & data, vector <string> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня прикладных протоколов
		 *
		 * @param protocols составляемый перечень названий прикладных протоколов
		 * @param result    накопитель, в конец которого дописывается тело расширения
		 *
		 * @return          отказ составления тела расширения
		 *
		 * @note Порядок перечня значим: он объявляет предпочтение стороны связи
		 *
		 * \~english
		 * @brief Method of the composition of the list of the application protocols
		 * @param protocols the list of the names of the application protocols being composed
		 * @param result    the accumulator the body of the extension is appended to the end of
		 * @return          the failure of the composition of the body of the extension
		 * @note The order of the list is significant: it declares the preference of the side of the connection
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t protocols(const vector <string> & protocols, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора выбранного прикладного протокола
		 *
		 * @param data   разбираемое тело расширения
		 * @param result название, в которое помещается выбранный прикладной протокол
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 3.1 RFC 7301: сервер отвечает тем же перечнем, но кладёт в него
		 *          ровно один протокол — тот, которым связь и пойдёт
		 *
		 * \~english
		 * @brief Method of the parsing of the chosen application protocol
		 * @param data   the body of the extension being parsed
		 * @param result the name the chosen application protocol is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 3.1 of RFC 7301: the server answers by the same list but puts exactly
		 *          one protocol into it — the one the connection will go by
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t protocol(const view_t & data, string & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления выбранного прикладного протокола
		 *
		 * @param protocol составляемое название выбранного прикладного протокола
		 * @param result   накопитель, в конец которого дописывается тело расширения
		 *
		 * @return         отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the chosen application protocol
		 * @param protocol the name of the chosen application protocol being composed
		 * @param result   the accumulator the body of the extension is appended to the end of
		 * @return         the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t protocol(const string & protocol, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора предложения заранее разделённых ключей
		 *
		 * @param data       разбираемое тело расширения приветствия клиента
		 * @param result     перечень, в который помещаются опознаватели ключей
		 * @param binders    перечень, в который помещаются привязки ключей
		 * @param truncation место, в которое помещается длина приветствия без привязок
		 *
		 * @return           отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.11.2 RFC 8446: привязка всякого ключа берётся от приветствия,
		 *          усечённого перед перечнем привязок, и длина этого усечения выводится здесь
		 *          же - иначе её пришлось бы искать разбором приветствия заново
		 *
		 * @note Длина усечения выводится от начала разбираемого тела расширения: чтобы
		 *       получить её от начала сообщения, к ней прибавляется место тела в сообщении
		 *
		 * \~english
		 * @brief Method of the parsing of an offer of the pre-shared keys
		 * @param data       the body of the extension of the greeting of the client being parsed
		 * @param result     the list the identifiers of the keys are put into
		 * @param binders    the list the binders of the keys are put into
		 * @param truncation the place the length of the greeting without the binders is put into
		 * @return           the failure of the parsing of the body of the extension
		 * @details The section 4.2.11.2 of RFC 8446: the binder of every key is taken from the greeting
		 *          truncated before the list of the binders, and the length of this truncation is output
		 *          here as well — otherwise it would have to be searched for by parsing the greeting anew
		 * @note The length of the truncation is output from the beginning of the parsed body of the
		 *       extension: to get it from the beginning of the message the place of the body in the
		 *       message is added to it
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t identities(const view_t & data, vector <identity_t> & result, vector <view_t> & binders, size_t & truncation) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления предложения заранее разделённых ключей
		 *
		 * @param identities составляемый перечень опознавателей ключей
		 * @param binders    составляемый перечень привязок ключей
		 * @param result     накопитель, в конец которого дописывается тело расширения
		 *
		 * @return           отказ составления тела расширения
		 *
		 * @note Число привязок обязано совпадать с числом опознавателей: всякому ключу
		 *       отвечает своя привязка, и разошедшиеся перечни сервер отвергнет
		 *
		 * \~english
		 * @brief Method of the composition of an offer of the pre-shared keys
		 * @param identities the list of the identifiers of the keys being composed
		 * @param binders    the list of the binders of the keys being composed
		 * @param result     the accumulator the body of the extension is appended to the end of
		 * @return           the failure of the composition of the body of the extension
		 * @note The number of the binders is obliged to coincide with the number of the identifiers: every
		 *       key corresponds to its own binder, and the server will reject the diverged lists
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t identities(const vector <identity_t> & identities, const vector <view_t> & binders, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора выбранного сервером заранее разделённого ключа
		 *
		 * @param data   разбираемое тело расширения приветствия сервера
		 * @param result место, в которое помещается место выбранного ключа в предложении
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * \~english
		 * @brief Method of the parsing of the pre-shared key chosen by the server
		 * @param data   the body of the extension of the greeting of the server being parsed
		 * @param result the place the position of the chosen key in the offer is put into
		 * @return       the failure of the parsing of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t chosen(const view_t & data, uint16_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления выбранного сервером заранее разделённого ключа
		 *
		 * @param chosen место выбранного ключа в предложении клиента
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the pre-shared key chosen by the server
		 * @param chosen the position of the chosen key in the offer of the client
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t chosen(const uint16_t chosen, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора предела упреждающих данных билета
		 *
		 * @param data   разбираемое тело расширения билета возобновления связи
		 * @param result место, в которое помещается предел упреждающих данных в байтах
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.10 RFC 8446: пределом сервер объявляет, сколько упреждающих
		 *          данных он примет по этому билету. В приветствии же и в защищённых
		 *          расширениях тело этого расширения пусто.
		 *
		 * \~english
		 * @brief Method of the parsing of the limit of the early data of a ticket
		 * @param data   the body of the extension of the ticket of the resumption being parsed
		 * @param result the place the limit of the early data in bytes is put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.10 of RFC 8446: by the limit the server declares how much early data it
		 *          will accept by this ticket. In a greeting and in the encrypted extensions the body of this
		 *          extension is empty.
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t early(const view_t & data, uint32_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления предела упреждающих данных билета
		 *
		 * @param limit  объявляемый предел упреждающих данных в байтах
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the limit of the early data of a ticket
		 * @param limit  the limit of the early data in bytes being declared
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t early(const uint32_t limit, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня меток времени подписанного сертификата
		 *
		 * @param data   разбираемое тело расширения signed_certificate_timestamp
		 * @param result накопитель, в конец которого дописываются записи перечня как есть
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 3.3 RFC 6962: SignedCertificateTimestampList - перечень записей с
		 *          двухбайтовыми длинами; ни перечень, ни запись пустыми быть не вправе.
		 *          Сама запись (издание, журнал, миг, подпись) здесь не толкуется
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the signed certificate timestamps
		 * @param data   the body of the signed_certificate_timestamp extension being parsed
		 * @param result the accumulator the entries of the list are appended to as they are
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 3.3 of RFC 6962: SignedCertificateTimestampList - a list of entries with
		 *          two-byte lengths; neither the list nor an entry may be empty. The entry itself (the
		 *          version, the log, the moment, the signature) is not interpreted here
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t timestamps(const view_t & data, vector <vector <uint8_t>> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня меток времени подписанного сертификата
		 *
		 * @param entries записи перечня как есть
		 * @param result  накопитель, в конец которого дописывается тело расширения
		 *
		 * @return        отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the signed certificate timestamps
		 * @param entries the entries of the list as they are
		 * @param result  the accumulator the body of the extension is appended to the end of
		 * @return        the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t timestamps(const vector <vector <uint8_t>> & entries, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня доверенных удостоверяющих центров
		 *
		 * @param data   разбираемое тело расширения certificate_authorities
		 * @param result накопитель, в конец которого дописываются имена как записаны (DER X.501 Name)
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 4.2.4 RFC 8446: перечень имён с двухбайтовыми длинами; ни перечень, ни
		 *          имя пустыми быть не вправе, а имя есть DER-запись SEQUENCE. Само имя здесь не
		 *          толкуется - его разбирает x509
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the trusted certificate authorities
		 * @param data   the body of the certificate_authorities extension being parsed
		 * @param result the accumulator the names are appended to as they are written (DER X.501 Name)
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 4.2.4 of RFC 8446: a list of names with two-byte lengths; neither the list
		 *          nor a name may be empty, and a name is a DER SEQUENCE record. The name itself is not
		 *          interpreted here - x509 parses it
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t authorities(const view_t & data, vector <vector <uint8_t>> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня доверенных удостоверяющих центров
		 *
		 * @param names  имена как записаны (DER X.501 Name)
		 * @param result накопитель, в конец которого дописывается тело расширения
		 *
		 * @return       отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the trusted certificate authorities
		 * @param names  the names as they are written (DER X.501 Name)
		 * @param result the accumulator the body of the extension is appended to the end of
		 * @return       the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t authorities(const vector <vector <uint8_t>> & names, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня протоколов выработки NPN, объявленного сервером
		 *
		 * @param data   разбираемое тело расширения next_protocol_negotiation приветствия сервера
		 * @param result накопитель, в конец которого дописываются названия протоколов
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Черновик draft-agl-tls-nextprotoneg: имена идут подряд с однобайтовыми
		 *          длинами без внешней длины; пустое имя запрещено, пустой перечень дозволен
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the NPN protocols declared by the server
		 * @param data   the body of the next_protocol_negotiation extension of the server hello being parsed
		 * @param result the accumulator the names of the protocols are appended to
		 * @return       the failure of the parsing of the body of the extension
		 * @details The draft-agl-tls-nextprotoneg: the names go one after another with one-byte lengths
		 *          without an outer length; an empty name is forbidden, an empty list is allowed
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t negotiation(const view_t & data, vector <string> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня протоколов выработки NPN
		 *
		 * @param protocols названия протоколов
		 * @param result    накопитель, в конец которого дописывается тело расширения
		 *
		 * @return          отказ составления тела расширения
		 *
		 * \~english
		 * @brief Method of the composition of the list of the NPN protocols
		 * @param protocols the names of the protocols
		 * @param result    the accumulator the body of the extension is appended to the end of
		 * @return          the failure of the composition of the body of the extension
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t negotiation(const vector <string> & protocols, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора перечня алгоритмов сжатия цепочки сертификатов
		 *
		 * @param data   разбираемое тело расширения
		 * @param result перечень, в который помещаются опознаватели алгоритмов
		 *
		 * @return       отказ разбора тела расширения
		 *
		 * @details Раздел 3 RFC 8879: перечень идёт с однобайтовой длиной впереди, всякий
		 *          опознаватель занимает два байта; пустой перечень отвергается
		 *
		 * @note Опознаватели выдаются числом и в порядке объявления: неведомые значения
		 *       здесь не отсеиваются, их пропускает тот, кто перечень сличает со своим
		 *
		 * \~english
		 * @brief Method of the parsing of the list of the algorithms of the compression of the chain of the certificates
		 * @param data   the body of the extension being parsed
		 * @param result the list the identifiers of the algorithms are put into
		 * @return       the failure of the parsing of the body of the extension
		 * @details The section 3 of RFC 8879: the list goes with a one-byte length in front, every
		 *          identifier occupies two bytes; an empty list is rejected
		 * @note The identifiers are given out as numbers and in the order of the announcement: the
		 *       unknown values are not sifted out here, they are skipped by the one who compares the
		 *       list with its own
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t algorithms(const view_t & data, vector <uint16_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод составления перечня алгоритмов сжатия цепочки сертификатов
		 *
		 * @param algorithms составляемый перечень опознавателей алгоритмов
		 * @param result     накопитель, в конец которого дописывается тело расширения
		 *
		 * @return           отказ составления тела расширения
		 *
		 * @note Перечень не пересортировывается: порядок его есть порядок предпочтения
		 *       потребителя, и по нему встречная сторона выбирает общий алгоритм
		 *
		 * \~english
		 * @brief Method of the composition of the list of the algorithms of the compression of the chain of the certificates
		 * @param algorithms the list of the identifiers of the algorithms being composed
		 * @param result     the accumulator the body of the extension is appended to the end of
		 * @return           the failure of the composition of the body of the extension
		 * @note The list is not re-sorted: its order is the order of the preference of the consumer,
		 *       and by it the peer chooses the common algorithm
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t algorithms(const vector <uint16_t> & algorithms, vector <uint8_t> & result) noexcept;
	};
};

#endif // __ANTS_EXTENSION__
