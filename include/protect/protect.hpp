/**
 * @file protect.hpp
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
 * @brief Заголовочный файл модуля защиты записей протокола TLS 1.3 наборами шифрования
 *        на алгоритмах ГОСТ и классическими наборами AES-GCM и ChaCha20-Poly1305, а также
 *        записей протокола TLS 1.2 наборами ECDHE на тех же шифрах
 *
 * \~english
 * @brief Header file of the module of the protection of the records of the TLS 1.3 protocol
 *        by the cipher suites on the GOST algorithms and by the classic AES-GCM and
 *        ChaCha20-Poly1305 suites
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_PROTECT__
#define __ANTS_PROTECT__

/**
 * Стандартные заголовочные файлы
 */
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <cipher/aes.hpp>
#include <cipher/gcm.hpp>
#include <cipher/mgm.hpp>
#include <cipher/mode.hpp>
#include <digest/hash.hpp>
#include <cipher/magma.hpp>
#include <cipher/kuznyechik.hpp>
#include <cipher/chachapoly.hpp>
#include <record/record.hpp>

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
	 * @brief Пространство имён защиты записей протокола TLS
	 *
	 * @details Раздел 5.2 RFC 8446: открытая запись обращается в защищённую наложением
	 *          шифрования с проверкой целостности, где связанными данными служит сам
	 *          заголовок записи, а истинный вид её содержимого прячется внутрь шифртекста.
	 *
	 * @note У наборов ГОСТ ключ записи вырабатывается заново для всякого порядкового номера
	 *       построением TLSTREE: тем ограничивается объём данных, зашифрованных на одном
	 *       ключе. У классических наборов ключ один на всё направление, а предел записей
	 *       на нём задан разделом 5.5 RFC 8446
	 *
	 * \~english
	 * @brief Namespace of the protection of the records of the TLS protocol
	 * @details The section 5.2 of RFC 8446: a plain record is turned into a protected one by the
	 *          application of an encryption with an integrity check, where the header of the record
	 *          itself serves as the associated data, while the true type of its content is hidden
	 *          inside the ciphertext.
	 * @note At the GOST suites the key of a record is derived anew for every sequence number by
	 *       the TLSTREE construction: this limits the volume of the data encrypted under a single
	 *       key. At the classic suites the key is one for the whole direction, while the limit of
	 *       the records under it is set by the section 5.5 of RFC 8446
	 *
	 * \~
	 */
	namespace protect {
		/**
		 * \~russian
		 * @brief Наибольшая длина ключа набора шифрования в байтах
		 *
		 * @details У наборов ГОСТ, у AES-256 и у ChaCha20-Poly1305 ключ занимает тридцать два
		 *          байта, у AES-128 - шестнадцать; длину ключа набора отдаёт метод key
		 *
		 * \~english
		 * @brief Greatest length of the key of a cipher suite in bytes
		 * @details At the GOST suites, at AES-256 and at ChaCha20-Poly1305 the key occupies thirty
		 *          two bytes, at AES-128 - sixteen; the length of the key of a suite is given by the
		 *          key method
		 *
		 * \~
		 */
		static constexpr size_t PROTECT_KEY = 32;

		/**
		 * \~russian
		 * @brief Наибольшая длина вектора замены набора шифрования в байтах
		 *
		 * @details У наборов ГОСТ длина вектора замены равна длине блока базового шифра: у
		 *          «Кузнечика» это шестнадцать байтов, у «Магмы» - восемь; у наборов AES-GCM и
		 *          ChaCha20-Poly1305 вектор занимает двенадцать байтов (раздел 5.3 RFC 8446)
		 *
		 * \~english
		 * @brief Greatest length of the initialization vector of a cipher suite in bytes
		 * @details At the GOST suites the length of the initialization vector equals the length of a
		 *          block of the base cipher: at «Kuznyechik» it is sixteen bytes, at «Magma» it is
		 *          eight; at the AES-GCM and ChaCha20-Poly1305 suites the vector occupies twelve
		 *          bytes (the section 5.3 of RFC 8446)
		 *
		 * \~
		 */
		static constexpr size_t PROTECT_VECTOR = 16;

		/**
		 * \~russian
		 * @brief Отказы защиты записей
		 *
		 * \~english
		 * @brief Failures of the protection of the records
		 *
		 * \~
		 */
		enum class error_t : uint8_t {
			NONE     = 0x00, /*!< \~russian Отказа нет \~english There is no failure \~ */
			STATE    = 0x01, /*!< \~russian Набор шифрования ещё не установлен \~english The cipher suite is not set yet \~ */
			LENGTH   = 0x02, /*!< \~russian Длина содержимого записи выходит за дозволенные пределы \~english The length of the content of the record goes beyond the allowed limits \~ */
			SEQUENCE = 0x03, /*!< \~russian Порядковые номера записей на этом ключе исчерпаны \~english The sequence numbers of the records under this key are exhausted \~ */
			TAG      = 0x04, /*!< \~russian Метка целостности записи не сошлась \~english The authentication tag of the record did not match \~ */
			TYPE     = 0x05, /*!< \~russian Вид содержимого записи протоколом не определён \~english The type of the content of the record is not defined by the protocol \~ */
			CIPHER   = 0x06, /*!< \~russian Базовый шифр набора отработать не смог \~english The base cipher of the suite was unable to work \~ */
			MEMORY   = 0x07  /*!< \~russian Памяти под итог не хватило \~english There was not enough memory for the outcome \~ */
		};

		/**
		 * \~russian
		 * @brief Наборы шифрования протокола TLS 1.3
		 *
		 * @details Наборы ГОСТ различаются базовым шифром и тем, как часто сменяется ключ
		 *          записи: у наборов с буквой L смена редкая, у наборов с буквой S - частая.
		 *          Классические наборы раздела B.4 RFC 8446 различаются шифром записей (AES-GCM
		 *          либо ChaCha20-Poly1305), длиной ключа и хешем расписания ключей
		 *
		 * @note Значения, здесь не перечисленные, в перечнях встречной стороны пропускаются
		 *       молча (RFC 8701): набор неведомый - не набор негодный
		 *
		 * \~english
		 * @brief Cipher suites of the TLS 1.3 protocol
		 * @details The GOST suites differ by the base cipher and by how often the key of a record is
		 *          changed: at the suites with the letter L the change is rare, at the suites with
		 *          the letter S it is frequent. The classic suites of the section B.4 of RFC 8446
		 *          differ by the cipher of the records (AES-GCM or ChaCha20-Poly1305), by the length
		 *          of the key and by the hash of the key schedule
		 * @note The values not listed here are skipped silently in the lists of the peer (RFC 8701):
		 *       an unknown suite is not an invalid suite
		 *
		 * \~
		 */
		enum class suite_t : uint16_t {
			NONE             = 0x0000, /*!< \~russian Набор шифрования не установлен \~english The cipher suite is not set \~ */
			KUZNYECHIK_MGM_L = 0xC103, /*!< \~russian «Кузнечик» в режиме MGM с редкой сменой ключа записи \~english «Kuznyechik» in the MGM mode with a rare change of the key of a record \~ */
			MAGMA_MGM_L      = 0xC104, /*!< \~russian «Магма» в режиме MGM с редкой сменой ключа записи \~english «Magma» in the MGM mode with a rare change of the key of a record \~ */
			KUZNYECHIK_MGM_S = 0xC105, /*!< \~russian «Кузнечик» в режиме MGM с частой сменой ключа записи \~english «Kuznyechik» in the MGM mode with a frequent change of the key of a record \~ */
			MAGMA_MGM_S      = 0xC106, /*!< \~russian «Магма» в режиме MGM с частой сменой ключа записи \~english «Magma» in the MGM mode with a frequent change of the key of a record \~ */
			AES_128_GCM_SHA256 = 0x1301, /*!< \~russian AES-128 в режиме GCM с расписанием на SHA-256 \~english AES-128 in the GCM mode with the schedule on SHA-256 \~ */
			AES_256_GCM_SHA384 = 0x1302, /*!< \~russian AES-256 в режиме GCM с расписанием на SHA-384 \~english AES-256 in the GCM mode with the schedule on SHA-384 \~ */
			CHACHA20_POLY1305_SHA256 = 0x1303, /*!< \~russian ChaCha20-Poly1305 с расписанием на SHA-256 \~english ChaCha20-Poly1305 with the schedule on SHA-256 \~ */
			ECDHE_ECDSA_AES_128_GCM_SHA256       = 0xC02B, /*!< \~russian TLS 1.2: ECDHE с подписью ECDSA, AES-128-GCM, PRF на SHA-256 (RFC 5289) \~english TLS 1.2: ECDHE with an ECDSA signature, AES-128-GCM, the PRF on SHA-256 (RFC 5289) \~ */
			ECDHE_ECDSA_AES_256_GCM_SHA384       = 0xC02C, /*!< \~russian TLS 1.2: ECDHE с подписью ECDSA, AES-256-GCM, PRF на SHA-384 (RFC 5289) \~english TLS 1.2: ECDHE with an ECDSA signature, AES-256-GCM, the PRF on SHA-384 (RFC 5289) \~ */
			ECDHE_RSA_AES_128_GCM_SHA256         = 0xC02F, /*!< \~russian TLS 1.2: ECDHE с подписью RSA, AES-128-GCM, PRF на SHA-256 (RFC 5289) \~english TLS 1.2: ECDHE with an RSA signature, AES-128-GCM, the PRF on SHA-256 (RFC 5289) \~ */
			ECDHE_RSA_AES_256_GCM_SHA384         = 0xC030, /*!< \~russian TLS 1.2: ECDHE с подписью RSA, AES-256-GCM, PRF на SHA-384 (RFC 5289) \~english TLS 1.2: ECDHE with an RSA signature, AES-256-GCM, the PRF on SHA-384 (RFC 5289) \~ */
			ECDHE_RSA_CHACHA20_POLY1305_SHA256   = 0xCCA8, /*!< \~russian TLS 1.2: ECDHE с подписью RSA, ChaCha20-Poly1305, PRF на SHA-256 (RFC 7905) \~english TLS 1.2: ECDHE with an RSA signature, ChaCha20-Poly1305, the PRF on SHA-256 (RFC 7905) \~ */
			ECDHE_ECDSA_CHACHA20_POLY1305_SHA256 = 0xCCA9  /*!< \~russian TLS 1.2: ECDHE с подписью ECDSA, ChaCha20-Poly1305, PRF на SHA-256 (RFC 7905) \~english TLS 1.2: ECDHE with an ECDSA signature, ChaCha20-Poly1305, the PRF on SHA-256 (RFC 7905) \~ */
		};

		/**
		 * \~russian
		 * @brief Алгоритмы подписи, которых набор шифрования TLS 1.2 требует от сертификата
		 *
		 * @details Раздел 2 RFC 8422: у наборов ECDHE_ECDSA сертификат несёт ключ ECDSA либо
		 *          EdDSA, у наборов ECDHE_RSA - ключ RSA; наборы TLS 1.3 подписи в имени не
		 *          несут вовсе
		 *
		 * \~english
		 * @brief Signature algorithms a TLS 1.2 cipher suite requires from the certificate
		 * @details The section 2 of RFC 8422: at the ECDHE_ECDSA suites the certificate carries an ECDSA or
		 *          an EdDSA key, at the ECDHE_RSA suites - an RSA key; the TLS 1.3 suites do not carry a
		 *          signature in the name at all
		 *
		 * \~
		 */
		enum class signer_t : uint8_t {
			NONE  = 0x00, /*!< \~russian Набор подписи не требует \~english The suite does not require a signature \~ */
			ECDSA = 0x01, /*!< \~russian Подпись ECDSA либо EdDSA \~english An ECDSA or an EdDSA signature \~ */
			RSA   = 0x02  /*!< \~russian Подпись RSA \~english An RSA signature \~ */
		};

		/**
		 * \~russian
		 * @brief Метод получения длины вектора замены набора шифрования
		 *
		 * @param suite набор шифрования
		 *
		 * @return      длина вектора замены в байтах, ноль у неизвестного набора
		 *
		 * @note У наборов ГОСТ она равна длине блока базового шифра, ей же равна и длина
		 *       метки целостности записи; у наборов AES-GCM и ChaCha20-Poly1305 вектор
		 *       занимает двенадцать байтов, а длину метки отдаёт метод tag
		 *
		 * \~english
		 * @brief Method of getting the length of the initialization vector of a cipher suite
		 * @param suite the cipher suite
		 * @return      the length of the initialization vector in bytes, a zero at an unknown suite
		 * @note At the GOST suites it equals the length of a block of the base cipher, and the length
		 *       of the authentication tag of a record equals it as well; at the AES-GCM and
		 *       ChaCha20-Poly1305 suites the vector occupies twelve bytes, while the length of the
		 *       tag is given by the tag method
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t block(const suite_t suite) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения длины ключа набора шифрования
		 *
		 * @param suite набор шифрования
		 *
		 * @return      длина ключа в байтах, ноль у неизвестного набора
		 *
		 * \~english
		 * @brief Method of getting the length of the key of a cipher suite
		 * @param suite the cipher suite
		 * @return      the length of the key in bytes, a zero at an unknown suite
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t key(const suite_t suite) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения длины метки целостности записи набора шифрования
		 *
		 * @param suite набор шифрования
		 *
		 * @return      длина метки целостности в байтах, ноль у неизвестного набора
		 *
		 * \~english
		 * @brief Method of getting the length of the authentication tag of a record of a cipher suite
		 * @param suite the cipher suite
		 * @return      the length of the authentication tag in bytes, a zero at an unknown suite
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t tag(const suite_t suite) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения хеша расписания ключей набора шифрования
		 *
		 * @param suite набор шифрования
		 *
		 * @return      хеш расписания ключей, NONE у неизвестного набора
		 *
		 * @details Раздел 7.1 RFC 8446: расписание ключей и переписка рукопожатия ведутся
		 *          хешем набора шифрования; у наборов ГОСТ это «Стрибог»-256
		 *
		 * \~english
		 * @brief Method of getting the hash of the key schedule of a cipher suite
		 * @param suite the cipher suite
		 * @return      the hash of the key schedule, NONE at an unknown suite
		 * @details The section 7.1 of RFC 8446: the key schedule and the transcript of the handshake are
		 *          conducted by the hash of the cipher suite; at the GOST suites it is «Streebog»-256
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ digest::hash_t hash(const suite_t suite) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения наибольшего порядкового номера записи набора шифрования
		 *
		 * @param suite набор шифрования
		 *
		 * @return      наибольший порядковый номер записи, ноль у неизвестного набора
		 *
		 * @details Достигнув этого номера, связь обязана сменить ключевой материал: дальше
		 *          записи на нём защищать нельзя
		 *
		 * @note Раздел 5.5 RFC 8446: у AES-GCM предел около 2^24,5 записей полной длины, а у
		 *       ChaCha20-Poly1305 порядковый номер переполнится раньше, чем стойкость
		 *       просядет (2^-57 на 2^64 записей). Оттого у набора ChaCha20-Poly1305 предел
		 *       взят в 2^62: он недостижим на деле, но оставляет заслон номеров живым и не
		 *       подпускает счётчик к переполнению, за которым одноразовое значение повторилось бы
		 *
		 * \~english
		 * @brief Method of getting the greatest sequence number of a record of a cipher suite
		 * @param suite the cipher suite
		 * @return      the greatest sequence number of a record, a zero at an unknown suite
		 * @details Having reached this number, a connection is obliged to change the key material:
		 *          further records may not be protected under it
		 * @note The section 5.5 of RFC 8446: at AES-GCM the limit is about 2^24.5 full-length records,
		 *       while at ChaCha20-Poly1305 the sequence number would wrap before the safety drops
		 *       (2^-57 at 2^64 records). Hence at the ChaCha20-Poly1305 suite the limit is taken as
		 *       2^62: it is unreachable in practice, yet keeps the guard of the numbers alive and does
		 *       not let the counter approach the wrap, behind which the nonce would repeat
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ uint64_t limit(const suite_t suite) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки принадлежности набора шифрования изданию TLS 1.2
		 *
		 * @param suite набор шифрования
		 *
		 * @return      признак того, что набор ведёт записи по разделу 6.2.3.3 RFC 5246
		 *
		 * @details Наборы TLS 1.2 защищают записи иначе: заголовок несёт истинный вид
		 *          содержимого, связанными данными служат порядковый номер и заголовок
		 *          открытой записи (RFC 5288, RFC 7905), а у AES-GCM явная часть одноразового
		 *          значения идёт в самой записи
		 *
		 * \~english
		 * @brief Method of checking that a cipher suite belongs to the TLS 1.2 edition
		 * @param suite the cipher suite
		 * @return      the flag of the suite conducting the records by the section 6.2.3.3 of RFC 5246
		 * @details The TLS 1.2 suites protect the records differently: the header carries the true type of
		 *          the content, the sequence number and the header of the plain record serve as the
		 *          associated data (RFC 5288, RFC 7905), and at AES-GCM the explicit part of the nonce goes
		 *          in the record itself
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool legacy(const suite_t suite) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения алгоритма подписи, требуемого набором шифрования TLS 1.2
		 *
		 * @param suite набор шифрования
		 *
		 * @return      алгоритм подписи, NONE у наборов TLS 1.3 и у неизвестного набора
		 *
		 * \~english
		 * @brief Method of getting the signature algorithm required by a TLS 1.2 cipher suite
		 * @param suite the cipher suite
		 * @return      the signature algorithm, NONE at the TLS 1.3 suites and at an unknown suite
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ signer_t signer(const suite_t suite) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки ключа записи построением TLSTREE
		 *
		 * @param suite    набор шифрования, которым заданы постоянные построения
		 * @param key      корневой ключ выработки ключа записи
		 * @param sequence порядковый номер записи
		 * @param result   место, в которое помещается ключ записи
		 *
		 * @return         признак успешности выработки ключа записи
		 *
		 * @details Ключ вырабатывается тремя ярусами выработки производного ключа, и затравкой
		 *          всякого яруса служит порядковый номер записи, обрезанный своей постоянной.
		 *          Оттого соседние записи делят ключ до тех пор, пока обрезанный номер не
		 *          изменится, а изменившись - уводят ключ безвозвратно
		 *
		 * @note Место итога обязано вмещать PROTECT_KEY байтов
		 * @note У классических наборов построения нет: ключом записи служит сам корневой
		 *       ключ, и метод лишь переносит его на место итога
		 *
		 * \~english
		 * @brief Method of the derivation of the key of a record by the TLSTREE construction
		 * @param suite    the cipher suite the constants of the construction are set by
		 * @param key      the root key of the derivation of the key of the record
		 * @param sequence the sequence number of the record
		 * @param result   the place the key of the record is put into
		 * @return         the flag of the success of the derivation of the key of the record
		 * @details The key is derived by three levels of the derivation of a key, and the sequence
		 *          number of the record truncated by the constant of the level serves as the seed of
		 *          every level. Hence the neighbouring records share a key until the truncated number
		 *          changes, and having changed, it takes the key away irreversibly
		 * @note The place of the outcome is obliged to hold PROTECT_KEY bytes
		 * @note At the classic suites there is no construction: the root key itself serves as the key
		 *       of a record, and the method only moves it to the place of the outcome
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool tree(const suite_t suite, const view_t & key, const uint64_t sequence, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Защита записей одного направления связи
		 *
		 * @details Объект хранит ключевой материал одного направления и порядковый номер
		 *          записи, который сам растёт с каждой защищённой либо снятой записью. Для
		 *          встречного направления заводится второй такой же объект.
		 *
		 * @note Ввода-вывода объект не ведёт: наложение защиты составляет целую запись, а
		 *       снятие принимает то, что выдал сборщик слоя записей
		 *
		 * \~english
		 * @brief Protection of the records of a single direction of a connection
		 * @details The object stores the key material of a single direction and the sequence number
		 *          of a record, which grows on its own with every protected or unprotected record. A
		 *          second object of the same kind is created for the opposite direction.
		 * @note The object does not perform an input-output: the application of the protection composes
		 *       a whole record, while the removal accepts what the assembler of the record layer has
		 *       produced
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Protection {
			private:
				// Признак того, что ключевой материал установлен
				bool _ready;
			private:
				// Набор шифрования, которым защищаются записи
				suite_t _suite;
			private:
				// Длина вектора замены набора шифрования
				size_t _size;
			private:
				// Длина метки целостности записи набора шифрования
				size_t _tag;
			private:
				// Длина ключа набора шифрования
				size_t _width;
			private:
				// Признак классического набора шифрования AES-GCM либо ChaCha20-Poly1305
				bool _classic;
			private:
				// Признак набора ChaCha20-Poly1305, обходящегося без базового блочного шифра
				bool _stream;
			private:
				// Признак набора издания TLS 1.2 с защитой записей по разделу 6.2.3.3 RFC 5246
				bool _legacy;
			private:
				// Порядковый номер очередной записи
				uint64_t _sequence;
			private:
				// Наибольший порядковый номер записи набора шифрования
				uint64_t _limit;
			private:
				// Порядковый номер записи, на котором выработан ключ записи
				uint64_t _derived;
			private:
				// Корневой ключ направления связи
				uint8_t _key[PROTECT_KEY];
			private:
				// Вектор замены направления связи
				uint8_t _vector[PROTECT_VECTOR];
			private:
				// Объект базового шифра «Магма»
				cipher::magma_t _magma;
			private:
				// Объект базового шифра «Кузнечик»
				cipher::kuznyechik_t _kuznyechik;
			private:
				// Объект базового шифра AES классических наборов
				cipher::aes_t _aes;
			private:
				/**
				 * \~russian
				 * @brief Метод подготовки базового шифра к защите записи
				 *
				 * @param sequence порядковый номер защищаемой записи
				 * @param block    описание базового шифра, в которое помещается итог
				 *
				 * @return         отказ подготовки базового шифра
				 *
				 * \~english
				 * @brief Method of the preparation of the base cipher for the protection of a record
				 * @param sequence the sequence number of the record being protected
				 * @param block    the description of the base cipher the outcome is put into
				 * @return         the failure of the preparation of the base cipher
				 *
				 * \~
				 */
				error_t prepare(const uint64_t sequence, cipher::block_t & block) noexcept;
				/**
				 * \~russian
				 * @brief Метод выработки одноразового значения записи
				 *
				 * @param sequence порядковый номер защищаемой записи
				 * @param result   место, в которое помещается одноразовое значение
				 *
				 * \~english
				 * @brief Method of the derivation of the nonce of a record
				 * @param sequence the sequence number of the record being protected
				 * @param result   the place the nonce is put into
				 *
				 * \~
				 */
				void nonce(const uint64_t sequence, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод составления связанных данных записи издания TLS 1.2
				 *
				 * @param sequence порядковый номер записи
				 * @param type     вид содержимого записи
				 * @param length   длина открытого содержимого записи
				 * @param result   место, в которое помещаются связанные данные
				 *
				 * @details Раздел 6.2.3.3 RFC 5246: порядковый номер, вид содержимого, издание
				 *          протокола и длина открытого содержимого - тринадцать байтов
				 *
				 * \~english
				 * @brief Method of the composition of the associated data of a record of the TLS 1.2 edition
				 * @param sequence the sequence number of the record
				 * @param type     the type of the content of the record
				 * @param length   the length of the plain content of the record
				 * @param result   the place the associated data is put into
				 * @details The section 6.2.3.3 of RFC 5246: the sequence number, the type of the content, the
				 *          edition of the protocol and the length of the plain content - thirteen bytes
				 *
				 * \~
				 */
				void associate(const uint64_t sequence, const record::type_t type, const size_t length, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод наложения защиты на запись издания TLS 1.2
				 *
				 * @param type   вид содержимого защищаемой записи
				 * @param data   защищаемое содержимое записи
				 * @param result накопитель, в конец которого дописывается защищённая запись
				 *
				 * @return       отказ наложения защиты на запись
				 *
				 * \~english
				 * @brief Method of the application of the protection to a record of the TLS 1.2 edition
				 * @param type   the type of the content of the record being protected
				 * @param data   the content of the record being protected
				 * @param result the accumulator the protected record is appended to the end of
				 * @return       the failure of the application of the protection to the record
				 *
				 * \~
				 */
				error_t wrap(const record::type_t type, const view_t & data, vector <uint8_t> & result) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия защиты с записи издания TLS 1.2
				 *
				 * @param header заголовок принятой защищённой записи
				 * @param data   защищённое содержимое принятой записи
				 * @param type   вид содержимого, в который помещается вид содержимого записи
				 * @param result накопитель, в конец которого дописывается открытое содержимое записи
				 *
				 * @return       отказ снятия защиты с записи
				 *
				 * \~english
				 * @brief Method of the removal of the protection from a record of the TLS 1.2 edition
				 * @param header the header of the received protected record
				 * @param data   the protected content of the received record
				 * @param type   the type of the content the type of the content of the record is put into
				 * @param result the accumulator the plain content of the record is appended to the end of
				 * @return       the failure of the removal of the protection from the record
				 *
				 * \~
				 */
				error_t unwrap(const record::header_t & header, const view_t & data, record::type_t & type, vector <uint8_t> & result) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности защиты записей к работе
				 *
				 * @return признак того, что ключевой материал установлен
				 *
				 * \~english
				 * @brief Method of checking the readiness of the protection of the records for the work
				 * @return the flag of the key material being set
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения набора шифрования, которым защищаются записи
				 *
				 * @return набор шифрования направления связи
				 *
				 * \~english
				 * @brief Method of getting the cipher suite the records are protected by
				 * @return the cipher suite of the direction of the connection
				 *
				 * \~
				 */
				suite_t suite() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения порядкового номера очередной записи
				 *
				 * @return порядковый номер очередной записи направления связи
				 *
				 * \~english
				 * @brief Method of getting the sequence number of the next record
				 * @return the sequence number of the next record of the direction of the connection
				 *
				 * \~
				 */
				uint64_t sequence() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки ключевого материала направления связи
				 *
				 * @param suite  устанавливаемый набор шифрования
				 * @param key    корневой ключ направления связи
				 * @param vector вектор замены направления связи
				 *
				 * @return       признак успешности установки ключевого материала
				 *
				 * @details Раздел 7.3 RFC 8446: ключ и вектор замены вырабатываются расписанием
				 *          ключей рукопожатия. Порядковый номер записи сбрасывается в ноль всякой
				 *          сменой ключевого материала
				 *
				 * \~english
				 * @brief Method of setting the key material of a direction of a connection
				 * @param suite  the cipher suite being set
				 * @param key    the root key of the direction of the connection
				 * @param vector the initialization vector of the direction of the connection
				 * @return       the flag of the success of the setting of the key material
				 * @details The section 7.3 of RFC 8446: the key and the initialization vector are derived
				 *          by the key schedule of the handshake. The sequence number of a record is reset
				 *          to a zero by every change of the key material
				 *
				 * \~
				 */
				bool start(const suite_t suite, const view_t & key, const view_t & vector) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса ключевого материала направления связи
				 *
				 * \~english
				 * @brief Method of the reset of the key material of a direction of a connection
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод наложения защиты на запись
				 *
				 * @param type    истинный вид содержимого защищаемой записи
				 * @param data    защищаемое содержимое записи
				 * @param result  накопитель, в конец которого дописывается защищённая запись
				 * @param padding длина дополнения, скрывающего истинную длину содержимого
				 *
				 * @return        отказ наложения защиты на запись
				 *
				 * @details Раздел 5.2 RFC 8446: заголовок защищённой записи всегда выдаёт себя за
				 *          прикладные данные издания TLS 1.2, а истинный вид содержимого идёт
				 *          последним значащим байтом внутри шифртекста
				 *
				 * @note Дописывается целая запись вместе с заголовком: заголовок служит связанными
				 *       данными, и составляется он здесь же
				 *
				 * @note У наборов TLS 1.2 заголовок несёт истинный вид содержимого, дополнение не
				 *       кладётся, связанными данными идут порядковый номер и заголовок открытой
				 *       записи (раздел 6.2.3.3 RFC 5246), а у AES-GCM перед шифртекстом идёт явная
				 *       часть одноразового значения - порядковый номер записи (RFC 5288)
				 *
				 * \~english
				 * @brief Method of the application of the protection to a record
				 * @param type    the true type of the content of the record being protected
				 * @param data    the content of the record being protected
				 * @param result  the accumulator the protected record is appended to the end of
				 * @param padding the length of the padding hiding the true length of the content
				 * @return        the failure of the application of the protection to the record
				 * @details The section 5.2 of RFC 8446: the header of a protected record always pretends
				 *          to be the application data of the TLS 1.2 edition, while the true type of the
				 *          content goes as the last significant byte inside the ciphertext
				 * @note A whole record together with the header is appended: the header serves as the
				 *       associated data, and it is composed right here
				 *
				 * \~
				 */
				error_t seal(const record::type_t type, const view_t & data, vector <uint8_t> & result, const size_t padding = 0) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия защиты с записи
				 *
				 * @param header заголовок принятой защищённой записи
				 * @param data   защищённое содержимое принятой записи
				 * @param type   вид содержимого, в который помещается истинный вид содержимого записи
				 * @param result накопитель, в конец которого дописывается открытое содержимое записи
				 *
				 * @return       отказ снятия защиты с записи
				 *
				 * @details Раздел 5.2 RFC 8446: истинным видом содержимого объявляется последний
				 *          значащий байт открытого текста, а нули за ним отбрасываются дополнением.
				 *          Открытый текст из одних нулей истинного вида содержимого не несёт и
				 *          принимается за отказ
				 *
				 * @note Открытое содержимое дописывается лишь после того, как метка целостности
				 *       сошлась
				 *
				 * @note У наборов TLS 1.2 вид содержимого берётся из заголовка записи, а явная часть
				 *       одноразового значения AES-GCM читается из самой записи (RFC 5288)
				 *
				 * \~english
				 * @brief Method of the removal of the protection from a record
				 * @param header the header of the received protected record
				 * @param data   the protected content of the received record
				 * @param type   the type of the content the true type of the content of the record is put into
				 * @param result the accumulator the plain content of the record is appended to the end of
				 * @return       the failure of the removal of the protection from the record
				 * @details The section 5.2 of RFC 8446: the last significant byte of the plain text is
				 *          declared to be the true type of the content, while the zeroes behind it are
				 *          discarded as the padding. A plain text of the zeroes alone does not carry a
				 *          true type of the content and is taken for a failure
				 * @note The plain content is appended only after the authentication tag has matched
				 *
				 * \~
				 */
				error_t open(const record::header_t & header, const view_t & data, record::type_t & type, vector <uint8_t> & result) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод наложения защиты на запись с заданными связанными данными и номером
				 *
				 * @param associated связанные данные записи: её заголовок, составленный снаружи
				 * @param sequence   порядковый номер записи, задающий одноразовое значение
				 * @param type       истинный вид содержимого защищаемой записи
				 * @param data       защищаемое содержимое записи
				 * @param result     накопитель, в конец которого дописываются шифртекст и метка целостности
				 * @param padding    длина дополнения, скрывающего истинную длину содержимого
				 *
				 * @return           отказ наложения защиты на запись
				 *
				 * @details Раздел 4.2 RFC 9147: заголовок записи поверх дейтаграммы составляет
				 *          связь, а номер записи она ведёт сама по порам ключей - оттого и то и
				 *          другое подаются снаружи, а собственный счётчик защиты не движется
				 *
				 * @note Заголовок в накопитель не дописывается: составивший его кладёт его сам
				 *
				 * \~english
				 * @brief Method of the application of the protection to a record with the given associated
				 *        data and number
				 * @param associated the associated data of the record: its header composed outside
				 * @param sequence   the sequence number of the record setting the nonce
				 * @param type       the true type of the content of the record being protected
				 * @param data       the content of the record being protected
				 * @param result     the accumulator the ciphertext and the authentication tag are appended to the end of
				 * @param padding    the length of the padding hiding the true length of the content
				 * @return           the failure of the application of the protection to the record
				 * @details The section 4.2 of RFC 9147: the header of a record over a datagram is composed by the
				 *          connection, and the number of the record it leads itself by the epochs — hence both are
				 *          given from outside, while the own counter of the protection does not move
				 * @note The header is not appended to the accumulator: the one who composed it puts it itself
				 *
				 * \~
				 */
				error_t seal(const view_t & associated, const uint64_t sequence, const record::type_t type, const view_t & data, vector <uint8_t> & result, const size_t padding) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия защиты с записи с заданными связанными данными и номером
				 *
				 * @param associated связанные данные записи: её заголовок, каким он был при наложении защиты
				 * @param sequence   восстановленный порядковый номер записи
				 * @param data       защищённое содержимое принятой записи
				 * @param type       вид содержимого, в который помещается истинный вид содержимого записи
				 * @param result     накопитель, в конец которого дописывается открытое содержимое записи
				 *
				 * @return           отказ снятия защиты с записи
				 *
				 * @note Собственный счётчик защиты не движется: порядок приёма записей поверх
				 *       дейтаграмм ведёт окно защиты от повторов у связи
				 *
				 * \~english
				 * @brief Method of the removal of the protection from a record with the given associated data
				 *        and number
				 * @param associated the associated data of the record: its header as it was at the application of the protection
				 * @param sequence   the restored sequence number of the record
				 * @param data       the protected content of the received record
				 * @param type       the type of the content the true type of the content of the record is put into
				 * @param result     the accumulator the plain content of the record is appended to the end of
				 * @return           the failure of the removal of the protection from the record
				 * @note The own counter of the protection does not move: the order of the receipt of the records
				 *       over datagrams is led by the anti-replay window of the connection
				 *
				 * \~
				 */
				error_t open(const view_t & associated, const uint64_t sequence, const view_t & data, record::type_t & type, vector <uint8_t> & result) noexcept;
			public:
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
				Protection() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Protection() noexcept;
		} protection_t;
	};
};

#endif // __ANTS_PROTECT__
