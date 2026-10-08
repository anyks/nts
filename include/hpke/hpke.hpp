/**
 * @file hpke.hpp
 * @date 2026-09-06
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
 * @brief Заголовочный файл модуля гибридного шифрования с открытым ключом HPKE по
 *        RFC 9180 — инкапсуляция ключа DHKEM(X25519, HKDF-SHA256), расписание ключей
 *        на HKDF, шифрование с порядковыми номерами на AEAD и выработка секретов экспорта
 *
 * \~english
 * @brief Header file of the module of the hybrid public key encryption HPKE according to
 *        RFC 9180 — the key encapsulation DHKEM(X25519, HKDF-SHA256), the key schedule on
 *        HKDF, the encryption with sequence numbers on an AEAD and the production of the
 *        exported secrets
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#pragma once
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

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 *
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён модуля гибридного шифрования с открытым ключом HPKE
	 *
	 * @details Модуль сложен по RFC 9180 поверх примитивов библиотеки: общее значение на
	 *          кривой Curve25519 берётся у модуля `agreement`, извлечение и растяжение
	 *          ключа — у `digest`, шифрование с проверкой подлинности — у `cipher`.
	 *          Ничего из движка TLS модуль не трогает: он самодостаточен и годится и для
	 *          зашифрованного приветствия ECH, и потребителю напрямую.
	 *
	 *          Ввода и вывода модуль не ведёт, исключений на путях разбора не бросает:
	 *          всякий отказ отдаётся кодом причины, нехватка памяти — кодом `MEMORY`.
	 *          Секретные значения — ключи, общие значения, ключ шифра, секрет экспорта —
	 *          стираются по завершении работы либо при отказе.
	 *
	 * \~english
	 * @brief Namespace of the module of the hybrid public key encryption HPKE
	 * @details The module is composed according to RFC 9180 on top of the primitives of the
	 *          library: the shared value on the curve Curve25519 is taken from the module
	 *          `agreement`, the extraction and expansion of the key — from `digest`, the
	 *          authenticated encryption — from `cipher`. The module touches nothing from the
	 *          TLS engine: it is self-sufficient and suits both the encrypted client hello ECH
	 *          and the consumer directly.
	 *          The module leads no input and output and throws no exceptions on the parsing
	 *          paths: every failure is given as a reason code, the lack of memory — as the
	 *          code `MEMORY`. The secret values — the keys, the shared values, the cipher key,
	 *          the exporter secret — are wiped on the completion of the work or on a failure.
	 *
	 * \~
	 *
	 */
	namespace hpke {
		/**
		 * \~russian
		 * @brief Причина отказа
		 *
		 * \~english
		 * @brief Reason of a failure
		 *
		 * \~
		 *
		 */
		enum class error_t : uint8_t {
			NONE          = 0x00, /*!< \~russian Отказа не произошло \~english No failure has occurred \~ */
			SUITE         = 0x01, /*!< \~russian Набор алгоритмов не поддерживается либо не установлен \~english The ciphersuite is not supported or is not set \~ */
			MODE          = 0x02, /*!< \~russian Режим работы неизвестен \~english The mode of the work is unknown \~ */
			ARGUMENT      = 0x03, /*!< \~russian Довод не задан либо места под итог не хватает \~english An argument is not given or the room for the result is not enough \~ */
			KEY           = 0x04, /*!< \~russian Ключ не установлен либо записан неверной длиной \~english The key is not set or is written with a wrong length \~ */
			PSK           = 0x05, /*!< \~russian Заранее разделённый ключ и его опознаватель не отвечают режиму \~english The pre-shared key and its identifier do not meet the mode \~ */
			ENCAPSULATION = 0x06, /*!< \~russian Инкапсулированный ключ негоден: неверная длина либо общее значение нулевое \~english The encapsulated key is unsuitable: a wrong length or the shared value is zero \~ */
			ENTROPY       = 0x07, /*!< \~russian Источник случайных значений отказал \~english The source of the random values has failed \~ */
			READY         = 0x08, /*!< \~russian Состояние связи не установлено \~english The context is not set up \~ */
			AEAD          = 0x09, /*!< \~russian Шифрование недоступно: набор только для экспорта либо шифр отказал \~english The encryption is unavailable: the export-only suite or the cipher has failed \~ */
			SEQUENCE      = 0x0A, /*!< \~russian Порядковые номера исчерпаны \~english The sequence numbers are exhausted \~ */
			OPEN          = 0x0B, /*!< \~russian Шифртекст не прошёл проверку подлинности \~english The ciphertext has not passed the authenticity check \~ */
			LENGTH        = 0x0C, /*!< \~russian Запрошенная длина недопустима \~english The requested length is inadmissible \~ */
			MEMORY        = 0x0D  /*!< \~russian Не удалось выделить память \~english It was not possible to allocate memory \~ */
		};

		/**
		 * \~russian
		 * @brief Способ инкапсуляции ключа
		 *
		 * @details Значения отвечают опознавателям KEM раздела 7.1 RFC 9180
		 *
		 * \~english
		 * @brief Key encapsulation mechanism
		 * @details The values correspond to the KEM identifiers of the section 7.1 of RFC 9180
		 *
		 * \~
		 *
		 */
		enum class kem_t : uint16_t {
			NONE              = 0x0000, /*!< \~russian Способ не установлен \~english The mechanism is not set \~ */
			P256_HKDF_SHA256  = 0x0010, /*!< \~russian DHKEM(P-256, HKDF-SHA256) \~english DHKEM(P-256, HKDF-SHA256) \~ */
			P384_HKDF_SHA384  = 0x0011, /*!< \~russian DHKEM(P-384, HKDF-SHA384) \~english DHKEM(P-384, HKDF-SHA384) \~ */
			P521_HKDF_SHA512  = 0x0012, /*!< \~russian DHKEM(P-521, HKDF-SHA512) \~english DHKEM(P-521, HKDF-SHA512) \~ */
			X25519_HKDF_SHA256 = 0x0020, /*!< \~russian DHKEM(X25519, HKDF-SHA256) \~english DHKEM(X25519, HKDF-SHA256) \~ */
			X448_HKDF_SHA512  = 0x0021, /*!< \~russian DHKEM(X448, HKDF-SHA512) \~english DHKEM(X448, HKDF-SHA512) \~ */
			MLKEM512          = 0x0040, /*!< \~russian ML-KEM-512 по draft-ietf-hpke-pq: секретный ключ - зерно в шестьдесят четыре байта \~english ML-KEM-512 by draft-ietf-hpke-pq: the secret key is a seed of sixty four bytes \~ */
			MLKEM768          = 0x0041, /*!< \~russian ML-KEM-768 по draft-ietf-hpke-pq: секретный ключ - зерно в шестьдесят четыре байта \~english ML-KEM-768 by draft-ietf-hpke-pq: the secret key is a seed of sixty four bytes \~ */
			MLKEM1024         = 0x0042, /*!< \~russian ML-KEM-1024 по draft-ietf-hpke-pq: секретный ключ - зерно в шестьдесят четыре байта \~english ML-KEM-1024 by draft-ietf-hpke-pq: the secret key is a seed of sixty four bytes \~ */
			MLKEM768_P256     = 0x0050, /*!< \~russian Гибрид ML-KEM-768 и P-256 по draft-irtf-cfrg-concrete-hybrid-kems: секретный ключ - зерно в тридцать два байта \~english The hybrid of ML-KEM-768 and P-256 by draft-irtf-cfrg-concrete-hybrid-kems: the secret key is a seed of thirty two bytes \~ */
			MLKEM1024_P384    = 0x0051, /*!< \~russian Гибрид ML-KEM-1024 и P-384 по draft-irtf-cfrg-concrete-hybrid-kems: секретный ключ - зерно в тридцать два байта \~english The hybrid of ML-KEM-1024 and P-384 by draft-irtf-cfrg-concrete-hybrid-kems: the secret key is a seed of thirty two bytes \~ */
			MLKEM768_X25519   = 0x647A  /*!< \~russian Гибрид ML-KEM-768 и X25519 (X-Wing) по draft-irtf-cfrg-concrete-hybrid-kems: секретный ключ - зерно в тридцать два байта \~english The hybrid of ML-KEM-768 and X25519 (X-Wing) by draft-irtf-cfrg-concrete-hybrid-kems: the secret key is a seed of thirty two bytes \~ */
		};

		/**
		 * \~russian
		 * @brief Функция выработки ключа
		 *
		 * @details Значения отвечают опознавателям KDF раздела 7.2 RFC 9180
		 *
		 * \~english
		 * @brief Key derivation function
		 * @details The values correspond to the KDF identifiers of the section 7.2 of RFC 9180
		 *
		 * \~
		 *
		 */
		enum class kdf_t : uint16_t {
			NONE          = 0x0000, /*!< \~russian Функция не установлена \~english The function is not set \~ */
			HKDF_SHA256   = 0x0001, /*!< \~russian HKDF-SHA256 \~english HKDF-SHA256 \~ */
			HKDF_SHA384   = 0x0002, /*!< \~russian HKDF-SHA384 \~english HKDF-SHA384 \~ */
			HKDF_SHA512   = 0x0003, /*!< \~russian HKDF-SHA512 \~english HKDF-SHA512 \~ */
			SHAKE128      = 0x0010, /*!< \~russian Одноступенчатая функция SHAKE128 по draft-ietf-hpke-pq \~english The one-stage function SHAKE128 by draft-ietf-hpke-pq \~ */
			SHAKE256      = 0x0011, /*!< \~russian Одноступенчатая функция SHAKE256 по draft-ietf-hpke-pq \~english The one-stage function SHAKE256 by draft-ietf-hpke-pq \~ */
			TURBOSHAKE128 = 0x0012, /*!< \~russian Одноступенчатая функция TurboSHAKE128 по draft-ietf-hpke-pq \~english The one-stage function TurboSHAKE128 by draft-ietf-hpke-pq \~ */
			TURBOSHAKE256 = 0x0013  /*!< \~russian Одноступенчатая функция TurboSHAKE256 по draft-ietf-hpke-pq \~english The one-stage function TurboSHAKE256 by draft-ietf-hpke-pq \~ */
		};

		/**
		 * \~russian
		 * @brief Шифр с проверкой подлинности
		 *
		 * @details Значения отвечают опознавателям AEAD раздела 7.3 RFC 9180
		 *
		 * \~english
		 * @brief Authenticated encryption with associated data
		 * @details The values correspond to the AEAD identifiers of the section 7.3 of RFC 9180
		 *
		 * \~
		 *
		 */
		enum class aead_t : uint16_t {
			NONE              = 0x0000, /*!< \~russian Шифр не установлен \~english The cipher is not set \~ */
			AES_128_GCM       = 0x0001, /*!< \~russian AES-128-GCM \~english AES-128-GCM \~ */
			AES_256_GCM       = 0x0002, /*!< \~russian AES-256-GCM \~english AES-256-GCM \~ */
			CHACHA20_POLY1305 = 0x0003, /*!< \~russian ChaCha20-Poly1305 \~english ChaCha20-Poly1305 \~ */
			EXPORT_ONLY       = 0xFFFF  /*!< \~russian Только экспорт секретов, шифрования нет \~english Only the export of secrets, no encryption \~ */
		};

		/**
		 * \~russian
		 * @brief Режим работы
		 *
		 * @details Значения отвечают перечню режимов раздела 5 RFC 9180
		 *
		 * \~english
		 * @brief Mode of the work
		 * @details The values correspond to the list of modes of the section 5 of RFC 9180
		 *
		 * \~
		 *
		 */
		enum class regime_t : uint8_t {
			BASE     = 0x00, /*!< \~russian Базовый режим: получатель по открытому ключу \~english The base mode: the recipient by the public key \~ */
			PSK      = 0x01, /*!< \~russian Режим с заранее разделённым ключом \~english The mode with a pre-shared key \~ */
			AUTH     = 0x02, /*!< \~russian Режим с подлинностью отправителя по его ключу \~english The mode with the authentication of the sender by its key \~ */
			AUTH_PSK = 0x03  /*!< \~russian Режим с подлинностью отправителя и заранее разделённым ключом \~english The mode with the authentication of the sender and a pre-shared key \~ */
		};

		/**
		 * \~russian
		 * @brief Размер ключей и инкапсулированного ключа DHKEM(X25519, HKDF-SHA256) в байтах
		 *
		 * \~english
		 * @brief Size of the keys and of the encapsulated key of DHKEM(X25519, HKDF-SHA256) in bytes
		 *
		 * \~
		 *
		 */
		static constexpr size_t X25519_SIZE = 32;

		/**
		 * \~russian
		 * @brief Наибольшая длина открытого ключа способа инкапсуляции в байтах:
		 *        1665 у гибрида ML-KEM-1024 и P-384
		 *
		 * \~english
		 * @brief Greatest length of the public key of the encapsulation mechanism in bytes:
		 *        1665 at the hybrid of ML-KEM-1024 and P-384
		 *
		 * \~
		 *
		 */
		static constexpr size_t KEM_PUBLIC = 1665;
		/**
		 * \~russian
		 * @brief Наибольшая длина секретного ключа способа инкапсуляции в байтах:
		 *        66 у DHKEM(P-521, HKDF-SHA512)
		 *
		 * \~english
		 * @brief Greatest length of the secret key of the encapsulation mechanism in bytes:
		 *        66 at DHKEM(P-521, HKDF-SHA512)
		 *
		 * \~
		 *
		 */
		static constexpr size_t KEM_SECRET = 66;
		/**
		 * \~russian
		 * @brief Наибольшая длина инкапсулированного ключа в байтах:
		 *        1665 у гибрида ML-KEM-1024 и P-384
		 *
		 * \~english
		 * @brief Greatest length of the encapsulated key in bytes:
		 *        1665 at the hybrid of ML-KEM-1024 and P-384
		 *
		 * \~
		 *
		 */
		static constexpr size_t KEM_CIPHER = 1665;
		/**
		 * \~russian
		 * @brief Наибольшая длина исходного материала выработки пары ключей в байтах:
		 *        64 у чистого ML-KEM
		 *
		 * \~english
		 * @brief Greatest length of the input keying material of the production of a key pair
		 *        in bytes: 64 at the pure ML-KEM
		 *
		 * \~
		 *
		 */
		static constexpr size_t KEM_SEED = 64;

		/**
		 * \~russian
		 * @brief Наибольшая длина общего значения способа инкапсуляции в байтах:
		 *        Nsecret раздела 7.1 RFC 9180 и таблиц draft-ietf-hpke-pq
		 *
		 * \~english
		 * @brief Greatest length of the shared secret of the encapsulation mechanism in bytes:
		 *        Nsecret of the section 7.1 of RFC 9180 and of the tables of draft-ietf-hpke-pq
		 *
		 * \~
		 *
		 */
		static constexpr size_t KEM_SHARED = 64;

		/**
		 * \~russian
		 * @brief Наибольшая длина хеша функций выработки ключа в байтах
		 *
		 * \~english
		 * @brief Greatest length of the hash of the key derivation functions in bytes
		 *
		 * \~
		 *
		 */
		static constexpr size_t HASH_SIZE = 64;

		/**
		 * \~russian
		 * @brief Наибольшая длина ключа шифра в байтах
		 *
		 * \~english
		 * @brief Greatest length of the cipher key in bytes
		 *
		 * \~
		 *
		 */
		static constexpr size_t KEY_SIZE = 32;

		/**
		 * \~russian
		 * @brief Длина начального заполнения шифров в байтах
		 *
		 * \~english
		 * @brief Length of the nonce of the ciphers in bytes
		 *
		 * \~
		 *
		 */
		static constexpr size_t NONCE_SIZE = 12;

		/**
		 * \~russian
		 * @brief Длина метки подлинности шифров в байтах
		 *
		 * \~english
		 * @brief Length of the authentication tag of the ciphers in bytes
		 *
		 * \~
		 *
		 */
		static constexpr size_t TAG_SIZE = 16;

		/**
		 * \~russian
		 * @brief Набор алгоритмов
		 *
		 * @details Тройка раздела 5 RFC 9180: способ инкапсуляции ключа, функция выработки
		 *          ключа и шифр с проверкой подлинности
		 *
		 * \~english
		 * @brief Ciphersuite
		 * @details The triple of the section 5 of RFC 9180: the key encapsulation mechanism, the
		 *          key derivation function and the authenticated encryption
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Suite {
			// Способ инкапсуляции ключа
			kem_t kem;
			// Функция выработки ключа
			kdf_t kdf;
			// Шифр с проверкой подлинности
			aead_t aead;
			/**
			 * \~russian
			 * @brief Конструктор пустого набора
			 *
			 * \~english
			 * @brief Constructor of an empty suite
			 *
			 * \~
			 *
			 */
			Suite() noexcept;
			/**
			 * \~russian
			 * @brief Конструктор набора
			 *
			 * @param kem  способ инкапсуляции ключа
			 * @param kdf  функция выработки ключа
			 * @param aead шифр с проверкой подлинности
			 *
			 * \~english
			 * @brief Constructor of a suite
			 * @param kem  the key encapsulation mechanism
			 * @param kdf  the key derivation function
			 * @param aead the authenticated encryption
			 *
			 * \~
			 *
			 */
			Suite(const kem_t kem, const kdf_t kdf, const aead_t aead) noexcept;
		} suite_t;

		/**
		 * \~russian
		 * @brief Заранее разделённый ключ с опознавателем
		 *
		 * @details Раздел 5.1 RFC 9180: в режимах PSK и AUTH_PSK ключ и опознаватель обязаны
		 *          быть непустыми, в режимах BASE и AUTH — пустыми
		 *
		 * \~english
		 * @brief Pre-shared key with an identifier
		 * @details The section 5.1 of RFC 9180: in the modes PSK and AUTH_PSK the key and the
		 *          identifier must be non-empty, in the modes BASE and AUTH — empty
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Shared {
			// Просмотр заранее разделённого ключа
			view_t key;
			// Просмотр опознавателя ключа
			view_t identity;
			/**
			 * \~russian
			 * @brief Конструктор пустого ключа
			 *
			 * \~english
			 * @brief Constructor of an empty key
			 *
			 * \~
			 *
			 */
			Shared() noexcept;
			/**
			 * \~russian
			 * @brief Конструктор ключа
			 *
			 * @param key      просмотр заранее разделённого ключа
			 * @param identity просмотр опознавателя ключа
			 *
			 * \~english
			 * @brief Constructor of a key
			 * @param key      the view of the pre-shared key
			 * @param identity the view of the identifier of the key
			 *
			 * \~
			 *
			 */
			Shared(const view_t & key, const view_t & identity) noexcept;
		} shared_t;

		/**
		 * \~russian
		 * @brief Метод извлечения длины хеша функции выработки ключа
		 *
		 * @param kdf функция выработки ключа
		 * @return    длина хеша в байтах либо ноль у неизвестной функции
		 *
		 * \~english
		 * @brief Method of getting the length of the hash of the key derivation function
		 * @param kdf the key derivation function
		 * @return    the length of the hash in bytes or zero for an unknown function
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ size_t length(const kdf_t kdf) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения длины открытого ключа способа инкапсуляции
		 *
		 * @param kem способ инкапсуляции ключа
		 * @return    длина открытого ключа в байтах либо ноль у неизвестного способа
		 *
		 * \~english
		 * @brief Method of getting the length of the public key of the encapsulation mechanism
		 * @param kem the key encapsulation mechanism
		 * @return    the length of the public key in bytes or zero for an unknown mechanism
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ size_t length(const kem_t kem) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения длины секретного ключа способа инкапсуляции
		 *
		 * @param kem способ инкапсуляции ключа
		 * @return    длина секретного ключа в байтах либо ноль у неизвестного способа
		 *
		 * \~english
		 * @brief Method of getting the length of the secret key of the encapsulation mechanism
		 * @param kem the key encapsulation mechanism
		 * @return    the length of the secret key in bytes or zero for an unknown mechanism
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ size_t secret(const kem_t kem) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения длины инкапсулированного ключа способа инкапсуляции
		 *
		 * @param kem способ инкапсуляции ключа
		 * @return    длина инкапсулированного ключа в байтах либо ноль у неизвестного способа
		 *
		 * \~english
		 * @brief Method of getting the length of the encapsulated key of the encapsulation mechanism
		 * @param kem the key encapsulation mechanism
		 * @return    the length of the encapsulated key in bytes or zero for an unknown mechanism
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ size_t overhead(const kem_t kem) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения длины исходного материала выработки пары ключей
		 *
		 * @param kem способ инкапсуляции ключа
		 * @return    наименьшая длина исходного материала в байтах либо ноль у неизвестного способа
		 *
		 * \~english
		 * @brief Method of getting the length of the input keying material of the production of a key pair
		 * @param kem the key encapsulation mechanism
		 * @return    the least length of the input keying material in bytes or zero for an unknown mechanism
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ size_t material(const kem_t kem) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки признака подлинности отправителя у способа инкапсуляции
		 *
		 * @param kem способ инкапсуляции ключа
		 * @return    признак того, что способ поддерживает режимы AUTH и AUTH_PSK
		 *
		 * @details Раздел 7.2 draft-ietf-hpke-pq: постквантовые способы и гибриды режимы с
		 *          подлинностью отправителя по ключу не поддерживают - ими доступны лишь
		 *          режимы BASE и PSK
		 *
		 * \~english
		 * @brief Method of checking the flag of the sender authentication of the encapsulation mechanism
		 * @param kem the key encapsulation mechanism
		 * @return    the flag that the mechanism supports the modes AUTH and AUTH_PSK
		 * @details The section 7.2 of draft-ietf-hpke-pq: the post-quantum mechanisms and the hybrids do
		 *          not support the modes with the sender authentication by a key - only the modes BASE
		 *          and PSK are available with them
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ bool authenticated(const kem_t kem) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения длины ключа шифра
		 *
		 * @param aead шифр с проверкой подлинности
		 * @return     длина ключа в байтах, ноль у набора только для экспорта и у неизвестного шифра
		 *
		 * \~english
		 * @brief Method of getting the length of the cipher key
		 * @param aead the authenticated encryption
		 * @return     the length of the key in bytes, zero for the export-only suite and for an unknown cipher
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ size_t length(const aead_t aead) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения длины метки подлинности шифра
		 *
		 * @param aead шифр с проверкой подлинности
		 * @return     длина метки в байтах, ноль у набора только для экспорта и у неизвестного шифра
		 *
		 * \~english
		 * @brief Method of getting the length of the authentication tag of the cipher
		 * @param aead the authenticated encryption
		 * @return     the length of the tag in bytes, zero for the export-only suite and for an unknown cipher
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ size_t overhead(const aead_t aead) noexcept;
		/**
		 * \~russian
		 * @brief Метод проверки поддержки набора алгоритмов
		 *
		 * @param suite набор алгоритмов
		 * @return      признак того, что все три алгоритма набора поддерживаются
		 *
		 * \~english
		 * @brief Method of checking the support of a ciphersuite
		 * @param suite the ciphersuite
		 * @return      the flag that all three algorithms of the suite are supported
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ bool supported(const suite_t & suite) noexcept;

		/**
		 * \~russian
		 * @brief Пара ключей способа инкапсуляции
		 *
		 * @details Хранит секретный и открытый ключи DHKEM. Секретный ключ стирается при
		 *          очистке и при уничтожении объекта. Ключ вырабатывается из случайных байтов,
		 *          из исходного материала по разделу 7.1.3 RFC 9180 либо задаётся байтами
		 *          секретного ключа
		 *
		 * \~english
		 * @brief Key pair of the encapsulation mechanism
		 * @details Stores the secret and the public keys of DHKEM. The secret key is wiped on the
		 *          clearing and on the destruction of the object. The key is produced from random
		 *          bytes, from the input keying material according to the section 7.1.3 of RFC 9180
		 *          or is set by the bytes of the secret key
		 *
		 * \~
		 *
		 */
		typedef class __ANTS_SHARED_EXPORT__ Key {
			private:
				// Способ инкапсуляции ключа
				kem_t _kem;
			private:
				// Длина занятой части секретного ключа
				uint16_t _secretSize;
				// Длина занятой части открытого ключа
				uint16_t _pointSize;
			private:
				// Секретный ключ
				uint8_t _secret[KEM_SECRET];
				// Открытый ключ
				uint8_t _point[KEM_PUBLIC];
			private:
				/**
				 * \~russian
				 * @brief Метод выработки пары ключей гибридного способа из зерна
				 *
				 * @param kem  способ инкапсуляции ключа
				 * @param seed зерно в тридцать два байта
				 * @return     признак успешности выработки
				 *
				 * @details Функция DeriveKeyPair раздела 5.5 draft-irtf-cfrg-hybrid-kems (каркас CG):
				 *          зерно растягивается SHAKE256 в зерно ML-KEM и зерно группы, из первого
				 *          вырабатывается пара ML-KEM, из второго отбирается скаляр группы
				 *
				 * \~english
				 * @brief Method of the production of a key pair of the hybrid mechanism from a seed
				 * @param kem  the key encapsulation mechanism
				 * @param seed the seed of thirty two bytes
				 * @return     the flag of the success of the production
				 * @details The function DeriveKeyPair of the section 5.5 of draft-irtf-cfrg-hybrid-kems
				 *          (the CG framework): the seed is expanded by SHAKE256 into the ML-KEM seed and
				 *          the group seed, the ML-KEM key pair is produced from the first, the group
				 *          scalar is selected from the second
				 *
				 * \~
				 *
				 */
				bool grown(const kem_t kem, const view_t & seed) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности пары ключей
				 *
				 * @return признак того, что пара ключей установлена
				 *
				 * \~english
				 * @brief Method of checking the readiness of the key pair
				 * @return the flag that the key pair is set
				 *
				 * \~
				 *
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения способа инкапсуляции ключа
				 *
				 * @return способ инкапсуляции ключа
				 *
				 * \~english
				 * @brief Method of getting the key encapsulation mechanism
				 * @return the key encapsulation mechanism
				 *
				 * \~
				 *
				 */
				kem_t kem() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения секретного ключа
				 *
				 * @return просмотр секретного ключа либо пустой просмотр у неготовой пары
				 *
				 * \~english
				 * @brief Method of getting the secret key
				 * @return the view of the secret key or an empty view for a key pair that is not ready
				 *
				 * \~
				 *
				 */
				view_t secret() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения открытого ключа
				 *
				 * @return просмотр открытого ключа либо пустой просмотр у неготовой пары
				 *
				 * \~english
				 * @brief Method of getting the public key
				 * @return the view of the public key or an empty view for a key pair that is not ready
				 *
				 * \~
				 *
				 */
				view_t point() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод выработки пары ключей из случайных байтов
				 *
				 * @param kem способ инкапсуляции ключа
				 * @return    причина отказа либо NONE
				 *
				 * \~english
				 * @brief Method of the production of a key pair from random bytes
				 * @param kem the key encapsulation mechanism
				 * @return    the reason of a failure or NONE
				 *
				 * \~
				 *
				 */
				error_t generate(const kem_t kem) noexcept;
				/**
				 * \~russian
				 * @brief Метод выработки пары ключей из исходного материала
				 *
				 * @param kem      способ инкапсуляции ключа
				 * @param material исходный ключевой материал длиной не короче material(kem)
				 * @return         причина отказа либо NONE
				 *
				 * @details Функция DeriveKeyPair раздела 7.1.3 RFC 9180 у способов Диффи-Хеллмана:
				 *          секретный ключ выводится растяжением метки «sk» из извлечения материала
				 *          с меткой «dkp_prk» (у кривых NIST - отбором кандидатов с меткой
				 *          «candidate»). У чистого ML-KEM и гибридов - вывод зерна одноступенчатой
				 *          функцией SHAKE256 с меткой «DeriveKeyPair» по draft-ietf-hpke-pq
				 *
				 * \~english
				 * @brief Method of the production of a key pair from the input keying material
				 * @param kem      the key encapsulation mechanism
				 * @param material the input keying material no shorter than material(kem)
				 * @return         the reason of a failure or NONE
				 * @details The function DeriveKeyPair of the section 7.1.3 of RFC 9180 at the Diffie-Hellman
				 *          mechanisms: the secret key is derived by the expansion of the label «sk» from the
				 *          extraction of the material with the label «dkp_prk» (at the NIST curves - by the
				 *          selection of candidates with the label «candidate»). At the pure ML-KEM and the
				 *          hybrids - the derivation of a seed by the one-stage function SHAKE256 with the
				 *          label «DeriveKeyPair» by draft-ietf-hpke-pq
				 *
				 * \~
				 *
				 */
				error_t derive(const kem_t kem, const view_t & material) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки пары ключей по секретному ключу
				 *
				 * @param kem    способ инкапсуляции ключа
				 * @param secret секретный ключ длиной secret(kem)
				 * @return       причина отказа либо NONE
				 *
				 * \~english
				 * @brief Method of setting the key pair by the secret key
				 * @param kem    the key encapsulation mechanism
				 * @param secret the secret key with the length secret(kem)
				 * @return       the reason of a failure or NONE
				 *
				 * \~
				 *
				 */
				error_t set(const kem_t kem, const view_t & secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод стирания пары ключей
				 *
				 * \~english
				 * @brief Method of wiping the key pair
				 *
				 * \~
				 *
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор пустой пары ключей
				 *
				 * \~english
				 * @brief Constructor of an empty key pair
				 *
				 * \~
				 *
				 */
				Key() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор: стирает секретный ключ
				 *
				 * \~english
				 * @brief Destructor: wipes the secret key
				 *
				 * \~
				 *
				 */
				~Key() noexcept;
		} key_t;

		/**
		 * \~russian
		 * @brief Состояние связи HPKE
		 *
		 * @details Раздел 5.2 RFC 9180: ключ шифра, начальное заполнение, порядковый номер и
		 *          секрет экспорта, выработанные расписанием ключей. У отправителя доступно
		 *          зашифрование, у получателя — расшифрование, экспорт доступен обоим.
		 *          Начальное заполнение всякого сообщения — base_nonce XOR порядковый номер,
		 *          номер растёт на единицу после каждого сообщения.
		 *
		 * \~english
		 * @brief HPKE context
		 * @details The section 5.2 of RFC 9180: the cipher key, the base nonce, the sequence
		 *          number and the exporter secret produced by the key schedule. The sender has the
		 *          sealing, the recipient — the opening, the export is available to both. The
		 *          nonce of every message is base_nonce XOR the sequence number, the number grows
		 *          by one after every message.
		 *
		 * \~
		 *
		 */
		/**
		 * Предварительные объявления функций установки состояния: они дружественны
		 * контексту, а у MSVC первое объявление задаёт связывание - дружественное без
		 * признака экспорта спорило бы с экспортируемым объявлением ниже (C2375)
		 */
		class Context;
		__ANTS_SHARED_EXPORT__ error_t sender(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, const key_t & ephemeral, uint8_t * enc, Context & context) noexcept;
		__ANTS_SHARED_EXPORT__ error_t recipient(const suite_t & suite, const regime_t mode, const key_t & own, const view_t & enc, const view_t & info, const shared_t & psk, const view_t & authenticator, Context & context) noexcept;
		typedef class __ANTS_SHARED_EXPORT__ Context {
			private:
				// Признак того, что состояние установлено
				bool _ready;
				// Признак стороны отправителя
				bool _sender;
			private:
				// Набор алгоритмов
				suite_t _suite;
			private:
				// Порядковый номер следующего сообщения
				uint64_t _sequence;
			private:
				// Ключ шифра
				uint8_t _key[KEY_SIZE];
				// Начальное заполнение
				uint8_t _nonce[NONCE_SIZE];
				// Секрет экспорта
				uint8_t _exporter[HASH_SIZE];
			private:
				// Развёрнутый ключ шифра AES
				cipher::aes_t _aes;
			private:
				/**
				 * Дружественные функции установки состояния
				 */
				friend error_t sender(const suite_t &, const regime_t, const view_t &, const view_t &, const shared_t &, const key_t *, const key_t &, uint8_t *, Context &) noexcept;
				friend error_t recipient(const suite_t &, const regime_t, const key_t &, const view_t &, const view_t &, const shared_t &, const view_t &, Context &) noexcept;
			private:
				/**
				 * \~russian
				 * @brief Метод установки состояния по общему значению
				 *
				 * @param suite  набор алгоритмов
				 * @param mode   режим работы
				 * @param shared общее значение способа инкапсуляции
				 * @param info   привязка к применению
				 * @param psk    заранее разделённый ключ с опознавателем
				 * @param sender признак стороны отправителя
				 * @return       причина отказа либо NONE
				 *
				 * \~english
				 * @brief Method of setting up the context by the shared secret
				 * @param suite  the ciphersuite
				 * @param mode   the mode of the work
				 * @param shared the shared secret of the encapsulation mechanism
				 * @param info   the application binding
				 * @param psk    the pre-shared key with the identifier
				 * @param sender the flag of the side of the sender
				 * @return       the reason of a failure or NONE
				 *
				 * \~
				 *
				 */
				error_t setup(const suite_t & suite, const regime_t mode, const view_t & shared, const view_t & info, const shared_t & psk, const bool sender) noexcept;
				/**
				 * \~russian
				 * @brief Метод выработки начального заполнения сообщения
				 *
				 * @param result место под начальное заполнение длиной NONCE_SIZE
				 *
				 * \~english
				 * @brief Method of the production of the nonce of a message
				 * @param result the room for the nonce with the length NONCE_SIZE
				 *
				 * \~
				 *
				 */
				void mask(uint8_t * result) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности состояния
				 *
				 * @return признак того, что состояние установлено
				 *
				 * \~english
				 * @brief Method of checking the readiness of the context
				 * @return the flag that the context is set up
				 *
				 * \~
				 *
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения набора алгоритмов
				 *
				 * @return набор алгоритмов состояния
				 *
				 * \~english
				 * @brief Method of getting the ciphersuite
				 * @return the ciphersuite of the context
				 *
				 * \~
				 *
				 */
				const suite_t & suite() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения порядкового номера следующего сообщения
				 *
				 * @return порядковый номер следующего сообщения
				 *
				 * \~english
				 * @brief Method of getting the sequence number of the next message
				 * @return the sequence number of the next message
				 *
				 * \~
				 *
				 */
				uint64_t sequence() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки порядкового номера следующего сообщения
				 *
				 * @param sequence порядковый номер следующего сообщения
				 * @return         причина отказа либо NONE
				 *
				 * @details Раздел 9.7.1 RFC 9180 допускает явные порядковые номера у переписки,
				 *          где сообщения приходят не по порядку; повторное применение номера у
				 *          отправителя — дело потребителя, модуль его не сторожит
				 *
				 * \~english
				 * @brief Method of setting the sequence number of the next message
				 * @param sequence the sequence number of the next message
				 * @return         the reason of a failure or NONE
				 * @details The section 9.7.1 of RFC 9180 allows explicit sequence numbers for a
				 *          correspondence where messages arrive out of order; the reuse of a number by
				 *          the sender is up to the consumer, the module does not guard it
				 *
				 * \~
				 *
				 */
				error_t sequence(const uint64_t sequence) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод зашифрования сообщения
				 *
				 * @param associated связанные данные, вправе быть пустыми
				 * @param source     открытый текст, вправе быть пустым
				 * @param result     место под шифртекст с меткой подлинности длиной source.size + TAG_SIZE
				 * @return           причина отказа либо NONE
				 *
				 * \~english
				 * @brief Method of sealing a message
				 * @param associated the associated data, may be empty
				 * @param source     the plaintext, may be empty
				 * @param result     the room for the ciphertext with the tag with the length source.size + TAG_SIZE
				 * @return           the reason of a failure or NONE
				 *
				 * \~
				 *
				 */
				error_t seal(const view_t & associated, const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод зашифрования сообщения в накопитель
				 *
				 * @param associated связанные данные, вправе быть пустыми
				 * @param source     открытый текст, вправе быть пустым
				 * @param result     накопитель шифртекста с меткой подлинности
				 * @return           причина отказа либо NONE
				 *
				 * \~english
				 * @brief Method of sealing a message into a buffer
				 * @param associated the associated data, may be empty
				 * @param source     the plaintext, may be empty
				 * @param result     the buffer of the ciphertext with the tag
				 * @return           the reason of a failure or NONE
				 *
				 * \~
				 *
				 */
				error_t seal(const view_t & associated, const view_t & source, vector <uint8_t> & result) noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования сообщения
				 *
				 * @param associated связанные данные, вправе быть пустыми
				 * @param source     шифртекст с меткой подлинности длиной не короче TAG_SIZE
				 * @param result     место под открытый текст длиной source.size - TAG_SIZE
				 * @return           причина отказа либо NONE
				 *
				 * @details При отказе подлинности место под открытый текст стирается
				 *
				 * \~english
				 * @brief Method of opening a message
				 * @param associated the associated data, may be empty
				 * @param source     the ciphertext with the tag no shorter than TAG_SIZE
				 * @param result     the room for the plaintext with the length source.size - TAG_SIZE
				 * @return           the reason of a failure or NONE
				 * @details On a failure of the authenticity the room for the plaintext is wiped
				 *
				 * \~
				 *
				 */
				error_t open(const view_t & associated, const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования сообщения в накопитель
				 *
				 * @param associated связанные данные, вправе быть пустыми
				 * @param source     шифртекст с меткой подлинности длиной не короче TAG_SIZE
				 * @param result     накопитель открытого текста
				 * @return           причина отказа либо NONE
				 *
				 * \~english
				 * @brief Method of opening a message into a buffer
				 * @param associated the associated data, may be empty
				 * @param source     the ciphertext with the tag no shorter than TAG_SIZE
				 * @param result     the buffer of the plaintext
				 * @return           the reason of a failure or NONE
				 *
				 * \~
				 *
				 */
				error_t open(const view_t & associated, const view_t & source, vector <uint8_t> & result) noexcept;
				/**
				 * \~russian
				 * @brief Метод выработки секрета экспорта
				 *
				 * @param context привязка секрета, вправе быть пустой
				 * @param result  место под секрет
				 * @param size    длина секрета в байтах, не больше 255 длин хеша функции выработки ключа
				 * @return        причина отказа либо NONE
				 *
				 * @details Раздел 5.3 RFC 9180: растяжение секрета экспорта меткой «sec»
				 *
				 * \~english
				 * @brief Method of the production of an exported secret
				 * @param context the binding of the secret, may be empty
				 * @param result  the room for the secret
				 * @param size    the length of the secret in bytes, not more than 255 hash lengths of the key derivation function
				 * @return        the reason of a failure or NONE
				 * @details The section 5.3 of RFC 9180: the expansion of the exporter secret with the label «sec»
				 *
				 * \~
				 *
				 */
				error_t exporter(const view_t & context, uint8_t * result, const size_t size) const noexcept;
				/**
				 * \~russian
				 * @brief Метод стирания состояния
				 *
				 * \~english
				 * @brief Method of wiping the context
				 *
				 * \~
				 *
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор пустого состояния
				 *
				 * \~english
				 * @brief Constructor of an empty context
				 *
				 * \~
				 *
				 */
				Context() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор: стирает ключи
				 *
				 * \~english
				 * @brief Destructor: wipes the keys
				 *
				 * \~
				 *
				 */
				~Context() noexcept;
		} context_t;

		/**
		 * \~russian
		 * @brief Метод инкапсуляции ключа
		 *
		 * @param ephemeral     мимолётная пара ключей отправителя
		 * @param point         открытый ключ получателя длиной length(suite.kem)
		 * @param authenticator пара ключей отправителя для подлинности либо nullptr
		 * @param shared        место под общее значение длиной не короче KEM_SHARED
		 * @param result        место под инкапсулированный ключ длиной overhead(suite.kem)
		 * @return              причина отказа либо NONE
		 *
		 * @details Функции Encap и AuthEncap раздела 7.1.1 RFC 9180. Мимолётная пара подаётся
		 *          доводом ради воспроизводимости; в работе её вырабатывает `sender`
		 *
		 * \~english
		 * @brief Method of the key encapsulation
		 * @param ephemeral     the ephemeral key pair of the sender
		 * @param point         the public key of the recipient with the length length(suite.kem)
		 * @param authenticator the key pair of the sender for the authentication or nullptr
		 * @param shared        the room for the shared secret no shorter than KEM_SHARED
		 * @param result        the room for the encapsulated key with the length overhead(suite.kem)
		 * @return              the reason of a failure or NONE
		 * @details The functions Encap and AuthEncap of the section 7.1.1 of RFC 9180. The ephemeral
		 *          key pair is given as an argument for the reproducibility; in the work it is
		 *          produced by `sender`
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t encapsulate(const key_t & ephemeral, const view_t & point, const key_t * authenticator, uint8_t * shared, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод декапсуляции ключа
		 *
		 * @param own           пара ключей получателя
		 * @param enc           инкапсулированный ключ длиной overhead(suite.kem)
		 * @param authenticator открытый ключ отправителя для подлинности либо пустой просмотр
		 * @param shared        место под общее значение длиной не короче KEM_SHARED
		 * @return              причина отказа либо NONE
		 *
		 * @details Функции Decap и AuthDecap раздела 7.1.1 RFC 9180
		 *
		 * \~english
		 * @brief Method of the key decapsulation
		 * @param own           the key pair of the recipient
		 * @param enc           the encapsulated key with the length overhead(suite.kem)
		 * @param authenticator the public key of the sender for the authentication or an empty view
		 * @param shared        the room for the shared secret no shorter than KEM_SHARED
		 * @return              the reason of a failure or NONE
		 * @details The functions Decap and AuthDecap of the section 7.1.1 of RFC 9180
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t decapsulate(const key_t & own, const view_t & enc, const view_t & authenticator, uint8_t * shared) noexcept;

		/**
		 * \~russian
		 * @brief Метод установки состояния отправителя по заданной мимолётной паре
		 *
		 * @param suite         набор алгоритмов
		 * @param mode          режим работы
		 * @param point         открытый ключ получателя длиной length(suite.kem)
		 * @param info          привязка к применению, вправе быть пустой
		 * @param psk           заранее разделённый ключ с опознавателем: непустой в режимах PSK и AUTH_PSK
		 * @param authenticator пара ключей отправителя: задана в режимах AUTH и AUTH_PSK, иначе nullptr
		 * @param ephemeral     мимолётная пара ключей отправителя
		 * @param enc           место под инкапсулированный ключ длиной overhead(suite.kem)
		 * @param context       состояние связи отправителя
		 * @return              причина отказа либо NONE
		 *
		 * @details Функции SetupBaseS, SetupPSKS, SetupAuthS и SetupAuthPSKS раздела 5.1 RFC 9180
		 *          с мимолётной парой, заданной снаружи: так воспроизводятся вектора стандарта
		 *
		 * \~english
		 * @brief Method of setting up the context of the sender by a given ephemeral key pair
		 * @param suite         the ciphersuite
		 * @param mode          the mode of the work
		 * @param point         the public key of the recipient with the length length(suite.kem)
		 * @param info          the application binding, may be empty
		 * @param psk           the pre-shared key with the identifier: non-empty in the modes PSK and AUTH_PSK
		 * @param authenticator the key pair of the sender: given in the modes AUTH and AUTH_PSK, otherwise nullptr
		 * @param ephemeral     the ephemeral key pair of the sender
		 * @param enc           the room for the encapsulated key with the length overhead(suite.kem)
		 * @param context       the context of the sender
		 * @return              the reason of a failure or NONE
		 * @details The functions SetupBaseS, SetupPSKS, SetupAuthS and SetupAuthPSKS of the section 5.1
		 *          of RFC 9180 with the ephemeral key pair given from outside: this is how the test
		 *          vectors of the standard are reproduced
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t sender(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, const key_t & ephemeral, uint8_t * enc, context_t & context) noexcept;
		/**
		 * \~russian
		 * @brief Метод установки состояния отправителя
		 *
		 * @param suite         набор алгоритмов
		 * @param mode          режим работы
		 * @param point         открытый ключ получателя длиной length(suite.kem)
		 * @param info          привязка к применению, вправе быть пустой
		 * @param psk           заранее разделённый ключ с опознавателем: непустой в режимах PSK и AUTH_PSK
		 * @param authenticator пара ключей отправителя: задана в режимах AUTH и AUTH_PSK, иначе nullptr
		 * @param enc           место под инкапсулированный ключ длиной overhead(suite.kem)
		 * @param context       состояние связи отправителя
		 * @return              причина отказа либо NONE
		 *
		 * @details Мимолётная пара ключей вырабатывается из случайных байтов и стирается
		 *
		 * \~english
		 * @brief Method of setting up the context of the sender
		 * @param suite         the ciphersuite
		 * @param mode          the mode of the work
		 * @param point         the public key of the recipient with the length length(suite.kem)
		 * @param info          the application binding, may be empty
		 * @param psk           the pre-shared key with the identifier: non-empty in the modes PSK and AUTH_PSK
		 * @param authenticator the key pair of the sender: given in the modes AUTH and AUTH_PSK, otherwise nullptr
		 * @param enc           the room for the encapsulated key with the length overhead(suite.kem)
		 * @param context       the context of the sender
		 * @return              the reason of a failure or NONE
		 * @details The ephemeral key pair is produced from random bytes and is wiped
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t sender(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, uint8_t * enc, context_t & context) noexcept;
		/**
		 * \~russian
		 * @brief Метод установки состояния получателя
		 *
		 * @param suite         набор алгоритмов
		 * @param mode          режим работы
		 * @param own           пара ключей получателя
		 * @param enc           инкапсулированный ключ длиной overhead(suite.kem)
		 * @param info          привязка к применению, вправе быть пустой
		 * @param psk           заранее разделённый ключ с опознавателем: непустой в режимах PSK и AUTH_PSK
		 * @param authenticator открытый ключ отправителя: задан в режимах AUTH и AUTH_PSK, иначе пустой просмотр
		 * @param context       состояние связи получателя
		 * @return              причина отказа либо NONE
		 *
		 * @details Функции SetupBaseR, SetupPSKR, SetupAuthR и SetupAuthPSKR раздела 5.1 RFC 9180
		 *
		 * \~english
		 * @brief Method of setting up the context of the recipient
		 * @param suite         the ciphersuite
		 * @param mode          the mode of the work
		 * @param own           the key pair of the recipient
		 * @param enc           the encapsulated key with the length overhead(suite.kem)
		 * @param info          the application binding, may be empty
		 * @param psk           the pre-shared key with the identifier: non-empty in the modes PSK and AUTH_PSK
		 * @param authenticator the public key of the sender: given in the modes AUTH and AUTH_PSK, otherwise an empty view
		 * @param context       the context of the recipient
		 * @return              the reason of a failure or NONE
		 * @details The functions SetupBaseR, SetupPSKR, SetupAuthR and SetupAuthPSKR of the section 5.1 of RFC 9180
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t recipient(const suite_t & suite, const regime_t mode, const key_t & own, const view_t & enc, const view_t & info, const shared_t & psk, const view_t & authenticator, context_t & context) noexcept;

		/**
		 * \~russian
		 * @brief Метод зашифрования одного сообщения
		 *
		 * @param suite         набор алгоритмов
		 * @param mode          режим работы
		 * @param point         открытый ключ получателя длиной length(suite.kem)
		 * @param info          привязка к применению, вправе быть пустой
		 * @param psk           заранее разделённый ключ с опознавателем по режиму
		 * @param authenticator пара ключей отправителя по режиму либо nullptr
		 * @param associated    связанные данные, вправе быть пустыми
		 * @param source        открытый текст, вправе быть пустым
		 * @param enc           накопитель инкапсулированного ключа
		 * @param result        накопитель шифртекста с меткой подлинности
		 * @return              причина отказа либо NONE
		 *
		 * @details Одношаговая обёртка раздела 6.1 RFC 9180: установка состояния и одно зашифрование
		 *
		 * \~english
		 * @brief Method of sealing a single message
		 * @param suite         the ciphersuite
		 * @param mode          the mode of the work
		 * @param point         the public key of the recipient with the length length(suite.kem)
		 * @param info          the application binding, may be empty
		 * @param psk           the pre-shared key with the identifier according to the mode
		 * @param authenticator the key pair of the sender according to the mode or nullptr
		 * @param associated    the associated data, may be empty
		 * @param source        the plaintext, may be empty
		 * @param enc           the buffer of the encapsulated key
		 * @param result        the buffer of the ciphertext with the tag
		 * @return              the reason of a failure or NONE
		 * @details The single-shot wrapper of the section 6.1 of RFC 9180: the setup of the context and one sealing
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t seal(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, const view_t & associated, const view_t & source, vector <uint8_t> & enc, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод расшифрования одного сообщения
		 *
		 * @param suite         набор алгоритмов
		 * @param mode          режим работы
		 * @param own           пара ключей получателя
		 * @param enc           инкапсулированный ключ длиной overhead(suite.kem)
		 * @param info          привязка к применению, вправе быть пустой
		 * @param psk           заранее разделённый ключ с опознавателем по режиму
		 * @param authenticator открытый ключ отправителя по режиму либо пустой просмотр
		 * @param associated    связанные данные, вправе быть пустыми
		 * @param source        шифртекст с меткой подлинности
		 * @param result        накопитель открытого текста
		 * @return              причина отказа либо NONE
		 *
		 * @details Одношаговая обёртка раздела 6.1 RFC 9180: установка состояния и одно расшифрование
		 *
		 * \~english
		 * @brief Method of opening a single message
		 * @param suite         the ciphersuite
		 * @param mode          the mode of the work
		 * @param own           the key pair of the recipient
		 * @param enc           the encapsulated key with the length overhead(suite.kem)
		 * @param info          the application binding, may be empty
		 * @param psk           the pre-shared key with the identifier according to the mode
		 * @param authenticator the public key of the sender according to the mode or an empty view
		 * @param associated    the associated data, may be empty
		 * @param source        the ciphertext with the tag
		 * @param result        the buffer of the plaintext
		 * @return              the reason of a failure or NONE
		 * @details The single-shot wrapper of the section 6.1 of RFC 9180: the setup of the context and one opening
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t open(const suite_t & suite, const regime_t mode, const key_t & own, const view_t & enc, const view_t & info, const shared_t & psk, const view_t & authenticator, const view_t & associated, const view_t & source, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки секрета экспорта отправителем за один шаг
		 *
		 * @param suite         набор алгоритмов
		 * @param mode          режим работы
		 * @param point         открытый ключ получателя длиной length(suite.kem)
		 * @param info          привязка к применению, вправе быть пустой
		 * @param psk           заранее разделённый ключ с опознавателем по режиму
		 * @param authenticator пара ключей отправителя по режиму либо nullptr
		 * @param context       привязка секрета, вправе быть пустой
		 * @param size          длина секрета в байтах
		 * @param enc           накопитель инкапсулированного ключа
		 * @param result        накопитель секрета
		 * @return              причина отказа либо NONE
		 *
		 * @details Одношаговая обёртка SendExport раздела 6.2 RFC 9180
		 *
		 * \~english
		 * @brief Method of the production of an exported secret by the sender in a single step
		 * @param suite         the ciphersuite
		 * @param mode          the mode of the work
		 * @param point         the public key of the recipient with the length length(suite.kem)
		 * @param info          the application binding, may be empty
		 * @param psk           the pre-shared key with the identifier according to the mode
		 * @param authenticator the key pair of the sender according to the mode or nullptr
		 * @param context       the binding of the secret, may be empty
		 * @param size          the length of the secret in bytes
		 * @param enc           the buffer of the encapsulated key
		 * @param result        the buffer of the secret
		 * @return              the reason of a failure or NONE
		 * @details The single-shot wrapper SendExport of the section 6.2 of RFC 9180
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t dispatch(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, const view_t & context, const size_t size, vector <uint8_t> & enc, vector <uint8_t> & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки секрета экспорта получателем за один шаг
		 *
		 * @param suite         набор алгоритмов
		 * @param mode          режим работы
		 * @param own           пара ключей получателя
		 * @param enc           инкапсулированный ключ длиной overhead(suite.kem)
		 * @param info          привязка к применению, вправе быть пустой
		 * @param psk           заранее разделённый ключ с опознавателем по режиму
		 * @param authenticator открытый ключ отправителя по режиму либо пустой просмотр
		 * @param context       привязка секрета, вправе быть пустой
		 * @param size          длина секрета в байтах
		 * @param result        накопитель секрета
		 * @return              причина отказа либо NONE
		 *
		 * @details Одношаговая обёртка ReceiveExport раздела 6.2 RFC 9180
		 *
		 * \~english
		 * @brief Method of the production of an exported secret by the recipient in a single step
		 * @param suite         the ciphersuite
		 * @param mode          the mode of the work
		 * @param own           the key pair of the recipient
		 * @param enc           the encapsulated key with the length overhead(suite.kem)
		 * @param info          the application binding, may be empty
		 * @param psk           the pre-shared key with the identifier according to the mode
		 * @param authenticator the public key of the sender according to the mode or an empty view
		 * @param context       the binding of the secret, may be empty
		 * @param size          the length of the secret in bytes
		 * @param result        the buffer of the secret
		 * @return              the reason of a failure or NONE
		 * @details The single-shot wrapper ReceiveExport of the section 6.2 of RFC 9180
		 *
		 * \~
		 *
		 */
		__ANTS_SHARED_EXPORT__ error_t receive(const suite_t & suite, const regime_t mode, const key_t & own, const view_t & enc, const view_t & info, const shared_t & psk, const view_t & authenticator, const view_t & context, const size_t size, vector <uint8_t> & result) noexcept;
	};
};

