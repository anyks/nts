/**
 * @file slhdsa.hpp
 * @date 2026-10-03
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
 * @brief Заголовочный файл модуля выработки и проверки электронной подписи
 *        SLH-DSA (модуль безсостоянной хешированной подписи) по FIPS 205
 *
 * \~english
 * @brief Header file of the module of the production and the check of the
 *        electronic signature SLH-DSA (stateless hash-based signature module)
 *        according to FIPS 205
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
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

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
	 * @brief Пространство имён модулей электронной подписи
	 *
	 * \~english
	 * @brief Namespace of the electronic signature modules
	 *
	 * \~
	 */
	namespace sign {
		/**
		 * \~russian
		 * @brief Электронная подпись SLH-DSA по FIPS 205
		 *
		 * @details Гипердерево из d деревьев XMSS высотой h′ каждое поверх леса
		 *          FORS: подпись - R ‖ k × (sk ‖ путь) FORS ‖ d подписей XMSS.
		 *          Ключ подписи - четыре значения по n байтов: SK.seed ‖ SK.prf ‖
		 *          PK.seed ‖ PK.root; ключ проверки - PK.seed ‖ PK.root. Зерно
		 *          порождения - три значения по n байтов: SK.seed ‖ SK.prf ‖
		 *          PK.seed. Подписывается сообщение с обвязкой 0x00 ‖ длина
		 *          контекста ‖ контекст ‖ сообщение; контекст в TLS пустой.
		 *          Двенадцать наборов параметров: SHA2 либо SHAKE по категориям
		 *          стойкости 1, 3 и 5 в вариантах малых (s) и быстрых (f).
		 *
		 * @note Выработка подписи идёт за постоянное время по ключу в части
		 *       секретных значений; проверка подписи секретов не касается и
		 *       вправе идти переменным временем
		 *
		 * \~english
		 * @brief Electronic signature SLH-DSA according to FIPS 205
		 * @details A hypertree of d XMSS trees of the height h′ each over a FORS
		 *          forest: the signature is R ‖ k × (sk ‖ path) FORS ‖ d XMSS
		 *          signatures. The key of the signature is four values of n bytes:
		 *          SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root; the key of the check is
		 *          PK.seed ‖ PK.root. The generation seed is three values of n
		 *          bytes: SK.seed ‖ SK.prf ‖ PK.seed. The message is signed with
		 *          the wrapper 0x00 ‖ length of the context ‖ context ‖ message;
		 *          the context in TLS is empty. Twelve parameter sets: SHA2 or
		 *          SHAKE by the security categories 1, 3 and 5 in the small (s)
		 *          and fast (f) variants.
		 * @note The production of the signature goes in a constant time by the key
		 *       in the part of secret values; the check of the signature touches
		 *       no secrets and may go in a variable time
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Slhdsa {
			public:
				/**
				 * \~russian
				 * @brief Наборы параметров стандарта
				 *
				 * \~english
				 * @brief Parameter sets of the standard
				 *
				 * \~
				 */
				enum class set_t : uint8_t {
					NONE        = 0x00, /*!< \~russian Набор не установлен \~english The set is not set \~ */
					SHA2_128S   = 0x01, /*!< \~russian SLH-DSA-SHA2-128s \~english SLH-DSA-SHA2-128s \~ */
					SHAKE_128S  = 0x02, /*!< \~russian SLH-DSA-SHAKE-128s \~english SLH-DSA-SHAKE-128s \~ */
					SHA2_128F   = 0x03, /*!< \~russian SLH-DSA-SHA2-128f \~english SLH-DSA-SHA2-128f \~ */
					SHAKE_128F  = 0x04, /*!< \~russian SLH-DSA-SHAKE-128f \~english SLH-DSA-SHAKE-128f \~ */
					SHA2_192S   = 0x05, /*!< \~russian SLH-DSA-SHA2-192s \~english SLH-DSA-SHA2-192s \~ */
					SHAKE_192S  = 0x06, /*!< \~russian SLH-DSA-SHAKE-192s \~english SLH-DSA-SHAKE-192s \~ */
					SHA2_192F   = 0x07, /*!< \~russian SLH-DSA-SHA2-192f \~english SLH-DSA-SHA2-192f \~ */
					SHAKE_192F  = 0x08, /*!< \~russian SLH-DSA-SHAKE-192f \~english SLH-DSA-SHAKE-192f \~ */
					SHA2_256S   = 0x09, /*!< \~russian SLH-DSA-SHA2-256s \~english SLH-DSA-SHA2-256s \~ */
					SHAKE_256S  = 0x0A, /*!< \~russian SLH-DSA-SHAKE-256s \~english SLH-DSA-SHAKE-256s \~ */
					SHA2_256F   = 0x0B, /*!< \~russian SLH-DSA-SHA2-256f \~english SLH-DSA-SHA2-256f \~ */
					SHAKE_256F  = 0x0C  /*!< \~russian SLH-DSA-SHAKE-256f \~english SLH-DSA-SHAKE-256f \~ */
				};
			private:
				/**
				 * Набор параметров ключа
				 */
				set_t _set;
				/**
				 * Признак установленного ключа подписи
				 */
				bool _secret;
				/**
				 * Признак установленного ключа проверки подписи
				 */
				bool _public;
				/**
				 * Запись ключа подписи: SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root
				 */
				uint8_t _key[128];
				/**
				 * Запись ключа проверки: PK.seed ‖ PK.root
				 */
				uint8_t _pkey[64];
			public:
				/**
				 * \~russian
				 * @brief Метод получения набора параметров ключа
				 *
				 * @return набор параметров ключа, NONE без ключа
				 *
				 * \~english
				 * @brief Method of getting the parameter set of the key
				 * @return the parameter set of the key, NONE without a key
				 *
				 * \~
				 */
				set_t set() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера подписи
				 *
				 * @return размер подписи в байтах, ноль без ключа
				 *
				 * \~english
				 * @brief Method of getting the size of the signature
				 * @return the size of the signature in bytes, zero without a key
				 *
				 * \~
				 */
				size_t size() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения верхнего предела длины подписи в записанном виде
				 *
				 * @return верхний предел длины подписи в байтах, ноль без ключа
				 *
				 * \~english
				 * @brief Method of getting the upper bound of the signature length in the written form
				 * @return the upper bound of the signature length in bytes, zero without a key
				 *
				 * \~
				 */
				size_t limit() const noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния модуля
				 *
				 * \~english
				 * @brief Method of the reset of the module state
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения размера зерна порождения набора в байтах
				 *
				 * @param set набор параметров
				 *
				 * @return    размер зерна порождения в байтах (3n), ноль у несуществующего набора
				 *
				 * \~english
				 * @brief Method of getting the size of the generation seed of the set in bytes
				 * @param set the parameter set
				 * @return    the size of the generation seed in bytes (3n), zero at a nonexistent set
				 *
				 * \~
				 */
				static size_t seedSize(const set_t set) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера ключа подписи набора в байтах
				 *
				 * @param set набор параметров
				 *
				 * @return    размер ключа подписи в байтах (4n), ноль у несуществующего набора
				 *
				 * \~english
				 * @brief Method of getting the size of the key of the signature of the set in bytes
				 * @param set the parameter set
				 * @return    the size of the key of the signature in bytes (4n), zero at a nonexistent set
				 *
				 * \~
				 */
				static size_t secretSize(const set_t set) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера ключа проверки набора в байтах
				 *
				 * @param set набор параметров
				 *
				 * @return    размер ключа проверки в байтах (2n), ноль у несуществующего набора
				 *
				 * \~english
				 * @brief Method of getting the size of the key of the check of the set in bytes
				 * @param set the parameter set
				 * @return    the size of the key of the check in bytes (2n), zero at a nonexistent set
				 *
				 * \~
				 */
				static size_t publicSize(const set_t set) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера подписи набора в байтах
				 *
				 * @param set набор параметров
				 *
				 * @return    размер подписи в байтах, ноль у несуществующего набора
				 *
				 * \~english
				 * @brief Method of getting the size of the signature of the set in bytes
				 * @param set the parameter set
				 * @return    the size of the signature in bytes, zero at a nonexistent set
				 *
				 * \~
				 */
				static size_t signatureSize(const set_t set) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод порождения долговременного ключа подписи из зерна
				 *
				 * @param set    набор параметров
				 * @param seed   зерно выработки длиной 3n байтов: SK.seed ‖ SK.prf ‖ PK.seed
				 * @param key    место, в которое помещается ключ проверки PK.seed ‖ PK.root
				 * @param secret место, в которое помещается ключ подписи SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root
				 *
				 * @return       признак успешности порождения ключа
				 *
				 * @details Раздел 10.1 FIPS 205: корень PK.root вычисляется вершиной
				 *          дерева верхнего слоя из зерна - на одном зерне выходит
				 *          один и тот же ключ
				 *
				 * \~english
				 * @brief Method of the generation of a long-term key of the signature from a seed
				 * @param set    the parameter set
				 * @param seed   the generation seed of a length of 3n bytes: SK.seed ‖ SK.prf ‖ PK.seed
				 * @param key    the place the key of the check PK.seed ‖ PK.root is put into
				 * @param secret the place the key of the signature SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root is put into
				 * @return       the flag of the success of the key generation
				 * @details Section 10.1 of FIPS 205: the root PK.root is computed by
				 *          the top of the upper layer tree from the seed - the same
				 *          seed gives the same key
				 *
				 * \~
				 */
				bool generate(const set_t set, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод порождения долговременного ключа подписи из источника случайности
				 *
				 * @param set    набор параметров
				 * @param key    место, в которое помещается ключ проверки PK.seed ‖ PK.root
				 * @param secret место, в которое помещается ключ подписи SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root
				 *
				 * @return       признак успешности порождения ключа
				 *
				 * @details Зерно выработки берётся из источника случайности целиком;
				 *          отказ источника отвечает отказом порождения
				 *
				 * \~english
				 * @brief Method of the generation of a long-term key of the signature from the source of randomness
				 * @param set    the parameter set
				 * @param key    the place the key of the check PK.seed ‖ PK.root is put into
				 * @param secret the place the key of the signature SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root is put into
				 * @return       the flag of the success of the key generation
				 * @details The generation seed is taken from the source of randomness
				 *          entirely; a refusal of the source answers by a refusal of
				 *          the generation
				 *
				 * \~
				 */
				bool generate(const set_t set, uint8_t * key, uint8_t * secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа подписи
				 *
				 * @param set    набор параметров ключа
				 * @param secret запись ключа подписи SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root по набору
				 *
				 * @return       признак успешности установки ключа подписи
				 *
				 * @details Ключ проверки выводится из записи ключа подписи сразу же:
				 *          корень PK.root вычисляется заново из SK.seed и PK.seed и
				 *          сличается с записанным, при несовпадении ключ отвергается
				 *
				 * \~english
				 * @brief Method of setting the key of the signature
				 * @param set    the parameter set of the key
				 * @param secret the record of the key of the signature SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root per set
				 * @return       the flag of the success of the setting of the key of the signature
				 * @details The key of the check is derived from the record of the key
				 *          of the signature at once: the root PK.root is computed anew
				 *          from SK.seed and PK.seed and collated with the written one,
				 *          at a mismatch the key is rejected
				 *
				 * \~
				 */
				bool secret(const set_t set, const view_t & secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа проверки подписи
				 *
				 * @param set набор параметров ключа
				 * @param key запись ключа проверки PK.seed ‖ PK.root по набору
				 *
				 * @return    признак успешности установки ключа проверки подписи
				 *
				 * \~english
				 * @brief Method of setting the key of the check of the signature
				 * @param set the parameter set of the key
				 * @param key the record of the key of the check PK.seed ‖ PK.root per set
				 * @return    the flag of the success of the setting of the key of the check
				 *
				 * \~
				 */
				bool key(const set_t set, const view_t & key) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения ключа проверки подписи
				 *
				 * @param result место, в которое записывается ключ проверки PK.seed ‖ PK.root по набору
				 * @param size   размер места, не меньше размера ключа проверки набора
				 *
				 * @return       признак успешности получения ключа проверки подписи
				 *
				 * \~english
				 * @brief Method of getting the key of the check of the signature
				 * @param result the place the key of the check PK.seed ‖ PK.root per set is written into
				 * @param size   the size of the place, not less than the size of the public key of the set
				 * @return       the flag of the success of the getting of the key of the check
				 *
				 * \~
				 */
				bool key(uint8_t * result, const size_t size) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод выработки подписи со случайностью от источника
				 *
				 * @param message подписываемое сообщение целиком
				 * @param context контекст подписи, до 255 байтов, в TLS пустой
				 * @param result  место, в которое помещается подпись R ‖ FORS ‖ HT по набору
				 *
				 * @return        признак успешности выработки подписи
				 *
				 * @details Раздел 10.2 FIPS 205: случайность opt_rand берётся из
				 *          источника целиком, оттого повтор выработки на одном ключе
				 *          и сообщении даёт разные подписи (хеджированная подпись)
				 *
				 * \~english
				 * @brief Method of the production of a signature with randomness from the source
				 * @param message the message being signed as a whole
				 * @param context the context of the signature, up to 255 bytes, empty in TLS
				 * @param result  the place the signature R ‖ FORS ‖ HT per set is put into
				 * @return        the flag of the success of the production of the signature
				 * @details Section 10.2 of FIPS 205: the randomness opt_rand is taken
				 *          from the source entirely, therefore a repetition of the
				 *          production on a single key and message gives different
				 *          signatures (hedged signature)
				 *
				 * \~
				 */
				bool make(const view_t & message, const view_t & context, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод выработки подписи с заданной случайностью
				 *
				 * @param rnd     случайность подписи, читаются первые n байтов
				 * @param message подписываемое сообщение целиком
				 * @param context контекст подписи, до 255 байтов, в TLS пустой
				 * @param result  место, в которое помещается подпись R ‖ FORS ‖ HT по набору
				 *
				 * @return        признак успешности выработки подписи
				 *
				 * @details Раздел 10.2 FIPS 205: случайность opt_rand подаётся извне,
				 *          оттого на одних rnd, ключе и сообщении выходит одна и та же
				 *          подпись; тридцать два нулевых байта дают детерминированный
				 *          вариант - случайностью служит PK.seed из ключа (примечание
				 *          стандарта)
				 *
				 * \~english
				 * @brief Method of the production of a signature with a given randomness
				 * @param rnd     the randomness of the signature, the first n bytes are read
				 * @param message the message being signed as a whole
				 * @param context the context of the signature, up to 255 bytes, empty in TLS
				 * @param result  the place the signature R ‖ FORS ‖ HT per set is put into
				 * @return        the flag of the success of the production of the signature
				 * @details Section 10.2 of FIPS 205: the randomness opt_rand is given
				 *          from the outside, therefore on the same rnd, key and message
				 *          the same signature comes out; thirty two zero bytes give
				 *          the deterministic variant - the randomness is PK.seed of
				 *          the key (the note of the standard)
				 *
				 * \~
				 */
				bool make(const view_t & rnd, const view_t & message, const view_t & context, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки подписи
				 *
				 * @param message   подписанное сообщение целиком
				 * @param context   контекст подписи, до 255 байтов, в TLS пустой
				 * @param signature проверяемая подпись R ‖ FORS ‖ HT по набору
				 *
				 * @return          признак того, что подпись сошлась
				 *
				 * @details Раздел 10.3 FIPS 205: длина записи обязана равняться
				 *          размеру подписи набора, а гипердерево обязано сойтись
				 *          с корнем ключа проверки
				 *
				 * \~english
				 * @brief Method of the check of a signature
				 * @param message   the signed message as a whole
				 * @param context   the context of the signature, up to 255 bytes, empty in TLS
				 * @param signature the signature being checked R ‖ FORS ‖ HT per set
				 * @return          the flag of the signature having converged
				 * @details Section 10.3 of FIPS 205: the length of the record must be
				 *          equal to the size of the signature of the set, and the
				 *          hypertree must converge with the root of the key of the check
				 *
				 * \~
				 */
				bool check(const view_t & message, const view_t & context, const view_t & signature) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Slhdsa() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Slhdsa() noexcept;
		} slhdsa_t;
	};
};

