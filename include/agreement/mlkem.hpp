/**
 * @file mlkem.hpp
 * @date 2026-09-07
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
 * @brief Модуль инкапсуляции ключа на решётках ML-KEM по FIPS 203
 *
 * \~english
 * @brief Module of the key encapsulation on lattices ML-KEM according to FIPS 203
 *
 * \~
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
	 * @brief Пространство имён модулей выработки общего ключа
	 *
	 * \~english
	 * @brief Namespace of the modules of the production of a shared key
	 *
	 * \~
	 */
	namespace agreement {
		/**
		 * \~russian
		 * @brief Длина зерна выработки пары ключей ML-KEM в байтах: d || z
		 *
		 * \~english
		 * @brief Length of the seed of the generation of an ML-KEM key pair in bytes: d || z
		 *
		 * \~
		 */
		static constexpr size_t MLKEM_SEED = 64;
		/**
		 * \~russian
		 * @brief Длина общего секрета ML-KEM в байтах
		 *
		 * \~english
		 * @brief Length of the ML-KEM shared secret in bytes
		 *
		 * \~
		 */
		static constexpr size_t MLKEM_SHARED = 32;
		/**
		 * \~russian
		 * @brief Длина случайного сообщения инкапсуляции в байтах
		 *
		 * \~english
		 * @brief Length of the random message of the encapsulation in bytes
		 *
		 * \~
		 */
		static constexpr size_t MLKEM_MESSAGE = 32;
		/**
		 * \~russian
		 * @brief Наборы параметров ML-KEM: значение перечисления равно размерности модуля k
		 *
		 * \~english
		 * @brief ML-KEM parameter sets: the value of the enumeration is equal to the module rank k
		 *
		 * \~
		 */
		enum class kem_t : uint8_t {
			// Набор не установлен
			NONE      = 0x00, /*!< \~russian Набор не установлен \~english The set is not set \~ */
			// ML-KEM-512, уровень стойкости 1
			MLKEM512  = 0x02, /*!< \~russian ML-KEM-512, уровень стойкости 1 \~english ML-KEM-512, security category 1 \~ */
			// ML-KEM-768, уровень стойкости 3
			MLKEM768  = 0x03, /*!< \~russian ML-KEM-768, уровень стойкости 3 \~english ML-KEM-768, security category 3 \~ */
			// ML-KEM-1024, уровень стойкости 5
			MLKEM1024 = 0x04  /*!< \~russian ML-KEM-1024, уровень стойкости 5 \~english ML-KEM-1024, security category 5 \~ */
		};
		/**
		 * \~russian
		 * @brief Функция получения длины ключа инкапсуляции набора
		 *
		 * @param kem набор параметров
		 * @return    длина ключа инкапсуляции в байтах либо нуль
		 *
		 * \~english
		 * @brief Function of the obtaining of the length of the encapsulation key of a set
		 *
		 * @param kem parameter set
		 * @return    length of the encapsulation key in bytes or zero
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t encapsulation(const kem_t kem) noexcept;
		/**
		 * \~russian
		 * @brief Функция получения длины ключа декапсуляции набора
		 *
		 * @param kem набор параметров
		 * @return    длина ключа декапсуляции в байтах либо нуль
		 *
		 * \~english
		 * @brief Function of the obtaining of the length of the decapsulation key of a set
		 *
		 * @param kem parameter set
		 * @return    length of the decapsulation key in bytes or zero
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t decapsulation(const kem_t kem) noexcept;
		/**
		 * \~russian
		 * @brief Функция получения длины шифртекста набора
		 *
		 * @param kem набор параметров
		 * @return    длина шифртекста в байтах либо нуль
		 *
		 * \~english
		 * @brief Function of the obtaining of the length of the ciphertext of a set
		 *
		 * @param kem parameter set
		 * @return    length of the ciphertext in bytes or zero
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t ciphertext(const kem_t kem) noexcept;
		/**
		 * \~russian
		 * @brief Функция проверки ключа инкапсуляции
		 *
		 * @details Раздел 7.2 FIPS 203: длина ключа сходится с набором, а всякий коэффициент
		 *          записи лежит в диапазоне модуля, то есть кодирование разобранного ключа
		 *          даёт те же байты
		 *
		 * @param kem набор параметров
		 * @param key ключ инкапсуляции
		 * @return    признак того, что ключ годен
		 *
		 * \~english
		 * @brief Function of the check of an encapsulation key
		 *
		 * @details Section 7.2 of FIPS 203: the length of the key agrees with the set, and every
		 *          coefficient of the record lies in the range of the modulus, that is the encoding
		 *          of the parsed key gives the same bytes
		 *
		 * @param kem parameter set
		 * @param key encapsulation key
		 * @return    sign that the key is valid
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool validate(const kem_t kem, const view_t & key) noexcept;
		/**
		 * \~russian
		 * @brief Функция выработки пары ключей из зерна
		 *
		 * @details Алгоритм 16 FIPS 203: зерно есть d || z по тридцать два байта; ключ
		 *          декапсуляции пишется полной записью dk_PKE || ek || H(ek) || z
		 *
		 * @param kem    набор параметров
		 * @param seed   зерно выработки в шестьдесят четыре байта
		 * @param key    место, в которое помещается ключ инкапсуляции
		 * @param secret место, в которое помещается ключ декапсуляции
		 * @return       признак того, что пара ключей выработана
		 *
		 * \~english
		 * @brief Function of the generation of a key pair from a seed
		 *
		 * @details Algorithm 16 of FIPS 203: the seed is d || z by thirty two bytes; the
		 *          decapsulation key is written by the full record dk_PKE || ek || H(ek) || z
		 *
		 * @param kem    parameter set
		 * @param seed   seed of the generation of sixty four bytes
		 * @param key    place into which the encapsulation key is put
		 * @param secret place into which the decapsulation key is put
		 * @return       sign that the key pair is generated
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool generate(const kem_t kem, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept;
		/**
		 * \~russian
		 * @brief Функция выработки пары ключей на случайном зерне
		 *
		 * @param kem    набор параметров
		 * @param key    место, в которое помещается ключ инкапсуляции
		 * @param secret место, в которое помещается ключ декапсуляции
		 * @return       признак того, что пара ключей выработана
		 *
		 * \~english
		 * @brief Function of the generation of a key pair on a random seed
		 *
		 * @param kem    parameter set
		 * @param key    place into which the encapsulation key is put
		 * @param secret place into which the decapsulation key is put
		 * @return       sign that the key pair is generated
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool generate(const kem_t kem, uint8_t * key, uint8_t * secret) noexcept;
		/**
		 * \~russian
		 * @brief Функция инкапсуляции на заданном сообщении
		 *
		 * @details Алгоритм 17 FIPS 203 с сообщением m, переданным снаружи; ключ
		 *          инкапсуляции проверяется по разделу 7.2 перед употреблением
		 *
		 * @param kem     набор параметров
		 * @param key     ключ инкапсуляции собеседника
		 * @param message случайное сообщение в тридцать два байта
		 * @param cipher  место, в которое помещается шифртекст
		 * @param shared  место, в которое помещается общий секрет в тридцать два байта
		 * @return        признак того, что инкапсуляция выполнена
		 *
		 * \~english
		 * @brief Function of the encapsulation on a given message
		 *
		 * @details Algorithm 17 of FIPS 203 with the message m passed from outside; the
		 *          encapsulation key is checked by section 7.2 before the use
		 *
		 * @param kem     parameter set
		 * @param key     encapsulation key of the peer
		 * @param message random message of thirty two bytes
		 * @param cipher  place into which the ciphertext is put
		 * @param shared  place into which the shared secret of thirty two bytes is put
		 * @return        sign that the encapsulation is done
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool encapsulate(const kem_t kem, const view_t & key, const view_t & message, uint8_t * cipher, uint8_t * shared) noexcept;
		/**
		 * \~russian
		 * @brief Функция инкапсуляции на случайном сообщении
		 *
		 * @param kem    набор параметров
		 * @param key    ключ инкапсуляции собеседника
		 * @param cipher место, в которое помещается шифртекст
		 * @param shared место, в которое помещается общий секрет в тридцать два байта
		 * @return       признак того, что инкапсуляция выполнена
		 *
		 * \~english
		 * @brief Function of the encapsulation on a random message
		 *
		 * @param kem    parameter set
		 * @param key    encapsulation key of the peer
		 * @param cipher place into which the ciphertext is put
		 * @param shared place into which the shared secret of thirty two bytes is put
		 * @return       sign that the encapsulation is done
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool encapsulate(const kem_t kem, const view_t & key, uint8_t * cipher, uint8_t * shared) noexcept;
		/**
		 * \~russian
		 * @brief Функция декапсуляции
		 *
		 * @details Алгоритм 18 FIPS 203 с проверками раздела 7.3: длины ключа и шифртекста
		 *          сходятся с набором, хеш ключа инкапсуляции внутри ключа декапсуляции
		 *          сходится. Негодный шифртекст не отвергается, а даёт неявно отвергнутый
		 *          секрет J(z || c), как велит стандарт
		 *
		 * @param kem    набор параметров
		 * @param secret свой ключ декапсуляции
		 * @param cipher шифртекст собеседника
		 * @param shared место, в которое помещается общий секрет в тридцать два байта
		 * @return       признак того, что декапсуляция выполнена
		 *
		 * \~english
		 * @brief Function of the decapsulation
		 *
		 * @details Algorithm 18 of FIPS 203 with the checks of section 7.3: the lengths of the
		 *          key and of the ciphertext agree with the set, the hash of the encapsulation key
		 *          inside the decapsulation key agrees. An invalid ciphertext is not refused but
		 *          gives the implicitly rejected secret J(z || c), as the standard orders
		 *
		 * @param kem    parameter set
		 * @param secret own decapsulation key
		 * @param cipher ciphertext of the peer
		 * @param shared place into which the shared secret of thirty two bytes is put
		 * @return       sign that the decapsulation is done
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool decapsulate(const kem_t kem, const view_t & secret, const view_t & cipher, uint8_t * shared) noexcept;
	};
};

