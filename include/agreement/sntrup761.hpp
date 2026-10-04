/**
 * @file sntrup761.hpp
 * @date 2026-10-04
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
 * @brief Заголовочный файл модуля инкапсуляции ключа Streamlined NTRU Prime sntrup761
 *
 * \~english
 * @brief Header file of the module of the key encapsulation Streamlined NTRU Prime sntrup761
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_SNTRUP761__
#define __ANTS_SNTRUP761__

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
		 * @brief Длина открытого ключа sntrup761 в байтах
		 *
		 * \~english
		 * @brief Length of the sntrup761 public key in bytes
		 *
		 * \~
		 */
		static constexpr size_t SNTRUP761_PUBLIC = 1158;
		/**
		 * \~russian
		 * @brief Длина секретного ключа sntrup761 в байтах
		 *
		 * \~english
		 * @brief Length of the sntrup761 secret key in bytes
		 *
		 * \~
		 */
		static constexpr size_t SNTRUP761_SECRET = 1763;
		/**
		 * \~russian
		 * @brief Длина шифртекста sntrup761 в байтах
		 *
		 * \~english
		 * @brief Length of the sntrup761 ciphertext in bytes
		 *
		 * \~
		 */
		static constexpr size_t SNTRUP761_CIPHERTEXT = 1039;
		/**
		 * \~russian
		 * @brief Длина общего секрета sntrup761 в байтах
		 *
		 * \~english
		 * @brief Length of the sntrup761 shared secret in bytes
		 *
		 * \~
		 */
		static constexpr size_t SNTRUP761_SHARED = 32;

		/**
		 * \~russian
		 * @brief Метод выработки пары ключей sntrup761
		 *
		 * @details Арифметика в Z/4591[x]/(x^761 − x − 1), малые полиномы в {-1,0,1}.
		 *          Секретный ключ содержит f, ginv, открытый ключ, случайное зерно rho
		 *          и кэш Hash4(pk) для ускорения декапсуляции
		 *
		 * @param key    место, в которое помещается открытый ключ длиной SNTRUP761_PUBLIC
		 * @param secret место, в которое помещается секретный ключ длиной SNTRUP761_SECRET
		 *
		 * @return       признак успешности выработки пары ключей
		 *
		 * \~english
		 * @brief Method of the generation of an sntrup761 key pair
		 *
		 * @details Arithmetic in Z/4591[x]/(x^761 − x − 1), small polynomials in {-1,0,1}.
		 *          The secret key contains f, ginv, the public key, a random seed rho
		 *          and a cache Hash4(pk) to speed up decapsulation
		 *
		 * @param key    the place the public key of the length SNTRUP761_PUBLIC is put into
		 * @param secret the place the secret key of the length SNTRUP761_SECRET is put into
		 *
		 * @return       the flag of the success of the generation of the key pair
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool pair(uint8_t * key, uint8_t * secret) noexcept;
		/**
		 * \~russian
		 * @brief Метод инкапсуляции общего секрета sntrup761
		 *
		 * @details Вырабатывает случайный вход r, шифрует его открытым ключом,
		 *          вычисляет подтверждение HashConfirm и общий секрет HashSession
		 *
		 * @param key      открытый ключ встречной стороны длиной SNTRUP761_PUBLIC
		 * @param cipher   место, в которое помещается шифртекст длиной SNTRUP761_CIPHERTEXT
		 * @param shared   место, в которое помещается общий секрет длиной SNTRUP761_SHARED
		 *
		 * @return         признак успешности инкапсуляции
		 *
		 * \~english
		 * @brief Method of the encapsulation of a shared secret sntrup761
		 *
		 * @details Generates a random input r, encrypts it with the public key,
		 *          computes the confirmation HashConfirm and the shared secret HashSession
		 *
		 * @param key      the public key of the opposite side of the length SNTRUP761_PUBLIC
		 * @param cipher   the place the ciphertext of the length SNTRUP761_CIPHERTEXT is put into
		 * @param shared   the place the shared secret of the length SNTRUP761_SHARED is put into
		 *
		 * @return         the flag of the success of the encapsulation
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool encaps(const view_t & key, uint8_t * cipher, uint8_t * shared) noexcept;
		/**
		 * \~russian
		 * @brief Метод декапсуляции общего секрета sntrup761
		 *
		 * @details Расшифровывает вход r, проверяет шифртекст повторным шифрованием,
		 *          при несовпадении подставляет зерно rho вместо r для неявного отказа
		 *
		 * @param cipher   шифртекст длиной SNTRUP761_CIPHERTEXT
		 * @param secret   секретный ключ длиной SNTRUP761_SECRET
		 * @param shared   место, в которое помещается общий секрет длиной SNTRUP761_SHARED
		 *
		 * @return         признак успешности декапсуляции (ложь при подмене шифртекста)
		 *
		 * \~english
		 * @brief Method of the decapsulation of a shared secret sntrup761
		 *
		 * @details Decrypts the input r, checks the ciphertext by re-encryption,
		 *          on mismatch substitutes the seed rho instead of r for implicit rejection
		 *
		 * @param cipher   the ciphertext of the length SNTRUP761_CIPHERTEXT
		 * @param secret   the secret key of the length SNTRUP761_SECRET
		 * @param shared   the place the shared secret of the length SNTRUP761_SHARED is put into
		 *
		 * @return         the flag of the success of the decapsulation (false on ciphertext tampering)
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool decaps(const view_t & cipher, const view_t & secret, uint8_t * shared) noexcept;
	};
};

#endif // __ANTS_SNTRUP761__
