/**
 * @file bcrypt.hpp
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
 * @brief Заголовочный файл модуля выработки ключа bcrypt_pbkdf
 *
 * \~english
 * @brief Header file of the module of the key derivation bcrypt_pbkdf
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
	 * @brief Пространство имён модулей хеширования и выработки ключей
	 *
	 * \~english
	 * @brief Namespace of the hashing and key derivation modules
	 *
	 * \~
	 */
	namespace digest {
		/**
		 * \~russian
		 * @brief Метод выработки ключа bcrypt_pbkdf
		 *
		 * @details PBKDF2 с хешем bcrypt: пароль и соль предварительно хешируются SHA-512,
		 *          выход расширен до 256 бит, магическая строка «OxychromaticBlowfishSwatDynamite»,
		 *          64 круга начального расширения состояния. Выходные байты перемешиваются
		 *          для предотвращения атаки на подключи
		 *
		 * @param pass   пароль
		 * @param salt   соль
		 * @param key    место, в которое помещается выработанный ключ
		 * @param keylen длина вырабатываемого ключа в байтах
		 * @param rounds число кругов
		 *
		 * @return       признак успешности выработки ключа
		 *
		 * \~english
		 * @brief Method of the key derivation bcrypt_pbkdf
		 *
		 * @details PBKDF2 with the bcrypt hash: the password and the salt are pre-hashed with SHA-512,
		 *          the output is expanded to 256 bits, the magic string «OxychromaticBlowfishSwatDynamite»,
		 *          64 rounds of the initial state expansion. The output bytes are shuffled
		 *          to prevent the subkey attack
		 *
		 * @param pass   password
		 * @param salt   salt
		 * @param key    the place the derived key is put into
		 * @param keylen length of the derived key in bytes
		 * @param rounds number of rounds
		 *
		 * @return       the flag of the success of the key derivation
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool bcrypt(const view_t & pass, const view_t & salt, uint8_t * key, const size_t keylen, const size_t rounds) noexcept;
	};
};

