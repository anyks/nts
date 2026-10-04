/**
 * @file openssh.hpp
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
 * @brief Заголовочный файл модуля формата ключей openssh-key-v1
 *
 * \~english
 * @brief Header file of the module of the openssh-key-v1 key format
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_OPENSSH__
#define __ANTS_OPENSSH__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <keys/keys.hpp>

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
	 * @brief Пространство имён модулей работы с ключами
	 *
	 * \~english
	 * @brief Namespace of the key modules
	 *
	 * \~
	 */
	namespace keys {
		/**
		 * \~russian
		 * @brief Пространство имён формата openssh-key-v1
		 *
		 * \~english
		 * @brief Namespace of the openssh-key-v1 format
		 *
		 * \~
		 */
		namespace openssh {
			/**
			 * \~russian
			 * @brief Метка PEM для openssh-key-v1
			 *
			 * \~english
			 * @brief PEM label for openssh-key-v1
			 *
			 * \~
			 */
			static constexpr char PEM_LABEL[] = "OPENSSH PRIVATE KEY";

			/**
			 * \~russian
			 * @brief Метод разбора ключа openssh-key-v1
			 *
			 * @details Формат: магия «openssh-key-v1\0», ciphername, kdfname, kdfoptions,
			 *          число ключей, открытые ключи, зашифрованный либо открытый блок
			 *          секретных ключей. Поддерживаются ciphername «none» и «aes256-ctr»,
			 *          kdfname «none» и «bcrypt»
			 *
			 * @param data     запись ключа (DER либо PEM)
			 * @param password пароль для зашифрованного ключа, пустой для незашифрованного
			 * @param key      разобранный ключ
			 * @param comment  комментарий ключа
			 *
			 * @return         признак успешности разбора
			 *
			 * \~english
			 * @brief Method of the parsing of an openssh-key-v1 key
			 *
			 * @details Format: magic «openssh-key-v1\0», ciphername, kdfname, kdfoptions,
			 *          number of keys, public keys, encrypted or plain block of secret keys.
			 *          Supported ciphername «none» and «aes256-ctr», kdfname «none» and «bcrypt»
			 *
			 * @param data     key record (DER or PEM)
			 * @param password password for an encrypted key, empty for a plain one
			 * @param key      parsed key
			 * @param comment  key comment
			 *
			 * @return         the flag of the success of the parsing
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ bool decode(const view_t & data, const view_t & password, key_t & key, string & comment) noexcept;
			/**
			 * \~russian
			 * @brief Метод записи ключа openssh-key-v1
			 *
			 * @details Записывает ключ в формате openssh-key-v1. При пустом пароле
			 *          ciphername и kdfname равны «none», иначе «aes256-ctr» и «bcrypt»
			 *          с 16 кругами bcrypt_pbkdf
			 *
			 * @param key      ключ для записи
			 * @param comment  комментарий ключа
			 * @param password пароль для шифрования, пустой для незашифрованной записи
			 * @param result   место, в которое помещается запись DER
			 *
			 * @return         признак успешности записи
			 *
			 * \~english
			 * @brief Method of the writing of an openssh-key-v1 key
			 *
			 * @details Writes the key in the openssh-key-v1 format. At an empty password
			 *          ciphername and kdfname are «none», otherwise «aes256-ctr» and «bcrypt»
			 *          with 16 rounds of bcrypt_pbkdf
			 *
			 * @param key      key to write
			 * @param comment  key comment
			 * @param password password for encryption, empty for a plain record
			 * @param result   the place the DER record is put into
			 *
			 * @return         the flag of the success of the writing
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ bool encode(const key_t & key, const string & comment, const view_t & password, vector <uint8_t> & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод записи открытого ключа в строку authorized_keys
			 *
			 * @details Формат: «ssh-ed25519 AAAA… комментарий» — тип ключа, base64
			 *          открытого ключа, комментарий через пробел
			 *
			 * @param key     открытый ключ
			 * @param comment комментарий
			 *
			 * @return        строка authorized_keys
			 *
			 * \~english
			 * @brief Method of the writing of a public key into an authorized_keys line
			 *
			 * @details Format: «ssh-ed25519 AAAA… comment» — key type, base64
			 *          of the public key, comment separated by space
			 *
			 * @param key     public key
			 * @param comment comment
			 *
			 * @return        authorized_keys line
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ string publish(const key_t & key, const string & comment) noexcept;
			/**
			 * \~russian
			 * @brief Метод вычисления отпечатка ключа SHA256
			 *
			 * @details Отпечаток: «SHA256:» + base64 без padding от SHA-256 открытого ключа
			 *
			 * @param key открытый ключ
			 *
			 * @return    отпечаток
			 *
			 * \~english
			 * @brief Method of the computation of the SHA256 fingerprint of a key
			 *
			 * @details Fingerprint: «SHA256:» + base64 without padding of SHA-256 of the public key
			 *
			 * @param key public key
			 *
			 * @return    fingerprint
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ string fingerprint(const key_t & key) noexcept;
		};
	};
};

#endif // __ANTS_OPENSSH__
