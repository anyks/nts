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
#pragma once

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
			/**
			 * \~russian
			 * @brief Сведения о записи known_hosts
			 *
			 * @details Запись known_hosts: хозяин (открытым текстом либо хешем
			 *          HMAC-SHA1), тип ключа, открытый ключ, комментарий
			 *
			 * \~english
			 * @brief Info of a known_hosts record
			 * @details A known_hosts record: the host (in plain text or by an
			 *          HMAC-SHA1 hash), the key type, the public key, the comment
			 *
			 * \~
			 *
			 */
			typedef struct __ANTS_SHARED_EXPORT__ KnownHost {
				// Хозяин открытым текстом; пусто у хешированной записи
				string host;
				// Признак хешированной записи (хозяин под HMAC-SHA1)
				bool hashed;
				// Соль хеша хозяина (у хешированной записи)
				vector <uint8_t> salt;
				// Хеш хозяина HMAC-SHA1 (у хешированной записи)
				vector <uint8_t> hash;
				// Тип ключа («ssh-ed25519»)
				string type;
				// Открытый ключ (запись SSH-строки типа и ключа)
				vector <uint8_t> key;
				// Комментарий
				string comment;
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 *
				 */
				KnownHost() noexcept : hashed(false) {}
			} known_host_t;
			/**
			 * \~russian
			 * @brief Метод разбора строки known_hosts
			 *
			 * @param line   строка known_hosts
			 * @param result место, в которое помещаются сведения о записи
			 *
			 * @return       признак успешности разбора
			 *
			 * @details Принимаются оба вида: открытая «хозяин тип ключ комментарий»
			 *          и хешированная «|1|base64(соль)|base64(HMAC-SHA1(соль, хозяин))
			 *          тип ключ комментарий»
			 *
			 * \~english
			 * @brief Method of the parsing of a known_hosts line
			 * @param line   the known_hosts line
			 * @param result the place the record info is put into
			 * @return       the flag of the success of the parsing
			 * @details Both kinds are accepted: the plain «host type key comment»
			 *          and the hashed «|1|base64(salt)|base64(HMAC-SHA1(salt, host))
			 *          type key comment»
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ bool knownHosts(const string & line, known_host_t & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод сборки строки known_hosts
			 *
			 * @param host    хозяин
			 * @param key     открытый ключ
			 * @param comment комментарий
			 * @param hashed  признак хеширования хозяина HMAC-SHA1
			 * @param result  место, в которое помещается строка known_hosts
			 *
			 * @return        признак успешности сборки
			 *
			 * @details При hashed хозяин идёт хешем HMAC-SHA1 со случайной солью
			 *          в двадцать байтов; иначе - открытым текстом
			 *
			 * \~english
			 * @brief Method of the building of a known_hosts line
			 * @param host    the host
			 * @param key     the public key
			 * @param comment the comment
			 * @param hashed  the flag of the hashing of the host by HMAC-SHA1
			 * @param result  the place the known_hosts line is put into
			 * @return        the flag of the success of the building
			 * @details At hashed the host goes by an HMAC-SHA1 hash with a random
			 *          salt of twenty bytes; otherwise - in plain text
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ bool knownHosts(const string & host, const key_t & key, const string & comment, const bool hashed, string & result) noexcept;
			/**
			 * \~russian
			 * @brief Метод сверки хозяина с записью known_hosts
			 *
			 * @param record сведения о записи known_hosts
			 * @param host   сверяемый хозяин
			 *
			 * @return       признак совпадения хозяина
			 *
			 * @details У открытой записи хозяин сличается строкой; у хешированной -
			 *          вычислением HMAC-SHA1(соль, хозяин) и постоянной сверкой
			 *
			 * \~english
			 * @brief Method of the matching of a host against a known_hosts record
			 * @param record the known_hosts record info
			 * @param host   the host being matched
			 * @return       the flag of the match of the host
			 * @details At a plain record the host is compared as a string; at a hashed
			 *          one - by computing HMAC-SHA1(salt, host) and a constant-time
			 *          comparison
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ bool knownHostsMatch(const known_host_t & record, const string & host) noexcept;
		};
	};
};

