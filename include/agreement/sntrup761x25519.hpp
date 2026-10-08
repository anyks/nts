/**
 * @file sntrup761x25519.hpp
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
 * @brief Заголовочный файл модуля гибридного обмена ключами —
 *        sntrup761x25519-sha512 по draft-josefsson-ntruprime-ssh
 *
 * \~english
 * @brief Header file of the hybrid key exchange module —
 *        sntrup761x25519-sha512 according to draft-josefsson-ntruprime-ssh
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
#include <agreement/sntrup761.hpp>
#include <agreement/x25519.hpp>

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
	 * @brief Пространство имён модулей выработки общего ключа
	 *
	 * \~english
	 * @brief Namespace of the modules of the production of a shared key
	 *
	 * \~
	 *
	 */
	namespace agreement {
		/**
		 * \~russian
		 * @brief Длина открытого значения клиента гибрида в байтах
		 *
		 * @details Открытый ключ sntrup761 (1158) и открытый ключ X25519 (32),
		 *          lattice впереди
		 *
		 * \~english
		 * @brief Length of the client public value of the hybrid in bytes
		 * @details The sntrup761 public key (1158) and the X25519 public key (32),
		 *          the lattice first
		 *
		 * \~
		 */
		static constexpr size_t SNTRUP761X25519_CLIENT = (SNTRUP761_PUBLIC + X25519_SIZE);

		/**
		 * \~russian
		 * @brief Длина открытого значения сервера гибрида в байтах
		 *
		 * @details Шифртекст sntrup761 (1039) и открытый ключ X25519 (32),
		 *          lattice впереди
		 *
		 * \~english
		 * @brief Length of the server public value of the hybrid in bytes
		 * @details The sntrup761 ciphertext (1039) and the X25519 public key (32),
		 *          the lattice first
		 *
		 * \~
		 */
		static constexpr size_t SNTRUP761X25519_SERVER = (SNTRUP761_CIPHERTEXT + X25519_SIZE);

		/**
		 * \~russian
		 * @brief Длина общего секрета гибрида в байтах
		 *
		 * @details K = SHA-512(K_PQ ‖ K_CL): шестьдесят четыре байта
		 *
		 * \~english
		 * @brief Length of the shared secret of the hybrid in bytes
		 * @details K = SHA-512(K_PQ ‖ K_CL): sixty-four bytes
		 *
		 * \~
		 */
		static constexpr size_t SNTRUP761X25519_SHARED = 64;

		/**
		 * \~russian
		 * @brief Метод выработки открытого значения клиента гибрида
		 *
		 * @param key    место, в которое записывается открытое значение клиента (1190 байтов)
		 * @param secret место, в которое записывается секрет клиента (1763 + 32 байтов: секрет sntrup761 и секрет X25519)
		 *
		 * @return       признак успешности выработки
		 *
		 * @details draft-josefsson-ntruprime-ssh: открытый ключ sntrup761 (1158)
		 *          и открытый ключ X25519 (32), lattice впереди; секрет клиента
		 *          хранит секрет sntrup761 и секрет X25519 подряд
		 *
		 * \~english
		 * @brief Method of the production of the client public value of the hybrid
		 * @param key    the place the client public value is written into (1190 bytes)
		 * @param secret the place the client secret is written into (1763 + 32 bytes: the sntrup761 secret and the X25519 secret)
		 * @return       the flag of the success of the production
		 * @details draft-josefsson-ntruprime-ssh: the sntrup761 public key (1158)
		 *          and the X25519 public key (32), the lattice first; the client
		 *          secret keeps the sntrup761 secret and the X25519 secret in a row
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool pairSntrup761x25519(uint8_t * key, uint8_t * secret) noexcept;

		/**
		 * \~russian
		 * @brief Метод ответа сервера гибридного обмена
		 *
		 * @param key    открытое значение клиента (1190 байтов)
		 * @param cipher место, в которое записывается открытое значение сервера (1071 байт)
		 * @param secret место, в которое записывается секрет сервера (32 байта: секрет X25519)
		 * @param shared место, в которое записывается общий секрет (64 байта)
		 *
		 * @return       признак успешности ответа
		 *
		 * @details Сервер инкапсулирует секрет sntrup761 по ключу клиента и
		 *          вырабатывает общее значение X25519 со своим мимолётным секретом;
		 *          K = SHA-512(K_PQ ‖ K_CL)
		 *
		 * \~english
		 * @brief Method of the server answer of the hybrid exchange
		 * @param key    the client public value (1190 bytes)
		 * @param cipher the place the server public value is written into (1071 bytes)
		 * @param secret the place the server secret is written into (32 bytes: the X25519 secret)
		 * @param shared the place the shared secret is written into (64 bytes)
		 * @return       the flag of the success of the answer
		 * @details The server encapsulates the sntrup761 secret by the client key and
		 *          produces the X25519 shared value with its ephemeral secret;
		 *          K = SHA-512(K_PQ ‖ K_CL)
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool encapsSntrup761x25519(const view_t & key, uint8_t * cipher, uint8_t * secret, uint8_t * shared) noexcept;

		/**
		 * \~russian
		 * @brief Метод завершения гибридного обмена клиентом
		 *
		 * @param cipher открытое значение сервера (1071 байт)
		 * @param secret секрет клиента (1763 + 32 байтов)
		 * @param shared место, в которое записывается общий секрет (64 байта)
		 *
		 * @return       признак успешности завершения (ложь при подмене шифртекста)
		 *
		 * @details Клиент распаковывает секрет sntrup761 и вырабатывает общее
		 *          значение X25519; K = SHA-512(K_PQ ‖ K_CL)
		 *
		 * \~english
		 * @brief Method of the completion of the hybrid exchange by the client
		 * @param cipher the server public value (1071 bytes)
		 * @param secret the client secret (1763 + 32 bytes)
		 * @param shared the place the shared secret is written into (64 bytes)
		 * @return       the flag of the success of the completion (false on ciphertext tampering)
		 * @details The client decapsulates the sntrup761 secret and produces the
		 *          X25519 shared value; K = SHA-512(K_PQ ‖ K_CL)
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool decapsSntrup761x25519(const view_t & cipher, const view_t & secret, uint8_t * shared) noexcept;
	} // namespace agreement
} // namespace nts

