/**
 * @file sha1.hpp
 * @date 2026-09-04
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
 * @brief Заголовочный файл модуля хеширования SHA-1 — выработка хеша длиной 160
 *        разрядов по FIPS 180-4
 *
 * \~english
 * @brief Header file of the SHA-1 hashing module — the production of a hash of a length
 *        of 160 bits according to FIPS 180-4
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
	 * @brief Пространство имён модулей хеширования
	 *
	 * \~english
	 * @brief Namespace of the hashing modules
	 *
	 * \~
	 */
	namespace digest {
		/**
		 * \~russian
		 * @brief Хеширование по FIPS 180-4
		 *
		 * @details Сообщение подаётся вызовами update кусками произвольного размера, а
		 *          выработанный хеш снимается вызовом finish. Повторное хеширование
		 *          требует вызова reset: finish оставляет объект в завершённом состоянии
		 *
		 * @note SHA-1 стойкости к коллизиям лишён и криптографической защитой служить
		 *       не вправе; он держится ради протоколов, которые его требуют: отпечатки
		 *       сертификатов и унаследованные схемы подлинности
		 *
		 * @note Памяти хеширование не выделяет и исключений не возбуждает; состояние
		 *       затирается при снятии хеша и при уничтожении объекта
		 *
		 * \~english
		 * @brief Hashing according to FIPS 180-4
		 * @details The message is fed by the calls of update by the chunks of an arbitrary size,
		 *          and the produced hash is taken by the call of finish. A repeated hashing requires
		 *          the call of reset: finish leaves the object in the finished state
		 * @note SHA-1 has no collision resistance and must not serve as a cryptographic protection;
		 *       it is kept for the protocols that require it: the fingerprints of the certificates
		 *       and the legacy authentication schemes
		 * @note The hashing does not allocate memory and raises no exceptions; the state is wiped
		 *       at the taking of the hash and at the destruction of the object
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Sha1 {
			private:
				// Признак того, что хеш уже снят
				bool _finished;
				// Число байтов, накопленных в незавершённом блоке
				size_t _size;
			private:
				// Вычисляемое значение хеша
				uint32_t _hash[5];
				// Число разобранных байтов сообщения
				uint64_t _count;
			private:
				// Накопитель незавершённого блока сообщения
				uint8_t _block[64];
			private:
				/**
				 * \~russian
				 * @brief Метод разбора блока сообщения
				 *
				 * @param block разбираемый блок: накопитель либо сам кусок сообщения
				 *
				 * \~english
				 * @brief Method of the parsing of a block of the message
				 * @param block the block being parsed: the accumulator or the chunk of the message itself
				 *
				 * \~
				 */
				void compress(const uint8_t * block) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод сброса состояния хеширования
				 *
				 * \~english
				 * @brief Method of the reset of the state of the hashing
				 *
				 * \~
				 */
				void reset() noexcept;
				/**
				 * \~russian
				 * @brief Метод подачи куска сообщения
				 *
				 * @param data подаваемый кусок сообщения
				 *
				 * \~english
				 * @brief Method of feeding a chunk of the message
				 * @param data the chunk of the message being fed
				 *
				 * \~
				 */
				void update(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия выработанного хеша
				 *
				 * @param result место, в которое записывается хеш
				 * @param size   размер места в байтах, не меньше длины хеша
				 *
				 * @return       признак успешности снятия хеша
				 *
				 * @note Повторное снятие без сброса отвергается: состояние после снятия
				 *       затёрто
				 *
				 * \~english
				 * @brief Method of taking the produced hash
				 * @param result the place the hash is written into
				 * @param size   the size of the place in bytes, not less than the length of the hash
				 * @return       the flag of the success of the taking of the hash
				 * @note A repeated taking without a reset is refused: the state after the taking is wiped
				 *
				 * \~
				 */
				bool finish(uint8_t * result, const size_t size) noexcept;
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
				Sha1() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Sha1() noexcept;
		} sha1_t;

		/**
		 * \~russian
		 * @brief Метод выработки хеша SHA-1 целого сообщения
		 *
		 * @param data   хешируемое сообщение
		 * @param result место, в которое записывается хеш
		 * @param size   размер места в байтах, не меньше длины хеша
		 *
		 * @return       признак успешности выработки хеша
		 *
		 * \~english
		 * @brief Method of the production of the SHA-1 hash of a whole message
		 * @param data   the message being hashed
		 * @param result the place the hash is written into
		 * @param size   the size of the place in bytes, not less than the length of the hash
		 * @return       the flag of the success of the production of the hash
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool sha1(const view_t & data, uint8_t * result, const size_t size) noexcept;
	};
};

