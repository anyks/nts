/**
 * @file ripemd.hpp
 * @date 2026-10-10
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
 * @brief Модуль хеш-функции RIPEMD-160 (Доббертин, Босселарс, Пренел)
 *
 * \~english
 * @brief Module of the hash function RIPEMD-160 (Dobbertin, Bosselaers, Preneel)
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
		 * @brief Длина хеша RIPEMD-160 в байтах
		 *
		 * \~english
		 * @brief Length of the RIPEMD-160 hash in bytes
		 *
		 * \~
		 */
		static constexpr size_t RIPEMD160 = 20;
		/**
		 * \~russian
		 * @brief Хеш-функция RIPEMD-160
		 *
		 * @details Сообщение подаётся вызовами update кусками произвольного размера, а
		 *          выработанный хеш снимается вызовом finish. Повторное хеширование
		 *          требует вызова reset: finish оставляет объект в завершённом состоянии
		 *
		 * \~english
		 * @brief The RIPEMD-160 hash function
		 *
		 * @details The message is fed by the calls of update by the chunks of an arbitrary size,
		 *          and the produced hash is taken by the call of finish. A repeated hashing requires
		 *          the call of reset: finish leaves the object in the finished state
		 * \~russian
		 * @note Состояние и накопитель незавершённого блока затираются при снятии хеша
		 *       и при разрушении объекта
		 * \~english
		 * @note The state and the accumulator of the unfinished block are wiped
		 *       at the taking of the hash and at the destruction of the object
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Ripemd {
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
				 *
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
				 *
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
				 * @return       признак успешности снятия хеша
				 *
				 * @note Повторное снятие без сброса отвергается: состояние после снятия
				 *       затёрто
				 *
				 * \~english
				 * @brief Method of taking the produced hash
				 *
				 * @param result the place the hash is written into
				 * @param size   the size of the place in bytes, not less than the length of the hash
				 * @return       the flag of the success of the taking of the hash
				 *
				 * @note A repeated taking without a reset is refused: the state after the taking is
				 *       wiped
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
				Ripemd() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Ripemd() noexcept;
		} ripemd_t;

		/**
		 * \~russian
		 * @brief Функция выработки хеша RIPEMD-160 целого сообщения
		 *
		 * @param data   хешируемое сообщение
		 * @param result место, в которое записывается хеш
		 * @param size   размер места в байтах, не меньше длины хеша
		 * @return       признак успешности выработки хеша
		 *
		 * \~english
		 * @brief Function of the production of the RIPEMD-160 hash of a whole message
		 *
		 * @param data   the message being hashed
		 * @param result the place the hash is written into
		 * @param size   the size of the place in bytes, not less than the length of the hash
		 * @return       the flag of the success of the production of the hash
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool ripemd160(const view_t & data, uint8_t * result, const size_t size) noexcept;
	};
};
