/**
 * @file streebog.hpp
 * @date 2026-08-27
 *
 * @license{LicenseRef-ANYKS-TLS-1.0}
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
 * @brief Заголовочный файл модуля хеширования «Стрибог» — выработка хеша длиной
 *        256 либо 512 разрядов по ГОСТ Р 34.11-2012
 *
 * \~english
 * @brief Header file of the «Streebog» hashing module — the production of a hash of a length
 *        of 256 or 512 bits according to GOST R 34.11-2012
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANYKS_TLS_STREEBOG__
#define __ANYKS_TLS_STREEBOG__

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
namespace anyks {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён модулей хеширования
	 *
	 * @details Хеширование ведётся потоком: сообщение подаётся кусками произвольного
	 *          размера, и выработанный хеш от нарезки на куски не зависит. Памяти
	 *          хеширование не выделяет вовсе и исключений не возбуждает.
	 *
	 * \~english
	 * @brief Namespace of the hashing modules
	 * @details The hashing is conducted by a stream: the message is fed by the chunks of an
	 *          arbitrary size, and the produced hash does not depend on the cutting into the
	 *          chunks. The hashing does not allocate memory at all and raises no exceptions.
	 *
	 * \~
	 */
	namespace digest {
		/**
		 * \~russian
		 * @brief Длина вырабатываемого хеша
		 *
		 * @details Значение отвечает длине хеша в байтах
		 *
		 * \~english
		 * @brief Length of the produced hash
		 * @details The value corresponds to the length of the hash in bytes
		 *
		 * \~
		 */
		enum class type_t : uint8_t {
			NONE  = 0x00, // Длина хеша не установлена
			SHORT = 0x20, // Хеш длиной 256 разрядов
			LONG  = 0x40  // Хеш длиной 512 разрядов
		};

		/**
		 * \~russian
		 * @brief Хеширование по ГОСТ Р 34.11-2012
		 *
		 * @details Сообщение подаётся вызовами update кусками произвольного размера, а
		 *          выработанный хеш снимается вызовом finish. Повторное хеширование
		 *          требует вызова reset: finish оставляет объект в завершённом состоянии.
		 *
		 * @note Обе длины хеша вырабатываются одним и тем же преобразованием и
		 *       различаются лишь начальным значением и тем, что хеш длиной 256 разрядов
		 *       берётся старшей половиной итога. Отдельного устройства под них нет
		 *
		 * \~english
		 * @brief Hashing according to GOST R 34.11-2012
		 * @details The message is fed by the calls of update by the chunks of an arbitrary size,
		 *          while the produced hash is taken by a call of finish. A repeated hashing
		 *          requires a call of reset: finish leaves the object in a finished state.
		 * @note Both lengths of the hash are produced by one and the same transformation and
		 *       differ only by the initial value and by the fact that a hash of a length of 256 bits
		 *       is taken as the high half of the result. There is no separate structure for them
		 *
		 * \~
		 */
		typedef class __ANYKS_TLS_SHARED_EXPORT__ Streebog {
			private:
				// Длина вырабатываемого хеша
				type_t _type;
			private:
				// Признак того, что хеш уже снят
				bool _finished;
				// Число байтов, накопленных в незавершённом блоке
				size_t _size;
			private:
				// Вычисляемое значение хеша
				uint64_t _hash[8];
				// Число разобранных разрядов сообщения
				uint64_t _count[8];
				// Контрольная сумма разобранных блоков сообщения
				uint64_t _sum[8];
			private:
				// Накопитель незавершённого блока сообщения
				uint8_t _block[64];
			public:
				/**
				 * \~russian
				 * @brief Метод извлечения длины вырабатываемого хеша
				 *
				 * @return длина вырабатываемого хеша
				 *
				 * \~english
				 * @brief Method of getting the length of the produced hash
				 * @return the length of the produced hash
				 *
				 * \~
				 */
				type_t type() const noexcept;
				/**
				 * \~russian
				 * @brief Метод приведения объекта к началу хеширования
				 *
				 * @param type длина вырабатываемого хеша
				 *
				 * \~english
				 * @brief Method of bringing the object to the beginning of the hashing
				 * @param type the length of the produced hash
				 *
				 * \~
				 */
				void reset(const type_t type) noexcept;
				/**
				 * \~russian
				 * @brief Метод подачи куска сообщения
				 *
				 * @param data подаваемый кусок сообщения
				 *
				 * @note Кусок подаётся любого размера, включая нулевой. Выработанный хеш
				 *       от нарезки сообщения на куски не зависит
				 *
				 * \~english
				 * @brief Method of feeding a chunk of the message
				 * @param data the chunk of the message being fed
				 * @note A chunk of any size is fed, including a zero one. The produced hash
				 *       does not depend on the cutting of the message into the chunks
				 *
				 * \~
				 */
				void update(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия выработанного хеша
				 *
				 * @param result место, в которое помещается выработанный хеш
				 * @param size   размер места, в которое помещается хеш
				 *
				 * @return признак успешности снятия хеша
				 *
				 * @note Отказом отвечают недостаточный размер места, неустановленная длина
				 *       хеша и повторное снятие
				 *
				 * \~english
				 * @brief Method of taking the produced hash
				 * @param result the place the produced hash is put into
				 * @param size   the size of the place the hash is put into
				 * @return the flag of the success of the taking of the hash
				 * @note A failure is answered to an insufficient size of the place, to an unset length
				 *       of the hash and to a repeated taking
				 *
				 * \~
				 */
				bool finish(uint8_t * result, const size_t size) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 * @param type длина вырабатываемого хеша
				 *
				 * \~english
				 * @brief Constructor
				 * @param type the length of the produced hash
				 *
				 * \~
				 */
				Streebog(const type_t type = type_t::LONG) noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Streebog() noexcept {}
		} streebog_t;

		/**
		 * \~russian
		 * @brief Метод выработки хеша сообщения, поданного целиком
		 *
		 * @param type   длина вырабатываемого хеша
		 * @param data   хешируемое сообщение
		 * @param result место, в которое помещается выработанный хеш
		 * @param size   размер места, в которое помещается хеш
		 *
		 * @return признак успешности выработки хеша
		 *
		 * \~english
		 * @brief Method of the production of a hash of a message fed as a whole
		 * @param type   the length of the produced hash
		 * @param data   the message being hashed
		 * @param result the place the produced hash is put into
		 * @param size   the size of the place the hash is put into
		 * @return the flag of the success of the production of the hash
		 *
		 * \~
		 */
		__ANYKS_TLS_SHARED_EXPORT__ bool streebog(const type_t type, const view_t & data, uint8_t * result, const size_t size) noexcept;
	};
};

#endif // __ANYKS_TLS_STREEBOG__
