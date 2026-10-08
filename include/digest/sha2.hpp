/**
 * @file sha2.hpp
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
 * @brief Заголовочный файл модуля хеширования SHA-2 — выработка хеша длиной 224,
 *        256, 384 либо 512 разрядов по FIPS 180-4
 *
 * \~english
 * @brief Header file of the SHA-2 hashing module — the production of a hash of a length
 *        of 224, 256, 384 or 512 bits according to FIPS 180-4
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
		 * @brief Разновидность хеша SHA-2
		 *
		 * @details Значение отвечает длине хеша в байтах. Хеши длиной 224 и 256
		 *          разрядов вырабатываются преобразованием над словами в 32 разряда
		 *          с блоком в 64 байта, хеши длиной 384 и 512 разрядов - преобразованием
		 *          над словами в 64 разряда с блоком в 128 байтов; усечённые хеши
		 *          отличаются от полных начальным значением и отбрасыванием хвоста итога
		 *
		 * \~english
		 * @brief Kind of the SHA-2 hash
		 * @details The value corresponds to the length of the hash in bytes. The hashes of a length
		 *          of 224 and 256 bits are produced by a transformation over the 32-bit words with a
		 *          block of 64 bytes, the hashes of a length of 384 and 512 bits - by a transformation
		 *          over the 64-bit words with a block of 128 bytes; the truncated hashes differ from
		 *          the full ones by the initial value and the dropping of the tail of the result
		 *
		 * \~
		 */
		enum class sha_t : uint8_t {
			NONE   = 0x00, /*!< \~russian Разновидность не установлена \~english The kind is not set \~ */
			SHA224 = 0x1C, /*!< \~russian Хеш длиной 224 разряда \~english Hash of a length of 224 bits \~ */
			SHA256 = 0x20, /*!< \~russian Хеш длиной 256 разрядов \~english Hash of a length of 256 bits \~ */
			SHA384 = 0x30, /*!< \~russian Хеш длиной 384 разряда \~english Hash of a length of 384 bits \~ */
			SHA512 = 0x40  /*!< \~russian Хеш длиной 512 разрядов \~english Hash of a length of 512 bits \~ */
		};

		/**
		 * \~russian
		 * @brief Хеширование по FIPS 180-4
		 *
		 * @details Сообщение подаётся вызовами update кусками произвольного размера, а
		 *          выработанный хеш снимается вызовом finish. Повторное хеширование
		 *          требует вызова reset: finish оставляет объект в завершённом состоянии.
		 *          Порядок байтов хеша один - тот, которым его записывает стандарт и
		 *          передают протоколы, оттого довода порядка здесь нет
		 *
		 * @note Памяти хеширование не выделяет и исключений не возбуждает; состояние
		 *       затирается при снятии хеша и при уничтожении объекта
		 *
		 * \~english
		 * @brief Hashing according to FIPS 180-4
		 * @details The message is fed by the calls of update by the chunks of an arbitrary size,
		 *          and the produced hash is taken by the call of finish. A repeated hashing requires
		 *          the call of reset: finish leaves the object in the finished state. The byte order
		 *          of the hash is the only one - the one the standard writes it by and the protocols
		 *          transfer it by, therefore there is no argument of the order here
		 * @note The hashing does not allocate memory and raises no exceptions; the state is wiped
		 *       at the taking of the hash and at the destruction of the object
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Sha2 {
			private:
				// Разновидность вырабатываемого хеша
				sha_t _type;
			private:
				// Признак того, что хеш уже снят
				bool _finished;
				// Число байтов, накопленных в незавершённом блоке
				size_t _size;
			private:
				// Вычисляемое значение хеша: восемь слов по 64 разряда либо по 32 в младших половинах
				uint64_t _hash[8];
				// Число разобранных байтов сообщения: младшая и старшая части
				uint64_t _count[2];
			private:
				// Накопитель незавершённого блока сообщения
				uint8_t _block[128];
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
				 * @brief Метод получения разновидности вырабатываемого хеша
				 *
				 * @return разновидность вырабатываемого хеша
				 *
				 * \~english
				 * @brief Method of getting the kind of the produced hash
				 * @return the kind of the produced hash
				 *
				 * \~
				 */
				sha_t type() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера блока сообщения
				 *
				 * @return размер блока в байтах: 64 либо 128
				 *
				 * \~english
				 * @brief Method of getting the size of the block of the message
				 * @return the size of the block in bytes: 64 or 128
				 *
				 * \~
				 */
				size_t block() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод сброса состояния хеширования
				 *
				 * @param type разновидность вырабатываемого хеша
				 *
				 * \~english
				 * @brief Method of the reset of the state of the hashing
				 * @param type the kind of the produced hash
				 *
				 * \~
				 */
				void reset(const sha_t type) noexcept;
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
				 * @param type разновидность вырабатываемого хеша
				 *
				 * \~english
				 * @brief Constructor
				 * @param type the kind of the produced hash
				 *
				 * \~
				 */
				Sha2(const sha_t type = sha_t::SHA256) noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Sha2() noexcept;
		} sha2_t;

		/**
		 * \~russian
		 * @brief Метод выработки хеша SHA-2 целого сообщения
		 *
		 * @param type   разновидность вырабатываемого хеша
		 * @param data   хешируемое сообщение
		 * @param result место, в которое записывается хеш
		 * @param size   размер места в байтах, не меньше длины хеша
		 *
		 * @return       признак успешности выработки хеша
		 *
		 * \~english
		 * @brief Method of the production of the SHA-2 hash of a whole message
		 * @param type   the kind of the produced hash
		 * @param data   the message being hashed
		 * @param result the place the hash is written into
		 * @param size   the size of the place in bytes, not less than the length of the hash
		 * @return       the flag of the success of the production of the hash
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool sha2(const sha_t type, const view_t & data, uint8_t * result, const size_t size) noexcept;
	};
};

