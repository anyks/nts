/**
 * @file blake2.hpp
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
 * @brief Модуль хеширования BLAKE2b и BLAKE2s по RFC 7693 с ключевым режимом и переменной длиной итога
 *
 * @section Намеренные решения
 *
 * 1. BLAKE2 заведён и в общий перечень `digest::hash_t` (BLAKE2S256, BLAKE2B512), оттого HMAC и
 *    HKDF идут поверх него как поверх любого хеша. Это выглядит избыточным при родном ключевом
 *    режиме, но именно так описаны Noise и WireGuard: HKDF там строится над HMAC-BLAKE2s, а не над
 *    ключевым BLAKE2s. Соблюдение описания, а не недосмотр; ключевой режим - для тех, кому он нужен
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_BLAKE2__
#define __ANTS_BLAKE2__

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
		 * @brief Наибольшая длина итога и ключа BLAKE2b в байтах
		 *
		 * \~english
		 * @brief Greatest length of the result and of the key of BLAKE2b in bytes
		 *
		 * \~
		 */
		static constexpr size_t BLAKE2B_LENGTH = 64;
		/**
		 * \~russian
		 * @brief Наибольшая длина итога и ключа BLAKE2s в байтах
		 *
		 * \~english
		 * @brief Greatest length of the result and of the key of BLAKE2s in bytes
		 *
		 * \~
		 */
		static constexpr size_t BLAKE2S_LENGTH = 32;
		/**
		 * \~russian
		 * @brief Разновидности BLAKE2
		 *
		 * \~english
		 * @brief Kinds of BLAKE2
		 *
		 * \~
		 */
		enum class blake_t : uint8_t {
			NONE    = 0x00, /*!< \~russian Разновидность не установлена \~english The kind is not set \~ */
			BLAKE2B = 0x40, /*!< \~russian BLAKE2b: слова в 64 разряда, блок 128 байтов, итог до 64 байтов \~english BLAKE2b: 64-bit words, 128-byte block, result up to 64 bytes \~ */
			BLAKE2S = 0x20  /*!< \~russian BLAKE2s: слова в 32 разряда, блок 64 байта, итог до 32 байтов \~english BLAKE2s: 32-bit words, 64-byte block, result up to 32 bytes \~ */
		};
		/**
		 * \~russian
		 * @brief Класс хеширования BLAKE2
		 *
		 * @details Длина итога задаётся при заведении от 1 до наибольшей у разновидности; ключ
		 *          необязателен и длиной до наибольшей у разновидности - с ним хеш есть
		 *          имитовставка (раздел 3.3 RFC 7693). Сообщение подаётся кусками любой длины
		 *
		 * \~english
		 * @brief Class of the BLAKE2 hashing
		 *
		 * @details The length of the result is set at the start from 1 up to the greatest of the
		 *          kind; the key is optional and up to the greatest of the kind - with it the hash
		 *          is a MAC (section 3.3 of RFC 7693). The message is fed by pieces of any length
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Blake2 {
			private:
				// Разновидность хеша
				blake_t _type;
			private:
				// Признак того, что итог уже снят либо разновидность не заведена
				bool _finished;
				// Длина итога в байтах
				size_t _length;
				// Число байтов в незавершённом блоке
				size_t _size;
			private:
				// Состояние: восемь слов по 64 разряда либо по 32 в младших половинах
				uint64_t _hash[8];
				// Счётчик поглощённых байтов: младшая и старшая части
				uint64_t _count[2];
			private:
				// Накопитель незавершённого блока
				uint8_t _block[128];
			private:
				/**
				 * @brief Метод сжатия блока
				 *
				 * @param last признак последнего блока
				 *
				 */
				void compress(const bool last) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения разновидности хеша
				 *
				 * @return разновидность хеша
				 *
				 * \~english
				 * @brief Method of the obtaining of the kind of the hash
				 *
				 * @return kind of the hash
				 *
				 * \~
				 */
				blake_t type() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения длины итога
				 *
				 * @return длина итога в байтах
				 *
				 * \~english
				 * @brief Method of the obtaining of the length of the result
				 *
				 * @return length of the result in bytes
				 *
				 * \~
				 */
				size_t length() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера блока разновидности
				 *
				 * @return размер блока в байтах
				 *
				 * \~english
				 * @brief Method of the obtaining of the block size of the kind
				 *
				 * @return block size in bytes
				 *
				 * \~
				 */
				size_t block() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод заведения хеша
				 *
				 * @param type   разновидность
				 * @param length длина итога в байтах от 1 до наибольшей у разновидности
				 * @param key    ключ имитовставки либо пустой вид
				 *
				 * @return       признак того, что хеш заведён
				 *
				 * \~english
				 * @brief Method of the start of the hash
				 *
				 * @param type   kind
				 * @param length length of the result in bytes from 1 up to the greatest of the kind
				 * @param key    key of the MAC or an empty view
				 *
				 * @return       sign that the hash is started
				 *
				 * \~
				 */
				bool start(const blake_t type, const size_t length, const view_t & key) noexcept;
				/**
				 * \~russian
				 * @brief Метод подачи куска сообщения
				 *
				 * @param data кусок сообщения
				 *
				 * @return     признак того, что кусок поглощён
				 *
				 * \~english
				 * @brief Method of the feeding of a piece of the message
				 *
				 * @param data piece of the message
				 *
				 * @return     sign that the piece is absorbed
				 *
				 * \~
				 */
				bool update(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия итога
				 *
				 * @param result место, в которое помещается итог
				 * @param size   длина места: ровно длина итога
				 *
				 * @return       признак того, что итог снят; повторное снятие отвергается
				 *
				 * \~english
				 * @brief Method of the taking of the result
				 *
				 * @param result place into which the result is put
				 * @param size   length of the place: exactly the length of the result
				 *
				 * @return       sign that the result is taken; a repeated taking is refused
				 *
				 * \~
				 */
				bool finish(uint8_t * result, const size_t size) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор: хеш не заведён
				 *
				 * \~english
				 * @brief Constructor: the hash is not started
				 *
				 * \~
				 */
				Blake2() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор: состояние затирается
				 *
				 * \~english
				 * @brief Destructor: the state is wiped
				 *
				 * \~
				 */
				~Blake2() noexcept;
		} blake2_t;
		/**
		 * \~russian
		 * @brief Метод хеширования сообщения за один вызов
		 *
		 * @param type   разновидность
		 * @param key    ключ имитовставки либо пустой вид
		 * @param data   сообщение
		 * @param result место, в которое помещается итог
		 * @param size   длина итога в байтах от 1 до наибольшей у разновидности
		 *
		 * @return       признак того, что итог вычислен
		 *
		 * \~english
		 * @brief Method of the hashing of a message by one call
		 *
		 * @param type   kind
		 * @param key    key of the MAC or an empty view
		 * @param data   message
		 * @param result place into which the result is put
		 * @param size   length of the result in bytes from 1 up to the greatest of the kind
		 *
		 * @return       sign that the result is computed
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool blake2(const blake_t type, const view_t & key, const view_t & data, uint8_t * result, const size_t size) noexcept;
	};
};

#endif // __ANTS_BLAKE2__
