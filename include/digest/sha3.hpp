/**
 * @file sha3.hpp
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
 * \~russian
 * @brief Модуль хеширования SHA-3 и функций переменного выхода SHAKE по FIPS 202
 *
 * \~english
 * @brief Module of the hashing SHA-3 and the functions of a variable output SHAKE according to FIPS 202
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
		 * @brief Размер состояния Keccak-f[1600] в байтах
		 *
		 * \~english
		 * @brief Size of the Keccak-f[1600] state in bytes
		 *
		 * \~
		 */
		static constexpr size_t SHA3_STATE = 200;
		/**
		 * \~russian
		 * @brief Разновидности преобразований FIPS 202
		 *
		 * @details У хешей значение перечисления равно длине итога в байтах; у функций
		 *          переменного выхода длина итога выбирается вызывающей стороной
		 *
		 * \~english
		 * @brief Kinds of the FIPS 202 transformations
		 *
		 * @details At the hashes the value of the enumeration is equal to the length of the
		 *          result in bytes; at the extendable-output functions the length of the result
		 *          is chosen by the caller
		 *
		 * \~
		 */
		enum class sha3_t : uint8_t {
			// Разновидность не установлена
			NONE     = 0x00, /*!< \~russian Разновидность не установлена \~english The kind is not set \~ */
			// Хеш SHA3-224
			SHA3_224 = 0x1C, /*!< \~russian Хеш SHA3-224 \~english The SHA3-224 hash \~ */
			// Хеш SHA3-256
			SHA3_256 = 0x20, /*!< \~russian Хеш SHA3-256 \~english The SHA3-256 hash \~ */
			// Хеш SHA3-384
			SHA3_384 = 0x30, /*!< \~russian Хеш SHA3-384 \~english The SHA3-384 hash \~ */
			// Хеш SHA3-512
			SHA3_512 = 0x40, /*!< \~russian Хеш SHA3-512 \~english The SHA3-512 hash \~ */
			// Функция переменного выхода SHAKE128
			SHAKE128 = 0x81, /*!< \~russian Функция переменного выхода SHAKE128 \~english The SHAKE128 extendable-output function \~ */
			// Функция переменного выхода SHAKE256
			SHAKE256 = 0x82, /*!< \~russian Функция переменного выхода SHAKE256 \~english The SHAKE256 extendable-output function \~ */
			// Настраиваемая функция переменного выхода cSHAKE128 (SP 800-185)
			CSHAKE128 = 0x91, /*!< \~russian Настраиваемая функция переменного выхода cSHAKE128 (SP 800-185) \~english The customizable extendable-output function cSHAKE128 (SP 800-185) \~ */
			// Настраиваемая функция переменного выхода cSHAKE256 (SP 800-185)
			CSHAKE256 = 0x92  /*!< \~russian Настраиваемая функция переменного выхода cSHAKE256 (SP 800-185) \~english The customizable extendable-output function cSHAKE256 (SP 800-185) \~ */
		};
		/**
		 * \~russian
		 * @brief Функция получения длины итога разновидности
		 *
		 * @param type разновидность преобразования
		 * @return     длина итога хеша в байтах либо нуль у функций переменного выхода
		 *
		 * \~english
		 * @brief Function of the obtaining of the length of the result of a kind
		 *
		 * @param type kind of the transformation
		 * @return     length of the result of the hash in bytes or zero at the extendable-output functions
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t length(const sha3_t type) noexcept;
		/**
		 * \~russian
		 * @brief Функция получения скорости разновидности
		 *
		 * @param type разновидность преобразования
		 * @return     число байтов, поглощаемых или выдаваемых за одну перестановку, либо нуль
		 *
		 * \~english
		 * @brief Function of the obtaining of the rate of a kind
		 *
		 * @param type kind of the transformation
		 * @return     number of the bytes absorbed or squeezed per one permutation or zero
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t rate(const sha3_t type) noexcept;
		/**
		 * \~russian
		 * @brief Класс преобразования FIPS 202
		 *
		 * @details Губка Keccak: сообщение поглощается кусками по скорости разновидности,
		 *          затем состояние дополняется по правилу разновидности и итог выжимается.
		 *          У хешей итог снимается методом finish ровно на длину разновидности; у
		 *          функций переменного выхода итог выжимается методом squeeze любыми кусками
		 *          сколько угодно раз, а поглощение после первого выжимания отвергается
		 *
		 * \~english
		 * @brief Class of a FIPS 202 transformation
		 *
		 * @details The Keccak sponge: the message is absorbed by the pieces of the rate of the
		 *          kind, then the state is padded by the rule of the kind and the result is
		 *          squeezed. At the hashes the result is taken by the finish method exactly to
		 *          the length of the kind; at the extendable-output functions the result is
		 *          squeezed by the squeeze method by any pieces any number of times, and an
		 *          absorption after the first squeezing is refused
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Keccak {
			private:
				// Разновидность преобразования
				sha3_t _type;
			private:
				// Признак того, что выжимание итога началось
				bool _squeezing;
				// Число байтов, поглощённых в незавершённый блок либо уже выжатых из блока
				size_t _size;
				// Скорость разновидности в байтах
				size_t _rate;
			private:
				// Состояние губки: двадцать пять полос по 64 разряда
				uint64_t _state[25];
			private:
				/**
				 * \~russian
				 * @brief Метод перестановки состояния Keccak-f[1600]
				 *
				 * \~english
				 * @brief Method of the permutation of the state of Keccak-f[1600]
				 *
				 * \~
				 */
				void permute() noexcept;
				/**
				 * \~russian
				 * @brief Метод дополнения сообщения и перехода к выжиманию
				 *
				 * \~english
				 * @brief Method of the padding of the message and the transition to the squeezing
				 *
				 * \~
				 */
				void seal() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения разновидности преобразования
				 *
				 * @return разновидность преобразования
				 *
				 * \~english
				 * @brief Method of the obtaining of the kind of the transformation
				 *
				 * @return kind of the transformation
				 *
				 * \~
				 */
				sha3_t type() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения скорости преобразования
				 *
				 * @return число байтов, поглощаемых за одну перестановку
				 *
				 * \~english
				 * @brief Method of the obtaining of the rate of the transformation
				 *
				 * @return number of the bytes absorbed per one permutation
				 *
				 * \~
				 */
				size_t block() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод сброса преобразования в начальное состояние
				 *
				 * @param type разновидность преобразования
				 *
				 * \~english
				 * @brief Method of the reset of the transformation to the initial state
				 *
				 * @param type kind of the transformation
				 *
				 * \~
				 */
				void reset(const sha3_t type) noexcept;
				/**
				 * \~russian
				 * @brief Метод поглощения куска сообщения
				 *
				 * @param data кусок сообщения
				 * @return     признак того, что кусок поглощён: после выжимания поглощение отвергается
				 *
				 * \~english
				 * @brief Method of the absorption of a piece of the message
				 *
				 * @param data piece of the message
				 * @return     sign that the piece is absorbed: after a squeezing the absorption is refused
				 *
				 * \~
				 */
				bool update(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод выжимания куска итога функции переменного выхода
				 *
				 * @param result место, в которое помещается кусок итога
				 * @param size   длина куска итога в байтах
				 * @return       признак того, что кусок выжат: у хешей выжимание отвергается
				 *
				 * \~english
				 * @brief Method of the squeezing of a piece of the result of an extendable-output function
				 *
				 * @param result place into which the piece of the result is put
				 * @param size   length of the piece of the result in bytes
				 * @return       sign that the piece is squeezed: at the hashes the squeezing is refused
				 *
				 * \~
				 */
				bool squeeze(uint8_t * result, const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия итога хеша
				 *
				 * @param result место, в которое помещается итог
				 * @param size   длина места в байтах: у хешей ровно длина разновидности, у функций переменного выхода любая
				 * @return       признак того, что итог снят; повторное снятие отвергается
				 *
				 * \~english
				 * @brief Method of the taking of the result of the hash
				 *
				 * @param result place into which the result is put
				 * @param size   length of the place in bytes: at the hashes exactly the length of the kind, at the extendable-output functions any
				 * @return       sign that the result is taken; a repeated taking is refused
				 *
				 * \~
				 */
				bool finish(uint8_t * result, const size_t size) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 * @param type разновидность преобразования
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * @param type kind of the transformation
				 *
				 * \~
				 */
				Keccak(const sha3_t type) noexcept;
				/**
				 * \~russian
				 * @brief Деструктор: состояние затирается
				 *
				 * \~english
				 * @brief Destructor: the state is wiped
				 *
				 * \~
				 */
				~Keccak() noexcept;
		} keccak_t;
		/**
		 * \~russian
		 * @brief Функция хеширования сообщения за один вызов
		 *
		 * @param type   разновидность преобразования
		 * @param data   сообщение
		 * @param result место, в которое помещается итог
		 * @param size   длина итога в байтах: у хешей ровно длина разновидности, у функций переменного выхода любая
		 * @return       признак того, что итог вычислен
		 *
		 * \~english
		 * @brief Function of the hashing of a message by one call
		 *
		 * @param type   kind of the transformation
		 * @param data   message
		 * @param result place into which the result is put
		 * @param size   length of the result in bytes: at the hashes exactly the length of the kind, at the extendable-output functions any
		 * @return       sign that the result is computed
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool sha3(const sha3_t type, const view_t & data, uint8_t * result, const size_t size) noexcept;
	};
};

