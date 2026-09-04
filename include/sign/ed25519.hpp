/**
 * @file ed25519.hpp
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
 * @brief Заголовочный файл модуля выработки и проверки электронной подписи
 *        Ed25519 по RFC 8032
 *
 * \~english
 * @brief Header file of the module of the production and the check of the electronic
 *        signature Ed25519 according to RFC 8032
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_ED25519__
#define __ANTS_ED25519__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <math/number.hpp>

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
	 * @brief Пространство имён модулей электронной подписи
	 *
	 * \~english
	 * @brief Namespace of the electronic signature modules
	 *
	 * \~
	 */
	namespace sign {
		/**
		 * \~russian
		 * @brief Электронная подпись Ed25519 по RFC 8032
		 *
		 * @details Ключ подписи - тридцать два байта зерна, из которых хешем SHA-512
		 *          выводятся скаляр и приставка. Ключ проверки - тридцать два байта
		 *          сжатой точки. Подпись - шестьдесят четыре байта: сжатая точка R и
		 *          скаляр S подряд, оба младшим байтом вперёд.
		 *
		 * @note Подпись детерминирована: случайного числа она не требует, а повтор
		 *       выработки на одном ключе и сообщении выдаёт ту же подпись
		 *
		 * @note Выработка подписи идёт за постоянное время по ключу; проверка подписи
		 *       секретов не касается и вправе идти переменным временем
		 *
		 * \~english
		 * @brief Electronic signature Ed25519 according to RFC 8032
		 * @details The key of the signature is thirty two bytes of a seed, from which the scalar
		 *          and the prefix are derived by the hash SHA-512. The key of the check is thirty
		 *          two bytes of a compressed point. The signature is sixty four bytes: the compressed
		 *          point R and the scalar S in a row, both with the junior byte ahead.
		 * @note The signature is deterministic: it requires no random number, and a repetition of
		 *       the production on a single key and message gives the same signature
		 * @note The production of the signature goes in a constant time by the key; the check of the
		 *       signature touches no secrets and may go in a variable time
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Ed25519 {
			public:
				/**
				 * \~russian
				 * @brief Размер ключа подписи и ключа проверки в байтах
				 *
				 * \~english
				 * @brief Size of the key of the signature and of the key of the check in bytes
				 *
				 * \~
				 */
				static constexpr size_t KEY_SIZE = 32;

				/**
				 * \~russian
				 * @brief Размер подписи в байтах
				 *
				 * \~english
				 * @brief Size of a signature in bytes
				 *
				 * \~
				 */
				static constexpr size_t SIGNATURE_SIZE = 64;
			private:
				// Признак того, что ключ подписи установлен
				bool _secret;
				// Признак того, что ключ проверки подписи установлен
				bool _public;
			private:
				// Скаляр ключа подписи, выведенный из зерна
				uint8_t _scalar[KEY_SIZE];
				// Приставка выработки случайности подписи, выведенная из зерна
				uint8_t _prefix[KEY_SIZE];
				// Сжатая точка ключа проверки подписи
				uint8_t _key[KEY_SIZE];
			private:
				// Арифметика порядка подгруппы точек кривой
				math::modulus_t _order;
			public:
				/**
				 * \~russian
				 * @brief Метод получения размера подписи
				 *
				 * @return размер подписи в байтах
				 *
				 * \~english
				 * @brief Method of getting the size of a signature
				 * @return the size of a signature in bytes
				 *
				 * \~
				 */
				size_t size() const noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния модуля
				 *
				 * \~english
				 * @brief Method of the reset of the state of the module
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки ключа подписи
				 *
				 * @param secret зерно ключа подписи длиной в тридцать два байта
				 *
				 * @return признак успешности установки ключа подписи
				 *
				 * @note Ключ проверки подписи вырабатывается из ключа подписи сразу же
				 *
				 * \~english
				 * @brief Method of setting the key of the signature
				 * @param secret the seed of the key of the signature of a length of thirty two bytes
				 * @return the flag of the success of the setting of the key of the signature
				 * @note The key of the check of the signature is produced from the key of the signature at once
				 *
				 * \~
				 */
				bool secret(const view_t & secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа проверки подписи
				 *
				 * @param key сжатая точка ключа проверки подписи длиной в тридцать два байта
				 *
				 * @return признак успешности установки ключа проверки подписи
				 *
				 * @note Точка, не лежащая на кривой либо записанная неканонически, отвергается
				 *
				 * @note Если ключ подписи уже установлен, открытый ключ из него выведен:
				 *       поданный обязан сойтись с выведенным, тогда состояние не меняется,
				 *       а чужой отвергается. Закрытый ключ этим вызовом не затирается
				 *
				 * \~english
				 * @brief Method of setting the key of the check of the signature
				 * @param key the compressed point of the key of the check of the signature of a length of thirty two bytes
				 * @return the flag of the success of the setting of the key of the check of the signature
				 * @note A point not lying on the curve or written non-canonically is rejected
				 *
				 * @note If the signing key is already set, the public key is derived from it: the given one
				 *       must coincide with the derived one, then the state does not change, and a foreign one
				 *       is rejected. The private key is not wiped by this call
				 *
				 * \~
				 */
				bool key(const view_t & key) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения ключа проверки подписи
				 *
				 * @param result место, в которое записывается сжатая точка ключа проверки подписи
				 * @param size   размер места, не меньше тридцати двух байтов
				 *
				 * @return признак успешности получения ключа проверки подписи
				 *
				 * \~english
				 * @brief Method of getting the key of the check of the signature
				 * @param result the place the compressed point of the key of the check of the signature is written into
				 * @param size   the size of the place, not less than thirty two bytes
				 * @return the flag of the success of the getting of the key of the check of the signature
				 *
				 * \~
				 */
				bool key(uint8_t * result, const size_t size) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод выработки подписи
				 *
				 * @param message подписываемое сообщение целиком
				 * @param result  место, в которое помещается подпись длиной в шестьдесят четыре байта
				 *
				 * @return признак успешности выработки подписи
				 *
				 * @details Раздел 5.1.6 RFC 8032: подписывается само сообщение, а не его хеш -
				 *          хеш SHA-512 берётся внутри дважды, с приставкой и с точкой R
				 *
				 * \~english
				 * @brief Method of the production of a signature
				 * @param message the message being signed as a whole
				 * @param result  the place the signature of a length of sixty four bytes is put into
				 * @return the flag of the success of the production of the signature
				 * @details The section 5.1.6 of RFC 8032: the message itself is signed, not its hash -
				 *          the hash SHA-512 is taken inside twice, with the prefix and with the point R
				 *
				 * \~
				 */
				bool make(const view_t & message, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки подписи
				 *
				 * @param message   подписанное сообщение целиком
				 * @param signature проверяемая подпись длиной в шестьдесят четыре байта
				 *
				 * @return признак того, что подпись сошлась
				 *
				 * @details Раздел 5.1.7 RFC 8032: скаляр S, не меньший порядка подгруппы, и
				 *          точка R, записанная неканонически либо не лежащая на кривой,
				 *          отвергаются прежде всякой арифметики
				 *
				 * \~english
				 * @brief Method of the check of a signature
				 * @param message   the signed message as a whole
				 * @param signature the signature being checked of a length of sixty four bytes
				 * @return the flag of the signature having converged
				 * @details The section 5.1.7 of RFC 8032: the scalar S not less than the order of the
				 *          subgroup and the point R written non-canonically or not lying on the curve
				 *          are rejected before any arithmetic
				 *
				 * \~
				 */
				bool check(const view_t & message, const view_t & signature) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Ed25519() noexcept;
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
				~Ed25519() noexcept;
		} ed25519_t;
	};
};

#endif // __ANTS_ED25519__
