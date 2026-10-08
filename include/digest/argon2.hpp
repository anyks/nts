/**
 * @file argon2.hpp
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
 * @brief Модуль вывода ключа из пароля Argon2 по RFC 9106: Argon2d, Argon2i, Argon2id
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
#include <string>
#include <vector>
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
		 * @brief Издание Argon2, которое ведёт модуль (0x13)
		 *
		 * \~english
		 * @brief Edition of Argon2 the module implements (0x13)
		 *
		 * \~
		 */
		static constexpr uint32_t ARGON2_VERSION = 0x13;
		/**
		 * \~russian
		 * @brief Разновидности Argon2 по разделу 3.1 RFC 9106
		 *
		 * @details Значение перечисления есть параметр y стандарта
		 *
		 * \~english
		 * @brief Kinds of Argon2 by section 3.1 of RFC 9106
		 *
		 * @details The value of the enumeration is the y parameter of the standard
		 *
		 * \~
		 */
		enum class argon_t : uint8_t {
			ARGON2D  = 0x00, /*!< \~russian Argon2d: обращения к памяти зависят от пароля \~english Argon2d: the memory accesses depend on the password \~ */
			ARGON2I  = 0x01, /*!< \~russian Argon2i: обращения к памяти от пароля не зависят \~english Argon2i: the memory accesses are independent of the password \~ */
			ARGON2ID = 0x02  /*!< \~russian Argon2id: первая половина первого прохода как 2i, далее как 2d \~english Argon2id: the first half of the first pass as 2i, then as 2d \~ */
		};
		/**
		 * \~russian
		 * @brief Параметры Argon2
		 *
		 * @details Память задаётся в кибибайтах и обязана быть не меньше 8·lanes; проходов и
		 *          дорожек - не меньше одной; длина метки - не меньше четырёх байтов. Значения
		 *          хранятся потребителем рядом с солью и меткой и читаются оттуда при проверке
		 *
		 * \~english
		 * @brief Argon2 parameters
		 *
		 * @details The memory is set in kibibytes and must be at least 8·lanes; the passes and
		 *          the lanes - at least one; the tag length - at least four bytes. The values are
		 *          stored by the consumer next to the salt and the tag and read from there at a check
		 *
		 * \~
		 */
		typedef struct Argon {
			// Разновидность
			argon_t type;
			// Память в кибибайтах (m)
			uint32_t memory;
			// Число проходов (t)
			uint32_t passes;
			// Число дорожек (p)
			uint32_t lanes;
			/**
			 * \~russian
			 * @brief Конструктор: Argon2id, 64 МиБ, три прохода, четыре дорожки (второй набор раздела 4 RFC 9106)
			 *
			 * \~english
			 * @brief Constructor: Argon2id, 64 MiB, three passes, four lanes (the second set of section 4 of RFC 9106)
			 *
			 * \~
			 */
			Argon() noexcept : type(argon_t::ARGON2ID), memory(65536), passes(3), lanes(4) {}
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param type   разновидность
			 * @param memory память в кибибайтах
			 * @param passes число проходов
			 * @param lanes  число дорожек
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * @param type   kind
			 * @param memory memory in kibibytes
			 * @param passes number of the passes
			 * @param lanes  number of the lanes
			 *
			 * \~
			 */
			Argon(const argon_t type, const uint32_t memory, const uint32_t passes, const uint32_t lanes) noexcept : type(type), memory(memory), passes(passes), lanes(lanes) {}
		} argon_params_t;
		/**
		 * \~russian
		 * @brief Метод вывода ключа из пароля Argon2
		 *
		 * @details Алгоритм раздела 3 RFC 9106 издания 0x13. Память под матрицу блоков занимается
		 *          на время вызова и затирается; при нехватке памяти метод отвечает отказом, а не
		 *          падением. Дорожки считаются последовательно: итог от числа потоков не зависит
		 *
		 * @param params     параметры
		 * @param password   пароль (P)
		 * @param salt       соль (S), не короче восьми байтов
		 * @param secret     тайное значение (K) либо пустой вид
		 * @param associated связанные данные (X) либо пустой вид
		 * @param result     место, в которое помещается метка (T)
		 * @param size       длина метки в байтах, не меньше четырёх
		 *
		 * @return           признак того, что метка выведена
		 *
		 * \~english
		 * @brief Method of the derivation of a key from a password by Argon2
		 *
		 * @details The algorithm of section 3 of RFC 9106, edition 0x13. The memory for the block
		 *          matrix is taken for the duration of the call and wiped; at a lack of memory the
		 *          method answers by a refusal, not by a crash. The lanes are computed sequentially:
		 *          the result does not depend on the number of the threads
		 *
		 * @param params     parameters
		 * @param password   password (P)
		 * @param salt       salt (S), at least eight bytes
		 * @param secret     secret value (K) or an empty view
		 * @param associated associated data (X) or an empty view
		 * @param result     place into which the tag (T) is put
		 * @param size       length of the tag in bytes, at least four
		 *
		 * @return           sign that the tag is derived
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool argon2(const argon_params_t & params, const view_t & password, const view_t & salt, const view_t & secret, const view_t & associated, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Запись Argon2 в строке PHC: параметры, соль и необязательный выход
		 *
		 * @details Строка вида `$argon2id$v=19$m=65536,t=3,p=4$соль[$выход]` (base64 без
		 *          дополнения). Блок параметров с солью - обязательная часть, годная и выводу
		 *          ключа (выход нигде не хранится), и проверке пароля; хвост с выходом -
		 *          необязательная часть, у вывода ключа пустая
		 *
		 * \~english
		 * @brief Argon2 record in the PHC string: the parameters, the salt and the optional output
		 *
		 * @details A string of the form `$argon2id$v=19$m=65536,t=3,p=4$salt[$output]` (base64
		 *          without padding). The block of the parameters with the salt is the mandatory part,
		 *          fit both for a key derivation (the output is stored nowhere) and for a password
		 *          check; the tail with the output is the optional part, empty at a key derivation
		 *
		 * \~
		 */
		typedef struct Record {
			// Параметры
			argon_params_t params;
			// Соль
			vector <uint8_t> salt;
			// Выход (метка) либо пусто
			vector <uint8_t> tag;
			// Тайное значение (K) либо пусто: строка PHC его не несёт, запись с ним отвергается
			vector <uint8_t> secret;
			// Связанные данные (X) либо пусто: строка PHC их не несёт, запись с ними отвергается
			vector <uint8_t> associated;
		} argon_record_t;
		/**
		 * \~russian
		 * @brief Метод разбора строки PHC
		 *
		 * @details Принимаются лишь `argon2d`, `argon2i`, `argon2id` с `v=19` (издание 0x13, единственное
		 *          у модуля), параметры строго в порядке `m,t,p`, соль и выход в base64 без дополнения;
		 *          поля `keyid` и `data` не поддерживаются - отказ
		 *
		 * @param text   строка PHC
		 * @param result запись
		 *
		 * @return       признак того, что строка разобрана
		 *
		 * \~english
		 * @brief Method of the parsing of a PHC string
		 *
		 * @details Only `argon2d`, `argon2i`, `argon2id` with `v=19` are accepted (edition 0x13, the
		 *          only one of the module), the parameters strictly in the order `m,t,p`, the salt and
		 *          the output in base64 without padding; the `keyid` and `data` fields are not
		 *          supported - a refusal
		 *
		 * @param text   PHC string
		 * @param result record
		 *
		 * @return       sign that the string is parsed
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool phc(const string & text, argon_record_t & result) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи строки PHC
		 *
		 * @param record запись: соль не короче восьми байтов, выход при наличии не короче четырёх
		 * @param result строка PHC
		 *
		 * @return       признак того, что строка записана
		 *
		 * @note Запись с непустым тайным значением либо связанными данными отвергается: строка
		 *       PHC их не несёт, и запись, молча теряющая часть входа, дала бы при чтении иной ключ
		 *
		 * \~english
		 * @brief Method of the writing of a PHC string
		 *
		 * @param record record: the salt not shorter than eight bytes, the output when present not shorter than four
		 * @param result PHC string
		 *
		 * @return       sign that the string is written
		 *
		 * @note A record with a non-empty secret value or associated data is refused: the PHC string
		 *       does not carry them, and a writing that silently loses a part of the input would give
		 *       another key at the reading
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool phc(const argon_record_t & record, string & result) noexcept;
	};
};

