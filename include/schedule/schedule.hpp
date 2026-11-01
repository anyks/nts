/**
 * @file schedule.hpp
 * @date 2026-08-29
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
 * @brief Заголовочный файл модуля расписания ключей протокола TLS 1.3 на хеше по
 *        ГОСТ Р 34.11-2012
 *
 * \~english
 * @brief Header file of the module of the key schedule of the TLS 1.3 protocol on the hash
 *        according to GOST R 34.11-2012
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
#include <digest/hash.hpp>

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
	 * @brief Пространство имён расписания ключей протокола TLS
	 *
	 * @details Раздел 7.1 RFC 8446: всякий ключ связи выводится из предыдущего значения
	 *          цепочкой извлечения и растяжения, а метка назначения и хеш переписки
	 *          рукопожатия входят в вывод наравне с самим значением. Оттого ключ связан и
	 *          со своим назначением, и со всем, что стороны друг другу сказали.
	 *
	 * @note Расписание ведётся хешем набора шифрования: у наборов на алгоритмах ГОСТ это
	 *       «Стрибог» длиной 256 разрядов (раздел 4.2 описания наборов), у классических
	 *       наборов - SHA-256 либо SHA-384 (раздел 7.1 RFC 8446). Методы без довода хеша
	 *       ведут расписание «Стрибогом» - так сложена ветвь ГОСТ, и итог её не меняется
	 *
	 * \~english
	 * @brief Namespace of the key schedule of the TLS protocol
	 *
	 * @details The section 7.1 of RFC 8446: every key of a connection is derived from the previous
	 *          value by a chain of an extraction and an expansion, while the label of the purpose and
	 *          the hash of the transcript of the handshake enter the derivation on a par with the value
	 *          itself. Hence a key is bound both to its purpose and to everything the parties have said
	 *          to each other.
	 *
	 * @note The schedule is conducted by the hash of the cipher suite: at the suites on the GOST
	 *       algorithms it is «Streebog» of a length of 256 bits (the section 4.2 of the description of
	 *       the suites), at the classic suites it is SHA-256 or SHA-384 (the section 7.1 of RFC 8446).
	 *       The methods without the argument of the hash conduct the schedule by «Streebog» - so the
	 *       GOST branch is composed, and its outcome does not change
	 *
	 * \~
	 */
	namespace schedule {
		/**
		 * \~russian
		 * @brief Длина значения расписания ключей в байтах у хеша в 256 разрядов
		 *
		 * @note У расписания на SHA-384 значение длиннее: наибольшую длину задаёт SCHEDULE_WIDEST
		 *
		 * \~english
		 * @brief Length of a value of the key schedule in bytes at a hash of 256 bits
		 *
		 * @note At the schedule on SHA-384 a value is longer: the greatest length is set by SCHEDULE_WIDEST
		 *
		 * \~
		 */
		static constexpr size_t SCHEDULE_SECRET = 32;

		/**
		 * \~russian
		 * @brief Наибольшая длина значения расписания ключей в байтах
		 *
		 * @details Длина значения равна длине хеша набора шифрования, и место под значение
		 *          заводится по наибольшему из хешей библиотеки
		 *
		 * \~english
		 * @brief Greatest length of a value of the key schedule in bytes
		 *
		 * @details The length of a value equals the length of the hash of the cipher suite, and the place
		 *          for a value is set up by the greatest of the hashes of the library
		 *
		 * \~
		 */
		static constexpr size_t SCHEDULE_WIDEST = 64;

		/**
		 * \~russian
		 * @brief Наибольшая длина метки назначения выводимого значения в байтах
		 *
		 * @details Раздел 7.1 RFC 8446: метка вместе с приставкой протокола записывается
		 *          одним байтом длины, а приставка занимает шесть байтов
		 *
		 * \~english
		 * @brief Greatest length of the label of the purpose of a value being derived in bytes
		 *
		 * @details The section 7.1 of RFC 8446: a label together with the prefix of the protocol is
		 *          written by a single byte of a length, while the prefix occupies six bytes
		 *
		 * \~
		 */
		static constexpr size_t SCHEDULE_LABEL = (255 - 6);

		/**
		 * \~russian
		 * @brief Функция извлечения значения расписания ключей
		 *
		 * @param salt   соль извлечения значения
		 * @param key    ключевой материал, из которого извлекается значение
		 * @param result место, в которое помещается извлечённое значение
		 * @return       признак успешности извлечения значения
		 *
		 * @details Раздел 2.2 RFC 5869: извлечение есть имитовставка, где солью служит ключ,
		 *          а ключевым материалом - сообщение
		 *
		 * @note Место итога обязано вмещать SCHEDULE_SECRET байтов
		 *
		 * \~english
		 * @brief Function of the extraction of a value of the key schedule
		 *
		 * @param salt   the salt of the extraction of the value
		 * @param key    the key material the value is extracted from
		 * @param result the place the extracted value is put into
		 * @return       the flag of the success of the extraction of the value
		 *
		 * @details The section 2.2 of RFC 5869: an extraction is an authentication code, where the salt
		 *          serves as the key and the key material serves as the message
		 *
		 * @note The place of the outcome is obliged to hold SCHEDULE_SECRET bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool extract(const view_t & salt, const view_t & key, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Функция извлечения значения расписания ключей выбранным хешем
		 *
		 * @param algorithm хеш, которым ведётся расписание ключей
		 * @param salt      соль извлечения значения
		 * @param key       ключевой материал, из которого извлекается значение
		 * @param result    место, в которое помещается извлечённое значение
		 * @return          признак успешности извлечения значения
		 *
		 * @note Место итога обязано вмещать длину хеша
		 *
		 * \~english
		 * @brief Function of the extraction of a value of the key schedule by the chosen hash
		 *
		 * @param algorithm the hash the key schedule is conducted by
		 * @param salt      the salt of the extraction of the value
		 * @param key       the key material the value is extracted from
		 * @param result    the place the extracted value is put into
		 * @return          the flag of the success of the extraction of the value
		 *
		 * @note The place of the outcome is obliged to hold the length of the hash
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool extract(const digest::hash_t algorithm, const view_t & salt, const view_t & key, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Функция растяжения значения расписания ключей
		 *
		 * @param secret растягиваемое значение расписания ключей
		 * @param info   описание назначения растянутого значения
		 * @param result место, в которое помещается растянутое значение
		 * @param size   требуемая длина растянутого значения в байтах
		 * @return       признак успешности растяжения значения
		 *
		 * @details Раздел 2.3 RFC 5869: значение растягивается цепочкой имитовставок, где
		 *          всякая следующая берётся от предыдущей, описания назначения и порядкового
		 *          номера части
		 *
		 * \~english
		 * @brief Function of the expansion of a value of the key schedule
		 *
		 * @param secret the value of the key schedule being expanded
		 * @param info   the description of the purpose of the expanded value
		 * @param result the place the expanded value is put into
		 * @param size   the required length of the expanded value in bytes
		 * @return       the flag of the success of the expansion of the value
		 *
		 * @details The section 2.3 of RFC 5869: a value is expanded by a chain of the authentication
		 *          codes, where every next one is taken from the previous one, from the description of
		 *          the purpose and from the sequence number of the part
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool expand(const view_t & secret, const view_t & info, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Функция растяжения значения расписания ключей выбранным хешем
		 *
		 * @param algorithm хеш, которым ведётся расписание ключей
		 * @param secret    растягиваемое значение расписания ключей
		 * @param info      описание назначения растянутого значения
		 * @param result    место, в которое помещается растянутое значение
		 * @param size      требуемая длина растянутого значения в байтах
		 * @return          признак успешности растяжения значения
		 *
		 * \~english
		 * @brief Function of the expansion of a value of the key schedule by the chosen hash
		 *
		 * @param algorithm the hash the key schedule is conducted by
		 * @param secret    the value of the key schedule being expanded
		 * @param info      the description of the purpose of the expanded value
		 * @param result    the place the expanded value is put into
		 * @param size      the required length of the expanded value in bytes
		 * @return          the flag of the success of the expansion of the value
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool expand(const digest::hash_t algorithm, const view_t & secret, const view_t & info, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Функция вывода значения по метке назначения
		 *
		 * @param secret  значение расписания ключей, из которого ведётся вывод
		 * @param label   метка назначения выводимого значения
		 * @param context привязка выводимого значения к переписке рукопожатия
		 * @param result  место, в которое помещается выведенное значение
		 * @param size    требуемая длина выведенного значения в байтах
		 * @return        признак успешности вывода значения
		 *
		 * @details Раздел 7.1 RFC 8446: описанием назначения служит запись из требуемой длины,
		 *          метки с приставкой протокола и привязки, каждая своей длиной вперёд
		 *
		 * \~english
		 * @brief Function of the derivation of a value by a label of a purpose
		 *
		 * @param secret  the value of the key schedule the derivation is conducted from
		 * @param label   the label of the purpose of the value being derived
		 * @param context the binding of the value being derived to the transcript of the handshake
		 * @param result  the place the derived value is put into
		 * @param size    the required length of the derived value in bytes
		 * @return        the flag of the success of the derivation of the value
		 *
		 * @details The section 7.1 of RFC 8446: a record of the required length, of the label with the
		 *          prefix of the protocol and of the binding, each with its length ahead, serves as the
		 *          description of the purpose
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool derive(const view_t & secret, const view_t & label, const view_t & context, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Функция вывода значения по метке назначения выбранным хешем
		 *
		 * @param algorithm хеш, которым ведётся расписание ключей
		 * @param secret    значение расписания ключей, из которого ведётся вывод
		 * @param label     метка назначения выводимого значения
		 * @param context   привязка выводимого значения к переписке рукопожатия
		 * @param result    место, в которое помещается выведенное значение
		 * @param size      требуемая длина выведенного значения в байтах
		 * @return          признак успешности вывода значения
		 *
		 * \~english
		 * @brief Function of the derivation of a value by a label of a purpose by the chosen hash
		 *
		 * @param algorithm the hash the key schedule is conducted by
		 * @param secret    the value of the key schedule the derivation is conducted from
		 * @param label     the label of the purpose of the value being derived
		 * @param context   the binding of the value being derived to the transcript of the handshake
		 * @param result    the place the derived value is put into
		 * @param size      the required length of the derived value in bytes
		 * @return          the flag of the success of the derivation of the value
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool derive(const digest::hash_t algorithm, const view_t & secret, const view_t & label, const view_t & context, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Функция вывода очередного значения расписания ключей
		 *
		 * @param secret значение расписания ключей, из которого ведётся вывод
		 * @param label  метка назначения выводимого значения
		 * @param digest хеш переписки рукопожатия на этот миг
		 * @param result место, в которое помещается выведенное значение
		 * @return       признак успешности вывода значения
		 *
		 * @details Раздел 7.1 RFC 8446: то же, что и вывод по метке назначения, но длиной в
		 *          хеш, а привязкой берётся хеш переписки рукопожатия
		 *
		 * @note Место итога обязано вмещать SCHEDULE_SECRET байтов
		 *
		 * \~english
		 * @brief Function of the derivation of the next value of the key schedule
		 *
		 * @param secret the value of the key schedule the derivation is conducted from
		 * @param label  the label of the purpose of the value being derived
		 * @param digest the hash of the transcript of the handshake at this moment
		 * @param result the place the derived value is put into
		 * @return       the flag of the success of the derivation of the value
		 *
		 * @details The section 7.1 of RFC 8446: the same as the derivation by a label of a purpose, but
		 *          of a length of the hash, while the hash of the transcript of the handshake is taken
		 *          as the binding
		 *
		 * @note The place of the outcome is obliged to hold SCHEDULE_SECRET bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool secret(const view_t & secret, const view_t & label, const view_t & digest, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Функция вывода очередного значения расписания ключей выбранным хешем
		 *
		 * @param algorithm хеш, которым ведётся расписание ключей
		 * @param secret    значение расписания ключей, из которого ведётся вывод
		 * @param label     метка назначения выводимого значения
		 * @param digest    хеш переписки рукопожатия на этот миг
		 * @param result    место, в которое помещается выведенное значение
		 * @return          признак успешности вывода значения
		 *
		 * @note Место итога обязано вмещать длину хеша
		 *
		 * \~english
		 * @brief Function of the derivation of the next value of the key schedule by the chosen hash
		 *
		 * @param algorithm the hash the key schedule is conducted by
		 * @param secret    the value of the key schedule the derivation is conducted from
		 * @param label     the label of the purpose of the value being derived
		 * @param digest    the hash of the transcript of the handshake at this moment
		 * @param result    the place the derived value is put into
		 * @return          the flag of the success of the derivation of the value
		 *
		 * @note The place of the outcome is obliged to hold the length of the hash
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool secret(const digest::hash_t algorithm, const view_t & secret, const view_t & label, const view_t & digest, uint8_t * result) noexcept;
	};
};

