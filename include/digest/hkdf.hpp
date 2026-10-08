/**
 * @file hkdf.hpp
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
 * @brief Заголовочный файл модуля вывода ключей HKDF по RFC 5869 над любым хешем
 *        библиотеки
 *
 * \~english
 * @brief Header file of the HKDF key derivation module according to RFC 5869 over any
 *        hash of the library
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
		 * @brief Метод извлечения псевдослучайного ключа из исходного материала
		 *
		 * @param algorithm алгоритм хеширования
		 * @param salt      соль: пустая соль заменяется нулями в длину хеша
		 * @param material  исходный ключевой материал
		 * @param result    место, в которое помещается псевдослучайный ключ
		 * @param size      размер места в байтах, не меньше длины хеша
		 *
		 * @return          признак успешности извлечения
		 *
		 * @details Раздел 2.2 RFC 5869: PRK = HMAC(salt, IKM), длина ключа равна длине
		 *          хеша
		 *
		 * \~english
		 * @brief Method of the extraction of a pseudorandom key from the input material
		 * @param algorithm the hashing algorithm
		 * @param salt      the salt: an empty salt is replaced by zeros of the length of the hash
		 * @param material  the input keying material
		 * @param result    the place the pseudorandom key is put into
		 * @param size      the size of the place in bytes, not less than the length of the hash
		 * @return          the flag of the success of the extraction
		 * @details The section 2.2 of RFC 5869: PRK = HMAC(salt, IKM), the length of the key equals
		 *          the length of the hash
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool extract(const hash_t algorithm, const view_t & salt, const view_t & material, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод развёртывания псевдослучайного ключа в ключевой материал
		 *
		 * @param algorithm алгоритм хеширования
		 * @param key       псевдослучайный ключ длиной не короче хеша
		 * @param info      привязка выводимого материала, вправе быть пустой
		 * @param result    место, в которое помещается выведенный материал
		 * @param size      требуемая длина материала, не больше 255 длин хеша
		 *
		 * @return          признак успешности развёртывания
		 *
		 * @details Раздел 2.3 RFC 5869: T(i) = HMAC(PRK, T(i-1) | info | i)
		 *
		 * \~english
		 * @brief Method of the expansion of a pseudorandom key into the keying material
		 * @param algorithm the hashing algorithm
		 * @param key       the pseudorandom key of a length not shorter than the hash
		 * @param info      the binding of the derived material, may be empty
		 * @param result    the place the derived material is put into
		 * @param size      the required length of the material, not more than 255 lengths of the hash
		 * @return          the flag of the success of the expansion
		 * @details The section 2.3 of RFC 5869: T(i) = HMAC(PRK, T(i-1) | info | i)
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool expand(const hash_t algorithm, const view_t & key, const view_t & info, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод вывода ключевого материала из исходного за один вызов
		 *
		 * @param algorithm алгоритм хеширования
		 * @param salt      соль, вправе быть пустой
		 * @param material  исходный ключевой материал
		 * @param info      привязка выводимого материала, вправе быть пустой
		 * @param result    место, в которое помещается выведенный материал
		 * @param size      требуемая длина материала, не больше 255 длин хеша
		 *
		 * @return          признак успешности вывода
		 *
		 * @note Извлечение и развёртывание подряд; псевдослучайный ключ затирается
		 *
		 * \~english
		 * @brief Method of the derivation of the keying material from the input one by one call
		 * @param algorithm the hashing algorithm
		 * @param salt      the salt, may be empty
		 * @param material  the input keying material
		 * @param info      the binding of the derived material, may be empty
		 * @param result    the place the derived material is put into
		 * @param size      the required length of the material, not more than 255 lengths of the hash
		 * @return          the flag of the success of the derivation
		 * @note The extraction and the expansion in a row; the pseudorandom key is wiped
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool hkdf(const hash_t algorithm, const view_t & salt, const view_t & material, const view_t & info, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод развёртывания секрета с меткой по разделу 7.1 RFC 8446
		 *
		 * @param algorithm алгоритм хеширования
		 * @param secret    развёртываемый секрет длиной не короче хеша
		 * @param label     метка без приставки «tls13 », от 1 до 249 байтов
		 * @param context   привязка к переписке, до 255 байтов, вправе быть пустой
		 * @param result    место, в которое помещается выведенный материал
		 * @param size      требуемая длина материала, не больше 255 длин хеша
		 *
		 * @return          признак успешности развёртывания
		 *
		 * @details HKDF-Expand-Label: привязкой развёртывания идёт запись HkdfLabel -
		 *          длина в два байта, метка с приставкой «tls13 » и привязка к
		 *          переписке, обе с длиной в один байт. Так выводятся ключи TLS 1.3
		 *          и QUIC (метки «quic key», «quic iv», «quic hp», «client in»…)
		 *
		 * \~english
		 * @brief Method of the expansion of a secret with a label according to the section 7.1 of RFC 8446
		 * @param algorithm the hashing algorithm
		 * @param secret    the secret being expanded of a length not shorter than the hash
		 * @param label     the label without the «tls13 » prefix, from 1 to 249 bytes
		 * @param context   the binding to the transcript, up to 255 bytes, may be empty
		 * @param result    the place the derived material is put into
		 * @param size      the required length of the material, not more than 255 lengths of the hash
		 * @return          the flag of the success of the expansion
		 * @details HKDF-Expand-Label: the binding of the expansion is the HkdfLabel record - the length
		 *          in two bytes, the label with the «tls13 » prefix and the binding to the transcript,
		 *          both with the length in one byte. The keys of TLS 1.3 and of QUIC are derived so
		 *          (the labels «quic key», «quic iv», «quic hp», «client in»…)
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool label(const hash_t algorithm, const view_t & secret, const view_t & label, const view_t & context, uint8_t * result, const size_t size) noexcept;
	};
};

