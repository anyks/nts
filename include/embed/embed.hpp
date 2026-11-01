/**
 * @file embed.hpp
 * @date 2026-09-16
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
 * @brief Заголовочный файл модуля вывода ключа для зашивания в образ приложения
 *
 * \~english
 * @brief Header file of the key derivation module for embedding into the application image
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
#include <digest/argon2.hpp>

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
	 * @brief Пространство имён модуля зашивания ключа в образ
	 *
	 * @details Модуль есть A-NTS-сторона договора зашивания. Раскладку материала по образу и
	 *          его сбор на запуске ведёт распределитель AWH (`scatter_t`/`vessel_t`); здесь —
	 *          лишь превращение собранного материала либо пароля в ключ, детерминированно и
	 *          аллокатор-нейтрально (вход и выход байтами, кучи модуль не держит). Требования:
	 *          `anyks-tls/AWH-KEY-EMBEDDING.md`, требования 3 и 4
	 *
	 * \~english
	 * @brief Namespace of the module of the embedding of a key into the image
	 *
	 * @details The module is the A-NTS side of the embedding contract. The scattering of the
	 *          material over the image and its gathering at the launch are done by the AWH
	 *          allocator (`scatter_t`/`vessel_t`); here is only the turning of the gathered
	 *          material or a password into a key, deterministically and allocator-neutrally
	 *          (input and output by bytes, the module holds no heap). Requirements:
	 *          `anyks-tls/AWH-KEY-EMBEDDING.md`, requirements 3 and 4
	 *
	 * \~
	 */
	namespace embed {
		/**
		 * \~russian
		 * @brief Функция вывода зашитого ключа из собранного по образу материала
		 *
		 * @details Требование 3 записки о зашивании: ключ не хранится, а выводится из материала.
		 *          Вывод есть HKDF по RFC 5869 над указанным хешем: извлечение над материалом с
		 *          солью, затем расширение с меткой области, версией ключа и связкой. Версия
		 *          вплетается в вывод восемью октетами старшим байтом вперёд — отладочная и боевая
		 *          сборки выводят разные ключи не запретом, а тем, что ключ иной. Промежуточный
		 *          псевдослучайный ключ затирается на любом выходе. Вывод детерминирован: на
		 *          сборочной машине (закладка) и на запуске совпадает побайтно при равных входах
		 *
		 * @param algorithm алгоритм хеширования под HKDF
		 * @param material  собранный по образу материал (из `vessel_t` через `apply`)
		 * @param salt      соль сборки: пустая заменяется нулями в длину хеша
		 * @param context   привязка к образу, например контрольная сумма участка; допустимо пусто
		 * @param version   версия ключа, вплетаемая в вывод
		 * @param result    место, в которое помещается ключ
		 * @param size      размер места в байтах
		 * @return          признак того, что ключ выведен
		 *
		 * \~english
		 * @brief Function of the derivation of an embedded key from the material gathered over the image
		 *
		 * @details Requirement 3 of the embedding note: the key is not stored but derived from the
		 *          material. The derivation is HKDF by RFC 5869 over the given hash: extraction over
		 *          the material with the salt, then expansion with the area label, the key version
		 *          and the context. The version is woven into the output by eight octets most
		 *          significant byte first — the debug and the release builds derive different keys not
		 *          by a ban but by the key being different. The intermediate pseudorandom key is wiped
		 *          on any exit. The derivation is deterministic: on the build machine (the laying) and
		 *          at the launch it matches byte for byte at equal inputs
		 *
		 * @param algorithm the hashing algorithm under HKDF
		 * @param material  the material gathered over the image (from `vessel_t` via `apply`)
		 * @param salt      the build salt: an empty one is replaced by zeros of the length of the hash
		 * @param context   the binding to the image, e.g. the checksum of an area; may be empty
		 * @param version   the key version woven into the output
		 * @param result    the place the key is put into
		 * @param size      the size of the place in bytes
		 * @return          the sign that the key is derived
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool key(const digest::hash_t algorithm, const view_t & material, const view_t & salt, const view_t & context, const uint64_t version, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Функция вывода зашитого ключа из пароля растяжением Argon2
		 *
		 * @details Требование 4 записки о зашивании: пароль сам ключом не является — мало энтропии.
		 *          Ключ получается растяжением пароля Argon2 (по умолчанию Argon2id) с солью и
		 *          заданными параметрами. Версия ключа и привязка к образу вплетаются в связанные
		 *          данные Argon2: версия — восемью октетами старшим байтом вперёд, затем связка. Так
		 *          отладочная и боевая сборки выводят из одного пароля разные ключи. Затирание пароля
		 *          — за зовущим, сразу после вывода
		 *
		 * @param params   параметры Argon2
		 * @param password пароль
		 * @param salt     соль, не короче восьми байтов
		 * @param context  привязка к образу, например контрольная сумма участка; допустимо пусто
		 * @param version  версия ключа, вплетаемая в вывод
		 * @param result   место, в которое помещается ключ
		 * @param size     размер места в байтах, не меньше четырёх
		 * @return         признак того, что ключ выведен
		 *
		 * \~english
		 * @brief Function of the derivation of an embedded key from a password by the Argon2 stretching
		 *
		 * @details Requirement 4 of the embedding note: the password by itself is not a key — too
		 *          little entropy. The key is obtained by the Argon2 stretching of the password (by
		 *          default Argon2id) with a salt and the given parameters. The key version and the
		 *          binding to the image are woven into the associated data of Argon2: the version by
		 *          eight octets most significant byte first, then the context. Thus the debug and the
		 *          release builds derive different keys from one password. The wiping of the password
		 *          is up to the caller, right after the derivation
		 *
		 * @param params   the Argon2 parameters
		 * @param password the password
		 * @param salt     the salt, at least eight bytes
		 * @param context  the binding to the image, e.g. the checksum of an area; may be empty
		 * @param version  the key version woven into the output
		 * @param result   the place the key is put into
		 * @param size     the size of the place in bytes, at least four
		 * @return         the sign that the key is derived
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool secret(const digest::argon_params_t & params, const view_t & password, const view_t & salt, const view_t & context, const uint64_t version, uint8_t * result, const size_t size) noexcept;
	};
};

