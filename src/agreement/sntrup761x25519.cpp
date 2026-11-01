/**
 * @file sntrup761x25519.cpp
 * @date 2026-10-06
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
 * @brief Модуль гибридного обмена ключами —
 *        sntrup761x25519-sha512 по draft-josefsson-ntruprime-ssh
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <agreement/sntrup761x25519.hpp>
#include <digest/hash.hpp>
#include <sys/wipe.hpp>

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Затирание областей памяти берётся из открытого API библиотеки
	 */
	using nts::sys::wipe;

	/**
	 * @brief Функция склейки общего секрета гибрида
	 *
	 * @param pq     общий секрет sntrup761 (32 байта)
	 * @param cl     общий секрет X25519 (32 байта)
	 * @param shared место, в которое записывается общий секрет (64 байта)
	 *
	 * @details K = SHA-512(K_PQ ‖ K_CL)
	 *
	 */
	static void combine(const uint8_t * pq, const uint8_t * cl, uint8_t * shared) noexcept {
		// Объект хеширования
		digest::hasher_t hasher(digest::hash_t::SHA512);
		// Подаём общий секрет sntrup761
		hasher.update(view_t(pq, agreement::SNTRUP761_SHARED));
		// Подаём общий секрет X25519
		hasher.update(view_t(cl, agreement::X25519_SIZE));
		// Снимаем общий секрет гибрида
		hasher.finish(shared, agreement::SNTRUP761X25519_SHARED);
	}
}

/**
 * @brief Функция выработки открытого значения клиента гибрида
 *
 * @param key    место, в которое записывается открытое значение клиента (1190 байтов)
 * @param secret место, в которое записывается секрет клиента (1763 + 32 байтов: секрет sntrup761 и секрет X25519)
 * @return       признак успешности выработки
 *
 */
bool nts::agreement::pairSntrup761x25519(uint8_t * key, uint8_t * secret) noexcept {
	// Если место ключа либо секрета не передано
	if((key == nullptr) || (secret == nullptr))
		// Выводим отказ выработки
		return false;
	// Если пару sntrup761 выработать не удалось
	if(!pair(key, secret)){
		// Выполняем затирание секрета
		wipe(secret, SNTRUP761_SECRET + X25519_SIZE);
		// Выводим отказ выработки
		return false;
	}
	// Если пару X25519 выработать не удалось
	if(!generate(secret + SNTRUP761_SECRET, key + SNTRUP761_PUBLIC)){
		// Выполняем затирание секрета
		wipe(secret, SNTRUP761_SECRET + X25519_SIZE);
		// Выводим отказ выработки
		return false;
	}
	// Выводим признак успешности выработки
	return true;
}

/**
 * @brief Функция ответа сервера гибридного обмена
 *
 * @param key    открытое значение клиента (1190 байтов)
 * @param cipher место, в которое записывается открытое значение сервера (1071 байт)
 * @param secret место, в которое записывается секрет сервера (32 байта: секрет X25519)
 * @param shared место, в которое записывается общий секрет (64 байта)
 * @return       признак успешности ответа
 *
 */
bool nts::agreement::encapsSntrup761x25519(const view_t & key, uint8_t * cipher, uint8_t * secret, uint8_t * shared) noexcept {
	// Если значение клиента не той длины либо места итогов не переданы
	if((key.data == nullptr) || (key.size != SNTRUP761X25519_CLIENT) || (cipher == nullptr) || (secret == nullptr) || (shared == nullptr))
		// Выводим отказ ответа
		return false;
	// Место общего секрета sntrup761
	uint8_t pq[SNTRUP761_SHARED];
	// Если инкапсуляцию по ключу клиента выполнить не удалось
	if(!encaps(view_t(key.data, SNTRUP761_PUBLIC), cipher, pq)){
		// Выполняем затирание секрета
		wipe(pq, sizeof(pq));
		// Выводим отказ ответа
		return false;
	}
	// Место общего секрета X25519
	uint8_t cl[X25519_SIZE];
	// Если пару X25519 выработать либо общее значение получить не удалось
	if(!generate(secret, cipher + SNTRUP761_CIPHERTEXT) || !x25519(view_t(secret, X25519_SIZE), view_t(key.data + SNTRUP761_PUBLIC, X25519_SIZE), cl)){
		// Выполняем затирание рабочих областей
		wipe(pq, sizeof(pq));
		wipe(cl, sizeof(cl));
		// Выводим отказ ответа
		return false;
	}
	// Склеиваем общий секрет гибрида
	combine(pq, cl, shared);
	// Выполняем затирание рабочих областей
	wipe(pq, sizeof(pq));
	wipe(cl, sizeof(cl));
	// Выводим признак успешности ответа
	return true;
}

/**
 * @brief Функция завершения гибридного обмена клиентом
 *
 * @param cipher открытое значение сервера (1071 байт)
 * @param secret секрет клиента (1763 + 32 байтов)
 * @param shared место, в которое записывается общий секрет (64 байта)
 * @return       признак успешности завершения (ложь при подмене шифртекста)
 *
 */
bool nts::agreement::decapsSntrup761x25519(const view_t & cipher, const view_t & secret, uint8_t * shared) noexcept {
	// Если значение сервера не той длины, секрет не той длины либо место итога не передано
	if((cipher.data == nullptr) || (cipher.size != SNTRUP761X25519_SERVER) || (secret.data == nullptr) || (secret.size != (SNTRUP761_SECRET + X25519_SIZE)) || (shared == nullptr))
		// Выводим отказ завершения
		return false;
	// Место общего секрета sntrup761
	uint8_t pq[SNTRUP761_SHARED];
	// Если распаковать шифртекст не удалось (подмена шифртекста)
	if(!decaps(view_t(cipher.data, SNTRUP761_CIPHERTEXT), view_t(secret.data, SNTRUP761_SECRET), pq)){
		// Выполняем затирание секрета
		wipe(pq, sizeof(pq));
		// Выводим отказ завершения
		return false;
	}
	// Место общего секрета X25519
	uint8_t cl[X25519_SIZE];
	// Если общее значение X25519 получить не удалось
	if(!x25519(view_t(secret.data + SNTRUP761_SECRET, X25519_SIZE), view_t(cipher.data + SNTRUP761_CIPHERTEXT, X25519_SIZE), cl)){
		// Выполняем затирание рабочих областей
		wipe(pq, sizeof(pq));
		wipe(cl, sizeof(cl));
		// Выводим отказ завершения
		return false;
	}
	// Склеиваем общий секрет гибрида
	combine(pq, cl, shared);
	// Выполняем затирание рабочих областей
	wipe(pq, sizeof(pq));
	wipe(cl, sizeof(cl));
	// Выводим признак успешности завершения
	return true;
}
