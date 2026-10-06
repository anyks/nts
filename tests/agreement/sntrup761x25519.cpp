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
 * @brief Исходный файл проверок модуля гибридного обмена sntrup761x25519-sha512
 *
 * @note Эталоном служит самостоятельная склейка по draft-josefsson-ntruprime-ssh:
 *       общий секрет K = SHA-512(K_PQ ‖ K_CL) из секретов sntrup761 и X25519,
 *       выработанных по отдельности теми же ключами
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
#include <main.hpp>
#include <agreement/sntrup761x25519.hpp>
#include <digest/hash.hpp>
#include <sys/wipe.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Проверка кругового гибридного обмена
 */
TEST(Sntrup761x25519Test, Roundtrip) {
	// Открытое значение клиента
	uint8_t clientKey[agreement::SNTRUP761X25519_CLIENT];
	// Секрет клиента
	uint8_t clientSecret[agreement::SNTRUP761_SECRET + agreement::X25519_SIZE];
	// Выработка пары клиента обязана удаться
	ASSERT_TRUE(agreement::pairSntrup761x25519(clientKey, clientSecret));
	// Открытое значение сервера
	uint8_t serverCipher[agreement::SNTRUP761X25519_SERVER];
	// Секрет сервера
	uint8_t serverSecret[agreement::X25519_SIZE];
	// Общий секрет сервера
	uint8_t serverShared[agreement::SNTRUP761X25519_SHARED];
	// Ответ сервера обязан удаться
	ASSERT_TRUE(agreement::encapsSntrup761x25519(view_t(clientKey, sizeof(clientKey)), serverCipher, serverSecret, serverShared));
	// Общий секрет клиента
	uint8_t clientShared[agreement::SNTRUP761X25519_SHARED];
	// Завершение клиента обязано удаться
	ASSERT_TRUE(agreement::decapsSntrup761x25519(view_t(serverCipher, sizeof(serverCipher)), view_t(clientSecret, sizeof(clientSecret)), clientShared));
	// Общие секреты сторон обязаны совпасть побайтно
	ASSERT_EQ(::memcmp(serverShared, clientShared, sizeof(serverShared)), 0);
	// Общий секрет обязан быть ненулевым
	bool nonzero = false;
	for(size_t i = 0; i < sizeof(serverShared); i++)
		nonzero = (nonzero || (serverShared[i] != 0));
	ASSERT_TRUE(nonzero);
}

/**
 * Проверка склейки общего секрета против самостоятельной
 */
TEST(Sntrup761x25519Test, Combine) {
	// Открытое значение клиента
	uint8_t clientKey[agreement::SNTRUP761X25519_CLIENT];
	// Секрет клиента
	uint8_t clientSecret[agreement::SNTRUP761_SECRET + agreement::X25519_SIZE];
	// Выработка пары клиента обязана удаться
	ASSERT_TRUE(agreement::pairSntrup761x25519(clientKey, clientSecret));
	// Открытое значение сервера
	uint8_t serverCipher[agreement::SNTRUP761X25519_SERVER];
	// Секрет сервера
	uint8_t serverSecret[agreement::X25519_SIZE];
	// Общий секрет сервера
	uint8_t serverShared[agreement::SNTRUP761X25519_SHARED];
	// Ответ сервера обязан удаться
	ASSERT_TRUE(agreement::encapsSntrup761x25519(view_t(clientKey, sizeof(clientKey)), serverCipher, serverSecret, serverShared));
	/**
	 * Самостоятельная склейка: секрет sntrup761 из распаковки и секрет X25519
	 * из обмена теми же ключами, K = SHA-512(K_PQ ‖ K_CL)
	 */
	// Секрет sntrup761 из распаковки
	uint8_t pq[agreement::SNTRUP761_SHARED];
	ASSERT_TRUE(agreement::decaps(view_t(serverCipher, agreement::SNTRUP761_CIPHERTEXT), view_t(clientSecret, agreement::SNTRUP761_SECRET), pq));
	// Секрет X25519 из обмена
	uint8_t cl[agreement::X25519_SIZE];
	ASSERT_TRUE(agreement::x25519(view_t(clientSecret + agreement::SNTRUP761_SECRET, agreement::X25519_SIZE), view_t(serverCipher + agreement::SNTRUP761_CIPHERTEXT, agreement::X25519_SIZE), cl));
	// Склейка SHA-512(K_PQ ‖ K_CL)
	digest::hasher_t hasher(digest::hash_t::SHA512);
	hasher.update(view_t(pq, sizeof(pq)));
	hasher.update(view_t(cl, sizeof(cl)));
	uint8_t want[agreement::SNTRUP761X25519_SHARED];
	ASSERT_TRUE(hasher.finish(want, sizeof(want)));
	// Общий секрет клиента
	uint8_t clientShared[agreement::SNTRUP761X25519_SHARED];
	// Завершение клиента обязано удаться
	ASSERT_TRUE(agreement::decapsSntrup761x25519(view_t(serverCipher, sizeof(serverCipher)), view_t(clientSecret, sizeof(clientSecret)), clientShared));
	// Общий секрет обязан совпасть с самостоятельной склейкой побайтно
	ASSERT_EQ(::memcmp(clientShared, want, sizeof(want)), 0);
	// Выполняем затирание рабочих областей
	sys::wipe(pq, sizeof(pq));
	sys::wipe(cl, sizeof(cl));
}

/**
 * Проверка отказов на порченых записях
 */
TEST(Sntrup761x25519Test, Refusals) {
	// Открытое значение клиента
	uint8_t clientKey[agreement::SNTRUP761X25519_CLIENT];
	// Секрет клиента
	uint8_t clientSecret[agreement::SNTRUP761_SECRET + agreement::X25519_SIZE];
	// Выработка пары клиента обязана удаться
	ASSERT_TRUE(agreement::pairSntrup761x25519(clientKey, clientSecret));
	// Открытое значение сервера
	uint8_t serverCipher[agreement::SNTRUP761X25519_SERVER];
	// Секрет сервера
	uint8_t serverSecret[agreement::X25519_SIZE];
	// Общий секрет сервера
	uint8_t serverShared[agreement::SNTRUP761X25519_SHARED];
	// Ответ сервера обязан удаться
	ASSERT_TRUE(agreement::encapsSntrup761x25519(view_t(clientKey, sizeof(clientKey)), serverCipher, serverSecret, serverShared));
	// Общий секрет клиента
	uint8_t clientShared[agreement::SNTRUP761X25519_SHARED];
	// Подделанный шифртекст обязан отказать
	uint8_t forged[agreement::SNTRUP761X25519_SERVER];
	::memcpy(forged, serverCipher, sizeof(forged));
	forged[10] ^= 0x01;
	ASSERT_FALSE(agreement::decapsSntrup761x25519(view_t(forged, sizeof(forged)), view_t(clientSecret, sizeof(clientSecret)), clientShared));
	// Значение клиента не той длины обязано отказать
	ASSERT_FALSE(agreement::encapsSntrup761x25519(view_t(clientKey, sizeof(clientKey) - 1), serverCipher, serverSecret, serverShared));
	// Значение сервера не той длины обязано отказать
	ASSERT_FALSE(agreement::decapsSntrup761x25519(view_t(serverCipher, sizeof(serverCipher) - 1), view_t(clientSecret, sizeof(clientSecret)), clientShared));
	// Секрет не той длины обязан отказать
	ASSERT_FALSE(agreement::decapsSntrup761x25519(view_t(serverCipher, sizeof(serverCipher)), view_t(clientSecret, sizeof(clientSecret) - 1), clientShared));
	// Непереданные места обязаны отказать
	ASSERT_FALSE(agreement::pairSntrup761x25519(nullptr, clientSecret));
	ASSERT_FALSE(agreement::pairSntrup761x25519(clientKey, nullptr));
	ASSERT_FALSE(agreement::encapsSntrup761x25519(view_t(clientKey, sizeof(clientKey)), nullptr, serverSecret, serverShared));
	ASSERT_FALSE(agreement::decapsSntrup761x25519(view_t(serverCipher, sizeof(serverCipher)), view_t(clientSecret, sizeof(clientSecret)), nullptr));
}
