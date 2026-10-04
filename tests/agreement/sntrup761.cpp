/**
 * @file sntrup761.cpp
 * @date 2026-10-04
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
 * @brief Проверки модуля инкапсуляции ключа Streamlined NTRU Prime sntrup761
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <agreement/sntrup761.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Метод сравнения байтов
 *
 * @param a первый буфер
 * @param b второй буфер
 * @param n число байтов
 *
 * @return  признак совпадения
 *
 */
static bool same(const uint8_t * a, const uint8_t * b, const size_t n) {
	return ::memcmp(a, b, n) == 0;
}

/**
 * Проверка выработки пары ключей и обмена
 */
TEST(Sntrup761Test, Roundtrip) {
	// Буферы ключей
	std::vector <uint8_t> pk(agreement::SNTRUP761_PUBLIC);
	std::vector <uint8_t> sk(agreement::SNTRUP761_SECRET);
	// Вырабатываем пару ключей
	ASSERT_TRUE(agreement::pair(pk.data(), sk.data()));
	// Буферы шифртекста и общих секретов
	std::vector <uint8_t> cipher(agreement::SNTRUP761_CIPHERTEXT);
	std::vector <uint8_t> sharedA(agreement::SNTRUP761_SHARED);
	std::vector <uint8_t> sharedB(agreement::SNTRUP761_SHARED);
	// Инкапсуляция
	ASSERT_TRUE(agreement::encaps(view_t(pk.data(), pk.size()), cipher.data(), sharedA.data()));
	// Декапсуляция
	ASSERT_TRUE(agreement::decaps(view_t(cipher.data(), cipher.size()), view_t(sk.data(), sk.size()), sharedB.data()));
	// Общие секреты должны совпасть
	EXPECT_TRUE(same(sharedA.data(), sharedB.data(), agreement::SNTRUP761_SHARED));
}

/**
 * Проверка неявного отказа при подмене шифртекста
 */
TEST(Sntrup761Test, Tampered) {
	// Буферы ключей
	std::vector <uint8_t> pk(agreement::SNTRUP761_PUBLIC);
	std::vector <uint8_t> sk(agreement::SNTRUP761_SECRET);
	ASSERT_TRUE(agreement::pair(pk.data(), sk.data()));
	// Инкапсуляция
	std::vector <uint8_t> cipher(agreement::SNTRUP761_CIPHERTEXT);
	std::vector <uint8_t> sharedA(agreement::SNTRUP761_SHARED);
	ASSERT_TRUE(agreement::encaps(view_t(pk.data(), pk.size()), cipher.data(), sharedA.data()));
	// Портим шифртекст
	cipher[0] ^= 1;
	// Декапсуляция должна отказать
	std::vector <uint8_t> sharedB(agreement::SNTRUP761_SHARED);
	EXPECT_FALSE(agreement::decaps(view_t(cipher.data(), cipher.size()), view_t(sk.data(), sk.size()), sharedB.data()));
	// Общие секреты не должны совпасть
	EXPECT_FALSE(same(sharedA.data(), sharedB.data(), agreement::SNTRUP761_SHARED));
}

/**
 * Проверка отказа на неверных параметрах
 */
TEST(Sntrup761Test, Reject) {
	std::vector <uint8_t> pk(agreement::SNTRUP761_PUBLIC);
	std::vector <uint8_t> sk(agreement::SNTRUP761_SECRET);
	std::vector <uint8_t> cipher(agreement::SNTRUP761_CIPHERTEXT);
	std::vector <uint8_t> shared(agreement::SNTRUP761_SHARED);
	// Нулевые указатели
	EXPECT_FALSE(agreement::pair(nullptr, sk.data()));
	EXPECT_FALSE(agreement::pair(pk.data(), nullptr));
	EXPECT_FALSE(agreement::encaps(view_t(), cipher.data(), shared.data()));
	EXPECT_FALSE(agreement::encaps(view_t(pk.data(), pk.size()), nullptr, shared.data()));
	EXPECT_FALSE(agreement::encaps(view_t(pk.data(), pk.size()), cipher.data(), nullptr));
	EXPECT_FALSE(agreement::decaps(view_t(), view_t(sk.data(), sk.size()), shared.data()));
	EXPECT_FALSE(agreement::decaps(view_t(cipher.data(), cipher.size()), view_t(), shared.data()));
	EXPECT_FALSE(agreement::decaps(view_t(cipher.data(), cipher.size()), view_t(sk.data(), sk.size()), nullptr));
	// Неверные размеры
	EXPECT_FALSE(agreement::encaps(view_t(pk.data(), pk.size() - 1), cipher.data(), shared.data()));
	EXPECT_FALSE(agreement::decaps(view_t(cipher.data(), cipher.size() - 1), view_t(sk.data(), sk.size()), shared.data()));
	EXPECT_FALSE(agreement::decaps(view_t(cipher.data(), cipher.size()), view_t(sk.data(), sk.size() - 1), shared.data()));
}

/**
 * Проверка повторного использования ключа
 */
TEST(Sntrup761Test, Reuse) {
	std::vector <uint8_t> pk(agreement::SNTRUP761_PUBLIC);
	std::vector <uint8_t> sk(agreement::SNTRUP761_SECRET);
	ASSERT_TRUE(agreement::pair(pk.data(), sk.data()));
	// Несколько инкапсуляций с одним ключом
	for(size_t i = 0; i < 3; ++i){
		std::vector <uint8_t> cipher(agreement::SNTRUP761_CIPHERTEXT);
		std::vector <uint8_t> sharedA(agreement::SNTRUP761_SHARED);
		std::vector <uint8_t> sharedB(agreement::SNTRUP761_SHARED);
		ASSERT_TRUE(agreement::encaps(view_t(pk.data(), pk.size()), cipher.data(), sharedA.data()));
		ASSERT_TRUE(agreement::decaps(view_t(cipher.data(), cipher.size()), view_t(sk.data(), sk.size()), sharedB.data()));
		EXPECT_TRUE(same(sharedA.data(), sharedB.data(), agreement::SNTRUP761_SHARED));
	}
}
