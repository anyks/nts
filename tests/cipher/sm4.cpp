/**
 * @file: sm4.cpp
 * @date: 2026-10-04
 * @license: GPL-3.0
 *
 * @telegram: @forman
 * @author: Yuriy Lobarev
 * @phone: +7 (910) 983-95-90
 * @email: forman@anyks.com
 * @site: https://anyks.com
 *
 * @copyright: Copyright © 2026
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
#include <cipher/sm4.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Метод разбора шестнадцатеричной строки в байты
 *
 * @param text разбираемая строка
 *
 * @return     разобранные байты
 *
 */
static std::vector <uint8_t> bytes(const std::string & text) {
	// Разобранные байты
	std::vector <uint8_t> result;
	/**
	 * Выполняем перебор пар знаков
	 */
	for(size_t i = 0; (i + 1) < text.size(); i += 2)
		// Добавляем очередной байт
		result.push_back(static_cast <uint8_t> (std::stoul(text.substr(i, 2), nullptr, 16)));
	// Выводим разобранные байты
	return result;
}

/**
 * @brief Метод записи байтов шестнадцатеричной строкой
 *
 * @param data байты
 * @param size число байтов
 *
 * @return     запись строчными шестнадцатеричными знаками
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Собираемая запись
	std::string result;
	// Набор шестнадцатеричных знаков
	static const char * DIGITS = "0123456789abcdef";
	/**
	 * Выполняем перебор байтов
	 */
	for(size_t i = 0; i < size; i++){
		// Записываем старший полубайт
		result.push_back(DIGITS[data[i] >> 4]);
		// Записываем младший полубайт
		result.push_back(DIGITS[data[i] & 0x0F]);
	}
	// Выводим запись
	return result;
}

/**
 * Проверка вектора GB/T 32907-2016
 */
TEST(Sm4Test, Vector){
	// Ключ примера стандарта
	const std::vector <uint8_t> secret = bytes("0123456789abcdeffedcba9876543210");
	// Открытый текст примера стандарта
	const std::vector <uint8_t> plain = bytes("0123456789abcdeffedcba9876543210");
	// Объект шифра
	cipher::sm4_t sm4;
	// Проверяем неготовность шифра без ключа
	ASSERT_FALSE(sm4.ready());
	// Проверяем установку ключа
	ASSERT_TRUE(sm4.key(view_t(secret.data(), secret.size())));
	// Проверяем готовность шифра
	ASSERT_TRUE(sm4.ready());
	// Зашифрованный блок
	uint8_t sealed[16];
	// Проверяем зашифрование блока
	ASSERT_TRUE(sm4.encrypt(plain.data(), sealed));
	// Проверяем шифртекст примера стандарта
	ASSERT_EQ(text(sealed, sizeof(sealed)), "681edf34d206965e86b3e94f536e4246");
	// Расшифрованный блок
	uint8_t opened[16];
	// Проверяем расшифрование блока
	ASSERT_TRUE(sm4.decrypt(sealed, opened));
	// Проверяем схождение с открытым текстом
	ASSERT_EQ(::memcmp(opened, plain.data(), 16), 0);
}

/**
 * Проверка миллиона зашифрований по GB/T 32907-2016
 */
TEST(Sm4Test, Million){
	// Ключ примера стандарта
	const std::vector <uint8_t> secret = bytes("0123456789abcdeffedcba9876543210");
	// Объект шифра
	cipher::sm4_t sm4;
	// Проверяем установку ключа
	ASSERT_TRUE(sm4.key(view_t(secret.data(), secret.size())));
	// Текущий блок цепочки
	uint8_t block[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
	/**
	 * Выполняем миллион зашифрований подряд
	 */
	for(size_t i = 0; i < 1000000; i++){
		// Зашифрованный блок
		uint8_t sealed[16];
		// Проверяем зашифрование блока
		ASSERT_TRUE(sm4.encrypt(block, sealed));
		// Переносим итог в текущий блок
		::memcpy(block, sealed, 16);
	}
	// Проверяем итог цепочки примера стандарта
	ASSERT_EQ(text(block, sizeof(block)), "595298c7c6fd271f0402f804c33d3f66");
}

/**
 * Проверка совпадения места итога с местом исходного блока
 */
TEST(Sm4Test, InPlace){
	// Ключ примера стандарта
	const std::vector <uint8_t> secret = bytes("0123456789abcdeffedcba9876543210");
	// Объект шифра
	cipher::sm4_t sm4;
	// Проверяем установку ключа
	ASSERT_TRUE(sm4.key(view_t(secret.data(), secret.size())));
	// Блок, зашифровываемый на своём месте
	uint8_t block[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
	// Проверяем зашифрование блока на своём месте
	ASSERT_TRUE(sm4.encrypt(block, block));
	// Проверяем шифртекст примера стандарта
	ASSERT_EQ(text(block, sizeof(block)), "681edf34d206965e86b3e94f536e4246");
	// Проверяем расшифрование блока на своём месте
	ASSERT_TRUE(sm4.decrypt(block, block));
	// Проверяем схождение с открытым текстом
	ASSERT_EQ(text(block, sizeof(block)), "0123456789abcdeffedcba9876543210");
}

/**
 * Проверка отказов договора
 */
TEST(Sm4Test, Refusals){
	// Ключ примера стандарта
	const std::vector <uint8_t> secret = bytes("0123456789abcdeffedcba9876543210");
	// Открытый текст примера стандарта
	const std::vector <uint8_t> plain = bytes("0123456789abcdeffedcba9876543210");
	// Объект шифра
	cipher::sm4_t sm4;
	// Зашифрованный блок
	uint8_t sealed[16];
	// Проверяем отказ зашифрования без ключа
	ASSERT_FALSE(sm4.encrypt(plain.data(), sealed));
	// Проверяем отказ расшифрования без ключа
	ASSERT_FALSE(sm4.decrypt(plain.data(), sealed));
	// Проверяем отказ установки пустого ключа
	ASSERT_FALSE(sm4.key(view_t()));
	// Проверяем отказ установки ключа неверной длины
	ASSERT_FALSE(sm4.key(view_t(secret.data(), 15)));
	// Проверяем установку ключа
	ASSERT_TRUE(sm4.key(view_t(secret.data(), secret.size())));
	// Проверяем отказ зашифрования пустого блока
	ASSERT_FALSE(sm4.encrypt(nullptr, sealed));
	// Проверяем отказ зашифрования в пустое место
	ASSERT_FALSE(sm4.encrypt(plain.data(), nullptr));
	// Выполняем затирание ключа
	sm4.clear();
	// Проверяем неготовность шифра после затирания
	ASSERT_FALSE(sm4.ready());
	// Проверяем отказ зашифрования после затирания
	ASSERT_FALSE(sm4.encrypt(plain.data(), sealed));
}
