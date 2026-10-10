/**
 * @file des.cpp
 * @date 2026-10-10
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
 * @brief Проверки модуля блочного шифра DES и 3DES (FIPS 46-3)
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
#include <cipher/des.hpp>
#include <cipher/mode.hpp>

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
	// Выводим собранную запись
	return result;
}

/**
 * Классический вектор DES (FIPS 46-3): ключ 133457799bbcdff1, блок 0123456789abcdef
 */
TEST(DesTest, Single){
	// Шифр с ключом DES
	cipher::des_t cipher;
	// Устанавливаем ключ DES
	const std::vector <uint8_t> key = bytes("133457799bbcdff1");
	ASSERT_TRUE(cipher.key(view_t(key.data(), key.size())));
	// Готовность шифра
	ASSERT_TRUE(cipher.ready());
	// Зашифровываем блок
	const std::vector <uint8_t> plain = bytes("0123456789abcdef");
	uint8_t sealed[8], opened[8];
	ASSERT_TRUE(cipher.encrypt(plain.data(), sealed));
	// Проверяем зашифрованный блок
	ASSERT_EQ(text(sealed, sizeof(sealed)), "85e813540f0ab405");
	// Расшифровываем блок обратно
	ASSERT_TRUE(cipher.decrypt(sealed, opened));
	// Проверяем расшифрованный блок
	ASSERT_EQ(text(opened, sizeof(opened)), "0123456789abcdef");
}

/**
 * 3DES (EDE): вектор сверен с OpenSSL (enc -des-ede3), тождество DES при равных трёх ключах
 */
TEST(DesTest, Triple){
	// Шифр с ключом 3DES
	cipher::des_t cipher;
	// Устанавливаем ключ 3DES
	const std::vector <uint8_t> key = bytes("0123456789abcdef23456789abcdef01456789abcdef0123");
	ASSERT_TRUE(cipher.key(view_t(key.data(), key.size())));
	// Зашифровываем блок
	const std::vector <uint8_t> plain = bytes("5468652071756666");
	uint8_t sealed[8], opened[8];
	ASSERT_TRUE(cipher.encrypt(plain.data(), sealed));
	// Проверяем зашифрованный блок (сверено с OpenSSL)
	ASSERT_EQ(text(sealed, sizeof(sealed)), "56646d6f47b094c4");
	// Расшифровываем блок обратно
	ASSERT_TRUE(cipher.decrypt(sealed, opened));
	// Проверяем расшифрованный блок
	ASSERT_EQ(text(opened, sizeof(opened)), "5468652071756666");
	/**
	 * При равных трёх ключах 3DES совпадает с одиночным DES
	 */
	const std::vector <uint8_t> single = bytes("133457799bbcdff1");
	const std::vector <uint8_t> triple = bytes("133457799bbcdff1133457799bbcdff1133457799bbcdff1");
	const std::vector <uint8_t> block = bytes("0123456789abcdef");
	cipher::des_t one, three;
	ASSERT_TRUE(one.key(view_t(single.data(), single.size())));
	ASSERT_TRUE(three.key(view_t(triple.data(), triple.size())));
	uint8_t first[8], second[8];
	ASSERT_TRUE(one.encrypt(block.data(), first));
	ASSERT_TRUE(three.encrypt(block.data(), second));
	// Проверяем тождество
	ASSERT_EQ(::memcmp(first, second, sizeof(first)), 0);
}

/**
 * 3DES в режиме простой замены с зацеплением (3des-cbc у SSH): вектор сверен с OpenSSL
 * (enc -des-ede3-cbc)
 */
TEST(DesTest, Chaining){
	// Шифр с ключом 3DES
	cipher::des_t cipher;
	// Устанавливаем ключ 3DES
	const std::vector <uint8_t> key = bytes("0123456789abcdef23456789abcdef01456789abcdef0123");
	ASSERT_TRUE(cipher.key(view_t(key.data(), key.size())));
	// Режим простой замены с зацеплением
	cipher::chaining_t chaining;
	// Запускаем режим с синхропосылкой
	const std::vector <uint8_t> iv = bytes("0123456789abcdef");
	ASSERT_TRUE(chaining.start(cipher::block_t(cipher), view_t(iv.data(), iv.size())));
	// Зашифровываем сообщение из двух блоков
	const std::vector <uint8_t> plain = bytes("0123456789abcdeffedcba9876543210");
	std::vector <uint8_t> sealed(plain.size());
	ASSERT_TRUE(chaining.encrypt(view_t(plain.data(), plain.size()), sealed.data()));
	// Проверяем зашифрованное сообщение (сверено с OpenSSL)
	ASSERT_EQ(text(sealed.data(), sealed.size()), "4eba739c998bcb600601c393382098d8");
	// Расшифровываем сообщение обратно
	cipher::chaining_t back;
	ASSERT_TRUE(back.start(cipher::block_t(cipher), view_t(iv.data(), iv.size())));
	std::vector <uint8_t> opened(plain.size());
	ASSERT_TRUE(back.decrypt(view_t(sealed.data(), sealed.size()), opened.data()));
	// Проверяем расшифрованное сообщение
	ASSERT_EQ(text(opened.data(), opened.size()), "0123456789abcdeffedcba9876543210");
}

/**
 * Отказы и затирание ключа
 */
TEST(DesTest, Refusals){
	// Шифр без ключа
	cipher::des_t cipher;
	uint8_t block[8] = {0}, result[8];
	// Без ключа шифр не готов и отказывает
	ASSERT_FALSE(cipher.ready());
	EXPECT_FALSE(cipher.encrypt(block, result));
	EXPECT_FALSE(cipher.decrypt(block, result));
	// Ключ неподходящей длины отвергается
	const std::vector <uint8_t> shorty = bytes("133457799bbcdff1");
	EXPECT_FALSE(cipher.key(view_t(shorty.data(), 7)));
	EXPECT_FALSE(cipher.key(view_t(shorty.data(), 16)));
	EXPECT_FALSE(cipher.key(view_t(nullptr, 8)));
	// Годный ключ принимается
	ASSERT_TRUE(cipher.key(view_t(shorty.data(), shorty.size())));
	ASSERT_TRUE(cipher.ready());
	// Пустые блоки отвергаются
	EXPECT_FALSE(cipher.encrypt(nullptr, result));
	EXPECT_FALSE(cipher.encrypt(block, nullptr));
	// Затирание сбрасывает готовность
	cipher.clear();
	EXPECT_FALSE(cipher.ready());
	EXPECT_FALSE(cipher.encrypt(block, result));
}
