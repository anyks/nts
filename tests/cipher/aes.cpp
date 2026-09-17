/**
 * @file: aes.cpp
 * @date: 2026-09-04
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
#include <sys/machine.hpp>
#include <cipher/aes.hpp>
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
	// Выводим запись
	return result;
}

/**
 * @brief Метод проверки одного блока по приложению C FIPS 197
 *
 * @param key      ключ шифрования
 * @param expected ожидаемый шифртекст
 *
 */
static void solo(const std::string & key, const std::string & expected) {
	// Открытый текст приложения C
	const std::vector <uint8_t> plain = bytes("00112233445566778899aabbccddeeff");
	// Разобранный ключ
	const std::vector <uint8_t> secret = bytes(key);
	// Объект шифра
	cipher::aes_t aes;
	// Проверяем установку ключа
	ASSERT_TRUE(aes.key(view_t(secret.data(), secret.size()))) << "ключ " << key;
	// Проверяем готовность шифра
	ASSERT_TRUE(aes.ready());
	// Зашифрованный блок
	uint8_t sealed[16];
	// Проверяем зашифрование блока
	ASSERT_TRUE(aes.encrypt(plain.data(), sealed));
	// Проверяем шифртекст
	ASSERT_EQ(text(sealed, sizeof(sealed)), expected) << "ключ " << key;
	// Расшифрованный блок
	uint8_t opened[16];
	// Проверяем расшифрование блока
	ASSERT_TRUE(aes.decrypt(sealed, opened));
	// Проверяем схождение с открытым текстом
	ASSERT_EQ(::memcmp(opened, plain.data(), 16), 0) << "ключ " << key;
	// Выполняем сброс ключа
	aes.clear();
	// Проверяем отказ шифрования без ключа
	ASSERT_FALSE(aes.encrypt(plain.data(), sealed));
}

/**
 * Проверка векторов приложения C FIPS 197 на трёх длинах ключа
 */
TEST(AesTest, Fips197){
	// AES-128
	solo("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a");
	// AES-192
	solo("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191");
	// AES-256
	solo("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089");
}

/**
 * Проверка отказов установки ключа
 */
TEST(AesTest, Refusals){
	// Объект шифра
	cipher::aes_t aes;
	// Ключ негодной длины
	const std::vector <uint8_t> odd(20, 0x01);
	// Проверяем отказ ключа в 20 байтов
	ASSERT_FALSE(aes.key(view_t(odd.data(), odd.size())));
	// Проверяем отказ пустого ключа
	ASSERT_FALSE(aes.key(view_t()));
	// Проверяем неготовность шифра
	ASSERT_FALSE(aes.ready());
	// Блок
	uint8_t block[16] = {0};
	// Проверяем отказ шифрования без ключа
	ASSERT_FALSE(aes.encrypt(block, block));
	// Проверяем отказ расшифрования без ключа
	ASSERT_FALSE(aes.decrypt(block, block));
}

/**
 * Проверка сцепления блоков и обратной связи по приложению F NIST SP 800-38A
 */
TEST(AesTest, Modes){
	// Открытый текст приложения F: четыре блока
	const std::vector <uint8_t> plain = bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
	// Ключ AES-128
	const std::vector <uint8_t> key128 = bytes("2b7e151628aed2a6abf7158809cf4f3c");
	// Ключ AES-256
	const std::vector <uint8_t> key256 = bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
	// Вектор инициализации
	const std::vector <uint8_t> iv = bytes("000102030405060708090a0b0c0d0e0f");
	// Объект шифра
	cipher::aes_t aes;
	// Проверяем установку ключа AES-128
	ASSERT_TRUE(aes.key(view_t(key128.data(), key128.size())));
	// Зашифрованный текст
	uint8_t sealed[64];
	// Расшифрованный текст
	uint8_t opened[64];
	// Режим сцепления блоков
	cipher::chaining_t chaining;
	// Проверяем запуск сцепления блоков
	ASSERT_TRUE(chaining.start(cipher::block_t(aes), view_t(iv.data(), iv.size())));
	// Проверяем зашифрование сцеплением
	ASSERT_TRUE(chaining.encrypt(view_t(plain.data(), plain.size()), sealed));
	// Проверяем шифртекст CBC-AES128 приложения F.2.1
	ASSERT_EQ(text(sealed, sizeof(sealed)), "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7");
	// Проверяем перезапуск сцепления под расшифрование
	ASSERT_TRUE(chaining.start(cipher::block_t(aes), view_t(iv.data(), iv.size())));
	// Проверяем расшифрование сцеплением
	ASSERT_TRUE(chaining.decrypt(view_t(sealed, sizeof(sealed)), opened));
	// Проверяем схождение с открытым текстом
	ASSERT_EQ(::memcmp(opened, plain.data(), plain.size()), 0);
	// Режим обратной связи по шифртексту
	cipher::feedback_t feedback;
	// Проверяем запуск обратной связи полным блоком
	ASSERT_TRUE(feedback.start(cipher::block_t(aes), view_t(iv.data(), iv.size())));
	// Проверяем зашифрование обратной связью
	ASSERT_TRUE(feedback.encrypt(view_t(plain.data(), plain.size()), sealed));
	// Проверяем шифртекст CFB128-AES128 приложения F.3.13
	ASSERT_EQ(text(sealed, sizeof(sealed)), "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6");
	// Проверяем перезапуск обратной связи под расшифрование
	ASSERT_TRUE(feedback.start(cipher::block_t(aes), view_t(iv.data(), iv.size())));
	// Проверяем расшифрование обратной связью
	ASSERT_TRUE(feedback.decrypt(view_t(sealed, sizeof(sealed)), opened));
	// Проверяем схождение с открытым текстом
	ASSERT_EQ(::memcmp(opened, plain.data(), plain.size()), 0);
	// Проверяем установку ключа AES-256
	ASSERT_TRUE(aes.key(view_t(key256.data(), key256.size())));
	// Проверяем запуск сцепления блоков на AES-256
	ASSERT_TRUE(chaining.start(cipher::block_t(aes), view_t(iv.data(), iv.size())));
	// Проверяем зашифрование сцеплением
	ASSERT_TRUE(chaining.encrypt(view_t(plain.data(), plain.size()), sealed));
	// Проверяем шифртекст CBC-AES256 приложения F.2.5
	ASSERT_EQ(text(sealed, sizeof(sealed)), "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b");
}

/**
 * Проверка схождения обоих путей: командами машины и таблицами
 */
TEST(AesTest, Paths){
	// Открытый текст приложения F: четыре блока
	const std::vector <uint8_t> plain = bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
	// Ключ AES-192
	const std::vector <uint8_t> key = bytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
	// Вектор инициализации
	const std::vector <uint8_t> iv = bytes("000102030405060708090a0b0c0d0e0f");
	// Шифртексты обоих путей
	uint8_t first[64], second[64], opened[64];
	// Объект шифра
	cipher::aes_t aes;
	// Режим сцепления блоков
	cipher::chaining_t chaining;
	// Выполняем зашифрование на пути, выбранном машиной
	ASSERT_TRUE(aes.key(view_t(key.data(), key.size())));
	// Проверяем запуск сцепления
	ASSERT_TRUE(chaining.start(cipher::block_t(aes), view_t(iv.data(), iv.size())));
	// Проверяем зашифрование
	ASSERT_TRUE(chaining.encrypt(view_t(plain.data(), plain.size()), first));
	// Запрещаем машинные команды
	machine::allow(false);
	// Проверяем перезапуск сцепления таблицами
	ASSERT_TRUE(chaining.start(cipher::block_t(aes), view_t(iv.data(), iv.size())));
	// Проверяем зашифрование таблицами
	ASSERT_TRUE(chaining.encrypt(view_t(plain.data(), plain.size()), second));
	// Проверяем перезапуск под расшифрование таблицами
	ASSERT_TRUE(chaining.start(cipher::block_t(aes), view_t(iv.data(), iv.size())));
	// Проверяем расшифрование таблицами зашифрованного командами
	ASSERT_TRUE(chaining.decrypt(view_t(first, sizeof(first)), opened));
	// Возвращаем машинные команды
	machine::allow(true);
	// Проверяем шифртекст CBC-AES192 приложения F.2.3
	ASSERT_EQ(text(first, sizeof(first)), "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd");
	// Проверяем схождение путей
	ASSERT_EQ(text(second, sizeof(second)), text(first, sizeof(first)));
	// Проверяем расшифрование
	ASSERT_EQ(::memcmp(opened, plain.data(), plain.size()), 0);
}

/**
 * @brief Проверка выработки гаммы по многу блоков против поблочного шифрования
 *
 * @details Гамма вырабатывается по восемь блоков в полёте со счётчиком в регистре;
 *          итог обязан совпадать с шифрованием счётчика по блоку с побайтовым переносом,
 *          в том числе через границу младших четырёх байтов и на обоих путях
 */
TEST(AesTest, Stream){
	// Ключ AES-256
	const std::vector <uint8_t> key = bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
	// Счётчик за три блока до переполнения младших четырёх байтов
	uint8_t counter[16] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xff,0xff,0xff,0xfd};
	// Объект шифра
	cipher::aes_t aes;
	// Устанавливаем ключ
	ASSERT_TRUE(aes.key(view_t(key.data(), key.size())));
	// Число блоков: две восьмёрки и хвост
	const size_t blocks = 21;
	// Гамма по многу блоков, поблочно и таблицами
	uint8_t stream[21 * 16], single[21 * 16], tables[21 * 16];
	// Выполняем выработку гаммы машинным путём
	ASSERT_TRUE(aes.stream(counter, blocks, stream));
	// Запрещаем машинные команды
	machine::allow(false);
	// Выполняем выработку гаммы таблицами
	ASSERT_TRUE(aes.stream(counter, blocks, tables));
	// Возвращаем машинные команды
	machine::allow(true);
	// Текущий счётчик поблочного пути
	uint8_t current[16];
	// Копируем счётчик
	::memcpy(current, counter, sizeof(current));
	// Выполняем перебор блоков
	for(size_t b = 0; b < blocks; b++){
		// Выполняем перенос по младшим четырём байтам
		for(size_t i = 16; i > 12; i--){
			if(++current[i - 1] != 0)
				break;
		}
		// Шифруем очередной счётчик
		ASSERT_TRUE(aes.encrypt(current, single + (b * 16)));
	}
	// Проверяем схождение гаммы с поблочным шифрованием
	ASSERT_EQ(text(stream, sizeof(stream)), text(single, sizeof(single)));
	// Проверяем схождение путей
	ASSERT_EQ(text(tables, sizeof(tables)), text(single, sizeof(single)));
	// Проверяем, что счётчик прошёл границу младших четырёх байтов и старшие не тронуты
	ASSERT_EQ(current[11], static_cast <uint8_t> (0xfb));
	ASSERT_EQ(current[15], static_cast <uint8_t> (0xfd + 21));
}
