/**
 * @file hmac.cpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-ANYKS-TLS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Исходный файл проверок модуля имитовставки HMAC и порождающей функции TLS
 *
 * @note Контрольные примеры взяты из приложения А RFC 7836, случаи с первого по
 *       четвёртый: имитовставка обеих длин и порождающая последовательность обеих
 *       длин с их первыми двумя частями
 *
 * @note Схождение с этими примерами доказывает и порядок записи хеша: имитовставка
 *       строится на строке байтов, и запись вектором её бы не дала
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <cstring>
#include <main.hpp>
#include <digest/hmac.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace anyks;

/**
 * Ключ контрольных примеров
 */
static const char * SECRET = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/**
 * Сообщение выработки имитовставки контрольных примеров
 */
static const char * MESSAGE = "0126bdb87800af214341456563780100";

/**
 * Затравка выработки последовательности контрольных примеров
 */
static const char * SEED = "18471d622dc655c4d2d2269691ca4a560b50aba663553af241f1ada882c9f29a";

/**
 * Метка назначения последовательности контрольных примеров
 */
static const char * LABEL = "1122334455";

/**
 * @brief Метод разбора записи шестнадцатеричными знаками
 *
 * @param text разбираемая запись
 * @param data место, в которое помещаются разобранные байты
 *
 * @return     число разобранных байтов
 *
 */
static size_t bytes(const char * text, uint8_t * data) {
	// Число разобранных байтов
	size_t result = 0;
	/**
	 * Выполняем перебор пар знаков разбираемой записи
	 */
	for(size_t i = 0; text[i * 2] != '\0'; i++){
		// Собираемое значение байта
		uint8_t value = 0;
		/**
		 * Выполняем перебор знаков очередной пары
		 */
		for(size_t j = 0; j < 2; j++){
			// Извлекаем очередной знак записи
			const char letter = text[(i * 2) + j];
			// Дополняем значение байта очередным знаком записи
			value = static_cast <uint8_t> ((value << 4) | ((letter <= '9') ? (letter - '0') : ((letter - 'a') + 10)));
		}
		// Записываем разобранный байт
		data[result++] = value;
	}
	// Выводим число разобранных байтов
	return result;
}
/**
 * @brief Метод сборки записи шестнадцатеричными знаками
 *
 * @param data собираемые байты
 * @param size число собираемых байтов
 *
 * @return     собранная запись
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Собираемая запись
	std::string result;
	// Набор шестнадцатеричных знаков
	static const char * letters = "0123456789abcdef";
	/**
	 * Выполняем перебор собираемых байтов
	 */
	for(size_t i = 0; i < size; i++){
		// Записываем старший знак очередного байта
		result.append(1, letters[(data[i] >> 4) & 0x0F]);
		// Записываем младший знак очередного байта
		result.append(1, letters[data[i] & 0x0F]);
	}
	// Выводим собранную запись
	return result;
}

/**
 * @brief Проверка выработки имитовставки по контрольным примерам
 *
 */
TEST(HmacTest, Samples) {
	// Места, в которые помещаются разбираемые записи
	uint8_t secret[32], message[16], result[64];
	// Выполняем разбор ключа контрольных примеров
	ASSERT_EQ(bytes(SECRET, secret), static_cast <size_t> (32));
	// Выполняем разбор сообщения выработки имитовставки
	ASSERT_EQ(bytes(MESSAGE, message), static_cast <size_t> (16));
	// Выполняем выработку имитовставки длиной 256 разрядов
	ASSERT_TRUE(digest::hmac(digest::type_t::SHORT, view_t(secret, 32), view_t(message, 16), result, 32));
	// Сличаем выработанную имитовставку с контрольным примером
	ASSERT_EQ(text(result, 32), std::string("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"));
	// Выполняем выработку имитовставки длиной 512 разрядов
	ASSERT_TRUE(digest::hmac(digest::type_t::LONG, view_t(secret, 32), view_t(message, 16), result, 64));
	// Сличаем выработанную имитовставку с контрольным примером
	ASSERT_EQ(text(result, 64), std::string(
		"a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a77"
		"3d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"
	));
	// Проверяем усечение имитовставки до требуемой длины
	uint8_t item[64];
	// Выполняем выработку усечённой имитовставки
	ASSERT_TRUE(digest::hmac(digest::type_t::SHORT, view_t(secret, 32), view_t(message, 16), item, 8));
	// Сличаем усечённую имитовставку с началом полной
	ASSERT_EQ(text(item, 8), std::string("a1aa5f7de402d7b3"));
}
/**
 * @brief Проверка выработки порождающей последовательности по контрольным примерам
 *
 */
TEST(HmacTest, Sequence) {
	// Места, в которые помещаются разбираемые записи
	uint8_t secret[32], seed[32], label[8], result[128];
	// Выполняем разбор ключа контрольных примеров
	bytes(SECRET, secret);
	// Выполняем разбор затравки выработки последовательности
	bytes(SEED, seed);
	// Выполняем разбор метки назначения последовательности
	ASSERT_EQ(bytes(LABEL, label), static_cast <size_t> (5));
	// Выполняем выработку последовательности длиной 256 разрядов
	ASSERT_TRUE(digest::prf(digest::type_t::SHORT, view_t(secret, 32), view_t(label, 5), view_t(seed, 32), result, 64));
	// Сличаем первую часть последовательности с контрольным примером
	ASSERT_EQ(text(result, 32), std::string("ff09664a44745865944f839ebb48965f1544ff1cc8e8f16f247ee5f8a9ebe97f"));
	// Сличаем вторую часть последовательности с контрольным примером
	ASSERT_EQ(text(result + 32, 32), std::string("c4e3c7900e46cad3db6a01643063040ec67fc0fd5cd9f90465235237bdff2c02"));
	// Выполняем выработку последовательности длиной 512 разрядов
	ASSERT_TRUE(digest::prf(digest::type_t::LONG, view_t(secret, 32), view_t(label, 5), view_t(seed, 32), result, 128));
	// Сличаем первую часть последовательности с контрольным примером
	ASSERT_EQ(text(result, 64), std::string(
		"f35187a3dc9655113a0e84d06fd7526c5fc1fbdec1a0e4673dd6d79d0b920e65"
		"ad1bc47bb083b3851cb7cd8e7e6a911a626cf02b29e9e4a58ed766a449a7296d"
	));
	// Сличаем вторую часть последовательности с контрольным примером
	ASSERT_EQ(text(result + 64, 64), std::string(
		"e61a7a26c4d1caeecfd80cca65c71f0f88c1f822c0e8c0ad949d03fee139579f"
		"72ba0c3d32c5f954f1cccd54081fc7440278cba1fe7b7a17a986fdff5bd15d1f"
	));
	// Место, в которое помещается последовательность неполной длины
	uint8_t item[100];
	// Выполняем выработку последовательности длины, не кратной длине хеша
	ASSERT_TRUE(digest::prf(digest::type_t::SHORT, view_t(secret, 32), view_t(label, 5), view_t(seed, 32), item, sizeof(item)));
	// Сличаем начало полученной последовательности с выработанной прежде
	ASSERT_EQ(text(item, 32), std::string("ff09664a44745865944f839ebb48965f1544ff1cc8e8f16f247ee5f8a9ebe97f"));
	// Проверяем, что метка и затравка идут подряд одной строкой
	uint8_t merged[37];
	// Записываем метку назначения последовательности
	::memcpy(merged, label, 5);
	// Записываем затравку выработки последовательности
	::memcpy(merged + 5, seed, 32);
	// Выполняем выработку последовательности со слитной строкой в качестве затравки
	ASSERT_TRUE(digest::prf(digest::type_t::SHORT, view_t(secret, 32), view_t(), view_t(merged, sizeof(merged)), result, 32));
	// Сличаем полученную последовательность с выработанной с меткой
	ASSERT_EQ(text(result, 32), std::string("ff09664a44745865944f839ebb48965f1544ff1cc8e8f16f247ee5f8a9ebe97f"));
}
/**
 * @brief Проверка отказов выработки имитовставки и последовательности
 *
 */
TEST(HmacTest, Failures) {
	// Места, в которые помещаются разбираемые записи
	uint8_t secret[32], message[16], result[64];
	// Выполняем разбор ключа контрольных примеров
	bytes(SECRET, secret);
	// Выполняем разбор сообщения выработки имитовставки
	bytes(MESSAGE, message);
	// Проверяем отказ выработки имитовставки без длины хеша
	ASSERT_FALSE(digest::hmac(digest::type_t::NONE, view_t(secret, 32), view_t(message, 16), result, 32));
	// Проверяем отказ выработки имитовставки в непереданное место
	ASSERT_FALSE(digest::hmac(digest::type_t::SHORT, view_t(secret, 32), view_t(message, 16), nullptr, 32));
	// Проверяем отказ выработки имитовставки нулевой длины
	ASSERT_FALSE(digest::hmac(digest::type_t::SHORT, view_t(secret, 32), view_t(message, 16), result, 0));
	// Проверяем отказ выработки имитовставки длиннее хеша
	ASSERT_FALSE(digest::hmac(digest::type_t::SHORT, view_t(secret, 32), view_t(message, 16), result, 33));
	// Проверяем успешность выработки имитовставки с пустым ключом
	ASSERT_TRUE(digest::hmac(digest::type_t::SHORT, view_t(), view_t(message, 16), result, 32));
	// Проверяем успешность выработки имитовставки на пустом сообщении
	ASSERT_TRUE(digest::hmac(digest::type_t::SHORT, view_t(secret, 32), view_t(), result, 32));
	// Место, в которое помещается длинный ключ выработки имитовставки
	uint8_t buffer[128];
	/**
	 * Выполняем перебор байтов длинного ключа
	 */
	for(size_t i = 0; i < sizeof(buffer); i++)
		// Записываем очередной байт длинного ключа
		buffer[i] = static_cast <uint8_t> (i);
	/**
	 * Ключ длиннее блока сжатия заменяется своим хешем: раздел 2 RFC 2104 велит
	 * поступать так, и отказом это быть не должно
	 */
	ASSERT_TRUE(digest::hmac(digest::type_t::SHORT, view_t(buffer, sizeof(buffer)), view_t(message, 16), result, 32));
	// Проверяем отказ выработки последовательности без длины хеша
	ASSERT_FALSE(digest::prf(digest::type_t::NONE, view_t(secret, 32), view_t(), view_t(message, 16), result, 32));
	// Проверяем отказ выработки последовательности в непереданное место
	ASSERT_FALSE(digest::prf(digest::type_t::SHORT, view_t(secret, 32), view_t(), view_t(message, 16), nullptr, 32));
	// Проверяем отказ выработки последовательности нулевой длины
	ASSERT_FALSE(digest::prf(digest::type_t::SHORT, view_t(secret, 32), view_t(), view_t(message, 16), result, 0));
	// Проверяем успешность выработки последовательности без метки и затравки
	ASSERT_TRUE(digest::prf(digest::type_t::SHORT, view_t(secret, 32), view_t(), view_t(), result, 32));
}
