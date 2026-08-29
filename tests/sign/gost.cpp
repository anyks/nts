/**
 * @file gost.cpp
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
 * @brief Исходный файл проверок модуля электронной подписи по ГОСТ Р 34.10-2012
 *
 * @note Контрольный пример взят из раздела 7 RFC 7091 целиком: кривая, ключ подписи,
 *       ключ проверки, хеш сообщения, случайное число выработки и обе части подписи
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
#include <sign/gost.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace anyks;

/**
 * Хеш подписываемого сообщения контрольного примера
 */
static const char * DIGEST = "2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5";

/**
 * Случайное число выработки подписи контрольного примера
 */
static const char * RANDOM = "77105c9b20bcd3122823c8cf6fcc7b956de33814e95b7fe64fed924594dceab3";

/**
 * Ключ подписи контрольного примера
 */
static const char * SECRET = "7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28";

/**
 * Ожидаемая подпись контрольного примера
 */
static const char * SIGNATURE =
	"41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"
	"01456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40";

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
 * @brief Метод установки кривой контрольного примера
 *
 * @param curve устанавливаемая кривая
 *
 * @return      признак успешности установки кривой
 *
 */
static bool prepare(curve::curve_t & curve) {
	// Места, в которые помещаются параметры кривой
	uint8_t modulus[32], first[32], second[32], order[32], x[32], y[32];
	// Выполняем установку параметров кривой
	return curve.start(
		view_t(modulus, bytes("8000000000000000000000000000000000000000000000000000000000000431", modulus)),
		view_t(first, bytes("07", first)),
		view_t(second, bytes("5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e", second)),
		view_t(order, bytes("8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3", order)),
		view_t(x, bytes("02", x)),
		view_t(y, bytes("08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8", y))
	);
}

/**
 * @brief Проверка выработки подписи контрольного примера
 *
 */
TEST(GostTest, Make) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(prepare(curve));
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(gost.start(curve));
	// Места, в которые помещаются разбираемые записи
	uint8_t secret[32], digest[32], random[32];
	// Выполняем разбор ключа подписи
	ASSERT_TRUE(gost.secret(view_t(secret, bytes(SECRET, secret))));
	// Места, в которые записывается ключ проверки подписи
	uint8_t x[32], y[32];
	// Выполняем получение ключа проверки подписи
	ASSERT_TRUE(gost.key(x, y, sizeof(x)));
	// Сличаем первую координату ключа проверки с контрольным примером
	ASSERT_EQ(text(x, sizeof(x)), std::string("7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b"));
	// Сличаем вторую координату ключа проверки с контрольным примером
	ASSERT_EQ(text(y, sizeof(y)), std::string("26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da"));
	// Проверяем размер подписи
	ASSERT_EQ(gost.size(), static_cast <size_t> (64));
	// Место, в которое помещается выработанная подпись
	uint8_t signature[64];
	// Выполняем выработку подписи
	ASSERT_TRUE(gost.make(
		view_t(digest, bytes(DIGEST, digest)),
		view_t(random, bytes(RANDOM, random)),
		signature
	));
	// Сличаем выработанную подпись с контрольным примером
	ASSERT_EQ(text(signature, sizeof(signature)), std::string(SIGNATURE));
	// Выполняем проверку выработанной подписи
	ASSERT_TRUE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature))));
}
/**
 * @brief Проверка подписи одним лишь ключом проверки
 *
 */
TEST(GostTest, Check) {
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(prepare(curve));
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(gost.start(curve));
	// Места, в которые помещаются разбираемые записи
	uint8_t x[32], y[32], digest[32], signature[64];
	// Выполняем разбор координат ключа проверки подписи
	bytes("7f2b49e270db6d90d8595bec458b50c58585ba1d4e9b788f6689dbd8e56fd80b", x);
	bytes("26f1b489d6701dd185c8413a977b3cbbaf64d1c593d26627dffb101a87ff77da", y);
	// Выполняем установку ключа проверки подписи
	ASSERT_TRUE(gost.key(view_t(x, sizeof(x)), view_t(y, sizeof(y))));
	// Выполняем разбор хеша подписанного сообщения
	bytes(DIGEST, digest);
	// Выполняем разбор проверяемой подписи
	bytes(SIGNATURE, signature);
	// Проверяем схождение подписи контрольного примера
	ASSERT_TRUE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature))));
	// Проверяем отказ выработки подписи без ключа подписи
	uint8_t buffer[64];
	// Выполняем попытку выработки подписи
	ASSERT_FALSE(gost.make(view_t(digest, sizeof(digest)), view_t(x, sizeof(x)), buffer));
	/**
	 * Выполняем перебор байтов подписи
	 */
	for(size_t i = 0; i < sizeof(signature); i++){
		// Выполняем порчу очередного байта подписи
		signature[i] = static_cast <uint8_t> (signature[i] ^ 0x01);
		// Проверяем отказ проверки испорченной подписи
		ASSERT_FALSE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature)))) << "Место порчи: " << i;
		// Выполняем восстановление очередного байта подписи
		signature[i] = static_cast <uint8_t> (signature[i] ^ 0x01);
	}
	/**
	 * Выполняем перебор байтов хеша подписанного сообщения
	 */
	for(size_t i = 0; i < sizeof(digest); i++){
		// Выполняем порчу очередного байта хеша
		digest[i] = static_cast <uint8_t> (digest[i] ^ 0x01);
		// Проверяем отказ проверки подписи при испорченном хеше
		ASSERT_FALSE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature)))) << "Место порчи: " << i;
		// Выполняем восстановление очередного байта хеша
		digest[i] = static_cast <uint8_t> (digest[i] ^ 0x01);
	}
	// Проверяем схождение подписи после восстановления всех значений
	ASSERT_TRUE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature))));
}
/**
 * @brief Проверка отказов модуля электронной подписи
 *
 */
TEST(GostTest, Failures) {
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Проверяем отказ работы модуля до установки кривой
	ASSERT_FALSE(gost.ready());
	// Проверяем нулевой размер подписи до установки кривой
	ASSERT_EQ(gost.size(), static_cast <size_t> (0));
	// Места, в которые помещаются разбираемые записи
	uint8_t secret[32], digest[32], signature[64];
	// Выполняем разбор ключа подписи
	bytes(SECRET, secret);
	// Проверяем отказ установки ключа подписи до установки кривой
	ASSERT_FALSE(gost.secret(view_t(secret, sizeof(secret))));
	// Объект неустановленной эллиптической кривой
	curve::curve_t empty;
	// Проверяем отказ установки неготовой кривой
	ASSERT_FALSE(gost.start(empty));
	// Объект эллиптической кривой
	curve::curve_t curve;
	// Выполняем установку кривой контрольного примера
	ASSERT_TRUE(prepare(curve));
	// Выполняем установку эллиптической кривой
	ASSERT_TRUE(gost.start(curve));
	// Проверяем готовность модуля к работе
	ASSERT_TRUE(gost.ready());
	// Место, в которое помещается нулевой ключ подписи
	uint8_t zero[32];
	// Выполняем обнуление ключа подписи
	::memset(zero, 0, sizeof(zero));
	// Проверяем отказ установки нулевого ключа подписи
	ASSERT_FALSE(gost.secret(view_t(zero, sizeof(zero))));
	// Проверяем отказ проверки подписи без ключа проверки
	ASSERT_FALSE(gost.check(view_t(digest, bytes(DIGEST, digest)), view_t(signature, bytes(SIGNATURE, signature))));
	// Выполняем установку ключа подписи
	ASSERT_TRUE(gost.secret(view_t(secret, sizeof(secret))));
	// Проверяем отказ выработки подписи при нулевом случайном числе
	ASSERT_FALSE(gost.make(view_t(digest, sizeof(digest)), view_t(zero, sizeof(zero)), signature));
	// Проверяем отказ выработки подписи в непереданное место
	ASSERT_FALSE(gost.make(view_t(digest, sizeof(digest)), view_t(secret, sizeof(secret)), nullptr));
	// Проверяем отказ проверки подписи неверной длины
	ASSERT_FALSE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, 32)));
	// Выполняем обнуление проверяемой подписи
	::memset(signature, 0, sizeof(signature));
	// Проверяем отказ проверки нулевой подписи
	ASSERT_FALSE(gost.check(view_t(digest, sizeof(digest)), view_t(signature, sizeof(signature))));
	// Выполняем сброс состояния модуля
	gost.clear();
	// Проверяем отказ работы модуля после сброса его состояния
	ASSERT_FALSE(gost.ready());
}
