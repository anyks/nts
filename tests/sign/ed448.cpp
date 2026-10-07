/**
 * @file ed448.cpp
 * @date 2026-10-07
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
 * @brief Исходный файл проверок модуля электронной подписи Ed448
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <vector>
#include <string>
#include <sign/ed448.hpp>

/**
 * Подключаем библиотеку Google Test
 */
#include <gtest/gtest.h>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Контрольный пример «TEST 1» раздела 7.4 RFC 8032: зерно, ключ проверки, пустое
 * сообщение и подпись
 */
static const char * ONE_SECRET =
	"6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a352"
	"8c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
static const char * ONE_PUBLIC =
	"5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778ed"
	"f124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
static const char * ONE_MESSAGE = "";
static const char * ONE_SIGNATURE =
	"533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b"
	"233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e"
	"006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a"
	"7363268c71d95808ff2e652600";

/**
 * Контрольный пример «TEST 2» раздела 7.4 RFC 8032: то же зерно, сообщение из
 * одного байта 0x03 и подпись
 */
static const char * TWO_MESSAGE = "03";
static const char * TWO_SIGNATURE =
	"d9cb4716a9c61e3a290566889cd35b56e3d69ac13e99790219076d4842f2875844"
	"aafd9654db6cc6939f17fb0eea43ab148238412a752f2b0050e50c0c7b8e673369fe"
	"8d0d085076ddc3e13d62c0d318c1df0c78a057f524d044d7d4d5835dad51a58a7756"
	"2459035c04949e664fc86c3400";

/**
 * @brief Метод разбора записи шестнадцатеричными знаками
 *
 * @param text разбираемая запись
 *
 * @return     разобранные байты
 *
 */
static std::vector <uint8_t> bytes(const char * text) {
	// Разобранные байты
	std::vector <uint8_t> result;
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
		result.push_back(value);
	}
	// Выводим разобранные байты
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
 * @brief Метод получения области байтов вектора
 *
 * @param data вектор байтов
 *
 * @return     область байтов вектора
 *
 */
static view_t view(const std::vector <uint8_t> & data) {
	// Выводим область байтов вектора
	return view_t(data.empty() ? nullptr : data.data(), data.size());
}
/**
 * @brief Метод проверки контрольного примера
 *
 * @param secret    зерно ключа подписи
 * @param pub       ключ проверки подписи
 * @param message   подписываемое сообщение
 * @param signature ожидаемая подпись
 *
 */
static void example(const char * secret, const char * pub, const char * message, const char * signature) {
	// Объект модуля электронной подписи
	sign::ed448_t ed448;
	// Проверяем размер подписи
	ASSERT_EQ(ed448.size(), static_cast <size_t> (114));
	// Разобранные записи примера
	const std::vector <uint8_t> seed = bytes(secret), data = bytes(message), expected = bytes(signature);
	// Выполняем установку ключа подписи
	ASSERT_TRUE(ed448.secret(view(seed)));
	// Место ключа проверки подписи
	uint8_t key[57];
	// Выполняем получение ключа проверки подписи
	ASSERT_TRUE(ed448.key(key, sizeof(key)));
	// Сличаем ключ проверки с контрольным примером
	ASSERT_EQ(text(key, sizeof(key)), std::string(pub));
	// Место выработанной подписи
	uint8_t result[114];
	// Выполняем выработку подписи
	ASSERT_TRUE(ed448.make(view(data), result));
	// Сличаем выработанную подпись с контрольным примером
	ASSERT_EQ(text(result, sizeof(result)), std::string(signature));
	// Выполняем проверку выработанной подписи тем же объектом
	ASSERT_TRUE(ed448.check(view(data), view_t(result, sizeof(result))));
	// Объект проверки подписи одним ключом проверки
	sign::ed448_t verifier;
	// Выполняем установку ключа проверки подписи
	ASSERT_TRUE(verifier.key(view_t(key, sizeof(key))));
	// Выполняем проверку подписи контрольного примера
	ASSERT_TRUE(verifier.check(view(data), view(expected)));
	// Проверяем отказ выработки подписи без ключа подписи
	ASSERT_FALSE(verifier.make(view(data), result));
}

/**
 * Проверка контрольного примера TEST 1 с пустым сообщением
 */
TEST(Ed448Test, One) {
	// Выполняем проверку контрольного примера
	example(ONE_SECRET, ONE_PUBLIC, ONE_MESSAGE, ONE_SIGNATURE);
}
/**
 * Проверка контрольного примера TEST 2 с сообщением из одного байта
 */
TEST(Ed448Test, Two) {
	// Выполняем проверку контрольного примера
	example(ONE_SECRET, ONE_PUBLIC, TWO_MESSAGE, TWO_SIGNATURE);
}
/**
 * Проверка круговой подписи: порождённый ключ подписывает, тот же ключ проверяет,
 * чужой ключ подпись не сличает
 */
TEST(Ed448Test, Roundtrip) {
	// Объекты модулей электронной подписи сторон
	sign::ed448_t first, second;
	// Зерна ключей подписи сторон
	uint8_t seedFirst[57], seedSecond[57];
	// Выполняем порождение ключей подписи сторон
	ASSERT_TRUE(first.generate(seedFirst, sizeof(seedFirst)));
	ASSERT_TRUE(second.generate(seedSecond, sizeof(seedSecond)));
	// Ключи проверки подписи сторон
	uint8_t pubFirst[57], pubSecond[57];
	// Выполняем получение ключей проверки подписи сторон
	ASSERT_TRUE(first.key(pubFirst, sizeof(pubFirst)));
	ASSERT_TRUE(second.key(pubSecond, sizeof(pubSecond)));
	// Подписываемое сообщение
	const uint8_t message[] = {'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e'};
	// Место выработанной подписи
	uint8_t result[114];
	// Выполняем выработку подписи первой стороной
	ASSERT_TRUE(first.make(view_t(message, sizeof(message)), result));
	// Объект проверки подписи ключом первой стороны
	sign::ed448_t verifierFirst;
	// Выполняем установку ключа проверки первой стороны
	ASSERT_TRUE(verifierFirst.key(view_t(pubFirst, sizeof(pubFirst))));
	// Проверяем схождение подписи ключом первой стороны
	ASSERT_TRUE(verifierFirst.check(view_t(message, sizeof(message)), view_t(result, sizeof(result))));
	// Объект проверки подписи ключом второй стороны
	sign::ed448_t verifierSecond;
	// Выполняем установку ключа проверки второй стороны
	ASSERT_TRUE(verifierSecond.key(view_t(pubSecond, sizeof(pubSecond))));
	// Проверяем несхождение подписи первой стороны ключом второй стороны
	ASSERT_FALSE(verifierSecond.check(view_t(message, sizeof(message)), view_t(result, sizeof(result))));
}
/**
 * Проверка отказов проверки подписи: изменённое сообщение, порченая подпись,
 * неканоничный скаляр, чужой ключ проверки
 */
TEST(Ed448Test, Reject) {
	// Объект модуля электронной подписи
	sign::ed448_t ed448;
	// Разобранные записи примера
	const std::vector <uint8_t> seed = bytes(ONE_SECRET), data = bytes(TWO_MESSAGE), expected = bytes(TWO_SIGNATURE);
	// Выполняем установку ключа подписи
	ASSERT_TRUE(ed448.secret(view(seed)));
	// Проверяем схождение годной подписи
	ASSERT_TRUE(ed448.check(view(data), view(expected)));
	// Порченая подпись: изменённый байт точки R
	std::vector <uint8_t> forged = expected;
	// Ломаем байт подписи
	forged[10] ^= 0x01;
	// Проверяем отказ порченой подписи
	ASSERT_FALSE(ed448.check(view(data), view(forged)));
	// Порченая подпись: изменённый байт скаляра S
	forged = expected;
	// Ломаем байт скаляра подписи
	forged[100] ^= 0x01;
	// Проверяем отказ порченой подписи
	ASSERT_FALSE(ed448.check(view(data), view(forged)));
	// Изменённое сообщение
	const std::vector <uint8_t> altered = {0x04};
	// Проверяем отказ подписи на изменённом сообщении
	ASSERT_FALSE(ed448.check(view(altered), view(expected)));
	// Подпись с неканоничным скаляром: скаляр не меньше порядка подгруппы
	forged = expected;
	// Ставим старший байт скаляра: порядок короче пятидесяти семи байтов
	forged[113] = 0xFF;
	// Проверяем отказ подписи с неканоничным скаляром
	ASSERT_FALSE(ed448.check(view(data), view(forged)));
	// Чужой ключ проверки: ключ проверки от иного зерна
	sign::ed448_t alien;
	// Зерно чужого ключа
	uint8_t seedAlien[57];
	// Выполняем порождение чужого ключа
	ASSERT_TRUE(alien.generate(seedAlien, sizeof(seedAlien)));
	// Проверяем отказ годной подписи чужим ключом проверки
	ASSERT_FALSE(alien.check(view(data), view(expected)));
}
