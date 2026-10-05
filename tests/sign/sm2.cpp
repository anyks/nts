/**
 * @file sm2.cpp
 * @date 2026-10-04
 * @license: GPL-3.0
 *
 * @telegram: @forman
 * @author: Yuriy Lobarev
 * @phone: +7 (910) 983-95-90
 * @email: forman@anyks.com
 * @site: https://anyks.com
 *
 * @brief Исходный файл проверок модуля электронной подписи SM2
 *
 * @note Контрольный пример выработан на кривой curveSM2 по GB/T 32918.5-2017:
 *       ключ подписи, ключ проверки, значение Z_A при опознавателе
 *       «1234567812345678» (умолчание раздела 5 GB/T 32918.2-2016, оно же
 *       опознаватель сертификатов по RFC 8998), случайное число и обе части
 *       подписи сообщения «message digest». Пример сверен с OpenSSL 3.6 в обе
 *       стороны: его подпись сходится нашей проверкой, наша - его
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
#include <sign/sm2.hpp>
#include <curve/parameters.hpp>

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
 * Опознаватель подписывающего: умолчание раздела 5 GB/T 32918.2-2016
 */
static const char * ID = "1234567812345678";

/**
 * Подписываемое сообщение контрольного примера
 */
static const char * MESSAGE = "message digest";

/**
 * Проверка контрольного примера на кривой curveSM2
 */
TEST(Sm2Test, Vector){
	// Эллиптическая кривая SM2
	curve::curve_t curve;
	// Проверяем установку кривой по опознавателю
	ASSERT_TRUE(curve::parameters("1.2.156.10197.1.301", curve));
	// Ключ подписи примера
	const std::vector <uint8_t> secret = bytes("6551ae83fa8008f12538a6d58aee19002b3994aa24e795891ffae2b213c4490a");
	// Объект подписи
	sign::sm2_t sm2;
	// Проверяем установку кривой
	ASSERT_TRUE(sm2.start(curve));
	// Проверяем готовность модуля
	ASSERT_TRUE(sm2.ready());
	// Проверяем размер подписи
	ASSERT_EQ(sm2.size(), 64);
	// Проверяем установку ключа подписи
	ASSERT_TRUE(sm2.secret(view_t(secret.data(), secret.size()), view_t(reinterpret_cast <const uint8_t *> (ID), ::strlen(ID))));
	// Координаты ключа проверки подписи
	uint8_t x[32], y[32];
	// Проверяем получение ключа проверки подписи
	ASSERT_TRUE(sm2.key(x, y, sizeof(x)));
	// Проверяем первую координату ключа проверки примера
	ASSERT_EQ(text(x, sizeof(x)), "a533b7ec577792f56169a946e4aa90ebd050c669dd3794c0e05df293ff99e7b7");
	// Проверяем вторую координату ключа проверки примера
	ASSERT_EQ(text(y, sizeof(y)), "f0307832fcc52bf1f4130a72031cec9f0ade0d5eda855d31aff0173280f1f975");
	// Случайное число выработки подписи примера
	const std::vector <uint8_t> random = bytes("6cb28d99385c175c94f94e934817663fc176d925dd72b727260dbaae1fb2f96f");
	// Выработанная подпись
	uint8_t signature[64];
	// Проверяем выработку подписи
	ASSERT_TRUE(sm2.make(view_t(reinterpret_cast <const uint8_t *> (MESSAGE), ::strlen(MESSAGE)), view_t(random.data(), random.size()), signature));
	// Проверяем первую часть подписи примера
	ASSERT_EQ(text(signature, 32), "7ad35d40dd3b7d2b4d70151861810050ca0c5319bdfdad4c198535c0bebb4803");
	// Проверяем вторую часть подписи примера
	ASSERT_EQ(text(signature + 32, 32), "2624044cc8b3d81d0f264b065528c3719cf1d105e9d17aa9baf9bf51c245a7e3");
	// Проверяем схождение выработанной подписи
	ASSERT_TRUE(sm2.check(view_t(reinterpret_cast <const uint8_t *> (MESSAGE), ::strlen(MESSAGE)), view_t(signature, sizeof(signature))));
}

/**
 * Проверка подписи OpenSSL ключом проверки, установленным координатами
 */
TEST(Sm2Test, Public){
	// Эллиптическая кривая SM2
	curve::curve_t curve;
	// Проверяем установку кривой по опознавателю
	ASSERT_TRUE(curve::parameters("1.2.156.10197.1.301", curve));
	// Первая координата ключа проверки примера
	const std::vector <uint8_t> x = bytes("a533b7ec577792f56169a946e4aa90ebd050c669dd3794c0e05df293ff99e7b7");
	// Вторая координата ключа проверки примера
	const std::vector <uint8_t> y = bytes("f0307832fcc52bf1f4130a72031cec9f0ade0d5eda855d31aff0173280f1f975");
	// Объект подписи
	sign::sm2_t sm2;
	// Проверяем установку кривой
	ASSERT_TRUE(sm2.start(curve));
	// Проверяем установку ключа проверки подписи координатами
	ASSERT_TRUE(sm2.key(view_t(x.data(), x.size()), view_t(y.data(), y.size()), view_t(reinterpret_cast <const uint8_t *> (ID), ::strlen(ID))));
	// Подпись, выработанная OpenSSL 3.6 тем же ключом с тем же опознавателем
	const std::vector <uint8_t> signature = bytes(
		"bb810db39df67791a85b874ba618c346bdfb6abc78048364641a1e361c5da96f"
		"46ce9094383d4a9e076f6998dfb397eb272ebd72248567edb70612f2541e66ff"
	);
	// Проверяем схождение подписи OpenSSL
	ASSERT_TRUE(sm2.check(view_t(reinterpret_cast <const uint8_t *> (MESSAGE), ::strlen(MESSAGE)), view_t(signature.data(), signature.size())));
	// Иное сообщение
	const char * other = "message digest!";
	// Проверяем отказ схождения подписи на ином сообщении
	ASSERT_FALSE(sm2.check(view_t(reinterpret_cast <const uint8_t *> (other), ::strlen(other)), view_t(signature.data(), signature.size())));
}

/**
 * Проверка отказов договора
 */
TEST(Sm2Test, Refusals){
	// Эллиптическая кривая SM2
	curve::curve_t curve;
	// Проверяем установку кривой по опознавателю
	ASSERT_TRUE(curve::parameters("1.2.156.10197.1.301", curve));
	// Ключ подписи примера
	const std::vector <uint8_t> secret = bytes("6551ae83fa8008f12538a6d58aee19002b3994aa24e795891ffae2b213c4490a");
	// Случайное число выработки подписи примера
	const std::vector <uint8_t> random = bytes("6cb28d99385c175c94f94e934817663fc176d925dd72b727260dbaae1fb2f96f");
	// Подпись примера
	const std::vector <uint8_t> signature = bytes(
		"7ad35d40dd3b7d2b4d70151861810050ca0c5319bdfdad4c198535c0bebb4803"
		"2624044cc8b3d81d0f264b065528c3719cf1d105e9d17aa9baf9bf51c245a7e3"
	);
	// Объект подписи
	sign::sm2_t sm2;
	// Проверяем неготовность модуля без кривой
	ASSERT_FALSE(sm2.ready());
	// Проверяем отказ установки ключа без кривой
	ASSERT_FALSE(sm2.secret(view_t(secret.data(), secret.size()), view_t(reinterpret_cast <const uint8_t *> (ID), ::strlen(ID))));
	// Проверяем установку кривой
	ASSERT_TRUE(sm2.start(curve));
	// Выработанная подпись
	uint8_t made[64];
	// Проверяем отказ выработки подписи без ключа
	ASSERT_FALSE(sm2.make(view_t(reinterpret_cast <const uint8_t *> (MESSAGE), ::strlen(MESSAGE)), view_t(random.data(), random.size()), made));
	// Проверяем отказ проверки подписи без ключа
	ASSERT_FALSE(sm2.check(view_t(reinterpret_cast <const uint8_t *> (MESSAGE), ::strlen(MESSAGE)), view_t(signature.data(), signature.size())));
	// Проверяем отказ установки нулевого ключа подписи
	const uint8_t zero[32] = {0};
	ASSERT_FALSE(sm2.secret(view_t(zero, sizeof(zero)), view_t(reinterpret_cast <const uint8_t *> (ID), ::strlen(ID))));
	// Проверяем отказ установки ключа подписи с пустым опознавателем
	ASSERT_FALSE(sm2.secret(view_t(secret.data(), secret.size()), view_t()));
	// Проверяем установку ключа подписи
	ASSERT_TRUE(sm2.secret(view_t(secret.data(), secret.size()), view_t(reinterpret_cast <const uint8_t *> (ID), ::strlen(ID))));
	// Проверяем отказ выработки подписи нулевым случайным числом
	ASSERT_FALSE(sm2.make(view_t(reinterpret_cast <const uint8_t *> (MESSAGE), ::strlen(MESSAGE)), view_t(zero, sizeof(zero)), made));
	// Проверяем отказ проверки подписи неверной длины
	ASSERT_FALSE(sm2.check(view_t(reinterpret_cast <const uint8_t *> (MESSAGE), ::strlen(MESSAGE)), view_t(signature.data(), 63)));
	// Подпись с нулевой первой частью
	uint8_t broken[64] = {0};
	// Проверяем отказ проверки подписи с нулевой первой частью
	ASSERT_FALSE(sm2.check(view_t(reinterpret_cast <const uint8_t *> (MESSAGE), ::strlen(MESSAGE)), view_t(broken, sizeof(broken))));
	// Выполняем сброс состояния модуля
	sm2.clear();
	// Проверяем неготовность модуля после сброса
	ASSERT_FALSE(sm2.ready());
}
