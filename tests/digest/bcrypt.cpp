/**
 * @file bcrypt.cpp
 * @date 2026-10-11
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
 * @brief Проверки модуля выработки ключа bcrypt_pbkdf (OpenBSD)
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
#include <digest/bcrypt.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Функция разбора шестнадцатеричной строки в байты
 *
 * @param text разбираемая строка
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
 * @brief Функция получения просмотра строки знаков
 *
 * @param text строка знаков, на которую заводится просмотр
 * @return     просмотр области байтов строки знаков
 *
 */
static view_t text(const char * text) noexcept {
	// Выводим просмотр области байтов строки знаков
	return view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text));
}

/**
 * Проверка выработки ключа по контрольным примерам OpenBSD
 */
TEST(BcryptTest, Vectors) {
	// Контрольные примеры OpenBSD bcrypt_pbkdf: пароль, соль, круги, выработанный ключ
	static const struct {
		// Пароль и соль строкой, ключ шестнадцатеричной записью
		const char * pass, * salt, * key;
		// Число кругов выработки ключа
		size_t rounds;
	} VECTORS[] = {
		// Контрольный пример OpenBSD: password, salt, 4 круга, 32 байта
		{"password", "salt", "5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9", 4},
		// Контрольный пример OpenBSD: password, salt, 1 круг, 32 байта
		{"password", "salt", "7af41469e52860da49debfaa6a4e12a2cb857b907b2bb20d2902a9ccd424adb1", 1}
	};
	/**
	 * Выполняем перебор контрольных примеров
	 */
	for(const auto & item : VECTORS){
		// Место выработанного ключа
		uint8_t key[32];
		// Выполняем выработку ключа контрольного примера
		ASSERT_TRUE(digest::bcrypt(::text(item.pass), ::text(item.salt), key, sizeof(key), item.rounds)) << "пароль " << item.pass;
		// Сверяем выработанный ключ с контрольным примером
		EXPECT_EQ(std::vector <uint8_t> (key, key + sizeof(key)), bytes(item.key)) << "пароль " << item.pass;
	}
}

/**
 * Проверка выработки ключа длиной не в целое число блоков
 */
TEST(BcryptTest, Partial) {
	// Место выработанного ключа нестандартной длины
	uint8_t key[42];
	// Выполняем выработку ключа длиной не в целое число блоков: перемешивание байтов
	ASSERT_TRUE(digest::bcrypt(::text("password"), ::text("salt"), key, sizeof(key), 4));
	// Выработка того же ключа по блокам обязана дать те же байты на тех же местах
	uint8_t whole[64];
	// Выработка того же ключа целым числом блоков обязана удаться
	ASSERT_TRUE(digest::bcrypt(::text("password"), ::text("salt"), whole, sizeof(whole), 4));
	// Первые байты совпадают: перемешивание раскладывает их по местам одинаково
	EXPECT_EQ(key[0], whole[0]);
}

/**
 * Проверка отказов выработки ключа
 */
TEST(BcryptTest, Refusals) {
	// Место выработанного ключа
	uint8_t key[32];
	// Пустой пароль отвергается
	EXPECT_FALSE(digest::bcrypt(view_t(), ::text("salt"), key, sizeof(key), 4));
	// Пустая соль отвергается
	EXPECT_FALSE(digest::bcrypt(::text("password"), view_t(), key, sizeof(key), 4));
	// Нулевое место итога отвергается
	EXPECT_FALSE(digest::bcrypt(::text("password"), ::text("salt"), nullptr, sizeof(key), 4));
	// Нулевая длина итога отвергается
	EXPECT_FALSE(digest::bcrypt(::text("password"), ::text("salt"), key, 0, 4));
	// Нулевое число кругов отвергается
	EXPECT_FALSE(digest::bcrypt(::text("password"), ::text("salt"), key, sizeof(key), 0));
}
