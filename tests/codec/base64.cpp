/**
 * @file base64.cpp
 * @date 2026-11-07
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
 * @brief Проверки кодека основания 64
 *
 * @details Векторы разделов 4 и 10 RFC 4648, строгие отказы разбора, круг
 *          кодирования и разбора на случайных длинах, сличение переносимого и
 *          машинного путей понижением укрытия
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <codec/base64.hpp>
#include <sys/machine.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Проверка векторов RFC 4648
 *
 */
TEST(Base64Test, Vectors) {
	// Векторы раздела 10 RFC 4648
	static const struct { const char * data; const char * text; } ROWS[] = {
		{"", ""},
		{"f", "Zg=="},
		{"fo", "Zm8="},
		{"foo", "Zm9v"},
		{"foob", "Zm9vYg=="},
		{"fooba", "Zm9vYmE="},
		{"foobar", "Zm9vYmFy"}
	};
	/**
	 * Выполняем перебор векторов
	 */
	for(const auto & row : ROWS){
		// Запись вектора
		string text;
		// Кодируем данные вектора
		ASSERT_TRUE(codec::encode(view_t(reinterpret_cast <const uint8_t *> (row.data), ::strlen(row.data)), text));
		// Сличаем запись с вектором
		ASSERT_EQ(text, string(row.text));
		// Разобранные байты
		vector <uint8_t> bytes;
		// Разбираем запись вектора
		ASSERT_TRUE(codec::decode(view_t(reinterpret_cast <const uint8_t *> (row.text), ::strlen(row.text)), bytes));
		// Сличаем байты с данными вектора
		ASSERT_EQ(bytes, vector <uint8_t>(reinterpret_cast <const uint8_t *> (row.data), reinterpret_cast <const uint8_t *> (row.data) + ::strlen(row.data)));
	}
}
/**
 * @brief Проверка основания URL
 *
 */
TEST(Base64Test, Url) {
	// Запись знаками URL
	string text;
	// Кодируем хвостовые значения алфавитом URL
	ASSERT_TRUE(codec::encode(view_t(reinterpret_cast <const uint8_t *> (">?\xef"), 3), text, false, codec::alphabet_t::URL));
	// Хвостовые значения дают «-» и «_» без заполнения
	ASSERT_EQ(text, string("Pj_v"));
	// Разобранные байты
	vector <uint8_t> bytes;
	// Разбираем запись знаками URL
	ASSERT_TRUE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Pj_v"), 4), bytes, codec::alphabet_t::URL));
	// Сличаем байты
	ASSERT_EQ(bytes, vector <uint8_t>({'>', '?', 0xEF}));
}
/**
 * @brief Проверка отказов разбора
 *
 */
TEST(Base64Test, Refusals) {
	// Разобранные байты
	vector <uint8_t> bytes;
	// Посторонние знаки
	static const char * FOREIGN[] = {"@AAA", "AAA@", "AA A", "A\ta"};
	/**
	 * Выполняем перебор посторонних знаков
	 */
	for(const char * text : FOREIGN)
		// Посторонний знак отвергается
		ASSERT_FALSE(codec::decode(view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text)), bytes));
	// Пробельный знак пропускается при заказе
	ASSERT_TRUE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Zm9v\nYmFy"), 9), bytes, codec::alphabet_t::STANDARD, true));
	// Сличаем байты
	ASSERT_EQ(bytes, vector <uint8_t>({'f', 'o', 'o', 'b', 'a', 'r'}));
	// Длины с остатком один
	ASSERT_FALSE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Z"), 1), bytes));
	// Заполнение неверного счёта
	ASSERT_FALSE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Zg="), 3), bytes));
	ASSERT_FALSE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Zg==="), 5), bytes));
	ASSERT_FALSE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Zg==Zg=="), 8), bytes));
	// Знак после заполнения
	ASSERT_FALSE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Zm=="), 4), bytes));
	// Ненулевые отброшенные разряды
	ASSERT_FALSE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Zh=="), 4), bytes));
	ASSERT_FALSE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Zn/"), 3), bytes));
	// Заполнение отвергается целиком при запрете: издания вроде RFC 7515 велит запись без него
	ASSERT_FALSE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Zg=="), 4), bytes, codec::alphabet_t::STANDARD, false, false));
	// Запись без заполнения разбирается и при запрете
	ASSERT_TRUE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Zg"), 2), bytes, codec::alphabet_t::STANDARD, false, false));
	// Сличаем байты
	ASSERT_EQ(bytes, vector <uint8_t>({'f'}));
	// Место наполняется разбором
	ASSERT_TRUE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("Zm9v"), 4), bytes));
	// Место непусто до отказа
	ASSERT_FALSE(bytes.empty());
	// Отказ разбора постороннего знака
	ASSERT_FALSE(codec::decode(view_t(reinterpret_cast <const uint8_t *> ("@" "AAA"), 4), bytes));
	// Место затёрто и очищено отказом
	ASSERT_TRUE(bytes.empty());
}
/**
 * @brief Проверка круга кодирования и разбора
 *
 */
TEST(Base64Test, Roundtrip) {
	// Число проверенных длин
	size_t count = 0;
	/**
	 * Выполняем перебор длин входа
	 */
	for(size_t size = 0; size <= 256; size++){
		// Данные случайной длины
		vector <uint8_t> data(size);
			/**
		 * Выполняем перебор байтов данных
		 */
		for(size_t i = 0; i < size; i++)
			// Очередной байт череды
			data[i] = static_cast <uint8_t> ((i * 37 + size * 11) & 0xFF);
		// Запись с заполнением
		string text;
		// Кодируем данные
		ASSERT_TRUE(codec::encode(view_t(data.data(), data.size()), text)) << "длина " << size;
		// Длина записи кратна четырём при заполнении
		ASSERT_EQ(text.size() % 4, static_cast <size_t> (0)) << "длина " << size;
		// Разобранные байты
		vector <uint8_t> bytes;
		// Разбираем запись
		ASSERT_TRUE(codec::decode(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), bytes)) << "длина " << size;
		// Сличаем байты с данными
		ASSERT_EQ(bytes, data) << "длина " << size;
		// Запись без заполнения
		string stripped;
		// Кодируем данные без заполнения
		ASSERT_TRUE(codec::encode(view_t(data.data(), data.size()), stripped, false)) << "длина " << size;
		// Запись без заполнения короче на число знаков заполнения
		ASSERT_EQ(text.size() - stripped.size(), ((size % 3) ? (3 - (size % 3)) : 0)) << "длина " << size;
		// Разбираем запись без заполнения
		ASSERT_TRUE(codec::decode(view_t(reinterpret_cast <const uint8_t *> (stripped.data()), stripped.size()), bytes)) << "длина " << size;
		// Сличаем байты с данными
		ASSERT_EQ(bytes, data) << "длина " << size;
		// Считаем проверенную длину
		count++;
	}
	// Сличаем число проверенных длин
	ASSERT_EQ(count, static_cast <size_t> (257));
}
/**
 * @brief Проверка сличения переносимого и машинного путей
 *
 */
TEST(Base64Test, Paths) {
	// Данные череды
	vector <uint8_t> data(480);
	/**
	 * Выполняем перебор байтов данных
	 */
	for(size_t i = 0; i < data.size(); i++)
		// Очередной байт череды
		data[i] = static_cast <uint8_t> (i * 61);
	/**
	 * Выполняем перебор длин: шаг двадцать четыре байта векторного ядра, граница шага и длинный вход
	 */
	for(const size_t size : {static_cast <size_t> (24), static_cast <size_t> (25), static_cast <size_t> (300), static_cast <size_t> (480)}){
		// Запись машинного пути
		string machine;
		// Кодируем данные машинным путём
		ASSERT_TRUE(codec::encode(view_t(data.data(), size), machine)) << "длина " << size;
		// Запрещаем машинные команды
		machine::allow(false);
		// Запись переносимого пути
		string carried;
		// Кодируем данные переносимым путём
		ASSERT_TRUE(codec::encode(view_t(data.data(), size), carried)) << "длина " << size;
		// Возобновляем машинные команды
		machine::allow(true);
		// Пути обязаны сойтись знак в знак
		ASSERT_EQ(machine, carried) << "длина " << size;
	}
}
