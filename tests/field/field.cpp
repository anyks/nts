/**
 * @file field.cpp
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
 * @brief Исходный файл проверок модуля полей протокола TLS
 *
 * @note Отдельно проверяется, что отказавшее чтение места чтения не подвигает: разбор
 *       тела сообщения ведётся цепочкой чтений, и продолжение разбора после отказа
 *       означало бы разбор мусора
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <vector>
#include <cstring>
#include <main.hpp>
#include <field/field.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace anyks;

/**
 * Проверка чтения чисел заданной ширины
 */
TEST(FieldTest, Number){
	// Разбираемая область байтов
	const uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
	// Объект разборщика полей протокола
	field::scanner_t scanner;
	// Устанавливаем разбираемую область байтов
	scanner.start(view_t(data, sizeof(data)));
	// Прочитанное значение числа
	uint32_t value = 0;
	// Выполняем чтение числа шириной в один байт
	ASSERT_EQ(scanner.number(value, 1), field::error_t::NONE);
	// Проверяем прочитанное значение числа шириной в один байт
	ASSERT_EQ(value, static_cast <uint32_t> (0x01));
	// Выполняем чтение числа шириной в два байта
	ASSERT_EQ(scanner.number(value, 2), field::error_t::NONE);
	// Проверяем прочитанное значение числа шириной в два байта
	ASSERT_EQ(value, static_cast <uint32_t> (0x0203));
	// Выполняем чтение числа шириной в три байта
	ASSERT_EQ(scanner.number(value, 3), field::error_t::NONE);
	// Проверяем прочитанное значение числа шириной в три байта
	ASSERT_EQ(value, static_cast <uint32_t> (0x040506));
	// Выполняем чтение числа шириной в четыре байта
	ASSERT_EQ(scanner.number(value, 4), field::error_t::NONE);
	// Проверяем прочитанное значение числа шириной в четыре байта
	ASSERT_EQ(value, static_cast <uint32_t> (0x0708090A));
	// Проверяем, что разбираемая область прочитана целиком
	ASSERT_EQ(scanner.left(), static_cast <size_t> (0));
	// Проверяем отказ чтения числа за концом разбираемой области
	ASSERT_EQ(scanner.number(value, 1), field::error_t::HUNGRY);
	// Проверяем отказ чтения числа недозволенной ширины
	ASSERT_EQ(scanner.number(value, 5), field::error_t::WIDTH);
	// Проверяем отказ чтения числа нулевой ширины
	ASSERT_EQ(scanner.number(value, 0), field::error_t::WIDTH);
}

/**
 * Проверка чтения полей переменной длины
 */
TEST(FieldTest, Vector){
	// Разбираемая область с полями переменной длины
	const uint8_t data[] = {0x02, 0xAA, 0xBB, 0x00, 0x03, 0xCC, 0xDD, 0xEE, 0x00, 0x00, 0x01, 0xFF};
	// Объект разборщика полей протокола
	field::scanner_t scanner;
	// Устанавливаем разбираемую область байтов
	scanner.start(view_t(data, sizeof(data)));
	// Прочитанное содержимое поля переменной длины
	view_t body;
	// Выполняем чтение поля с длиной шириной в один байт
	ASSERT_EQ(scanner.vector(body, 1), field::error_t::NONE);
	// Проверяем длину прочитанного поля
	ASSERT_EQ(body.size, static_cast <size_t> (2));
	// Проверяем содержимое прочитанного поля
	ASSERT_EQ(body.data[0], static_cast <uint8_t> (0xAA));
	// Выполняем чтение поля с длиной шириной в два байта
	ASSERT_EQ(scanner.vector(body, 2), field::error_t::NONE);
	// Проверяем длину прочитанного поля
	ASSERT_EQ(body.size, static_cast <size_t> (3));
	// Проверяем содержимое прочитанного поля
	ASSERT_EQ(body.data[2], static_cast <uint8_t> (0xEE));
	// Выполняем чтение поля с длиной шириной в три байта
	ASSERT_EQ(scanner.vector(body, 3), field::error_t::NONE);
	// Проверяем длину прочитанного поля
	ASSERT_EQ(body.size, static_cast <size_t> (1));
	// Проверяем, что разбираемая область прочитана целиком
	ASSERT_EQ(scanner.left(), static_cast <size_t> (0));
	// Проверяем отказ чтения поля недозволенной ширины длины
	ASSERT_EQ(scanner.vector(body, 4), field::error_t::WIDTH);
}

/**
 * Проверка того, что отказавшее чтение места чтения не подвигает
 */
TEST(FieldTest, Rollback){
	// Разбираемая область с полем, объявившим длину сверх своей области
	const uint8_t data[] = {0x00, 0x10, 0xAA, 0xBB};
	// Объект разборщика полей протокола
	field::scanner_t scanner;
	// Устанавливаем разбираемую область байтов
	scanner.start(view_t(data, sizeof(data)));
	// Прочитанное содержимое поля переменной длины
	view_t body;
	// Проверяем отказ чтения поля, объявившего длину сверх своей области
	ASSERT_EQ(scanner.vector(body, 2), field::error_t::HUNGRY);
	// Проверяем, что отказавшее чтение места чтения не подвинуло
	ASSERT_EQ(scanner.offset(), static_cast <size_t> (0));
	// Проверяем, что вся разбираемая область осталась непрочитанной
	ASSERT_EQ(scanner.left(), sizeof(data));
	// Прочитанное значение числа
	uint32_t value = 0;
	// Выполняем чтение того же места числом
	ASSERT_EQ(scanner.number(value, 2), field::error_t::NONE);
	// Проверяем прочитанное значение объявленной длины поля
	ASSERT_EQ(value, static_cast <uint32_t> (0x0010));
}

/**
 * Проверка составления вложенных полей переменной длины
 */
TEST(FieldTest, Nesting){
	// Объект составителя полей протокола
	field::builder_t builder;
	// Открываем внешнее поле переменной длины
	ASSERT_EQ(builder.open(2), field::error_t::NONE);
	// Проверяем число ещё не закрытых полей
	ASSERT_EQ(builder.nesting(), static_cast <size_t> (1));
	// Записываем число внутри внешнего поля
	ASSERT_EQ(builder.number(0x1234, 2), field::error_t::NONE);
	// Открываем вложенное поле переменной длины
	ASSERT_EQ(builder.open(1), field::error_t::NONE);
	// Записываемая внутрь вложенного поля область байтов
	const uint8_t data[] = {0xAA, 0xBB, 0xCC};
	// Записываем область байтов внутри вложенного поля
	ASSERT_EQ(builder.bytes(view_t(data, sizeof(data))), field::error_t::NONE);
	// Закрываем вложенное поле переменной длины
	ASSERT_EQ(builder.close(), field::error_t::NONE);
	// Закрываем внешнее поле переменной длины
	ASSERT_EQ(builder.close(), field::error_t::NONE);
	// Проверяем, что незакрытых полей не осталось
	ASSERT_EQ(builder.nesting(), static_cast <size_t> (0));
	// Проверяем отказ закрытия поля, которого нет
	ASSERT_EQ(builder.close(), field::error_t::NESTING);
	// Ожидаемая составленная запись
	const uint8_t sample[] = {0x00, 0x06, 0x12, 0x34, 0x03, 0xAA, 0xBB, 0xCC};
	// Получаем составленную запись
	const view_t result = builder.data();
	// Проверяем схождение длины составленной записи с ожидаемой
	ASSERT_EQ(result.size, sizeof(sample));
	// Проверяем схождение составленной записи с ожидаемой
	ASSERT_EQ(::memcmp(result.data, sample, sizeof(sample)), 0);
	// Проверяем отказ записи числа, не входящего в свою ширину
	ASSERT_EQ(builder.number(0x100, 1), field::error_t::LENGTH);
	// Проверяем отказ открытия поля недозволенной ширины длины
	ASSERT_EQ(builder.open(4), field::error_t::WIDTH);
	// Выполняем сброс накопителя составляемой записи
	builder.clear();
	// Проверяем опустошение накопителя составителя
	ASSERT_EQ(builder.pending(), static_cast <size_t> (0));
}

/**
 * Проверка отказа закрытия поля, не входящего в свою длину
 */
TEST(FieldTest, Overflow){
	// Объект составителя полей протокола
	field::builder_t builder;
	// Открываем поле с длиной шириной в один байт
	ASSERT_EQ(builder.open(1), field::error_t::NONE);
	// Записываемая внутрь поля область байтов
	const vector <uint8_t> data(256, 0x00);
	// Записываем внутрь поля больше, чем вмещает его длина
	ASSERT_EQ(builder.bytes(view_t(data.data(), data.size())), field::error_t::NONE);
	// Проверяем отказ закрытия поля, не входящего в свою длину
	ASSERT_EQ(builder.close(), field::error_t::LENGTH);
	// Проверяем, что отказавшее закрытие поля открытым его и оставило
	ASSERT_EQ(builder.nesting(), static_cast <size_t> (1));
}
