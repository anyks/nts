/**
 * @file field.cpp
 * @date 2026-08-29
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
#include <starve.hpp>
#include <field/field.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

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

/**
 * Проверка отказов по недозволенной ширине записи длины
 */
TEST(FieldTest, Widthless){
	// Разбираемая область с полем переменной длины
	const uint8_t data[] = {0x01, 0xAA};
	// Объект разборщика полей протокола
	field::scanner_t scanner;
	// Устанавливаем разбираемую область байтов
	scanner.start(view_t(data, sizeof(data)));
	// Прочитанное содержимое поля переменной длины
	view_t body;
	// Проверяем отказ чтения поля с длиной нулевой ширины
	ASSERT_EQ(scanner.vector(body, 0), field::error_t::WIDTH);
	// Проверяем, что отказавшее чтение места чтения не подвинуло
	ASSERT_EQ(scanner.left(), sizeof(data));
	// Объект сборщика полей протокола
	field::builder_t builder;
	// Проверяем отказ записи числа нулевой ширины
	ASSERT_EQ(builder.number(0x01, 0), field::error_t::WIDTH);
	// Проверяем отказ записи числа недозволенной ширины
	ASSERT_EQ(builder.number(0x01, 5), field::error_t::WIDTH);
	// Проверяем отказ открытия поля с длиной нулевой ширины
	ASSERT_EQ(builder.open(0), field::error_t::WIDTH);
	// Проверяем отказ открытия поля с длиной недозволенной ширины
	ASSERT_EQ(builder.open(4), field::error_t::WIDTH);
	// Проверяем, что отказавшее открытие поля накопитель не тронуло
	ASSERT_EQ(builder.data().size, static_cast <size_t> (0));
	// Проверяем отказ закрытия неоткрытого поля переменной длины
	ASSERT_EQ(builder.close(), field::error_t::NESTING);
}

/**
 * @brief Проверка чтения всей оставшейся части разбираемой области
 *
 * @note Приём этот внутри библиотеки не зовётся: он заведён потребителям фреймворка,
 *       разбирающим поля собственных надстроек. Проверка его - единственное, что
 *       стережёт его работу
 *
 */
TEST(FieldTest, Remainder){
	// Разбираемая область полей
	const vector <uint8_t> data = {0x00, 0x2A, 0x41, 0x42, 0x43, 0x44};
	// Объект разборщика полей области
	field::scanner_t scanner;
	// Устанавливаем разбираемую область полей
	scanner.start(view_t(data.data(), data.size()));
	// Прочитанное число области полей
	uint32_t number = 0;
	// Выполняем чтение числа шириною в два байта
	ASSERT_EQ(scanner.number(number, 2), field::error_t::NONE);
	// Проверяем прочитанное число области полей
	ASSERT_EQ(number, static_cast <uint32_t> (0x002A));
	// Просмотр, в который помещается оставшаяся часть области
	view_t tail;
	// Выполняем чтение всей оставшейся части области полей
	ASSERT_EQ(scanner.rest(tail), field::error_t::NONE);
	// Проверяем длину прочитанной оставшейся части области
	ASSERT_EQ(tail.size, static_cast <size_t> (4));
	// Проверяем содержимое прочитанной оставшейся части области
	ASSERT_EQ(::memcmp(tail.data, data.data() + 2, tail.size), 0);
	// Проверяем, что за прочитанным остатком области не осталось ничего
	ASSERT_EQ(scanner.left(), static_cast <size_t> (0));
	/**
	 * Остаток пустой области пуст, и чтение его отказом не является: область
	 * разобрана до конца, и читать в ней более нечего
	 */
	view_t empty;
	// Выполняем чтение остатка разобранной до конца области
	ASSERT_EQ(scanner.rest(empty), field::error_t::NONE);
	// Проверяем нулевую длину остатка разобранной до конца области
	ASSERT_EQ(empty.size, static_cast <size_t> (0));
}

/**
 * @brief Функция составления вложенных полей при отмеренном запасе выделений
 *
 * @param data   область байтов, записываемая внутрь вложенного поля
 * @param intact признак схождения составленной записи с ожидаемой
 * @return       отказ, которым завершился первый несостоявшийся шаг
 *
 */
static field::error_t exhaust(const view_t & data, bool & intact) noexcept {
	// Снимаем признак схождения составленной записи с ожидаемой
	intact = false;
	// Объект составителя полей протокола
	field::builder_t builder;
	// Итог очередного шага
	field::error_t outcome = builder.open(2);
	// Если открытие внешнего поля не состоялось
	if(outcome != field::error_t::NONE)
		// Выводим отказ открытия
		return outcome;
	// Записываем число внутри внешнего поля
	outcome = builder.number(0x1234, 2);
	// Если запись числа не состоялась
	if(outcome != field::error_t::NONE)
		// Выводим отказ записи
		return outcome;
	// Открываем вложенное поле переменной длины
	outcome = builder.open(1);
	// Если открытие вложенного поля не состоялось
	if(outcome != field::error_t::NONE)
		// Выводим отказ открытия
		return outcome;
	// Записываем область байтов внутри вложенного поля
	outcome = builder.bytes(data);
	// Если запись области байтов не состоялась
	if(outcome != field::error_t::NONE)
		// Выводим отказ записи
		return outcome;
	// Закрываем вложенное поле переменной длины
	outcome = builder.close();
	// Если закрытие вложенного поля не состоялось
	if(outcome != field::error_t::NONE)
		// Выводим отказ закрытия
		return outcome;
	// Закрываем внешнее поле переменной длины
	outcome = builder.close();
	// Если закрытие внешнего поля не состоялось
	if(outcome != field::error_t::NONE)
		// Выводим отказ закрытия
		return outcome;
	// Получаем составленную запись
	const view_t result = builder.data();
	// Запоминаем схождение длины и хвоста составленной записи с ожидаемыми
	intact = ((result.size == (2 + 2 + 1 + data.size)) && (result.data[0] == 0x00) && (result.data[1] == static_cast <uint8_t> (3 + data.size)) && (result.data[4] == static_cast <uint8_t> (data.size)) && (::memcmp(result.data + 5, data.data, data.size) == 0));
	// Выводим успешность составления
	return field::error_t::NONE;
}

/**
 * Проверка составления полей при нехватке памяти
 */
TEST(FieldTest, Starved){
	// Записываемая внутрь вложенного поля область байтов
	vector <uint8_t> data(100, 0xAA);
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе составление обязано
	 * ответить либо успехом, либо отказом памяти, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 64; budget++){
		// Итог составления при отмеренном запасе
		field::error_t outcome = field::error_t::NONE;
		// Признак схождения составленной записи с ожидаемой
		bool intact = false;
		{
			// Отмеряем запас выделений на время составления
			starve::ration_t ration(budget);
			// Выполняем составление при отмеренном запасе
			outcome = exhaust(view_t(data.data(), data.size()), intact);
		}
		// Проверяем, что составление ответило успехом либо отказом памяти
		ASSERT_TRUE((outcome == field::error_t::NONE) || (outcome == field::error_t::MEMORY)) << "запас " << budget << " отказ " << static_cast <int> (outcome);
		// Проверяем, что успех не скрывает усечённой нехваткой памяти записи
		ASSERT_TRUE((outcome != field::error_t::NONE) || intact) << "запас " << budget;
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == field::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}

/**
 * Подключаем открытый API затирания области памяти: им же затирается накопитель
 */
#include <sys/wipe.hpp>

/**
 * Если проверка собрана под наблюдателем адресов: чтение накопителя за его сбросом
 * законно лишь по снятию отравы с области памяти
 */
#if defined(__has_feature)
	/**
	 * Опрашиваем поддержку наблюдателя адресов у собирателя
	 */
	#if __has_feature(address_sanitizer)
		#include <sanitizer/asan_interface.h>
		/**
		 * Наблюдатель есть: снятие отравы области памяти перед чтением накопителя
		 */
		#define ANTS_FIELD_UNPOISON(data, size) ASAN_UNPOISON_MEMORY_REGION(data, size)
	#endif
#endif
/**
 * Макрос не выставлен: наблюдателя адресов в сборке нет
 */
#if !defined(ANTS_FIELD_UNPOISON)
	/**
	 * Наблюдателя нет: снятие отравы вырождается в пустое действие
	 */
	#define ANTS_FIELD_UNPOISON(data, size) ((void) 0)
#endif

/**
 * Проверка затирания накопителя составителя: секреты (общее значение обмена, состояние
 * билета сеанса) складываются составителем, и по сбросу их в памяти оставаться не должно.
 * Область накопителя по сбросу читается по просмотру, снятому до сброса: у vector сброс
 * ёмкости не отдаёт, и память остаётся своей
 */
TEST(FieldTest, Wiped){
	// Составитель записи
	field::builder_t builder;
	// Записываемый секрет: длиннее короткого запаса строки, чтобы лежать в куче
	vector <uint8_t> secret(96, 0xA5);
	// Записываем число
	ASSERT_EQ(builder.number(0xDEADBEEF, 4), field::error_t::NONE);
	// Открываем поле
	ASSERT_EQ(builder.open(2), field::error_t::NONE);
	// Записываем секрет
	ASSERT_EQ(builder.bytes(view_t(secret.data(), secret.size())), field::error_t::NONE);
	// Закрываем поле
	ASSERT_EQ(builder.close(), field::error_t::NONE);
	// Просмотр составленной записи до сброса
	const view_t before = builder.data();
	// Запись составлена
	ASSERT_EQ(before.size, static_cast <size_t> (4 + 2 + secret.size()));
	// Секрет в записи лежит
	ASSERT_EQ(::memcmp(before.data + 6, secret.data(), secret.size()), 0);
	// Выполняем сброс накопителя
	builder.clear();
	// Накопитель пуст
	ASSERT_EQ(builder.pending(), static_cast <size_t> (0));
	// Снимаем отраву наблюдателя адресов с прежней области накопителя
	ANTS_FIELD_UNPOISON(before.data, before.size);
	// Число ненулевых байтов прежней области накопителя
	size_t dirty = 0;
	/**
	 * Выполняем перебор байтов прежней области накопителя
	 */
	for(size_t i = 0; i < before.size; i++)
		// Учитываем ненулевой байт
		dirty += ((before.data[i] != 0) ? 1 : 0);
	// Прежняя область накопителя затёрта целиком
	ASSERT_EQ(dirty, static_cast <size_t> (0));
	// Составитель годен к новой записи
	ASSERT_EQ(builder.bytes(view_t(secret.data(), 8)), field::error_t::NONE);
	// Новая запись составлена
	ASSERT_EQ(builder.data().size, static_cast <size_t> (8));
	// Помощник затирания вектора опустошает его
	sys::wipe(secret);
	// Вектор пуст
	ASSERT_TRUE(secret.empty());
}
