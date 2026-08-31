/**
 * @file asn1.cpp
 * @date 2026-08-26
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
 * @brief Исходный файл проверок модуля ASN.1 — разбор кодировки DER и отказ
 *        от послаблений кодировки BER
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <cstring>
#include <asn1/asn1.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Проверка разбора набора значений
 *
 */
TEST(ASN1Test, Sequence) {
	// Набор из целого числа и логического значения
	const uint8_t data[] = {0x30, 0x06, 0x02, 0x01, 0x05, 0x01, 0x01, 0xFF};
	// Создаём разборщик записи
	asn1::reader_t reader(data, sizeof(data));
	// Объект разобранного элемента
	asn1::element_t element;
	// Выполняем разбор набора значений
	ASSERT_TRUE(reader.next(asn1::tag_t::SEQUENCE, element));
	// Проверяем вид метки набора значений
	ASSERT_TRUE(element.constructed);
	// Проверяем размер содержимого набора значений
	ASSERT_EQ(element.content.size, size_t(6));
	// Проверяем размер записи набора значений целиком
	ASSERT_EQ(element.element.size, size_t(8));
	// Проверяем отсутствие данных после набора значений
	ASSERT_TRUE(reader.empty());

	// Создаём разборщик содержимого набора значений
	asn1::reader_t inner = reader.enter(element);
	// Целое число из набора значений
	int64_t number = 0;
	// Выполняем разбор целого числа
	ASSERT_TRUE(inner.next(asn1::tag_t::INTEGER, element));
	// Выполняем извлечение целого числа
	ASSERT_EQ(asn1::integer(element, number), asn1::error_t::NONE);
	// Проверяем значение целого числа
	ASSERT_EQ(number, int64_t(5));

	// Логическое значение из набора значений
	bool flag = false;
	// Выполняем разбор логического значения
	ASSERT_TRUE(inner.next(asn1::tag_t::BOOLEAN, element));
	// Выполняем извлечение логического значения
	ASSERT_EQ(asn1::boolean(element, flag), asn1::error_t::NONE);
	// Проверяем значение логического значения
	ASSERT_TRUE(flag);
	// Проверяем отсутствие данных после логического значения
	ASSERT_TRUE(inner.empty());
}
/**
 * @brief Проверка отказа от длины неопределённого вида
 *
 */
TEST(ASN1Test, IndefiniteLength) {
	// Набор значений с длиной неопределённого вида
	const uint8_t data[] = {0x30, 0x80, 0x01, 0x01, 0xFF, 0x00, 0x00};
	// Создаём разборщик записи
	asn1::reader_t reader(data, sizeof(data));
	// Объект разобранного элемента
	asn1::element_t element;
	// Проверяем отказ разбора
	ASSERT_FALSE(reader.next(element));
	// Проверяем причину отказа
	ASSERT_EQ(reader.err(), asn1::error_t::INDEFINITE);
}
/**
 * @brief Проверка отказа от длины, записанной не кратчайшим образом
 *
 */
TEST(ASN1Test, ExcessiveLength) {
	// Строка байтов с длиной, записанной длинной записью вместо короткой
	const uint8_t single[] = {0x04, 0x81, 0x01, 0x41};
	// Строка байтов с незначащим старшим байтом длины
	const uint8_t leading[] = {0x04, 0x82, 0x00, 0x01, 0x41};
	// Объект разобранного элемента
	asn1::element_t element;
	// Создаём разборщик записи с длинной записью длины
	asn1::reader_t first(single, sizeof(single));
	// Проверяем отказ разбора
	ASSERT_FALSE(first.next(element));
	// Проверяем причину отказа
	ASSERT_EQ(first.err(), asn1::error_t::EXCESSIVE);
	// Создаём разборщик записи с незначащим старшим байтом длины
	asn1::reader_t second(leading, sizeof(leading));
	// Проверяем отказ разбора
	ASSERT_FALSE(second.next(element));
	// Проверяем причину отказа
	ASSERT_EQ(second.err(), asn1::error_t::EXCESSIVE);
}
/**
 * @brief Проверка отказа от оборванных данных
 *
 */
TEST(ASN1Test, Truncated) {
	// Строка байтов, объявленная длиннее, чем записана
	const uint8_t data[] = {0x04, 0x05, 0x41, 0x42};
	// Создаём разборщик записи
	asn1::reader_t reader(data, sizeof(data));
	// Объект разобранного элемента
	asn1::element_t element;
	// Проверяем отказ разбора
	ASSERT_FALSE(reader.next(element));
	// Проверяем причину отказа
	ASSERT_EQ(reader.err(), asn1::error_t::TRUNCATED);
}
/**
 * @brief Проверка отказа от метки окончания содержимого
 *
 */
TEST(ASN1Test, EndOfContent) {
	// Метка окончания содержимого
	const uint8_t data[] = {0x00, 0x00};
	// Создаём разборщик записи
	asn1::reader_t reader(data, sizeof(data));
	// Объект разобранного элемента
	asn1::element_t element;
	// Проверяем отказ разбора
	ASSERT_FALSE(reader.next(element));
	// Проверяем причину отказа
	ASSERT_EQ(reader.err(), asn1::error_t::TAG);
}
/**
 * @brief Проверка отказа от номера метки, записанного не кратчайшим образом
 *
 */
TEST(ASN1Test, ExcessiveTag) {
	// Метка длинной записи с незначащим старшим байтом номера
	const uint8_t leading[] = {0x1F, 0x80, 0x01, 0x00};
	// Метка длинной записи там, где достаточно короткой
	const uint8_t single[] = {0x1F, 0x01, 0x00};
	// Объект разобранного элемента
	asn1::element_t element;
	// Создаём разборщик записи с незначащим старшим байтом номера
	asn1::reader_t first(leading, sizeof(leading));
	// Проверяем отказ разбора
	ASSERT_FALSE(first.next(element));
	// Проверяем причину отказа
	ASSERT_EQ(first.err(), asn1::error_t::EXCESSIVE);
	// Создаём разборщик записи с длинной записью номера метки
	asn1::reader_t second(single, sizeof(single));
	// Проверяем отказ разбора
	ASSERT_FALSE(second.next(element));
	// Проверяем причину отказа
	ASSERT_EQ(second.err(), asn1::error_t::EXCESSIVE);
}
/**
 * @brief Проверка разбора целого числа
 *
 */
TEST(ASN1Test, Integer) {
	// Целое число со знаком минус
	const uint8_t negative[] = {0x02, 0x01, 0xFF};
	// Целое число с незначащим старшим байтом
	const uint8_t excessive[] = {0x02, 0x02, 0x00, 0x05};
	// Целое число, не умещающееся в разрядную сетку
	const uint8_t huge[] = {0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	// Объект разобранного элемента
	asn1::element_t element;
	// Значение целого числа
	int64_t number = 0;
	// Создаём разборщик записи числа со знаком минус
	asn1::reader_t first(negative, sizeof(negative));
	// Выполняем разбор целого числа
	ASSERT_TRUE(first.next(asn1::tag_t::INTEGER, element));
	// Выполняем извлечение целого числа
	ASSERT_EQ(asn1::integer(element, number), asn1::error_t::NONE);
	// Проверяем значение целого числа
	ASSERT_EQ(number, int64_t(-1));
	// Создаём разборщик записи числа с незначащим старшим байтом
	asn1::reader_t second(excessive, sizeof(excessive));
	// Выполняем разбор целого числа
	ASSERT_TRUE(second.next(asn1::tag_t::INTEGER, element));
	// Проверяем отказ извлечения целого числа
	ASSERT_EQ(asn1::integer(element, number), asn1::error_t::EXCESSIVE);
	// Создаём разборщик записи числа, не умещающегося в разрядную сетку
	asn1::reader_t third(huge, sizeof(huge));
	// Выполняем разбор целого числа
	ASSERT_TRUE(third.next(asn1::tag_t::INTEGER, element));
	// Проверяем отказ извлечения целого числа
	ASSERT_EQ(asn1::integer(element, number), asn1::error_t::HUGE_SIZE);
	// Просмотр содержимого целого числа
	view_t view;
	// Выполняем извлечение содержимого целого числа
	ASSERT_EQ(asn1::integer(element, view), asn1::error_t::NONE);
	// Проверяем размер содержимого целого числа
	ASSERT_EQ(view.size, size_t(9));
}
/**
 * @brief Проверка разбора логического значения
 *
 */
TEST(ASN1Test, Boolean) {
	// Логическое значение с записью, принятой в кодировке BER
	const uint8_t data[] = {0x01, 0x01, 0x01};
	// Создаём разборщик записи
	asn1::reader_t reader(data, sizeof(data));
	// Объект разобранного элемента
	asn1::element_t element;
	// Значение логического значения
	bool flag = false;
	// Выполняем разбор логического значения
	ASSERT_TRUE(reader.next(asn1::tag_t::BOOLEAN, element));
	// Проверяем отказ извлечения логического значения
	ASSERT_EQ(asn1::boolean(element, flag), asn1::error_t::VALUE);
}
/**
 * @brief Проверка разбора строки битов
 *
 */
TEST(ASN1Test, Bits) {
	// Строка битов с обнулёнными неиспользуемыми разрядами
	const uint8_t correct[] = {0x03, 0x02, 0x03, 0xF8};
	// Строка битов с заполненными неиспользуемыми разрядами
	const uint8_t broken[] = {0x03, 0x02, 0x03, 0xFF};
	// Объект разобранного элемента
	asn1::element_t element;
	// Просмотр содержимого строки битов
	view_t view;
	// Число неиспользуемых разрядов последнего байта
	uint8_t unused = 0;
	// Создаём разборщик верной записи строки битов
	asn1::reader_t first(correct, sizeof(correct));
	// Выполняем разбор строки битов
	ASSERT_TRUE(first.next(asn1::tag_t::BIT_STRING, element));
	// Выполняем извлечение строки битов
	ASSERT_EQ(asn1::bits(element, view, unused), asn1::error_t::NONE);
	// Проверяем число неиспользуемых разрядов
	ASSERT_EQ(unused, uint8_t(3));
	// Проверяем размер содержимого строки битов
	ASSERT_EQ(view.size, size_t(1));
	// Создаём разборщик неверной записи строки битов
	asn1::reader_t second(broken, sizeof(broken));
	// Выполняем разбор строки битов
	ASSERT_TRUE(second.next(asn1::tag_t::BIT_STRING, element));
	// Проверяем отказ извлечения строки битов
	ASSERT_EQ(asn1::bits(element, view, unused), asn1::error_t::VALUE);
}
/**
 * @brief Проверка разбора опознавателя объекта
 *
 */
TEST(ASN1Test, ObjectIdentifier) {
	// Опознаватель подписи RSA с хешем SHA-256
	const uint8_t signature[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
	// Опознаватель общего имени
	const uint8_t name[] = {0x06, 0x03, 0x55, 0x04, 0x03};
	// Опознаватель с незначащим старшим байтом составляющей
	const uint8_t excessive[] = {0x06, 0x02, 0x80, 0x01};
	// Опознаватель с оборванной последней составляющей
	const uint8_t broken[] = {0x06, 0x02, 0x2A, 0x86};
	// Объект разобранного элемента
	asn1::element_t element;
	// Запись опознавателя объекта
	std::string result;
	// Создаём разборщик записи опознавателя подписи
	asn1::reader_t first(signature, sizeof(signature));
	// Выполняем разбор опознавателя объекта
	ASSERT_TRUE(first.next(asn1::tag_t::OBJECT, element));
	// Выполняем извлечение опознавателя объекта
	ASSERT_EQ(asn1::oid(element, result), asn1::error_t::NONE);
	// Проверяем запись опознавателя объекта
	ASSERT_STREQ(result.c_str(), "1.2.840.113549.1.1.11");
	// Создаём разборщик записи опознавателя общего имени
	asn1::reader_t second(name, sizeof(name));
	// Выполняем разбор опознавателя объекта
	ASSERT_TRUE(second.next(asn1::tag_t::OBJECT, element));
	// Выполняем извлечение опознавателя объекта
	ASSERT_EQ(asn1::oid(element, result), asn1::error_t::NONE);
	// Проверяем запись опознавателя объекта
	ASSERT_STREQ(result.c_str(), "2.5.4.3");
	// Создаём разборщик записи опознавателя с незначащим старшим байтом
	asn1::reader_t third(excessive, sizeof(excessive));
	// Выполняем разбор опознавателя объекта
	ASSERT_TRUE(third.next(asn1::tag_t::OBJECT, element));
	// Проверяем отказ извлечения опознавателя объекта
	ASSERT_EQ(asn1::oid(element, result), asn1::error_t::EXCESSIVE);
	// Создаём разборщик записи опознавателя с оборванной составляющей
	asn1::reader_t fourth(broken, sizeof(broken));
	// Выполняем разбор опознавателя объекта
	ASSERT_TRUE(fourth.next(asn1::tag_t::OBJECT, element));
	// Проверяем отказ извлечения опознавателя объекта
	ASSERT_EQ(asn1::oid(element, result), asn1::error_t::VALUE);
}
/**
 * @brief Проверка отказа от разбора содержимого простого элемента
 *
 */
TEST(ASN1Test, EnterPrimitive) {
	// Строка байтов, содержащая внутри себя запись набора значений
	const uint8_t data[] = {0x04, 0x03, 0x02, 0x01, 0x05};
	// Создаём разборщик записи
	asn1::reader_t reader(data, sizeof(data));
	// Объект разобранного элемента
	asn1::element_t element;
	// Выполняем разбор строки байтов
	ASSERT_TRUE(reader.next(asn1::tag_t::OCTET_STRING, element));
	// Создаём разборщик содержимого строки байтов
	asn1::reader_t inner = reader.enter(element);
	// Проверяем причину отказа
	ASSERT_EQ(inner.err(), asn1::error_t::FORM);
}
/**
 * @brief Проверка отказа от метки, отличной от ожидаемой
 *
 */
TEST(ASN1Test, UnexpectedTag) {
	// Строка байтов там, где ожидается целое число
	const uint8_t data[] = {0x04, 0x01, 0x05};
	// Создаём разборщик записи
	asn1::reader_t reader(data, sizeof(data));
	// Объект разобранного элемента
	asn1::element_t element;
	// Проверяем отказ разбора
	ASSERT_FALSE(reader.next(asn1::tag_t::INTEGER, element));
	// Проверяем причину отказа
	ASSERT_EQ(reader.err(), asn1::error_t::TAG);
}
/**
 * @brief Проверка разбора времени
 *
 */
TEST(ASN1Test, Time) {
	// Время с двузначным годом
	const uint8_t shortly[] = {0x17, 0x0D, '9', '9', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'};
	// Время с четырёхзначным годом
	const uint8_t full[] = {0x18, 0x0F, '2', '0', '2', '6', '0', '8', '2', '6', '1', '2', '3', '4', '5', '6', 'Z'};
	// Время начала промежутка, различаемого двузначным годом
	const uint8_t oldest[] = {0x17, 0x0D, '5', '0', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'};
	// Объект разобранного элемента
	asn1::element_t element;
	// Число секунд от начала эпохи
	int64_t value = 0;
	// Создаём разборщик записи времени с двузначным годом
	asn1::reader_t first(shortly, sizeof(shortly));
	// Выполняем разбор времени
	ASSERT_TRUE(first.next(asn1::tag_t::UTC_TIME, element));
	// Выполняем извлечение времени
	ASSERT_EQ(asn1::time(element, asn1::tag_t::UTC_TIME, value), asn1::error_t::NONE);
	// Проверяем значение времени
	ASSERT_EQ(value, int64_t(915148800));
	// Создаём разборщик записи времени с четырёхзначным годом
	asn1::reader_t second(full, sizeof(full));
	// Выполняем разбор времени
	ASSERT_TRUE(second.next(asn1::tag_t::GENERALIZED_TIME, element));
	// Выполняем извлечение времени
	ASSERT_EQ(asn1::time(element, asn1::tag_t::GENERALIZED_TIME, value), asn1::error_t::NONE);
	// Проверяем значение времени
	ASSERT_EQ(value, int64_t(1787747696));
	// Создаём разборщик записи времени начала промежутка
	asn1::reader_t third(oldest, sizeof(oldest));
	// Выполняем разбор времени
	ASSERT_TRUE(third.next(asn1::tag_t::UTC_TIME, element));
	// Выполняем извлечение времени
	ASSERT_EQ(asn1::time(element, asn1::tag_t::UTC_TIME, value), asn1::error_t::NONE);
	// Проверяем значение времени
	ASSERT_EQ(value, int64_t(-631152000));
}
/**
 * @brief Проверка отказа от записей времени, запрещённых кодировкой DER
 *
 */
TEST(ASN1Test, TimeStrict) {
	// Время без обозначения всемирного времени
	const uint8_t naked[] = {0x17, 0x0C, '9', '9', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0'};
	// Время со смещением часового пояса
	const uint8_t zoned[] = {0x17, 0x11, '9', '9', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', '+', '0', '3', '0', '0'};
	// Время без секунд
	const uint8_t brief[] = {0x17, 0x0B, '9', '9', '0', '1', '0', '1', '0', '0', '0', '0', 'Z'};
	// Время с долями секунды
	const uint8_t fraction[] = {0x18, 0x11, '2', '0', '2', '6', '0', '8', '2', '6', '1', '2', '3', '4', '5', '6', '.', '5', 'Z'};
	// Время с несуществующим месяцем
	const uint8_t month[] = {0x17, 0x0D, '9', '9', '1', '3', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'};
	// Время с несуществующим днём февраля
	const uint8_t day[] = {0x17, 0x0D, '9', '9', '0', '2', '2', '9', '0', '0', '0', '0', '0', '0', 'Z'};
	// Время с несуществующим часом
	const uint8_t hour[] = {0x17, 0x0D, '9', '9', '0', '1', '0', '1', '2', '4', '0', '0', '0', '0', 'Z'};
	// Набор записей времени, которые обязаны быть отвергнуты
	const view_t records[] = {
		view_t(naked, sizeof(naked)), view_t(zoned, sizeof(zoned)),
		view_t(brief, sizeof(brief)), view_t(fraction, sizeof(fraction)),
		view_t(month, sizeof(month)), view_t(day, sizeof(day)), view_t(hour, sizeof(hour))
	};
	/**
	 * Выполняем обход набора записей времени
	 */
	for(size_t i = 0; i < (sizeof(records) / sizeof(records[0])); i++){
		// Создаём разборщик записи времени
		asn1::reader_t reader(records[i].data, records[i].size);
		// Объект разобранного элемента
		asn1::element_t element;
		// Число секунд от начала эпохи
		int64_t value = 0;
		// Выполняем разбор элемента
		ASSERT_TRUE(reader.next(element)) << "запись " << i;
		// Определяем вид записи времени по метке элемента
		const asn1::tag_t type = static_cast <asn1::tag_t> (element.tag);
		// Проверяем отказ извлечения времени
		ASSERT_EQ(asn1::time(element, type, value), asn1::error_t::VALUE) << "запись " << i;
	}
	// Проверяем, что високосный год днём отвергнут не был
	const uint8_t leap[] = {0x18, 0x0F, '2', '0', '2', '4', '0', '2', '2', '9', '0', '0', '0', '0', '0', '0', 'Z'};
	// Создаём разборщик записи времени високосного года
	asn1::reader_t reader(leap, sizeof(leap));
	// Объект разобранного элемента
	asn1::element_t element;
	// Число секунд от начала эпохи
	int64_t value = 0;
	// Выполняем разбор времени
	ASSERT_TRUE(reader.next(asn1::tag_t::GENERALIZED_TIME, element));
	// Выполняем извлечение времени
	ASSERT_EQ(asn1::time(element, asn1::tag_t::GENERALIZED_TIME, value), asn1::error_t::NONE);
}
/**
 * @brief Проверка разбора строк
 *
 */
TEST(ASN1Test, Text) {
	// Строка печатного набора
	const uint8_t printable[] = {0x13, 0x09, 'a', 'n', 'y', 'k', 's', '.', 'c', 'o', 'm'};
	// Строка печатного набора со знаком не своего набора
	const uint8_t broken[] = {0x13, 0x03, 'a', '_', 'b'};
	// Строка кодировки UTF-8 с длинной записью знака
	const uint8_t overlong[] = {0x0C, 0x02, 0xC0, 0x80};
	// Строка кодировки UTF-8 со знаком области суррогатов
	const uint8_t surrogate[] = {0x0C, 0x03, 0xED, 0xA0, 0x80};
	// Строка кодировки UTF-8 с оборванной записью знака
	const uint8_t cropped[] = {0x0C, 0x02, 0xD0, 0x41};
	// Строка кодировки UCS-2 со знаками кириллицы
	const uint8_t wide[] = {0x1E, 0x04, 0x04, 0x10, 0x04, 0x11};
	// Строка кодировки UCS-2, оборванная посреди знака
	const uint8_t odd[] = {0x1E, 0x03, 0x04, 0x10, 0x04};
	// Объект разобранного элемента
	asn1::element_t element;
	// Разобранная строка
	std::string result;
	// Создаём разборщик строки печатного набора
	asn1::reader_t first(printable, sizeof(printable));
	// Выполняем разбор строки
	ASSERT_TRUE(first.next(asn1::tag_t::PRINTABLE_STRING, element));
	// Выполняем извлечение строки
	ASSERT_EQ(asn1::text(element, asn1::tag_t::PRINTABLE_STRING, result), asn1::error_t::NONE);
	// Проверяем значение строки
	ASSERT_STREQ(result.c_str(), "anyks.com");
	// Создаём разборщик строки со знаком не своего набора
	asn1::reader_t second(broken, sizeof(broken));
	// Выполняем разбор строки
	ASSERT_TRUE(second.next(asn1::tag_t::PRINTABLE_STRING, element));
	// Проверяем отказ извлечения строки
	ASSERT_EQ(asn1::text(element, asn1::tag_t::PRINTABLE_STRING, result), asn1::error_t::VALUE);
	// Набор неверных записей строк кодировки UTF-8
	const view_t records[] = {
		view_t(overlong, sizeof(overlong)), view_t(surrogate, sizeof(surrogate)), view_t(cropped, sizeof(cropped))
	};
	/**
	 * Выполняем обход набора неверных записей строк
	 */
	for(size_t i = 0; i < (sizeof(records) / sizeof(records[0])); i++){
		// Создаём разборщик записи строки
		asn1::reader_t reader(records[i].data, records[i].size);
		// Выполняем разбор строки
		ASSERT_TRUE(reader.next(asn1::tag_t::UTF8_STRING, element)) << "запись " << i;
		// Проверяем отказ извлечения строки
		ASSERT_EQ(asn1::text(element, asn1::tag_t::UTF8_STRING, result), asn1::error_t::VALUE) << "запись " << i;
	}
	// Создаём разборщик строки кодировки UCS-2
	asn1::reader_t third(wide, sizeof(wide));
	// Выполняем разбор строки
	ASSERT_TRUE(third.next(asn1::tag_t::BMP_STRING, element));
	// Выполняем извлечение строки
	ASSERT_EQ(asn1::text(element, asn1::tag_t::BMP_STRING, result), asn1::error_t::NONE);
	// Проверяем перекодировку строки в UTF-8
	ASSERT_STREQ(result.c_str(), "АБ");
	// Создаём разборщик строки, оборванной посреди знака
	asn1::reader_t fourth(odd, sizeof(odd));
	// Выполняем разбор строки
	ASSERT_TRUE(fourth.next(asn1::tag_t::BMP_STRING, element));
	// Проверяем отказ извлечения строки
	ASSERT_EQ(asn1::text(element, asn1::tag_t::BMP_STRING, result), asn1::error_t::VALUE);
}
/**
 * @brief Проверка записи набора значений
 *
 */
TEST(ASN1Test, Write) {
	// Ожидаемая запись набора из целого числа и логического значения
	const uint8_t expected[] = {0x30, 0x06, 0x02, 0x01, 0x05, 0x01, 0x01, 0xFF};
	// Создаём записчик записи
	asn1::writer_t writer;
	// Открываем набор значений
	ASSERT_TRUE(writer.open(asn1::tag_t::SEQUENCE));
	// Проверяем, что незавершённая запись наружу не отдаётся
	ASSERT_EQ(writer.data().size, size_t(0));
	// Записываем целое число
	ASSERT_TRUE(writer.integer(5));
	// Записываем логическое значение
	ASSERT_TRUE(writer.boolean(true));
	// Закрываем набор значений
	ASSERT_TRUE(writer.close());
	// Извлекаем собранную запись
	const view_t result = writer.data();
	// Проверяем размер собранной записи
	ASSERT_EQ(result.size, sizeof(expected));
	// Проверяем содержимое собранной записи
	ASSERT_EQ(memcmp(result.data, expected, sizeof(expected)), 0);
}
/**
 * @brief Проверка записи опознавателя объекта
 *
 */
TEST(ASN1Test, WriteObjectIdentifier) {
	// Ожидаемая запись опознавателя подписи RSA с хешем SHA-256
	const uint8_t expected[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
	// Создаём записчик записи
	asn1::writer_t writer;
	// Записываем опознаватель объекта
	ASSERT_TRUE(writer.oid("1.2.840.113549.1.1.11"));
	// Извлекаем собранную запись
	const view_t result = writer.data();
	// Проверяем размер собранной записи
	ASSERT_EQ(result.size, sizeof(expected));
	// Проверяем содержимое собранной записи
	ASSERT_EQ(memcmp(result.data, expected, sizeof(expected)), 0);
	// Очищаем собранную запись
	writer.clear();
	// Проверяем отказ записи опознавателя с недопустимой первой составляющей
	ASSERT_FALSE(writer.oid("3.1.1"));
	// Проверяем причину отказа
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	// Очищаем собранную запись
	writer.clear();
	// Проверяем отказ записи опознавателя из единственной составляющей
	ASSERT_FALSE(writer.oid("1"));
	// Проверяем причину отказа
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
}
/**
 * @brief Проверка отказа от непарного закрытия составных элементов
 *
 */
TEST(ASN1Test, WriteBalance) {
	// Создаём записчик записи
	asn1::writer_t writer;
	// Проверяем отказ закрытия неоткрытого составного элемента
	ASSERT_FALSE(writer.close());
	// Проверяем причину отказа
	ASSERT_EQ(writer.err(), asn1::error_t::BALANCE);
}
/**
 * @brief Проверка совпадения записи и разбора
 *
 */
TEST(ASN1Test, RoundTrip) {
	// Набор значений времени, проходящих запись и разбор
	const int64_t moments[] = {915148800, 1787747696, -631152000, 2524607999, 0};
	/**
	 * Выполняем обход набора значений времени
	 */
	for(size_t i = 0; i < (sizeof(moments) / sizeof(moments[0])); i++){
		// Создаём записчик записи
		asn1::writer_t writer;
		// Определяем вид записи времени по промежутку, различаемому двузначным годом
		const asn1::tag_t type = (((moments[i] >= -631152000) && (moments[i] <= 2524607999)) ? asn1::tag_t::UTC_TIME : asn1::tag_t::GENERALIZED_TIME);
		// Записываем время
		ASSERT_TRUE(writer.time(type, moments[i])) << "мгновение " << i;
		// Создаём разборщик собранной записи
		asn1::reader_t reader(writer.data().data, writer.data().size);
		// Объект разобранного элемента
		asn1::element_t element;
		// Число секунд от начала эпохи
		int64_t value = 0;
		// Выполняем разбор времени
		ASSERT_TRUE(reader.next(type, element)) << "мгновение " << i;
		// Выполняем извлечение времени
		ASSERT_EQ(asn1::time(element, type, value), asn1::error_t::NONE) << "мгновение " << i;
		// Проверяем совпадение записанного и разобранного значения
		ASSERT_EQ(value, moments[i]) << "мгновение " << i;
	}
	// Набор значений целых чисел, проходящих запись и разбор
	const int64_t numbers[] = {0, 1, -1, 127, 128, -128, -129, 255, 256, 65535, INT64_MAX, INT64_MIN};
	/**
	 * Выполняем обход набора значений целых чисел
	 */
	for(size_t i = 0; i < (sizeof(numbers) / sizeof(numbers[0])); i++){
		// Создаём записчик записи
		asn1::writer_t writer;
		// Записываем целое число
		ASSERT_TRUE(writer.integer(numbers[i])) << "число " << i;
		// Создаём разборщик собранной записи
		asn1::reader_t reader(writer.data().data, writer.data().size);
		// Объект разобранного элемента
		asn1::element_t element;
		// Значение целого числа
		int64_t value = 0;
		// Выполняем разбор целого числа
		ASSERT_TRUE(reader.next(asn1::tag_t::INTEGER, element)) << "число " << i;
		// Выполняем извлечение целого числа
		ASSERT_EQ(asn1::integer(element, value), asn1::error_t::NONE) << "число " << i;
		// Проверяем совпадение записанного и разобранного значения
		ASSERT_EQ(value, numbers[i]) << "число " << i;
	}
	// Набор строк, проходящих запись и разбор
	const char * strings[] = {"", "anyks.com", "Проверка кодировки", "a.b-c(d)"};
	// Набор видов строк, проходящих запись и разбор
	const asn1::tag_t types[] = {asn1::tag_t::UTF8_STRING, asn1::tag_t::BMP_STRING, asn1::tag_t::UNIVERSAL_STRING};
	/**
	 * Выполняем обход набора видов строк
	 */
	for(size_t i = 0; i < (sizeof(types) / sizeof(types[0])); i++){
		/**
		 * Выполняем обход набора строк
		 */
		for(size_t j = 0; j < (sizeof(strings) / sizeof(strings[0])); j++){
			// Создаём записчик записи
			asn1::writer_t writer;
			// Записываем строку
			ASSERT_TRUE(writer.text(types[i], strings[j])) << "строка " << i << ":" << j;
			// Создаём разборщик собранной записи
			asn1::reader_t reader(writer.data().data, writer.data().size);
			// Объект разобранного элемента
			asn1::element_t element;
			// Разобранная строка
			std::string value;
			// Выполняем разбор строки
			ASSERT_TRUE(reader.next(types[i], element)) << "строка " << i << ":" << j;
			// Выполняем извлечение строки
			ASSERT_EQ(asn1::text(element, types[i], value), asn1::error_t::NONE) << "строка " << i << ":" << j;
			// Проверяем совпадение записанной и разобранной строки
			ASSERT_STREQ(value.c_str(), strings[j]) << "строка " << i << ":" << j;
		}
	}
}
