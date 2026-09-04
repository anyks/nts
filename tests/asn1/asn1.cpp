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
#include <starve.hpp>
#include <cstring>
#include <asn1/asn1.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Проверка разбора усечённых и порченых записей ASN.1
 *
 * @note Проверка эта итога разбора не судит: усечённая запись вправе и не
 *       разобраться, и разобраться в иное. Судит она лишь того, что разбор всякой
 *       области байтов обходится без отказа работы и за поданную область не
 *       выходит - ни при обходе вложений, ни при извлечении значений всякого вида
 *       из всякого элемента. Смысл её раскрывается под санитайзерами
 *
 */
TEST(Asn1Test, Ragged) {
	// Создаём записчик разбираемой записи ASN.1
	asn1::writer_t writer;
	// Открываем последовательность записи
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем целое значение последовательности
	writer.integer(static_cast <int64_t> (-123456));
	// Записываем опознаватель объекта последовательности
	writer.oid("1.2.643.7.1.1.1.1");
	// Записываем истинность последовательности
	writer.boolean(true);
	// Записываем строку последовательности
	writer.text(asn1::tag_t::UTF8_STRING, "Проверка порчи записи");
	// Открываем вложенное множество последовательности
	writer.open(asn1::tag_t::SET);
	// Записываем время вложенного множества
	writer.time(asn1::tag_t::UTC_TIME, 1787747696);
	// Записываем строку разрядов вложенного множества
	writer.bits(view_t(reinterpret_cast <const uint8_t *> ("\x01\x02\x03"), 3), 0);
	// Закрываем вложенное множество последовательности
	writer.close();
	// Закрываем последовательность записи
	writer.close();
	// Проверяем успешность сборки разбираемой записи
	ASSERT_EQ(writer.err(), asn1::error_t::NONE);
	// Получаем собранную запись ASN.1
	const view_t whole = writer.data();
	// Выполняем перенос собранной записи ASN.1
	const vector <uint8_t> origin(whole.data, whole.data + whole.size);
	// Проверяем, что собранная запись не пуста
	ASSERT_GT(origin.size(), size_t(8));
	/**
	 * Виды меток, коими пробуется извлечение значения из элемента: своя метка у
	 * элемента лишь одна, и всякая иная для извлекателя ничем не лучше порченой
	 */
	const asn1::tag_t kinds[6] = {
		asn1::tag_t::UTC_TIME, asn1::tag_t::GENERALIZED_TIME,
		asn1::tag_t::UTF8_STRING, asn1::tag_t::PRINTABLE_STRING,
		asn1::tag_t::IA5_STRING, asn1::tag_t::BMP_STRING
	};
	/**
	 * Выполняем перебор длин усечения записи ASN.1
	 */
	for(size_t size = 0; size <= origin.size(); size++){
		/**
		 * Выполняем перебор мест порчи записи: нулевой круг порчи не вносит вовсе,
		 * и им проверяется само усечение
		 */
		for(size_t place = 0; place <= size; place++){
			// Выполняем перенос усекаемой записи ASN.1
			vector <uint8_t> item(origin.begin(), origin.begin() + static_cast <ptrdiff_t> (size));
			// Если очередной байт записи портится
			if((place > 0) && (place <= item.size()))
				// Выполняем обращение всех разрядов порченого байта
				item[place - 1] = static_cast <uint8_t> (item[place - 1] ^ 0xFF);
			// Создаём разборщик порченой записи ASN.1
			asn1::reader_t reader(item.data(), item.size());
			// Разбираемый элемент записи ASN.1
			asn1::element_t element;
			/**
			 * Выполняем обход элементов порченой записи ASN.1
			 */
			while(reader.next(element)){
				// Место, в которое помещается истинность элемента
				bool truth = false;
				// Место, в которое помещается целое значение элемента
				int64_t number = 0;
				// Место, в которое помещается целое значение элемента областью байтов
				view_t digits;
				// Место, в которое помещается строка разрядов элемента
				view_t bits;
				// Число неиспользуемых разрядов последнего байта
				uint8_t unused = 0;
				// Место, в которое помещается опознаватель объекта элемента
				string object;
				/**
				 * Всякий извлекатель пробуется на всяком элементе: своего вида у
				 * элемента лишь один, и прочие извлекатели обязаны ответить отказом,
				 * а не выходом за область байтов
				 */
				(void) asn1::boolean(element, truth);
				// Выполняем извлечение целого значения элемента
				(void) asn1::integer(element, number);
				// Выполняем извлечение целого значения элемента областью байтов
				(void) asn1::integer(element, digits);
				// Выполняем извлечение строки разрядов элемента
				(void) asn1::bits(element, bits, unused);
				// Выполняем извлечение опознавателя объекта элемента
				(void) asn1::oid(element, object);
				/**
				 * Выполняем перебор видов меток извлечения значения
				 */
				for(size_t kind = 0; kind < 6; kind++){
					// Место, в которое помещается время элемента
					int64_t moment = 0;
					// Место, в которое помещается строка элемента
					string line;
					// Выполняем извлечение времени элемента
					(void) asn1::time(element, kinds[kind], moment);
					// Выполняем извлечение строки элемента
					(void) asn1::text(element, kinds[kind], line);
				}
				// Создаём разборщик вложения очередного элемента
				asn1::reader_t inner = reader.enter(element);
				// Разбираемый элемент вложения
				asn1::element_t nested;
				/**
				 * Выполняем обход элементов вложения: вложением объявляет себя всякий
				 * элемент, и разбор его содержимого обязан выдержать что угодно
				 */
				while(inner.next(nested)){
					// Место, в которое помещается опознаватель объекта вложения
					string named;
					// Выполняем извлечение опознавателя объекта вложения
					(void) asn1::oid(nested, named);
				}
			}
		}
	}
}

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

/**
 * Метод проверки отказа извлечения строки заданного набора знаков
 *
 * @param data выдержка записи строки
 * @param size длина выдержки записи строки
 * @param type вид набора знаков строки
 *
 * @return     признак отказа извлечения строки
 *
 */
static bool refused(const uint8_t * data, const size_t size, const asn1::tag_t type) noexcept {
	// Объект разобранного элемента
	asn1::element_t element;
	// Создаём разборщик записи строки
	asn1::reader_t reader(data, size);
	// Если запись строки разобрать не удалось
	if(!reader.next(type, element))
		// Выводим признак отказа извлечения строки
		return true;
	// Извлечённая строка
	std::string result;
	// Выводим признак отказа извлечения строки
	return (asn1::text(element, type, result) != asn1::error_t::NONE);
}

/**
 * Проверка отказов извлечения строк с негодными записями знаков
 */
TEST(ASN1Test, Encodings) {
	/**
	 * Длинная запись знака отвергается у ВСЯКОЙ длины записи по отдельности. Прежде
	 * проверялась лишь двухбайтовая, а заслон разбирает три длины разными половинами
	 * условия, и трёхбайтовая с четырёхбайтовой оставались нетронутыми
	 */
	const uint8_t three[] = {0x0C, 0x03, 0xE0, 0x80, 0x80};
	// Проверяем отказ извлечения строки с трёхбайтовой длинной записью знака
	ASSERT_TRUE(refused(three, sizeof(three), asn1::tag_t::UTF8_STRING));
	// Строка кодировки UTF-8 с четырёхбайтовой длинной записью знака
	const uint8_t four[] = {0x0C, 0x04, 0xF0, 0x80, 0x80, 0x80};
	// Проверяем отказ извлечения строки с четырёхбайтовой длинной записью знака
	ASSERT_TRUE(refused(four, sizeof(four), asn1::tag_t::UTF8_STRING));
	// Строка кодировки UTF-8 со знаком за пределами области Юникода
	const uint8_t beyond[] = {0x0C, 0x04, 0xF4, 0x90, 0x80, 0x80};
	// Проверяем отказ извлечения строки со знаком за пределами области Юникода
	ASSERT_TRUE(refused(beyond, sizeof(beyond), asn1::tag_t::UTF8_STRING));
	/**
	 * Кодировка UCS-2 области суррогатов не имеет: пара суррогатов это средство
	 * кодировки UTF-16, которой здесь нет
	 */
	const uint8_t paired[] = {0x1E, 0x02, 0xD8, 0x00};
	// Проверяем отказ извлечения строки UCS-2 со знаком области суррогатов
	ASSERT_TRUE(refused(paired, sizeof(paired), asn1::tag_t::BMP_STRING));
	// Строка кодировки UCS-4 со знаком области суррогатов
	const uint8_t wider[] = {0x1C, 0x04, 0x00, 0x00, 0xD8, 0x00};
	// Проверяем отказ извлечения строки UCS-4 со знаком области суррогатов
	ASSERT_TRUE(refused(wider, sizeof(wider), asn1::tag_t::UNIVERSAL_STRING));
	// Строка кодировки UCS-4 со знаком за пределами области Юникода
	const uint8_t outside[] = {0x1C, 0x04, 0x00, 0x11, 0x00, 0x00};
	// Проверяем отказ извлечения строки UCS-4 со знаком за пределами области Юникода
	ASSERT_TRUE(refused(outside, sizeof(outside), asn1::tag_t::UNIVERSAL_STRING));
	// Строка кодировки UCS-4, оборванная посреди знака
	const uint8_t clipped[] = {0x1C, 0x03, 0x00, 0x00, 0x41};
	// Проверяем отказ извлечения строки UCS-4, оборванной посреди знака
	ASSERT_TRUE(refused(clipped, sizeof(clipped), asn1::tag_t::UNIVERSAL_STRING));
	/**
	 * Длина записи знака и его значение сверяются РАЗНЫМИ половинами условия: годная
	 * трёхбайтовая запись трогает ту половину, что отвечает за значение, и обязана
	 * пройти
	 */
	const uint8_t proper[] = {0x0C, 0x03, 0xE4, 0xB8, 0x80};
	// Создаём разборщик записи строки с годной трёхбайтовой записью знака
	asn1::reader_t reader(view_t(proper, sizeof(proper)));
	// Объект разобранного элемента
	asn1::element_t element;
	// Выполняем разбор записи строки с годной трёхбайтовой записью знака
	ASSERT_TRUE(reader.next(asn1::tag_t::UTF8_STRING, element));
	// Извлечённое значение строки
	std::string result;
	// Проверяем успешность извлечения строки с годной трёхбайтовой записью знака
	ASSERT_EQ(asn1::text(element, asn1::tag_t::UTF8_STRING, result), asn1::error_t::NONE);
	// Проверяем извлечённое значение строки
	ASSERT_STREQ(result.c_str(), "\xE4\xB8\x80");
	/**
	 * Область суррогатов ограничена сверху отдельной половиной условия: знак сразу за
	 * ней принадлежит кодировке UCS-2 законно и обязан пройти
	 */
	const uint8_t adjacent[] = {0x1E, 0x02, 0xE0, 0x00};
	// Создаём разборщик записи строки UCS-2 со знаком сразу за областью суррогатов
	asn1::reader_t following(view_t(adjacent, sizeof(adjacent)));
	// Выполняем разбор записи строки UCS-2 со знаком сразу за областью суррогатов
	ASSERT_TRUE(following.next(asn1::tag_t::BMP_STRING, element));
	// Проверяем успешность извлечения строки UCS-2 со знаком за областью суррогатов
	ASSERT_EQ(asn1::text(element, asn1::tag_t::BMP_STRING, result), asn1::error_t::NONE);
	// Проверяем извлечённое значение строки в кодировке UTF-8
	ASSERT_STREQ(result.c_str(), "\xEE\x80\x80");
}

/**
 * Проверка отказов извлечения строки битов с негодной записью
 */
TEST(ASN1Test, Bitwise) {
	// Объект разобранного элемента
	asn1::element_t element;
	// Извлечённая строка битов
	view_t result;
	// Число неиспользуемых битов в последнем байте
	uint8_t unused = 0;
	// Строка битов, объявившая неиспользуемых битов больше, чем есть в байте
	const uint8_t excessive[] = {0x03, 0x02, 0x08, 0xFF};
	// Создаём разборщик записи строки битов
	asn1::reader_t first(excessive, sizeof(excessive));
	// Выполняем разбор записи строки битов
	ASSERT_TRUE(first.next(asn1::tag_t::BIT_STRING, element));
	// Проверяем отказ извлечения строки битов с непомерным числом неиспользуемых
	ASSERT_EQ(asn1::bits(element, result, unused), asn1::error_t::VALUE);
	/**
	 * Пустая строка битов неиспользуемых разрядов иметь не может: разрядов у неё нет
	 * вовсе, и объявленное их число оставлять без внимания нельзя
	 */
	const uint8_t hollow[] = {0x03, 0x01, 0x03};
	// Создаём разборщик записи пустой строки битов
	asn1::reader_t second(hollow, sizeof(hollow));
	// Выполняем разбор записи строки битов
	ASSERT_TRUE(second.next(asn1::tag_t::BIT_STRING, element));
	// Проверяем отказ извлечения пустой строки битов с объявленными неиспользуемыми
	ASSERT_EQ(asn1::bits(element, result, unused), asn1::error_t::VALUE);
	/**
	 * Кодировка DER требует, чтобы неиспользуемые разряды последнего байта были
	 * нулевыми: иначе одна и та же строка битов получает разные записи
	 */
	const uint8_t dirty[] = {0x03, 0x02, 0x03, 0xFF};
	// Создаём разборщик записи строки битов
	asn1::reader_t third(dirty, sizeof(dirty));
	// Выполняем разбор записи строки битов
	ASSERT_TRUE(third.next(asn1::tag_t::BIT_STRING, element));
	// Проверяем отказ извлечения строки битов с ненулевыми неиспользуемыми разрядами
	ASSERT_EQ(asn1::bits(element, result, unused), asn1::error_t::VALUE);
	// Пустая строка битов, не объявившая неиспользуемых разрядов
	const uint8_t empty[] = {0x03, 0x01, 0x00};
	// Создаём разборщик записи пустой строки битов
	asn1::reader_t fourth(empty, sizeof(empty));
	// Выполняем разбор записи строки битов
	ASSERT_TRUE(fourth.next(asn1::tag_t::BIT_STRING, element));
	// Проверяем успешность извлечения пустой строки битов
	ASSERT_EQ(asn1::bits(element, result, unused), asn1::error_t::NONE);
	// Проверяем нулевое число неиспользуемых разрядов пустой строки битов
	ASSERT_EQ(unused, static_cast <uint8_t> (0));
	// Проверяем пустоту извлечённой строки битов
	ASSERT_EQ(result.size, static_cast <size_t> (0));
}

/**
 * Проверка отказов записчика на негодные значения
 */
TEST(ASN1Test, WriteRefusals) {
	// Создаём записчик записи
	asn1::writer_t writer;
	/**
	 * Первые две составляющие опознавателя сводятся в одно число умножением первой
	 * на сорок, и вторая при первой, меньшей двух, сорока достигать не смеет: иначе
	 * сведённое число попало бы в чужой поддиапазон, и опознаватель разобрался бы
	 * обратно другим
	 */
	ASSERT_FALSE(writer.oid("1.40.1"));
	// Проверяем причину отказа записи опознавателя
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	// Очищаем собранную запись
	writer.clear();
	// Проверяем отказ записи опознавателя со знаком не десятичного набора
	ASSERT_FALSE(writer.oid("1.2.a"));
	// Проверяем причину отказа записи опознавателя
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	// Очищаем собранную запись
	writer.clear();
	// Проверяем отказ записи опознавателя с составляющей сверх разрядной сетки
	ASSERT_FALSE(writer.oid("1.2.99999999999999999999999"));
	// Проверяем причину отказа записи опознавателя
	ASSERT_EQ(writer.err(), asn1::error_t::HUGE_SIZE);
	// Очищаем собранную запись
	writer.clear();
	/**
	 * Составляющая записывается семёрками разрядов от старших к младшим, и число
	 * семёрок ищется поразрядным сдвигом. У числа, занявшего все шестьдесят четыре разряда, семёрок
	 * этих десять, и предел цикла поиска трогает лишь оно
	 */
	ASSERT_TRUE(writer.oid("2.5.9223372036854775808"));
	// Проверяем успешность сборки записи опознавателя
	ASSERT_EQ(writer.err(), asn1::error_t::NONE);
	// Очищаем собранную запись
	writer.clear();
	// Проверяем отказ записи времени вида, записью времени не являющегося
	ASSERT_FALSE(writer.time(asn1::tag_t::INTEGER, 0));
	// Проверяем причину отказа записи времени
	ASSERT_EQ(writer.err(), asn1::error_t::TAG);
	// Очищаем собранную запись
	writer.clear();
	/**
	 * Двузначный год записи UTCTime разбирается по правилу раздела 4.1.2.5.1 RFC 5280
	 * и потому обнимает лишь сто лет с тысяча девятьсот пятидесятого
	 */
	ASSERT_FALSE(writer.time(asn1::tag_t::UTC_TIME, -662688000));
	// Проверяем причину отказа записи времени с годом до начала обнимаемого столетия
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	// Очищаем собранную запись
	writer.clear();
	// Проверяем отказ записи времени с годом после конца обнимаемого столетия
	ASSERT_FALSE(writer.time(asn1::tag_t::UTC_TIME, 2524608000));
	// Проверяем причину отказа записи времени
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	// Очищаем собранную запись
	writer.clear();
	// Проверяем отказ записи времени с годом до начала четырёхзначной записи
	ASSERT_FALSE(writer.time(asn1::tag_t::GENERALIZED_TIME, -63000000000LL));
	// Проверяем причину отказа записи времени
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	// Очищаем собранную запись
	writer.clear();
	// Проверяем отказ записи времени с годом, в четырёхзначную запись не влезающим
	ASSERT_FALSE(writer.time(asn1::tag_t::GENERALIZED_TIME, 300000000000LL));
	// Проверяем причину отказа записи времени
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	// Очищаем собранную запись
	writer.clear();
	// Строка битов, у которой объявлено больше неиспользуемых разрядов, чем есть в байте
	const uint8_t sample[] = {0xFF, 0xF0};
	// Проверяем отказ записи строки битов с непомерным числом неиспользуемых разрядов
	ASSERT_FALSE(writer.bits(view_t(sample, sizeof(sample)), 8));
	// Проверяем причину отказа записи строки битов
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	// Очищаем собранную запись
	writer.clear();
	// Проверяем отказ записи пустой строки битов с объявленными неиспользуемыми разрядами
	ASSERT_FALSE(writer.bits(view_t(sample, 0), 3));
	// Проверяем причину отказа записи строки битов
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	// Очищаем собранную запись
	writer.clear();
	// Проверяем отказ записи строки битов с ненулевыми неиспользуемыми разрядами
	ASSERT_FALSE(writer.bits(view_t(sample, sizeof(sample)), 5));
	// Проверяем причину отказа записи строки битов
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	// Очищаем собранную запись
	writer.clear();
	// Проверяем успешность записи пустой строки битов без неиспользуемых разрядов
	ASSERT_TRUE(writer.bits(view_t(nullptr, 0), 0));
	// Проверяем успешность сборки записи пустой строки битов
	ASSERT_EQ(writer.err(), asn1::error_t::NONE);
	// Очищаем собранную запись
	writer.clear();
	/**
	 * Кодировка UCS-2 знаки за пределами основной многоязычной области не
	 * представляет, а подменять их парой суррогатов нельзя
	 */
	ASSERT_FALSE(writer.text(asn1::tag_t::BMP_STRING, "\xF0\x9F\x98\x80"));
	// Проверяем причину отказа записи строки UCS-2
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
}

/**
 * Проверка разбора записи времени на границах суток и високосного года
 */
TEST(ASN1Test, Leaping) {
	// Объект разобранного элемента
	asn1::element_t element;
	// Разобранное время
	int64_t moment = 0;
	/**
	 * Правило високосного года о ТРЁХ условиях: год, кратный четырём, високосен, но
	 * кратный ста - нет, а кратный четырёмстам - опять да. Всякое из трёх стоит своей
	 * половиной условия, и годы 2000, 1900 и 2024 трогают их по отдельности
	 */
	const uint8_t quaternary[] = {0x18, 0x0F, '2', '0', '2', '4', '0', '2', '2', '9', '0', '0', '0', '0', '0', '0', 'Z'};
	// Создаём разборщик записи времени года, кратного четырём
	asn1::reader_t first(quaternary, sizeof(quaternary));
	// Выполняем разбор записи времени
	ASSERT_TRUE(first.next(asn1::tag_t::GENERALIZED_TIME, element));
	// Проверяем успешность разбора двадцать девятого февраля года, кратного четырём
	ASSERT_EQ(asn1::time(element, asn1::tag_t::GENERALIZED_TIME, moment), asn1::error_t::NONE);
	// Запись времени двадцать девятого февраля года, кратного четырёмстам
	const uint8_t quadringentary[] = {0x18, 0x0F, '2', '0', '0', '0', '0', '2', '2', '9', '0', '0', '0', '0', '0', '0', 'Z'};
	// Создаём разборщик записи времени года, кратного четырёмстам
	asn1::reader_t second(quadringentary, sizeof(quadringentary));
	// Выполняем разбор записи времени
	ASSERT_TRUE(second.next(asn1::tag_t::GENERALIZED_TIME, element));
	// Проверяем успешность разбора двадцать девятого февраля года, кратного четырёмстам
	ASSERT_EQ(asn1::time(element, asn1::tag_t::GENERALIZED_TIME, moment), asn1::error_t::NONE);
	// Запись времени двадцать девятого февраля года, кратного ста, но не четырёмстам
	const uint8_t centenary[] = {0x18, 0x0F, '1', '9', '0', '0', '0', '2', '2', '9', '0', '0', '0', '0', '0', '0', 'Z'};
	// Создаём разборщик записи времени года, кратного ста
	asn1::reader_t third(centenary, sizeof(centenary));
	// Выполняем разбор записи времени
	ASSERT_TRUE(third.next(asn1::tag_t::GENERALIZED_TIME, element));
	// Проверяем отказ разбора двадцать девятого февраля года, кратного ста
	ASSERT_EQ(asn1::time(element, asn1::tag_t::GENERALIZED_TIME, moment), asn1::error_t::VALUE);
	/**
	 * Часы, минуты и секунды сверяются ТРЕМЯ отдельными половинами условия, и всякая
	 * отвергает запись в одиночку. Високосной секунды кодировка не знает: раздел
	 * 4.1.2.5.2 RFC 5280 велит записывать время всемирным координированным
	 */
	const uint8_t leaping[] = {0x18, 0x0F, '2', '0', '2', '4', '0', '6', '3', '0', '2', '3', '5', '9', '6', '0', 'Z'};
	// Создаём разборщик записи времени с високосной секундой
	asn1::reader_t fourth(leaping, sizeof(leaping));
	// Выполняем разбор записи времени
	ASSERT_TRUE(fourth.next(asn1::tag_t::GENERALIZED_TIME, element));
	// Проверяем отказ разбора записи времени с високосной секундой
	ASSERT_EQ(asn1::time(element, asn1::tag_t::GENERALIZED_TIME, moment), asn1::error_t::VALUE);
	// Запись времени с несуществующей минутой
	const uint8_t minute[] = {0x18, 0x0F, '2', '0', '2', '4', '0', '6', '3', '0', '2', '3', '6', '0', '0', '0', 'Z'};
	// Создаём разборщик записи времени с несуществующей минутой
	asn1::reader_t fifth(minute, sizeof(minute));
	// Выполняем разбор записи времени
	ASSERT_TRUE(fifth.next(asn1::tag_t::GENERALIZED_TIME, element));
	// Проверяем отказ разбора записи времени с несуществующей минутой
	ASSERT_EQ(asn1::time(element, asn1::tag_t::GENERALIZED_TIME, moment), asn1::error_t::VALUE);
	// Запись времени с нулевым месяцем
	const uint8_t hollow[] = {0x18, 0x0F, '2', '0', '2', '4', '0', '0', '1', '5', '0', '0', '0', '0', '0', '0', 'Z'};
	// Создаём разборщик записи времени с нулевым месяцем
	asn1::reader_t sixth(hollow, sizeof(hollow));
	// Выполняем разбор записи времени
	ASSERT_TRUE(sixth.next(asn1::tag_t::GENERALIZED_TIME, element));
	// Проверяем отказ разбора записи времени с нулевым месяцем
	ASSERT_EQ(asn1::time(element, asn1::tag_t::GENERALIZED_TIME, moment), asn1::error_t::VALUE);
	// Запись времени с нулевым днём
	const uint8_t dayless[] = {0x18, 0x0F, '2', '0', '2', '4', '0', '6', '0', '0', '0', '0', '0', '0', '0', '0', 'Z'};
	// Создаём разборщик записи времени с нулевым днём
	asn1::reader_t seventh(dayless, sizeof(dayless));
	// Выполняем разбор записи времени
	ASSERT_TRUE(seventh.next(asn1::tag_t::GENERALIZED_TIME, element));
	// Проверяем отказ разбора записи времени с нулевым днём
	ASSERT_EQ(asn1::time(element, asn1::tag_t::GENERALIZED_TIME, moment), asn1::error_t::VALUE);
}

/**
 * Проверка выдачи собранной записи записчиком, завершившим работу отказом
 */
TEST(ASN1Test, Withheld) {
	// Создаём записчик записи
	asn1::writer_t writer;
	// Записываем годное целое число
	ASSERT_TRUE(writer.integer(42));
	// Проверяем, что собранная запись выдаётся
	ASSERT_NE(writer.data().size, static_cast <size_t> (0));
	/**
	 * Записчик, завершивший работу отказом, собранного не выдаёт вовсе: выдать
	 * недописанное значило бы выдать запись, годной не являющуюся. Незакрытый
	 * составной элемент и запомненный отказ сверяются РАЗНЫМИ половинами условия
	 */
	ASSERT_FALSE(writer.oid("3.1.1"));
	// Проверяем причину отказа записи опознавателя
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	// Проверяем, что записчик после отказа собранного не выдаёт
	ASSERT_EQ(writer.data().size, static_cast <size_t> (0));
	// Очищаем собранную запись
	writer.clear();
	// Записываем годное целое число заново
	ASSERT_TRUE(writer.integer(42));
	// Проверяем, что очистка вернула записчику способность выдавать собранное
	ASSERT_NE(writer.data().size, static_cast <size_t> (0));
	// Открываем составной элемент записи
	ASSERT_TRUE(writer.open(asn1::tag_t::SEQUENCE));
	// Проверяем, что записчик с незакрытым составным элементом собранного не выдаёт
	ASSERT_EQ(writer.data().size, static_cast <size_t> (0));
	// Закрываем составной элемент записи
	ASSERT_TRUE(writer.close());
	// Проверяем, что закрытие составного элемента выдачу вернуло
	ASSERT_NE(writer.data().size, static_cast <size_t> (0));
	// Строка битов, у которой место передано, а длина объявлена нулевой
	const uint8_t sample[] = {0xFF, 0xF0};
	// Проверяем успешность записи строки битов нулевой длины с переданным местом
	ASSERT_TRUE(writer.bits(view_t(sample, 0), 0));
	// Проверяем успешность сборки записи
	ASSERT_EQ(writer.err(), asn1::error_t::NONE);
	// Очищаем собранную запись
	writer.clear();
	/**
	 * Знак записи опознавателя сверяется с ОБЕИМИ границами десятичного набора, и
	 * знак ниже нуля трогает ту половину, что стережёт нижнюю границу
	 */
	ASSERT_FALSE(writer.oid("1.2.+3"));
	// Проверяем причину отказа записи опознавателя со знаком ниже десятичного набора
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
}

/**
 * @brief Проверка отказов разбора незнаковых записей
 *
 */
TEST(ASN1Test, Unlettered) {
	/**
	 * Запись времени со знаком, десятичным не являющимся: разбор берёт из неё числа
	 * знак за знаком, и всякий незнак обязан её отвергнуть.
	 *
	 * Незнак кладётся в поле ГОДА нарочно. Поля месяца, дня, часа и прочие сличаются
	 * ещё и с дозволенной областью, и незнак в любом из них отвергла бы уже эта
	 * сверка - заслоном знака проверялся бы не тот заслон. У года же области нет:
	 * отвергнуть его способна лишь сверка самого знака
	 */
	const uint8_t lettered[] = {0x17, 0x0D, '9', 'A', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'};
	// Создаём разборщик записи времени
	asn1::reader_t reader(lettered, sizeof(lettered));
	// Объект разобранного элемента
	asn1::element_t element;
	// Число секунд от начала эпохи
	int64_t value = 0;
	// Выполняем разбор элемента записи времени
	ASSERT_TRUE(reader.next(asn1::tag_t::UTC_TIME, element));
	// Проверяем отказ извлечения времени с незнаковым знаком
	ASSERT_EQ(asn1::time(element, asn1::tag_t::UTC_TIME, value), asn1::error_t::VALUE);
	/**
	 * Строка UTF-8, первый байт знака которой выходит за пределы области Юникода:
	 * четырёхбайтовая запись дозволена лишь до 0xF4, ибо область эта кончается на
	 * U+10FFFF
	 */
	const uint8_t beyond[] = {0x0C, 0x04, 0xF5, 0x80, 0x80, 0x80};
	// Строка UTF-8, первым байтом знака несущая продолжение записи
	const uint8_t trailing[] = {0x0C, 0x02, 0x80, 0x41};
	// Строка UTF-8 с первым байтом, ни одной записи не отвечающим
	const uint8_t alien[] = {0x0C, 0x02, 0xF8, 0x41};
	// Набор строк, которые обязаны быть отвергнуты
	const view_t records[] = {
		view_t(beyond, sizeof(beyond)), view_t(trailing, sizeof(trailing)), view_t(alien, sizeof(alien))
	};
	/**
	 * Выполняем обход набора отвергаемых строк
	 */
	for(size_t i = 0; i < (sizeof(records) / sizeof(records[0])); i++){
		// Создаём разборщик строки
		asn1::reader_t item(records[i].data, records[i].size);
		// Объект разобранного элемента строки
		asn1::element_t entry;
		// Разобранная строка
		std::string result;
		// Выполняем разбор элемента строки
		ASSERT_TRUE(item.next(asn1::tag_t::UTF8_STRING, entry)) << "строка " << i;
		// Проверяем отказ извлечения строки
		ASSERT_EQ(asn1::text(entry, asn1::tag_t::UTF8_STRING, result), asn1::error_t::VALUE) << "строка " << i;
	}
	// Строка UTF-8 с записью знака предельной дозволенной области
	const uint8_t utmost[] = {0x0C, 0x04, 0xF4, 0x8F, 0xBF, 0xBF};
	// Создаём разборщик строки предельного знака
	asn1::reader_t last(utmost, sizeof(utmost));
	// Объект разобранного элемента строки
	asn1::element_t entry;
	// Разобранная строка
	std::string result;
	// Выполняем разбор элемента строки
	ASSERT_TRUE(last.next(asn1::tag_t::UTF8_STRING, entry));
	// Проверяем, что знак предельной области отвергнут не был
	ASSERT_EQ(asn1::text(entry, asn1::tag_t::UTF8_STRING, result), asn1::error_t::NONE);
}

/**
 * @brief Проверка залипания отказа записывателя
 *
 * @note Записыватель, отказавший однажды, обязан отказывать и далее: без этого
 *       недописанная запись сошла бы за дописанную, и потребитель, сверяющий отказ
 *       лишь у последнего вызова, взял бы её за годную
 *
 */
TEST(ASN1Test, Sticky){
	// Записываемая строка знаков печатного набора
	const string text = "ANYKS";
	// Объект записывателя записи ASN.1
	asn1::writer_t writer;
	// Открываем набор значений записываемой записи
	ASSERT_TRUE(writer.open(asn1::tag_t::SEQUENCE));
	/**
	 * Раздел 8.19 X.690 велит записывать опознаватель объекта составляющими,
	 * разделёнными точкою: составляющая без единого знака записи не отвечает
	 */
	ASSERT_FALSE(writer.oid("1..2"));
	// Проверяем причину отказа записи опознавателя объекта
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	/**
	 * Отказ залип: всякий дальнейший вызов обязан отказывать, не глядя на свои
	 * собственные доводы, хотя бы те и были безупречны
	 */
	ASSERT_FALSE(writer.integer(1));
	// Проверяем отказ записи строки после залипшего отказа
	ASSERT_FALSE(writer.text(asn1::tag_t::UTF8_STRING, text));
	// Проверяем отказ записи истинностного значения после залипшего отказа
	ASSERT_FALSE(writer.boolean(true));
	// Проверяем отказ записи пустого значения после залипшего отказа
	ASSERT_FALSE(writer.nothing());
	// Проверяем отказ записи строки байтов после залипшего отказа
	ASSERT_FALSE(writer.octets(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size())));
	// Проверяем отказ записи строки разрядов после залипшего отказа
	ASSERT_FALSE(writer.bits(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size())));
	// Проверяем отказ записи опознавателя объекта после залипшего отказа
	ASSERT_FALSE(writer.oid("1.2.643"));
	// Проверяем отказ открытия набора значений после залипшего отказа
	ASSERT_FALSE(writer.open(asn1::tag_t::SET));
	// Проверяем отказ закрытия набора значений после залипшего отказа
	ASSERT_FALSE(writer.close());
	// Проверяем отказ записи мига времени после залипшего отказа
	ASSERT_FALSE(writer.time(asn1::tag_t::UTC_TIME, 1800000000));
	// Проверяем неизменность причины отказа после всех дальнейших вызовов
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	/**
	 * Сброс снимает залипший отказ вместе со всем написанным: записыватель годен
	 * заново, а недописанная запись пропадает целиком
	 */
	writer.clear();
	// Проверяем снятие причины отказа сбросом записывателя
	ASSERT_EQ(writer.err(), asn1::error_t::NONE);
	// Проверяем пустоту записи после сброса записывателя
	ASSERT_EQ(writer.data().size, static_cast <size_t> (0));
	// Проверяем успешность записи опознавателя объекта после сброса
	ASSERT_TRUE(writer.oid("1.2.643.7.1.1.1.1"));
	/**
	 * Знаки, набору знаков строки не принадлежащие, записи не подлежат: раздел 8.20
	 * X.690 отводит печатному набору свой перечень знаков
	 */
	asn1::writer_t narrow;
	// Записываемая строка со знаком, печатному набору не принадлежащим
	const string alien = string("ANYKS") + string(1, '\x01');
	// Проверяем отказ записи строки печатного набора со чужеродным знаком
	ASSERT_FALSE(narrow.text(asn1::tag_t::PRINTABLE_STRING, alien));
	// Проверяем причину отказа записи строки печатного набора
	ASSERT_EQ(narrow.err(), asn1::error_t::VALUE);
	/**
	 * Набор знаков IA5 шире печатного и вмещает знаки ниже пробела, а знаки выше
	 * 0x7F ему не принадлежат
	 */
	asn1::writer_t wide;
	// Проверяем успешность записи строки IA5 со знаком ниже пробела
	ASSERT_TRUE(wide.text(asn1::tag_t::IA5_STRING, alien));
	// Записываемая строка со знаком выше набора IA5
	const string beyond = string("ANYKS") + string(1, '\x80');
	// Объект записывателя строки со знаком выше набора IA5
	asn1::writer_t outer;
	// Проверяем отказ записи строки IA5 со знаком выше набора
	ASSERT_FALSE(outer.text(asn1::tag_t::IA5_STRING, beyond));
	/**
	 * Кодировка T.61 записывается как есть: перечня дозволенных знаков у неё здесь
	 * нет, и знак всякого значения ей принадлежит
	 */
	asn1::writer_t legacy;
	// Проверяем успешность записи строки кодировки T.61 со чужеродным знаком
	ASSERT_TRUE(legacy.text(asn1::tag_t::T61_STRING, beyond));
	// Проверяем, что запись строки кодировки T.61 не пуста
	ASSERT_NE(legacy.data().size, static_cast <size_t> (0));
	/**
	 * Вид строки, записи не подлежащий, отвергается видом метки: записывать строку
	 * набором значений неверно по самому её виду
	 */
	asn1::writer_t strange;
	// Проверяем отказ записи строки неподдерживаемого вида
	ASSERT_FALSE(strange.text(asn1::tag_t::SEQUENCE, text));
	// Проверяем причину отказа записи строки неподдерживаемого вида
	ASSERT_EQ(strange.err(), asn1::error_t::TAG);
}

/**
 * @brief Проверка отказов на негодные записи знаков и длин
 *
 */
TEST(ASN1Test, Malformed){
	// Объект записывателя записи ASN.1
	asn1::writer_t writer;
	/**
	 * Раздел 8.19 X.690 велит записывать строку UTF-8 по правилам кодировки: запись
	 * знака, оборванная на своей середине, правилам не отвечает
	 */
	const string ragged = string("ANYKS") + string(1, '\xD0');
	// Проверяем отказ записи строки UTF-8 с оборванной записью знака
	ASSERT_FALSE(writer.text(asn1::tag_t::UTF8_STRING, ragged));
	// Проверяем причину отказа записи строки UTF-8
	ASSERT_EQ(writer.err(), asn1::error_t::VALUE);
	/**
	 * Строки кодировок UCS-2 и UCS-4 собираются из знаков записи UTF-8, и та же
	 * оборванная запись отвергается их сборкою
	 */
	asn1::writer_t broad;
	// Проверяем отказ записи строки UCS-2 с оборванной записью знака
	ASSERT_FALSE(broad.text(asn1::tag_t::BMP_STRING, ragged));
	// Проверяем причину отказа записи строки UCS-2
	ASSERT_EQ(broad.err(), asn1::error_t::VALUE);
	// Объект записывателя строки кодировки UCS-4
	asn1::writer_t vast;
	// Проверяем отказ записи строки UCS-4 с оборванной записью знака
	ASSERT_FALSE(vast.text(asn1::tag_t::UNIVERSAL_STRING, ragged));
	/**
	 * Раздел 8.20 X.690 отводит печатному набору свой перечень знаков, и разбор
	 * строки сверяет его наравне с записью
	 */
	const vector <uint8_t> alien = {0x13, 0x06, 0x41, 0x4E, 0x59, 0x4B, 0x53, 0x01};
	// Объект разборщика записи строки печатного набора
	asn1::Reader reader(view_t(alien.data(), alien.size()));
	// Разбираемый элемент записи строки печатного набора
	asn1::element_t element;
	// Выполняем разбор элемента записи строки печатного набора
	ASSERT_TRUE(reader.next(asn1::tag_t::PRINTABLE_STRING, element));
	// Извлечённая запись строки печатного набора
	string value;
	// Проверяем отказ извлечения строки печатного набора со чужеродным знаком
	ASSERT_EQ(asn1::text(element, asn1::tag_t::PRINTABLE_STRING, value), asn1::error_t::VALUE);
	/**
	 * Строка видимых знаков ограничена тем же перечнем, что и печатная, но сверяется
	 * своею ветвью разбора: знак ниже пробела ей не принадлежит
	 */
	const vector <uint8_t> unseen = {0x1A, 0x06, 0x41, 0x4E, 0x59, 0x4B, 0x53, 0x01};
	// Объект разборщика записи строки видимых знаков
	asn1::Reader visible(view_t(unseen.data(), unseen.size()));
	// Разбираемый элемент записи строки видимых знаков
	asn1::element_t seen;
	// Выполняем разбор элемента записи строки видимых знаков
	ASSERT_TRUE(visible.next(asn1::tag_t::VISIBLE_STRING, seen));
	// Проверяем отказ извлечения строки видимых знаков со знаком ниже пробела
	ASSERT_EQ(asn1::text(seen, asn1::tag_t::VISIBLE_STRING, value), asn1::error_t::VALUE);
	/**
	 * Раздел 8.1.3 X.690 записывает длину свыше 127 байтов долгою формою, а число
	 * байтов её ограничено разрядностью машины: длина, в неё не входящая, разбору
	 * не подлежит
	 */
	const vector <uint8_t> immense = {
		0x04, 0x89, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	};
	// Объект разборщика записи непомерной длины
	asn1::Reader huge(view_t(immense.data(), immense.size()));
	// Разбираемый элемент записи непомерной длины
	asn1::element_t item;
	// Проверяем отказ разбора элемента непомерной длины
	ASSERT_FALSE(huge.next(item));
	// Проверяем причину отказа разбора элемента непомерной длины
	ASSERT_EQ(huge.err(), asn1::error_t::HUGE_SIZE);
	/**
	 * Разборщик выдаёт размер ЕЩЁ НЕ РАЗОБРАННЫХ данных, а не длину области целиком:
	 * отказ разбора настиг разборщик за меткою и длиною, и оба этих байта числятся
	 * разобранными. Приём заведён потребителям фреймворка и внутри библиотеки не
	 * зовётся вовсе
	 */
	ASSERT_EQ(huge.size(), immense.size() - 2);
	// Объект разборщика разобранной до конца записи
	asn1::Reader spent(view_t(alien.data(), alien.size()));
	// Разбираемый элемент разобранной до конца записи
	asn1::element_t spare;
	// Выполняем разбор единственного элемента записи
	ASSERT_TRUE(spent.next(spare));
	// Проверяем нулевую длину области, разобранной до конца
	ASSERT_EQ(spent.size(), static_cast <size_t> (0));
}

/**
 * @brief Проверка залипания отказа вида у входа в простой элемент
 *
 */
TEST(Asn1Test, Primitive){
	// Простой элемент с содержимым, похожим на вложенный OID
	const uint8_t data[] = {0x04, 0x05, 0x06, 0x03, 0x2A, 0x03, 0x04};
	asn1::reader_t reader(view_t(data, sizeof(data)));
	asn1::element_t element;
	ASSERT_TRUE(reader.next(element));
	ASSERT_FALSE(element.constructed);
	/**
	 * Вход в простой элемент отдаёт разборщик с отказом вида, и первое же чтение
	 * стирать этот отказ не вправе: содержимое простого элемента вложением не является
	 */
	asn1::reader_t inner = reader.enter(element);
	ASSERT_EQ(inner.err(), asn1::error_t::FORM);
	asn1::element_t nested;
	ASSERT_FALSE(inner.next(nested));
	ASSERT_EQ(inner.err(), asn1::error_t::FORM);
}

/**
 * Проверка извлечения опознавателя объекта при нехватке памяти
 */
TEST(Asn1Test, Starved){
	// Элемент опознавателя объекта, чья запись длиннее короткого запаса строки
	const uint8_t data[] = {0x06, 0x14, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01, 0xAF, 0xD7, 0xC1, 0x7F, 0xAF, 0xD7, 0xC1, 0x7F, 0xAF, 0xD7, 0xC1, 0x7F};
	// Разборщик элемента
	asn1::Reader reader(view_t(data, sizeof(data)));
	// Разбираемый элемент
	asn1::element_t element;
	// Проверяем разбор элемента
	ASSERT_TRUE(reader.next(element));
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе извлечение обязано
	 * ответить либо успехом, либо отказом памяти, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 16; budget++){
		// Место, в которое помещается опознаватель объекта
		string object;
		// Итог извлечения при отмеренном запасе
		asn1::error_t outcome = asn1::error_t::NONE;
		{
			// Отмеряем запас выделений на время извлечения
			starve::ration_t ration(budget);
			// Выполняем извлечение опознавателя при отмеренном запасе
			outcome = asn1::oid(element, object);
		}
		// Проверяем, что извлечение ответило успехом либо отказом памяти
		ASSERT_TRUE((outcome == asn1::error_t::NONE) || (outcome == asn1::error_t::MEMORY)) << "запас " << budget;
		// Если извлечение удалось
		if(outcome == asn1::error_t::NONE){
			// Проверяем извлечённый опознаватель
			ASSERT_EQ(object, "1.2.643.7.1.1.1.1.99999999.99999999.99999999") << "запас " << budget;
		}
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == asn1::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}
