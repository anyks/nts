/**
 * @file record.cpp
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
 * @brief Исходный файл проверок модуля слоя записей протокола TLS
 *
 * @note Разбор входящих записей проверяется на нескольких размерах куска подряд: слой
 *       записей обязан вести себя одинаково и когда запись приходит целиком, и когда
 *       она приходит по одному байту
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
#include <record/record.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Метод нарезки потока байтов на записи кусками заданной длины
 *
 * @param stream разбираемый поток байтов
 * @param chunk  длина куска, которым подаётся поток байтов
 * @param result перечень собранных записей
 *
 * @return       отказ, которым завершился разбор потока байтов
 *
 */
static record::error_t assemble(const vector <uint8_t> & stream, const size_t chunk, vector <pair <record::header_t, vector <uint8_t>>> & result) noexcept {
	// Объект сборщика входящих записей
	record::reader_t reader;
	// Выполняем сброс перечня собранных записей
	result.clear();
	/**
	 * Выполняем подачу потока байтов кусками заданной длины
	 */
	for(size_t offset = 0; offset < stream.size(); offset += chunk){
		// Определяем длину очередного подаваемого куска
		const size_t size = ((stream.size() - offset) < chunk ? (stream.size() - offset) : chunk);
		// Если очередной кусок подать не удалось
		if(reader.push(view_t(stream.data() + offset, size)) != record::error_t::NONE)
			// Выводим отказ подачи куска потока байтов
			return record::error_t::MEMORY;
		// Заголовок очередной собранной записи
		record::header_t header;
		// Содержимое очередной собранной записи
		view_t payload;
		// Отказ получения очередной собранной записи
		record::error_t error = record::error_t::NONE;
		/**
		 * Выполняем выборку всех собранных на этот миг записей
		 */
		while((error = reader.next(header, payload)) == record::error_t::NONE)
			// Добавляем очередную собранную запись в перечень
			result.push_back(make_pair(header, vector <uint8_t> (payload.data, payload.data + payload.size)));
		// Если разбор завершился не нехваткой данных
		if(error != record::error_t::HUNGRY)
			// Выводим отказ, которым завершился разбор потока байтов
			return error;
	}
	// Выводим успешность разбора потока байтов
	return record::error_t::NONE;
}

/**
 * Проверка разбора и записи заголовка записи
 */
TEST(RecordTest, Header){
	// Заголовок разбираемой записи
	record::header_t header;
	// Разбираемый заголовок записи рукопожатия длиной в три байта
	const uint8_t data[] = {0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03};
	// Выполняем разбор заголовка записи
	ASSERT_EQ(record::parse(view_t(data, sizeof(data)), header), record::error_t::NONE);
	// Проверяем вид содержимого разобранной записи
	ASSERT_EQ(header.type, record::type_t::HANDSHAKE);
	// Проверяем версию протокола разобранной записи
	ASSERT_EQ(header.version, record::version_t::TLS12);
	// Проверяем длину содержимого разобранной записи
	ASSERT_EQ(header.size, static_cast <size_t> (3));
	// Место, в которое записывается заголовок записи
	uint8_t buffer[record::RECORD_HEADER];
	// Выполняем обратную запись разобранного заголовка
	ASSERT_EQ(record::build(header, buffer), record::error_t::NONE);
	// Проверяем схождение записанного заголовка с разобранным
	ASSERT_EQ(::memcmp(buffer, data, record::RECORD_HEADER), 0);
}

/**
 * Проверка отказов разбора заголовка записи
 */
TEST(RecordTest, Reject){
	// Заголовок разбираемой записи
	record::header_t header;
	// Разбираемый заголовок записи неизвестного вида содержимого
	const uint8_t type[] = {0x19, 0x03, 0x03, 0x00, 0x01};
	// Проверяем отказ разбора записи неизвестного вида содержимого
	ASSERT_EQ(record::parse(view_t(type, sizeof(type)), header), record::error_t::TYPE);
	/**
	 * Раздел 5.1 RFC 8446 велит пренебрегать изданием протокола в заголовке записи во
	 * всех отношениях: разбор его переносит, но не судит
	 */
	const uint8_t version[] = {0x16, 0x03, 0x05, 0x00, 0x01};
	// Проверяем успешность разбора записи с неизвестным изданием протокола
	ASSERT_EQ(record::parse(view_t(version, sizeof(version)), header), record::error_t::NONE);
	// Проверяем перенос издания протокола разбором без правки
	ASSERT_EQ(static_cast <uint16_t> (header.version), static_cast <uint16_t> (0x0305));
	// Разбираемый заголовок записи с изданием протокола, вовсе не назначенным
	const uint8_t unnamed[] = {0x16, 0x00, 0x00, 0x00, 0x01};
	// Проверяем успешность разбора записи с вовсе не назначенным изданием протокола
	ASSERT_EQ(record::parse(view_t(unnamed, sizeof(unnamed)), header), record::error_t::NONE);
	/**
	 * Составление записи издание протокола, напротив, судит: своя сторона пишет туда
	 * лишь то, что стандартом ей предписано
	 */
	header.type = record::type_t::HANDSHAKE;
	// Устанавливаем издание протокола, стандартом не назначенное
	header.version = static_cast <record::version_t> (0x0305);
	// Устанавливаем длину содержимого составляемой записи
	header.size = 1;
	// Место, в которое составляется заголовок записи
	uint8_t built[record::RECORD_HEADER] = {0};
	// Проверяем отказ составления записи с неизвестным изданием протокола
	ASSERT_EQ(record::build(header, built), record::error_t::VERSION);
	// Разбираемый заголовок записи длиной сверх предела протокола
	const uint8_t length[] = {0x16, 0x03, 0x03, 0xFF, 0xFF};
	// Проверяем отказ разбора записи длиной сверх предела протокола
	ASSERT_EQ(record::parse(view_t(length, sizeof(length)), header), record::error_t::LENGTH);
	// Разбираемый заголовок пустой записи рукопожатия
	const uint8_t empty[] = {0x16, 0x03, 0x03, 0x00, 0x00};
	// Проверяем отказ разбора пустой записи рукопожатия
	ASSERT_EQ(record::parse(view_t(empty, sizeof(empty)), header), record::error_t::EMPTY);
	// Разбираемый недобранный заголовок записи
	const uint8_t hungry[] = {0x16, 0x03, 0x03};
	// Проверяем отказ разбора недобранного заголовка записи
	ASSERT_EQ(record::parse(view_t(hungry, sizeof(hungry)), header), record::error_t::HUNGRY);
	// Разбираемый заголовок пустой записи прикладных данных
	const uint8_t application[] = {0x17, 0x03, 0x03, 0x00, 0x00};
	// Проверяем успешность разбора пустой записи прикладных данных
	ASSERT_EQ(record::parse(view_t(application, sizeof(application)), header), record::error_t::NONE);
	// Проверяем длину содержимого пустой записи прикладных данных
	ASSERT_EQ(header.size, static_cast <size_t> (0));
}

/**
 * Проверка независимости разбора от нарезки потока на куски
 */
TEST(RecordTest, Independence){
	// Объект нарезчика исходящих записей
	record::writer_t writer;
	// Первое нарезаемое на записи сообщение
	const uint8_t first[] = {0x01, 0x00, 0x00, 0x04, 0x0A, 0x0B, 0x0C, 0x0D};
	// Второе нарезаемое на записи сообщение
	const uint8_t second[] = {0x14, 0x00, 0x00, 0x01, 0xFF};
	// Выполняем нарезку первого сообщения на записи
	ASSERT_EQ(writer.push(record::type_t::HANDSHAKE, record::version_t::TLS12, view_t(first, sizeof(first))), record::error_t::NONE);
	// Выполняем нарезку извещения о смене набора шифрования
	ASSERT_EQ(writer.push(record::type_t::CHANGE, record::version_t::TLS12, view_t(second, 1)), record::error_t::NONE);
	// Выполняем нарезку второго сообщения на записи
	ASSERT_EQ(writer.push(record::type_t::HANDSHAKE, record::version_t::TLS13, view_t(second, sizeof(second))), record::error_t::NONE);
	// Получаем готовый поток нарезанных записей
	const view_t data = writer.data();
	// Поток байтов, подаваемый сборщику входящих записей
	const vector <uint8_t> stream(data.data, data.data + data.size);
	// Перечень записей, собранных подачей потока целиком
	vector <pair <record::header_t, vector <uint8_t>>> sample;
	// Выполняем сборку записей подачей потока целиком
	ASSERT_EQ(assemble(stream, stream.size(), sample), record::error_t::NONE);
	// Проверяем число собранных записей
	ASSERT_EQ(sample.size(), static_cast <size_t> (3));
	// Проверяем вид содержимого первой собранной записи
	ASSERT_EQ(sample[0].first.type, record::type_t::HANDSHAKE);
	// Проверяем содержимое первой собранной записи
	ASSERT_EQ(::memcmp(sample[0].second.data(), first, sizeof(first)), 0);
	// Проверяем вид содержимого второй собранной записи
	ASSERT_EQ(sample[1].first.type, record::type_t::CHANGE);
	// Проверяем версию протокола третьей собранной записи
	ASSERT_EQ(sample[2].first.version, record::version_t::TLS13);
	/**
	 * Выполняем перебор размеров куска, которым подаётся поток байтов
	 */
	for(size_t chunk = 1; chunk <= stream.size(); chunk++){
		// Перечень записей, собранных подачей потока кусками
		vector <pair <record::header_t, vector <uint8_t>>> result;
		// Выполняем сборку записей подачей потока кусками
		ASSERT_EQ(assemble(stream, chunk, result), record::error_t::NONE);
		// Проверяем схождение числа собранных записей с образцом
		ASSERT_EQ(result.size(), sample.size());
		/**
		 * Выполняем перебор собранных записей
		 */
		for(size_t i = 0; i < result.size(); i++){
			// Проверяем схождение вида содержимого записи с образцом
			ASSERT_EQ(result[i].first.type, sample[i].first.type);
			// Проверяем схождение версии протокола записи с образцом
			ASSERT_EQ(result[i].first.version, sample[i].first.version);
			// Проверяем схождение содержимого записи с образцом
			ASSERT_EQ(result[i].second, sample[i].second);
		}
	}
}

/**
 * Проверка нарезки данных на несколько записей
 */
TEST(RecordTest, Fragment){
	// Объект нарезчика исходящих записей
	record::writer_t writer;
	// Устанавливаем предел длины содержимого нарезаемой записи
	ASSERT_TRUE(writer.limit(64));
	// Проверяем отказ поднятия предела сверх дозволенного протоколом
	ASSERT_FALSE(writer.limit(record::RECORD_PLAINTEXT + 1));
	// Нарезаемые на записи данные
	vector <uint8_t> source(150, 0);
	/**
	 * Выполняем заполнение нарезаемых на записи данных
	 */
	for(size_t i = 0; i < source.size(); i++)
		// Записываем очередной байт нарезаемых данных
		source[i] = static_cast <uint8_t> (i & 0xFF);
	// Выполняем нарезку данных на записи
	ASSERT_EQ(writer.push(record::type_t::APPLICATION, record::version_t::TLS12, view_t(source.data(), source.size())), record::error_t::NONE);
	// Проверяем объём нарезанных записей: три заголовка и все данные
	ASSERT_EQ(writer.pending(), (source.size() + (3 * record::RECORD_HEADER)));
	// Получаем готовый поток нарезанных записей
	const view_t data = writer.data();
	// Поток байтов, подаваемый сборщику входящих записей
	const vector <uint8_t> stream(data.data, data.data + data.size);
	// Перечень собранных записей
	vector <pair <record::header_t, vector <uint8_t>>> result;
	// Выполняем сборку записей подачей потока кусками по семь байтов
	ASSERT_EQ(assemble(stream, 7, result), record::error_t::NONE);
	// Проверяем число собранных записей
	ASSERT_EQ(result.size(), static_cast <size_t> (3));
	// Проверяем длину содержимого первой собранной записи
	ASSERT_EQ(result[0].second.size(), static_cast <size_t> (64));
	// Проверяем длину содержимого последней собранной записи
	ASSERT_EQ(result[2].second.size(), static_cast <size_t> (22));
	// Собранные из записей данные
	vector <uint8_t> assembled;
	/**
	 * Выполняем перебор собранных записей
	 */
	for(auto & item : result)
		// Выполняем склейку содержимого очередной собранной записи
		assembled.insert(assembled.end(), item.second.begin(), item.second.end());
	// Проверяем схождение собранных данных с нарезанными
	ASSERT_EQ(assembled, source);
}

/**
 * Проверка снятия переданных байтов записей
 */
TEST(RecordTest, Consume){
	// Объект нарезчика исходящих записей
	record::writer_t writer;
	// Нарезаемое на записи сообщение
	const uint8_t source[] = {0x01, 0x02, 0x03, 0x04};
	// Выполняем нарезку сообщения на записи
	ASSERT_EQ(writer.push(record::type_t::HANDSHAKE, record::version_t::TLS12, view_t(source, sizeof(source))), record::error_t::NONE);
	// Проверяем объём нарезанных записей
	ASSERT_EQ(writer.pending(), (sizeof(source) + record::RECORD_HEADER));
	// Проверяем отказ снятия большего объёма, чем нарезано
	ASSERT_FALSE(writer.consume(writer.pending() + 1));
	// Выполняем снятие переданной части записи
	ASSERT_TRUE(writer.consume(3));
	// Проверяем объём оставшихся записей
	ASSERT_EQ(writer.pending(), (sizeof(source) + record::RECORD_HEADER - 3));
	// Получаем оставшиеся готовые записи
	const view_t data = writer.data();
	// Проверяем, что просмотр начинается с младшего байта длины содержимого
	ASSERT_EQ(data.data[0], static_cast <uint8_t> (0x00));
	// Выполняем снятие остатка записи
	ASSERT_TRUE(writer.consume(writer.pending()));
	// Проверяем опустошение накопителя нарезчика
	ASSERT_EQ(writer.pending(), static_cast <size_t> (0));
	// Проверяем пустоту просмотра опустошённого накопителя
	ASSERT_EQ(writer.data().data, nullptr);
}

/**
 * Проверка предела длины содержимого принимаемой записи
 */
TEST(RecordTest, Limit){
	// Объект сборщика входящих записей
	record::reader_t reader;
	// Проверяем предел длины содержимого записи, взятый умолчанием
	ASSERT_EQ(reader.limit(), record::RECORD_CIPHERTEXT);
	// Устанавливаем предел длины содержимого принимаемой записи
	ASSERT_TRUE(reader.limit(16));
	// Проверяем отказ установки предела сверх дозволенного протоколом
	ASSERT_FALSE(reader.limit(record::RECORD_PROTECTED + 1));
	// Проверяем отказ установки нулевого предела
	ASSERT_FALSE(reader.limit(0));
	// Разбираемая запись длиной сверх принятого связью предела
	const uint8_t source[] = {0x17, 0x03, 0x03, 0x00, 0x20};
	// Выполняем подачу заголовка разбираемой записи
	/**
	 * Пустой кусок подаётся сборщику успешностью: подать нечего, но и отказывать не
	 * за что - собеседник вправе прислать запись и по одному байту
	 */
	ASSERT_EQ(reader.push(view_t(nullptr, 0)), record::error_t::NONE);
	// Проверяем успешность подачи куска нулевой длины
	ASSERT_EQ(reader.push(view_t(source, 0)), record::error_t::NONE);
	// Выполняем подачу принятых байтов сборщику записей
	ASSERT_EQ(reader.push(view_t(source, sizeof(source))), record::error_t::NONE);
	// Заголовок собранной записи
	record::header_t header;
	// Содержимое собранной записи
	view_t payload;
	// Проверяем отказ приёма записи длиной сверх принятого связью предела
	ASSERT_EQ(reader.next(header, payload), record::error_t::LENGTH);
	// Проверяем, что отказ разбора накопитель сборщика не сбросил
	ASSERT_EQ(reader.pending(), sizeof(source));
	// Выполняем сброс состояния сборщика
	reader.clear();
	// Проверяем опустошение накопителя сборщика
	ASSERT_EQ(reader.pending(), static_cast <size_t> (0));
}

/**
 * Проверка запрета пустого содержимого у записей, пустыми быть не вправе
 */
TEST(RecordTest, Hollow){
	// Заголовок составляемой записи
	record::header_t header;
	// Устанавливаем издание протокола составляемой записи
	header.version = record::version_t::TLS12;
	// Устанавливаем нулевую длину содержимого составляемой записи
	header.size = 0;
	// Место, в которое записывается заголовок составляемой записи
	uint8_t buffer[record::RECORD_HEADER];
	/**
	 * Раздел 5.1 RFC 8446: пустой вправе быть одна лишь запись прикладных данных.
	 * Пустая запись рукопожатия либо извещения передавала бы нуль сообщений, и
	 * поток таких записей стал бы средством измотать собеседника
	 */
	header.type = record::type_t::HANDSHAKE;
	// Проверяем отказ составления пустой записи рукопожатия
	ASSERT_EQ(record::build(header, buffer), record::error_t::EMPTY);
	// Устанавливаем видом содержимого записи извещение
	header.type = record::type_t::ALERT;
	// Проверяем отказ составления пустого извещения
	ASSERT_EQ(record::build(header, buffer), record::error_t::EMPTY);
	// Устанавливаем видом содержимого записи смену набора шифрования
	header.type = record::type_t::CHANGE;
	// Проверяем отказ составления пустой записи смены набора шифрования
	ASSERT_EQ(record::build(header, buffer), record::error_t::EMPTY);
	// Устанавливаем видом содержимого записи прикладные данные
	header.type = record::type_t::APPLICATION;
	// Проверяем успешность составления пустой записи прикладных данных
	ASSERT_EQ(record::build(header, buffer), record::error_t::NONE);
	// Объект нарезчика отправляемых записей
	record::writer_t writer;
	// Проверяем отказ нарезки пустого содержимого рукопожатия
	ASSERT_EQ(writer.push(record::type_t::HANDSHAKE, record::version_t::TLS12, view_t(nullptr, 0)), record::error_t::EMPTY);
	// Проверяем отказ нарезки пустого извещения
	ASSERT_EQ(writer.push(record::type_t::ALERT, record::version_t::TLS12, view_t(buffer, 0)), record::error_t::EMPTY);
	/**
	 * Пустые прикладные данные нарезаются успешностью: раздел 5.1 RFC 8446 их
	 * дозволяет, и запись такая идёт средством скрыть поток передачи
	 */
	ASSERT_EQ(writer.push(record::type_t::APPLICATION, record::version_t::TLS12, view_t(nullptr, 0)), record::error_t::NONE);
	// Проверяем, что пустая запись прикладных данных нарезана
	ASSERT_EQ(writer.data().size, record::RECORD_HEADER);
	// Объект нарезчика с пределом длины содержимого записи
	record::writer_t limited;
	// Проверяем отказ установки нулевого предела длины содержимого
	ASSERT_FALSE(limited.limit(0));
	// Проверяем отказ установки предела сверх открытой записи протокола
	ASSERT_FALSE(limited.limit(record::RECORD_PLAINTEXT + 1));
	// Проверяем успешность установки предела длиною в открытую запись протокола
	ASSERT_TRUE(limited.limit(record::RECORD_PLAINTEXT));
}

/**
 * Проверка отказов составления заголовка и нарезки записей
 */
TEST(RecordTest, Refusals){
	// Заголовок составляемой записи
	record::header_t header;
	// Устанавливаем вид содержимого записи
	header.type = record::type_t::HANDSHAKE;
	// Устанавливаем издание протокола записи
	header.version = record::version_t::TLS12;
	// Устанавливаем длину содержимого записи
	header.size = 16;
	// Место, в которое составляется заголовок записи
	uint8_t buffer[record::RECORD_HEADER];
	// Проверяем отказ составления заголовка в непереданное место
	ASSERT_EQ(record::build(header, nullptr), record::error_t::HUNGRY);
	// Проверяем успешность составления годного заголовка
	ASSERT_EQ(record::build(header, buffer), record::error_t::NONE);
	// Устанавливаем неведомый вид содержимого записи
	header.type = record::type_t::NONE;
	// Проверяем отказ составления заголовка с неведомым видом содержимого
	ASSERT_EQ(record::build(header, buffer), record::error_t::TYPE);
	// Восстанавливаем вид содержимого записи
	header.type = record::type_t::HANDSHAKE;
	/**
	 * Раздел 5.2 RFC 8446: защищённая запись не длиннее 2^14 + 256 байтов, а
	 * составление заголовка допускает запас шифрования - но не сверх него
	 */
	header.size = (record::RECORD_PROTECTED + 1);
	// Проверяем отказ составления заголовка с непомерной длиной содержимого
	ASSERT_EQ(record::build(header, buffer), record::error_t::LENGTH);
	// Нарезчик данных на записи
	record::writer_t writer;
	// Устанавливаем предел длины содержимого нарезаемой записи
	ASSERT_TRUE(writer.limit(16));
	// Проверяем, что предел хранится нарезчиком
	ASSERT_EQ(writer.limit(), static_cast <size_t> (16));
	// Нарезаемые данные
	const uint8_t data[] = {0x01, 0x02, 0x03};
	// Проверяем отказ нарезки данных неведомого вида содержимого
	ASSERT_EQ(writer.push(record::type_t::NONE, record::version_t::TLS12, view_t(data, sizeof(data))), record::error_t::TYPE);
	// Проверяем отказ нарезки данных неустановленного издания протокола
	ASSERT_EQ(writer.push(record::type_t::HANDSHAKE, record::version_t::NONE, view_t(data, sizeof(data))), record::error_t::VERSION);
	// Проверяем, что нарезчик отказами ничего не накопил
	ASSERT_EQ(writer.pending(), static_cast <size_t> (0));
}

/**
 * @brief Метод нарезки и сборки записей при отмеренном запасе выделений
 *
 * @param source нарезаемые на записи данные
 * @param intact признак схождения собранных данных с нарезанными
 *
 * @return       отказ, которым завершился первый несостоявшийся шаг
 *
 */
static record::error_t exhaust(const vector <uint8_t> & source, bool & intact) noexcept {
	// Снимаем признак схождения собранных данных с нарезанными
	intact = false;
	// Число собранных байтов данных
	size_t count = 0;
	// Объект нарезчика исходящих записей
	record::writer_t writer;
	// Устанавливаем предел длины содержимого нарезаемой записи
	writer.limit(64);
	// Итог очередного шага
	record::error_t outcome = writer.push(record::type_t::APPLICATION, record::version_t::TLS12, view_t(source.data(), source.size()));
	// Если нарезка данных на записи не состоялась
	if(outcome != record::error_t::NONE)
		// Выводим отказ нарезки
		return outcome;
	// Получаем готовый поток нарезанных записей
	const view_t data = writer.data();
	// Объект сборщика входящих записей
	record::reader_t reader;
	/**
	 * Выполняем подачу потока записей кусками по семь байтов
	 */
	for(size_t offset = 0; offset < data.size; offset += 7){
		// Определяем длину очередного подаваемого куска
		const size_t size = ((data.size - offset) < 7 ? (data.size - offset) : 7);
		// Выполняем подачу очередного куска потока
		outcome = reader.push(view_t(data.data + offset, size));
		// Если подача куска не состоялась
		if(outcome != record::error_t::NONE)
			// Выводим отказ подачи
			return outcome;
		// Заголовок очередной собранной записи
		record::header_t header;
		// Содержимое очередной собранной записи
		view_t payload;
		/**
		 * Выполняем выборку всех собранных на этот миг записей
		 */
		while((outcome = reader.next(header, payload)) == record::error_t::NONE){
			// Если содержимое собранной записи с нарезанными данными не сходится
			if(((count + payload.size) > source.size()) || (::memcmp(payload.data, source.data() + count, payload.size) != 0))
				// Выводим успешность сборки без схождения
				return record::error_t::NONE;
			// Увеличиваем число собранных байтов данных
			count += payload.size;
		}
		// Если сборка завершилась не нехваткой данных
		if(outcome != record::error_t::HUNGRY)
			// Выводим отказ сборки
			return outcome;
	}
	// Запоминаем схождение числа собранных байтов с числом нарезанных
	intact = (count == source.size());
	// Выводим успешность нарезки и сборки
	return record::error_t::NONE;
}

/**
 * Проверка нарезки и сборки записей при нехватке памяти
 */
TEST(RecordTest, Starved){
	// Нарезаемые на записи данные
	vector <uint8_t> source(150, 0);
	/**
	 * Выполняем заполнение нарезаемых на записи данных
	 */
	for(size_t i = 0; i < source.size(); i++)
		// Записываем очередной байт нарезаемых данных
		source[i] = static_cast <uint8_t> (i & 0xFF);
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе нарезка и сборка
	 * обязаны ответить либо успехом, либо отказом памяти, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 256; budget++){
		// Итог нарезки и сборки при отмеренном запасе
		record::error_t outcome = record::error_t::NONE;
		// Признак схождения собранных данных с нарезанными
		bool intact = false;
		{
			// Отмеряем запас выделений на время нарезки и сборки
			starve::ration_t ration(budget);
			// Выполняем нарезку и сборку при отмеренном запасе
			outcome = exhaust(source, intact);
		}
		// Проверяем, что нарезка и сборка ответили успехом либо отказом памяти
		ASSERT_TRUE((outcome == record::error_t::NONE) || (outcome == record::error_t::MEMORY)) << "запас " << budget << " отказ " << static_cast <int> (outcome);
		// Проверяем, что успех не скрывает усечённых нехваткой памяти данных
		ASSERT_TRUE((outcome != record::error_t::NONE) || intact) << "запас " << budget;
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == record::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}

/**
 * @brief Метод составления записи с заголовком издания 1.2
 *
 * @param type   вид содержимого записи
 * @param body   содержимое записи
 * @param stream накопитель, в конец которого дописывается запись
 *
 */
static void framing(const uint8_t type, const std::vector <uint8_t> & body, std::vector <uint8_t> & stream) {
	stream.push_back(type);
	stream.push_back(0x03);
	stream.push_back(0x03);
	stream.push_back(static_cast <uint8_t> (body.size() >> 8));
	stream.push_back(static_cast <uint8_t> (body.size() & 0xFF));
	stream.insert(stream.end(), body.begin(), body.end());
}

/**
 * Проверка уплотнения накопителя сборщика: разобранные записи снимаются с начала, недособранная сохраняется, разобранный целиком опустошается
 */
TEST(RecordTest, Compaction){
	record::reader_t reader;
	std::vector <uint8_t> stream;
	framing(0x16, {0x01, 0x02, 0x03}, stream);
	framing(0x17, {0x04, 0x05, 0x06, 0x07}, stream);
	framing(0x15, {0x08, 0x09}, stream);
	const size_t whole = stream.size();
	record::header_t header;
	view_t payload;
	// Две целые записи и половина третьей одной подачей
	ASSERT_EQ(reader.push(view_t(stream.data(), whole - 1)), record::error_t::NONE);
	ASSERT_EQ(reader.next(header, payload), record::error_t::NONE);
	ASSERT_EQ(header.type, record::type_t::HANDSHAKE);
	ASSERT_EQ(payload.size, static_cast <size_t> (3));
	ASSERT_EQ(payload.data[0], static_cast <uint8_t> (0x01));
	ASSERT_EQ(reader.next(header, payload), record::error_t::NONE);
	ASSERT_EQ(header.type, record::type_t::APPLICATION);
	ASSERT_EQ(payload.size, static_cast <size_t> (4));
	ASSERT_EQ(reader.next(header, payload), record::error_t::HUNGRY);
	ASSERT_EQ(reader.pending(), static_cast <size_t> (record::RECORD_HEADER + 2 - 1));
	// Остаток подаётся: разобранные записи сняты с начала, недособранная сохранена и дособрана
	ASSERT_EQ(reader.push(view_t(stream.data() + whole - 1, 1)), record::error_t::NONE);
	ASSERT_EQ(reader.pending(), static_cast <size_t> (record::RECORD_HEADER + 2));
	ASSERT_EQ(reader.next(header, payload), record::error_t::NONE);
	ASSERT_EQ(header.type, record::type_t::ALERT);
	ASSERT_EQ(payload.size, static_cast <size_t> (2));
	ASSERT_EQ(payload.data[1], static_cast <uint8_t> (0x09));
	ASSERT_EQ(reader.pending(), static_cast <size_t> (0));
	// Накопитель, разобранный целиком, опустошён: новая запись читается с нуля
	ASSERT_EQ(reader.push(view_t(stream.data(), record::RECORD_HEADER + 3)), record::error_t::NONE);
	ASSERT_EQ(reader.pending(), static_cast <size_t> (record::RECORD_HEADER + 3));
	ASSERT_EQ(reader.next(header, payload), record::error_t::NONE);
	ASSERT_EQ(header.type, record::type_t::HANDSHAKE);
	ASSERT_EQ(payload.data[2], static_cast <uint8_t> (0x03));
	ASSERT_EQ(reader.pending(), static_cast <size_t> (0));
	ASSERT_EQ(reader.next(header, payload), record::error_t::HUNGRY);
}

/**
 * Проверка известности видов содержимого и допустимости пустого содержимого
 */
TEST(RecordTest, Known){
	// Известные протоколу виды содержимого записи
	ASSERT_TRUE(record::known(record::type_t::CHANGE));
	ASSERT_TRUE(record::known(record::type_t::ALERT));
	ASSERT_TRUE(record::known(record::type_t::HANDSHAKE));
	ASSERT_TRUE(record::known(record::type_t::APPLICATION));
	ASSERT_TRUE(record::known(record::type_t::HEARTBEAT));
	ASSERT_TRUE(record::known(record::type_t::ACK));
	// Неустановленный вид содержимого протоколом не определён
	ASSERT_FALSE(record::known(record::type_t::NONE));
	// Вид содержимого вне перечня протокола не определён
	ASSERT_FALSE(record::known(static_cast <record::type_t> (0x19)));
	/**
	 * Раздел 6.2.1 RFC 5246 и раздел 5.1 RFC 8446: пустыми вправе быть только
	 * записи прикладных данных
	 */
	ASSERT_TRUE(record::empty(record::type_t::APPLICATION));
	// Запись рукопожатия пустой быть не вправе
	ASSERT_FALSE(record::empty(record::type_t::HANDSHAKE));
	// Извещение пустым быть не вправе
	ASSERT_FALSE(record::empty(record::type_t::ALERT));
	// Запись смены набора шифрования пустой быть не вправе
	ASSERT_FALSE(record::empty(record::type_t::CHANGE));
	// Сердцебиение пустым быть не вправе
	ASSERT_FALSE(record::empty(record::type_t::HEARTBEAT));
	// Подтверждение принятых записей пустым быть не вправе
	ASSERT_FALSE(record::empty(record::type_t::ACK));
}
