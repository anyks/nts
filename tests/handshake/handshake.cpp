/**
 * @file handshake.cpp
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
 * @brief Исходный файл проверок модуля обвязки сообщений рукопожатия протокола TLS
 *
 * @note Сообщения переписки взяты из приложения А описания наборов шифрования TLS 1.3 на
 *       алгоритмах ГОСТ: это открытые тела записей рукопожатия того самого примера, на
 *       котором сверялась защита записей
 *
 * @note Разбор проверяется на всех размерах куска подряд: границы записей сообщениям
 *       рукопожатия не подчиняются, и разбор обязан вести себя одинаково при любой их
 *       раскладке
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <vector>
#include <cstring>
#include <main.hpp>
#include <starve.hpp>
#include <handshake/handshake.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Сообщения рукопожатия контрольного примера
 */
static const char * MESSAGES[] = {
	"080000020000",
	"0B0001510000014D000148308201443081F2A00302010202023039300A06082A85030701010302301B3119301706035504031310676F73742E6578616D706C652E636F6D301E170D3230303232383131303833375A170D3330303232353131303833375A301B3119301706035504031310676F73742E6578616D706C652E636F6D305E301706082A85030701010101300B06092A85030701020101020343000440F383CEE83048B4EB14C71A7F6DE44A37CE11A6AC1750F1CFB8DAD8A38CCDD8FD06656F7CFC075F4083C3716221478F1EE24C6B1B70CCE3C72AFD2ACE65C775BCA321301F301D0603551D0E04160414F330FA7166DF095AF3A073BC3B8EA356D7DFAC71300A06082A85030701010302034100AB2EDA23F49B48623B0CFF5906B7DD3C23B473570B296A0871DD15EF9A33201B97904A5CFA6C931C5473DC0C5A5F2FBB2E50CF587AE27C4D8E52EB80189DD08B0000",
	"0F000044070A0040A0AA13915C5B80C602E2FD85804F992C771597AD37857AD6BC2A9D7BC5FEBEC37C7294BAA23CF69D03E4710BD70813FDAC596BC158E756BD371C442E9522DE87",
	"14000020E0BAA33614E069697E4DFAB071B9725773F8FE1A326A662D0F52309B45B6E031",
	"0400003500093A8086868686080000000000000000002088888888888888888888888888888888888888888888888888888888888888880000"
};

/**
 * Виды сообщений рукопожатия контрольного примера
 */
static const handshake::type_t TYPES[] = {
	handshake::type_t::EXTENSIONS,
	handshake::type_t::CERTIFICATE,
	handshake::type_t::VERIFY,
	handshake::type_t::FINISHED,
	handshake::type_t::TICKET
};

/**
 * @brief Метод разбора строки шестнадцатеричной записи в область байтов
 *
 * @param text разбираемая строка шестнадцатеричной записи
 *
 * @return     разобранная область байтов
 *
 */
static vector <uint8_t> decode(const char * text) noexcept {
	// Разобранная область байтов
	vector <uint8_t> result;
	// Получаем длину разбираемой строки
	const size_t length = ::strlen(text);
	/**
	 * Выполняем перебор пар знаков шестнадцатеричной записи
	 */
	for(size_t i = 0; (i + 1) < length; i += 2)
		// Добавляем очередной разобранный байт
		result.push_back(static_cast <uint8_t> (::strtoul(string(text + i, 2).c_str(), nullptr, 16)));
	// Выводим разобранную область байтов
	return result;
}

/**
 * Проверка разбора и записи обвязки сообщения рукопожатия
 */
TEST(HandshakeTest, Header){
	// Обвязка разбираемого сообщения рукопожатия
	handshake::header_t header;
	// Разбираемая обвязка сообщения завершения рукопожатия
	const uint8_t data[] = {0x14, 0x00, 0x00, 0x20};
	// Выполняем разбор обвязки сообщения рукопожатия
	ASSERT_EQ(handshake::parse(view_t(data, sizeof(data)), header), handshake::error_t::NONE);
	// Проверяем вид разобранного сообщения рукопожатия
	ASSERT_EQ(header.type, handshake::type_t::FINISHED);
	// Проверяем длину тела разобранного сообщения
	ASSERT_EQ(header.size, static_cast <size_t> (32));
	// Место, в которое записывается обвязка сообщения
	uint8_t buffer[handshake::HANDSHAKE_HEADER];
	// Выполняем обратную запись разобранной обвязки
	ASSERT_EQ(handshake::build(header, buffer), handshake::error_t::NONE);
	// Проверяем схождение записанной обвязки с разобранной
	ASSERT_EQ(::memcmp(buffer, data, sizeof(data)), 0);
	// Разбираемая обвязка сообщения неизвестного вида
	const uint8_t unknown[] = {0x2A, 0x00, 0x00, 0x01};
	// Проверяем отказ разбора сообщения неизвестного вида
	ASSERT_EQ(handshake::parse(view_t(unknown, sizeof(unknown)), header), handshake::error_t::TYPE);
	// Разбираемая недобранная обвязка сообщения
	const uint8_t hungry[] = {0x14, 0x00, 0x00};
	// Проверяем отказ разбора недобранной обвязки сообщения
	ASSERT_EQ(handshake::parse(view_t(hungry, sizeof(hungry)), header), handshake::error_t::HUNGRY);
	// Проверяем отказ записи обвязки сообщения неизвестного вида
	header.type = handshake::type_t::NONE;
	// Проверяем отказ записи обвязки сообщения неизвестного вида
	ASSERT_EQ(handshake::build(header, buffer), handshake::error_t::TYPE);
}

/**
 * Проверка независимости разбора от раскладки сообщений по кускам
 */
TEST(HandshakeTest, Independence){
	// Число сообщений рукопожатия контрольного примера
	const size_t count = (sizeof(MESSAGES) / sizeof(MESSAGES[0]));
	// Переписка рукопожатия, подаваемая сборщику
	vector <uint8_t> stream;
	// Перечень сообщений рукопожатия контрольного примера
	vector <vector <uint8_t>> sample;
	/**
	 * Выполняем перебор сообщений рукопожатия контрольного примера
	 */
	for(size_t i = 0; i < count; i++){
		// Получаем очередное сообщение рукопожатия
		sample.push_back(decode(MESSAGES[i]));
		// Выполняем склейку очередного сообщения в переписку рукопожатия
		stream.insert(stream.end(), sample[i].begin(), sample[i].end());
	}
	/**
	 * Выполняем перебор размеров куска, которым подаётся переписка рукопожатия
	 */
	for(size_t chunk = 1; chunk <= stream.size(); chunk = ((chunk < 8) ? (chunk + 1) : (chunk * 3))){
		// Объект сборщика входящих сообщений рукопожатия
		handshake::reader_t reader;
		// Число уже собранных сообщений рукопожатия
		size_t index = 0;
		/**
		 * Выполняем подачу переписки рукопожатия кусками заданной длины
		 */
		for(size_t offset = 0; offset < stream.size(); offset += chunk){
			// Определяем длину очередного подаваемого куска
			const size_t size = ((stream.size() - offset) < chunk ? (stream.size() - offset) : chunk);
			// Выполняем подачу очередного куска переписки рукопожатия
			/**
			 * Пустой кусок подаётся сборщику успешностью: подать нечего, но и
			 * отказывать не за что - записи вправе приходить и порожними
			 */
			ASSERT_EQ(reader.push(view_t(nullptr, 0)), handshake::error_t::NONE) << "кусок " << chunk;
			// Выполняем подачу очередного куска сборщику сообщений
			ASSERT_EQ(reader.push(view_t(stream.data() + offset, size)), handshake::error_t::NONE) << "кусок " << chunk;
			// Обвязка очередного собранного сообщения
			handshake::header_t header;
			// Тело очередного собранного сообщения
			view_t payload;
			/**
			 * Выполняем выборку всех собранных на этот миг сообщений
			 */
			while(reader.next(header, payload) == handshake::error_t::NONE){
				// Проверяем схождение вида собранного сообщения с контрольным примером
				ASSERT_EQ(header.type, TYPES[index]) << "кусок " << chunk;
				// Проверяем схождение длины тела собранного сообщения с контрольным примером
				ASSERT_EQ(header.size, (sample[index].size() - handshake::HANDSHAKE_HEADER)) << "кусок " << chunk;
				// Получаем собранное сообщение вместе с его обвязкой
				const view_t message = reader.message();
				// Проверяем схождение длины собранного сообщения с контрольным примером
				ASSERT_EQ(message.size, sample[index].size()) << "кусок " << chunk;
				// Проверяем схождение собранного сообщения с контрольным примером
				ASSERT_EQ(::memcmp(message.data, sample[index].data(), message.size), 0) << "кусок " << chunk;
				// Увеличиваем число уже собранных сообщений
				index++;
			}
		}
		// Проверяем схождение числа собранных сообщений с контрольным примером
		ASSERT_EQ(index, count) << "кусок " << chunk;
		// Проверяем, что неразобранных данных в накопителе не осталось
		ASSERT_EQ(reader.pending(), static_cast <size_t> (0)) << "кусок " << chunk;
	}
}

/**
 * Проверка составления сообщений рукопожатия
 */
TEST(HandshakeTest, Compose){
	// Объект составителя исходящих сообщений рукопожатия
	handshake::writer_t writer;
	// Число сообщений рукопожатия контрольного примера
	const size_t count = (sizeof(MESSAGES) / sizeof(MESSAGES[0]));
	// Переписка рукопожатия контрольного примера
	vector <uint8_t> sample;
	/**
	 * Выполняем перебор сообщений рукопожатия контрольного примера
	 */
	for(size_t i = 0; i < count; i++){
		// Получаем очередное сообщение рукопожатия
		const vector <uint8_t> message = decode(MESSAGES[i]);
		// Выполняем составление очередного сообщения рукопожатия
		ASSERT_EQ(writer.push(TYPES[i], view_t(message.data() + handshake::HANDSHAKE_HEADER, message.size() - handshake::HANDSHAKE_HEADER)), handshake::error_t::NONE) << "сообщение " << i;
		// Выполняем склейку очередного сообщения в переписку рукопожатия
		sample.insert(sample.end(), message.begin(), message.end());
	}
	// Получаем составленную переписку рукопожатия
	const view_t data = writer.data();
	// Проверяем схождение длины составленной переписки с контрольным примером
	ASSERT_EQ(data.size, sample.size());
	// Проверяем схождение составленной переписки с контрольным примером
	ASSERT_EQ(::memcmp(data.data, sample.data(), data.size), 0);
	// Проверяем отказ составления сообщения неизвестного вида
	ASSERT_EQ(writer.push(handshake::type_t::NONE, view_t(sample.data(), 1)), handshake::error_t::TYPE);
	// Выполняем сброс накопителя составленных сообщений
	writer.clear();
	// Проверяем опустошение накопителя составителя
	ASSERT_EQ(writer.pending(), static_cast <size_t> (0));
	// Проверяем пустоту просмотра опустошённого накопителя
	ASSERT_EQ(writer.data().data, nullptr);
}

/**
 * Проверка предела длины тела принимаемого сообщения
 */
TEST(HandshakeTest, Limit){
	// Объект сборщика входящих сообщений рукопожатия
	handshake::reader_t reader;
	// Проверяем предел длины тела сообщения, взятый умолчанием
	ASSERT_EQ(reader.limit(), handshake::HANDSHAKE_LIMIT);
	// Проверяем отказ установки предела сверх дозволенного протоколом
	ASSERT_FALSE(reader.limit(handshake::HANDSHAKE_LIMIT + 1));
	// Проверяем отказ установки нулевого предела
	ASSERT_FALSE(reader.limit(0));
	/**
	 * Непереданное содержимое записи сборщик принимает успешностью: подать нечего, а
	 * отказывать не за что. Переданность и длина сверяются РАЗНЫМИ половинами
	 * условия, и заявленная длина при непереданном месте содержимого не даёт
	 */
	ASSERT_EQ(reader.push(view_t(nullptr, 16)), handshake::error_t::NONE);
	// Обвязка сообщения, служащая переданным местом подачи
	const uint8_t sample[] = {0x0B, 0x00, 0x00, 0x00};
	// Проверяем успешность подачи содержимого записи нулевой длины
	ASSERT_EQ(reader.push(view_t(sample, 0)), handshake::error_t::NONE);
	// Проверяем, что пропущенные подачи накопитель сборщика не наполнили
	ASSERT_EQ(reader.pending(), static_cast <size_t> (0));
	// Устанавливаем предел длины тела принимаемого сообщения
	ASSERT_TRUE(reader.limit(16));
	// Обвязка сообщения, объявившего тело сверх принятого связью предела
	const uint8_t source[] = {0x0B, 0x00, 0x01, 0x51};
	// Выполняем подачу обвязки объявленного сообщения
	ASSERT_EQ(reader.push(view_t(source, sizeof(source))), handshake::error_t::NONE);
	// Обвязка собранного сообщения
	handshake::header_t header;
	// Тело собранного сообщения
	view_t payload;
	// Проверяем отказ приёма сообщения длиной сверх принятого связью предела
	ASSERT_EQ(reader.next(header, payload), handshake::error_t::LENGTH);
	// Проверяем, что отказ разбора накопитель сборщика не сбросил
	ASSERT_EQ(reader.pending(), sizeof(source));
	// Проверяем пустоту просмотра ещё не выданного сообщения
	ASSERT_EQ(reader.message().data, nullptr);
	// Выполняем сброс состояния сборщика
	reader.clear();
	// Проверяем опустошение накопителя сборщика
	ASSERT_EQ(reader.pending(), static_cast <size_t> (0));
}

/**
 * Проверка отказов составления заголовка сообщения рукопожатия
 */
TEST(HandshakeTest, Refusals){
	// Заголовок составляемого сообщения
	handshake::header_t header;
	// Устанавливаем вид сообщения рукопожатия
	header.type = handshake::type_t::FINISHED;
	// Устанавливаем длину тела сообщения
	header.size = 32;
	// Место, в которое составляется заголовок сообщения
	uint8_t buffer[handshake::HANDSHAKE_HEADER];
	// Проверяем отказ составления заголовка в непереданное место
	ASSERT_EQ(handshake::build(header, nullptr), handshake::error_t::HUNGRY);
	/**
	 * Длина тела объявляется тремя байтами: раздел 4 RFC 8446. Тело длиннее того в
	 * заголовок не входит, и составление обязано отказать, а не усечь длину
	 */
	header.size = (handshake::HANDSHAKE_LIMIT + 1);
	// Проверяем отказ составления заголовка с непомерной длиной тела
	ASSERT_EQ(handshake::build(header, buffer), handshake::error_t::LENGTH);
	// Устанавливаем наибольшую дозволенную длину тела сообщения
	header.size = handshake::HANDSHAKE_LIMIT;
	// Проверяем успешность составления заголовка на самой границе длины
	ASSERT_EQ(handshake::build(header, buffer), handshake::error_t::NONE);
}

/**
 * @brief Метод составления и сборки сообщений рукопожатия при отмеренном запасе выделений
 *
 * @param messages сообщения рукопожатия контрольного примера вместе с обвязкой
 * @param intact   признак схождения собранных сообщений с исходными
 *
 * @return         отказ, которым завершился первый несостоявшийся шаг
 *
 */
static handshake::error_t exhaust(const vector <vector <uint8_t>> & messages, bool & intact) noexcept {
	// Снимаем признак схождения собранных сообщений с исходными
	intact = false;
	// Число собранных сообщений рукопожатия
	size_t count = 0;
	// Объект составителя исходящих сообщений рукопожатия
	handshake::writer_t writer;
	// Итог очередного шага
	handshake::error_t outcome = handshake::error_t::NONE;
	/**
	 * Выполняем перебор сообщений рукопожатия контрольного примера
	 */
	for(size_t i = 0; i < messages.size(); i++){
		// Выполняем составление очередного сообщения рукопожатия
		outcome = writer.push(TYPES[i], view_t(messages[i].data() + handshake::HANDSHAKE_HEADER, messages[i].size() - handshake::HANDSHAKE_HEADER));
		// Если составление сообщения не состоялось
		if(outcome != handshake::error_t::NONE)
			// Выводим отказ составления
			return outcome;
	}
	// Получаем составленную переписку рукопожатия
	const view_t data = writer.data();
	// Объект сборщика входящих сообщений рукопожатия
	handshake::reader_t reader;
	/**
	 * Выполняем подачу переписки рукопожатия кусками по семь байтов
	 */
	for(size_t offset = 0; offset < data.size; offset += 7){
		// Определяем длину очередного подаваемого куска
		const size_t size = ((data.size - offset) < 7 ? (data.size - offset) : 7);
		// Выполняем подачу очередного куска переписки
		outcome = reader.push(view_t(data.data + offset, size));
		// Если подача куска не состоялась
		if(outcome != handshake::error_t::NONE)
			// Выводим отказ подачи
			return outcome;
		// Обвязка очередного собранного сообщения
		handshake::header_t header;
		// Тело очередного собранного сообщения
		view_t payload;
		/**
		 * Выполняем выборку всех собранных на этот миг сообщений
		 */
		while((outcome = reader.next(header, payload)) == handshake::error_t::NONE){
			// Если собранное сообщение с исходным не сходится
			if((count >= messages.size()) || (header.type != TYPES[count]) || (payload.size != (messages[count].size() - handshake::HANDSHAKE_HEADER)) || (::memcmp(payload.data, messages[count].data() + handshake::HANDSHAKE_HEADER, payload.size) != 0))
				// Выводим успешность сборки без схождения
				return handshake::error_t::NONE;
			// Увеличиваем число собранных сообщений
			count++;
		}
		// Если сборка завершилась не нехваткой данных
		if(outcome != handshake::error_t::HUNGRY)
			// Выводим отказ сборки
			return outcome;
	}
	// Запоминаем схождение числа собранных сообщений с числом составленных
	intact = (count == messages.size());
	// Выводим успешность составления и сборки
	return handshake::error_t::NONE;
}

/**
 * Проверка составления и сборки сообщений рукопожатия при нехватке памяти
 */
TEST(HandshakeTest, Starved){
	// Сообщения рукопожатия контрольного примера вместе с обвязкой
	vector <vector <uint8_t>> messages;
	/**
	 * Выполняем перебор сообщений рукопожатия контрольного примера
	 */
	for(size_t i = 0; i < (sizeof(MESSAGES) / sizeof(MESSAGES[0])); i++)
		// Добавляем очередное разобранное сообщение рукопожатия
		messages.push_back(decode(MESSAGES[i]));
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе составление и сборка
	 * обязаны ответить либо успехом, либо отказом памяти, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 256; budget++){
		// Итог составления и сборки при отмеренном запасе
		handshake::error_t outcome = handshake::error_t::NONE;
		// Признак схождения собранных сообщений с исходными
		bool intact = false;
		{
			// Отмеряем запас выделений на время составления и сборки
			starve::ration_t ration(budget);
			// Выполняем составление и сборку при отмеренном запасе
			outcome = exhaust(messages, intact);
		}
		// Проверяем, что составление и сборка ответили успехом либо отказом памяти
		ASSERT_TRUE((outcome == handshake::error_t::NONE) || (outcome == handshake::error_t::MEMORY)) << "запас " << budget << " отказ " << static_cast <int> (outcome);
		// Проверяем, что успех не скрывает усечённой нехваткой памяти переписки
		ASSERT_TRUE((outcome != handshake::error_t::NONE) || intact) << "запас " << budget;
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == handshake::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}
