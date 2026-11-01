/**
 * @file hello.cpp
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
 * @brief Исходный файл проверок модуля приветствий рукопожатия протокола TLS
 *
 * @note Приветствия взяты из приложения А описания наборов шифрования TLS 1.3 на
 *       алгоритмах ГОСТ целиком, вместе с обвязкой сообщения рукопожатия: два приветствия
 *       клиента, два приветствия сервера и одна просьба о повторе приветствия
 *
 * @note Всякое приветствие разбирается и составляется заново: составленное обязано
 *       сойтись с исходным байт в байт
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
#include <hello/hello.hpp>
#include <handshake/handshake.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Приветствия рукопожатия контрольного примера
 */
static const struct Sample {
	// Вид сообщения рукопожатия приветствия
	uint8_t type;
	// Сообщение приветствия вместе с обвязкой
	const char * message;
} SAMPLES[] = {
	{1, "010000DE03030303030303030303030303030303030303030303030303030303030303030303000002C105010000B3000A000400020028000D0010000E0709070A070B070C070D070E070F002B0003020304002D000201000033008600840028008005EEBDF3DDC1D2F5F3822433241284E77641487938EA88721F26203E9792B5CB97EB70EF02E8F72B7491D4F2CFDC332ADF7F1778E854A88DDC2113FEC527A15171A04CB0C573793A7AEF9BBCA486B6B046B2149B46F4332903E5B7C438ADD05E185EFBF45557475A8CCBF6ACED1A2EB416F916729D7CEF9CBD8334989304AFAE"},
	{2, "020000B60303838383838383838383838383838383838383838383838383838383838383838300C10500008E002B0002030400330084002800802F3C663FE74735A1C421160DF0F43266185FD30B6E5D6E88FC4061FAEACAB338B10A1BD20CB0B4EE757E74A0027D409FE937F01633A1E3F9A5518DEFD0F89F9D3D9F6CC651413DEC2C74366D83C47EE1DE4E421F65CD1163E94EA0C2E19ED45D35558B937D9BFDC5ECC2B2A21B4EC3D53B29579A8FD5E074811028FBCF17994F"},
	{2, "020000340303CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C00C10400000C002B00020304003300020023"},
	{1, "010000BF03030101010101010101010101010101010101010101010101010101010101010101000002C10401000094000A0006000400230028002B0003020304002D0002010100330046004400230040D35AA795C452450949591D60E7D5C076056D6646F3B80708CDC2E7034DE85F68D1122DC32A3B986D40FF910622A06C1226D9EC3A7D3A52E0A37C282C47602A430029002F000A00046550534B000000000021200BF74AA3933B7D1A66961B6E2CFB6A2804D696BB607710E3F56DDA91F56B57CB"},
	{2, "0200007C0303828282828282828282828282828282828282828282828282828282828282828200C104000054002B0002030400330044002300403D2FB067E106CC9980FB8842811164BA708BBB5038D5EDFBEE1D5E5DFBE6F74F1931217C67C2BDF46253DB9CE3487241F2DBD84E2DABDF65455851B0B19AEFEC002900020000"}
};

/**
 * @brief Функция разбора строки шестнадцатеричной записи в область байтов
 *
 * @param text разбираемая строка шестнадцатеричной записи
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
 * Проверка разбора приветствий рукопожатия
 */
TEST(HelloTest, Parse){
	/**
	 * Выполняем перебор приветствий контрольного примера
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
		// Получаем сообщение приветствия вместе с обвязкой
		const vector <uint8_t> message = decode(SAMPLES[i].message);
		// Обвязка сообщения приветствия
		handshake::header_t header;
		// Выполняем разбор обвязки сообщения приветствия
		ASSERT_EQ(handshake::parse(view_t(message.data(), message.size()), header), handshake::error_t::NONE) << "приветствие " << i;
		// Проверяем схождение вида сообщения с контрольным примером
		ASSERT_EQ(static_cast <uint8_t> (header.type), SAMPLES[i].type) << "приветствие " << i;
		// Проверяем схождение длины тела сообщения с его действительной длиной
		ASSERT_EQ(header.size, (message.size() - handshake::HANDSHAKE_HEADER)) << "приветствие " << i;
		// Получаем тело сообщения приветствия
		const view_t body(message.data() + handshake::HANDSHAKE_HEADER, header.size);
		// Если разбирается приветствие клиента
		if(header.type == handshake::type_t::CLIENT){
			// Разобранное приветствие клиента
			hello::client_t hello;
			// Выполняем разбор тела приветствия клиента
			ASSERT_EQ(hello::parse(body, hello), hello::error_t::NONE) << "приветствие " << i;
			// Проверяем версию протокола, доставшуюся от предыдущих изданий
			ASSERT_EQ(hello.version, static_cast <uint16_t> (0x0303)) << "приветствие " << i;
			// Проверяем непустоту перечня предлагаемых наборов шифрования
			ASSERT_FALSE(hello.suites.empty()) << "приветствие " << i;
			// Проверяем, что клиент предлагает единственный способ сжатия
			ASSERT_EQ(hello.methods.size(), static_cast <size_t> (1)) << "приветствие " << i;
			// Проверяем, что единственный предлагаемый способ сжатия пустой
			ASSERT_EQ(hello.methods[0], static_cast <uint8_t> (0x00)) << "приветствие " << i;
			// Проверяем, что клиент объявил поддерживаемые издания протокола
			ASSERT_NE(hello::extension(hello.extensions, 0x002B), nullptr) << "приветствие " << i;
			// Проверяем, что клиент объявил открытую часть ключа обмена
			ASSERT_NE(hello::extension(hello.extensions, 0x0033), nullptr) << "приветствие " << i;
		// Если разбирается приветствие сервера
		} else {
			// Разобранное приветствие сервера
			hello::server_t hello;
			// Выполняем разбор тела приветствия сервера
			ASSERT_EQ(hello::parse(body, hello), hello::error_t::NONE) << "приветствие " << i;
			// Проверяем версию протокола, доставшуюся от предыдущих изданий
			ASSERT_EQ(hello.version, static_cast <uint16_t> (0x0303)) << "приветствие " << i;
			// Проверяем, что сервер выбрал набор шифрования на алгоритмах ГОСТ
			ASSERT_EQ((hello.suite & 0xFF00), static_cast <uint16_t> (0xC100)) << "приветствие " << i;
			// Проверяем, что выбранный способ сжатия пустой
			ASSERT_EQ(hello.method, static_cast <uint8_t> (0x00)) << "приветствие " << i;
			// Проверяем, что сервер объявил выбранное издание протокола
			ASSERT_NE(hello::extension(hello.extensions, 0x002B), nullptr) << "приветствие " << i;
		}
	}
}

/**
 * Проверка составления приветствий рукопожатия заново
 */
TEST(HelloTest, Build){
	/**
	 * Выполняем перебор приветствий контрольного примера
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
		// Получаем сообщение приветствия вместе с обвязкой
		const vector <uint8_t> message = decode(SAMPLES[i].message);
		// Получаем тело сообщения приветствия
		const view_t body(message.data() + handshake::HANDSHAKE_HEADER, message.size() - handshake::HANDSHAKE_HEADER);
		// Накопитель, в который складывается составленное тело приветствия
		vector <uint8_t> result;
		// Если составляется приветствие клиента
		if(SAMPLES[i].type == 0x01){
			// Разобранное приветствие клиента
			hello::client_t hello;
			// Выполняем разбор тела приветствия клиента
			ASSERT_EQ(hello::parse(body, hello), hello::error_t::NONE) << "приветствие " << i;
			// Выполняем составление тела приветствия клиента заново
			ASSERT_EQ(hello::build(hello, result), hello::error_t::NONE) << "приветствие " << i;
		// Если составляется приветствие сервера
		} else {
			// Разобранное приветствие сервера
			hello::server_t hello;
			// Выполняем разбор тела приветствия сервера
			ASSERT_EQ(hello::parse(body, hello), hello::error_t::NONE) << "приветствие " << i;
			// Выполняем составление тела приветствия сервера заново
			ASSERT_EQ(hello::build(hello, result), hello::error_t::NONE) << "приветствие " << i;
		}
		// Проверяем схождение длины составленного тела с исходным
		ASSERT_EQ(result.size(), body.size) << "приветствие " << i;
		// Проверяем схождение составленного тела приветствия с исходным
		ASSERT_EQ(::memcmp(result.data(), body.data, result.size()), 0) << "приветствие " << i;
	}
}

/**
 * Проверка опознания просьбы о повторе приветствия клиента
 */
TEST(HelloTest, Retry){
	// Число просьб о повторе приветствия среди контрольных примеров
	size_t count = 0;
	/**
	 * Выполняем перебор приветствий контрольного примера
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
		// Если это приветствие клиента
		if(SAMPLES[i].type == 0x01)
			// Переходим к следующему приветствию
			continue;
		// Получаем сообщение приветствия вместе с обвязкой
		const vector <uint8_t> message = decode(SAMPLES[i].message);
		// Разобранное приветствие сервера
		hello::server_t hello;
		// Выполняем разбор тела приветствия сервера
		ASSERT_EQ(hello::parse(view_t(message.data() + handshake::HANDSHAKE_HEADER, message.size() - handshake::HANDSHAKE_HEADER), hello), hello::error_t::NONE) << "приветствие " << i;
		// Если приветствие сервера есть просьба о повторе приветствия клиента
		if(hello::retry(hello))
			// Увеличиваем число найденных просьб о повторе
			count++;
	}
	// Проверяем, что просьба о повторе приветствия среди примеров одна
	ASSERT_EQ(count, static_cast <size_t> (1));
}

/**
 * Проверка отказов разбора приветствий
 */
TEST(HelloTest, Reject){
	// Получаем приветствие клиента контрольного примера
	const vector <uint8_t> message = decode(SAMPLES[0].message);
	// Получаем тело приветствия клиента
	const vector <uint8_t> body(message.begin() + handshake::HANDSHAKE_HEADER, message.end());
	// Разобранное приветствие клиента
	hello::client_t hello;
	/**
	 * Выполняем перебор длин обрезанного тела приветствия
	 */
	/**
	 * Раздел 4.1.2 RFC 8446: обрез ровно за способами сжатия - годное приветствие
	 * прежних изданий без поля расширений, и лишь он разбором принимается
	 */
	// Смещение за заголовком: версия протокола и случайные байты
	size_t cut = 2 + hello::HELLO_RANDOM;
	// Пропускаем идентификатор сессии: длина и сам идентификатор
	cut += (1 + static_cast <size_t> (body[cut]));
	// Пропускаем наборы шифрования: длина списка и сами наборы
	cut += (2 + (static_cast <size_t> (body[cut]) << 8) + static_cast <size_t> (body[cut + 1]));
	// Пропускаем способы сжатия: длина списка и сами способы
	cut += (1 + static_cast <size_t> (body[cut]));
	/**
	 * Выполняем перебор обрезов от пустого тела до полного
	 */
	for(size_t i = 0; i < body.size(); i++){
		// Разобранное обрезанное приветствие клиента
		hello::client_t truncated;
		// Если обрез пришёлся ровно за способами сжатия
		if(i == cut){
			// Проверяем, что приветствие без поля расширений разбирается
			ASSERT_EQ(hello::parse(view_t(body.data(), i), truncated), hello::error_t::NONE) << "обрез " << i;
			// Проверяем, что расширений у него нет
			ASSERT_TRUE(truncated.extensions.empty());
			// Переходим к следующему обрезу
			continue;
		}
		// Проверяем, что обрезанное приветствие разобрано быть не может
		ASSERT_NE(hello::parse(view_t(body.data(), i), truncated), hello::error_t::NONE) << "обрез " << i;
	}
	// Тело приветствия клиента с лишним байтом на конце
	vector <uint8_t> trailing = body;
	// Дописываем лишний байт за телом приветствия
	trailing.push_back(0x00);
	// Проверяем отказ разбора приветствия с лишними байтами на конце
	ASSERT_EQ(hello::parse(view_t(trailing.data(), trailing.size()), hello), hello::error_t::TRAILING);
	// Выполняем разбор тела приветствия клиента
	ASSERT_EQ(hello::parse(view_t(body.data(), body.size()), hello), hello::error_t::NONE);
	// Получаем расширение поддерживаемых изданий протокола
	const hello::extension_t * extension = hello::extension(hello.extensions, 0x002B);
	// Проверяем, что расширение поддерживаемых изданий найдено
	ASSERT_NE(extension, nullptr);
	// Приветствие клиента с повторённым расширением
	hello::client_t repeated = hello;
	// Повторяем расширение поддерживаемых изданий в перечне расширений
	repeated.extensions.push_back(*extension);
	// Накопитель, в который складывается тело приветствия с повтором
	vector <uint8_t> composed;
	// Выполняем составление тела приветствия с повторённым расширением
	ASSERT_EQ(hello::build(repeated, composed), hello::error_t::NONE);
	// Разобранное приветствие с повторённым расширением
	hello::client_t sample;
	// Проверяем отказ разбора приветствия с повторённым расширением
	ASSERT_EQ(hello::parse(view_t(composed.data(), composed.size()), sample), hello::error_t::EXTENSION);
	// Приветствие клиента с пустым перечнем наборов шифрования
	hello::client_t empty = hello;
	// Опустошаем перечень предлагаемых наборов шифрования
	empty.suites.clear();
	// Выполняем сброс накопителя составленного тела приветствия
	composed.clear();
	// Проверяем отказ составления приветствия без наборов шифрования
	ASSERT_EQ(hello::build(empty, composed), hello::error_t::SUITE);
	/**
	 * Составитель приветствия пустого перечня наборов не выдаст, и достаётся такое
	 * приветствие только подделкой: место перечня наборов лежит за изданием протокола,
	 * случайным значением и опознавателем связи, и длина его правится прямо в записи
	 */
	vector <uint8_t> hollow = body;
	// Определяем место длины перечня наборов шифрования в теле приветствия
	const size_t place = (2 + 32 + 1 + static_cast <size_t> (body[2 + 32]));
	// Получаем длину перечня наборов шифрования подделываемого приветствия
	const size_t length = ((static_cast <size_t> (hollow[place]) << 8) | static_cast <size_t> (hollow[place + 1]));
	// Проверяем, что перечень наборов шифрования подделываемого приветствия не пуст
	ASSERT_GT(length, static_cast <size_t> (0));
	// Изымаем содержимое перечня наборов шифрования из тела приветствия
	hollow.erase((hollow.begin() + place + 2), (hollow.begin() + place + 2 + length));
	// Объявляем перечень наборов шифрования пустым
	hollow[place] = 0x00;
	// Объявляем младший байт длины перечня наборов шифрования пустым
	hollow[place + 1] = 0x00;
	// Разобранное приветствие с пустым перечнем наборов шифрования
	hello::client_t hollowed;
	// Проверяем отказ разбора приветствия с пустым перечнем наборов шифрования
	ASSERT_EQ(hello::parse(view_t(hollow.data(), hollow.size()), hollowed), hello::error_t::SUITE);
	// Тело приветствия с перечнем наборов, оборванным посреди набора
	vector <uint8_t> odd = body;
	// Изымаем один байт из содержимого перечня наборов шифрования
	odd.erase(odd.begin() + place + 2);
	// Объявляем перечень наборов шифрования короче на байт
	odd[place + 1] = static_cast <uint8_t> ((length - 1) & 0xFF);
	// Разобранное приветствие с оборванным перечнем наборов шифрования
	hello::client_t broken;
	// Проверяем отказ разбора приветствия с перечнем, оборванным посреди набора
	ASSERT_EQ(hello::parse(view_t(odd.data(), odd.size()), broken), hello::error_t::SUITE);
	// Приветствие клиента с непомерным опознавателем связи
	hello::client_t session = hello;
	// Устанавливаем опознаватель связи длиннее дозволенного
	session.session.assign(hello::HELLO_SESSION + 1, 0x00);
	// Проверяем отказ составления приветствия с непомерным опознавателем
	ASSERT_EQ(hello::build(session, composed), hello::error_t::SESSION);
}

/**
 * @brief Проверка отказов на негодные поля приветствий
 *
 * @note Тела эти собираются правкою годного приветствия: составление негодных не
 *       выдаёт, и через него подать их разбору нельзя
 *
 */
TEST(HelloTest, Deformed){
	// Получаем приветствие клиента контрольного примера
	const vector <uint8_t> message = decode(SAMPLES[0].message);
	// Получаем тело приветствия клиента
	const vector <uint8_t> body(message.begin() + handshake::HANDSHAKE_HEADER, message.end());
	// Разобранное приветствие клиента
	hello::client_t hello;
	// Выполняем разбор годного тела приветствия клиента
	ASSERT_EQ(hello::parse(view_t(body.data(), body.size()), hello), hello::error_t::NONE);
	/**
	 * Раздел 4.1.2 RFC 8446 велит клиенту объявлять единственный способ сжатия,
	 * равный нулю: пустой перечень способов сжатия правилам не отвечает. Место
	 * перечня отыскивается по длинам полей, идущих впереди него
	 */
	size_t offset = 2 + hello::HELLO_RANDOM;
	// Пропускаем опознаватель связи приветствия клиента
	offset += (1 + static_cast <size_t> (body[offset]));
	// Пропускаем перечень предлагаемых наборов шифрования
	offset += (2 + (static_cast <size_t> (body[offset]) << 8) + static_cast <size_t> (body[offset + 1]));
	// Проверяем, что перечень способов сжатия объявляет единственный способ
	ASSERT_EQ(body[offset], static_cast <uint8_t> (1));
	// Тело приветствия с пустым перечнем способов сжатия
	vector <uint8_t> methodless = body;
	// Объявляем перечень способов сжатия пустым
	methodless[offset] = 0x00;
	// Снимаем единственный способ сжатия из перечня
	methodless.erase(methodless.begin() + static_cast <ptrdiff_t> (offset) + 1);
	// Разобранное приветствие с пустым перечнем способов сжатия
	hello::client_t methodlessHello;
	// Проверяем отказ разбора приветствия с пустым перечнем способов сжатия
	ASSERT_EQ(hello::parse(view_t(methodless.data(), methodless.size()), methodlessHello), hello::error_t::METHOD);
	/**
	 * Перечень расширений, оборванный посреди вида расширения: вид объявлен двумя
	 * байтами, а за концом перечня взять их неоткуда
	 */
	vector <uint8_t> ragged = body;
	// Объявляем перечень расширений длиною в единственный байт
	ragged[offset + 2] = 0x00;
	// Ставим младший байт длины перечня расширений
	ragged[offset + 3] = 0x01;
	// Обрезаем тело приветствия по объявленной длине перечня расширений
	ragged.resize(offset + 5);
	// Разобранное приветствие с оборванным перечнем расширений
	hello::client_t raggedHello;
	// Проверяем отказ разбора приветствия с оборванным видом расширения
	ASSERT_EQ(hello::parse(view_t(ragged.data(), ragged.size()), raggedHello), hello::error_t::EXTENSION);
	/**
	 * Раздел 4.1.2 RFC 8446 отводит опознавателю связи не более 32 байтов, и
	 * составление приветствия с опознавателем длиннее того отказывает
	 */
	hello::client_t lengthy = hello;
	// Устанавливаем опознаватель связи длиннее дозволенного
	lengthy.session = vector <uint8_t> (33, 0x41);
	// Накопитель, в который складывается тело составляемого приветствия
	vector <uint8_t> composed;
	// Проверяем отказ составления приветствия с непомерным опознавателем связи
	ASSERT_EQ(hello::build(lengthy, composed), hello::error_t::SESSION);
	/**
	 * Способы сжатия объявляются при составлении наравне с разбором: приветствие
	 * без единого способа сжатия составлено быть не может
	 */
	hello::client_t bare = hello;
	// Сбрасываем перечень способов сжатия составляемого приветствия
	bare.methods.clear();
	// Проверяем отказ составления приветствия без способов сжатия
	ASSERT_EQ(hello::build(bare, composed), hello::error_t::METHOD);
	/**
	 * Ответное приветствие сервера хвоста за телом не имеет ровно так же, как и
	 * приветствие клиента: длина тела объявлена обвязкой сообщения
	 */
	hello::server_t answer;
	// Устанавливаем издание протокола ответного приветствия
	answer.version = 0x0303;
	// Устанавливаем избранный набор шифрования ответного приветствия
	answer.suite = hello.suites[0];
	// Устанавливаем способ сжатия ответного приветствия
	answer.method = 0x00;
	// Устанавливаем опознаватель связи ответного приветствия
	answer.session = hello.session;
	// Накопитель, в который складывается тело ответного приветствия
	vector <uint8_t> answered;
	// Выполняем составление тела ответного приветствия сервера
	ASSERT_EQ(hello::build(answer, answered), hello::error_t::NONE);
	// Разобранное ответное приветствие сервера
	hello::server_t taken;
	// Проверяем успешность разбора годного ответного приветствия
	ASSERT_EQ(hello::parse(view_t(answered.data(), answered.size()), taken), hello::error_t::NONE);
	// Тело ответного приветствия с лишним байтом на конце
	vector <uint8_t> trailing = answered;
	// Дописываем лишний байт за телом ответного приветствия
	trailing.push_back(0x00);
	// Проверяем отказ разбора ответного приветствия с лишним байтом на конце
	ASSERT_EQ(hello::parse(view_t(trailing.data(), trailing.size()), taken), hello::error_t::TRAILING);
	/**
	 * Перечень расширений ответного приветствия разбирается тем же разборщиком, и
	 * отказ его выносится наружу как есть
	 */
	vector <uint8_t> broken = answered;
	/**
	 * Объявляем перечень расширений длиною в единственный байт: вид расширения
	 * объявлен двумя, и взять их за концом перечня неоткуда
	 */
	broken[broken.size() - 2] = 0x00;
	// Ставим младший байт длины перечня расширений ответного приветствия
	broken[broken.size() - 1] = 0x01;
	// Дописываем единственный байт перечня расширений
	broken.push_back(0x00);
	// Проверяем отказ разбора ответного приветствия с оборванным расширением
	ASSERT_EQ(hello::parse(view_t(broken.data(), broken.size()), taken), hello::error_t::EXTENSION);
	/**
	 * Тело расширения объявляется двумя байтами, и перечень расширений - тоже:
	 * содержимое, в объявление не входящее, отвергается составлением
	 */
	hello::client_t overlong = hello;
	// Запись, длина которой не входит в объявление двух байтов
	const vector <uint8_t> couple(65536, 0x42);
	// Устанавливаем расширению приветствия непомерное тело
	overlong.extensions[0].data = view_t(couple.data(), couple.size());
	// Проверяем отказ составления приветствия с непомерным телом расширения
	ASSERT_EQ(hello::build(overlong, composed), hello::error_t::LENGTH);
	/**
	 * Перечень расширений объявляется двумя байтами целиком: два расширения, всякое
	 * из которых в своё объявление входит, вместе в него не входят
	 */
	overlong.extensions[0].data = view_t(couple.data(), couple.size() / 2);
	// Добавляем в перечень расширений второе расширение того же тела
	overlong.extensions.push_back(hello::extension_t(0x0100, view_t(couple.data(), couple.size() / 2)));
	// Проверяем отказ составления приветствия с непомерным перечнем расширений
	ASSERT_EQ(hello::build(overlong, composed), hello::error_t::LENGTH);
	/**
	 * Опознаватель связи ответного приветствия ограничен той же длиною: сервер
	 * повторяет опознаватель клиента, а тот длиннее 32 байтов быть не вправе
	 */
	hello::server_t immense = answer;
	// Устанавливаем опознаватель связи длиннее дозволенного
	immense.session = vector <uint8_t> (33, 0x41);
	// Проверяем отказ составления ответного приветствия с непомерным опознавателем
	ASSERT_EQ(hello::build(immense, answered), hello::error_t::SESSION);
}

/**
 * @brief Функция разбора и составления приветствий заново при отмеренном запасе выделений
 *
 * @param client тело приветствия клиента
 * @param server тело приветствия сервера
 * @param intact признак схождения составленных тел с исходными
 * @return       отказ, которым завершился первый несостоявшийся шаг
 *
 */
static hello::error_t exhaust(const view_t & client, const view_t & server, bool & intact) noexcept {
	// Снимаем признак схождения составленных тел с исходными
	intact = false;
	// Разобранное приветствие клиента
	hello::client_t first;
	// Разобранное приветствие сервера
	hello::server_t second;
	// Накопитель, в который складывается составленное тело приветствия
	vector <uint8_t> result;
	// Итог очередного шага
	hello::error_t outcome = hello::parse(client, first);
	// Если разбор приветствия клиента не состоялся
	if(outcome != hello::error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Выполняем составление тела приветствия клиента заново
	outcome = hello::build(first, result);
	// Если составление приветствия клиента не состоялось
	if(outcome != hello::error_t::NONE)
		// Выводим отказ составления
		return outcome;
	// Запоминаем схождение составленного тела приветствия клиента с исходным
	intact = ((result.size() == client.size) && (::memcmp(result.data(), client.data, client.size) == 0));
	// Выполняем разбор тела приветствия сервера
	outcome = hello::parse(server, second);
	// Если разбор приветствия сервера не состоялся
	if(outcome != hello::error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Выполняем сброс накопителя
	result.clear();
	// Выполняем составление тела приветствия сервера заново
	outcome = hello::build(second, result);
	// Если составление приветствия сервера не состоялось
	if(outcome != hello::error_t::NONE)
		// Выводим отказ составления
		return outcome;
	// Запоминаем схождение составленного тела приветствия сервера с исходным
	intact = (intact && (result.size() == server.size) && (::memcmp(result.data(), server.data, server.size) == 0));
	// Выводим успешность разбора и составления
	return hello::error_t::NONE;
}

/**
 * Проверка разбора и составления приветствий при нехватке памяти
 */
TEST(HelloTest, Starved){
	// Получаем сообщение приветствия клиента вместе с обвязкой
	const vector <uint8_t> client = decode(SAMPLES[0].message);
	// Получаем сообщение приветствия сервера вместе с обвязкой
	const vector <uint8_t> server = decode(SAMPLES[1].message);
	// Получаем тело приветствия клиента
	const view_t first(client.data() + handshake::HANDSHAKE_HEADER, client.size() - handshake::HANDSHAKE_HEADER);
	// Получаем тело приветствия сервера
	const view_t second(server.data() + handshake::HANDSHAKE_HEADER, server.size() - handshake::HANDSHAKE_HEADER);
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе разбор и составление
	 * обязаны ответить либо успехом, либо отказом памяти, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 256; budget++){
		// Итог разбора и составления при отмеренном запасе
		hello::error_t outcome = hello::error_t::NONE;
		// Признак схождения составленных тел с исходными
		bool intact = false;
		{
			// Отмеряем запас выделений на время разбора и составления
			starve::ration_t ration(budget);
			// Выполняем разбор и составление при отмеренном запасе
			outcome = exhaust(first, second, intact);
		}
		// Проверяем, что разбор и составление ответили успехом либо отказом памяти
		ASSERT_TRUE((outcome == hello::error_t::NONE) || (outcome == hello::error_t::MEMORY)) << "запас " << budget << " отказ " << static_cast <int> (outcome);
		// Проверяем, что успех не скрывает усечённого нехваткой памяти тела
		ASSERT_TRUE((outcome != hello::error_t::NONE) || intact) << "запас " << budget;
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == hello::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}

/**
 * Проверка приветствия клиента поверх дейтаграмм: за опознавателем связи идёт поле метки
 * возврата состояния с однобайтовой длиной (раздел 4.2.1 RFC 6347, раздел 5.3 RFC 9147) -
 * пустое поле складывается и разбирается, метка в 255 байтов повторяется дословно, метка
 * длиннее отвергается составлением, а тело поверх дейтаграмм разбором записями не признаётся
 */
TEST(HelloTest, Datagram){
	// Получаем приветствие клиента контрольного примера
	const vector <uint8_t> message = decode(SAMPLES[0].message);
	// Разобранное приветствие клиента
	hello::client_t hello;
	// Выполняем разбор тела приветствия записями
	ASSERT_EQ(hello::parse(view_t(message.data() + handshake::HANDSHAKE_HEADER, message.size() - handshake::HANDSHAKE_HEADER), hello), hello::error_t::NONE);
	// Метки у приветствия записями нет
	ASSERT_TRUE(hello.cookie.empty());
	// Накопитель тела поверх дейтаграмм
	vector <uint8_t> datagram;
	// Выполняем составление тела поверх дейтаграмм с пустой меткой
	ASSERT_EQ(hello::build(hello, datagram, true), hello::error_t::NONE);
	// Накопитель тела записями
	vector <uint8_t> stream;
	// Выполняем составление тела записями
	ASSERT_EQ(hello::build(hello, stream), hello::error_t::NONE);
	// Тело поверх дейтаграмм длиннее на байт длины пустой метки
	ASSERT_EQ(datagram.size(), stream.size() + 1);
	// Байт длины метки лежит за опознавателем связи и равен нулю
	ASSERT_EQ(datagram[2 + hello::HELLO_RANDOM + 1 + hello.session.size()], 0);
	// Разобранное приветствие поверх дейтаграмм
	hello::client_t parsed;
	// Выполняем разбор тела поверх дейтаграмм
	ASSERT_EQ(hello::parse(view_t(datagram.data(), datagram.size()), parsed, true), hello::error_t::NONE);
	// Метка пуста
	ASSERT_TRUE(parsed.cookie.empty());
	// Наборы сошлись
	ASSERT_EQ(parsed.suites, hello.suites);
	// Расширения сошлись числом
	ASSERT_EQ(parsed.extensions.size(), hello.extensions.size());
	// Тело поверх дейтаграмм разбором записями не признаётся: байт метки сдвигает наборы
	ASSERT_NE(hello::parse(view_t(datagram.data(), datagram.size()), parsed), hello::error_t::NONE);
	// Метка наибольшей длины
	hello.cookie.assign(hello::HELLO_COOKIE, 0xA5);
	// Выполняем сброс накопителя
	datagram.clear();
	// Выполняем составление тела с меткой наибольшей длины
	ASSERT_EQ(hello::build(hello, datagram, true), hello::error_t::NONE);
	// Выполняем разбор тела с меткой
	ASSERT_EQ(hello::parse(view_t(datagram.data(), datagram.size()), parsed, true), hello::error_t::NONE);
	// Метка повторена дословно
	ASSERT_EQ(parsed.cookie, hello.cookie);
	// Метка длиннее дозволенной
	hello.cookie.assign(hello::HELLO_COOKIE + 1, 0xA5);
	// Проверяем отказ составления
	ASSERT_EQ(hello::build(hello, datagram, true), hello::error_t::COOKIE);
	// Записями метка не пишется вовсе: составление проходит
	ASSERT_EQ(hello::build(hello, stream), hello::error_t::NONE);
	// Обрезанное тело: длина метки объявлена, а самой метки нет
	vector <uint8_t> truncated(datagram.begin(), datagram.begin() + 2 + hello::HELLO_RANDOM + 1 + hello.session.size() + 1);
	// Проверяем отказ обрыва тела
	ASSERT_EQ(hello::parse(view_t(truncated.data(), truncated.size()), parsed, true), hello::error_t::HUNGRY);
}
