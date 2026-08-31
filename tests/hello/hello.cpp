/**
 * @file hello.cpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-ANTS-1.0}
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
#include <hello/hello.hpp>
#include <handshake/handshake.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace anyks;

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
	for(size_t i = 0; i < body.size(); i++){
		// Разобранное обрезанное приветствие клиента
		hello::client_t truncated;
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
	// Приветствие клиента с непомерным опознавателем связи
	hello::client_t session = hello;
	// Устанавливаем опознаватель связи длиннее дозволенного
	session.session.assign(hello::HELLO_SESSION + 1, 0x00);
	// Проверяем отказ составления приветствия с непомерным опознавателем
	ASSERT_EQ(hello::build(session, composed), hello::error_t::SESSION);
}
