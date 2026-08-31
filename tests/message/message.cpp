/**
 * @file message.cpp
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
 * @brief Исходный файл проверок модуля сообщений подтверждения подлинности
 *
 * @note Сообщения взяты из приложения А описания наборов шифрования TLS 1.3 на алгоритмах
 *       ГОСТ: цепочка сертификатов, подпись владения ключом и завершение рукопожатия того
 *       же примера, на котором проверялись приветствия
 *
 * @note Завершение рукопожатия проверяется не круговым обходом, а выработкой заново из
 *       ключа завершения и хеша переписки, напечатанных там же
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
#include <message/message.hpp>
#include <handshake/handshake.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Сообщение цепочки сертификатов контрольного примера
 */
static const char * CERTIFICATE = "0B0001510000014D000148308201443081F2A00302010202023039300A06082A85030701010302301B3119301706035504031310676F73742E6578616D706C652E636F6D301E170D3230303232383131303833375A170D3330303232353131303833375A301B3119301706035504031310676F73742E6578616D706C652E636F6D305E301706082A85030701010101300B06092A85030701020101020343000440F383CEE83048B4EB14C71A7F6DE44A37CE11A6AC1750F1CFB8DAD8A38CCDD8FD06656F7CFC075F4083C3716221478F1EE24C6B1B70CCE3C72AFD2ACE65C775BCA321301F301D0603551D0E04160414F330FA7166DF095AF3A073BC3B8EA356D7DFAC71300A06082A85030701010302034100AB2EDA23F49B48623B0CFF5906B7DD3C23B473570B296A0871DD15EF9A33201B97904A5CFA6C931C5473DC0C5A5F2FBB2E50CF587AE27C4D8E52EB80189DD08B0000";

/**
 * Сообщение подписи владения ключом контрольного примера
 */
static const char * VERIFY = "0F000044070A0040A0AA13915C5B80C602E2FD85804F992C771597AD37857AD6BC2A9D7BC5FEBEC37C7294BAA23CF69D03E4710BD70813FDAC596BC158E756BD371C442E9522DE87";

/**
 * Сообщение завершения рукопожатия контрольного примера
 */
static const char * FINISHED = "14000020E0BAA33614E069697E4DFAB071B9725773F8FE1A326A662D0F52309B45B6E031";

/**
 * Ключ выработки завершения рукопожатия сервером
 */
static const char * SECRET = "53F1C0388F8A70C0BCA0DD21A030F2381C3437CD0E7EC93D0A965E25632DD79A";

/**
 * Хеш переписки рукопожатия на миг завершения
 */
static const char * TRANSCRIPT = "03EC9B1D0B37414245 72BAC9DF3AA52C03EFE9E958076943AFD85819BC602F46";

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
	 * Выполняем перебор знаков шестнадцатеричной записи
	 */
	for(size_t i = 0; (i + 1) < length; i += 2){
		// Если очередной знак записи не знак шестнадцатеричной цифры
		if(text[i] == ' '){
			// Отступаем на один знак назад
			i--;
			// Переходим к следующему знаку записи
			continue;
		}
		// Добавляем очередной разобранный байт
		result.push_back(static_cast <uint8_t> (::strtoul(string(text + i, 2).c_str(), nullptr, 16)));
	}
	// Выводим разобранную область байтов
	return result;
}

/**
 * Проверка разбора и составления цепочки сертификатов
 */
TEST(MessageTest, Certificate){
	// Получаем сообщение цепочки сертификатов вместе с обвязкой
	const vector <uint8_t> message = decode(CERTIFICATE);
	// Обвязка сообщения цепочки сертификатов
	handshake::header_t header;
	// Выполняем разбор обвязки сообщения цепочки сертификатов
	ASSERT_EQ(handshake::parse(view_t(message.data(), message.size()), header), handshake::error_t::NONE);
	// Проверяем вид разобранного сообщения рукопожатия
	ASSERT_EQ(header.type, handshake::type_t::CERTIFICATE);
	// Получаем тело сообщения цепочки сертификатов
	const view_t body(message.data() + handshake::HANDSHAKE_HEADER, header.size);
	// Разобранное сообщение цепочки сертификатов
	message::certificate_t certificate;
	// Выполняем разбор тела сообщения цепочки сертификатов
	ASSERT_EQ(message::parse(body, certificate), message::error_t::NONE);
	// Проверяем, что привязка цепочки к запросу сертификата пуста
	ASSERT_EQ(certificate.context.size, static_cast <size_t> (0));
	// Проверяем, что цепочка несёт единственный сертификат
	ASSERT_EQ(certificate.entries.size(), static_cast <size_t> (1));
	// Проверяем, что тело сертификата цепочки не пусто
	ASSERT_GT(certificate.entries[0].data.size, static_cast <size_t> (0));
	// Проверяем, что сертификат начинается с последовательности DER
	ASSERT_EQ(certificate.entries[0].data.data[0], static_cast <uint8_t> (0x30));
	// Проверяем, что расширений у записи цепочки нет
	ASSERT_TRUE(certificate.entries[0].extensions.empty());
	// Накопитель, в который складывается составленное тело сообщения
	vector <uint8_t> composed;
	// Выполняем составление тела сообщения цепочки сертификатов заново
	ASSERT_EQ(message::build(certificate, composed), message::error_t::NONE);
	// Проверяем схождение длины составленного тела с исходным
	ASSERT_EQ(composed.size(), body.size);
	// Проверяем схождение составленного тела сообщения с исходным
	ASSERT_EQ(::memcmp(composed.data(), body.data, composed.size()), 0);
}

/**
 * Проверка разбора и составления подписи владения ключом
 */
TEST(MessageTest, Verify){
	// Получаем сообщение подписи владения ключом вместе с обвязкой
	const vector <uint8_t> message = decode(VERIFY);
	// Обвязка сообщения подписи владения ключом
	handshake::header_t header;
	// Выполняем разбор обвязки сообщения подписи владения ключом
	ASSERT_EQ(handshake::parse(view_t(message.data(), message.size()), header), handshake::error_t::NONE);
	// Проверяем вид разобранного сообщения рукопожатия
	ASSERT_EQ(header.type, handshake::type_t::VERIFY);
	// Получаем тело сообщения подписи владения ключом
	const view_t body(message.data() + handshake::HANDSHAKE_HEADER, header.size);
	// Разобранное сообщение подписи владения ключом
	message::verify_t verify;
	// Выполняем разбор тела сообщения подписи владения ключом
	ASSERT_EQ(message::parse(body, verify), message::error_t::NONE);
	// Проверяем, что схема подписи владения ключом известна
	ASSERT_NE(extension::length(verify.scheme), static_cast <size_t> (0));
	// Проверяем, что подпись занимает две длины ключа своей схемы
	ASSERT_EQ(verify.signature.size, (extension::length(verify.scheme) * 2));
	// Место, в которое помещается обращённая запись подписи
	vector <uint8_t> reversed(verify.signature.size, 0);
	// Выполняем обращение записи подписи владения ключом
	ASSERT_EQ(message::reverse(verify.signature, reversed.data()), message::error_t::NONE);
	// Проверяем, что обращённая запись подписи с исходной разошлась
	ASSERT_NE(::memcmp(reversed.data(), verify.signature.data, reversed.size()), 0);
	// Место, в которое помещается дважды обращённая запись подписи
	vector <uint8_t> restored(verify.signature.size, 0);
	// Выполняем обращение записи подписи владения ключом обратно
	ASSERT_EQ(message::reverse(view_t(reversed.data(), reversed.size()), restored.data()), message::error_t::NONE);
	/**
	 * Обращение записи подписи само себе обратно: дважды обращённая подпись обязана
	 * сойтись с исходной байт в байт
	 */
	ASSERT_EQ(::memcmp(restored.data(), verify.signature.data, restored.size()), 0);
	// Накопитель, в который складывается составленное тело сообщения
	vector <uint8_t> composed;
	// Выполняем составление тела сообщения подписи владения ключом заново
	ASSERT_EQ(message::build(verify, composed), message::error_t::NONE);
	// Проверяем схождение длины составленного тела с исходным
	ASSERT_EQ(composed.size(), body.size);
	// Проверяем схождение составленного тела сообщения с исходным
	ASSERT_EQ(::memcmp(composed.data(), body.data, composed.size()), 0);
}

/**
 * Проверка выработки завершения рукопожатия
 */
TEST(MessageTest, Finished){
	// Получаем сообщение завершения рукопожатия вместе с обвязкой
	const vector <uint8_t> message = decode(FINISHED);
	// Обвязка сообщения завершения рукопожатия
	handshake::header_t header;
	// Выполняем разбор обвязки сообщения завершения рукопожатия
	ASSERT_EQ(handshake::parse(view_t(message.data(), message.size()), header), handshake::error_t::NONE);
	// Проверяем вид разобранного сообщения рукопожатия
	ASSERT_EQ(header.type, handshake::type_t::FINISHED);
	// Получаем ключ выработки завершения рукопожатия
	const vector <uint8_t> secret = decode(SECRET);
	// Получаем хеш переписки рукопожатия на миг завершения
	const vector <uint8_t> transcript = decode(TRANSCRIPT);
	// Место, в которое помещается выработанное завершение рукопожатия
	uint8_t result[32];
	// Выполняем выработку тела сообщения завершения рукопожатия
	ASSERT_EQ(message::finished(view_t(secret.data(), secret.size()), view_t(transcript.data(), transcript.size()), result), message::error_t::NONE);
	// Получаем тело сообщения завершения рукопожатия контрольного примера
	const view_t body(message.data() + handshake::HANDSHAKE_HEADER, header.size);
	// Проверяем длину тела сообщения завершения рукопожатия
	ASSERT_EQ(body.size, sizeof(result));
	// Проверяем схождение выработанного завершения с контрольным примером
	ASSERT_TRUE(message::compare(view_t(result, sizeof(result)), body));
	// Портим один байт выработанного завершения рукопожатия
	result[0] = static_cast <uint8_t> (result[0] ^ 0x01);
	// Проверяем расхождение испорченного завершения с контрольным примером
	ASSERT_FALSE(message::compare(view_t(result, sizeof(result)), body));
	// Проверяем расхождение завершений разной длины
	ASSERT_FALSE(message::compare(view_t(result, sizeof(result) - 1), body));
}

/**
 * Проверка составления подписываемого содержимого владения ключом
 */
TEST(MessageTest, Content){
	// Получаем хеш переписки рукопожатия на миг подписания
	const vector <uint8_t> transcript = decode(TRANSCRIPT);
	// Накопитель, в который складывается подписываемое содержимое сервера
	vector <uint8_t> server;
	// Выполняем составление подписываемого содержимого сервера
	ASSERT_EQ(message::content(view_t(transcript.data(), transcript.size()), true, server), message::error_t::NONE);
	// Проверяем длину подписываемого содержимого сервера
	ASSERT_EQ(server.size(), (64 + ::strlen("TLS 1.3, server CertificateVerify") + 1 + transcript.size()));
	/**
	 * Выполняем перебор пробелов подписываемого содержимого
	 */
	for(size_t i = 0; i < 64; i++)
		// Проверяем, что очередной байт подписываемого содержимого пробел
		ASSERT_EQ(server[i], static_cast <uint8_t> (0x20)) << "пробел " << i;
	// Проверяем название назначения подписываемого содержимого сервера
	ASSERT_EQ(::memcmp(server.data() + 64, "TLS 1.3, server CertificateVerify", 33), 0);
	// Проверяем разделитель названия назначения и хеша переписки
	ASSERT_EQ(server[64 + 33], static_cast <uint8_t> (0x00));
	// Проверяем схождение хеша переписки в подписываемом содержимом
	ASSERT_EQ(::memcmp(server.data() + 64 + 33 + 1, transcript.data(), transcript.size()), 0);
	// Накопитель, в который складывается подписываемое содержимое клиента
	vector <uint8_t> client;
	// Выполняем составление подписываемого содержимого клиента
	ASSERT_EQ(message::content(view_t(transcript.data(), transcript.size()), false, client), message::error_t::NONE);
	// Проверяем схождение длин подписываемого содержимого сторон
	ASSERT_EQ(client.size(), server.size());
	/**
	 * Подпись клиента за подпись сервера выдать нельзя: названия назначения у них
	 * разные, и подписывается вместе с хешем переписки именно оно
	 */
	ASSERT_NE(::memcmp(client.data(), server.data(), client.size()), 0);
	// Проверяем отказ составления содержимого без хеша переписки
	ASSERT_EQ(message::content(view_t(nullptr, 0), true, client), message::error_t::EMPTY);
}

/**
 * Проверка разбора и составления сообщения смены ключевого материала
 */
TEST(MessageTest, Update){
	// Накопитель, в который складывается тело сообщения
	vector <uint8_t> body;
	// Выполняем составление тела сообщения смены ключевого материала
	ASSERT_EQ(message::build(message::update_t::REQUEST, body), message::error_t::NONE);
	// Проверяем длину составленного тела сообщения
	ASSERT_EQ(body.size(), static_cast <size_t> (1));
	// Проверяем записанный вид смены ключевого материала
	ASSERT_EQ(body[0], 0x01);
	// Разбираемый вид смены ключевого материала
	message::update_t update = message::update_t::NOTIFY;
	// Выполняем разбор составленного тела сообщения
	ASSERT_EQ(message::parse(view_t(body.data(), body.size()), update), message::error_t::NONE);
	// Проверяем разобранный вид смены ключевого материала
	ASSERT_EQ(update, message::update_t::REQUEST);
	// Тело сообщения с видом смены, протоколом не определённым
	const uint8_t unknown[1] = {0x02};
	// Проверяем отказ разбора неизвестного вида смены ключей
	ASSERT_EQ(message::parse(view_t(unknown, sizeof(unknown)), update), message::error_t::EMPTY);
	// Тело сообщения, оборванное до вида смены ключей
	ASSERT_EQ(message::parse(view_t(), update), message::error_t::HUNGRY);
	// Тело сообщения с лишними байтами за видом смены ключей
	const uint8_t trailing[2] = {0x00, 0x00};
	// Проверяем отказ разбора тела с лишними байтами
	ASSERT_EQ(message::parse(view_t(trailing, sizeof(trailing)), update), message::error_t::TRAILING);
}

/**
 * Проверка разбора и составления билета возобновления связи
 */
TEST(MessageTest, Ticket){
	// Неповторимое значение составляемого билета
	const uint8_t nonce[4] = {0x00, 0x00, 0x00, 0x01};
	// Тело составляемого билета возобновления связи
	const uint8_t body[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
	// Составляемый билет возобновления связи
	message::ticket_t ticket;
	// Устанавливаем срок жизни составляемого билета
	ticket.lifetime = 7200;
	// Устанавливаем добавку к возрасту составляемого билета
	ticket.age = 0x01020304;
	// Устанавливаем неповторимое значение составляемого билета
	ticket.nonce = view_t(nonce, sizeof(nonce));
	// Устанавливаем тело составляемого билета
	ticket.data = view_t(body, sizeof(body));
	// Накопитель, в который складывается тело сообщения билета
	vector <uint8_t> result;
	// Выполняем составление тела сообщения билета
	ASSERT_EQ(message::build(ticket, result), message::error_t::NONE);
	// Разбираемый билет возобновления связи
	message::ticket_t parsed;
	// Выполняем разбор составленного тела сообщения
	ASSERT_EQ(message::parse(view_t(result.data(), result.size()), parsed), message::error_t::NONE);
	// Проверяем разобранный срок жизни билета
	ASSERT_EQ(parsed.lifetime, static_cast <uint32_t> (7200));
	// Проверяем разобранную добавку к возрасту билета
	ASSERT_EQ(parsed.age, static_cast <uint32_t> (0x01020304));
	// Проверяем длину разобранного неповторимого значения билета
	ASSERT_EQ(parsed.nonce.size, sizeof(nonce));
	// Проверяем схождение разобранного неповторимого значения с составленным
	ASSERT_EQ(::memcmp(parsed.nonce.data, nonce, sizeof(nonce)), 0);
	// Проверяем длину разобранного тела билета
	ASSERT_EQ(parsed.data.size, sizeof(body));
	// Проверяем схождение разобранного тела билета с составленным
	ASSERT_EQ(::memcmp(parsed.data.data, body, sizeof(body)), 0);
	// Проверяем отсутствие расширений разобранного билета
	ASSERT_TRUE(parsed.extensions.empty());
	// Билет с пустым телом составлению не подлежит
	message::ticket_t empty;
	// Устанавливаем неповторимое значение билета с пустым телом
	empty.nonce = view_t(nonce, sizeof(nonce));
	// Проверяем отказ составления билета с пустым телом
	ASSERT_EQ(message::build(empty, result), message::error_t::EMPTY);
	// Проверяем отказ разбора тела сообщения, оборванного посреди поля
	ASSERT_EQ(message::parse(view_t(result.data(), 3), parsed), message::error_t::HUNGRY);
}
