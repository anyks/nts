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
 * Проверка разбора усечённых и порченых тел сообщений
 *
 * @note Проверка эта итога разбора не судит: усечённое тело вправе и не
 *       разобраться, и разобраться в иное. Судит она лишь того, что всякий
 *       разборщик выдерживает всякое тело - и своё, и чужое, и обрубленное, - не
 *       валясь и за поданную область байтов не выходя. Смысл её раскрывается под
 *       санитайзерами: без них она стережёт лишь отказ работы
 */
TEST(MessageTest, Ragged){
	// Набор годных тел сообщений, служащий основою порчи
	vector <vector <uint8_t>> corpus;
	// Выполняем перебор образцов настоящих сообщений рукопожатия
	const char * samples[3] = {CERTIFICATE, VERIFY, FINISHED};
	/**
	 * Выполняем перебор образцов сообщений рукопожатия
	 */
	for(size_t item = 0; item < 3; item++){
		// Получаем очередное сообщение рукопожатия вместе с обвязкой
		const vector <uint8_t> message = decode(samples[item]);
		// Проверяем, что образец сообщения не короче своей обвязки
		ASSERT_GT(message.size(), static_cast <size_t> (handshake::HANDSHAKE_HEADER));
		// Складываем тело образца в набор годных тел
		corpus.push_back(vector <uint8_t> (message.begin() + handshake::HANDSHAKE_HEADER, message.end()));
	}
	// Накопитель, в который складывается тело билета возобновления связи
	vector <uint8_t> issued;
	// Неповторимое значение составляемого билета
	const uint8_t nonce[4] = {0x01, 0x02, 0x03, 0x04};
	// Составляемый билет возобновления связи
	message::ticket_t ticket;
	// Устанавливаем срок составляемого билета
	ticket.lifetime = 3600;
	// Устанавливаем добавку к возрасту составляемого билета
	ticket.age = 0;
	// Устанавливаем неповторимое значение составляемого билета
	ticket.nonce = view_t(nonce, sizeof(nonce));
	// Устанавливаем тело составляемого билета
	ticket.data = view_t(nonce, sizeof(nonce));
	// Если тело билета возобновления связи составить не удалось
	ASSERT_EQ(message::build(ticket, issued), message::error_t::NONE);
	// Складываем тело билета в набор годных тел
	corpus.push_back(issued);
	// Накопитель, в который складывается тело смены ключевого материала
	vector <uint8_t> renewed;
	// Если тело смены ключевого материала составить не удалось
	ASSERT_EQ(message::build(message::update_t::REQUEST, renewed), message::error_t::NONE);
	// Складываем тело смены ключевого материала в набор годных тел
	corpus.push_back(renewed);
	/**
	 * Выполняем перебор годных тел сообщений
	 */
	for(size_t body = 0; body < corpus.size(); body++){
		/**
		 * Выполняем перебор длин усечения очередного тела: тела образцов велики, и
		 * шаг усечения берётся по их размеру - иначе проверка идёт непомерно долго
		 */
		const size_t step = ((corpus[body].size() / 512) + 1);
		/**
		 * Выполняем перебор длин усечения очередного тела
		 */
		for(size_t size = 0; size <= corpus[body].size(); size += step){
			/**
			 * Выполняем перебор мест порчи очередного тела: нулевой круг порчи не
			 * вносит вовсе, и им проверяется само усечение
			 */
			for(size_t place = 0; place <= size; place += step){
				// Выполняем перенос очередного годного тела сообщения
				vector <uint8_t> item(corpus[body].begin(), corpus[body].begin() + static_cast <ptrdiff_t> (size));
				// Если очередной байт тела портится
				if((place > 0) && (place <= item.size()))
					// Выполняем обращение всех разрядов порченого байта
					item[place - 1] = static_cast <uint8_t> (item[place - 1] ^ 0xFF);
				// Просмотр разбираемого тела сообщения
				const view_t data(item.data(), item.size());
				// Место, в которое помещается разобранная цепочка сертификатов
				message::certificate_t certificate;
				// Место, в которое помещается разобранная подпись владения ключом
				message::verify_t verify;
				// Место, в которое помещается разобранная смена ключевого материала
				message::update_t update = message::update_t::NOTIFY;
				// Место, в которое помещается разобранный билет возобновления связи
				message::ticket_t taken;
				/**
				 * Всякое тело подаётся всякому разборщику: чужое тело для разборщика
				 * ничем не лучше порченого, и выдержать он обязан оба
				 */
				(void) message::parse(data, certificate);
				// Выполняем разбор подписи владения ключом
				(void) message::parse(data, verify);
				// Выполняем разбор смены ключевого материала
				(void) message::parse(data, update);
				// Выполняем разбор билета возобновления связи
				(void) message::parse(data, taken);
				/**
				 * Обрубок тела обязан быть отвергнут своим же разборщиком: всякое поле
				 * тела объявляет длину впереди содержимого, и обрубок объявленной длины
				 * не наберёт. Сверяется лишь усечение без порчи: порченый байт вправе
				 * оставить тело разбираемым, обратившись в другое годное значение.
				 * Образец завершения рукопожатия своего разборщика не имеет вовсе -
				 * он лежит здесь ради подачи чужим разборщикам
				 */
				if((place == 0) && (size < corpus[body].size())){
					/**
					 * Выполняем выбор разборщика, которому принадлежит очередное тело
					 */
					switch(body){
						// Обрубок тела цепочки сертификатов
						case 0: ASSERT_NE(message::parse(data, certificate), message::error_t::NONE) << "длина " << size; break;
						// Обрубок тела подписи владения ключом
						case 1: ASSERT_NE(message::parse(data, verify), message::error_t::NONE) << "длина " << size; break;
						// Обрубок тела билета возобновления связи
						case 3: ASSERT_NE(message::parse(data, taken), message::error_t::NONE) << "длина " << size; break;
						// Обрубок тела смены ключевого материала
						case 4: ASSERT_NE(message::parse(data, update), message::error_t::NONE) << "длина " << size; break;
					}
				}
			}
		}
	}
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

/**
 * Проверка отказов составления сообщений на пустые обязательные поля
 */
TEST(MessageTest, Refusals){
	// Накопитель, в который складывается тело составленного сообщения
	vector <uint8_t> result;
	// Тело сертификата, годное составлению сообщения
	const uint8_t body[] = {0x30, 0x03, 0x02, 0x01, 0x00};
	// Составляемое сообщение цепочки сертификатов
	message::certificate_t certificate;
	// Запись цепочки, у которой тело сертификата не передано
	message::entry_t entry;
	// Добавляем запись цепочки в составляемое сообщение
	certificate.entries.push_back(entry);
	// Проверяем отказ составления цепочки с непереданным телом сертификата
	ASSERT_EQ(message::build(certificate, result), message::error_t::EMPTY);
	// Устанавливаем телу сертификата записи нулевую длину
	certificate.entries[0].data = view_t(body, 0);
	// Проверяем отказ составления цепочки с телом сертификата нулевой длины
	ASSERT_EQ(message::build(certificate, result), message::error_t::EMPTY);
	// Устанавливаем годное тело сертификата записи
	certificate.entries[0].data = view_t(body, sizeof(body));
	// Проверяем успешность составления цепочки с годным телом сертификата
	ASSERT_EQ(message::build(certificate, result), message::error_t::NONE);
	// Составляемое сообщение подписи владения ключом
	message::verify_t verify;
	// Устанавливаем схему подписи владения ключом
	verify.scheme = extension::scheme_t::S256A;
	// Проверяем отказ составления подписи с непереданным её значением
	ASSERT_EQ(message::build(verify, result), message::error_t::EMPTY);
	// Устанавливаем значению подписи нулевую длину
	verify.signature = view_t(body, 0);
	// Проверяем отказ составления подписи со значением нулевой длины
	ASSERT_EQ(message::build(verify, result), message::error_t::EMPTY);
	// Составляемое сообщение билета возобновления связи
	message::ticket_t ticket;
	// Устанавливаем срок жизни билета возобновления связи
	ticket.lifetime = 3600;
	// Проверяем отказ составления билета с непереданным его телом
	ASSERT_EQ(message::build(ticket, result), message::error_t::EMPTY);
	// Устанавливаем телу билета нулевую длину
	ticket.data = view_t(body, 0);
	// Проверяем отказ составления билета с телом нулевой длины
	ASSERT_EQ(message::build(ticket, result), message::error_t::EMPTY);
	// Место, в которое помещается обращённая подпись владения ключом
	uint8_t reversed[64] = {0};
	// Проверяем отказ обращения непереданной подписи владения ключом
	ASSERT_EQ(message::reverse(view_t(nullptr, sizeof(reversed)), reversed), message::error_t::EMPTY);
	// Проверяем отказ обращения подписи владения ключом нулевой длины
	ASSERT_EQ(message::reverse(view_t(reversed, 0), reversed), message::error_t::EMPTY);
	// Проверяем отказ обращения подписи в непереданное место
	ASSERT_EQ(message::reverse(view_t(reversed, sizeof(reversed)), nullptr), message::error_t::EMPTY);
	// Проверяем отказ составления подписываемого содержимого без хеша переписки
	ASSERT_EQ(message::content(view_t(nullptr, sizeof(reversed)), true, result), message::error_t::EMPTY);
	// Проверяем отказ составления подписываемого содержимого с хешем нулевой длины
	ASSERT_EQ(message::content(view_t(reversed, 0), true, result), message::error_t::EMPTY);
	// Место, в которое помещается имитовставка завершения рукопожатия
	uint8_t ending[32] = {0};
	// Проверяем отказ выработки завершения без ключа его выработки
	ASSERT_EQ(message::finished(view_t(nullptr, sizeof(ending)), view_t(ending, sizeof(ending)), ending), message::error_t::EMPTY);
	// Проверяем отказ выработки завершения без хеша переписки рукопожатия
	ASSERT_EQ(message::finished(view_t(ending, sizeof(ending)), view_t(nullptr, sizeof(ending)), ending), message::error_t::EMPTY);
	// Проверяем отказ выработки завершения в непереданное место
	ASSERT_EQ(message::finished(view_t(ending, sizeof(ending)), view_t(ending, sizeof(ending)), nullptr), message::error_t::EMPTY);
	/**
	 * Сличение тел сообщений идёт за постоянное время и оттого отвечает расхождением,
	 * а не отказом: непереданное тело сойтись не может ни с чем, включая другое
	 * непереданное
	 */
	ASSERT_FALSE(message::compare(view_t(nullptr, sizeof(ending)), view_t(ending, sizeof(ending))));
	// Проверяем расхождение сличения с непереданным вторым телом сообщения
	ASSERT_FALSE(message::compare(view_t(ending, sizeof(ending)), view_t(nullptr, sizeof(ending))));
	// Проверяем расхождение сличения двух непереданных тел сообщений
	ASSERT_FALSE(message::compare(view_t(nullptr, 0), view_t(nullptr, 0)));
	// Проверяем схождение сличения тела сообщения с самим собой
	ASSERT_TRUE(message::compare(view_t(ending, sizeof(ending)), view_t(ending, sizeof(ending))));
}

/**
 * @brief Проверка границ длин полей при составлении тел сообщений
 *
 * @note Всякое поле тела сообщения объявляет длину впереди содержимого, и ширина
 *       объявления задана RFC 8446: содержимое, в неё не входящее, обязано быть
 *       отвергнуто составлением, а не записано усечённой длиной
 *
 */
TEST(MessageTest, Confines){
	// Накопитель, в который складывается тело составленного сообщения
	vector <uint8_t> result;
	// Тело сертификата, годное составлению сообщения
	const uint8_t body[] = {0x30, 0x03, 0x02, 0x01, 0x00};
	// Запись, длина которой не входит в объявление одного байта
	const vector <uint8_t> single(256, 0x41);
	// Запись, длина которой не входит в объявление двух байтов
	const vector <uint8_t> couple(65536, 0x42);
	// Составляемое сообщение цепочки сертификатов
	message::certificate_t certificate;
	// Запись цепочки составляемого сообщения
	message::entry_t entry;
	// Устанавливаем годное тело сертификата записи
	entry.data = view_t(body, sizeof(body));
	// Добавляем запись цепочки в составляемое сообщение
	certificate.entries.push_back(entry);
	/**
	 * Привязка цепочки сертификатов объявляется одним байтом: раздел 4.4.2 RFC 8446
	 */
	certificate.context = view_t(single.data(), single.size());
	// Проверяем отказ составления цепочки с непомерной привязкой
	ASSERT_EQ(message::build(certificate, result), message::error_t::LENGTH);
	// Сбрасываем привязку цепочки сертификатов
	certificate.context = view_t();
	/**
	 * Тело расширения записи цепочки объявляется двумя байтами
	 */
	hello::extension_t item;
	// Устанавливаем вид расширения записи цепочки
	item.type = 0x0001;
	// Устанавливаем непомерное тело расширения записи цепочки
	item.data = view_t(couple.data(), couple.size());
	// Добавляем расширение в запись цепочки составляемого сообщения
	certificate.entries[0].extensions.push_back(item);
	// Проверяем отказ составления цепочки с непомерным телом расширения
	ASSERT_EQ(message::build(certificate, result), message::error_t::LENGTH);
	// Сбрасываем перечень расширений записи цепочки
	certificate.entries[0].extensions.clear();
	/**
	 * Перечень расширений записи объявляется двумя байтами целиком: два расширения,
	 * всякое из которых в своё объявление входит, вместе в него не входят
	 */
	hello::extension_t piece;
	// Устанавливаем вид расширения записи цепочки
	piece.type = 0x0003;
	// Устанавливаем тело расширения длиною в половину объявления перечня
	piece.data = view_t(couple.data(), couple.size() / 2);
	// Добавляем первое расширение в запись цепочки сертификатов
	certificate.entries[0].extensions.push_back(piece);
	// Добавляем второе расширение в запись цепочки сертификатов
	certificate.entries[0].extensions.push_back(piece);
	// Проверяем отказ составления цепочки с непомерным перечнем расширений
	ASSERT_EQ(message::build(certificate, result), message::error_t::LENGTH);
	// Сбрасываем перечень расширений записи цепочки
	certificate.entries[0].extensions.clear();
	// Проверяем успешность составления цепочки после снятия непомерных полей
	ASSERT_EQ(message::build(certificate, result), message::error_t::NONE);
	/**
	 * Подпись владения ключом объявляется двумя байтами: раздел 4.4.3 RFC 8446
	 */
	message::verify_t verify;
	// Устанавливаем схему подписи владения ключом
	verify.scheme = extension::scheme_t::S256A;
	// Устанавливаем непомерное значение подписи владения ключом
	verify.signature = view_t(couple.data(), couple.size());
	// Проверяем отказ составления подписи непомерной длины
	ASSERT_EQ(message::build(verify, result), message::error_t::LENGTH);
	/**
	 * Неповторимое значение билета объявляется одним байтом, а тело билета и тела
	 * его расширений - двумя: раздел 4.6.1 RFC 8446
	 */
	message::ticket_t ticket;
	// Устанавливаем срок жизни билета возобновления связи
	ticket.lifetime = 3600;
	// Устанавливаем годное тело билета возобновления связи
	ticket.data = view_t(body, sizeof(body));
	// Устанавливаем непомерное неповторимое значение билета
	ticket.nonce = view_t(single.data(), single.size());
	// Проверяем отказ составления билета с непомерным неповторимым значением
	ASSERT_EQ(message::build(ticket, result), message::error_t::LENGTH);
	// Сбрасываем неповторимое значение билета
	ticket.nonce = view_t();
	// Устанавливаем непомерное тело билета возобновления связи
	ticket.data = view_t(couple.data(), couple.size());
	// Проверяем отказ составления билета с непомерным телом
	ASSERT_EQ(message::build(ticket, result), message::error_t::LENGTH);
	// Восстанавливаем годное тело билета возобновления связи
	ticket.data = view_t(body, sizeof(body));
	// Устанавливаем непомерное тело расширения билета
	ticket.extensions.push_back(item);
	// Проверяем отказ составления билета с непомерным телом расширения
	ASSERT_EQ(message::build(ticket, result), message::error_t::LENGTH);
	// Сбрасываем перечень расширений билета возобновления связи
	ticket.extensions.clear();
	/**
	 * Перечень расширений билета объявляется двумя байтами целиком: два расширения,
	 * всякое из которых в своё объявление входит, вместе в него не входят
	 */
	hello::extension_t half;
	// Устанавливаем вид расширения билета возобновления связи
	half.type = 0x0002;
	// Устанавливаем тело расширения длиною в половину объявления перечня
	half.data = view_t(couple.data(), couple.size() / 2);
	// Добавляем первое расширение в билет возобновления связи
	ticket.extensions.push_back(half);
	// Добавляем второе расширение в билет возобновления связи
	ticket.extensions.push_back(half);
	// Проверяем отказ составления билета с непомерным перечнем расширений
	ASSERT_EQ(message::build(ticket, result), message::error_t::LENGTH);
	// Сбрасываем перечень расширений билета возобновления связи
	ticket.extensions.clear();
	// Проверяем успешность составления билета после снятия непомерных полей
	ASSERT_EQ(message::build(ticket, result), message::error_t::NONE);
}

/**
 * @brief Проверка границ длин полей цепочки сертификатов в три байта
 *
 * @note Тело сертификата и цепочка целиком объявляются тремя байтами, оттого
 *       проверка их требует записи свыше 16 МиБ. Она заведена отдельно от прочих
 *       границ: та идёт мгновенно, а этой нужна память
 *
 */
TEST(MessageTest, Vastness){
	// Накопитель, в который складывается тело составленного сообщения
	vector <uint8_t> result;
	// Запись, длина которой не входит в объявление трёх байтов
	const vector <uint8_t> triple((1 << 24), 0x43);
	// Составляемое сообщение цепочки сертификатов
	message::certificate_t certificate;
	// Запись цепочки составляемого сообщения
	message::entry_t entry;
	// Устанавливаем непомерное тело сертификата записи
	entry.data = view_t(triple.data(), triple.size());
	// Добавляем запись цепочки в составляемое сообщение
	certificate.entries.push_back(entry);
	// Проверяем отказ составления цепочки с непомерным телом сертификата
	ASSERT_EQ(message::build(certificate, result), message::error_t::LENGTH);
	/**
	 * Цепочка сертификатов объявляется тремя байтами целиком: два сертификата,
	 * всякий из которых в своё объявление входит, вместе в него не входят
	 */
	certificate.entries[0].data = view_t(triple.data(), triple.size() / 2);
	// Добавляем в цепочку вторую запись того же тела
	certificate.entries.push_back(certificate.entries[0]);
	// Проверяем отказ составления цепочки непомерной длины
	ASSERT_EQ(message::build(certificate, result), message::error_t::LENGTH);
}

/**
 * @brief Проверка отказов разбора негодных тел сообщений
 *
 * @note Тела эти собираются байтами вручную: составление таких не выдаёт, и через
 *       него подать их разбору нельзя
 *
 */
TEST(MessageTest, Deformed){
	// Место, в которое помещается разобранная цепочка сертификатов
	message::certificate_t certificate;
	// Место, в которое помещается разобранная подпись владения ключом
	message::verify_t verify;
	// Место, в которое помещается разобранный билет возобновления связи
	message::ticket_t ticket;
	/**
	 * Тело цепочки сертификатов: привязка нулевой длины, а за нею цепочка из одной
	 * записи с телом сертификата в один байт и пустым перечнем расширений
	 */
	const vector <uint8_t> chain = {
		0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x30, 0x00, 0x00
	};
	// Проверяем успешность разбора годного тела цепочки сертификатов
	ASSERT_EQ(message::parse(view_t(chain.data(), chain.size()), certificate), message::error_t::NONE);
	// Тело цепочки сертификатов с лишним байтом за своим концом
	vector <uint8_t> trailing = chain;
	// Добавляем лишний байт за конец тела цепочки сертификатов
	trailing.push_back(0x00);
	/**
	 * Раздел 5.1 RFC 8446 не даёт телу сообщения хвоста: длина сообщения объявлена
	 * его обвязкой, и байты за разобранным телом означают запись негодную
	 */
	ASSERT_EQ(message::parse(view_t(trailing.data(), trailing.size()), certificate), message::error_t::TRAILING);
	/**
	 * Тело сертификата записи цепочки обязательно: раздел 4.4.2 RFC 8446 велит
	 * нести в записи сам сертификат, а не пустое место
	 */
	const vector <uint8_t> hollow = {
		0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	// Проверяем отказ разбора цепочки с пустым телом сертификата
	ASSERT_EQ(message::parse(view_t(hollow.data(), hollow.size()), certificate), message::error_t::EMPTY);
	/**
	 * Перечень расширений записи цепочки, оборванный на середине вида расширения:
	 * один байт вида прочитан быть не может, ибо вид объявлен двумя
	 */
	const vector <uint8_t> ragged = {
		0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x01, 0x30, 0x00, 0x01, 0x00
	};
	// Проверяем отказ разбора цепочки с оборванным перечнем расширений
	ASSERT_EQ(message::parse(view_t(ragged.data(), ragged.size()), certificate), message::error_t::EXTENSION);
	/**
	 * Перечень расширений, оборванный на теле расширения: вид прочитан, а тела
	 * объявленной длины за ним не набирается
	 */
	const vector <uint8_t> stumped = {
		0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x30, 0x00, 0x04,
		0x00, 0x2A, 0x00, 0x08
	};
	// Проверяем отказ разбора цепочки с оборванным телом расширения
	ASSERT_EQ(message::parse(view_t(stumped.data(), stumped.size()), certificate), message::error_t::EXTENSION);
	/**
	 * Раздел 4.2 RFC 8446: расширение одного вида дважды объявлено быть не вправе
	 */
	const vector <uint8_t> twofold = {
		0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x01, 0x30, 0x00, 0x08,
		0x00, 0x2A, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00
	};
	// Проверяем отказ разбора цепочки с дважды объявленным расширением
	ASSERT_EQ(message::parse(view_t(twofold.data(), twofold.size()), certificate), message::error_t::EXTENSION);
	/**
	 * Подпись владения ключом обязательна: раздел 4.4.3 RFC 8446 объявляет её полем
	 * тела сообщения, и пустой она быть не вправе
	 */
	const vector <uint8_t> unsigned_ = {0x08, 0x02, 0x00, 0x00};
	// Проверяем отказ разбора подписи владения ключом нулевой длины
	ASSERT_EQ(message::parse(view_t(unsigned_.data(), unsigned_.size()), verify), message::error_t::EMPTY);
	/**
	 * Тело билета возобновления связи: срок, добавка к возрасту, неповторимое
	 * значение нулевой длины, тело билета в один байт и пустой перечень расширений
	 */
	const vector <uint8_t> issued = {
		0x00, 0x00, 0x0E, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x41, 0x00, 0x00
	};
	// Проверяем успешность разбора годного тела билета возобновления связи
	ASSERT_EQ(message::parse(view_t(issued.data(), issued.size()), ticket), message::error_t::NONE);
	// Тело билета возобновления связи с лишним байтом за своим концом
	vector <uint8_t> excess = issued;
	// Добавляем лишний байт за конец тела билета возобновления связи
	excess.push_back(0x00);
	// Проверяем отказ разбора билета с лишним байтом за своим концом
	ASSERT_EQ(message::parse(view_t(excess.data(), excess.size()), ticket), message::error_t::TRAILING);
	/**
	 * Тело билета обязательно: раздел 4.6.1 RFC 8446 велит нести в билете значение,
	 * по которому связь возобновляется, а пустое место таким значением не служит
	 */
	vector <uint8_t> vacant = issued;
	// Обнуляем длину тела билета возобновления связи
	vacant[10] = 0x00;
	// Снимаем тело билета возобновления связи
	vacant.erase(vacant.begin() + 11);
	// Проверяем отказ разбора билета с телом нулевой длины
	ASSERT_EQ(message::parse(view_t(vacant.data(), vacant.size()), ticket), message::error_t::EMPTY);
	// Тело билета с оборванным перечнем расширений
	vector <uint8_t> broken = issued;
	// Объявляем перечень расширений билета длиной в один байт
	broken[13] = 0x01;
	// Добавляем единственный байт перечня расширений билета
	broken.push_back(0x00);
	// Проверяем отказ разбора билета с оборванным перечнем расширений
	ASSERT_EQ(message::parse(view_t(broken.data(), broken.size()), ticket), message::error_t::EXTENSION);
	/**
	 * Подпись владения ключом записывается двумя числами равной длины: раздел 2
	 * RFC 9215. Длина нечётная означает подпись, на два числа не делимую
	 */
	uint8_t reversed[64] = {0};
	// Проверяем отказ обращения подписи нечётной длины
	ASSERT_EQ(message::reverse(view_t(reversed, sizeof(reversed) - 1), reversed), message::error_t::LENGTH);
}
