/**
 * @file limit.cpp
 * @date 2026-09-08
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
 * @brief Исходный файл проверок пределов длины записи: record_size_limit (RFC 8449, расширение
 *        0x001C) и max_fragment_length (раздел 4 RFC 6066, расширение 0x0001) - обещание профиля
 *        отпечатка держится обеими сторонами в изданиях 1.2 и 1.3, оба расширения разом в обоих
 *        порядках, негодные значения, чужие эталоны openssl (-maxfraglen) и gnutls (--recordsize)
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <functional>
#include <algorithm>
#include <unistd.h>
#include <poll.h>
#include <iostream>

/**
 * Заголовочные файлы проверок
 */
#include <main.hpp>
#include <openssl.hpp>

/**
 * Заголовочные файлы проекта
 */
#include <pem/pem.hpp>
#include <alert/alert.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <context/context.hpp>
#include <extension/extension.hpp>
#include <fingerprint/fingerprint.hpp>

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * Каталог образцов ключей
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * @brief Служебные помощники проверок
 *
 */
namespace {
	/**
	 * Пределы сторон по итогу последнего рукопожатия: отправка и приём клиента, отправка и приём сервера
	 */
	static size_t LAST[4] = {0, 0, 0, 0};
	/**
	 * @brief Метод чтения файла образцов
	 *
	 * @param name имя файла
	 *
	 * @return     содержимое файла
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Файл образца
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Содержимое файла
		vector <uint8_t> result;
		// Если файл открыт, читаем его целиком
		if(file.is_open())
			// Читаем содержимое
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое
		return result;
	}
	/**
	 * @brief Метод загрузки ключа и цепочки из образцов
	 *
	 * @param name   имя пары файлов
	 * @param result полномочия сервера
	 *
	 * @return       признак успешной загрузки
	 *
	 */
	bool keyfile(const char * name, context::credential_t & result) noexcept {
		// Читаем закрытый ключ
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Читаем цепочку
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Если чего-то нет
		if(result.secret.empty() || text.empty())
			// Выводим отказ
			return false;
		// Очищаем цепочку
		result.chain.clear();
		// Разбираем цепочку из PEM
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Метод переноса байтов между сторонами, попутно считая записи прикладных данных
	 *
	 * @param client  клиент
	 * @param server  сервер
	 * @param records счётчик записей прикладных данных, увиденных на проводе (обе стороны)
	 * @param widest  наибольшая длина записи прикладных данных на проводе (без заголовка)
	 *
	 * @return        признак того, что байты перенесены
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server, size_t & records, size_t & widest) noexcept {
		// Признак переноса
		bool moved = false;
		/**
		 * Выполняем перехват ошибок памяти
		 */
		try {
			/**
			 * Выполняем перебор обеих сторон
			 */
			for(size_t side = 0; side < 2; side++){
				// Вывод стороны
				const view_t data = ((side == 0) ? client.output() : server.output());
				// Если выводить нечего
				if(data.size == 0)
					// Пропускаем сторону
					continue;
				// Снимок вывода
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				/**
				 * Выполняем перебор записей на проводе: у обеих сторон записи целые
				 */
				for(size_t offset = 0; (offset + 5) <= buffer.size();){
					// Длина записи
					const size_t length = ((static_cast <size_t> (buffer[offset + 3]) << 8) | buffer[offset + 4]);
					// Если запись прикладных данных, считаем её
					if(buffer[offset] == static_cast <uint8_t> (record::type_t::APPLICATION)){
						// Считаем запись
						records++;
						// Запоминаем наибольшую
						widest = ((length > widest) ? length : widest);
					}
					// Переходим к следующей записи
					offset += (5 + length);
				}
				// Если пишет клиент
				if(side == 0){
					// Забираем вывод клиента и отдаём серверу
					client.consume(buffer.size());
					server.push(view_t(buffer.data(), buffer.size()));
				// Если пишет сервер
				} else {
					// Забираем вывод сервера и отдаём клиенту
					server.consume(buffer.size());
					client.push(view_t(buffer.data(), buffer.size()));
				}
				// Отмечаем перенос
				moved = true;
			}
		// Если памяти не хватило
		} catch(const bad_alloc &) {
			// Выводим отказ
			return false;
		}
		// Выводим признак переноса
		return moved;
	}
	/**
	 * @brief Метод проведения обмена до тишины
	 *
	 * @param client  клиент
	 * @param server  сервер
	 * @param records счётчик записей прикладных данных
	 * @param widest  наибольшая запись прикладных данных
	 *
	 */
	void converse(client::context_t & client, server::context_t & server, size_t & records, size_t & widest) noexcept {
		/**
		 * Выполняем перенос, пока стороны пишут
		 */
		for(size_t i = 0; (i < 32) && pump(client, server, records, widest); i++)
			// Продолжаем
			continue;
	}
	/**
	 * @brief Метод снятия профиля с приветствия донора и дописывания расширения предела
	 *
	 * @param result профиль
	 * @param types  виды дописываемых расширений по порядку
	 * @param bodies тела расширений по порядку
	 *
	 * @return       признак готовности профиля
	 *
	 */
	bool profiling(fingerprint::profile_t & result, const vector <uint16_t> & types, const vector <vector <uint8_t>> & bodies) noexcept {
		// Клиент-донор
		client::context_t donor;
		// Имя узла донора
		donor.name("example.com");
		// Если приветствие донора не составлено
		if(donor.start() != context::error_t::NONE)
			// Выводим отказ
			return false;
		// Если приветствие донора не разобрано
		if(fingerprint::parse(donor.output(), result) != fingerprint::error_t::NONE)
			// Выводим отказ
			return false;
		/**
		 * Выполняем дописывание расширений
		 */
		for(size_t i = 0; i < types.size(); i++){
			// Расширение предела
			fingerprint::extension_t extension;
			// Вид и тело
			extension.type = types[i];
			extension.data = bodies[i];
			// Дописываем расширение
			result.extensions.push_back(extension);
		}
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод проведения связи по профилю с пределом и переноса длинных данных в обе стороны
	 *
	 * @param types   виды расширений предела
	 * @param bodies  тела расширений предела
	 * @param legacy  признак издания 1.2
	 * @param amount  объём данных в каждую сторону
	 * @param records счётчик записей прикладных данных на проводе
	 * @param widest  наибольшая запись прикладных данных на проводе
	 * @param failure ошибка клиента при отказе
	 * @param answer  вывод сервера в ответ на первое приветствие (ServerHello открыт у 1.2)
	 *
	 * @return        признак того, что связь установлена и данные дошли в обе стороны
	 *
	 */
	bool transfer(const vector <uint16_t> & types, const vector <vector <uint8_t>> & bodies, const bool legacy, const size_t amount, size_t & records, size_t & widest, context::error_t & failure, vector <uint8_t> & answer) noexcept {
		// Полномочия сервера
		context::credential_t credential;
		// Если ключ не загружен
		if(!keyfile("ec256", credential))
			// Выводим отказ
			return false;
		// Профиль с пределом
		fingerprint::profile_t profile;
		// Если профиль не собран
		if(!profiling(profile, types, bodies))
			// Выводим отказ
			return false;
		// Стороны связи
		client::context_t client;
		server::context_t server;
		// Имя узла
		client.name("example.com");
		// Если профиль не принят
		if(client.profile(profile) != context::error_t::NONE)
			// Выводим отказ
			return false;
		// Полномочия сервера
		server.credential(credential);
		// Если нужно издание 1.2
		if(legacy){
			// Ограничиваем издания сервера
			if(server.versions(0x0303, 0x0303) != context::error_t::NONE)
				// Выводим отказ
				return false;
		}
		// Если стороны не запущены
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE))
			// Выводим отказ
			return false;
		// Первое приветствие уходит серверу
		{
			// Снимок приветствия
			const view_t hello = client.output();
			const vector <uint8_t> buffer(hello.data, hello.data + hello.size);
			// Передаём приветствие
			client.consume(buffer.size());
			server.push(view_t(buffer.data(), buffer.size()));
			// Снимаем ответ сервера
			const view_t reply = server.output();
			answer.assign(reply.data, reply.data + reply.size);
		}
		// Счётчики рукопожатия не нужны
		size_t handshaking = 0, widening = 0;
		// Проводим рукопожатие
		converse(client, server, handshaking, widening);
		// Ошибка клиента
		failure = client.error();
		// Если связь не установлена
		if(!client.established() || !server.established())
			// Выводим отказ
			return false;
		// Запоминаем пределы сторон
		LAST[0] = client.ceiling();
		LAST[1] = client.threshold();
		LAST[2] = server.ceiling();
		LAST[3] = server.threshold();
		// Данные в обе стороны
		const vector <uint8_t> outward(amount, 0x41), inward(amount, 0x42);
		// Если клиент не отправил
		if(client.write(view_t(outward.data(), outward.size())) != context::error_t::NONE)
			// Выводим отказ
			return false;
		// Переносим
		converse(client, server, records, widest);
		// Принятое
		vector <uint8_t> received;
		// Если сервер не принял ровно то, что отправлено
		if((server.read(received) != context::error_t::NONE) || (received != outward))
			// Выводим отказ
			return false;
		// Если сервер не отправил
		if(server.write(view_t(inward.data(), inward.size())) != context::error_t::NONE)
			// Выводим отказ
			return false;
		// Переносим
		converse(client, server, records, widest);
		// Если клиент не принял ровно то, что отправлено
		if((client.read(received) != context::error_t::NONE) || (received != inward))
			// Выводим отказ
			return false;
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод розыска расширения в открытом ServerHello издания 1.2
	 *
	 * @param answer вывод сервера
	 * @param type   вид расширения
	 * @param body   найденное тело
	 *
	 * @return       признак наличия расширения
	 *
	 */
	bool replied(const vector <uint8_t> & answer, const uint16_t type, vector <uint8_t> & body) noexcept {
		// Разбираем записи ответа
		record::reader_t reader;
		// Если записи не разобраны
		if(reader.push(view_t(answer.data(), answer.size())) != record::error_t::NONE)
			// Выводим отказ
			return false;
		// Заголовок и содержимое первой записи
		record::header_t header;
		view_t content;
		// Если первой записи нет
		if(reader.next(header, content) != record::error_t::NONE)
			// Выводим отказ
			return false;
		// Разбираем сообщение рукопожатия
		handshake::reader_t messages;
		// Если сообщение не разобрано
		if(messages.push(content) != handshake::error_t::NONE)
			// Выводим отказ
			return false;
		// Заголовок и тело первого сообщения
		handshake::header_t heading;
		view_t body_;
		// Если первого сообщения нет
		if(messages.next(heading, body_) != handshake::error_t::NONE)
			// Выводим отказ
			return false;
		// Приветствие сервера
		hello::server_t hello;
		// Если приветствие не разобрано
		if(hello::parse(body_, hello) != hello::error_t::NONE)
			// Выводим отказ
			return false;
		// Ищем расширение
		const hello::extension_t * item = hello::extension(hello.extensions, type);
		// Если расширения нет
		if(item == nullptr)
			// Выводим отказ
			return false;
		// Забираем тело
		body.assign(item->data.data, item->data.data + item->data.size);
		// Выводим успешность
		return true;
	}
	/**
	 * @brief Метод составления тела record_size_limit
	 *
	 * @param value предел
	 *
	 * @return      тело расширения
	 *
	 */
	vector <uint8_t> bounded(const uint16_t value) noexcept {
		// Выводим два байта
		return vector <uint8_t> {static_cast <uint8_t> (value >> 8), static_cast <uint8_t> (value & 0xFF)};
	}
	/**
	 * Виды расширений
	 */
	static constexpr uint16_t LIMIT = static_cast <uint16_t> (extension::type_t::LIMIT);
	static constexpr uint16_t FRAGMENT = static_cast <uint16_t> (extension::type_t::FRAGMENT);
};

/**
 * Проверка record_size_limit из профиля в изданиях 1.3 и 1.2: сервер режет отправку под предел
 * клиента (1023 полезных байта у 1.3 - предел считается с октетом вида, 1024 у 1.2), клиент
 * шлёт по своему умолчанию, данные доходят в обе стороны
 */
TEST(LimitTest, RecordSizeLimit){
	// Издания
	static const bool LEGACY[] = {false, true};
	/**
	 * Выполняем перебор изданий
	 */
	for(size_t i = 0; i < 2; i++){
		// Счётчики
		size_t records = 0, widest = 0;
		context::error_t failure = context::error_t::NONE;
		vector <uint8_t> answer;
		// Связь с пределом 1024 и переносом 5000 байтов в каждую сторону
		ASSERT_TRUE(transfer({LIMIT}, {bounded(1024)}, LEGACY[i], 5000, records, widest, failure, answer)) << "издание " << (LEGACY[i] ? "1.2" : "1.3") << " отказ " << static_cast <int> (failure);
		// Клиент шлёт одной записью (сервер объявил 16385/16384), сервер - не меньше чем пятью
		EXPECT_GE(records, 6u) << "издание " << (LEGACY[i] ? "1.2" : "1.3");
		// Наибольшая запись на проводе - клиентская, 5000 байтов плюс защита
		EXPECT_GE(widest, 5000u);
		// Пределы: клиент шлёт по протоколу и принимает под свой предел, сервер шлёт под предел клиента и принимает по протоколу
		EXPECT_EQ(LAST[0], 16384u) << (LEGACY[i] ? "1.2" : "1.3");
		EXPECT_EQ(LAST[1], (LEGACY[i] ? 1024u : 1023u)) << (LEGACY[i] ? "1.2" : "1.3");
		EXPECT_EQ(LAST[2], (LEGACY[i] ? 1024u : 1023u)) << (LEGACY[i] ? "1.2" : "1.3");
		EXPECT_EQ(LAST[3], 16384u) << (LEGACY[i] ? "1.2" : "1.3");
		// У издания 1.2 ответ виден: сервер вернул record_size_limit со своим пределом 16384
		if(LEGACY[i]){
			vector <uint8_t> body;
			ASSERT_TRUE(replied(answer, LIMIT, body));
			EXPECT_EQ(body, bounded(16384));
		}
	}
}

/**
 * Проверка строгости нарезки сервера под record_size_limit: при пределе 64 ни одна запись
 * сервера не длиннее 64 байтов полезного содержимого плюс защита, и всё доходит
 */
TEST(LimitTest, Tight){
	// Издания
	static const bool LEGACY[] = {false, true};
	/**
	 * Выполняем перебор изданий
	 */
	for(size_t i = 0; i < 2; i++){
		// Счётчики
		size_t records = 0, widest = 0;
		context::error_t failure = context::error_t::NONE;
		vector <uint8_t> answer;
		// Связь с наименьшим дозволенным пределом и переносом 700 байтов
		ASSERT_TRUE(transfer({LIMIT}, {bounded(64)}, LEGACY[i], 700, records, widest, failure, answer)) << "издание " << (LEGACY[i] ? "1.2" : "1.3") << " отказ " << static_cast <int> (failure);
		// Сервер режет 700 байтов не меньше чем на 11 записей (63 либо 64 байта в каждой), клиент - одной
		EXPECT_GE(records, 12u) << "издание " << (LEGACY[i] ? "1.2" : "1.3");
		// Пределы: наименьший дозволенный у отправки сервера и приёма клиента
		EXPECT_EQ(LAST[2], (LEGACY[i] ? 64u : 63u)) << (LEGACY[i] ? "1.2" : "1.3");
		EXPECT_EQ(LAST[1], (LEGACY[i] ? 64u : 63u)) << (LEGACY[i] ? "1.2" : "1.3");
	}
}

/**
 * Проверка max_fragment_length из профиля: код 1 (512 байтов) связывает обе стороны в обоих
 * изданиях, ни одна запись прикладных данных на проводе не длиннее 512 байтов с защитой
 */
TEST(LimitTest, MaxFragmentLength){
	// Издания
	static const bool LEGACY[] = {false, true};
	/**
	 * Выполняем перебор изданий
	 */
	for(size_t i = 0; i < 2; i++){
		// Счётчики
		size_t records = 0, widest = 0;
		context::error_t failure = context::error_t::NONE;
		vector <uint8_t> answer;
		// Связь с кодом 1 и переносом 5000 байтов в каждую сторону
		ASSERT_TRUE(transfer({FRAGMENT}, {vector <uint8_t> {0x01}}, LEGACY[i], 5000, records, widest, failure, answer)) << "издание " << (LEGACY[i] ? "1.2" : "1.3") << " отказ " << static_cast <int> (failure);
		// Обе стороны режут: не меньше чем по десять записей с каждой
		EXPECT_GE(records, 20u) << "издание " << (LEGACY[i] ? "1.2" : "1.3");
		// Ни одна запись не длиннее 512 байтов содержимого плюс защита (метка 16, октет вида, у 1.2 явный вектор 8)
		EXPECT_LE(widest, 512u + 32u) << "издание " << (LEGACY[i] ? "1.2" : "1.3");
		// Пределы: договорённая длина связывает обе стороны в обе стороны
		for(size_t j = 0; j < 4; j++)
			EXPECT_EQ(LAST[j], (LEGACY[i] ? 512u : 511u)) << (LEGACY[i] ? "1.2" : "1.3") << " " << j;
		// У издания 1.2 ответ виден: сервер вернул тот же код
		if(LEGACY[i]){
			vector <uint8_t> body;
			ASSERT_TRUE(replied(answer, FRAGMENT, body));
			EXPECT_EQ(body, (vector <uint8_t> {0x01}));
		}
	}
}

/**
 * Проверка обоих расширений разом в обоих порядках (раздел 5 RFC 8449): сервер отвечает лишь
 * record_size_limit, max_fragment_length без ответа, нарезка сервера - по record_size_limit
 */
TEST(LimitTest, Both){
	// Порядки предложения
	static const vector <uint16_t> ORDERS[] = {{LIMIT, FRAGMENT}, {FRAGMENT, LIMIT}};
	static const vector <vector <uint8_t>> BODIES[] = {{bounded(2048), {0x01}}, {{0x01}, bounded(2048)}};
	/**
	 * Выполняем перебор порядков
	 */
	for(size_t i = 0; i < 2; i++){
		// Счётчики
		size_t records = 0, widest = 0;
		context::error_t failure = context::error_t::NONE;
		vector <uint8_t> answer;
		// Связь издания 1.2 с переносом 5000 байтов
		ASSERT_TRUE(transfer(ORDERS[i], BODIES[i], true, 5000, records, widest, failure, answer)) << "порядок " << i << " отказ " << static_cast <int> (failure);
		// Ответ: record_size_limit есть, max_fragment_length нет
		vector <uint8_t> body;
		EXPECT_TRUE(replied(answer, LIMIT, body)) << "порядок " << i;
		EXPECT_FALSE(replied(answer, FRAGMENT, body)) << "порядок " << i;
		// Сервер режет по 2048: три записи на 5000 байтов, клиент - одной; не по 512
		EXPECT_GE(records, 4u) << "порядок " << i;
		EXPECT_LT(records, 10u) << "порядок " << i;
		// Пределы: по record_size_limit, не по max_fragment_length
		EXPECT_EQ(LAST[2], 2048u) << "порядок " << i;
		EXPECT_EQ(LAST[1], 2048u) << "порядок " << i;
		EXPECT_EQ(LAST[0], 16384u) << "порядок " << i;
		EXPECT_EQ(LAST[3], 16384u) << "порядок " << i;
		// Издание 1.3: то же, ответ скрыт, судим по нарезке и пределам
		records = 0;
		widest = 0;
		ASSERT_TRUE(transfer(ORDERS[i], BODIES[i], false, 5000, records, widest, failure, answer)) << "порядок " << i << " отказ " << static_cast <int> (failure);
		EXPECT_GE(records, 4u) << "порядок " << i;
		EXPECT_LT(records, 10u) << "порядок " << i;
		EXPECT_EQ(LAST[2], 2047u) << "порядок " << i;
		EXPECT_EQ(LAST[1], 2047u) << "порядок " << i;
		EXPECT_EQ(LAST[0], 16384u) << "порядок " << i;
		EXPECT_EQ(LAST[3], 16384u) << "порядок " << i;
	}
}

/**
 * Проверка негодных значений: предел меньше 64 и код длины вне 1…4 отвергаются сервером
 * извещением illegal_parameter, тело неверной длины - decode_error
 */
TEST(LimitTest, Refusals){
	// Негодные тела
	static const uint16_t TYPES[] = {LIMIT, FRAGMENT, LIMIT, FRAGMENT};
	static const vector <uint8_t> BODIES[] = {bounded(63), {0x05}, {0x01}, {0x01, 0x02}};
	static const alert::description_t ALERTS[] = {alert::description_t::PARAMETER, alert::description_t::PARAMETER, alert::description_t::DECODE, alert::description_t::DECODE};
	/**
	 * Выполняем перебор негодных тел
	 */
	for(size_t i = 0; i < 4; i++){
		// Полномочия и профиль
		context::credential_t credential;
		ASSERT_TRUE(keyfile("ec256", credential));
		fingerprint::profile_t profile;
		ASSERT_TRUE(profiling(profile, {TYPES[i]}, {BODIES[i]}));
		// Стороны
		client::context_t client;
		server::context_t server;
		client.name("example.com");
		ASSERT_EQ(client.profile(profile), context::error_t::NONE);
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Обмен
		size_t records = 0, widest = 0;
		converse(client, server, records, widest);
		// Сервер отказал нужным извещением, клиент связь не установил
		EXPECT_EQ(server.state(), context::state_t::FAILED) << i;
		EXPECT_EQ(server.alert().description, ALERTS[i]) << i;
		EXPECT_FALSE(client.established()) << i;
		// Отказал именно сервер: клиент сам ответа не отвергал
		EXPECT_NE(client.error(), context::error_t::PARAMETERS) << i;
		EXPECT_NE(client.error(), context::error_t::MESSAGE) << i;
	}
}

/**
 * @brief Метод проведения связи издания 1.2 с искажением открытого вывода сервера по дороге
 *
 * @param types   виды расширений предела у клиента
 * @param bodies  тела расширений предела
 * @param distort искажение первого вывода сервера (приветствие и цепочка открыты у 1.2)
 * @param client  клиент по итогу
 *
 */
static void hostile(const vector <uint16_t> & types, const vector <vector <uint8_t>> & bodies, const std::function <void (vector <uint8_t> &, const size_t)> & distort, client::context_t & client){
	// Полномочия и профиль
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	fingerprint::profile_t profile;
	ASSERT_TRUE(profiling(profile, types, bodies));
	// Сервер
	server::context_t server;
	client.name("example.com");
	ASSERT_EQ(client.profile(profile), context::error_t::NONE);
	server.credential(credential);
	ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Номер вывода сервера
	size_t flight = 0;
	/**
	 * Выполняем обмен, искажая каждый вывод сервера по дороге
	 */
	for(size_t i = 0; i < 16; i++){
		// Признак переноса
		bool moved = false;
		// Вывод клиента уходит серверу как есть
		{
			const view_t data = client.output();
			if(data.size > 0){
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				client.consume(buffer.size());
				server.push(view_t(buffer.data(), buffer.size()));
				moved = true;
			}
		}
		// Вывод сервера искажается
		{
			const view_t data = server.output();
			if(data.size > 0){
				vector <uint8_t> buffer(data.data, data.data + data.size);
				server.consume(buffer.size());
				distort(buffer, flight++);
				client.push(view_t(buffer.data(), buffer.size()));
				moved = true;
			}
		}
		// Если тишина, выходим
		if(!moved)
			break;
	}
}

/**
 * Проверка стражи приёма у клиента: подтверждённый предел 64 и склеенные по дороге открытые
 * записи рукопожатия сервера издания 1.2 (сертификат и далее в одну запись) - record_overflow
 */
TEST(LimitTest, Overflow){
	// Клиент
	client::context_t client;
	// Связь с пределом 64 и склейкой записей после приветствия сервера
	// Признак того, что склейка легла
	bool merged_ = false;
	// Связь с пределом 64: второй вывод сервера (билет 1.2 открытым, до смены набора) склеивается в одну запись
	hostile({LIMIT}, {bounded(64)}, [&merged_](vector <uint8_t> & buffer, const size_t flight){
		// Первый вывод (приветствие и цепочка) не трогаем: предел клиент применяет с разбора полёта
		if(flight != 1)
			return;
		// Склеиваем подряд идущие открытые записи рукопожатия, остальное оставляем как есть
		vector <uint8_t> rebuilt, merged;
		for(size_t offset = 0; (offset + 5) <= buffer.size();){
			const size_t length = ((static_cast <size_t> (buffer[offset + 3]) << 8) | buffer[offset + 4]);
			if(buffer[offset] == 0x16)
				merged.insert(merged.end(), buffer.begin() + static_cast <std::ptrdiff_t> (offset + 5), buffer.begin() + static_cast <std::ptrdiff_t> (offset + 5 + length));
			else {
				if(!merged.empty()){
					const uint8_t header[5] = {0x16, 0x03, 0x03, static_cast <uint8_t> (merged.size() >> 8), static_cast <uint8_t> (merged.size() & 0xFF)};
					rebuilt.insert(rebuilt.end(), header, header + 5);
					rebuilt.insert(rebuilt.end(), merged.begin(), merged.end());
					merged_ = (merged_ || (merged.size() > 64));
					merged.clear();
				}
				rebuilt.insert(rebuilt.end(), buffer.begin() + static_cast <std::ptrdiff_t> (offset), buffer.begin() + static_cast <std::ptrdiff_t> (offset + 5 + length));
			}
			offset += (5 + length);
		}
		if(!merged.empty()){
			const uint8_t header[5] = {0x16, 0x03, 0x03, static_cast <uint8_t> (merged.size() >> 8), static_cast <uint8_t> (merged.size() & 0xFF)};
			rebuilt.insert(rebuilt.end(), header, header + 5);
			rebuilt.insert(rebuilt.end(), merged.begin(), merged.end());
			merged_ = (merged_ || (merged.size() > 64));
		}
		buffer.swap(rebuilt);
	}, client);
	// Склейка легла: билет длиннее 64 байтов ушёл одной записью
	ASSERT_TRUE(merged_);
	// Клиент отверг запись сверх подтверждённого предела
	EXPECT_FALSE(client.established());
	EXPECT_EQ(client.error(), context::error_t::RECORD);
	EXPECT_EQ(client.alert().description, alert::description_t::OVERSIZE);
}

/**
 * Проверка строгости клиента к ответу: предел сервера меньше 64 и код длины, отличный от
 * предложенного, - illegal_parameter (раздел 4 RFC 8449, раздел 4 RFC 6066)
 */
TEST(LimitTest, Hostile){
	// Подмены: искомое тело в открытом приветствии сервера и подмена
	static const uint16_t TYPES[] = {LIMIT, FRAGMENT};
	static const vector <uint8_t> OFFERED[] = {bounded(1024), {0x01}};
	static const vector <uint8_t> SEEK[] = {{0x00, 0x1C, 0x00, 0x02, 0x40, 0x00}, {0x00, 0x01, 0x00, 0x01, 0x01}};
	static const vector <uint8_t> SWAP[] = {{0x00, 0x1C, 0x00, 0x02, 0x00, 0x20}, {0x00, 0x01, 0x00, 0x01, 0x02}};
	/**
	 * Выполняем перебор подмен
	 */
	for(size_t i = 0; i < 2; i++){
		// Клиент
		client::context_t client;
		// Признак того, что подмена легла
		bool swapped = false;
		// Связь с подменой ответа сервера
		hostile({TYPES[i]}, {OFFERED[i]}, [i, &swapped](vector <uint8_t> & buffer, const size_t flight){
			// Первая запись первого вывода - приветствие сервера, в нём ищем ответное расширение
			if(flight != 0)
				return;
			const size_t length = ((static_cast <size_t> (buffer[3]) << 8) | buffer[4]);
			for(size_t offset = 5; (offset + SEEK[i].size()) <= (5 + length); offset++){
				if(std::equal(SEEK[i].begin(), SEEK[i].end(), buffer.begin() + static_cast <std::ptrdiff_t> (offset))){
					std::copy(SWAP[i].begin(), SWAP[i].end(), buffer.begin() + static_cast <std::ptrdiff_t> (offset));
					swapped = true;
					break;
				}
			}
		}, client);
		// Подмена легла, клиент отверг ответ
		ASSERT_TRUE(swapped) << i;
		EXPECT_FALSE(client.established()) << i;
		EXPECT_EQ(client.error(), context::error_t::PARAMETERS) << i;
		EXPECT_EQ(client.alert().description, alert::description_t::PARAMETER) << i;
	}
}

/**
 * Проверка строгости клиента к двойному ответу (раздел 5 RFC 8449): предложены оба расширения,
 * сервер ответил record_size_limit, а по дороге в открытое приветствие 1.2 дописан ещё и
 * max_fragment_length - клиент отвечает illegal_parameter
 */
TEST(LimitTest, Doubled){
	// Места дописывания: в конец перечня расширений и в его начало (до ответа record_size_limit)
	static const bool TAIL[] = {true, false};
	/**
	 * Выполняем перебор мест дописывания
	 */
	for(size_t i = 0; i < 2; i++){
		// Клиент
		client::context_t client;
		// Признак того, что дописывание легло
		bool appended = false;
		// Связь с обоими расширениями и дописыванием ответа
		hostile({LIMIT, FRAGMENT}, {bounded(1024), {0x01}}, [i, &appended](vector <uint8_t> & buffer, const size_t flight){
			// Только первая запись первого вывода - приветствие сервера
			if(flight != 0)
				return;
			// Длина записи и сообщения
			const size_t length = ((static_cast <size_t> (buffer[3]) << 8) | buffer[4]);
			const size_t message = ((static_cast <size_t> (buffer[6]) << 16) | (static_cast <size_t> (buffer[7]) << 8) | buffer[8]);
			// Приветствие: издание 2, случайность 32, опознаватель сеанса 1+n, набор 2, сжатие 1, длина расширений 2
			size_t offset = (9 + 2 + 32);
			offset += (1 + buffer[offset]);
			offset += (2 + 1);
			// Длина расширений
			const size_t extensions = ((static_cast <size_t> (buffer[offset]) << 8) | buffer[offset + 1]);
			// Конец расширений совпадает с концом сообщения и записи
			if(((offset + 2 + extensions) != (9 + message)) || ((5 + length) != (9 + message)))
				return;
			// Дописываем max_fragment_length с кодом 1: в конец либо в начало перечня
			static const uint8_t ECHO[] = {0x00, 0x01, 0x00, 0x01, 0x01};
			buffer.insert(buffer.begin() + static_cast <std::ptrdiff_t> (TAIL[i] ? (5 + length) : (offset + 2)), ECHO, ECHO + sizeof(ECHO));
			// Поправляем длины: расширений, сообщения и записи
			buffer[offset] = static_cast <uint8_t> ((extensions + sizeof(ECHO)) >> 8);
			buffer[offset + 1] = static_cast <uint8_t> ((extensions + sizeof(ECHO)) & 0xFF);
			buffer[6] = static_cast <uint8_t> ((message + sizeof(ECHO)) >> 16);
			buffer[7] = static_cast <uint8_t> ((message + sizeof(ECHO)) >> 8);
			buffer[8] = static_cast <uint8_t> ((message + sizeof(ECHO)) & 0xFF);
			buffer[3] = static_cast <uint8_t> ((length + sizeof(ECHO)) >> 8);
			buffer[4] = static_cast <uint8_t> ((length + sizeof(ECHO)) & 0xFF);
			appended = true;
		}, client);
		// Дописывание легло, клиент отверг двойной ответ
		ASSERT_TRUE(appended) << i;
		EXPECT_FALSE(client.established()) << i;
		EXPECT_EQ(client.error(), context::error_t::PARAMETERS) << i;
		EXPECT_EQ(client.alert().description, alert::description_t::PARAMETER) << i;
	}
}

/**
 * Проверка чужим эталоном openssl: s_client -maxfraglen 512 против сервера A-NTS в изданиях
 * 1.3 и 1.2 - сервер отвечает тем же кодом и режет ответ HTTP под 512 байтов, openssl, строгий
 * к длине входящих записей, принимает ответ целиком
 */
TEST(LimitTest, Openssl){
	// Оснастка
	const toolkit_t toolkit = inspect();
	// Если openssl нет
	if(!toolkit.present){
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если s_client не знает -maxfraglen (старше 1.1.1)
	if(!listed("s_client", "maxfraglen")){
		GTEST_SKIP() << "openssl s_client без -maxfraglen";
	}
	// Полномочия
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	const std::string crt = std::string(CORPUS) + "/ec256.crt";
	// Издания
	static const char * FLAGS[] = {"-tls1_3", "-tls1_2"};
	static const bool AVAILABLE[] = {toolkit.tls13, toolkit.tls12};
	/**
	 * Выполняем перебор изданий
	 */
	for(size_t i = 0; i < 2; i++){
		// Если издания у openssl нет
		if(!AVAILABLE[i])
			// Пропускаем издание
			continue;
		// Порт
		uint16_t number = 0;
		const int listener = harbour(number);
		ASSERT_GE(listener, 0);
		// Журнал
		const std::string log = "/tmp/ants-limit-client-" + std::to_string(number) + ".log";
		// Запускаем клиента с пределом 512 и запросом
		ASSERT_TRUE(launch("(printf 'GET / HTTP/1.0\\r\\n\\r\\n'; sleep 2) | openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " " + FLAGS[i] + " -maxfraglen 512 -CAfile " + crt + " -servername localhost -ign_eof > " + log + " 2>&1", log, log + ".pid"));
		sentinel_t sentinel(log + ".pid");
		// Принимаем подключение
		const int fd = greeted(listener);
		ASSERT_GE(fd, 0);
		// Сервер
		server::context_t server;
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256});
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Если издание 1.2, ограничиваем
		if(i == 1){
			ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		}
		server.credential(credential);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Рукопожатие
		const bool complete = serve(server, fd);
		ASSERT_TRUE(complete) << "отказ " << static_cast <int> (server.error()) << " извещение " << static_cast <int> (server.alert().description);
		ASSERT_EQ(server.error(), context::error_t::NONE);
		/**
		 * Читаем запрос до пустой строки, каждое чтение ограничено опросом в 200 мс: s_client
		 * может слать его кусками, а openssl 3.0.18 на Solaris после договорённого
		 * max_fragment_length шлёт «GET» и стопорится вовсе (против s_server, который на
		 * расширение не отвечает, тот же клиент шлёт всё) - потому запрос здесь не обязателен,
		 * проверяется нарезка нашего ответа и его приём клиентом
		 */
		vector <uint8_t> request;
		for(size_t j = 0; (j < 16) && (string(request.begin(), request.end()).find("\r\n\r\n") == string::npos); j++){
			struct pollfd waiting;
			waiting.fd = fd;
			waiting.events = POLLIN;
			waiting.revents = 0;
			if(::poll(&waiting, 1, 200) <= 0)
				continue;
			uint8_t buffer[16384];
			const ssize_t received = ::recv(fd, buffer, sizeof(buffer), 0);
			if(received <= 0)
				break;
			ASSERT_EQ(server.push(view_t(buffer, static_cast <size_t> (received))), context::error_t::NONE);
			vector <uint8_t> piece;
			ASSERT_EQ(server.read(piece), context::error_t::NONE);
			request.insert(request.end(), piece.begin(), piece.end());
		}
		if(string(request.begin(), request.end()).find("GET /") == string::npos)
			std::cerr << "запрос от s_client неполный [" << string(request.begin(), request.end()) << "] - свойство клиента стенда, ответ шлётся всё равно" << std::endl;
		// Ответ длиннее предела: 3000 байтов тела
		const std::string body(3000, 'Z');
		const std::string reply = "HTTP/1.0 200 OK\r\nContent-Length: 3000\r\n\r\n" + body;
		ASSERT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> (reply.data()), reply.size())), context::error_t::NONE);
		// На проводе ни одной записи длиннее 512 байтов содержимого плюс защита
		{
			const view_t data = server.output();
			size_t widest = 0;
			for(size_t offset = 0; (offset + 5) <= data.size;){
				const size_t length = ((static_cast <size_t> (data.data[offset + 3]) << 8) | data.data[offset + 4]);
				widest = ((length > widest) ? length : widest);
				offset += (5 + length);
			}
			EXPECT_LE(widest, 512u + 32u) << FLAGS[i];
			(void) ::send(fd, data.data, data.size, 0);
			server.consume(data.size);
		}
		// Прощаемся
		ASSERT_TRUE(farewell(server, fd));
		::close(fd);
		::close(listener);
		// Клиент принял тело целиком
		std::string text;
		ASSERT_TRUE(settle(log, text)) << text;
		EXPECT_NE(text.find(body), std::string::npos) << FLAGS[i] << " " << text.substr(0, 400);
		EXPECT_EQ(text.find("record overflow"), std::string::npos) << text;
		::remove(log.c_str());
	}
}

/**
 * Проверка чужим эталоном gnutls: gnutls-serv --recordsize 512 отвечает record_size_limit со
 * своим пределом, клиент A-NTS по профилю с 0x001C режет отправку под 512, gnutls принимает и
 * отдаёт эхом
 */
TEST(LimitTest, Gnutls){
	// Если gnutls-serv нет
	if(::system("gnutls-serv --version >/dev/null 2>&1") != 0){
		GTEST_SKIP() << "gnutls-serv недоступен";
	}
	// Полномочия
	const std::string crt = std::string(CORPUS) + "/ec256.crt", key = std::string(CORPUS) + "/ec256.pem";
	// Порт
	const uint16_t number = vacant(false);
	ASSERT_NE(number, 0);
	// Журнал
	const std::string log = "/tmp/ants-limit-gnutls-" + std::to_string(number) + ".log";
	// Запускаем сервер с пределом 512 в режиме эха
	ASSERT_TRUE(launch("gnutls-serv --port " + std::to_string(number) + " --x509certfile " + crt + " --x509keyfile " + key + " --echo --recordsize 512 --priority NORMAL:+VERS-TLS1.3:+VERS-TLS1.2 > " + log + " 2>&1", log, log + ".pid"));
	sentinel_t sentinel(log + ".pid");
	// Подключаемся
	const int fd = dial(number);
	ASSERT_GE(fd, 0) << "порт " << number;
	// Профиль с record_size_limit 16385
	fingerprint::profile_t profile;
	ASSERT_TRUE(profiling(profile, {LIMIT}, {bounded(16385)}));
	// Клиент
	client::context_t client;
	client.name("localhost");
	ASSERT_EQ(client.profile(profile), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Рукопожатие
	for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
		relay(client, fd);
	if(!client.established()){ std::string journal; (void) settle(log, journal); ADD_FAILURE() << journal; }
	ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
	// Шлём 3000 байтов: без нарезки под 512 gnutls ответил бы record_overflow
	const std::string message(2999, 'Q');
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ((message + "\n").data()), message.size() + 1)), context::error_t::NONE);
	// На проводе ни одной записи длиннее 512 байтов содержимого плюс защита
	{
		const view_t data = client.output();
		size_t widest = 0, count = 0;
		for(size_t offset = 0; (offset + 5) <= data.size;){
			const size_t length = ((static_cast <size_t> (data.data[offset + 3]) << 8) | data.data[offset + 4]);
			widest = ((length > widest) ? length : widest);
			count++;
			offset += (5 + length);
		}
		EXPECT_LE(widest, 512u + 32u);
		EXPECT_GE(count, 6u);
	}
	// Читаем эхо
	vector <uint8_t> echo;
	for(size_t i = 0; (i < 32) && (echo.size() < message.size()); i++){
		relay(client, fd);
		vector <uint8_t> piece;
		ASSERT_EQ(client.read(piece), context::error_t::NONE) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		echo.insert(echo.end(), piece.begin(), piece.end());
	}
	EXPECT_GE(echo.size(), message.size());
	EXPECT_EQ(string(echo.begin(), echo.begin() + static_cast <long> (std::min(echo.size(), message.size()))), message.substr(0, std::min(echo.size(), message.size())));
	::close(fd);
	sentinel.halt();
	std::string journal;
	(void) settle(log, journal);
	::remove(log.c_str());
}
