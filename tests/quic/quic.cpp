/**
 * @file quic.cpp
 * @date 2026-09-04
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
 * @brief Исходный файл проверок рукопожатия по уровням защиты для QUIC (RFC 9001):
 *        петлевое рукопожатие сообщениями по уровням, секреты уровней, параметры переноса,
 *        упреждающие данные без конца, кодек билета, отказы и нехватка памяти
 *
 * @note Эталоном секретов служат RFC 8448 (расписание над значениями направлений) и
 *       запись того же расписания на записях: значение, выданное наружу, обязано снимать
 *       защиту с записи, сложенной движком переносом записями
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include "rfc8448.hpp"
#include <pem/pem.hpp>
#include <record/record.hpp>
#include <message/message.hpp>
#include <handshake/handshake.hpp>
#include <protect/protect.hpp>
#include <session/session.hpp>
#include <schedule/schedule.hpp>
#include <extension/extension.hpp>
#include <digest/hash.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору ключей для сличения
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * @brief Метод разбора области байтов из шестнадцатеричной записи
	 *
	 * @param text шестнадцатеричная запись области байтов
	 *
	 * @return     разобранная область байтов
	 *
	 */
	vector <uint8_t> decode(const char * text) noexcept {
		// Разобранная область байтов
		vector <uint8_t> result;
		/**
		 * Выполняем перебор пар символов записи
		 */
		for(size_t i = 0; text[i] != '\0' && text[i + 1] != '\0'; i += 2)
			// Добавляем очередной разобранный байт
			result.push_back(static_cast <uint8_t> (::strtoul(string(text + i, 2).c_str(), nullptr, 16)));
		// Выводим разобранную область байтов
		return result;
	}
	/**
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 *
	 * @return     содержимое файла набора
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Открываем файл набора на чтение
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Содержимое файла набора
		vector <uint8_t> result;
		// Если файл набора открыт
		if(file.is_open())
			// Переносим содержимое файла набора
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое файла набора
		return result;
	}
	/**
	 * @brief Метод составления подлинности стороны из ключей набора
	 *
	 * @param name   имя ключа набора: rsa2048, ec256, ec384 либо ed25519
	 * @param result подлинность, в которую помещается итог
	 *
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool identity(const char * name, context::credential_t & result) noexcept {
		// Читаем секретный ключ набора в записи PEM
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Читаем сертификат набора в записи PEM
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Если ключ либо сертификат не прочитаны
		if(result.secret.empty() || text.empty())
			// Выводим отказ составления подлинности
			return false;
		// Выполняем сброс цепочки сертификатов
		result.chain.clear();
		// Выводим итог разбора цепочки сертификатов из записи PEM
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * Уровни защиты, несущие сообщения рукопожатия, в порядке подачи
	 */
	static const context::level_t LEVELS[] = {context::level_t::INITIAL, context::level_t::HANDSHAKE, context::level_t::APPLICATION};
	/**
	 * @brief Метод переноса сообщений одного уровня от одной стороны к другой
	 *
	 * @param from  связь стороны, отдающей сообщения
	 * @param to    связь стороны, принимающей сообщения
	 * @param level уровень защиты переносимых сообщений
	 *
	 * @return      признак того, что сообщения переносились
	 *
	 */
	template <typename A, typename B>
	bool carry(A & from, B & to, const context::level_t level) noexcept {
		// Получаем сообщения, отправляемые на уровне
		const view_t data = from.output(level);
		// Если отправлять на уровне нечего
		if(data.size == 0)
			// Выводим признак того, что сообщения не переносились
			return false;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Выполняем перенос отправляемых сообщений
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем отправленные сообщения с накопителя уровня
			from.consume(level, buffer.size());
			// Выполняем подачу сообщений принимающей стороне на том же уровне
			to.push(level, view_t(buffer.data(), buffer.size()));
		/**
		 * Если памяти под перенос сообщений не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим признак того, что сообщения не переносились
			return false;
		}
		// Выводим признак того, что сообщения переносились
		return true;
	}
	/**
	 * @brief Метод передачи сообщений между сторонами по всем уровням защиты
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что сообщения между сторонами передавались
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Признак того, что сообщения между сторонами передавались
		bool moved = false;
		/**
		 * Выполняем перебор уровней защиты в порядке их следования
		 */
		for(size_t i = 0; i < (sizeof(LEVELS) / sizeof(LEVELS[0])); i++)
			// Переносим сообщения уровня от клиента к серверу
			moved = (carry(client, server, LEVELS[i]) || moved);
		/**
		 * Выполняем перебор уровней защиты в порядке их следования
		 */
		for(size_t i = 0; i < (sizeof(LEVELS) / sizeof(LEVELS[0])); i++)
			// Переносим сообщения уровня от сервера к клиенту
			moved = (carry(server, client, LEVELS[i]) || moved);
		// Выводим признак того, что сообщения между сторонами передавались
		return moved;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон связи по уровням
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 */
	void converse(client::context_t & client, server::context_t & server) noexcept {
		/**
		 * Выполняем передачу сообщений между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			// Продолжаем передачу сообщений между сторонами связи
			continue;
	}
	/**
	 * Параметры переноса клиента: содержимое связью не толкуется
	 */
	static const vector <uint8_t> CLIENT_PARAMETERS = {0x01, 0x04, 0x80, 0x00, 0xFF, 0xFF, 0x04, 0x04, 0x80, 0x10, 0x00, 0x00};
	/**
	 * Параметры переноса сервера: содержимое связью не толкуется
	 */
	static const vector <uint8_t> SERVER_PARAMETERS = {0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x03, 0x02, 0x45, 0xAC};
	/**
	 * @brief Метод настройки сторон связи под перенос по уровням
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param suite      набор шифрования обеих сторон
	 * @param group      группа обмена обеих сторон
	 * @param credential подлинность сервера и клиента
	 * @param mutual     запрашивается ли подлинность клиента
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const protect::suite_t suite, const extension::group_t group, const context::credential_t & credential, const bool mutual) noexcept {
		// Устанавливаем перенос по уровням клиенту
		client.transport(context::transport_t::LEVELS);
		// Устанавливаем перенос по уровням серверу
		server.transport(context::transport_t::LEVELS);
		// Устанавливаем набор шифрования клиенту
		client.suites(vector <protect::suite_t> {suite});
		// Устанавливаем набор шифрования серверу
		server.suites(vector <protect::suite_t> {suite});
		// Устанавливаем группу обмена клиенту
		client.groups(vector <extension::group_t> {group});
		// Устанавливаем группу обмена серверу
		server.groups(vector <extension::group_t> {group});
		// Устанавливаем прикладной протокол клиенту
		client.protocols(vector <string> {"h3"});
		// Устанавливаем прикладной протокол серверу
		server.protocols(vector <string> {"h3"});
		// Устанавливаем параметры переноса клиенту
		client.parameters(CLIENT_PARAMETERS);
		// Устанавливаем параметры переноса серверу
		server.parameters(SERVER_PARAMETERS);
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Если запрашивается подлинность клиента
		if(mutual){
			// Требуем подлинность клиента
			server.request(true);
			// Устанавливаем подлинность клиента
			client.credential(credential);
		}
	}
	/**
	 * @brief Метод получения значения направления связи стороны
	 *
	 * @param context   связь стороны
	 * @param level     уровень защиты значения
	 * @param direction направление связи относительно стороны
	 *
	 * @return          значение направления либо пустой перечень
	 *
	 */
	template <typename T>
	vector <uint8_t> traffic(const T & context, const context::level_t level, const context::direction_t direction) noexcept {
		// Место, в которое помещается значение направления
		uint8_t buffer[schedule::SCHEDULE_WIDEST];
		// Длина значения направления
		size_t size = 0;
		// Если значение направления ещё не выведено
		if(!context.secret(level, direction, buffer, size))
			// Выводим пустой перечень
			return vector <uint8_t> ();
		// Выводим значение направления
		return vector <uint8_t> (buffer, buffer + size);
	}
	/**
	 * @brief Метод составления сообщения рукопожатия с обвязкой
	 *
	 * @param type вид сообщения рукопожатия
	 * @param body тело сообщения рукопожатия
	 *
	 * @return     сообщение рукопожатия с обвязкой
	 *
	 */
	vector <uint8_t> compose(const handshake::type_t type, const vector <uint8_t> & body) noexcept {
		// Составитель сообщения рукопожатия
		handshake::writer_t writer;
		// Если сообщение составить не удалось
		if(writer.push(type, view_t(body.data(), body.size())) != handshake::error_t::NONE)
			// Выводим пустой перечень
			return vector <uint8_t> ();
		// Получаем составленное сообщение
		const view_t data = writer.data();
		// Выводим составленное сообщение
		return vector <uint8_t> (data.data, data.data + data.size);
	}
	/**
	 * Наборы шифрования перебора
	 */
	static const protect::suite_t SUITES[] = {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::CHACHA20_POLY1305_SHA256};
	/**
	 * Группы обмена перебора
	 */
	static const extension::group_t GROUPS[] = {extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1};
	/**
	 * Ключи набора
	 */
	static const char * ENTRIES[] = {"rsa2048", "ec256", "ec384", "ed25519"};
};

/**
 * Проверка петлевого рукопожатия по уровням: все наборы, группы и ключи с подлинностью
 * клиента, параметры переноса в обе стороны, секреты уровней с обеих сторон, билет на
 * уровне прикладных данных, возобновление и упреждающие данные без их конца
 */
TEST(QuicTest, Loopback){
	/**
	 * Выполняем перебор ключей набора
	 */
	for(size_t k = 0; k < (sizeof(ENTRIES) / sizeof(ENTRIES[0])); k++){
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность из ключей набора
		ASSERT_TRUE(identity(ENTRIES[k], credential)) << "ключ " << ENTRIES[k];
		/**
		 * Выполняем перебор наборов шифрования
		 */
		for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
			// Длина значений направлений по хешу набора
			const size_t width = digest::length(protect::hash(SUITES[s]));
			/**
			 * Выполняем перебор групп обмена
			 */
			for(size_t g = 0; g < (sizeof(GROUPS) / sizeof(GROUPS[0])); g++){
				// Связь стороны клиента
				client::context_t client;
				// Связь стороны сервера
				server::context_t server;
				// Настраиваем стороны с подлинностью клиента
				arrange(client, server, SUITES[s], GROUPS[g], credential, true);
				// Разрешаем упреждающие данные выдаваемым билетом
				server.advance(true, 4096);
				// Проверяем способ переноса клиента
				ASSERT_EQ(client.transport(), context::transport_t::LEVELS);
				// Проверяем отсутствие уровня до заведения связи
				ASSERT_EQ(client.level(context::direction_t::WRITE), context::level_t::NONE);
				// Заводим сервер
				ASSERT_EQ(server.start(), context::error_t::NONE) << ENTRIES[k] << " " << s << " " << g;
				// Заводим клиента
				ASSERT_EQ(client.start(), context::error_t::NONE) << ENTRIES[k] << " " << s << " " << g;
				// Проверяем начальный уровень записи клиента
				ASSERT_EQ(client.level(context::direction_t::WRITE), context::level_t::INITIAL);
				// Проверяем, что приветствие клиента лежит на начальном уровне
				ASSERT_GT(client.output(context::level_t::INITIAL).size, static_cast <size_t> (0));
				// Проверяем, что приветствие клиента начинается видом ClientHello
				ASSERT_EQ(client.output(context::level_t::INITIAL).data[0], static_cast <uint8_t> (handshake::type_t::CLIENT));
				// Проверяем пустоту прочих уровней клиента
				ASSERT_EQ(client.output(context::level_t::HANDSHAKE).size, static_cast <size_t> (0));
				// Проверяем недоступность секретов до приветствия сервера
				ASSERT_TRUE(traffic(client, context::level_t::HANDSHAKE, context::direction_t::WRITE).empty());
				// Переносим приветствие клиента серверу
				ASSERT_TRUE(carry(client, server, context::level_t::INITIAL));
				// Проверяем, что приветствие сервера лежит на начальном уровне
				ASSERT_EQ(server.output(context::level_t::INITIAL).data[0], static_cast <uint8_t> (handshake::type_t::SERVER));
				// Проверяем, что выход сервера лежит на уровне рукопожатия
				ASSERT_EQ(server.output(context::level_t::HANDSHAKE).data[0], static_cast <uint8_t> (handshake::type_t::EXTENSIONS));
				// Проверяем уровень записи сервера: выход ушёл, сервер уже на прикладных ключах
				ASSERT_EQ(server.level(context::direction_t::WRITE), context::level_t::APPLICATION);
				// Проверяем уровень чтения сервера: за приветствием сервера клиент отвечает ключами рукопожатия
				ASSERT_EQ(server.level(context::direction_t::READ), context::level_t::HANDSHAKE);
				// Проверяем готовность секретов рукопожатия сервера
				ASSERT_EQ(traffic(server, context::level_t::HANDSHAKE, context::direction_t::WRITE).size(), width);
				// Проверяем готовность секретов прикладных данных сервера
				ASSERT_EQ(traffic(server, context::level_t::APPLICATION, context::direction_t::READ).size(), width);
				// Проводим рукопожатие до конца
				converse(client, server);
				// Проверяем установленность связи клиентом
				ASSERT_TRUE(client.established()) << ENTRIES[k] << " " << s << " " << g << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
				// Проверяем установленность связи сервером
				ASSERT_TRUE(server.established()) << ENTRIES[k] << " " << s << " " << g;
				// Проверяем набор шифрования
				ASSERT_EQ(client.suite(), SUITES[s]);
				// Проверяем схождение наборов сторон
				ASSERT_EQ(server.suite(), SUITES[s]);
				// Проверяем прикладной протокол клиента
				ASSERT_EQ(client.protocol(), "h3");
				// Проверяем прикладной протокол сервера
				ASSERT_EQ(server.protocol(), "h3");
				// Проверяем цепочку сервера у клиента
				ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
				// Проверяем цепочку клиента у сервера
				ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
				// Проверяем приём параметров переноса клиентом
				ASSERT_TRUE(client.acquired());
				// Проверяем приём параметров переноса сервером
				ASSERT_TRUE(server.acquired());
				// Проверяем параметры сервера у клиента
				ASSERT_EQ(client.parameters(), SERVER_PARAMETERS);
				// Проверяем параметры клиента у сервера
				ASSERT_EQ(server.parameters(), CLIENT_PARAMETERS);
				// Проверяем уровни обеих сторон по установлении связи
				ASSERT_EQ(client.level(context::direction_t::WRITE), context::level_t::APPLICATION);
				// Проверяем уровень чтения клиента
				ASSERT_EQ(client.level(context::direction_t::READ), context::level_t::APPLICATION);
				// Проверяем уровень чтения сервера
				ASSERT_EQ(server.level(context::direction_t::READ), context::level_t::APPLICATION);
				/**
				 * Выполняем перебор уровней рукопожатия и прикладных данных
				 */
				for(size_t l = 1; l < (sizeof(LEVELS) / sizeof(LEVELS[0])); l++){
					// Значение записи клиента
					const vector <uint8_t> cw = traffic(client, LEVELS[l], context::direction_t::WRITE);
					// Значение чтения клиента
					const vector <uint8_t> cr = traffic(client, LEVELS[l], context::direction_t::READ);
					// Значение записи сервера
					const vector <uint8_t> sw = traffic(server, LEVELS[l], context::direction_t::WRITE);
					// Значение чтения сервера
					const vector <uint8_t> sr = traffic(server, LEVELS[l], context::direction_t::READ);
					// Проверяем длину значения по хешу набора
					ASSERT_EQ(cw.size(), width) << "уровень " << l;
					// Проверяем схождение записи клиента с чтением сервера
					ASSERT_EQ(cw, sr) << "уровень " << l;
					// Проверяем схождение чтения клиента с записью сервера
					ASSERT_EQ(cr, sw) << "уровень " << l;
					// Проверяем различие направлений
					ASSERT_NE(cw, cr) << "уровень " << l;
				}
				// Проверяем различие значений рукопожатия и прикладных данных
				ASSERT_NE(traffic(client, context::level_t::HANDSHAKE, context::direction_t::WRITE), traffic(client, context::level_t::APPLICATION, context::direction_t::WRITE));
				// Проверяем отсутствие значения упреждения на полном рукопожатии
				ASSERT_TRUE(traffic(client, context::level_t::EARLY, context::direction_t::WRITE).empty());
				// Проверяем отсутствие значения начального уровня: его выводит перенос
				ASSERT_TRUE(traffic(client, context::level_t::INITIAL, context::direction_t::WRITE).empty());
				// Проверяем, что упреждение не предлагалось и не отвергалось
				ASSERT_FALSE(client.rejected());
				// Проверяем, что прикладные данные записями не идут
				ASSERT_EQ(client.write(view_t(CLIENT_PARAMETERS.data(), CLIENT_PARAMETERS.size())), context::error_t::STATE);
				// Проверяем, что смена ключей сообщением не делается
				ASSERT_EQ(client.update(true), context::error_t::STATE);
				// Проверяем, что закрытие извещением не делается
				ASSERT_EQ(server.close(), context::error_t::STATE);
				// Проверяем, что связь осталась установленной
				ASSERT_TRUE(client.established() && server.established());
				// Выдаём билет
				ASSERT_EQ(server.issue(), context::error_t::NONE);
				// Проверяем, что билет лежит на уровне прикладных данных
				ASSERT_EQ(server.output(context::level_t::APPLICATION).data[0], static_cast <uint8_t> (handshake::type_t::TICKET));
				// Проверяем пустоту уровня рукопожатия сервера
				ASSERT_EQ(server.output(context::level_t::HANDSHAKE).size, static_cast <size_t> (0));
				// Доставляем билет
				converse(client, server);
				// Проверяем получение билета клиентом
				ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
				// Проверяем набор билета
				ASSERT_EQ(client.tickets()[0].suite, SUITES[s]);
				// Проверяем предел упреждения билета
				ASSERT_EQ(client.tickets()[0].advance, static_cast <uint32_t> (4096));
				// Проверяем параметры переноса сервера в билете
				ASSERT_EQ(client.tickets()[0].parameters, SERVER_PARAMETERS);
				// Связь возобновляющего клиента
				client::context_t resuming;
				// Связь возобновляющего сервера
				server::context_t resumed;
				// Настраиваем стороны без подлинности клиента
				arrange(resuming, resumed, SUITES[s], GROUPS[g], credential, false);
				// Предъявляем билет
				resuming.resume(client.tickets()[0]);
				// Признаём билеты
				resumed.resume(server.tickets());
				// Предлагаем упреждающие данные
				resuming.advance(true);
				// Принимаем упреждающие данные
				resumed.advance(true, 4096);
				// Заводим сервер
				ASSERT_EQ(resumed.start(), context::error_t::NONE);
				// Заводим клиента
				ASSERT_EQ(resuming.start(), context::error_t::NONE);
				// Проверяем ход упреждения у клиента
				ASSERT_TRUE(resuming.earlying());
				// Проверяем уровень записи клиента: упреждение
				ASSERT_EQ(resuming.level(context::direction_t::WRITE), context::level_t::EARLY);
				// Значение упреждения клиента
				const vector <uint8_t> early = traffic(resuming, context::level_t::EARLY, context::direction_t::WRITE);
				// Проверяем длину значения упреждения по хешу набора билета
				ASSERT_EQ(early.size(), width);
				// Проверяем отсутствие значения упреждения на чтение у клиента
				ASSERT_TRUE(traffic(resuming, context::level_t::EARLY, context::direction_t::READ).empty());
				// Переносим приветствие клиента серверу
				ASSERT_TRUE(carry(resuming, resumed, context::level_t::INITIAL));
				// Проверяем приём упреждения сервером
				ASSERT_TRUE(resumed.accepted());
				// Проверяем ход упреждения у сервера
				ASSERT_TRUE(resumed.earlying());
				// Проверяем уровень чтения сервера: ответ клиента ждётся ключами рукопожатия, упреждение идёт своим уровнем
				ASSERT_EQ(resumed.level(context::direction_t::READ), context::level_t::HANDSHAKE);
				// Проверяем схождение значения упреждения сервера с клиентским
				ASSERT_EQ(traffic(resumed, context::level_t::EARLY, context::direction_t::READ), early);
				// Проверяем отсутствие значения упреждения на запись у сервера
				ASSERT_TRUE(traffic(resumed, context::level_t::EARLY, context::direction_t::WRITE).empty());
				// Переносим приветствие сервера клиенту
				ASSERT_TRUE(carry(resumed, resuming, context::level_t::INITIAL));
				// Проверяем, что клиент по приветствию сервера упреждение ещё ведёт
				ASSERT_TRUE(resuming.earlying());
				// Переносим выход сервера клиенту
				ASSERT_TRUE(carry(resumed, resuming, context::level_t::HANDSHAKE));
				// Проверяем приём упреждения клиентом
				ASSERT_TRUE(resuming.accepted());
				// Проверяем, что упреждение не отвергнуто
				ASSERT_FALSE(resuming.rejected());
				// Проверяем, что за завершением клиента упреждение окончено
				ASSERT_FALSE(resuming.earlying());
				// Проверяем, что ответ клиента начинается завершением: конца упреждения нет
				ASSERT_EQ(resuming.output(context::level_t::HANDSHAKE).data[0], static_cast <uint8_t> (handshake::type_t::FINISHED));
				// Переносим завершение клиента серверу
				ASSERT_TRUE(carry(resuming, resumed, context::level_t::HANDSHAKE));
				// Проверяем, что сервер упреждение окончил
				ASSERT_FALSE(resumed.earlying());
				// Проверяем установленность связи
				ASSERT_TRUE(resuming.established() && resumed.established()) << ENTRIES[k] << " " << s << " " << g << " " << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
				// Проверяем возобновление билетом
				ASSERT_TRUE(resuming.shared() && resumed.shared());
				// Проверяем параметры переноса возобновлённой связи
				ASSERT_EQ(resuming.parameters(), SERVER_PARAMETERS);
				// Проверяем схождение прикладных значений возобновлённой связи
				ASSERT_EQ(traffic(resuming, context::level_t::APPLICATION, context::direction_t::WRITE), traffic(resumed, context::level_t::APPLICATION, context::direction_t::READ));
				// Проверяем, что значение упреждения по-прежнему доступно
				ASSERT_EQ(traffic(resuming, context::level_t::EARLY, context::direction_t::WRITE), early);
			}
		}
	}
}

/**
 * Проверка просьбы о повторе приветствия по уровням: обе просьбы идут начальным уровнем
 */
TEST(QuicTest, Retry){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
	// Клиент поддерживает обе группы
	client.groups(vector <extension::group_t> {extension::group_t::X25519, extension::group_t::SECP256R1});
	// Доля ключа идёт лишь по X25519
	client.shares(vector <extension::group_t> {extension::group_t::X25519});
	// Сервер признаёт лишь P-256
	server.groups(vector <extension::group_t> {extension::group_t::SECP256R1});
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Переносим приветствие клиента
	ASSERT_TRUE(carry(client, server, context::level_t::INITIAL));
	// Проверяем, что просьба о повторе лежит на начальном уровне
	ASSERT_EQ(server.output(context::level_t::INITIAL).data[0], static_cast <uint8_t> (handshake::type_t::SERVER));
	// Проверяем, что выхода сервера на уровне рукопожатия ещё нет
	ASSERT_EQ(server.output(context::level_t::HANDSHAKE).size, static_cast <size_t> (0));
	// Переносим просьбу о повторе клиенту
	ASSERT_TRUE(carry(server, client, context::level_t::INITIAL));
	// Проверяем, что повторное приветствие лежит на начальном уровне
	ASSERT_EQ(client.output(context::level_t::INITIAL).data[0], static_cast <uint8_t> (handshake::type_t::CLIENT));
	// Проводим рукопожатие до конца
	converse(client, server);
	// Проверяем установленность связи
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	// Проверяем параметры переноса после повтора
	ASSERT_EQ(server.parameters(), CLIENT_PARAMETERS);
	// Проверяем схождение значений рукопожатия
	ASSERT_EQ(traffic(client, context::level_t::HANDSHAKE, context::direction_t::WRITE), traffic(server, context::level_t::HANDSHAKE, context::direction_t::READ));
}

/**
 * Проверка сличения выданных секретов с расписанием на записях: значение, выданное наружу
 * переносом записями, снимает защиту с записи, сложенной защитой записей того же движка; вывод
 * ключа и вектора из значения направления сверен с RFC 8448 байт в байт
 */
TEST(QuicTest, Records){
	// Набор шифрования следа RFC 8448
	const protect::suite_t suite = protect::suite_t::AES_128_GCM_SHA256;
	// Значение направления сервера на ступени рукопожатия из RFC 8448
	const vector <uint8_t> reference = decode(rfc8448::S3_S_HS);
	// Ключ и вектор замены
	uint8_t key[protect::PROTECT_KEY], vector_[protect::PROTECT_VECTOR];
	// Выводим ключевой материал из значения направления RFC 8448
	ASSERT_EQ(session::material(view_t(reference.data(), reference.size()), suite, key, vector_), session::error_t::NONE);
	// Проверяем схождение ключа с RFC 8448
	ASSERT_EQ(vector <uint8_t> (key, key + 16), decode(rfc8448::S3_S_HS_KEY));
	// Проверяем схождение вектора с RFC 8448
	ASSERT_EQ(vector <uint8_t> (vector_, vector_ + 12), decode(rfc8448::S3_S_HS_IV));
	// Значение прикладных данных сервера из RFC 8448
	const vector <uint8_t> applied = decode(rfc8448::S3_S_AP);
	// Выводим ключевой материал прикладных данных из RFC 8448
	ASSERT_EQ(session::material(view_t(applied.data(), applied.size()), suite, key, vector_), session::error_t::NONE);
	// Проверяем схождение прикладного ключа с RFC 8448
	ASSERT_EQ(vector <uint8_t> (key, key + 16), decode(rfc8448::S3_S_AP_KEY));
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("rsa2048", credential));
	/**
	 * Выполняем перебор наборов шифрования
	 */
	for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
		// Связь стороны клиента переносом записями
		client::context_t client;
		// Связь стороны сервера переносом записями
		server::context_t server;
		// Устанавливаем набор шифрования клиенту
		client.suites(vector <protect::suite_t> {SUITES[s]});
		// Устанавливаем набор шифрования серверу
		server.suites(vector <protect::suite_t> {SUITES[s]});
		// Устанавливаем группу обмена клиенту
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Устанавливаем группу обмена серверу
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Проверяем способ переноса по умолчанию
		ASSERT_EQ(client.transport(), context::transport_t::RECORDS);
		// Проверяем, что подача по уровням переносу записями отвергается
		ASSERT_EQ(client.push(context::level_t::INITIAL, view_t(CLIENT_PARAMETERS.data(), CLIENT_PARAMETERS.size())), context::error_t::STATE);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проверяем, что подача по уровням переносу записями отвергается без обрыва
		ASSERT_EQ(client.push(context::level_t::INITIAL, view_t(CLIENT_PARAMETERS.data(), CLIENT_PARAMETERS.size())), context::error_t::LEVEL);
		// Проверяем, что связь не оборвана
		ASSERT_EQ(client.state(), context::state_t::HANDSHAKE);
		// Приветствие клиента записью
		const view_t greeting = client.output();
		// Переносим приветствие клиента
		const vector <uint8_t> hello(greeting.data, greeting.data + greeting.size);
		// Снимаем приветствие с накопителя клиента
		client.consume(hello.size());
		// Подаём приветствие серверу
		ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
		// Проверяем готовность значений рукопожатия сервера переносом записями
		ASSERT_EQ(traffic(server, context::level_t::HANDSHAKE, context::direction_t::WRITE).size(), digest::length(protect::hash(SUITES[s])));
		// Выход сервера записями
		const view_t flight = server.output();
		// Переносим выход сервера
		const vector <uint8_t> wire(flight.data, flight.data + flight.size);
		// Сборщик записей выхода сервера
		record::reader_t records;
		// Собираем записи выхода сервера
		ASSERT_EQ(records.push(view_t(wire.data(), wire.size())), record::error_t::NONE);
		// Заголовок записи
		record::header_t header;
		// Содержимое записи
		view_t payload;
		// Читаем приветствие сервера: оно идёт открытым
		ASSERT_EQ(records.next(header, payload), record::error_t::NONE);
		// Проверяем вид открытой записи
		ASSERT_EQ(header.type, record::type_t::HANDSHAKE);
		// Читаем следующую запись
		ASSERT_EQ(records.next(header, payload), record::error_t::NONE);
		// Если это запись смены набора шифрования, читаем следующую
		if(header.type == record::type_t::CHANGE){
			// Читаем защищённую запись выхода сервера
			ASSERT_EQ(records.next(header, payload), record::error_t::NONE);
		}
		// Проверяем, что запись защищена: снаружи она прикладная
		ASSERT_EQ(header.type, record::type_t::APPLICATION);
		// Значение направления сервера на ступени рукопожатия, выданное наружу
		const vector <uint8_t> secret = traffic(server, context::level_t::HANDSHAKE, context::direction_t::WRITE);
		// Выводим ключевой материал из выданного значения
		ASSERT_EQ(session::material(view_t(secret.data(), secret.size()), SUITES[s], key, vector_), session::error_t::NONE);
		// Защита принимающей стороны на выведенном материале
		protect::protection_t receiver;
		// Заводим защиту принимающей стороны
		ASSERT_TRUE(receiver.start(SUITES[s], view_t(key, protect::key(SUITES[s])), view_t(vector_, protect::block(SUITES[s]))));
		// Истинный вид содержимого записи
		record::type_t type = record::type_t::NONE;
		// Накопитель открытого содержимого
		vector <uint8_t> opened;
		// Снимаем защиту с выхода сервера выданным наружу значением
		ASSERT_EQ(receiver.open(header, payload, type, opened), protect::error_t::NONE) << "набор " << s;
		// Проверяем вид содержимого выхода сервера
		ASSERT_EQ(type, record::type_t::HANDSHAKE);
		// Проверяем, что выход сервера начинается защищёнными расширениями
		ASSERT_EQ(opened[0], static_cast <uint8_t> (handshake::type_t::EXTENSIONS));
		// Подаём выход сервера клиенту
		ASSERT_EQ(client.push(view_t(wire.data(), wire.size())), context::error_t::NONE);
		// Снимаем выход с накопителя сервера
		server.consume(wire.size());
		// Ответ клиента записями
		const view_t answer = client.output();
		// Переносим ответ клиента
		const vector <uint8_t> reply(answer.data, answer.data + answer.size);
		// Снимаем ответ с накопителя клиента
		client.consume(reply.size());
		// Подаём ответ клиента серверу
		ASSERT_EQ(server.push(view_t(reply.data(), reply.size())), context::error_t::NONE);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем схождение значений сторон переносом записями
		ASSERT_EQ(traffic(client, context::level_t::APPLICATION, context::direction_t::READ), traffic(server, context::level_t::APPLICATION, context::direction_t::WRITE));
		// Прикладные данные сервера
		const string text = "Прикладные данные, защищённые записью";
		// Отправляем прикладные данные сервером
		ASSERT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size())), context::error_t::NONE);
		// Запись прикладных данных сервера
		const view_t sealed = server.output();
		// Переносим запись прикладных данных
		const vector <uint8_t> record(sealed.data, sealed.data + sealed.size);
		// Разбираем заголовок записи прикладных данных
		ASSERT_EQ(record::parse(view_t(record.data(), record.size()), header), record::error_t::NONE);
		// Значение прикладных данных сервера, выданное наружу клиенту на чтение
		const vector <uint8_t> reading = traffic(client, context::level_t::APPLICATION, context::direction_t::READ);
		// Выводим ключевой материал прикладных данных из выданного значения
		ASSERT_EQ(session::material(view_t(reading.data(), reading.size()), SUITES[s], key, vector_), session::error_t::NONE);
		// Защита принимающей стороны на прикладном материале
		protect::protection_t applying;
		// Заводим защиту принимающей стороны
		ASSERT_TRUE(applying.start(SUITES[s], view_t(key, protect::key(SUITES[s])), view_t(vector_, protect::block(SUITES[s]))));
		// Сбрасываем накопитель открытого содержимого: снятие защиты дописывает в него
		opened.clear();
		// Снимаем защиту с прикладной записи выданным наружу значением
		ASSERT_EQ(applying.open(header, view_t(record.data() + record::RECORD_HEADER, record.size() - record::RECORD_HEADER), type, opened), protect::error_t::NONE);
		// Проверяем вид содержимого
		ASSERT_EQ(type, record::type_t::APPLICATION);
		// Проверяем схождение прикладных данных
		ASSERT_EQ(string(opened.begin(), opened.end()), text);
		// Смена ключей сервером с просьбой об ответной
		ASSERT_EQ(server.update(true), context::error_t::NONE);
		// Значение прикладных данных сервера после смены ключей
		const vector <uint8_t> renewed = traffic(server, context::level_t::APPLICATION, context::direction_t::WRITE);
		// Проверяем, что значение сменилось
		ASSERT_NE(renewed, reading);
		// Накопитель сервера целиком: прикладная запись и смена ключей за нею
		const view_t whole = server.output();
		// Переносим накопитель сервера
		const vector <uint8_t> tail(whole.data, whole.data + whole.size);
		// Проверяем, что смена ключей легла за прикладной записью
		ASSERT_GT(tail.size(), record.size());
		// Подаём прикладные данные и смену ключей клиенту
		ASSERT_EQ(client.push(view_t(tail.data(), tail.size())), context::error_t::NONE);
		// Снимаем накопитель сервера
		server.consume(tail.size());
		// Проверяем схождение сменённого значения у клиента
		ASSERT_EQ(traffic(client, context::level_t::APPLICATION, context::direction_t::READ), renewed);
	}
}

/**
 * Проверка отказов переноса по уровням: смена ключей сообщением, конец упреждающих данных,
 * отсутствие параметров переноса, параметры переноса переносу записями, отсутствие прикладного
 * протокола, сообщение не на своём уровне, сообщение на уровне упреждения, байты записей
 */
TEST(QuicTest, Refusals){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Отказ: смена ключей сообщением KeyUpdate по установленной связи
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established() && server.established());
		// Тело сообщения смены ключей
		vector <uint8_t> body;
		// Составляем тело смены ключей
		ASSERT_EQ(message::build(message::update_t::NOTIFY, body), message::error_t::NONE);
		// Сообщение смены ключей с обвязкой
		const vector <uint8_t> update = compose(handshake::type_t::UPDATE, body);
		// Подаём смену ключей клиенту на уровне прикладных данных
		ASSERT_EQ(client.push(context::level_t::APPLICATION, view_t(update.data(), update.size())), context::error_t::ORDER);
		// Проверяем обрыв связи
		ASSERT_EQ(client.state(), context::state_t::FAILED);
		// Проверяем извещение unexpected_message
		ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
		// Проверяем, что извещение записью не ушло: накопители уровней пусты
		ASSERT_EQ(client.output(context::level_t::APPLICATION).size, static_cast <size_t> (0));
		// Подаём смену ключей серверу на уровне прикладных данных
		ASSERT_EQ(server.push(context::level_t::APPLICATION, view_t(update.data(), update.size())), context::error_t::ORDER);
		// Проверяем обрыв связи сервером
		ASSERT_EQ(server.state(), context::state_t::FAILED);
		// Проверяем, что после обрыва секреты затёрты
		ASSERT_TRUE(traffic(server, context::level_t::APPLICATION, context::direction_t::WRITE).empty());
	}
	// Отказ: конец упреждающих данных под QUIC не посылается и не принимается
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Переносим приветствие клиента
		ASSERT_TRUE(carry(client, server, context::level_t::INITIAL));
		// Переносим приветствие сервера
		ASSERT_TRUE(carry(server, client, context::level_t::INITIAL));
		// Конец упреждающих данных с обвязкой
		const vector <uint8_t> eoed = compose(handshake::type_t::EARLY, vector <uint8_t> ());
		// Подаём конец упреждающих данных серверу на уровне рукопожатия
		ASSERT_EQ(server.push(context::level_t::HANDSHAKE, view_t(eoed.data(), eoed.size())), context::error_t::ORDER);
		// Проверяем обрыв связи
		ASSERT_EQ(server.state(), context::state_t::FAILED);
		// Проверяем извещение unexpected_message
		ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	}
	// Отказ: приветствие без параметров переноса у сервера по уровням
	{
		// Связь стороны клиента переносом записями
		client::context_t client;
		// Связь стороны сервера переносом по уровням
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Возвращаем клиента к переносу записями: параметров переноса он не шлёт
		client.transport(context::transport_t::RECORDS);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Приветствие клиента записью
		const view_t wire = client.output();
		// Проверяем, что приветствие сложено записью
		ASSERT_GT(wire.size, record::RECORD_HEADER);
		// Подаём серверу тело записи: само сообщение без заголовка записи
		ASSERT_EQ(server.push(context::level_t::INITIAL, view_t(wire.data + record::RECORD_HEADER, wire.size - record::RECORD_HEADER)), context::error_t::PARAMETERS);
		// Проверяем обрыв связи
		ASSERT_EQ(server.state(), context::state_t::FAILED);
		// Проверяем извещение missing_extension
		ASSERT_EQ(server.alert().description, alert::description_t::MISSING);
	}
	// Отказ: параметры переноса в приветствии у сервера переносом записями
	{
		// Связь стороны клиента переносом по уровням
		client::context_t client;
		// Связь стороны сервера переносом записями
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Возвращаем сервер к переносу записями
		server.transport(context::transport_t::RECORDS);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Приветствие клиента сообщением
		const view_t message = client.output(context::level_t::INITIAL);
		// Нарезчик записей
		record::writer_t writer;
		// Заворачиваем приветствие в запись
		ASSERT_EQ(writer.push(record::type_t::HANDSHAKE, record::version_t::TLS12, message), record::error_t::NONE);
		// Подаём запись серверу
		ASSERT_EQ(server.push(writer.data()), context::error_t::PARAMETERS);
		// Проверяем обрыв связи
		ASSERT_EQ(server.state(), context::state_t::FAILED);
		// Проверяем извещение unsupported_extension
		ASSERT_EQ(server.alert().description, alert::description_t::EXTENSION);
		// Проверяем, что извещение записью ушло
		ASSERT_GT(server.output().size, static_cast <size_t> (0));
	}
	// Отказ: приветствие без прикладного протокола у сервера по уровням
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Клиент без прикладных протоколов
		client.protocols(vector <string> ());
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Проверяем отказ заведения клиента без протоколов
		ASSERT_EQ(client.start(), context::error_t::SETTINGS);
		// Связь второго клиента с чужим протоколом
		client::context_t alien;
		// Связь второго сервера
		server::context_t judge;
		// Настраиваем стороны
		arrange(alien, judge, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Клиент предлагает чужой протокол
		alien.protocols(vector <string> {"hq-interop"});
		// Заводим сервер
		ASSERT_EQ(judge.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(alien.start(), context::error_t::NONE);
		// Переносим приветствие клиента
		ASSERT_TRUE(carry(alien, judge, context::level_t::INITIAL));
		// Проверяем обрыв связи сервером
		ASSERT_EQ(judge.state(), context::state_t::FAILED);
		// Проверяем отказ отсутствия общего протокола
		ASSERT_EQ(judge.error(), context::error_t::PROTOCOL);
		// Проверяем извещение no_application_protocol
		ASSERT_EQ(judge.alert().description, alert::description_t::PROTOCOL);
		// Сервер без прикладных протоколов
		server::context_t mute;
		// Устанавливаем перенос по уровням
		mute.transport(context::transport_t::LEVELS);
		// Устанавливаем подлинность сервера
		mute.credential(credential);
		// Проверяем отказ заведения сервера без протоколов
		ASSERT_EQ(mute.start(), context::error_t::SETTINGS);
		// Раздел 8.2 RFC 9001: без параметров переноса связь по уровням не заводится, пустое расширение потребителю не нужно
		client::context_t bare;
		// Сервер той же связи
		server::context_t host;
		// Заводим связь по уровням
		arrange(bare, host, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Опустошаем параметры переноса у обеих сторон
		bare.parameters(vector <uint8_t> ());
		host.parameters(vector <uint8_t> ());
		// Проверяем отказ настроек у клиента
		ASSERT_EQ(bare.start(), context::error_t::SETTINGS);
		// Проверяем отказ настроек у сервера
		ASSERT_EQ(host.start(), context::error_t::SETTINGS);
	}
	// Отказ: сообщение не на своём уровне и сообщение на уровне упреждения
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Приветствие клиента
		const view_t greeting = client.output(context::level_t::INITIAL);
		// Переносим приветствие клиента
		const vector <uint8_t> hello(greeting.data, greeting.data + greeting.size);
		// Подаём приветствие серверу на уровне упреждения: сообщений он не несёт
		ASSERT_EQ(server.push(context::level_t::EARLY, view_t(hello.data(), hello.size())), context::error_t::LEVEL);
		// Проверяем, что связь не оборвана: подача без уровня - оплошность ведущего
		ASSERT_EQ(server.state(), context::state_t::HANDSHAKE);
		// Подаём приветствие серверу без уровня
		ASSERT_EQ(server.push(context::level_t::NONE, view_t(hello.data(), hello.size())), context::error_t::LEVEL);
		// Подаём серверу байты записей
		ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::LEVEL);
		// Проверяем, что связь не оборвана
		ASSERT_EQ(server.state(), context::state_t::HANDSHAKE);
		// Подаём приветствие серверу на уровне рукопожатия
		ASSERT_EQ(server.push(context::level_t::HANDSHAKE, view_t(hello.data(), hello.size())), context::error_t::LEVEL);
		// Проверяем обрыв связи
		ASSERT_EQ(server.state(), context::state_t::FAILED);
		// Проверяем извещение unexpected_message
		ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
		// Связь второго сервера
		server::context_t second;
		// Связь второго клиента
		client::context_t another;
		// Настраиваем стороны
		arrange(another, second, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(second.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(another.start(), context::error_t::NONE);
		// Переносим приветствие клиента
		ASSERT_TRUE(carry(another, second, context::level_t::INITIAL));
		// Выход сервера на уровне рукопожатия
		const view_t flight = second.output(context::level_t::HANDSHAKE);
		// Переносим выход сервера
		const vector <uint8_t> guarded(flight.data, flight.data + flight.size);
		// Подаём выход сервера клиенту на начальном уровне прежде приветствия сервера
		ASSERT_EQ(another.push(context::level_t::INITIAL, view_t(guarded.data(), guarded.size())), context::error_t::ORDER);
		// Проверяем обрыв связи клиента
		ASSERT_EQ(another.state(), context::state_t::FAILED);
		// Связь третьего сервера
		server::context_t third;
		// Связь третьего клиента
		client::context_t once;
		// Настраиваем стороны
		arrange(once, third, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(third.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(once.start(), context::error_t::NONE);
		// Переносим приветствие клиента
		ASSERT_TRUE(carry(once, third, context::level_t::INITIAL));
		// Приветствие сервера
		const view_t answer = third.output(context::level_t::INITIAL);
		// Переносим приветствие сервера
		const vector <uint8_t> server_hello(answer.data, answer.data + answer.size);
		// Выход сервера
		const view_t rest = third.output(context::level_t::HANDSHAKE);
		// Приветствие сервера и его выход одной подачей на начальном уровне
		vector <uint8_t> coalesced(server_hello);
		// Добавляем выход сервера к приветствию
		coalesced.insert(coalesced.end(), rest.data, rest.data + rest.size);
		// Подаём слитую подачу клиенту: за приветствием сервера уровень чтения меняется
		ASSERT_EQ(once.push(context::level_t::INITIAL, view_t(coalesced.data(), coalesced.size())), context::error_t::LEVEL);
		// Проверяем обрыв связи клиента
		ASSERT_EQ(once.state(), context::state_t::FAILED);
		// Проверяем извещение unexpected_message
		ASSERT_EQ(once.alert().description, alert::description_t::UNEXPECTED);
		// Связь четвёртого сервера
		server::context_t fourth;
		// Связь четвёртого клиента
		client::context_t split;
		// Настраиваем стороны
		arrange(split, fourth, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(fourth.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(split.start(), context::error_t::NONE);
		// Приветствие клиента
		const view_t whole = split.output(context::level_t::INITIAL);
		// Подаём серверу половину приветствия на начальном уровне
		ASSERT_EQ(fourth.push(context::level_t::INITIAL, view_t(whole.data, whole.size / 2)), context::error_t::NONE);
		// Проверяем, что связь ждёт остатка
		ASSERT_EQ(fourth.state(), context::state_t::HANDSHAKE);
		// Досылаем остаток на уровне рукопожатия
		ASSERT_EQ(fourth.push(context::level_t::HANDSHAKE, view_t(whole.data + (whole.size / 2), whole.size - (whole.size / 2))), context::error_t::LEVEL);
		// Проверяем обрыв связи
		ASSERT_EQ(fourth.state(), context::state_t::FAILED);
	}
	// Отказ: прикладные данные и закрытие переносу по уровням не положены
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established() && server.established());
		// Накопитель принятых данных
		vector <uint8_t> received;
		// Проверяем, что чтение прикладных данных отвергается
		ASSERT_EQ(client.read(received), context::error_t::STATE);
		// Проверяем, что запись прикладных данных отвергается
		ASSERT_EQ(server.write(view_t(SERVER_PARAMETERS.data(), SERVER_PARAMETERS.size())), context::error_t::STATE);
		// Проверяем, что закрытие отвергается
		ASSERT_EQ(client.close(), context::error_t::STATE);
		// Проверяем, что смена ключей отвергается
		ASSERT_EQ(server.update(false), context::error_t::STATE);
		// Проверяем, что связь осталась установленной
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем, что накопитель записей пуст
		ASSERT_EQ(client.output().size, static_cast <size_t> (0));
	}
}

/**
 * Проверка кодека билета: круг записи и чтения, самодостаточность записи для возобновления
 * связи, чужое издание, обрезание на всякой длине, порча длин полей, лишний хвост, пустой
 * вход и билет, в запись не входящий
 */
TEST(QuicTest, Ticket){
	// Билет возобновления связи
	context::ticket_t ticket;
	// Устанавливаем набор шифрования билета
	ticket.suite = protect::suite_t::AES_256_GCM_SHA384;
	// Устанавливаем миг выдачи: старше 32 разрядов
	ticket.moment = 0x0000000123456789LL;
	// Устанавливаем срок жизни билета
	ticket.lifetime = 7200;
	// Устанавливаем предел упреждающих данных
	ticket.advance = 16384;
	// Устанавливаем добавку к возрасту
	ticket.age = 0xDEADBEEF;
	// Устанавливаем прикладной протокол
	ticket.protocol = "h3";
	// Устанавливаем тело билета
	ticket.identity = decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
	// Устанавливаем ключ билета длиною в SHA-384
	ticket.secret = decode(rfc8448::S3_RESUMPTION);
	// Добавляем ключу байтов до длины SHA-384
	ticket.secret.insert(ticket.secret.end(), ticket.secret.begin(), ticket.secret.begin() + 16);
	// Устанавливаем параметры переноса собеседника
	ticket.parameters = SERVER_PARAMETERS;
	// Устанавливаем признак порядка «шифрование, затем имитовставка»: у билета 1.3 он ничего не значит, но запись его переносит
	ticket.etm = true;
	// Запись билета
	vector <uint8_t> encoded;
	// Записываем билет
	ASSERT_EQ(context::encode(ticket, encoded), context::error_t::NONE);
	// Проверяем издание записи
	ASSERT_EQ(encoded[0], static_cast <uint8_t> (0x03));
	// Проверяем длину записи: 1 + 2 + 8 + 4 + 4 + 4 + 1 и четыре поля с длинами, за ними признак ALPS и два пустых поля настроек (издание 3)
	ASSERT_EQ(encoded.size(), static_cast <size_t> (24 + 2 + 2 + 2 + 32 + 2 + 48 + 2 + SERVER_PARAMETERS.size() + 1 + 2 + 2));
	// Прочитанный билет
	context::ticket_t decoded;
	// Читаем билет
	ASSERT_EQ(context::decode(view_t(encoded.data(), encoded.size()), decoded), context::error_t::NONE);
	// Проверяем набор шифрования
	ASSERT_EQ(decoded.suite, ticket.suite);
	// Проверяем миг выдачи
	ASSERT_EQ(decoded.moment, ticket.moment);
	// Проверяем срок жизни
	ASSERT_EQ(decoded.lifetime, ticket.lifetime);
	// Проверяем предел упреждения
	ASSERT_EQ(decoded.advance, ticket.advance);
	// Проверяем добавку к возрасту
	ASSERT_EQ(decoded.age, ticket.age);
	// Проверяем признак порядка «шифрование, затем имитовставка»
	ASSERT_EQ(decoded.etm, ticket.etm);
	// Проверяем прикладной протокол
	ASSERT_EQ(decoded.protocol, ticket.protocol);
	// Проверяем тело билета
	ASSERT_EQ(decoded.identity, ticket.identity);
	// Проверяем ключ билета
	ASSERT_EQ(decoded.secret, ticket.secret);
	// Проверяем параметры переноса
	ASSERT_EQ(decoded.parameters, ticket.parameters);
	// Повторная запись прочитанного билета
	vector <uint8_t> again;
	// Записываем прочитанный билет
	ASSERT_EQ(context::encode(decoded, again), context::error_t::NONE);
	// Проверяем схождение записей байт в байт
	ASSERT_EQ(again, encoded);
	// Отрицательный миг выдачи
	ticket.moment = -1;
	// Записываем билет с отрицательным мигом
	ASSERT_EQ(context::encode(ticket, encoded), context::error_t::NONE);
	// Читаем билет с отрицательным мигом
	ASSERT_EQ(context::decode(view_t(encoded.data(), encoded.size()), decoded), context::error_t::NONE);
	// Проверяем отрицательный миг
	ASSERT_EQ(decoded.moment, static_cast <int64_t> (-1));
	// Пустой билет
	const context::ticket_t blank;
	// Записываем пустой билет
	ASSERT_EQ(context::encode(blank, encoded), context::error_t::NONE);
	// Проверяем длину записи пустого билета
	ASSERT_EQ(encoded.size(), static_cast <size_t> (24 + 8 + 5));
	// Читаем пустой билет
	ASSERT_EQ(context::decode(view_t(encoded.data(), encoded.size()), decoded), context::error_t::NONE);
	// Проверяем пустоту ключа
	ASSERT_TRUE(decoded.secret.empty());
	// Проверяем пустоту параметров
	ASSERT_TRUE(decoded.parameters.empty());
	// Возвращаем билету миг выдачи
	ticket.moment = 0x0000000123456789LL;
	// Записываем полный билет заново
	ASSERT_EQ(context::encode(ticket, encoded), context::error_t::NONE);
	// Отказ: пустой вход
	ASSERT_EQ(context::decode(view_t(), decoded), context::error_t::TICKET);
	// Отказ: чужое издание
	{
		// Порченая запись
		vector <uint8_t> broken = encoded;
		// Меняем издание записи
		broken[0] = 0x04;
		// Проверяем отказ чтения
		ASSERT_EQ(context::decode(view_t(broken.data(), broken.size()), decoded), context::error_t::TICKET);
	}
	/**
	 * Отказ: обрезание записи на всякой длине
	 */
	for(size_t i = 1; i < encoded.size(); i++)
		// Проверяем отказ чтения обрезанной записи
		ASSERT_EQ(context::decode(view_t(encoded.data(), i), decoded), context::error_t::TICKET) << "длина " << i;
	// Отказ: лишний байт за хвостом
	{
		// Порченая запись
		vector <uint8_t> broken = encoded;
		// Добавляем лишний байт
		broken.push_back(0x00);
		// Проверяем отказ чтения
		ASSERT_EQ(context::decode(view_t(broken.data(), broken.size()), decoded), context::error_t::TICKET);
	}
	// Отказ: порча длины прикладного протокола вверх
	{
		// Порченая запись
		vector <uint8_t> broken = encoded;
		// Раздуваем длину протокола
		broken[24 + 1] = 0xFF;
		// Проверяем отказ чтения
		ASSERT_EQ(context::decode(view_t(broken.data(), broken.size()), decoded), context::error_t::TICKET);
	}
	// Отказ: порча длины прикладного протокола вниз - хвост сдвигается и не сходится
	{
		// Порченая запись
		vector <uint8_t> broken = encoded;
		// Ужимаем длину протокола
		broken[24 + 1] = 0x01;
		// Проверяем отказ чтения
		ASSERT_EQ(context::decode(view_t(broken.data(), broken.size()), decoded), context::error_t::TICKET);
	}
	// Отказ: порча длины ключа за предел хеша
	{
		// Место длины ключа: заголовок, протокол и тело билета
		const size_t place = (24 + 2 + 2 + 2 + 32);
		// Порченая запись
		vector <uint8_t> broken = encoded;
		// Объявляем ключ длиною в 65 байтов
		broken[place] = 0x00;
		// Младший байт длины ключа
		broken[place + 1] = 0x41;
		// Добавляем записи байтов под объявленную длину
		broken.insert(broken.begin() + place + 2 + 48, 17, 0x00);
		// Проверяем отказ чтения
		ASSERT_EQ(context::decode(view_t(broken.data(), broken.size()), decoded), context::error_t::TICKET);
	}
	// Отказ: порча длины параметров переноса
	{
		// Место длины параметров
		const size_t place = (24 + 2 + 2 + 2 + 32 + 2 + 48);
		// Порченая запись
		vector <uint8_t> broken = encoded;
		// Раздуваем длину параметров
		broken[place + 1] = static_cast <uint8_t> (SERVER_PARAMETERS.size() + 1);
		// Проверяем отказ чтения
		ASSERT_EQ(context::decode(view_t(broken.data(), broken.size()), decoded), context::error_t::TICKET);
	}
	// Отказ: билет с ключом шире хеша в запись не входит
	{
		// Негодный билет
		context::ticket_t wide = ticket;
		// Раздуваем ключ билета
		wide.secret.assign(65, 0x5A);
		// Проверяем отказ записи
		ASSERT_EQ(context::encode(wide, encoded), context::error_t::TICKET);
	}
	// Отказ: билет с телом, в два байта длины не входящим
	{
		// Негодный билет
		context::ticket_t wide = ticket;
		// Раздуваем тело билета
		wide.identity.assign(65536, 0x5A);
		// Проверяем отказ записи
		ASSERT_EQ(context::encode(wide, encoded), context::error_t::TICKET);
	}
	// Самодостаточность записи: билет, прошедший через октеты, возобновляет связь
	{
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity("ed25519", credential));
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны
		arrange(client, server, protect::suite_t::CHACHA20_POLY1305_SHA256, extension::group_t::X25519, credential, false);
		// Разрешаем упреждающие данные билетом
		server.advance(true, 2048);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established() && server.established());
		// Выдаём билет
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Доставляем билет
		converse(client, server);
		// Проверяем получение билета
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Запись билета клиента
		vector <uint8_t> clientside;
		// Записываем билет клиента
		ASSERT_EQ(context::encode(client.tickets()[0], clientside), context::error_t::NONE);
		// Запись билета сервера
		vector <uint8_t> serverside;
		// Записываем билет сервера
		ASSERT_EQ(context::encode(server.tickets()[0], serverside), context::error_t::NONE);
		// Билет клиента из октетов
		context::ticket_t presented;
		// Читаем билет клиента
		ASSERT_EQ(context::decode(view_t(clientside.data(), clientside.size()), presented), context::error_t::NONE);
		// Проверяем параметры переноса в билете
		ASSERT_EQ(presented.parameters, SERVER_PARAMETERS);
		// Билет сервера из октетов
		context::ticket_t recognized;
		// Читаем билет сервера
		ASSERT_EQ(context::decode(view_t(serverside.data(), serverside.size()), recognized), context::error_t::NONE);
		// Связь возобновляющего клиента
		client::context_t resuming;
		// Связь возобновляющего сервера
		server::context_t resumed;
		// Настраиваем стороны
		arrange(resuming, resumed, protect::suite_t::CHACHA20_POLY1305_SHA256, extension::group_t::X25519, credential, false);
		// Предъявляем билет из октетов
		resuming.resume(presented);
		// Признаём билет из октетов
		resumed.resume(vector <context::ticket_t> {recognized});
		// Предлагаем упреждающие данные
		resuming.advance(true);
		// Принимаем упреждающие данные
		resumed.advance(true, 2048);
		// Заводим сервер
		ASSERT_EQ(resumed.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(resuming.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(resuming, resumed);
		// Проверяем установленность связи
		ASSERT_TRUE(resuming.established() && resumed.established()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
		// Проверяем возобновление билетом
		ASSERT_TRUE(resuming.shared() && resumed.shared());
		// Проверяем приём упреждения
		ASSERT_TRUE(resuming.accepted() && resumed.accepted());
	}
}

/**
 * Проверка отказа сервера от упреждающих данных под QUIC: признак отвергнутости у клиента,
 * значение упреждения выведено, ход упреждения прекращён выходом сервера
 */
TEST(QuicTest, Rejected){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec384", credential));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Настраиваем стороны
	arrange(client, server, protect::suite_t::AES_256_GCM_SHA384, extension::group_t::SECP384R1, credential, false);
	// Разрешаем упреждающие данные билетом
	server.advance(true, 1024);
	// Заводим сервер
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проводим рукопожатие
	converse(client, server);
	// Выдаём билет
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Доставляем билет
	converse(client, server);
	// Проверяем получение билета
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
	// Связь возобновляющего клиента
	client::context_t resuming;
	// Связь возобновляющего сервера
	server::context_t resumed;
	// Настраиваем стороны
	arrange(resuming, resumed, protect::suite_t::AES_256_GCM_SHA384, extension::group_t::SECP384R1, credential, false);
	// Предъявляем билет
	resuming.resume(client.tickets()[0]);
	// Признаём билеты
	resumed.resume(server.tickets());
	// Предлагаем упреждающие данные
	resuming.advance(true);
	// Сервер упреждающие данные не принимает
	resumed.advance(false);
	// Заводим сервер
	ASSERT_EQ(resumed.start(), context::error_t::NONE);
	// Заводим клиента
	ASSERT_EQ(resuming.start(), context::error_t::NONE);
	// Проверяем ход упреждения
	ASSERT_TRUE(resuming.earlying());
	// Проверяем, что решения ещё нет
	ASSERT_FALSE(resuming.rejected());
	// Переносим приветствие клиента
	ASSERT_TRUE(carry(resuming, resumed, context::level_t::INITIAL));
	// Проверяем, что сервер упреждение не принял
	ASSERT_FALSE(resumed.accepted());
	// Проверяем, что сервер упреждение не ведёт
	ASSERT_FALSE(resumed.earlying());
	// Переносим приветствие сервера
	ASSERT_TRUE(carry(resumed, resuming, context::level_t::INITIAL));
	// Переносим выход сервера
	ASSERT_TRUE(carry(resumed, resuming, context::level_t::HANDSHAKE));
	// Проверяем отказ сервера у клиента
	ASSERT_TRUE(resuming.rejected());
	// Проверяем, что упреждение не принято
	ASSERT_FALSE(resuming.accepted());
	// Проверяем, что ход упреждения прекращён
	ASSERT_FALSE(resuming.earlying());
	// Проводим рукопожатие до конца
	converse(resuming, resumed);
	// Проверяем установленность связи
	ASSERT_TRUE(resuming.established() && resumed.established());
	// Проверяем возобновление билетом
	ASSERT_TRUE(resuming.shared() && resumed.shared());
}

/**
 * Проверка нехватки памяти на новых путях: рукопожатие по уровням с параметрами переноса
 * и билетом, кодек билета
 */
TEST(QuicTest, Starved){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(identity("ec256", credential));
	// Признак того, что нехватка памяти встретилась
	bool starved = false;
	// Признак того, что связь на щедром запасе установилась
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны с подлинностью клиента
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, true);
		// Разрешаем упреждающие данные билетом
		server.advance(true, 1024);
		// Отказы сторон
		context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
		// Отказ выдачи билета
		context::error_t issued = context::error_t::NONE;
		{
			// Ограничиваем запас выделений
			starve::ration_t ration(budget);
			// Заводим сервер
			first = server.start();
			// Заводим клиента
			second = client.start();
			// Если стороны заведены
			if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
				// Проводим рукопожатие
				converse(client, server);
				// Если связь установлена
				if(client.established() && server.established()){
					// Выдаём билет
					issued = server.issue();
					// Доставляем билет
					converse(client, server);
				}
				// Отказ сервера после рукопожатия
				first = server.error();
				// Отказ клиента
				second = client.error();
			}
		}
		// Запоминаем нехватку памяти
		starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY) || (issued == context::error_t::MEMORY));
		/**
		 * Дозволенные исходы: успех либо нехватка памяти. Извещения по уровням не идут,
		 * оттого обрыва собеседником внутренним извещением здесь не бывает
		 */
		const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY)) &&
			((second == context::error_t::NONE) || (second == context::error_t::MEMORY)) &&
			((issued == context::error_t::NONE) || (issued == context::error_t::MEMORY));
		// Проверяем законность исхода
		ASSERT_TRUE(lawful) << "запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second) << " " << static_cast <int> (issued);
		// Запоминаем установление связи с билетом
		complete = (client.established() && server.established() && (client.tickets().size() == 1));
	}
	// Проверяем, что нехватка памяти встретилась
	ASSERT_TRUE(starved);
	// Проверяем, что на щедром запасе связь установилась
	ASSERT_TRUE(complete);
	// Билет кодека
	context::ticket_t ticket;
	// Устанавливаем прикладной протокол длиннее короткого запаса строки
	ticket.protocol = "application-protocol-longer-than-sso";
	// Устанавливаем тело билета
	ticket.identity = decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
	// Устанавливаем ключ билета
	ticket.secret = decode(rfc8448::S3_RESUMPTION);
	// Устанавливаем параметры переноса
	ticket.parameters = SERVER_PARAMETERS;
	// Признак нехватки памяти кодека
	bool hungry = false;
	// Признак успешного круга
	bool rounded = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 64) && !rounded; budget++){
		// Отказы записи и чтения
		context::error_t written = context::error_t::NONE, read = context::error_t::NONE;
		// Запись билета
		vector <uint8_t> encoded;
		// Прочитанный билет
		context::ticket_t decoded;
		{
			// Ограничиваем запас выделений
			starve::ration_t ration(budget);
			// Записываем билет
			written = context::encode(ticket, encoded);
			// Если билет записан
			if(written == context::error_t::NONE)
				// Читаем билет
				read = context::decode(view_t(encoded.data(), encoded.size()), decoded);
		}
		// Запоминаем нехватку памяти
		hungry = (hungry || (written == context::error_t::MEMORY) || (read == context::error_t::MEMORY));
		// Проверяем законность исходов
		ASSERT_TRUE(((written == context::error_t::NONE) || (written == context::error_t::MEMORY)) && ((read == context::error_t::NONE) || (read == context::error_t::MEMORY))) << "запас " << budget;
		// Запоминаем успешный круг
		rounded = ((written == context::error_t::NONE) && (read == context::error_t::NONE) && (decoded.parameters == ticket.parameters) && (decoded.protocol == ticket.protocol));
	}
	// Проверяем, что нехватка памяти встретилась
	ASSERT_TRUE(hungry);
	// Проверяем, что на щедром запасе круг пройден
	ASSERT_TRUE(rounded);
}
