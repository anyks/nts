/**
 * @file alps.cpp
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
 * @brief Исходный файл проверок прикладных настроек ALPS (draft-vvv-tls-alps): обмен
 *        настройками обеими точками кода, наследование билетом при упреждении, профиль
 *        отпечатка с ALPS, отказы враждебных сторон и пайок памяти
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

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <identity.hpp>
#include <adversary.hpp>
#include <pem/pem.hpp>
#include <alert/alert.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <context/context.hpp>
#include <extension/extension.hpp>
#include <fingerprint/fingerprint.hpp>

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
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 *
	 * @return     содержимое файла набора
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		vector <uint8_t> result;
		if(file.is_open())
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		return result;
	}
	/**
	 * @brief Метод составления подлинности стороны из ключей набора (identity.hpp вырабатывает ГОСТ)
	 *
	 * @param name   имя ключа набора
	 * @param result подлинность, в которую помещается итог
	 *
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool keyfile(const char * name, context::credential_t & result) noexcept {
		result.secret = corpus((std::string(name) + ".pem").c_str());
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		if(result.secret.empty() || text.empty())
			return false;
		result.chain.clear();
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Метод составления области байтов из текста
	 *
	 * @param text текст
	 *
	 * @return     область байтов
	 *
	 */
	vector <uint8_t> bytes(const char * text) noexcept {
		return vector <uint8_t> (text, text + ::strlen(text));
	}
	/**
	 * @brief Метод передачи байтов между сторонами связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что байты между сторонами передавались
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
		bool moved = false;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			view_t data = client.output();
			if(data.size > 0){
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				client.consume(buffer.size());
				server.push(view_t(buffer.data(), buffer.size()));
				moved = true;
			}
			data = server.output();
			if(data.size > 0){
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				server.consume(buffer.size());
				client.push(view_t(buffer.data(), buffer.size()));
				moved = true;
			}
		/**
		 * Если памяти под перенос байтов не хватило
		 */
		} catch(const bad_alloc &) {
			return false;
		}
		return moved;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 */
	void converse(client::context_t & client, server::context_t & server) noexcept {
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			continue;
	}
	/**
	 * @brief Метод обмена прикладными данными в обе стороны
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что данные дошли в обе стороны без искажения
	 *
	 */
	bool barter(client::context_t & client, server::context_t & server) noexcept {
		const string request = "Запрос по связи с прикладными настройками";
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			return false;
		converse(client, server);
		vector <uint8_t> received;
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			return false;
		const string answer = "Ответ по связи с прикладными настройками";
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())) != context::error_t::NONE)
			return false;
		converse(client, server);
		if((client.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != answer))
			return false;
		return true;
	}
	/**
	 * @brief Метод настройки сторон под ALPS: протокол h2 у обеих, настройки по заказу
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param credential подлинность сервера
	 * @param mine       настройки клиента для h2 либо nullptr, когда не объявляются
	 * @param theirs     настройки сервера для h2 либо nullptr, когда не объявляются
	 * @param type       точка кода обеих сторон
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const context::credential_t & credential, const char * mine, const char * theirs, const extension::type_t type) noexcept {
		server.credential(credential);
		client.protocols(vector <string> {"h2", "http/1.1"});
		server.protocols(vector <string> {"h2"});
		if(mine != nullptr)
			client.settings("h2", bytes(mine));
		if(theirs != nullptr)
			server.settings("h2", bytes(theirs));
		client.codepoint(type);
		server.codepoint(type);
	}
	/**
	 * Точки кода ALPS
	 */
	static const extension::type_t POINTS[] = {extension::type_t::SETTINGS, extension::type_t::SETTINGS_OLD};
};

/**
 * Проверка обмена настройками обеими точками кода: настройки доходят в обе стороны,
 * а возобновление без упреждения договаривает их заново
 */
TEST(AlpsTest, Loopback){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	/**
	 * Выполняем перебор точек кода
	 */
	for(size_t p = 0; p < (sizeof(POINTS) / sizeof(POINTS[0])); p++){
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, "client-h2", "server-h2", POINTS[p]);
		ASSERT_EQ(client.codepoint(), POINTS[p]);
		ASSERT_EQ(server.codepoint(), POINTS[p]);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << p << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_EQ(client.protocol(), "h2");
		EXPECT_TRUE(client.settled());
		EXPECT_TRUE(server.settled());
		EXPECT_EQ(client.settings(), bytes("server-h2"));
		EXPECT_EQ(server.settings(), bytes("client-h2"));
		ASSERT_TRUE(barter(client, server));
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		converse(client, server);
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		EXPECT_TRUE(client.tickets()[0].settled);
		EXPECT_EQ(client.tickets()[0].settings, bytes("client-h2"));
		EXPECT_EQ(client.tickets()[0].obtained, bytes("server-h2"));
		client::context_t resuming;
		server::context_t resumed;
		arrange(resuming, resumed, credential, "client-h2-again", "server-h2-again", POINTS[p]);
		resuming.resume(client.tickets()[0]);
		resumed.resume(server.tickets());
		ASSERT_EQ(resumed.start(), context::error_t::NONE);
		ASSERT_EQ(resuming.start(), context::error_t::NONE);
		converse(resuming, resumed);
		ASSERT_TRUE(resuming.established() && resumed.established());
		ASSERT_TRUE(resuming.shared() && resumed.shared());
		EXPECT_TRUE(resuming.settled() && resumed.settled());
		EXPECT_EQ(resuming.settings(), bytes("server-h2-again"));
		EXPECT_EQ(resumed.settings(), bytes("client-h2-again"));
		ASSERT_TRUE(barter(resuming, resumed));
	}
}

/**
 * Проверка расхождения точек кода: связь идёт без настроек молча, а ручка точки кода
 * различает этот случай снаружи
 */
TEST(AlpsTest, Codepoints){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	arrange(client, server, credential, "client-h2", "server-h2", extension::type_t::SETTINGS_OLD);
	server.codepoint(extension::type_t::SETTINGS);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established());
	EXPECT_EQ(client.protocol(), "h2");
	EXPECT_FALSE(client.settled());
	EXPECT_FALSE(server.settled());
	EXPECT_TRUE(client.settings().empty());
	EXPECT_TRUE(server.settings().empty());
	EXPECT_NE(client.codepoint(), server.codepoint());
	ASSERT_TRUE(barter(client, server));
}

/**
 * Проверка отсутствия настроек у одной из сторон: без настроек сервера либо без настроек
 * клиента для выбранного протокола ALPS не согласуется
 */
TEST(AlpsTest, Absent){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, "client-h2", nullptr, extension::type_t::SETTINGS);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_FALSE(client.settled() || server.settled());
	}
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, "client-h2", nullptr, extension::type_t::SETTINGS);
		server.protocols(vector <string> {"http/1.1"});
		server.settings("http/1.1", bytes("server-http"));
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_EQ(client.protocol(), "http/1.1");
		EXPECT_FALSE(client.settled() || server.settled());
	}
}

/**
 * Проверка пустых настроек: пустые настройки согласуются наравне с непустыми, и
 * согласование видно лишь через settled()
 */
TEST(AlpsTest, Empty){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	arrange(client, server, credential, "", "", extension::type_t::SETTINGS);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established());
	EXPECT_TRUE(client.settled() && server.settled());
	EXPECT_TRUE(client.settings().empty() && server.settings().empty());
	ASSERT_TRUE(barter(client, server));
}

/**
 * Проверка враждебного сервера: настройки в защищённых расширениях без прикладного
 * протокола обрывают связь извещением illegal_parameter
 */
TEST(AlpsTest, Lying){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("rsa2048", credential));
	client::context_t client;
	client.protocols(vector <string> {"h2"});
	client.settings("h2", bytes("client-h2"));
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::SETTLING, &credential));
	EXPECT_EQ(client.error(), context::error_t::MESSAGE);
	EXPECT_EQ(client.alert().description, alert::description_t::PARAMETER);
	EXPECT_FALSE(client.established());
	EXPECT_FALSE(client.settled());
}

/**
 * Проверка враждебного клиента: предложив ALPS и получив настройки сервера, он шлёт
 * завершение без защищённых расширений - сервер отвечает unexpected_message
 */
TEST(AlpsTest, Missing){
	// Враждебный клиент набора проверок говорит лишь наборами ГОСТ: подлинность и набор ему под стать
	context::credential_t credential;
	ASSERT_TRUE(identity("anyks.com", credential));
	server::context_t server;
	server.credential(credential);
	server.suites(vector <protect::suite_t> {protect::suite_t::MAGMA_MGM_L});
	server.protocols(vector <string> {"h2"});
	server.settings("h2", bytes("server-h2"));
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_TRUE(intruder(server, distortion_t::TACITURN, &credential));
	EXPECT_EQ(server.error(), context::error_t::ORDER);
	EXPECT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	EXPECT_FALSE(server.established());
	EXPECT_TRUE(server.settled());
	// Пустой перечень протоколов с настройками черновиком запрещён: decode_error
	server::context_t another;
	another.credential(credential);
	another.suites(vector <protect::suite_t> {protect::suite_t::MAGMA_MGM_L});
	another.protocols(vector <string> {"h2"});
	another.settings("h2", bytes("server-h2"));
	ASSERT_EQ(another.start(), context::error_t::NONE);
	(void) intruder(another, distortion_t::VOIDSETTLED, &credential);
	EXPECT_EQ(another.error(), context::error_t::MESSAGE);
	EXPECT_EQ(another.alert().description, alert::description_t::DECODE);
	EXPECT_FALSE(another.established() || another.settled());
	// Отказ принят ещё приветствием: наружу ушло одно извещение, а не приветствие сервера
	ASSERT_GT(another.output().size, static_cast <size_t> (0));
	EXPECT_EQ(another.output().data[0], static_cast <uint8_t> (0x15));
}

/**
 * Проверка наследования билетом: при принятых упреждающих данных обе стороны берут
 * настройки из билета, а расширение и сообщение клиента по связи не идут
 */
TEST(AlpsTest, Resumed){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	client::context_t client;
	server::context_t server;
	arrange(client, server, credential, "client-h2", "server-h2", extension::type_t::SETTINGS);
	server.advance(true);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established());
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	converse(client, server);
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
	ASSERT_GT(client.tickets()[0].advance, static_cast <uint32_t> (0));
	client::context_t resuming;
	server::context_t resumed;
	arrange(resuming, resumed, credential, "client-h2", "server-h2", extension::type_t::SETTINGS);
	resumed.advance(true);
	resuming.advance(true);
	resuming.resume(client.tickets()[0]);
	resumed.resume(server.tickets());
	ASSERT_EQ(resumed.start(), context::error_t::NONE);
	ASSERT_EQ(resuming.start(), context::error_t::NONE);
	const string request = "Упреждающие данные по связи с унаследованными настройками";
	ASSERT_EQ(resuming.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	converse(resuming, resumed);
	ASSERT_TRUE(resuming.established() && resumed.established()) << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
	ASSERT_TRUE(resuming.accepted() && resumed.accepted());
	EXPECT_TRUE(resuming.settled() && resumed.settled());
	EXPECT_EQ(resuming.settings(), bytes("server-h2"));
	EXPECT_EQ(resumed.settings(), bytes("client-h2"));
	vector <uint8_t> received;
	ASSERT_EQ(resumed.read(received), context::error_t::NONE);
	EXPECT_EQ(string(received.begin(), received.end()), request);
	ASSERT_TRUE(barter(resuming, resumed));
}

/**
 * Проверка расхождения настроек с билетом: сменившиеся настройки клиента не дают
 * предложить упреждение, сменившиеся настройки сервера - принять его; ALPS при этом
 * договаривается заново
 */
TEST(AlpsTest, Mismatch){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	/**
	 * Выполняем перебор сторон, сменивших настройки: клиент, сервер, обе
	 */
	for(size_t side = 0; side < 3; side++){
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, "client-h2", "server-h2", extension::type_t::SETTINGS);
		server.advance(true);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		converse(client, server);
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		client::context_t resuming;
		server::context_t resumed;
		const bool mine = ((side == 0) || (side == 2)), theirs = ((side == 1) || (side == 2));
		arrange(resuming, resumed, credential, (mine ? "client-h2-changed" : "client-h2"), (theirs ? "server-h2-changed" : "server-h2"), extension::type_t::SETTINGS);
		resumed.advance(true);
		resuming.advance(true);
		resuming.resume(client.tickets()[0]);
		resumed.resume(server.tickets());
		ASSERT_EQ(resumed.start(), context::error_t::NONE);
		ASSERT_EQ(resuming.start(), context::error_t::NONE);
		// Смена настроек клиентом упреждение не предлагает вовсе, смена сервером - отвергает предложенное
		EXPECT_EQ(resuming.earlying(), !mine) << side;
		converse(resuming, resumed);
		ASSERT_TRUE(resuming.established() && resumed.established()) << side << " " << static_cast <int> (resuming.error()) << " " << static_cast <int> (resumed.error());
		ASSERT_TRUE(resuming.shared() && resumed.shared()) << side;
		EXPECT_FALSE(resuming.accepted() || resumed.accepted()) << side;
		EXPECT_TRUE(resuming.settled() && resumed.settled()) << side;
		EXPECT_EQ(resuming.settings(), bytes(theirs ? "server-h2-changed" : "server-h2")) << side;
		EXPECT_EQ(resumed.settings(), bytes(mine ? "client-h2-changed" : "client-h2")) << side;
		ASSERT_TRUE(barter(resuming, resumed)) << side;
	}
	// Без настроек у нового клиента при билете с согласованными настройками упреждение тоже не идёт
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, "client-h2", "server-h2", extension::type_t::SETTINGS);
		server.advance(true);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		converse(client, server);
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		client::context_t resuming;
		server::context_t resumed;
		arrange(resuming, resumed, credential, nullptr, "server-h2", extension::type_t::SETTINGS);
		resumed.advance(true);
		resuming.advance(true);
		resuming.resume(client.tickets()[0]);
		resumed.resume(server.tickets());
		ASSERT_EQ(resumed.start(), context::error_t::NONE);
		ASSERT_EQ(resuming.start(), context::error_t::NONE);
		EXPECT_FALSE(resuming.earlying());
		converse(resuming, resumed);
		ASSERT_TRUE(resuming.established() && resumed.established());
		EXPECT_FALSE(resuming.accepted() || resumed.accepted());
		EXPECT_FALSE(resuming.settled() || resumed.settled());
	}
}

/**
 * Проверка профиля отпечатка с ALPS: снимок приветствия с прежней точкой кода выставляет
 * точку сам, протоколы снимка объявляются с пустыми настройками, и сервер с той же точкой
 * договаривает ALPS
 */
TEST(AlpsTest, Profile){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	fingerprint::profile_t source;
	{
		client::context_t donor;
		donor.name("example.com");
		donor.protocols(vector <string> {"h2", "http/1.1"});
		donor.settings("h2", bytes("donor-h2"));
		donor.codepoint(extension::type_t::SETTINGS_OLD);
		ASSERT_EQ(donor.start(), context::error_t::NONE);
		ASSERT_EQ(fingerprint::parse(donor.output(), source), fingerprint::error_t::NONE);
	}
	bool found = false;
	/**
	 * Выполняем перебор расширений снимка
	 */
	for(size_t i = 0; i < source.extensions.size(); i++){
		if(source.extensions[i].type == static_cast <uint16_t> (extension::type_t::SETTINGS_OLD)){
			found = true;
			ASSERT_EQ(source.extensions[i].protocols.size(), static_cast <size_t> (1));
			EXPECT_EQ(source.extensions[i].protocols[0], "h2");
		}
		EXPECT_NE(source.extensions[i].type, static_cast <uint16_t> (extension::type_t::SETTINGS));
	}
	ASSERT_TRUE(found);
	client::context_t client;
	server::context_t server;
	client.name("example.com");
	ASSERT_EQ(client.profile(source), context::error_t::NONE);
	EXPECT_EQ(client.codepoint(), extension::type_t::SETTINGS_OLD);
	server.credential(credential);
	server.protocols(vector <string> {"h2"});
	server.settings("h2", bytes("server-h2"));
	server.codepoint(extension::type_t::SETTINGS_OLD);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	fingerprint::profile_t made;
	ASSERT_EQ(fingerprint::parse(client.output(), made), fingerprint::error_t::NONE);
	ASSERT_EQ(made.extensions.size(), source.extensions.size());
	/**
	 * Выполняем сличение видов и тел расширений снимка и сложенного приветствия
	 */
	for(size_t i = 0; i < made.extensions.size(); i++){
		EXPECT_EQ(made.extensions[i].type, source.extensions[i].type) << i;
		if((made.extensions[i].type == static_cast <uint16_t> (extension::type_t::SETTINGS_OLD)) || (made.extensions[i].type == static_cast <uint16_t> (extension::type_t::PROTOCOLS)))
			EXPECT_EQ(made.extensions[i].data, source.extensions[i].data) << i;
	}
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
	EXPECT_EQ(client.protocol(), "h2");
	EXPECT_TRUE(client.settled() && server.settled());
	EXPECT_EQ(client.settings(), bytes("server-h2"));
	EXPECT_TRUE(server.settings().empty());
	ASSERT_TRUE(barter(client, server));
	// Профиль с ALPS против сервера иной точки кода: связь без настроек
	client::context_t other;
	server::context_t another;
	other.name("example.com");
	ASSERT_EQ(other.profile(source), context::error_t::NONE);
	another.credential(credential);
	another.protocols(vector <string> {"h2"});
	another.settings("h2", bytes("server-h2"));
	ASSERT_EQ(another.start(), context::error_t::NONE);
	ASSERT_EQ(other.start(), context::error_t::NONE);
	converse(other, another);
	ASSERT_TRUE(other.established() && another.established());
	EXPECT_FALSE(other.settled() || another.settled());
}

/**
 * Проверка записи билета с полями ALPS: круг записи и чтения, издание 3, обрезание
 */
TEST(AlpsTest, Ticket){
	context::ticket_t ticket;
	ticket.suite = protect::suite_t::AES_128_GCM_SHA256;
	ticket.protocol = "h2";
	ticket.settled = true;
	ticket.settings = bytes("mine");
	ticket.obtained = bytes("theirs");
	ticket.identity.assign(8, 0x11);
	ticket.secret.assign(32, 0x22);
	vector <uint8_t> encoded;
	ASSERT_EQ(context::encode(ticket, encoded), context::error_t::NONE);
	EXPECT_EQ(encoded[0], static_cast <uint8_t> (0x04));
	context::ticket_t decoded;
	ASSERT_EQ(context::decode(view_t(encoded.data(), encoded.size()), decoded), context::error_t::NONE);
	EXPECT_TRUE(decoded.settled);
	EXPECT_EQ(decoded.settings, ticket.settings);
	EXPECT_EQ(decoded.obtained, ticket.obtained);
	EXPECT_EQ(decoded.protocol, "h2");
	/**
	 * Отказ: обрезание записи на всякой длине
	 */
	for(size_t i = 1; i < encoded.size(); i++)
		ASSERT_EQ(context::decode(view_t(encoded.data(), i), decoded), context::error_t::TICKET) << "длина " << i;
	// Признак согласования вне 0..1
	vector <uint8_t> broken = encoded;
	broken[encoded.size() - ticket.settings.size() - ticket.obtained.size() - 5] = 0x02;
	EXPECT_EQ(context::decode(view_t(broken.data(), broken.size()), decoded), context::error_t::TICKET);
	// Прежнее издание записи отвергается
	broken = encoded;
	broken[0] = 0x02;
	EXPECT_EQ(context::decode(view_t(broken.data(), broken.size()), decoded), context::error_t::TICKET);
	// Пустой билет: настройки не согласованы
	const context::ticket_t blank;
	EXPECT_FALSE(blank.settled);
	ASSERT_EQ(context::encode(blank, encoded), context::error_t::NONE);
	ASSERT_EQ(context::decode(view_t(encoded.data(), encoded.size()), decoded), context::error_t::NONE);
	EXPECT_FALSE(decoded.settled);
	EXPECT_TRUE(decoded.settings.empty() && decoded.obtained.empty());
}

/**
 * Проверка отказов: настройки для протокола вне перечня, непомерное имя протокола,
 * чужой вид расширения точкой кода, издание 1.2 без ALPS
 */
TEST(AlpsTest, Refusals){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	{
		client::context_t client;
		client.protocols(vector <string> {"h2"});
		client.settings("http/1.1", bytes("x"));
		EXPECT_EQ(client.start(), context::error_t::PROTOCOL);
	}
	{
		server::context_t server;
		server.credential(credential);
		server.protocols(vector <string> {"h2"});
		server.settings("h3", bytes("x"));
		EXPECT_EQ(server.start(), context::error_t::PROTOCOL);
	}
	{
		client::context_t client;
		const string longest(256, 'a');
		client.protocols(vector <string> {longest});
		client.settings(longest, bytes("x"));
		EXPECT_EQ(client.start(), context::error_t::PROTOCOL);
	}
	{
		client::context_t client;
		client.codepoint(extension::type_t::SETTINGS_OLD);
		client.codepoint(extension::type_t::NAME);
		EXPECT_EQ(client.codepoint(), extension::type_t::SETTINGS_OLD);
		client.codepoint(extension::type_t::SETTINGS);
		EXPECT_EQ(client.codepoint(), extension::type_t::SETTINGS);
	}
	{
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, "client-h2", "server-h2", extension::type_t::SETTINGS);
		ASSERT_EQ(client.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.versions(0x0303, 0x0303), context::error_t::NONE);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		fingerprint::profile_t made;
		ASSERT_EQ(fingerprint::parse(client.output(), made), fingerprint::error_t::NONE);
		/**
		 * Выполняем перебор расширений приветствия издания 1.2
		 */
		for(size_t i = 0; i < made.extensions.size(); i++)
			EXPECT_NE(made.extensions[i].type, static_cast <uint16_t> (extension::type_t::SETTINGS)) << i;
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		EXPECT_FALSE(client.settled() || server.settled());
	}
	{
		// Повтор по тому же протоколу заменяет настройки
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, "first", "server-h2", extension::type_t::SETTINGS);
		client.settings("h2", bytes("second"));
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		EXPECT_EQ(server.settings(), bytes("second"));
	}
}

/**
 * Проверка под пайком памяти: связь с настройками либо устанавливается, либо честно
 * отвечает нехваткой памяти
 */
TEST(AlpsTest, Starved){
	context::credential_t credential;
	ASSERT_TRUE(keyfile("ec256", credential));
	bool starved = false;
	bool complete = false;
	/**
	 * Выполняем перебор запасов выделений
	 */
	for(size_t budget = 0; (budget < 4000) && !complete; budget += ((budget < 200) ? 1 : 37)){
		client::context_t client;
		server::context_t server;
		arrange(client, server, credential, "client-h2", "server-h2", extension::type_t::SETTINGS);
		context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
		{
			starve::ration_t ration(budget);
			first = server.start();
			second = client.start();
			if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
				converse(client, server);
				first = server.error();
				second = client.error();
			}
		}
		starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY));
		const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
			((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL)));
		ASSERT_TRUE(lawful) << "запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second);
		complete = (client.established() && server.established());
		if(complete){
			EXPECT_TRUE(client.settled() && server.settled());
			EXPECT_EQ(client.settings(), bytes("server-h2"));
			EXPECT_EQ(server.settings(), bytes("client-h2"));
		}
	}
	ASSERT_TRUE(starved);
	ASSERT_TRUE(complete);
}
