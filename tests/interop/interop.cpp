/**
 * @file interop.cpp
 * @date 2026-09-06
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
 * @brief Исходный файл проверок обмена классических наборов TLS 1.3 с настоящим openssl:
 *        наш клиент против s_server и s_client против нашего сервера по всем ключам
 *        набора, трём наборам шифрования и трём группам обмена
 *
 * @note Набор вынесен из проверок classic, чтобы те не зависели от системного openssl;
 *       ключи и сертификаты берутся из набора tests/corpus
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
#include <iostream>
#include <unistd.h>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <openssl.hpp>
#include <pem/pem.hpp>
#include <protect/protect.hpp>
#include <extension/extension.hpp>
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
	 * Наборы шифрования классической ветви
	 */
	static const protect::suite_t SUITES[] = {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::CHACHA20_POLY1305_SHA256};
	/**
	 * @brief Метод получения имени набора шифрования у openssl
	 *
	 * @param suite набор шифрования
	 *
	 * @return      имя набора у openssl
	 *
	 */
	const char * title(const protect::suite_t suite) noexcept {
		/**
		 * Определяем набор шифрования
		 */
		switch(static_cast <uint16_t> (suite)){
			// TLS_AES_128_GCM_SHA256
			case static_cast <uint16_t> (protect::suite_t::AES_128_GCM_SHA256):
				// Выводим имя набора
				return "TLS_AES_128_GCM_SHA256";
			// TLS_AES_256_GCM_SHA384
			case static_cast <uint16_t> (protect::suite_t::AES_256_GCM_SHA384):
				// Выводим имя набора
				return "TLS_AES_256_GCM_SHA384";
			// TLS_CHACHA20_POLY1305_SHA256
			case static_cast <uint16_t> (protect::suite_t::CHACHA20_POLY1305_SHA256):
				// Выводим имя набора
				return "TLS_CHACHA20_POLY1305_SHA256";
		}
		// Выводим пустое имя
		return "";
	}
	/**
	 * Группы обмена классической ветви
	 */
	static const extension::group_t GROUPS[] = {extension::group_t::X25519, extension::group_t::SECP256R1, extension::group_t::SECP384R1};
	/**
	 * Ключи набора и схемы их подписи
	 */
	static const struct Entry {
		// Имя ключа набора
		const char * name;
		// Схема подписи ключа
		extension::scheme_t scheme;
	} ENTRIES[] = {
		{"rsa2048", extension::scheme_t::RSA_PSS_RSAE_SHA256},
		{"ec256", extension::scheme_t::ECDSA_SECP256R1_SHA256},
		{"ec384", extension::scheme_t::ECDSA_SECP384R1_SHA384},
		{"ed25519", extension::scheme_t::ED25519}
	};
	/**
	 * @brief Метод щупа набора шифрования TLS 1.3 у openssl
	 *
	 * @param suite набор шифрования
	 *
	 * @return      признак того, что openssl умеет набор (проба возможности)
	 *
	 */
	bool capable(const protect::suite_t suite) noexcept {
		// Пробуем набор у openssl
		return (shell(std::string("openssl ciphers -s -tls1_3 -ciphersuites ") + title(suite) + " >/dev/null 2>&1") == 0);
	}
	/**
	 * @brief Метод оглашения пропусков частей сличения
	 *
	 * @param toolkit способности openssl
	 * @param chacha  признак того, что openssl умеет TLS_CHACHA20_POLY1305_SHA256
	 *
	 */
	void announce(const toolkit_t & toolkit, const bool chacha) noexcept {
		// Если openssl без Ed25519
		if(!toolkit.edwards)
			// Сообщаем о пропуске части вслух
			std::cout << "openssl без Ed25519: сличение по ключу ed25519 пропущено" << std::endl;
		// Если openssl без ChaCha20-Poly1305
		if(!chacha)
			// Сообщаем о пропуске части вслух
			std::cout << "openssl без TLS_CHACHA20_POLY1305_SHA256: сличение по набору 0x1303 пропущено" << std::endl;
	}
};

/**
 * Проверка обмена с настоящим openssl: наш клиент против s_server по всем ключам набора,
 * трём наборам шифрования и трём группам обмена с взаимной подлинностью и ответом HTTP
 */
TEST(InteropTest, Server){
	// Способности системного openssl, снятые щупами
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен
	if(!toolkit.present){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl не умеет TLS 1.3 (проба возможности, не по номеру издания)
	if(!toolkit.tls13){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без TLS 1.3";
	}
	// Признак того, что openssl умеет TLS_CHACHA20_POLY1305_SHA256 (проба возможности)
	const bool chacha = capable(protect::suite_t::CHACHA20_POLY1305_SHA256);
	// Оглашаем пропуски частей
	announce(toolkit, chacha);
	/**
	 * Выполняем перебор ключей набора
	 */
	for(size_t k = 0; k < (sizeof(ENTRIES) / sizeof(ENTRIES[0])); k++){
		// Если ключ Ed25519 недоступен openssl
		if(!toolkit.edwards && (ENTRIES[k].scheme == extension::scheme_t::ED25519))
			// Переходим к следующему ключу
			continue;
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity(ENTRIES[k].name, credential));
		// Пути к сертификату и ключу
		const std::string crt = std::string(CORPUS) + "/" + ENTRIES[k].name + ".crt", key = std::string(CORPUS) + "/" + ENTRIES[k].name + ".pem";
		/**
		 * Выполняем перебор наборов шифрования
		 */
		for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
			// Если набор ChaCha20-Poly1305 недоступен openssl
			if(!chacha && (SUITES[s] == protect::suite_t::CHACHA20_POLY1305_SHA256))
				// Переходим к следующему набору
				continue;
			// Имя набора у openssl
			const char * name = title(SUITES[s]);
			/**
			 * Выполняем перебор групп обмена
			 */
			for(size_t g = 0; g < (sizeof(GROUPS) / sizeof(GROUPS[0])); g++){
				// Имя группы у openssl
				const char * curve = naming(GROUPS[g]);
				// Свободный порт
				const uint16_t number = vacant(false);
				// Проверяем наличие порта
				ASSERT_NE(number, 0);
				// Журнал сервера openssl
				const std::string log = "/tmp/ants-interop-server-" + std::to_string(number) + ".log";
				// Запускаем сервер openssl в один приём с ответом HTTP и с запросом подлинности клиента
				ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_3 -cert " + crt + " -key " + key + " -Verify 1 -CAfile " + crt + " -ciphersuites " + name + " -groups " + curve + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
				// Сторож сервера openssl: снимается по номеру и при отказе посреди проверки
				sentinel_t sentinel(log + ".pid");
				// Подключаемся к серверу openssl
				const int fd = dial(number);
				// Проверяем подключение
				ASSERT_GE(fd, 0) << "порт " << number;
				// Связь стороны клиента
				client::context_t client;
				// Наборы клиента
				client.suites(vector <protect::suite_t> {SUITES[s]});
				// Группы клиента
				client.groups(vector <extension::group_t> {GROUPS[g]});
				// Подлинность клиента тем же ключом
				client.credential(credential);
				// Имя узла
				client.name("localhost");
				// Заводим клиента
				ASSERT_EQ(client.start(), context::error_t::NONE);
				/**
				 * Выполняем передачу байтов до установления связи
				 */
				for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
					// Передаём байты
					relay(client, fd);
				// Проверяем установленность связи
				ASSERT_TRUE(client.established()) << ENTRIES[k].name << " " << name << " " << curve << " отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
				// Проверяем набор
				ASSERT_EQ(client.suite(), SUITES[s]);
				// Проверяем цепочку сервера
				ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
				// Запрос HTTP серверу openssl
				const string request = "GET / HTTP/1.0\r\n\r\n";
				// Отправляем запрос
				ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
				// Накопитель ответа
				vector <uint8_t> answer;
				/**
				 * Выполняем передачу байтов до получения ответа
				 */
				for(size_t i = 0; (i < 16) && answer.empty(); i++){
					// Передаём байты
					relay(client, fd);
					// Читаем принятые данные
					ASSERT_EQ(client.read(answer), context::error_t::NONE);
				}
				// Проверяем, что ответ HTTP получен
				ASSERT_NE(string(answer.begin(), answer.end()).find("HTTP/1.0 200"), string::npos) << ENTRIES[k].name << " " << name << " " << curve;
				// Закрываем сокет
				closing(fd);
				// Снимаем сервер до удаления журнала: иначе отметка завершения воссоздаст файл
				sentinel.halt();
				// Журнал сервера
				std::string journal;
				// Дожидаемся отметки завершения снятого сервера
				(void) settle(log, journal);
				// Удаляем журнал
				::remove(log.c_str());
			}
		}
	}
}

/**
 * Проверка обмена с настоящим openssl: s_client против нашего сервера по всем ключам
 * набора, трём наборам шифрования и трём группам обмена с подлинностью клиента и
 * проверкой сертификата сервера у клиента openssl
 */
TEST(InteropTest, Client){
	// Способности системного openssl, снятые щупами
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен
	if(!toolkit.present){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl не умеет TLS 1.3 (проба возможности, не по номеру издания)
	if(!toolkit.tls13){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без TLS 1.3";
	}
	// Признак того, что openssl умеет TLS_CHACHA20_POLY1305_SHA256 (проба возможности)
	const bool chacha = capable(protect::suite_t::CHACHA20_POLY1305_SHA256);
	// Оглашаем пропуски частей
	announce(toolkit, chacha);
	/**
	 * Выполняем перебор ключей набора
	 */
	for(size_t k = 0; k < (sizeof(ENTRIES) / sizeof(ENTRIES[0])); k++){
		// Если ключ Ed25519 недоступен openssl
		if(!toolkit.edwards && (ENTRIES[k].scheme == extension::scheme_t::ED25519))
			// Переходим к следующему ключу
			continue;
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(identity(ENTRIES[k].name, credential));
		// Пути к сертификату и ключу
		const std::string crt = std::string(CORPUS) + "/" + ENTRIES[k].name + ".crt", key = std::string(CORPUS) + "/" + ENTRIES[k].name + ".pem";
		/**
		 * Выполняем перебор наборов шифрования
		 */
		for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
			// Если набор ChaCha20-Poly1305 недоступен openssl
			if(!chacha && (SUITES[s] == protect::suite_t::CHACHA20_POLY1305_SHA256))
				// Переходим к следующему набору
				continue;
			// Имя набора у openssl
			const char * name = title(SUITES[s]);
			/**
			 * Выполняем перебор групп обмена
			 */
			for(size_t g = 0; g < (sizeof(GROUPS) / sizeof(GROUPS[0])); g++){
				// Имя группы у openssl
				const char * curve = naming(GROUPS[g]);
				// Порт сервера
				uint16_t number = 0;
				// Слушающий сокет
				const int listener = harbour(number);
				// Проверяем сокет
				ASSERT_GE(listener, 0);
				// Журнал клиента openssl
				const std::string log = "/tmp/ants-interop-client-" + std::to_string(number) + ".log";
				// Запускаем клиента openssl: подлинность клиента тем же ключом, сервер проверяется по своему сертификату
				ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_3 -CAfile " + crt + " -cert " + crt + " -key " + key + " -ciphersuites " + name + " -groups " + curve + " -servername localhost -verify_return_error </dev/null >" + log + " 2>&1", log, log + ".pid"));
				// Сторож клиента openssl
				sentinel_t sentinel(log + ".pid");
				// Принимаем подключение
				const int fd = greeted(listener);
				// Проверяем подключение
				ASSERT_GE(fd, 0);
				// Связь стороны сервера
				server::context_t server;
				// Наборы сервера
				server.suites(vector <protect::suite_t> {SUITES[s]});
				// Группы сервера
				server.groups(vector <extension::group_t> {GROUPS[g]});
				// Подлинность сервера
				server.credential(credential);
				// Запрашиваем подлинность клиента
				server.request(true);
				// Заводим сервер
				ASSERT_EQ(server.start(), context::error_t::NONE);
				// Ведём связь до конца рукопожатия
				const bool complete = serve(server, fd);
				// Проверяем, что рукопожатие дошло до конца
				ASSERT_TRUE(complete) << ENTRIES[k].name << " " << name << " " << curve << " отказ " << static_cast <int> (server.error());
				// Проверяем, что отказа не было
				ASSERT_EQ(server.error(), context::error_t::NONE) << ENTRIES[k].name << " " << name << " " << curve;
				// Проверяем набор
				ASSERT_EQ(server.suite(), SUITES[s]);
				// Проверяем подлинность клиента
				ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
				// Закрываем связь, коли она ещё открыта
				ASSERT_TRUE(farewell(server, fd));
				// Закрываем сокет
				closing(fd);
				// Закрываем слушающий сокет
				closing(listener);
				// Текст журнала клиента
				std::string text;
				// Клиент обязан завершиться
				ASSERT_TRUE(settle(log, text)) << text;
				// Проверка подлинности сервера у клиента обязана сойтись
				ASSERT_NE(text.find("Verify return code: 0 (ok)"), std::string::npos) << text;
				// Удаляем журнал
				::remove(log.c_str());
			}
		}
	}
}
