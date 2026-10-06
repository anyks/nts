/**
 * @file interop.cpp
 * @date 2026-10-06
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
 * @brief Исходный файл проверок связи модуля ACME с эталонным сервером
 *
 * @note Эталоном служит сервер Pebble (Let's Encrypt): проверка прогоняет
 *       полный поток RFC 8555 — directory, newNonce, newAccount, newOrder,
 *       ответ на испытание http-01, finalize с запросом PKCS #10 модуля
 *       x509::request, сгрузка сертификата и его отзыв. Транспортом HTTP
 *       служит curl: модуль ACME транспорта не несёт. Проверка пропускается,
 *       если сервер недоступен по адресу https://localhost:14000/dir
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
#include <sstream>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <posix.hpp>
#include <pem/pem.hpp>
#include <jws/jws.hpp>
#include <acme/acme.hpp>
#include <x509/x509.hpp>
#include <x509/request.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору образцов проверок
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * Адрес каталога эталонного сервера
 */
static const char * PEBBLE = "https://localhost:14000/dir";

/**
 * Служебные объекты проверок связи с эталонным сервером
 */
namespace {
	/**
	 * @brief Метод чтения файла целиком
	 *
	 * @param path путь к читаемому файлу
	 *
	 * @return     содержимое файла
	 *
	 */
	static std::string slurp(const std::string & path) {
		// Открываем файл на чтение
		std::ifstream file(path, std::ios::binary);
		// Читаем содержимое файла в поток
		std::stringstream stream;
		// Переливаем содержимое файла
		stream << file.rdbuf();
		// Выводим содержимое файла
		return stream.str();
	}
	/**
	 * @brief Метод получения просмотра строки
	 *
	 * @param text строка, на которую заводится просмотр
	 *
	 * @return     просмотр строки
	 *
	 */
	static view_t view(const std::string & text) {
		// Выводим просмотр строки
		return view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size());
	}
	/**
	 * @brief Метод запуска команды интерпретатора
	 *
	 * @param command запускаемая команда
	 *
	 * @return        код ответа команды
	 *
	 */
	static int shell(const std::string & command) noexcept {
		// Запускаем команды с пустым входом
		return ::system((command + " </dev/null").c_str());
	}
	/**
	 * @brief Песочница файлов проверки
	 *
	 */
	typedef struct Sandbox {
		// Путь к песочнице
		std::string _path;
		/**
		 * @brief Метод заведения песочницы
		 *
		 * @return признак успешности заведения
		 *
		 */
		bool ready() noexcept {
			// Образец пути песочницы
			char pattern[] = "/tmp/ants-acme-XXXXXX";
			// Заводим песочницу
			const char * made = ::mkdtemp(pattern);
			// Если песочница завелась
			if(made != nullptr)
				// Запоминаем путь к ней
				this->_path.assign(made);
			// Выводим признак заведения
			return (made != nullptr);
		}
		/**
		 * @brief Метод получения пути к файлу песочницы
		 *
		 * @param name имя файла
		 *
		 * @return     путь к файлу песочницы
		 *
		 */
		std::string file(const std::string & name) const {
			// Выводим путь к файлу
			return (this->_path + "/" + name);
		}
		/**
		 * @brief Метод записи файла песочницы
		 *
		 * @param name    имя файла
		 * @param content содержимое файла
		 *
		 */
		void spill(const std::string & name, const std::string & content) const {
			// Открываем файл на запись
			std::ofstream file(this->file(name), std::ios::binary);
			// Записываем содержимое
			file << content;
		}
		/**
		 * @brief Деструктор песочницы
		 *
		 */
		~Sandbox() noexcept {
			// Если песочница заведена
			if(!this->_path.empty())
				// Убираем песочницу
				(void) shell((std::string("rm -rf ") + this->_path).c_str());
		}
	} sandbox_t;
	/**
	 * @brief Ответ HTTP эталонного сервера
	 *
	 */
	typedef struct Answer {
		// Состояние ответа HTTP
		uint32_t status;
		// Метка новизны из заголовка Replay-Nonce
		std::string nonce;
		// Адрес из заголовка Location
		std::string location;
		// Тело ответа
		std::string body;
	} answer_t;
	/**
	 * @brief Метод выполнения запроса HTTP к эталонному серверу
	 *
	 * @param sandbox песочница файлов проверки
	 * @param method  метод запроса: GET либо POST
	 * @param url     адрес запроса
	 * @param body    тело запроса, пустое у запроса GET
	 * @param result  ответ сервера
	 *
	 * @return        признак того, что ответ получен
	 *
	 */
	static bool http(const sandbox_t & sandbox, const std::string & method, const std::string & url, const std::string & body, answer_t & result) {
		// Файлы заголовков и тела ответа
		const std::string headers = sandbox.file("headers.txt");
		const std::string content = sandbox.file("body.txt");
		// Команда запроса
		std::string command = "curl -sk -A ants-acme -o " + content + " -D " + headers + " -X " + method;
		// Если тело задано: запрос несёт тело application/jose+json
		if(!body.empty()){
			// Записываем тело запроса в файл
			sandbox.spill("request.txt", body);
			// Дописываем тело запроса
			command += " -H \"Content-Type: application/jose+json\" --data-binary @" + sandbox.file("request.txt");
		}
		// Дописываем адрес запроса
		command += " " + url;
		// Выполняем запрос
		if(shell(command + " >/dev/null 2>&1") != 0)
			// Выводим отказ запроса
			return false;
		// Читаем заголовки ответа
		const std::string head = slurp(headers);
		// Если заголовков нет
		if(head.empty())
			// Выводим отказ запроса
			return false;
		// Извлекаем состояние ответа
		{
			// Позиция состояния
			const size_t position = head.find(' ');
			// Если состояния нет
			if(position == std::string::npos)
				// Выводим отказ запроса
				return false;
			// Разбираем состояние
			result.status = static_cast <uint32_t> (::strtoul(head.c_str() + position + 1, nullptr, 10));
		}
		// Извлекаем метку новизны
		result.nonce.clear();
		{
			// Позиция заголовка Replay-Nonce: берём последнее вхождение, у ответа
			// с продолжением заголовков несколько блоков
			size_t position = head.rfind("Replay-Nonce: ");
			// Если заголовок не найден в ином регистре
			if(position == std::string::npos)
				// Ищем в ином регистре
				position = head.rfind("replay-nonce: ");
			// Если заголовок найден
			if(position != std::string::npos){
				// Переносим позицию за имя заголовка
				position += 14;
				// Конец значения заголовка
				const size_t end = head.find('\n', position);
				// Извлекаем значение заголовка
				result.nonce = head.substr(position, ((end == std::string::npos) ? end : (end - position)));
				// Убираем возврат каретки
				while(!result.nonce.empty() && ((result.nonce.back() == '\r') || (result.nonce.back() == ' ')))
					// Усекаем значение
					result.nonce.pop_back();
			}
		}
		// Извлекаем адрес Location
		result.location.clear();
		{
			// Позиция заголовка Location
			size_t position = head.find("Location: ");
			// Если заголовок не найден в ином регистре
			if(position == std::string::npos)
				// Ищем в ином регистре
				position = head.find("location: ");
			// Если заголовок найден
			if(position != std::string::npos){
				// Переносим позицию за имя заголовка
				position += 10;
				// Конец значения заголовка
				const size_t end = head.find('\n', position);
				// Извлекаем значение заголовка
				result.location = head.substr(position, ((end == std::string::npos) ? end : (end - position)));
				// Убираем возврат каретки
				while(!result.location.empty() && ((result.location.back() == '\r') || (result.location.back() == ' ')))
					// Усекаем значение
					result.location.pop_back();
			}
		}
		// Читаем тело ответа
		result.body = slurp(content);
		// Выводим полученность ответа
		return true;
	}
	/**
	 * @brief Метод выполнения запроса ACME к эталонному серверу
	 *
	 * @param sandbox песочница файлов проверки
	 * @param url     адрес ресурса запроса
	 * @param nonce   метка новизны
	 * @param kid     адрес учётной записи, пустой при записи ключа JWK
	 * @param key     сведения об открытом ключе учётной записи
	 * @param payload полезная нагрузка запроса
	 * @param signer  подготовленный секретный ключ учётной записи
	 * @param result  ответ сервера
	 *
	 * @return        признак того, что ответ получен и подпись принята
	 *
	 */
	static bool call(const sandbox_t & sandbox, const std::string & url, const std::string & nonce, const std::string & kid, const keys::key_t & key, const std::string & payload, const keys::signer_t & signer, answer_t & result) {
		// Выполняем запрос с повтором по отказу badNonce, как велит раздел 6.5 RFC 8555
		for(size_t attempt = 0; attempt < 3; attempt++){
			// Собираем тело запроса
			std::string body;
			// Если тело собрать не удалось
			if(acme::request(url, nonce, kid, key, view(payload), signer, body) != acme::error_t::NONE)
				// Выводим отказ запроса
				return false;
			// Выполняем запрос
			if(!http(sandbox, "POST", url, body, result))
				// Выводим отказ запроса
				return false;
			// Если отказ не о метке новизны
			if(result.body.find("badNonce") == std::string::npos)
				// Выводим полученность ответа
				return true;
			// Если свежей метки ответ не несёт
			if(result.nonce.empty())
				// Выводим отказ запроса
				return false;
			// Обновляем метку новизны
			nonce = result.nonce;
		}
		// Повторы исчерпаны
		return false;
	}
}

/**
 * @brief Проверка полного потока ACME против эталонного сервера Pebble
 *
 */
TEST(AcmeInteropTest, Pebble) {
	// Если эталонный сервер недоступен: проверка пропускается
	if(shell(std::string("curl -sk --max-time 3 ") + PEBBLE + " >/dev/null 2>&1") != 0)
		// Пропускаем проверку
		GTEST_SKIP() << "Сервер Pebble недоступен по адресу " << PEBBLE;
	// Заводим песочницу файлов проверки
	sandbox_t sandbox;
	// Песочница обязана завестись
	ASSERT_TRUE(sandbox.ready());
	// Разбираем ключ учётной записи набора
	keys::key_t key;
	{
		// Читаем запись ключа
		const std::string text = slurp(std::string(CORPUS) + "/ca-ec.key");
		// Разбор обязан удаться
		ASSERT_EQ(keys::decode(text, view_t(), key), keys::error_t::NONE);
	}
	// Готовим ключ подписи учётной записи
	keys::signer_t signer;
	ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/ca-ec.key"))), keys::error_t::NONE);
	// Разбираем каталог службы
	acme::directory_t directory;
	{
		// Ответ сервера
		answer_t answer;
		// Запрашиваем каталог
		ASSERT_TRUE(http(sandbox, "GET", PEBBLE, "", answer));
		// Состояние ответа - 200
		ASSERT_EQ(answer.status, 200);
		// Разбор каталога обязан удаться
		ASSERT_EQ(directory.parse(view(answer.body)), acme::error_t::NONE) << answer.body;
	}
	// Запрашиваем метку новизны
	std::string nonce;
	{
		// Ответ сервера
		answer_t answer;
		// Запрашиваем метку
		ASSERT_TRUE(http(sandbox, "GET", directory.newNonce, "", answer));
		// Состояние ответа - 204
		ASSERT_EQ(answer.status, 204);
		// Метка обязана быть
		ASSERT_FALSE(answer.nonce.empty());
		// Запоминаем метку
		nonce = answer.nonce;
	}
	// Заводим учётную запись
	std::string kid;
	{
		// Полезная нагрузка заведения записи
		std::string payload;
		acme::newAccount({"mailto:admin@example.org"}, true, false, payload);
		// Ответ сервера
		answer_t answer;
		// Заводим запись
		ASSERT_TRUE(call(sandbox, directory.newAccount, nonce, "", key, payload, signer, answer));
		// Состояние ответа - 201 либо 200: запись заведена либо уже была, подпись JWK принята
		ASSERT_TRUE((answer.status == 201) || (answer.status == 200)) << answer.body;
		// Адрес записи обязан быть
		ASSERT_FALSE(answer.location.empty());
		// Запоминаем адрес записи
		kid = answer.location;
		// Разбираем ответ записи
		acme::account_t account;
		ASSERT_EQ(account.parse(view(answer.body)), acme::error_t::NONE) << answer.body;
		// Состояние записи - valid
		ASSERT_EQ(account.status, "valid");
		// Обновляем метку новизны
		nonce = answer.nonce;
	}
	// Заводим заказ
	std::string orderUrl;
	acme::order_t order;
	{
		// Полезная нагрузка заведения заказа
		std::string payload;
		ASSERT_EQ(acme::newOrder({{acme::identifier_t::DNS, "example.org"}}, payload), acme::error_t::NONE);
		// Ответ сервера
		answer_t answer;
		// Заводим заказ
		ASSERT_TRUE(call(sandbox, directory.newOrder, nonce, kid, key, payload, signer, answer));
		// Состояние ответа - 201: заказ заведён, подпись kid принята
		ASSERT_EQ(answer.status, 201) << answer.body;
		// Запоминаем адрес заказа
		orderUrl = answer.location;
		// Разбираем заказ
		ASSERT_EQ(order.parse(view(answer.body)), acme::error_t::NONE) << answer.body;
		// Состояние заказа - pending либо ready: служба вправе подтвердить сразу
		ASSERT_TRUE((order.status.compare("pending") == 0) || (order.status.compare("ready") == 0)) << answer.body;
		// Идентификатор заказа один
		ASSERT_EQ(order.identifiers.size(), 1);
		ASSERT_EQ(order.identifiers[0].second, "example.org");
		// Запись полномочий одна
		ASSERT_EQ(order.authorizations.size(), 1);
		// Обновляем метку новизны
		nonce = answer.nonce;
	}
	// Разбираем запись полномочий
	acme::authorization_t authorization;
	{
		// Ответ сервера
		answer_t answer;
		// Запрашиваем запись полномочий запросом POST-as-GET
		ASSERT_TRUE(call(sandbox, order.authorizations[0], nonce, kid, key, "", signer, answer));
		// Состояние ответа - 200
		ASSERT_EQ(answer.status, 200) << answer.body;
		// Разбор записи обязан удаться
		ASSERT_EQ(authorization.parse(view(answer.body)), acme::error_t::NONE) << answer.body;
		// Обновляем метку новизны
		nonce = answer.nonce;
	}
	// Ищем испытание dns-01: Pebble резолвит его моком DNS сам
	const acme::challenge_t * challenge = nullptr;
	// Выполняем обход испытаний записи
	for(size_t position = 0; position < authorization.challenges.size(); position++){
		// Если испытание dns-01
		if(authorization.challenges[position].type.compare("dns-01") == 0)
			// Запоминаем испытание
			challenge = &authorization.challenges[position];
	}
	// Испытание dns-01 обязано быть
	ASSERT_TRUE(challenge != nullptr);
	// Вырабатываем полномочный ключ испытания: мок DNS Pebble отвечает им сам
	std::string authorization_key;
	ASSERT_EQ(acme::keyAuthorization(challenge->token, key, authorization_key), acme::error_t::NONE);
	// Отвечаем на испытание
	{
		// Полезная нагрузка ответа на испытание
		std::string payload;
		acme::answer(payload);
		// Ответ сервера
		answer_t answer;
		// Отвечаем на испытание
		ASSERT_TRUE(call(sandbox, challenge->url, nonce, kid, key, payload, signer, answer));
		// Состояние ответа - 200: ответ принят; 400 - испытание уже подтверждено
		// службой в режиме всегда действующей проверки
		ASSERT_TRUE((answer.status == 200) || (answer.status == 400)) << answer.body;
		// Обновляем метку новизны
		nonce = answer.nonce;
	}
	// Pebble проверяет испытание http-01 обращением к адресу идентификатора:
	// проверка идёт мимо нас, потому ждём итогового состояния записи опросом
	{
		// Состояние записи полномочий
		std::string status;
		// Выполняем опрос записи до итогового состояния
		for(size_t attempt = 0; attempt < 10; attempt++){
			// Ответ сервера
			answer_t answer;
			// Запрашиваем запись полномочий
			ASSERT_TRUE(call(sandbox, order.authorizations[0], nonce, kid, key, "", signer, answer));
			// Разбираем запись
			acme::authorization_t current;
			ASSERT_EQ(current.parse(view(answer.body)), acme::error_t::NONE) << answer.body;
			// Обновляем метку новизны
			nonce = answer.nonce;
			// Если состояние итоговое
			if(current.status.compare("pending") != 0){
				// Запоминаем состояние
				status = current.status;
				// Выходим из опроса
				break;
			}
			// Ждём секунду
			::sleep(1);
		}
		// Запись обязана стать действующей: мок DNS Pebble отвечает на испытание
		// dns-01 полномочным ключом сам
		ASSERT_EQ(status, "valid");
	}
	// Готовим запрос на сертификат модулем x509::request
	std::vector <uint8_t> csr;
	// Запись запроса набора: ключ владельца берём из него, запись обязана пережить разобранный запрос
	const std::string referenceText = slurp(std::string(CORPUS) + "/leaf-ec.csr");
	// Разобранная запись PEM запроса
	std::vector <pem::block_t> referenceBlocks;
	// Разбираем запись PEM запроса
	ASSERT_EQ(pem::decode(referenceText, referenceBlocks), pem::error_t::NONE);
	// Запись не пуста
	ASSERT_FALSE(referenceBlocks.empty());
	{
		// Разбираем запрос набора: ключ владельца берём из него
		x509::request_t reference;
		// Разбор запроса обязан удаться
		ASSERT_EQ(reference.parse(view_t(referenceBlocks[0].data.data(), referenceBlocks[0].data.size())), x509::error_t::NONE);
		// Готовим ключ подписи владельца
		keys::signer_t leafSigner;
		ASSERT_EQ(leafSigner.prepare(view(slurp(std::string(CORPUS) + "/leaf-ec.key"))), keys::error_t::NONE);
		// Имя владельца сертификата
		x509::name_t subject;
		// Признак CN имени
		x509::attribute_t attribute;
		// Устанавливаем опознаватель признака CN
		attribute.oid = "2.5.4.3";
		// Устанавливаем вид записи значения признака
		attribute.type = asn1::tag_t::UTF8_STRING;
		// Устанавливаем значение признака
		attribute.value = "example.org";
		// Составляющая имени из единственного признака
		subject.parts.push_back(std::vector <x509::attribute_t> (1, attribute));
		// Расширение дополнительных имён владельца: SAN example.org, как велит раздел 7.4 RFC 8555
		std::vector <x509::extension_t> extensions;
		{
			// Тело расширения: SEQUENCE { dNSName [2] «example.org» }
			static const uint8_t san[] = {0x30, 0x0D, 0x82, 0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g'};
			// Расширение дополнительных имён владельца
			x509::extension_t extension;
			// Устанавливаем опознаватель расширения subjectAltName
			extension.oid = "2.5.29.17";
			// Устанавливаем тело расширения
			extension.value = view_t(san, sizeof(san));
			// Запоминаем расширение
			extensions.push_back(extension);
		}
		// Собираем запрос на сертификат ключом и именем владельца
		ASSERT_EQ(x509::encode(subject, reference.key(), extensions, leafSigner, digest::hash_t::SHA256, csr), x509::error_t::NONE);
	}
	// Завершаем заказ
	{
		// Полезная нагрузка завершения заказа
		std::string payload;
		acme::finalize(view_t(csr.data(), csr.size()), payload);
		// Ответ сервера
		answer_t answer;
		// Завершаем заказ
		ASSERT_TRUE(call(sandbox, order.finalize, nonce, kid, key, payload, signer, answer));
		// Состояние ответа - 200: запрос принят
		ASSERT_EQ(answer.status, 200) << answer.body;
		// Обновляем метку новизны
		nonce = answer.nonce;
	}
	// Ждём выдачи сертификата опросом заказа
	std::string certificateUrl;
	{
		// Выполняем опрос заказа до выдачи
		for(size_t attempt = 0; attempt < 10; attempt++){
			// Ответ сервера
			answer_t answer;
			// Запрашиваем заказ
			ASSERT_TRUE(call(sandbox, orderUrl, nonce, kid, key, "", signer, answer));
			// Разбираем заказ
			acme::order_t current;
			ASSERT_EQ(current.parse(view(answer.body)), acme::error_t::NONE) << answer.body;
			// Обновляем метку новизны
			nonce = answer.nonce;
			// Если сертификат выдан
			if(!current.certificate.empty()){
				// Запоминаем адрес сертификата
				certificateUrl = current.certificate;
				// Выходим из опроса
				break;
			}
			// Заказ обязан остаться действующим
			ASSERT_NE(current.status, "invalid") << answer.body;
			// Ждём секунду
			::sleep(1);
		}
		// Адрес сертификата обязан быть
		ASSERT_FALSE(certificateUrl.empty());
	}
	// Сгружаем сертификат
	std::string certificate;
	{
		// Ответ сервера
		answer_t answer;
		// Сгружаем сертификат
		ASSERT_TRUE(call(sandbox, certificateUrl, nonce, kid, key, "", signer, answer));
		// Состояние ответа - 200
		ASSERT_EQ(answer.status, 200) << answer.body;
		// Тело ответа несёт цепочку PEM
		ASSERT_NE(answer.body.find("-----BEGIN CERTIFICATE-----"), std::string::npos);
		// Запоминаем сертификат
		certificate = answer.body;
		// Обновляем метку новизны
		nonce = answer.nonce;
	}
	// Разбираем выданный сертификат модулем x509
	{
		// Разбираем запись PEM
		std::vector <pem::block_t> blocks;
		ASSERT_EQ(pem::decode(certificate, blocks), pem::error_t::NONE);
		// Цепочка не пуста
		ASSERT_FALSE(blocks.empty());
		// Разбираем сертификат владельца
		x509::certificate_t leaf;
		ASSERT_EQ(leaf.parse(view_t(blocks[0].data.data(), blocks[0].data.size())), x509::error_t::NONE);
		// Сертификат несёт дополнительное имя example.org: служба пишет идентификатор в SAN
		const x509::extension_t * san = leaf.extension("2.5.29.17");
		// Расширение SAN обязано быть
		ASSERT_TRUE(san != nullptr);
		// Разбираем дополнительные имена владельца
		std::vector <x509::alternative_t> alternatives;
		ASSERT_EQ(x509::alternatives(*san, alternatives), x509::error_t::NONE);
		// Имя example.org обязано быть среди дополнительных
		bool found = false;
		// Выполняем обход дополнительных имён
		for(size_t position = 0; position < alternatives.size(); position++){
			// Если имя доменное и совпало
			if((alternatives[position].kind == x509::kind_t::DNS) && (alternatives[position].value.compare("example.org") == 0))
				// Запоминаем найденность
				found = true;
		}
		// Имя обязано найтись
		ASSERT_TRUE(found);
	}
	// Отзываем сертификат
	{
		// Разбираем запись PEM сертификата в DER
		std::vector <pem::block_t> blocks;
		ASSERT_EQ(pem::decode(certificate, blocks), pem::error_t::NONE);
		// Полезная нагрузка отзыва
		std::string payload;
		acme::revokeCert(view_t(blocks[0].data.data(), blocks[0].data.size()), 4, payload);
		// Ответ сервера
		answer_t answer;
		// Отзываем сертификат ключом учётной записи
		ASSERT_TRUE(call(sandbox, directory.revokeCert, nonce, kid, key, payload, signer, answer));
		// Состояние ответа - 200: отзыв принят
		ASSERT_EQ(answer.status, 200) << answer.body;
	}
}
