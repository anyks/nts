/**
 * @file context.cpp
 * @date 2026-08-30
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
 * @brief Исходный файл проверок фасадов связи протокола TLS 1.3
 *
 * @note Обе стороны связи ведутся в одном приложении, а сети между ними нет вовсе:
 *       байты одной стороны подаются другой напрямую
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <asn1/asn1.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <handshake/handshake.hpp>
#include <sign/gost.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <entropy/entropy.hpp>
#include <digest/streebog.hpp>
#include <curve/parameters.hpp>
#include <adversary.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace anyks;

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * @brief Метод составления записи имени стороны сертификата
	 *
	 * @param writer составитель записи сертификата
	 * @param name   записываемое имя стороны сертификата
	 *
	 * @return       признак успешности составления записи имени
	 *
	 */
	bool title(asn1::writer_t & writer, const string & name) noexcept {
		// Открываем набор записей имени стороны сертификата
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ составления записи имени
			return false;
		// Открываем множество свойств имени стороны
		if(!writer.open(asn1::tag_t::SET))
			// Выводим отказ составления записи имени
			return false;
		// Открываем набор записи свойства имени
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ составления записи имени
			return false;
		// Записываем опознаватель свойства общего имени
		if(!writer.oid("2.5.4.3"))
			// Выводим отказ составления записи имени
			return false;
		// Записываем значение общего имени стороны
		if(!writer.text(asn1::tag_t::UTF8_STRING, name))
			// Выводим отказ составления записи имени
			return false;
		// Закрываем набор записи свойства имени
		if(!writer.close())
			// Выводим отказ составления записи имени
			return false;
		// Закрываем множество свойств имени стороны
		if(!writer.close())
			// Выводим отказ составления записи имени
			return false;
		// Выводим итог закрытия набора записей имени стороны
		return writer.close();
	}
	/**
	 * @brief Метод выработки подлинности стороны связи
	 *
	 * @param name   общее имя стороны выработанного сертификата
	 * @param result подлинность, в которую помещается итог выработки
	 *
	 * @return       признак успешности выработки подлинности стороны
	 *
	 * @note Сертификат выходит самоподписанным: связь доверие к издателю не проверяет,
	 *       а подпись владения ключом сличается именно с этим сертификатом
	 *
	 */
	bool identity(const string & name, context::credential_t & result) noexcept {
		// Эллиптическая кривая ключа стороны связи
		curve::curve_t curve;
		// Если кривую ключа стороны связи завести не удалось
		if(!curve::parameters("1.2.643.2.2.35.1", curve))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Секретный ключ стороны связи
		math::number_t number;
		// Если секретный ключ стороны связи выработать не удалось
		if(!entropy::number(curve.order(), number) || curve.order().zero(number))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Занимаем место под секретный ключ стороны связи
		result.secret.assign(curve.size(), 0);
		// Если секретный ключ стороны связи записать не удалось
		if(!curve.order().store(number, result.secret.data(), curve.size()))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Объект модуля электронной подписи
		sign::gost_t gost;
		// Если эллиптическую кривую подписи установить не удалось
		if(!gost.start(curve))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Если секретный ключ подписи установить не удалось
		if(!gost.secret(view_t(result.secret.data(), result.secret.size())))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Места, в которые помещаются координаты открытого ключа
		uint8_t x[32], y[32];
		// Если открытый ключ стороны связи получить не удалось
		if(!gost.key(x, y, curve.size()))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Место, в которое помещается запись открытого ключа
		uint8_t opened[64];
		/**
		 * Выполняем разворот записи координат: раздел 4 RFC 9215 велит записывать их в
		 * сертификат от младшего байта к старшему
		 */
		for(size_t i = 0; i < curve.size(); i++){
			// Переносим очередной байт первой координаты
			opened[i] = x[curve.size() - i - 1];
			// Переносим очередной байт второй координаты
			opened[curve.size() + i] = y[curve.size() - i - 1];
		}
		// Составитель записи открытого ключа стороны
		asn1::writer_t key;
		// Если запись открытого ключа составить не удалось
		if(!key.octets(view_t(opened, curve.size() * 2)))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Получаем составленную запись открытого ключа
		const view_t element = key.data();
		// Составитель тела сертификата стороны связи
		asn1::writer_t body;
		// Открываем набор записей тела сертификата
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Открываем запись издания сертификата
		if(!body.open(asn1::cls_t::CONTEXT, 0))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Записываем издание сертификата
		if(!body.integer(2))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Закрываем запись издания сертификата
		if(!body.close())
			// Выводим отказ выработки подлинности стороны
			return false;
		// Записываем порядковый номер сертификата
		if(!body.integer(1))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Открываем набор записи алгоритма подписи сертификата
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Записываем опознаватель алгоритма подписи сертификата
		if(!body.oid("1.2.643.7.1.1.3.2"))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Закрываем набор записи алгоритма подписи сертификата
		if(!body.close())
			// Выводим отказ выработки подлинности стороны
			return false;
		// Если имя издателя сертификата записать не удалось
		if(!title(body, name))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Открываем набор записи срока действия сертификата
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Записываем начало срока действия сертификата
		if(!body.time(asn1::tag_t::UTC_TIME, 1767225600))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Записываем окончание срока действия сертификата
		if(!body.time(asn1::tag_t::UTC_TIME, 2082758400))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Закрываем набор записи срока действия сертификата
		if(!body.close())
			// Выводим отказ выработки подлинности стороны
			return false;
		// Если имя владельца сертификата записать не удалось
		if(!title(body, name))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Открываем набор сведений об открытом ключе
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Открываем набор записи алгоритма открытого ключа
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Записываем опознаватель алгоритма открытого ключа
		if(!body.oid("1.2.643.7.1.1.1.1"))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Открываем набор настроек алгоритма открытого ключа
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Записываем опознаватель набора параметров кривой
		if(!body.oid("1.2.643.2.2.35.1"))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Закрываем набор настроек алгоритма открытого ключа
		if(!body.close())
			// Выводим отказ выработки подлинности стороны
			return false;
		// Закрываем набор записи алгоритма открытого ключа
		if(!body.close())
			// Выводим отказ выработки подлинности стороны
			return false;
		// Записываем разряды открытого ключа стороны связи
		if(!body.bits(element))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Закрываем набор сведений об открытом ключе
		if(!body.close())
			// Выводим отказ выработки подлинности стороны
			return false;
		// Закрываем набор записей тела сертификата
		if(!body.close())
			// Выводим отказ выработки подлинности стороны
			return false;
		// Получаем составленное тело сертификата
		const view_t tbs = body.data();
		// Место, в которое помещается хеш тела сертификата
		uint8_t hash[32];
		// Если хеш тела сертификата выработать не удалось
		if(!digest::streebog(digest::type_t::SHORT, tbs, hash, sizeof(hash), digest::order_t::VECTOR))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Место, в которое помещается подпись тела сертификата
		uint8_t signature[math::NUMBER_SIZE * 2];
		// Если подпись тела сертификата выработать не удалось
		if(!gost.make(view_t(hash, sizeof(hash)), signature))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Место, в которое помещается подпись в записи сертификата
		uint8_t reversed[64];
		/**
		 * Выполняем перестановку частей подписи: раздел 2 RFC 9215 велит записывать в
		 * сертификат сперва число s, а затем число r
		 */
		::memcpy(reversed, signature + curve.size(), curve.size());
		// Переносим вторую часть подписи сертификата
		::memcpy(reversed + curve.size(), signature, curve.size());
		// Составитель записи сертификата стороны связи
		asn1::writer_t writer;
		// Открываем набор записей сертификата
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Разборщик составленного тела сертификата
		asn1::Reader reader(tbs);
		// Разбираемый элемент тела сертификата
		asn1::element_t item;
		// Если составленное тело сертификата разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, item))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Записываем тело сертификата стороны связи
		if(!writer.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), item.content))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Открываем набор записи алгоритма подписи сертификата
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Записываем опознаватель алгоритма подписи сертификата
		if(!writer.oid("1.2.643.7.1.1.3.2"))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Закрываем набор записи алгоритма подписи сертификата
		if(!writer.close())
			// Выводим отказ выработки подлинности стороны
			return false;
		// Записываем подпись тела сертификата
		if(!writer.bits(view_t(reversed, curve.size() * 2)))
			// Выводим отказ выработки подлинности стороны
			return false;
		// Закрываем набор записей сертификата
		if(!writer.close())
			// Выводим отказ выработки подлинности стороны
			return false;
		// Получаем составленную запись сертификата
		const view_t data = writer.data();
		// Выполняем сброс цепочки сертификатов стороны связи
		result.chain.clear();
		// Добавляем составленный сертификат в цепочку стороны связи
		result.chain.push_back(vector <uint8_t> (data.data, data.data + data.size));
		// Выводим успешность выработки подлинности стороны связи
		return true;
	}
	/**
	 * @brief Метод передачи накопленных байтов между сторонами связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что байты между сторонами передавались
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Признак того, что байты между сторонами передавались
		bool moved = false;
		// Получаем байты, отправляемые клиентом
		view_t data = client.output();
		// Если клиенту есть что отправить серверу
		if(data.size > 0){
			// Выполняем перенос отправляемых байтов
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем отправленные байты с накопителя клиента
			client.consume(buffer.size());
			// Выполняем подачу отправленных байтов серверу
			server.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем, что байты между сторонами передавались
			moved = true;
		}
		// Получаем байты, отправляемые сервером
		data = server.output();
		// Если серверу есть что отправить клиенту
		if(data.size > 0){
			// Выполняем перенос отправляемых байтов
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем отправленные байты с накопителя сервера
			server.consume(buffer.size());
			// Выполняем подачу отправленных байтов клиенту
			client.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем, что байты между сторонами передавались
			moved = true;
		}
		// Выводим признак того, что байты между сторонами передавались
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
			// Продолжаем передачу байтов между сторонами связи
			continue;
	}
};

/**
 * Проверка полного рукопожатия с подлинностью сервера
 */
TEST(ContextTest, Handshake){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи стороной клиента
	ASSERT_TRUE(client.established());
	// Проверяем установленность связи стороной сервера
	ASSERT_TRUE(server.established());
	// Проверяем схождение наборов шифрования сторон связи
	ASSERT_EQ(client.suite(), server.suite());
	// Проверяем получение клиентом цепочки сертификатов сервера
	ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
	// Проверяем схождение принятого сертификата с отправленным
	ASSERT_EQ(client.peer()[0], credentials.chain[0]);
	// Прикладные данные, отправляемые клиентом
	const string request = "Запрос прикладного протокола";
	// Выполняем отправку прикладных данных клиентом
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Накопитель, в который помещаются принятые прикладные данные
	vector <uint8_t> received;
	// Выполняем получение принятых сервером прикладных данных
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Проверяем схождение принятых данных с отправленными
	ASSERT_EQ(string(received.begin(), received.end()), request);
	// Прикладные данные, отправляемые сервером
	const string answer = "Ответ прикладного протокола";
	// Выполняем отправку прикладных данных сервером
	ASSERT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Выполняем получение принятых клиентом прикладных данных
	ASSERT_EQ(client.read(received), context::error_t::NONE);
	// Проверяем схождение принятых данных с отправленными
	ASSERT_EQ(string(received.begin(), received.end()), answer);
	// Выполняем закрытие связи стороной клиента
	ASSERT_EQ(client.close(), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Проверяем закрытие связи стороной сервера
	ASSERT_EQ(server.state(), context::state_t::CLOSED);
}

/**
 * Проверка рукопожатия со встречной подлинностью клиента
 */
TEST(ContextTest, Mutual){
	// Подлинность сторон связи
	context::credential_t first, second;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", first));
	// Выполняем выработку подлинности стороны клиента
	ASSERT_TRUE(identity("client.anyks.com", second));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(first);
	// Устанавливаем требование подлинности клиента
	server.request(true);
	// Устанавливаем подлинность стороны клиента
	client.credential(second);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи стороной клиента
	ASSERT_TRUE(client.established());
	// Проверяем установленность связи стороной сервера
	ASSERT_TRUE(server.established());
	// Проверяем получение сервером цепочки сертификатов клиента
	ASSERT_EQ(server.peer().size(), static_cast <size_t> (1));
	// Проверяем схождение принятого сертификата с отправленным
	ASSERT_EQ(server.peer()[0], second.chain[0]);
}

/**
 * Проверка рукопожатия с просьбой о повторе приветствия
 */
TEST(ContextTest, Retry){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	/**
	 * Клиент объявляет две кривые обмена ключами, а открытую часть ключа шлёт лишь
	 * для первой из них: второй кривой сервер и попросит повторить приветствие
	 */
	client.groups({extension::group_t::GC256B, extension::group_t::GC512C});
	// Устанавливаем единственную кривую обмена ключами сервера
	server.groups({extension::group_t::GC512C});
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи стороной клиента
	ASSERT_TRUE(client.established());
	// Проверяем установленность связи стороной сервера
	ASSERT_TRUE(server.established());
}

/**
 * Проверка обрыва связи испорченной записью
 */
TEST(ContextTest, Corrupted){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Получаем приветствие, отправляемое клиентом серверу
	view_t greeting = client.output();
	// Выполняем перенос отправляемого клиентом приветствия
	const vector <uint8_t> hello(greeting.data, greeting.data + greeting.size);
	// Снимаем отправленное приветствие с накопителя клиента
	client.consume(hello.size());
	// Выполняем подачу приветствия клиента серверу
	ASSERT_EQ(server.push(view_t(hello.data(), hello.size())), context::error_t::NONE);
	// Получаем байты, отправляемые сервером клиенту
	const view_t data = server.output();
	// Проверяем наличие отправляемых сервером байтов
	ASSERT_GT(data.size, static_cast <size_t> (0));
	// Выполняем перенос отправляемых сервером байтов
	vector <uint8_t> buffer(data.data, data.data + data.size);
	// Снимаем отправленные байты с накопителя сервера
	server.consume(buffer.size());
	// Портим последний байт отправленных сервером записей
	buffer[buffer.size() - 1] ^= 0x01;
	// Выполняем подачу испорченных байтов клиенту
	client.push(view_t(buffer.data(), buffer.size()));
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.state(), context::state_t::FAILED);
	// Проверяем отказ, которым связь оборвана
	ASSERT_EQ(client.error(), context::error_t::PROTECTION);
	// Проверяем извещение, которым связь оборвана
	ASSERT_EQ(client.alert().description, alert::description_t::MAC);
}

/**
 * Проверка отвержения заведения связи без настроек
 */
TEST(ContextTest, Settings){
	// Связь стороны сервера
	server::context_t server;
	// Проверяем отказ заведения связи сервера без своей подлинности
	ASSERT_EQ(server.start(), context::error_t::SETTINGS);
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проверяем отказ повторного заведения связи
	ASSERT_EQ(client.start(), context::error_t::STATE);
	// Проверяем отказ отправки прикладных данных до установления связи
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("test"), 4)), context::error_t::STATE);
	// Выполняем сброс состояния связи стороны клиента
	client.clear();
	// Проверяем сброс состояния связи стороны клиента
	ASSERT_EQ(client.state(), context::state_t::NONE);
	// Проверяем заведение связи заново после сброса
	ASSERT_EQ(client.start(), context::error_t::NONE);
}

/**
 * Проверка смены ключевого материала установленной связи
 */
TEST(ContextTest, Update){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Накопитель, в который помещаются принятые прикладные данные
	vector <uint8_t> received;
	// Прикладные данные, отправляемые до смены ключевого материала
	const string first = "Данные до смены ключей";
	// Выполняем смену ключевого материала своего направления клиентом
	ASSERT_EQ(client.update(false), context::error_t::NONE);
	// Выполняем отправку прикладных данных новыми ключами клиента
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (first.data()), first.size())), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Проверяем сохранность связи стороной сервера
	ASSERT_TRUE(server.established());
	// Выполняем получение принятых сервером прикладных данных
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Проверяем схождение принятых данных с отправленными
	ASSERT_EQ(string(received.begin(), received.end()), first);
	// Прикладные данные, отправляемые за просьбою о встречной смене
	const string second = "Данные после встречной смены";
	/**
	 * Выполняем смену ключевого материала сервером с просьбою о встречной смене:
	 * клиент обязан сменить ключи своего направления в ответ
	 */
	ASSERT_EQ(server.update(true), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Проверяем сохранность связи стороной клиента
	ASSERT_TRUE(client.established());
	// Выполняем передачу встречной смены ключей серверу
	pump(client, server);
	// Выполняем отправку прикладных данных новыми ключами клиента
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (second.data()), second.size())), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Выполняем получение принятых сервером прикладных данных
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Проверяем схождение принятых данных с отправленными
	ASSERT_EQ(string(received.begin(), received.end()), second);
	// Прикладные данные, отправляемые сервером новыми ключами
	const string third = "Ответ сервера новыми ключами";
	// Выполняем отправку прикладных данных новыми ключами сервера
	ASSERT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> (third.data()), third.size())), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Выполняем получение принятых клиентом прикладных данных
	ASSERT_EQ(client.read(received), context::error_t::NONE);
	// Проверяем схождение принятых данных с отправленными
	ASSERT_EQ(string(received.begin(), received.end()), third);
}

/**
 * Проверка отвержения смены ключевого материала не в свой черёд
 */
TEST(ContextTest, Rotation){
	// Связь стороны клиента
	client::context_t client;
	// Проверяем отказ смены ключевого материала до заведения связи
	ASSERT_EQ(client.update(false), context::error_t::STATE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проверяем отказ смены ключевого материала до рукопожатия
	ASSERT_EQ(client.update(false), context::error_t::STATE);
}

/**
 * Проверка выдачи билетов возобновления связи
 */
TEST(ContextTest, Ticket){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем отсутствие билетов до их выдачи сервером
	ASSERT_TRUE(client.tickets().empty());
	// Выполняем выдачу первого билета возобновления связи
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Выполняем выдачу второго билета возобновления связи
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Проверяем число билетов, принятых клиентом
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (2));
	// Проверяем число билетов, выданных сервером
	ASSERT_EQ(server.tickets().size(), static_cast <size_t> (2));
	/**
	 * Выполняем перебор билетов возобновления связи
	 */
	for(size_t i = 0; i < client.tickets().size(); i++){
		// Проверяем схождение тела принятого билета с выданным
		ASSERT_EQ(client.tickets()[i].identity, server.tickets()[i].identity);
		/**
		 * Ключ билета выводится обеими сторонами самостоятельно и по связи не
		 * передаётся вовсе: сходятся они лишь потому, что выведены из одного значения
		 */
		ASSERT_EQ(client.tickets()[i].secret, server.tickets()[i].secret);
		// Проверяем длину ключа принятого билета
		ASSERT_EQ(client.tickets()[i].secret.size(), static_cast <size_t> (32));
		// Проверяем схождение срока жизни принятого билета с выданным
		ASSERT_EQ(client.tickets()[i].lifetime, server.tickets()[i].lifetime);
		// Проверяем схождение добавки к возрасту билета с выданной
		ASSERT_EQ(client.tickets()[i].age, server.tickets()[i].age);
	}
	/**
	 * Ключи двух билетов одной связи расходятся: неповторимое значение билета для
	 * того в вывод ключа и подаётся
	 */
	ASSERT_NE(client.tickets()[0].secret, client.tickets()[1].secret);
	// Проверяем расхождение тел двух билетов одной связи
	ASSERT_NE(client.tickets()[0].identity, client.tickets()[1].identity);
	// Прикладные данные, отправляемые за выдачей билетов
	const string request = "Данные после выдачи билетов";
	// Выполняем отправку прикладных данных клиентом
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Накопитель, в который помещаются принятые прикладные данные
	vector <uint8_t> received;
	// Выполняем получение принятых сервером прикладных данных
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Проверяем схождение принятых данных с отправленными
	ASSERT_EQ(string(received.begin(), received.end()), request);
}

/**
 * Проверка отвержения выдачи билета не в свой черёд
 */
TEST(ContextTest, Issue){
	// Связь стороны сервера
	server::context_t server;
	// Проверяем отказ выдачи билета до заведения связи
	ASSERT_EQ(server.issue(), context::error_t::STATE);
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Проверяем отказ выдачи билета до рукопожатия
	ASSERT_EQ(server.issue(), context::error_t::STATE);
}

/**
 * Проверка возобновления связи выданным билетом
 */
TEST(ContextTest, Resume){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Билеты возобновления связи, выданные первой связью
	vector <context::ticket_t> issued;
	/**
	 * Ведём первую связь: она пройдёт полным рукопожатием и выдаст билет
	 */
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Выполняем проведение рукопожатия сторон связи
		converse(client, server);
		// Проверяем установленность связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем, что первая связь билетом не возобновлялась
		ASSERT_FALSE(client.shared());
		// Выполняем выдачу билета возобновления связи
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Выполняем передачу билета возобновления связи клиенту
		pump(client, server);
		// Проверяем приём билета возобновления связи клиентом
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Запоминаем билеты, выданные первой связью
		issued = server.tickets();
		// Проверяем схождение принятого билета с выданным
		ASSERT_EQ(client.tickets()[0].secret, issued[0].secret);
		// Запоминаем принятый клиентом билет возобновления связи
		issued.push_back(client.tickets()[0]);
	}
	// Связь стороны клиента, возобновляющая прошлую
	client::context_t client;
	// Связь стороны сервера, признающая выданный билет
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем билеты, признаваемые сервером
	server.resume(vector <context::ticket_t> {issued[0]});
	// Предъявляем серверу билет, принятый прошлой связью
	client.resume(issued[1]);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established());
	// Проверяем установленность связи стороной сервера
	ASSERT_TRUE(server.established());
	// Проверяем возобновление связи заранее разделённым ключом
	ASSERT_TRUE(client.shared());
	// Проверяем возобновление связи стороной сервера
	ASSERT_TRUE(server.shared());
	/**
	 * При возобновлении связи цепочки сертификатов не бывает вовсе: подлинность
	 * сторон подтверждена билетом, а не сертификатом
	 */
	ASSERT_TRUE(client.peer().empty());
	// Прикладные данные, отправляемые по возобновлённой связи
	const string request = "Данные возобновлённой связи";
	// Выполняем отправку прикладных данных клиентом
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Накопитель, в который помещаются принятые прикладные данные
	vector <uint8_t> received;
	// Выполняем получение принятых сервером прикладных данных
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Проверяем схождение принятых данных с отправленными
	ASSERT_EQ(string(received.begin(), received.end()), request);
}

/**
 * Проверка отвержения билета, сервером не признанного
 */
TEST(ContextTest, Unknown){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Предъявляемый серверу билет возобновления связи
	context::ticket_t ticket;
	// Устанавливаем тело предъявляемого билета
	ticket.identity.assign(32, 0x11);
	// Устанавливаем ключ предъявляемого билета
	ticket.secret.assign(32, 0x22);
	// Предъявляем серверу билет, которого он не выдавал
	client.resume(ticket);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	/**
	 * Непризнанный билет связи не рвёт: она идёт полным рукопожатием, будто билета
	 * и не предъявлялось вовсе
	 */
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем, что связь билетом не возобновлена
	ASSERT_FALSE(client.shared());
	// Проверяем, что сервер связь билетом не возобновлял
	ASSERT_FALSE(server.shared());
	// Проверяем предъявление сервером цепочки сертификатов
	ASSERT_EQ(client.peer().size(), static_cast <size_t> (1));
}

/**
 * Проверка отвержения билета с испорченной привязкой
 */
TEST(ContextTest, Binder){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Билет, признаваемый сервером
	context::ticket_t known;
	// Устанавливаем тело признаваемого билета
	known.identity.assign(32, 0x33);
	// Устанавливаем ключ признаваемого билета
	known.secret.assign(32, 0x44);
	// Билет, предъявляемый клиентом
	context::ticket_t offered = known;
	/**
	 * Портим ключ предъявляемого билета: тело его сервером признаётся, а вот
	 * привязка, выработанная на ином ключе, не сойдётся
	 */
	offered.secret.assign(32, 0x55);
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем билеты, признаваемые сервером
	server.resume(vector <context::ticket_t> {known});
	// Предъявляем серверу билет с испорченным ключом
	client.resume(offered);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем обрыв связи стороной сервера
	ASSERT_EQ(server.state(), context::state_t::FAILED);
	// Проверяем отказ, которым связь оборвана
	ASSERT_EQ(server.error(), context::error_t::SIGNATURE);
	// Проверяем извещение, которым связь оборвана
	ASSERT_EQ(server.alert().description, alert::description_t::DECRYPT);
}

/**
 * Проверка возобновления связи с просьбою о повторе приветствия
 */
TEST(ContextTest, Retried){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Билеты возобновления связи, выданные первой связью
	vector <context::ticket_t> issued;
	// Билет, принятый клиентом первой связи
	context::ticket_t accepted;
	/**
	 * Ведём первую связь: она пройдёт полным рукопожатием и выдаст билет
	 */
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Выполняем проведение рукопожатия сторон связи
		converse(client, server);
		// Проверяем установленность связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established());
		// Выполняем выдачу билета возобновления связи
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Выполняем передачу билета возобновления связи клиенту
		pump(client, server);
		// Проверяем приём билета возобновления связи клиентом
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Запоминаем билеты, признаваемые будущим сервером
		issued = server.tickets();
		// Запоминаем билет, принятый клиентом первой связи
		accepted = client.tickets()[0];
	}
	// Связь стороны клиента, возобновляющая прошлую
	client::context_t client;
	// Связь стороны сервера, признающая выданный билет
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем билеты, признаваемые сервером
	server.resume(issued);
	// Предъявляем серверу билет, принятый прошлой связью
	client.resume(accepted);
	/**
	 * Клиент объявляет две кривые обмена ключами, а открытую часть ключа шлёт лишь
	 * для первой из них: второй кривой сервер и попросит повторить приветствие
	 */
	client.groups({extension::group_t::GC256B, extension::group_t::GC512C});
	// Устанавливаем единственную кривую обмена ключами сервера
	server.groups({extension::group_t::GC512C});
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	/**
	 * Просьба о повторе приветствия возобновлению не мешает: привязка билета
	 * вырабатывается заново, уже от переписки с просьбою о повторе
	 */
	ASSERT_TRUE(client.shared());
	// Проверяем возобновление связи стороной сервера
	ASSERT_TRUE(server.shared());
	// Проверяем отсутствие цепочки сертификатов при возобновлении
	ASSERT_TRUE(client.peer().empty());
	// Прикладные данные, отправляемые по возобновлённой связи
	const string request = "Данные связи, возобновлённой с повтором приветствия";
	// Выполняем отправку прикладных данных клиентом
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Накопитель, в который помещаются принятые прикладные данные
	vector <uint8_t> received;
	// Выполняем получение принятых сервером прикладных данных
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Проверяем схождение принятых данных с отправленными
	ASSERT_EQ(string(received.begin(), received.end()), request);
}

/**
 * @brief Служебные объекты проверок упреждающих данных
 *
 */
namespace {
	/**
	 * @brief Метод проведения связи, выдающей билет возобновления
	 *
	 * @param credentials подлинность стороны сервера
	 * @param issued      перечень, в который помещается билет, признаваемый сервером
	 * @param accepted    билет, в который помещается принятый клиентом
	 *
	 * @return            признак успешности выдачи билета возобновления связи
	 *
	 */
	bool granted(const context::credential_t & credentials, vector <context::ticket_t> & issued, context::ticket_t & accepted) noexcept {
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		/**
		 * Упреждающие данные дозволяются билетом: раздел 4.6.1 RFC 8446 велит объявлять
		 * их предел расширением билета, и без него будущий клиент упреждения не предложит
		 */
		server.advance(true);
		// Если связь стороны сервера завести не удалось
		if(server.start() != context::error_t::NONE)
			// Выводим отказ выдачи билета возобновления связи
			return false;
		// Если связь стороны клиента завести не удалось
		if(client.start() != context::error_t::NONE)
			// Выводим отказ выдачи билета возобновления связи
			return false;
		// Выполняем проведение рукопожатия сторон связи
		converse(client, server);
		// Если рукопожатие сторонами связи не пройдено
		if(!client.established() || !server.established())
			// Выводим отказ выдачи билета возобновления связи
			return false;
		// Если билет возобновления связи выдать не удалось
		if(server.issue() != context::error_t::NONE)
			// Выводим отказ выдачи билета возобновления связи
			return false;
		// Выполняем передачу билета возобновления связи клиенту
		pump(client, server);
		// Если билет возобновления связи клиентом не принят
		if(client.tickets().empty())
			// Выводим отказ выдачи билета возобновления связи
			return false;
		// Запоминаем билеты, признаваемые будущим сервером
		issued = server.tickets();
		// Запоминаем билет, принятый клиентом связи
		accepted = client.tickets()[0];
		// Выводим успешность выдачи билета возобновления связи
		return true;
	}
};

/**
 * Проверка упреждающих данных, принятых сервером
 */
TEST(ContextTest, Advance){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Билеты, признаваемые сервером возобновляемой связи
	vector <context::ticket_t> issued;
	// Билет, принятый клиентом прошлой связи
	context::ticket_t accepted;
	// Выполняем проведение связи, выдающей билет возобновления
	ASSERT_TRUE(granted(credentials, issued, accepted));
	// Связь стороны клиента, возобновляющая прошлую
	client::context_t client;
	// Связь стороны сервера, признающая выданный билет
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем билеты, признаваемые сервером
	server.resume(issued);
	// Устанавливаем приём упреждающих данных сервером
	server.advance(true);
	// Предъявляем серверу билет, принятый прошлой связью
	client.resume(accepted);
	// Устанавливаем предложение упреждающих данных сервером
	client.advance(true);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Прикладные данные, отправляемые вместе с приветствием клиента
	const string request = "Упреждающие данные, посланные до ответа сервера";
	/**
	 * Отправляем прикладные данные, не дождавшись ответа сервера: связь на этот миг
	 * ещё не установлена, и ключи их выведены из одного лишь билета
	 */
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Проверяем, что связь на миг отправки ещё не установлена
	ASSERT_FALSE(client.established());
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем возобновление связи заранее разделённым ключом
	ASSERT_TRUE(client.shared() && server.shared());
	// Проверяем приём упреждающих данных сервером
	ASSERT_TRUE(client.accepted());
	// Накопитель, в который помещаются принятые прикладные данные
	vector <uint8_t> received;
	// Выполняем получение принятых сервером прикладных данных
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Проверяем схождение принятых упреждающих данных с отправленными
	ASSERT_EQ(string(received.begin(), received.end()), request);
	// Прикладные данные, отправляемые по установленной связи
	const string answer = "Ответ по установленной связи";
	// Выполняем отправку прикладных данных сервером
	ASSERT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Выполняем получение принятых клиентом прикладных данных
	ASSERT_EQ(client.read(received), context::error_t::NONE);
	// Проверяем схождение принятых данных с отправленными
	ASSERT_EQ(string(received.begin(), received.end()), answer);
}

/**
 * Проверка упреждающих данных, сервером отвергнутых
 */
TEST(ContextTest, Rejected){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Билеты, признаваемые сервером возобновляемой связи
	vector <context::ticket_t> issued;
	// Билет, принятый клиентом прошлой связи
	context::ticket_t accepted;
	// Выполняем проведение связи, выдающей билет возобновления
	ASSERT_TRUE(granted(credentials, issued, accepted));
	// Связь стороны клиента, возобновляющая прошлую
	client::context_t client;
	// Связь стороны сервера, признающая выданный билет
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем билеты, признаваемые сервером
	server.resume(issued);
	/**
	 * Приём упреждающих данных сервером не объявляется: связь пройдёт возобновлением,
	 * а посланное упреждением пропадёт
	 */
	server.advance(false);
	// Предъявляем серверу билет, принятый прошлой связью
	client.resume(accepted);
	// Устанавливаем предложение упреждающих данных сервером
	client.advance(true);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Прикладные данные, отправляемые вместе с приветствием клиента
	const string request = "Упреждающие данные, которые сервер не примет";
	// Выполняем отправку упреждающих данных клиентом
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	/**
	 * Отвергнутые упреждающие данные связи не рвут: их записи сервер пропускает, а
	 * рукопожатие идёт своим чередом
	 */
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем возобновление связи заранее разделённым ключом
	ASSERT_TRUE(client.shared() && server.shared());
	// Проверяем отвержение упреждающих данных сервером
	ASSERT_FALSE(client.accepted());
	// Накопитель, в который помещаются принятые прикладные данные
	vector <uint8_t> received;
	// Выполняем получение принятых сервером прикладных данных
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Проверяем, что отвергнутые упреждающие данные сервера не достигли
	ASSERT_TRUE(received.empty());
	// Прикладные данные, отправляемые по установленной связи
	const string repeated = "Те же данные, посланные заново по установленной связи";
	// Выполняем отправку прикладных данных клиентом
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (repeated.data()), repeated.size())), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	pump(client, server);
	// Выполняем получение принятых сервером прикладных данных
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Проверяем схождение принятых данных с отправленными
	ASSERT_EQ(string(received.begin(), received.end()), repeated);
}

/**
 * Проверка отвержения упреждающих данных вне возобновления связи
 */
TEST(ContextTest, Untimely){
	// Связь стороны клиента
	client::context_t client;
	// Устанавливаем предложение упреждающих данных сервером
	client.advance(true);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	/**
	 * Без билета возобновления связи упреждающих данных не бывает: ключи их выводить
	 * не из чего, и отправка их отвергается состоянием связи
	 */
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("test"), 4)), context::error_t::STATE);
}

/**
 * Проверка выбора прикладного протокола и приёма имени узла сервером
 */
TEST(ContextTest, Protocol){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем имя узла, за которым идёт клиент
	client.name("anyks.com");
	// Устанавливаем прикладные протоколы, предлагаемые клиентом
	client.protocols({"http/1.1", "h2"});
	/**
	 * Порядок сервера обратен порядку клиента: раздел 3.2 RFC 7301 отдаёт выбор
	 * серверу, и выбран должен быть протокол, стоящий первым именно у него
	 */
	server.protocols({"h2", "http/1.1"});
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи стороной клиента
	ASSERT_TRUE(client.established());
	// Проверяем установленность связи стороной сервера
	ASSERT_TRUE(server.established());
	// Проверяем выбор прикладного протокола сервером
	ASSERT_EQ(server.protocol(), "h2");
	// Проверяем схождение прикладного протокола сторон связи
	ASSERT_EQ(client.protocol(), server.protocol());
	// Проверяем приём сервером имени узла, за которым пришёл клиент
	ASSERT_EQ(server.name(), "anyks.com");
}

/**
 * Проверка обрыва связи при отсутствии общего прикладного протокола
 */
TEST(ContextTest, Mismatch){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем прикладные протоколы, предлагаемые клиентом
	client.protocols({"http/1.1"});
	// Устанавливаем прикладные протоколы, признаваемые сервером
	server.protocols({"h2"});
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем обрыв связи стороной сервера
	ASSERT_EQ(server.error(), context::error_t::PROTOCOL);
	/**
	 * Раздел 3.2 RFC 7301: отсутствие общего протокола объявляется извещением
	 * «no_application_protocol» с числом 120
	 */
	ASSERT_EQ(server.alert().description, alert::description_t::PROTOCOL);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
	// Проверяем, что прикладного протокола связь не выбрала
	ASSERT_TRUE(server.protocol().empty());
}

/**
 * Проверка отвержения клиентом протокола, которого он не предлагал
 */
TEST(ContextTest, Foreign){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем прикладные протоколы, предлагаемые клиентом
	client.protocols({"h2"});
	// Устанавливаем прикладные протоколы, признаваемые сервером
	server.protocols({"h2"});
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	/**
	 * Приветствие клиента составлено заведением связи и уже лежит в накопителе: сменив
	 * перечень теперь, мы получаем сервер, отвечающий протоколом, которого связь клиента
	 * не предлагала, - именно этот случай раздел 3.2 RFC 7301 и запрещает принимать
	 */
	client.protocols({"http/1.1"});
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.error(), context::error_t::PROTOCOL);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::PROTOCOL);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
	// Проверяем, что прикладного протокола клиент не принял
	ASSERT_TRUE(client.protocol().empty());
}

/**
 * Проверка суждения о сроке билета возобновления связи
 */
TEST(ContextTest, Lifetime){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Миг выдачи билета возобновления связи
	const int64_t issued = 1800000000;
	// Билет, выданный сервером, и билет, принятый клиентом
	vector <context::ticket_t> tickets;
	/**
	 * Ведём первую связь: она пройдёт полным рукопожатием и выдаст билет
	 */
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Устанавливаем миг, которым сервер судит сроки билетов
		server.moment(issued);
		// Устанавливаем миг, которым клиент судит сроки билетов
		client.moment(issued);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Выполняем проведение рукопожатия сторон связи
		converse(client, server);
		// Проверяем установленность связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established());
		// Выполняем выдачу билета возобновления связи
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Выполняем передачу билета возобновления связи клиенту
		pump(client, server);
		// Проверяем приём билета возобновления связи клиентом
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Запоминаем билет, выданный сервером
		tickets = server.tickets();
		// Запоминаем билет, принятый клиентом
		tickets.push_back(client.tickets()[0]);
		// Проверяем, что миг выдачи проставлен обеими сторонами
		ASSERT_EQ(tickets[0].moment, issued);
		// Проверяем схождение мига выдачи у обеих сторон
		ASSERT_EQ(tickets[1].moment, issued);
	}
	/**
	 * Выполняем перебор мигов, которыми судится срок билета
	 */
	for(size_t item = 0; item < 2; item++){
		/**
		 * Первый заход идёт в пределах срока билета, второй - за его пределом: срок
		 * билета объявлен сервером в две тысячи семьсот часов, и второй миг его
		 * заведомо переступает
		 */
		const int64_t moment = (issued + ((item == 0) ? 3600 : 100000));
		// Связь стороны клиента, возобновляющая прошлую
		client::context_t client;
		// Связь стороны сервера, признающая выданный билет
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Устанавливаем миг, которым сервер судит сроки билетов
		server.moment(moment);
		// Устанавливаем миг, которым клиент судит сроки билетов
		client.moment(moment);
		// Устанавливаем билеты, признаваемые сервером
		server.resume(vector <context::ticket_t> (1, tickets[0]));
		// Предъявляем билет возобновления связи серверу
		client.resume(tickets[1]);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Выполняем проведение рукопожатия сторон связи
		converse(client, server);
		// Проверяем установленность связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << "миг " << moment;
		/**
		 * В пределах срока связь возобновляется билетом, а за пределом его - идёт
		 * полным рукопожатием: раздел 4.6.1 RFC 8446 велит держать билет не дольше
		 * объявленного срока
		 */
		ASSERT_EQ(client.shared(), (item == 0)) << "миг " << moment;
		// Проверяем схождение суждения сторон о билете
		ASSERT_EQ(server.shared(), client.shared()) << "миг " << moment;
	}
}

/**
 * Проверка сличения объявленного возраста билета с наблюдаемым
 */
TEST(ContextTest, Freshness){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Миг выдачи билета возобновления связи
	const int64_t issued = 1800000000;
	// Билет, выданный сервером, и билет, принятый клиентом
	vector <context::ticket_t> tickets;
	/**
	 * Ведём первую связь: она пройдёт полным рукопожатием и выдаст билет
	 */
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Устанавливаем миг, которым сервер судит сроки билетов
		server.moment(issued);
		// Устанавливаем миг, которым клиент судит сроки билетов
		client.moment(issued);
		// Объявляем дозволение упреждающих данных будущим билетом
		server.advance(true);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Выполняем проведение рукопожатия сторон связи
		converse(client, server);
		// Выполняем выдачу билета возобновления связи
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Выполняем передачу билета возобновления связи клиенту
		pump(client, server);
		// Проверяем приём билета возобновления связи клиентом
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Запоминаем билет, выданный сервером
		tickets = server.tickets();
		// Запоминаем билет, принятый клиентом
		tickets.push_back(client.tickets()[0]);
	}
	/**
	 * Выполняем перебор расхождений часов сторон связи
	 */
	for(size_t item = 0; item < 2; item++){
		/**
		 * Первый заход идёт при сошедшихся часах сторон, второй - при разошедшихся на
		 * полминуты: окно сличения возраста уже этого расхождения
		 */
		const int64_t drift = ((item == 0) ? 0 : 30);
		// Связь стороны клиента, возобновляющая прошлую
		client::context_t client;
		// Связь стороны сервера, признающая выданный билет
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Устанавливаем миг, которым сервер судит сроки билетов
		server.moment(issued + 3600 + drift);
		// Устанавливаем миг, которым клиент судит сроки билетов
		client.moment(issued + 3600);
		// Устанавливаем билеты, признаваемые сервером
		server.resume(vector <context::ticket_t> (1, tickets[0]));
		// Предъявляем билет возобновления связи серверу
		client.resume(tickets[1]);
		// Объявляем предложение упреждающих данных клиентом
		client.advance(true);
		// Объявляем приём упреждающих данных сервером
		server.advance(true);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Прикладные данные, отправляемые клиентом с упреждением
		const string request = "Упреждающие данные";
		// Выполняем отправку упреждающих данных клиентом
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE) << "расхождение " << drift;
		// Выполняем проведение рукопожатия сторон связи
		converse(client, server);
		// Проверяем установленность связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established()) << "расхождение " << drift;
		// Проверяем возобновление связи билетом при всяком расхождении часов
		ASSERT_TRUE(client.shared()) << "расхождение " << drift;
		/**
		 * Разошедшиеся часы упреждающих данных не пропускают: раздел 4.2.10 RFC 8446
		 * велит сличать объявленный возраст билета с наблюдаемым, а возобновлению
		 * связи расхождение это не мешает
		 */
		ASSERT_EQ(client.accepted(), (item == 0)) << "расхождение " << drift;
	}
}

/**
 * Проверка предела упреждающих данных, объявленного билетом
 */
TEST(ContextTest, Overrun){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Предел упреждающих данных, объявляемый билетом
	const uint32_t limit = 64;
	// Билет, выданный сервером, и билет, принятый клиентом
	vector <context::ticket_t> tickets;
	/**
	 * Ведём первую связь: она выдаст билет с объявленным пределом упреждения
	 */
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Объявляем предел упреждающих данных будущим билетом
		server.advance(true, limit);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Выполняем проведение рукопожатия сторон связи
		converse(client, server);
		// Выполняем выдачу билета возобновления связи
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Выполняем передачу билета возобновления связи клиенту
		pump(client, server);
		// Проверяем приём билета возобновления связи клиентом
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Запоминаем билет, выданный сервером
		tickets = server.tickets();
		// Запоминаем билет, принятый клиентом
		tickets.push_back(client.tickets()[0]);
		// Проверяем объявление предела упреждающих данных билетом
		ASSERT_EQ(tickets[1].advance, limit);
	}
	// Связь стороны клиента, возобновляющая прошлую
	client::context_t client;
	// Связь стороны сервера, признающая выданный билет
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем предел упреждающих данных стороны сервера
	server.advance(true, limit);
	// Устанавливаем билеты, признаваемые сервером
	server.resume(vector <context::ticket_t> (1, tickets[0]));
	// Предъявляем билет возобновления связи серверу
	client.resume(tickets[1]);
	// Объявляем предложение упреждающих данных клиентом
	client.advance(true);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Упреждающие данные, укладывающиеся в объявленный предел
	const vector <uint8_t> fitting(limit, 0x41);
	// Выполняем отправку упреждающих данных в пределах дозволенного
	ASSERT_EQ(client.write(view_t(fitting.data(), fitting.size())), context::error_t::NONE);
	/**
	 * Предел упреждающих данных объявлен билетом, и выход за него связь отвергает
	 * своей же стороной: раздел 4.2.10 RFC 8446 велит клиенту за предел не выходить
	 */
	ASSERT_EQ(client.write(view_t(fitting.data(), 1)), context::error_t::LIMIT);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем приём упреждающих данных сервером
	ASSERT_TRUE(client.accepted());
	// Накопитель, в который помещаются принятые прикладные данные
	vector <uint8_t> received;
	// Выполняем получение принятых сервером упреждающих данных
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	// Проверяем схождение принятых упреждающих данных с отправленными
	ASSERT_EQ(received, fitting);
}

/**
 * Проверка обрыва связи при выходе клиента за предел упреждающих данных
 */
TEST(ContextTest, Excess){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Предел упреждающих данных, объявляемый билетом
	const uint32_t limit = 64;
	// Билет, выданный сервером, и билет, принятый клиентом
	vector <context::ticket_t> tickets;
	/**
	 * Ведём первую связь: она выдаст билет с объявленным пределом упреждения
	 */
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Объявляем предел упреждающих данных будущим билетом
		server.advance(true, limit);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Выполняем проведение рукопожатия сторон связи
		converse(client, server);
		// Выполняем выдачу билета возобновления связи
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Выполняем передачу билета возобновления связи клиенту
		pump(client, server);
		// Проверяем приём билета возобновления связи клиентом
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		// Запоминаем билет, выданный сервером
		tickets = server.tickets();
		// Запоминаем билет, принятый клиентом
		tickets.push_back(client.tickets()[0]);
	}
	/**
	 * Клиенту переписывается объявленный билетом предел: так выходит клиент, предела
	 * не блюдущий, - его-то сервер и обязан оборвать
	 */
	tickets[1].advance = (limit * 4);
	// Связь стороны клиента, возобновляющая прошлую
	client::context_t client;
	// Связь стороны сервера, признающая выданный билет
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем предел упреждающих данных стороны сервера
	server.advance(true, limit);
	// Устанавливаем билеты, признаваемые сервером
	server.resume(vector <context::ticket_t> (1, tickets[0]));
	// Предъявляем билет возобновления связи серверу
	client.resume(tickets[1]);
	// Объявляем предложение упреждающих данных клиентом
	client.advance(true, tickets[1].advance);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Упреждающие данные, выходящие за объявленный сервером предел
	const vector <uint8_t> excess(limit * 2, 0x42);
	// Выполняем отправку упреждающих данных сверх дозволенного сервером
	ASSERT_EQ(client.write(view_t(excess.data(), excess.size())), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем обрыв связи стороной сервера
	ASSERT_EQ(server.error(), context::error_t::LIMIT);
	/**
	 * Раздел 4.2.10 RFC 8446: выход за предел упреждающих данных сервер объявляет
	 * извещением «unexpected_message»
	 */
	ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * @brief Служебные объекты проверок подделанного приветствия сервера
 *
 */
namespace {
	/**
	 * @brief Метод подделки приветствия сервера на пути к клиенту
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @param offset место подделываемых байтов в приветствии сервера
	 * @param data   подделываемые байты
	 * @param size   число подделываемых байтов
	 *
	 * @return       признак успешности подделки приветствия сервера
	 *
	 * @note Приветствие сервера идёт открытым: защита записей заводится лишь за ним,
	 *       и подделать его на пути к клиенту можно прямо в потоке байтов
	 *
	 */
	bool forge(client::context_t & client, server::context_t & server, const size_t offset, const uint8_t * data, const size_t size) noexcept {
		// Получаем байты, отправляемые клиентом серверу
		view_t sending = client.output();
		// Выполняем перенос отправляемых клиентом байтов
		const vector <uint8_t> greeting(sending.data, sending.data + sending.size);
		// Снимаем отправленные байты с накопителя клиента
		client.consume(greeting.size());
		// Выполняем подачу приветствия клиента серверу
		server.push(view_t(greeting.data(), greeting.size()));
		// Получаем байты, отправляемые сервером клиенту
		sending = server.output();
		// Если сервер клиенту ничего не ответил
		if(sending.size < (offset + size))
			// Выводим отказ подделки приветствия сервера
			return false;
		// Выполняем перенос отправляемых сервером байтов
		vector <uint8_t> answer(sending.data, sending.data + sending.size);
		// Снимаем отправленные байты с накопителя сервера
		server.consume(answer.size());
		/**
		 * Выполняем подделку байтов приветствия сервера
		 */
		for(size_t i = 0; i < size; i++)
			// Записываем очередной подделываемый байт приветствия
			answer[offset + i] = data[i];
		// Выполняем подачу подделанного приветствия клиенту
		client.push(view_t(answer.data(), answer.size()));
		// Выводим успешность подделки приветствия сервера
		return true;
	}
};

/**
 * Проверка сличения опознавателя связи, возвращённого сервером
 */
TEST(ContextTest, Echo){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	/**
	 * Опознаватель связи подделывается целиком, а не одним байтом: сам он случаен, и
	 * подделка одного байта раз в двести пятьдесят шесть совпала бы с настоящим
	 */
	const vector <uint8_t> session(hello::HELLO_SESSION, 0xA5);
	/**
	 * Опознаватель связи лежит за заголовком записи, обвязкой сообщения, изданием
	 * протокола, случайным значением и длиною самого опознавателя
	 */
	ASSERT_TRUE(forge(client, server, 5 + 4 + 2 + 32 + 1, session.data(), session.size()));
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	/**
	 * Раздел 4.1.3 RFC 8446: опознаватель связи сервер обязан вернуть тем же, каким
	 * его прислал клиент, а разошедшийся объявляется извещением «illegal_parameter»
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона понижения издания протокола
 */
TEST(ContextTest, Downgrade){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	/**
	 * Выполняем перебор заслонов понижения издания протокола
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Заслон понижения издания протокола
		const uint8_t downgrade[8] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, static_cast <uint8_t> (item)};
		/**
		 * Заслон лежит в хвосте случайного значения сервера, а само оно идёт за
		 * заголовком записи, обвязкой сообщения и изданием протокола
		 */
		ASSERT_TRUE(forge(client, server, 5 + 4 + 2 + 32 - sizeof(downgrade), downgrade, sizeof(downgrade)));
		// Проверяем обрыв связи стороной клиента
		ASSERT_EQ(client.error(), context::error_t::VERSION) << "заслон " << item;
		// Проверяем извещение, которым связь оборвана клиентом
		ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER) << "заслон " << item;
		// Проверяем неустановленность связи стороной клиента
		ASSERT_FALSE(client.established()) << "заслон " << item;
	}
}

/**
 * Проверка сличения кривой, о которой сервер просит повторить приветствие
 */
TEST(ContextTest, Chosen){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	/**
	 * Первый заход подделывает просьбу о кривой, ключ по которой клиент уже отправил,
	 * второй - о кривой, клиентом не предложенной вовсе
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		/**
		 * Клиент объявляет две кривые обмена ключами, а открытую часть ключа шлёт лишь
		 * для первой из них: второй кривой сервер и попросит повторить приветствие
		 */
		client.groups({extension::group_t::GC256B, extension::group_t::GC512C});
		// Устанавливаем единственную кривую обмена ключами сервера
		server.groups({extension::group_t::GC512C});
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Получаем байты, отправляемые клиентом серверу
		view_t sending = client.output();
		// Выполняем перенос отправляемых клиентом байтов
		const vector <uint8_t> greeting(sending.data, sending.data + sending.size);
		// Снимаем отправленные байты с накопителя клиента
		client.consume(greeting.size());
		// Выполняем подачу приветствия клиента серверу
		server.push(view_t(greeting.data(), greeting.size()));
		// Получаем байты, отправляемые сервером клиенту
		sending = server.output();
		// Выполняем перенос отправляемых сервером байтов
		vector <uint8_t> answer(sending.data, sending.data + sending.size);
		// Снимаем отправленные байты с накопителя сервера
		server.consume(answer.size());
		/**
		 * Кривая, о которой просит сервер, лежит в теле расширения открытой части
		 * ключа: у просьбы о повторе тело это состоит из одного её опознавателя
		 */
		const uint8_t pattern[4] = {0x00, 0x33, 0x00, 0x02};
		// Место опознавателя кривой в просьбе о повторе приветствия
		size_t place = answer.size();
		/**
		 * Выполняем розыск расширения открытой части ключа обмена
		 */
		for(size_t i = 0; (i + sizeof(pattern) + 2) <= answer.size(); i++){
			// Если расширение открытой части ключа обмена найдено
			if(::memcmp(answer.data() + i, pattern, sizeof(pattern)) == 0){
				// Запоминаем место опознавателя кривой
				place = (i + sizeof(pattern));
				// Прекращаем розыск расширения
				break;
			}
		}
		// Проверяем, что расширение открытой части ключа обмена найдено
		ASSERT_LT(place, answer.size()) << "заход " << item;
		/**
		 * Подделываем опознаватель кривой: первым заходом - на ту, ключ по которой
		 * клиент уже отправил, вторым - на кривую вне его предложения
		 */
		const uint16_t group = static_cast <uint16_t> ((item == 0) ? extension::group_t::GC256B : extension::group_t::GC256A);
		// Записываем старший байт опознавателя подделанной кривой
		answer[place] = static_cast <uint8_t> ((group >> 8) & 0xFF);
		// Записываем младший байт опознавателя подделанной кривой
		answer[place + 1] = static_cast <uint8_t> (group & 0xFF);
		// Выполняем подачу подделанной просьбы о повторе клиенту
		client.push(view_t(answer.data(), answer.size()));
		/**
		 * Раздел 4.1.4 RFC 8446: просить повтора сервер вправе лишь на кривой, которую
		 * клиент предложил и ключа по которой ещё не прислал
		 */
		ASSERT_EQ(client.error(), context::error_t::GROUP) << "заход " << item;
		// Проверяем извещение, которым связь оборвана клиентом
		ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER) << "заход " << item;
		// Проверяем неустановленность связи стороной клиента
		ASSERT_FALSE(client.established()) << "заход " << item;
	}
}

/**
 * @brief Служебные объекты проверок подделанного приветствия клиента
 *
 */
namespace {
	/**
	 * @brief Метод подачи серверу составленного приветствия клиента
	 *
	 * @param server   связь стороны сервера
	 * @param greeting подаваемое приветствие клиента
	 *
	 * @return         признак успешности подачи приветствия серверу
	 *
	 * @note Приветствие клиента идёт открытым, и составить его целиком можно и без
	 *       связи стороны клиента: тем и проверяются заслоны, которых своя же сторона
	 *       никогда не переступит
	 *
	 */
	bool submit(server::context_t & server, const hello::client_t & greeting) noexcept {
		// Накопитель, в который складывается тело приветствия клиента
		vector <uint8_t> body;
		// Если тело приветствия клиента составить не удалось
		if(hello::build(greeting, body) != hello::error_t::NONE)
			// Выводим отказ подачи приветствия серверу
			return false;
		// Объект составителя отправляемых сообщений рукопожатия
		handshake::writer_t writer;
		// Если сообщение приветствия клиента составить не удалось
		if(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())) != handshake::error_t::NONE)
			// Выводим отказ подачи приветствия серверу
			return false;
		// Получаем составленное сообщение приветствия клиента
		const view_t message = writer.data();
		// Заголовок записи, которой идёт приветствие клиента
		record::header_t header;
		// Устанавливаем вид записи приветствия клиента
		header.type = record::type_t::HANDSHAKE;
		// Устанавливаем издание протокола записи приветствия
		header.version = record::version_t::TLS12;
		// Устанавливаем длину содержимого записи приветствия
		header.size = message.size;
		// Накопитель, в который складывается запись приветствия клиента
		vector <uint8_t> data(record::RECORD_HEADER + message.size, 0);
		// Если заголовок записи приветствия составить не удалось
		if(record::build(header, data.data()) != record::error_t::NONE)
			// Выводим отказ подачи приветствия серверу
			return false;
		// Переносим сообщение приветствия в запись протокола
		::memcpy(data.data() + record::RECORD_HEADER, message.data, message.size);
		// Выполняем подачу записи приветствия клиента серверу
		server.push(view_t(data.data(), data.size()));
		// Выводим успешность подачи приветствия серверу
		return true;
	}
	/**
	 * @brief Метод составления годного приветствия клиента
	 *
	 * @param greeting приветствие, в которое помещается итог составления
	 * @param bodies   накопители, в которых лежат тела расширений приветствия
	 *
	 * @return         признак успешности составления приветствия клиента
	 *
	 */
	bool compose(hello::client_t & greeting, vector <vector <uint8_t>> & bodies) noexcept {
		// Устанавливаем издание протокола, доставшееся от предыдущих изданий
		greeting.version = 0x0303;
		// Устанавливаем опознаватель связи приветствия
		greeting.session.assign(hello::HELLO_SESSION, 0x11);
		// Устанавливаем перечень предлагаемых наборов шифрования
		greeting.suites.push_back(static_cast <uint16_t> (protect::suite_t::MAGMA_MGM_L));
		// Устанавливаем перечень способов сжатия
		greeting.methods.assign(1, 0x00);
		/**
		 * Выполняем заполнение случайного значения приветствия
		 */
		for(size_t i = 0; i < hello::HELLO_RANDOM; i++)
			// Записываем очередной байт случайного значения
			greeting.random[i] = static_cast <uint8_t> (i);
		// Занимаем место под тела расширений приветствия
		bodies.resize(3);
		// Если перечень изданий протокола составить не удалось
		if(extension::versions(vector <uint16_t> (1, 0x0304), bodies[0]) != extension::error_t::NONE)
			// Выводим отказ составления приветствия клиента
			return false;
		// Добавляем расширение перечня изданий протокола
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(bodies[0].data(), bodies[0].size())));
		// Если перечень кривых обмена ключами составить не удалось
		if(extension::groups(vector <extension::group_t> (1, extension::group_t::GC256B), bodies[1]) != extension::error_t::NONE)
			// Выводим отказ составления приветствия клиента
			return false;
		// Добавляем расширение перечня кривых обмена ключами
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS), view_t(bodies[1].data(), bodies[1].size())));
		// Открытая часть ключа обмена приветствия
		const vector <uint8_t> opened(64, 0x22);
		// Если перечень открытых частей ключей обмена составить не удалось
		if(extension::shares(vector <extension::share_t> (1, extension::share_t(extension::group_t::GC256B, view_t(opened.data(), opened.size()))), bodies[2]) != extension::error_t::NONE)
			// Выводим отказ составления приветствия клиента
			return false;
		// Добавляем расширение открытых частей ключей обмена
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(bodies[2].data(), bodies[2].size())));
		// Выводим успешность составления приветствия клиента
		return true;
	}
};

/**
 * Проверка заслонов приветствия клиента
 */
TEST(ContextTest, Malformed){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	/**
	 * Выполняем перебор заслонов приветствия клиента
	 */
	for(size_t item = 0; item < 4; item++){
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Устанавливаем набор шифрования, признаваемый сервером
		server.suites({protect::suite_t::MAGMA_MGM_L});
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Составляемое приветствие клиента
		hello::client_t greeting;
		// Накопители, в которых лежат тела расширений приветствия
		vector <vector <uint8_t>> bodies;
		// Выполняем составление годного приветствия клиента
		ASSERT_TRUE(compose(greeting, bodies)) << "заслон " << item;
		/**
		 * Выполняем порчу составленного приветствия клиента
		 */
		switch(item){
			/**
			 * Повтор расширения ловит сам разборщик приветствия: раздел 4.2 RFC 8446
			 * дозволяет расширение всякого вида лишь однажды
			 */
			case 0: greeting.extensions.push_back(greeting.extensions[0]); break;
			// Если приветствие портится негодным способом сжатия
			case 1: greeting.methods.assign(1, 0x01); break;
			/**
			 * Если приветствие портится ключом по кривой, поддержку которой клиент
			 * не объявил
			 */
			case 2: {
				// Открытая часть ключа обмена по необъявленной кривой
				const vector <uint8_t> opened(128, 0x33);
				// Занимаем место под тело подделанного расширения
				bodies.push_back(vector <uint8_t> ());
				// Если перечень открытых частей ключей обмена составить не удалось
				ASSERT_EQ(extension::shares(vector <extension::share_t> (1, extension::share_t(extension::group_t::GC512C, view_t(opened.data(), opened.size()))), bodies.back()), extension::error_t::NONE);
				// Заменяем расширение открытых частей ключей обмена подделанным
				greeting.extensions[2] = hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(bodies.back().data(), bodies.back().size()));
			} break;
			/**
			 * Если приветствие портится заранее разделённым ключом не на последнем
			 * месте перечня расширений
			 */
			case 3: {
				// Опознаватель предъявляемого заранее разделённого ключа
				const vector <uint8_t> identity(32, 0x44);
				// Привязка предъявляемого заранее разделённого ключа
				const vector <uint8_t> binder(32, 0x55);
				// Занимаем место под тело расширения заранее разделённых ключей
				bodies.push_back(vector <uint8_t> ());
				// Если предложение заранее разделённых ключей составить не удалось
				ASSERT_EQ(extension::identities(
					vector <extension::identity_t> (1, extension::identity_t(view_t(identity.data(), identity.size()), 0)),
					vector <view_t> (1, view_t(binder.data(), binder.size())), bodies.back()
				), extension::error_t::NONE);
				// Добавляем расширение заранее разделённых ключей
				greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(bodies.back().data(), bodies.back().size())));
				/**
				 * Расширение имени узла ложится за заранее разделённым ключом: тем и
				 * нарушается правило раздела 4.2.11 RFC 8446 о последнем месте
				 */
				bodies.push_back(vector <uint8_t> ());
				// Если имя запрашиваемого узла составить не удалось
				ASSERT_EQ(extension::name(view_t(reinterpret_cast <const uint8_t *> ("anyks.com"), 9), bodies.back()), extension::error_t::NONE);
				// Добавляем расширение имени запрашиваемого узла
				greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(bodies.back().data(), bodies.back().size())));
			} break;
		}
		// Выполняем подачу подделанного приветствия серверу
		ASSERT_TRUE(submit(server, greeting)) << "заслон " << item;
		// Проверяем обрыв связи стороной сервера
		ASSERT_NE(server.error(), context::error_t::NONE) << "заслон " << item;
		/**
		 * Повтор расширения объявляется извещением «decode_error» разборщиком, а
		 * приветствие, само себе противоречащее, - извещением «illegal_parameter»:
		 * раздел 4.1.2 RFC 8446
		 */
		ASSERT_EQ(server.alert().description, ((item == 0) ? alert::description_t::DECODE : alert::description_t::PARAMETER)) << "заслон " << item;
		// Проверяем неустановленность связи стороной сервера
		ASSERT_FALSE(server.established()) << "заслон " << item;
	}
}

/**
 * Проверка заслона непрошенного расширения в ответе сервера
 */
TEST(ContextTest, Unwanted){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера непрошенным расширением
	ASSERT_TRUE(adversary(client, distortion_t::EXTENSION));
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	/**
	 * Раздел 4.2 RFC 8446: ответ на непрошенное расширение объявляется извещением
	 * «unsupported_extension»
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::EXTENSION);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслонов цепочки сертификатов, принятой от сервера
 */
TEST(ContextTest, Chain){
	// Искажения цепочки сертификатов, вносимые враждебным сервером
	const distortion_t distortions[2] = {distortion_t::CONTEXT, distortion_t::EMPTINESS};
	/**
	 * Выполняем перебор искажений цепочки сертификатов
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны клиента
		client::context_t client;
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE) << "искажение " << item;
		// Выполняем ответ враждебного сервера искажённой цепочкой сертификатов
		ASSERT_TRUE(adversary(client, distortions[item])) << "искажение " << item;
		/**
		 * Раздел 4.4.2 RFC 8446: непустой опознаватель запроса объявляется отказом
		 * разбора сообщения, а пустая цепочка сервера - отказом подлинности
		 */
		ASSERT_EQ(client.error(), ((item == 0) ? context::error_t::MESSAGE : context::error_t::CERTIFICATE)) << "искажение " << item;
		// Проверяем извещение, которым связь оборвана клиентом
		ASSERT_EQ(client.alert().description, alert::description_t::BADCERT) << "искажение " << item;
		// Проверяем неустановленность связи стороной клиента
		ASSERT_FALSE(client.established()) << "искажение " << item;
	}
}

/**
 * Проверка заслона схемы подписи, объявленной сервером
 */
TEST(ContextTest, Declared){
	// Подлинность враждебного сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности враждебного сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера неизвестной схемой подписи
	ASSERT_TRUE(adversary(client, distortion_t::SCHEME, &credentials));
	/**
	 * Заслон схемы стоит прежде проверки самой подписи: оттого отказ приходит именно
	 * схемой, а не несошедшейся подписью
	 */
	ASSERT_EQ(client.error(), context::error_t::SCHEME);
	/**
	 * Раздел 4.4.3 RFC 8446: непригодная схема подписи объявляется извещением
	 * «illegal_parameter»
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
	// Связь стороны клиента, судящая схему чужой кривой
	client::context_t foreign;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(foreign.start(), context::error_t::NONE);
	/**
	 * Схема известная, но положенная кривой, которой в сертификате нет: подпись по
	 * ней проверялась бы не тем ключом, которым объявлена
	 */
	ASSERT_TRUE(adversary(foreign, distortion_t::FOREIGN, &credentials));
	// Проверяем обрыв связи отказом схемы подписи
	ASSERT_EQ(foreign.error(), context::error_t::SCHEME);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(foreign.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(foreign.established());
}

/**
 * Проверка заслона срока билета, объявленного сервером
 */
TEST(ContextTest, Expiry){
	// Подлинность враждебного сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности враждебного сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем рукопожатие враждебного сервера с билетом свыше семи суток
	ASSERT_TRUE(adversary(client, distortion_t::LIFETIME, &credentials));
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	/**
	 * Раздел 4.6.1 RFC 8446: срок билета свыше семи суток объявляется извещением
	 * «illegal_parameter»
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем, что билет с негодным сроком связью не принят
	ASSERT_TRUE(client.tickets().empty());
}

/**
 * Проверка заслона записи смены набора шифрования
 */
TEST(ContextTest, Changing){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	/**
	 * Составляем запись смены набора шифрования с негодным содержимым
	 */
	{
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Содержимое записи смены набора шифрования
		const uint8_t content[1] = {0x02};
		// Объект нарезчика отправляемых записей
		record::writer_t writer;
		// Выполняем нарезку записи смены набора шифрования
		ASSERT_EQ(writer.push(record::type_t::CHANGE, record::version_t::TLS12, view_t(content, sizeof(content))), record::error_t::NONE);
		// Получаем нарезанную запись смены набора шифрования
		const view_t records = writer.data();
		// Выполняем подачу записи смены набора шифрования серверу
		server.push(records);
		/**
		 * Раздел 5 RFC 8446: запись смены набора шифрования несёт единственное
		 * дозволенное значение, а иное её содержимое - это уже не она
		 */
		ASSERT_EQ(server.error(), context::error_t::RECORD);
		// Проверяем извещение, которым связь оборвана сервером
		ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	}
	/**
	 * Подаём годную запись смены набора шифрования за установленной связью
	 */
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Выполняем проведение рукопожатия сторон связи
		converse(client, server);
		// Проверяем установленность связи стороной клиента
		ASSERT_TRUE(client.established());
		// Содержимое записи смены набора шифрования
		const uint8_t content[1] = {0x01};
		// Объект нарезчика отправляемых записей
		record::writer_t writer;
		// Выполняем нарезку записи смены набора шифрования
		ASSERT_EQ(writer.push(record::type_t::CHANGE, record::version_t::TLS12, view_t(content, sizeof(content))), record::error_t::NONE);
		// Выполняем подачу записи смены набора шифрования клиенту
		client.push(writer.data());
		/**
		 * Раздел 5 RFC 8446: за установленной связью эта запись не значит ничего, и
		 * пропускать её больше нельзя
		 */
		ASSERT_EQ(client.error(), context::error_t::RECORD);
		// Проверяем извещение, которым связь оборвана клиентом
		ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	}
}

/**
 * Проверка заслона открытого содержимого, переросшего дозволенный предел
 */
TEST(ContextTest, Oversize){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	/**
	 * Размеров два: первый перерос предел открытого содержимого, но в предел
	 * сборщика записей укладывается, а второй перерос и его - так проверяются оба
	 * заслона, а не один вместо другого
	 */
	const size_t sizes[2] = {(record::RECORD_PLAINTEXT + 128), (record::RECORD_CIPHERTEXT + 128)};
	/**
	 * Выполняем перебор размеров переросшего содержимого
	 */
	for(size_t item = 0; item < 2; item++){
	// Размер содержимого, переросшего дозволенный предел
	const size_t size = sizes[item];
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE) << "размер " << item;
	// Составляемая запись связи, переросшая дозволенный предел
	vector <uint8_t> wire(record::RECORD_HEADER + size, 0x00);
	// Заголовок составляемой записи связи
	record::header_t header;
	// Устанавливаем вид содержимого составляемой записи
	header.type = record::type_t::HANDSHAKE;
	// Устанавливаем версию протокола составляемой записи
	header.version = record::version_t::TLS12;
	// Устанавливаем размер содержимого составляемой записи
	header.size = size;
	// Выполняем составление заголовка записи связи
	ASSERT_EQ(record::build(header, wire.data()), record::error_t::NONE) << "размер " << item;
	// Выполняем подачу переросшей записи серверу
	server.push(view_t(wire.data(), wire.size()));
	/**
	 * Раздел 5.2 RFC 8446: открытое содержимое свыше 16384 байтов объявляется
	 * извещением «record_overflow»
	 */
	ASSERT_EQ(server.error(), context::error_t::RECORD);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::OVERSIZE) << "размер " << item;
	}
}

/**
 * Проверка заслона сообщения рукопожатия, разорванного чужой записью
 */
TEST(ContextTest, Divided){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера разорванным сообщением рукопожатия
	ASSERT_TRUE(adversary(client, distortion_t::INTERLEAVE));
	/**
	 * Раздел 5.1 RFC 8446: сообщения рукопожатия перемежать записями иного
	 * содержимого нельзя, и разрыв объявляется извещением «unexpected_message»
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка рукопожатия враждебного клиента, ничего не искажающего
 */
TEST(ContextTest, Intruder){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем набор шифрования, признаваемый сервером
	server.suites({protect::suite_t::MAGMA_MGM_L});
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем рукопожатие враждебного клиента, ничего не искажающего
	ASSERT_TRUE(intruder(server, distortion_t::NONE));
	/**
	 * Оснастка проверяется прежде заслонов: рукопожатие, сложенное вручную, обязано
	 * устанавливать связь - иначе всякий отказ будет отказом самой оснастки
	 */
	ASSERT_EQ(server.error(), context::error_t::NONE);
	// Проверяем установленность связи стороной сервера
	ASSERT_TRUE(server.established());
}

/**
 * Проверка заслона опознавателя запроса подлинности клиента
 */
TEST(ContextTest, Echoed){
	// Подлинность сторон связи
	context::credential_t credentials;
	// Выполняем выработку подлинности сторон связи
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем набор шифрования, признаваемый сервером
	server.suites({protect::suite_t::MAGMA_MGM_L});
	// Запрашиваем подлинность клиента стороной сервера
	server.request(true);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем рукопожатие враждебного клиента с чужим опознавателем запроса
	ASSERT_TRUE(intruder(server, distortion_t::CONTEXT, &credentials));
	/**
	 * Раздел 4.4.2 RFC 8446: опознаватель запроса, взятый с потолка, отвечает не тому
	 * запросу, который был сделан
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::BADCERT);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка повтора метки возврата состояния сервера
 */
TEST(ContextTest, Label){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем просьбу враждебного сервера о повторе приветствия с меткой
	ASSERT_TRUE(adversary(client, distortion_t::COOKIE));
	// Проверяем, что связь просьбу о повторе приняла
	ASSERT_EQ(client.error(), context::error_t::NONE);
	// Получаем повторное приветствие, отправленное клиентом
	const view_t sending = client.output();
	// Проверяем отправку повторного приветствия клиентом
	ASSERT_GT(sending.size, static_cast <size_t> (0));
	// Объект сборщика записей повторного приветствия
	record::reader_t records;
	// Выполняем подачу повторного приветствия сборщику записей
	ASSERT_EQ(records.push(sending), record::error_t::NONE);
	// Заголовок записи повторного приветствия
	record::header_t header;
	// Содержимое записи повторного приветствия
	view_t payload;
	// Выполняем чтение записи повторного приветствия
	ASSERT_EQ(records.next(header, payload), record::error_t::NONE);
	// Объект сборщика сообщений повторного приветствия
	handshake::reader_t messages;
	// Выполняем подачу содержимого записи сборщику сообщений
	ASSERT_EQ(messages.push(payload), handshake::error_t::NONE);
	// Заголовок сообщения повторного приветствия
	handshake::header_t item;
	// Тело сообщения повторного приветствия
	view_t body;
	// Выполняем чтение сообщения повторного приветствия
	ASSERT_EQ(messages.next(item, body), handshake::error_t::NONE);
	// Проверяем, что прочитано именно приветствие клиента
	ASSERT_EQ(item.type, handshake::type_t::CLIENT);
	// Разбираемое повторное приветствие клиента
	hello::client_t greeting;
	// Выполняем разбор повторного приветствия клиента
	ASSERT_EQ(hello::parse(body, greeting), hello::error_t::NONE);
	// Разыскиваем расширение метки возврата состояния сервера
	const hello::extension_t * label = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::COOKIE));
	/**
	 * Раздел 4.2.2 RFC 8446: метка повторяется дословно, ибо сервер возвращает ею
	 * состояние, которого у себя не держал
	 */
	ASSERT_NE(label, nullptr);
	// Метка возврата состояния, объявленная просьбой о повторе
	const uint8_t expected[6] = {0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
	// Проверяем длину повторённой метки возврата состояния
	ASSERT_EQ(label->data.size, sizeof(expected));
	// Проверяем дословность повторённой метки возврата состояния
	ASSERT_EQ(::memcmp(label->data.data, expected, sizeof(expected)), 0);
}

/**
 * Проверка заслона состава расширений приветствия сервера
 */
TEST(ContextTest, Composition){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера расширением не своего сообщения
	ASSERT_TRUE(adversary(client, distortion_t::GREETING));
	/**
	 * Раздел 4.1.3 RFC 8446: приветствию сервера положены всего три расширения, а
	 * всё прочее принадлежит защищённым расширениям
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::EXTENSION);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка метки возврата состояния сервера в просьбе о повторе приветствия
 */
TEST(ContextTest, Stateless){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	/**
	 * Клиент объявляет две кривые обмена ключами, а открытую часть ключа шлёт лишь
	 * для первой из них: второй кривой сервер и попросит повторить приветствие
	 */
	client.groups({extension::group_t::GC256B, extension::group_t::GC512C});
	// Устанавливаем единственную кривую обмена ключами сервера
	server.groups({extension::group_t::GC512C});
	// Метка возврата состояния, выдаваемая сервером
	const vector <uint8_t> cookie = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Устанавливаем метку возврата состояния стороны сервера
	server.cookie(cookie);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проверяем, что метки от клиента сервер ещё не принял
	ASSERT_TRUE(server.cookie().empty());
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи стороной клиента
	ASSERT_TRUE(client.established());
	// Проверяем установленность связи стороной сервера
	ASSERT_TRUE(server.established());
	/**
	 * Раздел 4.2.2 RFC 8446: клиент повторяет метку дословно, и сервер получает своё
	 * состояние назад, не храня его у себя между приветствиями
	 */
	ASSERT_EQ(server.cookie(), cookie);
}
