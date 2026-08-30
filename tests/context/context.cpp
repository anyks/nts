/**
 * @file context.cpp
 * @date 2026-08-30
 *
 * @license{LicenseRef-ANYKS-TLS-1.0}
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
#include <sign/gost.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <entropy/entropy.hpp>
#include <digest/streebog.hpp>
#include <curve/parameters.hpp>

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
	void handshake(client::context_t & client, server::context_t & server) noexcept {
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
	handshake(client, server);
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
	handshake(client, server);
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
	handshake(client, server);
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
	handshake(client, server);
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
	handshake(client, server);
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
		handshake(client, server);
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
	handshake(client, server);
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
	handshake(client, server);
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
	handshake(client, server);
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
		handshake(client, server);
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
	handshake(client, server);
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
		// Если связь стороны сервера завести не удалось
		if(server.start() != context::error_t::NONE)
			// Выводим отказ выдачи билета возобновления связи
			return false;
		// Если связь стороны клиента завести не удалось
		if(client.start() != context::error_t::NONE)
			// Выводим отказ выдачи билета возобновления связи
			return false;
		// Выполняем проведение рукопожатия сторон связи
		handshake(client, server);
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
	handshake(client, server);
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
	handshake(client, server);
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
	handshake(client, server);
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
	handshake(client, server);
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
	handshake(client, server);
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.error(), context::error_t::PROTOCOL);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::PROTOCOL);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
	// Проверяем, что прикладного протокола клиент не принял
	ASSERT_TRUE(client.protocol().empty());
}
