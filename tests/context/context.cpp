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
#include <cstring>
#include <main.hpp>
#include <starve.hpp>
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
using namespace nts;

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
	bool identity(const string & name, context::credential_t & result, const bool alien) noexcept {
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
		/**
		 * Чужой алгоритм ключа: опознаватель берётся эллиптическим вне ГОСТ, а подпись и
		 * само значение остаются ГОСТ - разбор ключа обязан отвергнуть лист до всякой
		 * сверки подписи
		 */
		if(!body.oid(alien ? "1.2.840.10045.2.1" : "1.2.643.7.1.1.1.1"))
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
	 * @brief Метод выработки подлинности стороны связи своим алгоритмом ГОСТ
	 *
	 * @param name   общее имя стороны выработанного сертификата
	 * @param result подлинность, в которую помещается итог выработки
	 *
	 * @return       признак успешности выработки подлинности стороны
	 *
	 */
	bool identity(const string & name, context::credential_t & result) noexcept {
		// Вырабатываем подлинность своим алгоритмом
		return identity(name, result, false);
	}
	/**
	 * @brief Метод подачи связи одиночного сообщения рукопожатия открытой записью
	 *
	 * @param type вид подаваемого сообщения рукопожатия
	 * @param body тело подаваемого сообщения рукопожатия
	 * @param wire накопитель, в который складывается составленная запись
	 *
	 * @return     признак успешности составления записи связи
	 *
	 * @note Подача идёт открытой записью, ибо связь свежа и защиты записей ещё не
	 *       завела: так проверяются заслоны черёда, стоящие до всякого разбора тела
	 *
	 */
	bool sole(const handshake::type_t type, const view_t & body, vector <uint8_t> & wire) noexcept {
		// Объект составителя отправляемых сообщений рукопожатия
		handshake::writer_t writer;
		// Если сообщение рукопожатия составить не удалось
		if(writer.push(type, body) != handshake::error_t::NONE)
			// Выводим отказ составления записи связи
			return false;
		// Получаем составленное сообщение рукопожатия
		const view_t message = writer.data();
		// Объект нарезчика отправляемых записей
		record::writer_t plain;
		// Если сообщение рукопожатия на записи нарезать не удалось
		if(plain.push(record::type_t::HANDSHAKE, record::version_t::TLS12, message) != record::error_t::NONE)
			// Выводим отказ составления записи связи
			return false;
		// Получаем нарезанные записи сообщения рукопожатия
		const view_t plaintext = plain.data();
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Выполняем перенос нарезанных записей в накопитель
			wire.assign(plaintext.data, plaintext.data + plaintext.size);
		/**
		 * Если памяти под накопитель не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ составления записи связи
			return false;
		}
		// Выводим успешность составления записи связи
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
		/**
		 * Выполняем перехват ошибок работы с памятью: под отмеренным запасом выделений
		 * переносу байтов памяти может не хватить, и тогда байты остаются в накопителе
		 * отправителя, а передача считается не состоявшейся
		 */
		try {
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
		/**
		 * Если памяти под перенос байтов не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим признак того, что байты между сторонами не передавались
			return false;
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
	/**
	 * @brief Виды нарушений договора связи при нехватке памяти
	 *
	 */
	enum class breach_t : uint8_t {
		NONE     = 0x00, // Нарушения нет
		SETUP    = 0x01, // Заведение связи ответило отказом, отличным от нехватки памяти
		TORN     = 0x02, // Связь оборвана отказом, отличным от нехватки памяти
		NOTICE   = 0x03, // Связь оборвана нехваткой памяти, но извещение не о внутреннем отказе
		WRITE    = 0x04, // Отправка прикладных данных ответила отказом вне договора
		READ     = 0x05, // Получение прикладных данных ответило отказом вне договора
		PAYLOAD  = 0x06, // Принятые прикладные данные разошлись с отправленными
		CLOSE    = 0x07, // Закрытие связи ответило отказом вне договора
		FINISHED = 0x08  // На достаточном запасе связь не прошла весь путь без отказа памяти
	};
	/**
	 * @brief Метод проверки одной стороны оборванной связи
	 *
	 * @param state       состояние проверяемой стороны связи
	 * @param error       отказ, которым сторона связи оборвана
	 * @param description описание извещения, которым сторона связи оборвана
	 * @param torn        признак обрыва связи, выставляемый по итогу проверки
	 *
	 * @return            обнаруженное нарушение договора связи
	 *
	 */
	breach_t torn(const context::state_t state, const context::error_t error, const alert::description_t description, bool & torn) noexcept {
		// Если связь стороной не оборвана
		if(state != context::state_t::FAILED)
			// Выводим отсутствие нарушения договора связи
			return breach_t::NONE;
		// Запоминаем, что связь оборвана
		torn = true;
		// Если связь оборвана отказом, отличным от нехватки памяти
		if(error != context::error_t::MEMORY)
			// Выводим нарушение вида обрыва связи
			return breach_t::TORN;
		// Если извещение обрыва не о внутреннем отказе
		if(description != alert::description_t::INTERNAL)
			// Выводим нарушение вида извещения об обрыве связи
			return breach_t::NOTICE;
		// Выводим отсутствие нарушения договора связи
		return breach_t::NONE;
	}
	/**
	 * @brief Метод проверки отказа вызова связи при нехватке памяти
	 *
	 * @param error проверяемый отказ вызова связи
	 *
	 * @return      признак того, что отказ вызова договору отвечает
	 *
	 * @note Дозволены успех, нехватка памяти да отказы состояния: последние идут
	 *       следствием обрыва связи либо несостоявшегося рукопожатия
	 *
	 */
	bool lawful(const context::error_t error) noexcept {
		// Выводим признак того, что отказ вызова договору отвечает
		return (
			(error == context::error_t::NONE) || (error == context::error_t::MEMORY) ||
			(error == context::error_t::STATE) || (error == context::error_t::CLOSED)
		);
	}
	/**
	 * @brief Метод ведения связи при отмеренном запасе выделений
	 *
	 * @param client      связь стороны клиента
	 * @param server      связь стороны сервера
	 * @param credentials подлинность стороны сервера
	 * @param starved     признак того, что нехватка памяти хоть раз объявлена отказом
	 *
	 * @return            обнаруженное нарушение договора связи
	 *
	 * @note Запас выделений отмеряется тем, кто связь ведёт: сами связи достаются
	 *       заведёнными как внутри запаса, так и вне его
	 *
	 */
	breach_t starving(client::context_t & client, server::context_t & server, const context::credential_t & credentials, bool & starved) noexcept {
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Выполняем заведение связи стороны сервера
		context::error_t error = server.start();
		// Запоминаем объявленный отказ памяти
		starved = (starved || (error == context::error_t::MEMORY));
		// Если заведение связи сервера ответило отказом вне договора
		if((error != context::error_t::NONE) && (error != context::error_t::MEMORY))
			// Выводим нарушение договора заведения связи
			return breach_t::SETUP;
		// Выполняем заведение связи стороны клиента
		error = client.start();
		// Запоминаем объявленный отказ памяти
		starved = (starved || (error == context::error_t::MEMORY));
		// Если заведение связи клиента ответило отказом вне договора
		if((error != context::error_t::NONE) && (error != context::error_t::MEMORY))
			// Выводим нарушение договора заведения связи
			return breach_t::SETUP;
		// Выполняем проведение рукопожатия сторон связи
		converse(client, server);
		// Признак того, что связь оборвана одной из сторон
		bool failed = false;
		// Выполняем проверку обрыва связи стороной клиента
		breach_t breach = torn(client.state(), client.error(), client.alert().description, failed);
		// Если договор обрыва связи нарушен
		if(breach != breach_t::NONE)
			// Выводим обнаруженное нарушение договора связи
			return breach;
		// Выполняем проверку обрыва связи стороной сервера
		breach = torn(server.state(), server.error(), server.alert().description, failed);
		// Если договор обрыва связи нарушен
		if(breach != breach_t::NONE)
			// Выводим обнаруженное нарушение договора связи
			return breach;
		// Запоминаем обрыв связи нехваткой памяти
		starved = (starved || failed);
		// Текст прикладных данных, отправляемых клиентом
		static const char text[] = "Запрос прикладного протокола при нехватке памяти";
		// Прикладные данные, отправляемые клиентом
		const view_t request(reinterpret_cast <const uint8_t *> (text), sizeof(text) - 1);
		// Выполняем отправку прикладных данных клиентом
		error = client.write(request);
		// Запоминаем объявленный отказ памяти
		starved = (starved || (error == context::error_t::MEMORY));
		// Если отправка прикладных данных ответила отказом вне договора
		if(!lawful(error))
			// Выводим нарушение договора отправки прикладных данных
			return breach_t::WRITE;
		// Признак того, что прикладные данные отправлены
		const bool written = (error == context::error_t::NONE);
		// Выполняем передачу байтов между сторонами связи
		pump(client, server);
		// Выполняем проверку обрыва связи стороной сервера
		breach = torn(server.state(), server.error(), server.alert().description, failed);
		// Если договор обрыва связи нарушен
		if(breach != breach_t::NONE)
			// Выводим обнаруженное нарушение договора связи
			return breach;
		// Накопитель, в который помещаются принятые прикладные данные
		vector <uint8_t> received;
		// Выполняем получение принятых сервером прикладных данных
		error = server.read(received);
		// Запоминаем объявленный отказ памяти
		starved = (starved || (error == context::error_t::MEMORY));
		// Если получение прикладных данных ответило отказом вне договора
		if(!lawful(error))
			// Выводим нарушение договора получения прикладных данных
			return breach_t::READ;
		/**
		 * Принятые данные обязаны сойтись с отправленными, когда отправка удалась,
		 * передача байтов состоялась и связь при этом не оборвана: нехватка памяти
		 * вправе не донести данные, но не вправе их исказить
		 */
		if(written && (error == context::error_t::NONE) && !received.empty() && ((received.size() != request.size) || (::memcmp(received.data(), request.data, request.size) != 0)))
			// Выводим нарушение целости прикладных данных
			return breach_t::PAYLOAD;
		// Выполняем закрытие связи стороной клиента
		error = client.close();
		// Запоминаем объявленный отказ памяти
		starved = (starved || (error == context::error_t::MEMORY));
		// Если закрытие связи ответило отказом вне договора
		if(!lawful(error))
			// Выводим нарушение договора закрытия связи
			return breach_t::CLOSE;
		// Выполняем передачу байтов между сторонами связи
		pump(client, server);
		// Выполняем закрытие связи стороной сервера
		error = server.close();
		// Запоминаем объявленный отказ памяти
		starved = (starved || (error == context::error_t::MEMORY));
		// Если закрытие связи ответило отказом вне договора
		if(!lawful(error))
			// Выводим нарушение договора закрытия связи
			return breach_t::CLOSE;
		// Выполняем передачу байтов между сторонами связи
		pump(client, server);
		// Выполняем проверку обрыва связи стороной клиента
		breach = torn(client.state(), client.error(), client.alert().description, failed);
		// Если договор обрыва связи нарушен
		if(breach != breach_t::NONE)
			// Выводим обнаруженное нарушение договора связи
			return breach;
		// Выполняем проверку обрыва связи стороной сервера
		breach = torn(server.state(), server.error(), server.alert().description, failed);
		// Если договор обрыва связи нарушен
		if(breach != breach_t::NONE)
			// Выводим обнаруженное нарушение договора связи
			return breach;
		// Запоминаем обрыв связи нехваткой памяти
		starved = (starved || failed);
		// Выводим отсутствие нарушения договора связи
		return breach_t::NONE;
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
	/**
	 * Оборванная связь принимать больше нечего: состояние сверяется ОТДЕЛЬНОЙ
	 * половиной заслона от незаведённости, и оборванная связь трогает именно её
	 */
	ASSERT_EQ(client.push(view_t(buffer.data(), buffer.size())), context::error_t::STATE);
	// Проверяем отказ закрытия оборванной связи
	ASSERT_EQ(client.close(), context::error_t::CLOSED);
	// Проверяем, что отвергнутая подача состояния связи не изменила
	ASSERT_EQ(client.state(), context::state_t::FAILED);
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
 * Проверка предложения упреждающих данных билетом, их не дозволяющим
 */
TEST(ContextTest, Disallowed){
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
	// Проверяем, что выданный билет упреждающие данные дозволяет
	ASSERT_GT(accepted.advance, static_cast <uint32_t> (0));
	// Объявляем принятый билет упреждающих данных не дозволяющим
	accepted.advance = 0;
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
	// Устанавливаем предложение упреждающих данных клиентом
	client.advance(true);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	/**
	 * Предложение связи и дозволение билета сверяются РАЗНЫМИ половинами условия:
	 * связь упреждающие данные предлагает, а билет их не дозволяет, и расширение
	 * упреждающих данных в приветствие не ложится
	 */
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем возобновление связи заранее разделённым ключом
	ASSERT_TRUE(client.shared() && server.shared());
	// Проверяем, что упреждающие данные связью не объявлены принятыми
	ASSERT_FALSE(client.accepted());
	// Проверяем, что и сервер приёма упреждающих данных не объявляет
	ASSERT_FALSE(server.accepted());
}

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
	// Проверяем, что и сам сервер приём упреждающих данных объявляет
	ASSERT_TRUE(server.accepted());
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
 * Проверка пропуска данных, пришедших за извещением о закрытии
 */
TEST(ContextTest, Trailing){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем рукопожатие враждебного сервера с данными за закрытием
	ASSERT_TRUE(adversary(client, distortion_t::AFTERCLOSE, &credentials));
	/**
	 * Раздел 6.1 RFC 8446 велит пропускать всё, что пришло за извещением о закрытии:
	 * обрыв связи здесь был бы отступлением от стандарта
	 */
	ASSERT_EQ(client.error(), context::error_t::NONE);
	// Накопитель, в который помещаются принятые прикладные данные
	vector <uint8_t> received;
	// Выполняем получение принятых клиентом прикладных данных
	client.read(received);
	// Проверяем, что данные за извещением о закрытии связью пропущены
	ASSERT_TRUE(received.empty());
}

/**
 * Проверка заслона конца упреждающих данных, которых не посылали
 */
TEST(ContextTest, Farewell){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем рукопожатие враждебного клиента с концом упреждающих данных
	ASSERT_TRUE(intruder(server, distortion_t::FAREWELL, &credentials));
	/**
	 * Раздел 4.5 RFC 8446: конец упреждающих данных закрывает поток, идущий ключами
	 * упреждения, а связь этого потока не открывала вовсе
	 */
	ASSERT_EQ(server.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка отвержения упреждающих данных при смене прикладного протокола
 */
TEST(ContextTest, Dialect){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Билет, принятый клиентом прошлой связи
	context::ticket_t accepted;
	// Билеты, признаваемые сервером возобновляемой связи
	vector <context::ticket_t> issued;
	/**
	 * Проводим связь, выдающую билет, по прикладному протоколу «h2»
	 */
	{
		// Связь стороны клиента, выдающей связи
		client::context_t client;
		// Связь стороны сервера, выдающей связи
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Устанавливаем прикладной протокол, признаваемый сервером
		server.protocols({"h2"});
		// Устанавливаем приём упреждающих данных сервером
		server.advance(true);
		// Устанавливаем прикладной протокол, предлагаемый клиентом
		client.protocols({"h2"});
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Выполняем проведение рукопожатия сторон связи
		converse(client, server);
		// Проверяем установленность связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем выбор прикладного протокола сторонами связи
		ASSERT_EQ(client.protocol(), "h2");
		// Выполняем выдачу билета возобновления связи сервером
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Выполняем передачу билета возобновления связи клиенту
		pump(client, server);
		// Проверяем приём билета возобновления связи клиентом
		ASSERT_FALSE(client.tickets().empty());
		// Запоминаем билеты, признаваемые будущим сервером
		issued = server.tickets();
		// Запоминаем билет, принятый клиентом связи
		accepted = client.tickets()[0];
	}
	// Проверяем, что билет несёт прикладной протокол выдавшей его связи
	ASSERT_EQ(accepted.protocol, "h2");
	// Связь стороны клиента, возобновляющая прошлую
	client::context_t client;
	// Связь стороны сервера, признающая выданный билет
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	/**
	 * Новая связь идёт иным прикладным протоколом: возобновлению это не мешает, а
	 * упреждающим данным - мешает
	 */
	server.protocols({"http/1.1"});
	// Устанавливаем билеты, признаваемые сервером
	server.resume(issued);
	// Устанавливаем приём упреждающих данных сервером
	server.advance(true);
	// Устанавливаем прикладной протокол, предлагаемый клиентом
	client.protocols({"http/1.1"});
	// Предъявляем серверу билет, принятый прошлой связью
	client.resume(accepted);
	// Устанавливаем предложение упреждающих данных сервером
	client.advance(true);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Прикладные данные, отправляемые вместе с приветствием клиента
	const string request = "Упреждающие данные, сложенные по прежнему протоколу";
	// Выполняем отправку упреждающих данных клиентом
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем возобновление связи заранее разделённым ключом
	ASSERT_TRUE(client.shared() && server.shared());
	// Проверяем выбор нового прикладного протокола сторонами связи
	ASSERT_EQ(client.protocol(), "http/1.1");
	/**
	 * Раздел 4.2.10 RFC 8446: прикладной протокол связи с протоколом билета разошёлся,
	 * и упреждающие данные сервером не принимаются
	 */
	ASSERT_FALSE(client.accepted());
}

/**
 * Проверка отвержения упреждающих данных при смене набора шифрования
 */
TEST(ContextTest, Divergent){
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
	// Проверяем, что билет выдан набором шифрования на шифре «Кузнечик»
	ASSERT_EQ(accepted.suite, protect::suite_t::KUZNYECHIK_MGM_L);
	// Связь стороны клиента, возобновляющая прошлую
	client::context_t client;
	// Связь стороны сервера, признающая выданный билет
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	/**
	 * Сервер признаёт единственный набор шифрования, и набор этот не тот, каким выдан
	 * билет: возобновлению связи это не мешает, а упреждающим данным - мешает
	 */
	server.suites({protect::suite_t::MAGMA_MGM_L});
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
	const string request = "Упреждающие данные, зашифрованные набором билета";
	// Выполняем отправку упреждающих данных клиентом
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем возобновление связи заранее разделённым ключом
	ASSERT_TRUE(client.shared() && server.shared());
	/**
	 * Раздел 4.2.10 RFC 8446: набор шифрования связи с набором билета разошёлся, и
	 * упреждающие данные сервером не принимаются
	 */
	ASSERT_FALSE(client.accepted());
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
	// Проверяем, что и сам сервер приём упреждающих данных объявляет
	ASSERT_TRUE(server.accepted());
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
 * Проверка сличения длины опознавателя связи, возвращённого сервером
 */
TEST(ContextTest, Truncated){
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
	// Получаем байты, отправляемые клиентом серверу
	view_t sending = client.output();
	// Выполняем перенос отправляемых клиентом байтов
	const vector <uint8_t> greeting(sending.data, sending.data + sending.size);
	// Снимаем отправленные байты с накопителя клиента
	client.consume(greeting.size());
	// Выполняем подачу приветствия клиента серверу
	ASSERT_EQ(server.push(view_t(greeting.data(), greeting.size())), context::error_t::NONE);
	// Получаем байты, отправляемые сервером клиенту
	sending = server.output();
	// Проверяем наличие отправляемых сервером байтов
	ASSERT_GT(sending.size, static_cast <size_t> (0));
	// Выполняем перенос отправляемых сервером байтов
	vector <uint8_t> answer(sending.data, sending.data + sending.size);
	// Снимаем отправленные байты с накопителя сервера
	server.consume(answer.size());
	// Место длины опознавателя связи в приветствии сервера
	const size_t place = (5 + 4 + 2 + 32);
	// Проверяем длину опознавателя связи приветствия сервера
	ASSERT_EQ(answer[place], static_cast <uint8_t> (hello::HELLO_SESSION));
	/**
	 * Опознаватель связи изымается из приветствия ЦЕЛИКОМ, а длины записи и сообщения
	 * рукопожатия правятся следом: подделка одной лишь длины оборвала бы приветствие
	 * посреди поля, и заслон длины опознавателя связи остался бы нетронутым
	 */
	answer.erase((answer.begin() + place + 1), (answer.begin() + place + 1 + hello::HELLO_SESSION));
	// Объявляем опознаватель связи приветствия сервера пустым
	answer[place] = 0x00;
	// Определяем длину сообщения рукопожатия за изъятием опознавателя связи
	const size_t length = (((static_cast <size_t> (answer[6]) << 16) | (static_cast <size_t> (answer[7]) << 8) |
	                        static_cast <size_t> (answer[8])) - hello::HELLO_SESSION);
	// Правим старший байт длины сообщения рукопожатия
	answer[6] = static_cast <uint8_t> ((length >> 16) & 0xFF);
	// Правим средний байт длины сообщения рукопожатия
	answer[7] = static_cast <uint8_t> ((length >> 8) & 0xFF);
	// Правим младший байт длины сообщения рукопожатия
	answer[8] = static_cast <uint8_t> (length & 0xFF);
	// Определяем длину записи за изъятием опознавателя связи
	const size_t volume = (((static_cast <size_t> (answer[3]) << 8) | static_cast <size_t> (answer[4])) - hello::HELLO_SESSION);
	// Правим старший байт длины записи
	answer[3] = static_cast <uint8_t> ((volume >> 8) & 0xFF);
	// Правим младший байт длины записи
	answer[4] = static_cast <uint8_t> (volume & 0xFF);
	// Выполняем подачу подделанного приветствия клиенту
	client.push(view_t(answer.data(), answer.size()));
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	/**
	 * Длина опознавателя связи и содержимое его сверяются РАЗНЫМИ половинами заслона:
	 * пустой опознаватель при непустом предложенном трогает ту половину, что отвечает
	 * за длину, и до сличения содержимого дело не доходит вовсе
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
		/**
		 * Предел длины ставится ДО заведения накопителя. Сборщик записей сверяет длину
		 * содержимого сам, но сверка та идёт уже после того, как накопитель заведён по
		 * сумме заголовка с длиной сообщения, - а сумма эта у непомерной длины
		 * заворачивается за ноль, оставляя накопитель пустым под непомерный перенос
		 */
		if(message.size > record::RECORD_PLAINTEXT)
			// Выводим отказ подачи приветствия серверу
			return false;
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
		bodies.resize(4);
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
		/**
		 * Раздел 9.2 RFC 8446 велит клиенту объявлять схемы подписи всякий раз, когда
		 * сервер подтверждает подлинность сертификатом: годное приветствие несёт их
		 */
		if(extension::schemes(vector <extension::scheme_t> (1, extension::scheme_t::S256B), bodies[3]) != extension::error_t::NONE)
			// Выводим отказ составления приветствия клиента
			return false;
		// Добавляем расширение схем подписи, признаваемых клиентом
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(bodies[3].data(), bodies[3].size())));
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
	for(size_t item = 0; item < 5; item++){
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
			 * Раздел 4.1.2 RFC 8446 велит перечню способов сжатия нести ровно ОДИН
			 * способ. Число способов и значение единственного из них сверяются
			 * разными половинами заслона, и перечень из двух способов, всякий из
			 * которых сам по себе годен, трогает ту половину, что считает их число
			 */
			case 4: greeting.methods.assign(2, 0x00); break;
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
 * Проверка заслона отсутствия схем подписи в приветствии клиента
 */
TEST(ContextTest, Signing){
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
	// Составляемое приветствие клиента
	hello::client_t greeting;
	// Накопители, в которых лежат тела расширений приветствия
	vector <vector <uint8_t>> bodies;
	// Выполняем составление годного приветствия клиента
	ASSERT_TRUE(compose(greeting, bodies));
	/**
	 * Выполняем перебор расширений составленного приветствия
	 */
	for(size_t i = 0; i < greeting.extensions.size(); i++){
		// Если найдено расширение схем подписи
		if(greeting.extensions[i].type == static_cast <uint16_t> (extension::type_t::SCHEMES)){
			// Изымаем расширение схем подписи из приветствия клиента
			greeting.extensions.erase(greeting.extensions.begin() + i);
			// Прекращаем перебор расширений приветствия
			break;
		}
	}
	// Выполняем подачу подделанного приветствия серверу
	ASSERT_TRUE(submit(server, greeting));
	/**
	 * Раздел 9.2 RFC 8446: без схем подписи сервер, подтверждающий подлинность
	 * сертификатом, подписать владение своим ключом не вправе ничем
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::MISSING);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона непрошенного расширения записи цепочки сертификатов
 */
TEST(ContextTest, Adorned){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем рукопожатие враждебного сервера с непрошенным расширением записи
	ASSERT_TRUE(adversary(client, distortion_t::ADORNED));
	/**
	 * Раздел 4.4.2 RFC 8446: расширения записи цепочки отвечают тем, которые клиент
	 * предложил приветствием, а всё прочее объявляется «unsupported_extension»
	 */
	ASSERT_EQ(client.error(), context::error_t::EXTENSION);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::EXTENSION);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона запроса подлинности без схем подписи
 */
TEST(ContextTest, Voiceless){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем рукопожатие враждебного сервера с запросом без схем подписи
	ASSERT_TRUE(adversary(client, distortion_t::SILENT));
	/**
	 * Раздел 4.3.2 RFC 8446: запрос подлинности обязан нести схемы подписи, ибо без
	 * них клиенту нечем узнать, какую подпись сервер сличить сумеет
	 */
	ASSERT_EQ(client.error(), context::error_t::SCHEME);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::MISSING);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона приветствия клиента искажением ARCHAIC
 */
TEST(ContextTest, Ancient){
	// Подлинность сторон связи
	context::credential_t credentials;
	// Выполняем выработку подлинности сторон связи
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	/**
	 * Сервер ведёт лишь издание 1.3: с умолчанием 1.2…1.3 приветствие без перечня
	 * изданий законно вело бы связь изданием 1.2 (приложение D.2 RFC 8446)
	 */
	ASSERT_EQ(server.versions(0x0304, 0x0304), context::error_t::NONE);
	// Устанавливаем набор шифрования, признаваемый сервером
	server.suites({protect::suite_t::MAGMA_MGM_L});
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::ARCHAIC, &credentials);
	/**
	 * Раздел 4.2.1 RFC 8446 велит объявлять перечень изданий протокола всяким
	 * приветствием клиента: без него издание связи неопределимо вовсе
	 */
	ASSERT_EQ(server.error(), context::error_t::VERSION);
	/**
	 * Приложение D.2 RFC 8446 велит серверу, не поддерживающему изданий, объявленных
	 * приветствием без перечня, обрывать связь извещением protocol_version. Извещение
	 * missing_extension сюда НЕ относится: раздел 9.2 держит его для приветствия,
	 * ведущего переговоры по этому стандарту, а таковым он числит лишь приветствие,
	 * несущее перечень изданий с 0x0304 в теле
	 */
	ASSERT_EQ(server.alert().description, alert::description_t::VERSION);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона приветствия клиента искажением OUTDATED
 */
TEST(ContextTest, Antique){
	// Подлинность сторон связи
	context::credential_t credentials;
	// Выполняем выработку подлинности сторон связи
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	/**
	 * Сервер ведёт лишь издание 1.3: с умолчанием 1.2…1.3 приветствие без перечня
	 * изданий законно вело бы связь изданием 1.2 (приложение D.2 RFC 8446)
	 */
	ASSERT_EQ(server.versions(0x0304, 0x0304), context::error_t::NONE);
	// Устанавливаем набор шифрования, признаваемый сервером
	server.suites({protect::suite_t::MAGMA_MGM_L});
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::OUTDATED, &credentials);
	/**
	 * Раздел 4.2.1 RFC 8446: не найдя среди предложенных изданий своего, сервер
	 * обязан оборвать связь извещением о несовпадении издания протокола
	 */
	ASSERT_EQ(server.error(), context::error_t::VERSION);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::VERSION);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона приветствия клиента искажением ALIEN
 */
TEST(ContextTest, Estranged){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::ALIEN, &credentials);
	/**
	 * Раздел 4.1.1 RFC 8446: не найдя общего с клиентом набора шифрования, сервер
	 * обязан оборвать связь извещением о несостоявшемся рукопожатии
	 */
	ASSERT_EQ(server.error(), context::error_t::SUITE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона приветствия клиента искажением BARE
 */
TEST(ContextTest, Naked){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::BARE, &credentials);
	/**
	 * Раздел 4.2.7 RFC 8446: не опознав доли клиента, сервер ищет перечень кривых,
	 * и отсутствие его при (EC)DHE - отсутствие обязательного расширения
	 */
	ASSERT_EQ(server.error(), context::error_t::GROUP);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::MISSING);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона приветствия клиента искажением STRANGER
 */
TEST(ContextTest, Foreignness){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::STRANGER, &credentials);
	/**
	 * Раздел 4.1.1 RFC 8446: не найдя общей с клиентом кривой обмена ключами, сервер
	 * обязан оборвать связь извещением о несостоявшемся рукопожатии
	 */
	ASSERT_EQ(server.error(), context::error_t::GROUP);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона приветствия клиента искажением HOLLOW
 */
TEST(ContextTest, Voided){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::HOLLOW, &credentials);
	/**
	 * Раздел 4.2.8 RFC 8446: открытая часть ключа в доле обмена длиной не короче
	 * байта, и пустую долю отвергает уже разбор расширения - отказом записи
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона прикладных данных до установления связи
 */
TEST(ContextTest, Precocious){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Прикладные данные, поданные связи до её установления
	const uint8_t grain[4] = {0x41, 0x4E, 0x54, 0x53};
	// Составляемая запись прикладных данных
	vector <uint8_t> wire(record::RECORD_HEADER + sizeof(grain), 0x00);
	// Заголовок составляемой записи связи
	record::header_t header;
	// Устанавливаем вид содержимого составляемой записи
	header.type = record::type_t::APPLICATION;
	// Устанавливаем версию протокола составляемой записи
	header.version = record::version_t::TLS12;
	// Устанавливаем размер содержимого составляемой записи
	header.size = sizeof(grain);
	// Выполняем составление заголовка записи связи
	ASSERT_EQ(record::build(header, wire.data()), record::error_t::NONE);
	// Переносим прикладные данные в составляемую запись
	::memcpy(wire.data() + record::RECORD_HEADER, grain, sizeof(grain));
	// Выполняем подачу записи прикладных данных клиенту
	client.push(view_t(wire.data(), wire.size()));
	/**
	 * Раздел 5.1 RFC 8446: прикладные данные идут лишь по установлении связи, а
	 * упреждающими они здесь быть не могут - их шлёт клиент, а не сервер
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона записи с неподдержанным видом содержимого
 */
TEST(ContextTest, Nondescript){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	/**
	 * Заголовок набивается здесь вручную: свой составитель записей вид содержимого
	 * сличает и неподдержанного не пропускает, а заслон проверяется приёмный
	 */
	const vector <uint8_t> wire = {0xFF, 0x03, 0x03, 0x00, 0x01, 0x00};
	// Выполняем подачу записи неподдержанного вида клиенту
	client.push(view_t(wire.data(), wire.size()));
	/**
	 * Раздел 5.1 RFC 8446 велит обрывать связь на записи с видом содержимого,
	 * связью не признаваемым
	 */
	ASSERT_EQ(client.error(), context::error_t::RECORD);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона смены ключевого материала до установления связи
 */
TEST(ContextTest, Renewal){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Накопитель, в который складывается подаваемая запись связи
	vector <uint8_t> wire;
	// Выполняем составление подаваемой записи связи
	ASSERT_TRUE(sole(handshake::type_t::UPDATE, view_t(reinterpret_cast <const uint8_t *> ("\x00"), 1), wire));
	// Выполняем подачу составленной записи связи
	client.push(view_t(wire.data(), wire.size()));
	/**
	 * Раздел 4.6.3 RFC 8446: смена ключевого материала идёт лишь по установлении
	 * связи, ибо менять ей до того нечего
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона выдачи билета возобновления до установления связи
 */
TEST(ContextTest, Granted){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Накопитель, в который складывается подаваемая запись связи
	vector <uint8_t> wire;
	// Выполняем составление подаваемой записи связи
	ASSERT_TRUE(sole(handshake::type_t::TICKET, view_t(nullptr, 0), wire));
	// Выполняем подачу составленной записи связи
	client.push(view_t(wire.data(), wire.size()));
	/**
	 * Раздел 4.6.1 RFC 8446: билет возобновления выдаётся лишь по установлении
	 * связи, ибо выводится он из её же ключевого материала
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона защищённых расширений, пришедших серверу
 */
TEST(ContextTest, Misdirected){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Накопитель, в который складывается подаваемая запись связи
	vector <uint8_t> wire;
	// Выполняем составление подаваемой записи связи
	ASSERT_TRUE(sole(handshake::type_t::EXTENSIONS, view_t(nullptr, 0), wire));
	// Выполняем подачу составленной записи связи
	server.push(view_t(wire.data(), wire.size()));
	/**
	 * Защищённые расширения шлёт сервер, и приход их серверу же означает либо
	 * оплошность собеседника, либо подделку
	 */
	ASSERT_EQ(server.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана
	ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона конца упреждающих данных, пришедшего клиенту
 */
TEST(ContextTest, Reversed){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Накопитель, в который складывается подаваемая запись связи
	vector <uint8_t> wire;
	// Выполняем составление подаваемой записи связи
	ASSERT_TRUE(sole(handshake::type_t::EARLY, view_t(nullptr, 0), wire));
	// Выполняем подачу составленной записи связи
	client.push(view_t(wire.data(), wire.size()));
	/**
	 * Конец упреждающих данных шлёт клиент, и приход его клиенту же означает либо
	 * оплошность собеседника, либо подделку
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона сообщения рукопожатия неведомого вида
 */
TEST(ContextTest, Unheard){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	/**
	 * Запись набивается здесь вручную: свой составитель вид сообщения рукопожатия
	 * сличает и неведомого не строит, а заслон проверяется приёмный. Первые пять
	 * байтов - заголовок записи, за ними вид сообщения и нулевая его длина
	 */
	const vector <uint8_t> wire = {0x16, 0x03, 0x03, 0x00, 0x04, 0xEE, 0x00, 0x00, 0x00};
	// Выполняем подачу составленной записи связи
	client.push(view_t(wire.data(), wire.size()));
	/**
	 * Раздел 4 RFC 8446: сообщение рукопожатия неведомого вида разбору не подлежит,
	 * и связь на нём обрывается
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона просьбы о пересогласовании HelloRequest изданием 1.3: вид ноль изданию
 * 1.3 неведом (раздел 4 RFC 8446), и клиент «только 1.3» до приветствия сервера, как и
 * сервер до приветствия клиента, обрывают связь извещением unexpected_message
 */
TEST(ContextTest, Unsolicited){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Запись просьбы о пересогласовании
	vector <uint8_t> wire;
	// Составляем открытую запись просьбы с пустым телом
	ASSERT_TRUE(sole(handshake::type_t::HELLO_REQUEST, view_t(nullptr, 0), wire));
	{
		// Связь стороны клиента
		client::context_t client;
		// Клиент ведёт лишь издание 1.3
		ASSERT_EQ(client.versions(0x0304, 0x0304), context::error_t::NONE);
		// Выполняем заведение связи стороны клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Выполняем подачу просьбы клиенту
		ASSERT_EQ(client.push(view_t(wire.data(), wire.size())), context::error_t::ORDER);
		// Проверяем извещение, которым связь оборвана
		ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
		// Проверяем неустановленность связи
		ASSERT_FALSE(client.established());
	}
	{
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Выполняем подачу просьбы серверу: просьбу шлёт лишь сервер
		ASSERT_EQ(server.push(view_t(wire.data(), wire.size())), context::error_t::ORDER);
		// Проверяем извещение, которым связь оборвана
		ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
		// Проверяем неустановленность связи
		ASSERT_FALSE(server.established());
	}
}

/**
 * Проверка заслона приветствия сервера без издания протокола
 */
TEST(ContextTest, Speechless){
	// Связь стороны клиента
	client::context_t client;
	/**
	 * Клиент ведёт лишь издание 1.3: с умолчанием 1.2…1.3 приветствие сервера без
	 * расширения издания законно вело бы связь изданием 1.2 (приложение D.1 RFC 8446)
	 */
	ASSERT_EQ(client.versions(0x0304, 0x0304), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::SPEECHLESS));
	/**
	 * Раздел 4.2.1 RFC 8446 велит серверу объявлять выбранное издание протокола
	 * расширением приветствия: без него связь издания не знает вовсе
	 */
	ASSERT_EQ(client.error(), context::error_t::VERSION);
	/**
	 * Приветствие без расширения издания означает выбор издания, объявленного
	 * заголовком, - то есть TLS 1.2 либо более раннего. Приложение D.1 RFC 8446 велит
	 * обрывать связь по неподдерживаемому изданию извещением protocol_version, а не
	 * missing_extension: последнее раздел 9.2 держит для СЕРВЕРА, принявшего негодное
	 * приветствие клиента
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::VERSION);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона понижения издания протокола сервером
 */
TEST(ContextTest, Regressed){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::REGRESSED));
	/**
	 * Раздел 4.2.1 RFC 8446: связь ведётся единственным изданием, и объявление
	 * издания предыдущего есть попытка увести стороны ниже
	 */
	ASSERT_EQ(client.error(), context::error_t::VERSION);
	/**
	 * Раздел 4.2.1 RFC 8446 велит обрывать связь извещением illegal_parameter, если
	 * расширение издания несёт издание, клиентом не предложенное либо предшествующее
	 * TLS 1.3. Извещение это ИНОЕ, нежели при вовсе отсутствующем расширении: там
	 * сервер издания не объявлял и остался при заголовке, а тут объявил негодное
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона приветствия сервера без открытой части ключа обмена
 */
TEST(ContextTest, Keyless){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::KEYLESS));
	/**
	 * Раздел 4.2.8 RFC 8446: при обмене мимолётными ключами сервер обязан объявить
	 * свою открытую часть, и без неё общего значения вывести не из чего
	 */
	ASSERT_EQ(client.error(), context::error_t::EXCHANGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::MISSING);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона кривой обмена, о которой сервера не просили
 */
TEST(ContextTest, Swapped){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::SWAPPED));
	/**
	 * Раздел 4.2.8 RFC 8446: доля сервера обязана идти по той же кривой, по какой
	 * шла доля клиента, им же выбранная
	 */
	ASSERT_EQ(client.error(), context::error_t::GROUP);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона приветствия клиента, не объявившего схем подписи
 */
TEST(ContextTest, Wordless){
	// Подлинность сторон связи
	context::credential_t credentials;
	// Выполняем выработку подлинности сторон связи
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::WORDLESS, &credentials);
	/**
	 * Раздел 9.2 RFC 8446: без схем подписи сервер подписать владение ключом не вправе
	 * ничем. Отсутствие схем и возобновление ключом сверяются РАЗНЫМИ половинами
	 * заслона: возобновление сертификата не требует, и там расширение это не нужно
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::MISSING);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона выбора сервером ключа, клиентом не предложенного
 */
TEST(ContextTest, Presumed){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::PRESUMED));
	/**
	 * Раздел 4.2.11 RFC 8446: сервер вправе выбрать лишь тот заранее разделённый
	 * ключ, какой клиент ему предложил, и место выбора обязано лежать в предложении
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона выбора ключа у клиента, его не предлагавшего
 */
TEST(ContextTest, Unoffered){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::UNOFFERED));
	/**
	 * Место выбранного ключа и наличие самого предложения сверяются РАЗНЫМИ половинами
	 * заслона: выбор ПЕРВОГО ключа у клиента, не предлагавшего ни одного, годен местом
	 * и негоден отсутствием предложения
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона служебного сообщения переписки, пришедшего проводом
 */
TEST(ContextTest, Synthetic){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Накопитель, в который складывается подаваемая запись связи
	vector <uint8_t> wire;
	// Выполняем составление подаваемой записи связи
	ASSERT_TRUE(sole(handshake::type_t::DIGEST, view_t(nullptr, 0), wire));
	// Выполняем подачу составленной записи связи
	client.push(view_t(wire.data(), wire.size()));
	/**
	 * Раздел 4.4.1 RFC 8446: сообщение это связь складывает себе сама, заменяя им
	 * приветствие клиента в переписке за просьбой о повторе. Проводом оно не ходит
	 * вовсе, и приход его означает либо оплошность собеседника, либо подделку
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона предложения ключа без способов обмена им
 */
TEST(ContextTest, Modeless){
	// Подлинность сторон связи
	context::credential_t credentials;
	// Выполняем выработку подлинности сторон связи
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Билеты, признаваемые сервером возобновляемой связи
	vector <context::ticket_t> issued;
	// Билет, принятый клиентом прошлой связи
	context::ticket_t accepted;
	// Выполняем проведение связи, выдающей билет возобновления
	ASSERT_TRUE(granted(credentials, issued, accepted));
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем билеты, признаваемые сервером
	server.resume(issued);
	// Устанавливаем набор шифрования, признаваемый сервером
	server.suites({protect::suite_t::MAGMA_MGM_L});
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::MODELESS, &credentials);
	/**
	 * Раздел 4.2.9 RFC 8446 велит клиенту, предлагающему заранее разделённый ключ,
	 * объявлять и способы обмена им: без них сервер выбора связи не знает
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::MISSING);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона негодных способов обмена заранее разделённым ключом
 */
TEST(ContextTest, Garbled){
	// Подлинность сторон связи
	context::credential_t credentials;
	// Выполняем выработку подлинности сторон связи
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Билеты, признаваемые сервером возобновляемой связи
	vector <context::ticket_t> issued;
	// Билет, принятый клиентом прошлой связи
	context::ticket_t accepted;
	// Выполняем проведение связи, выдающей билет возобновления
	ASSERT_TRUE(granted(credentials, issued, accepted));
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем билеты, признаваемые сервером
	server.resume(issued);
	// Устанавливаем набор шифрования, признаваемый сервером
	server.suites({protect::suite_t::MAGMA_MGM_L});
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::GARBLED, &credentials);
	/**
	 * Тело расширения способов обмена разбору не поддалось, и молчать о том нельзя:
	 * дальнейший выбор связи опирался бы на неразобранное
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона негодного предложения заранее разделённого ключа
 */
TEST(ContextTest, Spurious){
	// Подлинность сторон связи
	context::credential_t credentials;
	// Выполняем выработку подлинности сторон связи
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Билеты, признаваемые сервером возобновляемой связи
	vector <context::ticket_t> issued;
	// Билет, принятый клиентом прошлой связи
	context::ticket_t accepted;
	// Выполняем проведение связи, выдающей билет возобновления
	ASSERT_TRUE(granted(credentials, issued, accepted));
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем билеты, признаваемые сервером
	server.resume(issued);
	// Устанавливаем набор шифрования, признаваемый сервером
	server.suites({protect::suite_t::MAGMA_MGM_L});
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::SPURIOUS, &credentials);
	/**
	 * Раздел 4.2.11 RFC 8446: предложение несёт опознаватели ключей и привязки к ним,
	 * и неразобранным оно к выбору ключа не годится
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона усечённого извещения собеседника
 */
TEST(ContextTest, Curtailed){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	/**
	 * Извещение кладёт в тело записи два байта - его строгость и его причину.
	 * Запись набивается вручную: единственный байт тела разбору не поддастся
	 */
	const vector <uint8_t> wire = {0x15, 0x03, 0x03, 0x00, 0x01, 0x01};
	// Выполняем подачу усечённого извещения клиенту
	client.push(view_t(wire.data(), wire.size()));
	/**
	 * Раздел 6 RFC 8446 кладёт извещению ровно два байта, и усечённое разбору не
	 * подлежит: молчать о нём нельзя, ибо им собеседник мог бы скрыть обрыв связи
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона негодного тела защищённых расширений сервера
 */
TEST(ContextTest, Mangled){
	// Подлинность сторон связи
	context::credential_t credentials;
	// Выполняем выработку подлинности сторон связи
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым сообщением
	ASSERT_TRUE(adversary(client, distortion_t::MANGLED, &credentials));
	/**
	 * Тело защищённых расширений объявляет длину перечня свыше собственного размера:
	 * разбору оно не поддаётся, и молчать о том нельзя
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
}

/**
 * Проверка заслона негодного тела билета возобновления связи
 */
TEST(ContextTest, Tattered){
	// Подлинность сторон связи
	context::credential_t credentials;
	// Выполняем выработку подлинности сторон связи
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым сообщением
	ASSERT_TRUE(adversary(client, distortion_t::TATTERED, &credentials));
	/**
	 * Раздел 4.6.1 RFC 8446: билет несёт срок, добавку к возрасту, неповторимое
	 * значение и своё тело, и неразобранным к возобновлению он не годится
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
}

/**
 * Проверка заслона негодного тела смены ключевого материала
 */
TEST(ContextTest, Scrambled){
	// Подлинность сторон связи
	context::credential_t credentials;
	// Выполняем выработку подлинности сторон связи
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым сообщением
	ASSERT_TRUE(adversary(client, distortion_t::SCRAMBLED, &credentials));
	/**
	 * Раздел 4.6.3 RFC 8446 кладёт смене ключевого материала тело ровно в один байт,
	 * и пустое тело разбору не поддаётся
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	/**
	 * Раздел 6 RFC 8446: сообщение негодной записи объявляется decode_error, а
	 * illegal_parameter отведён неизвестному значению просьбы (раздел 4.6.3)
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
}

/**
 * Проверка заслона негодного перечня изданий протокола
 */
TEST(ContextTest, Malversion){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::MALVERSION, &credentials);
	/**
	 * Тело расширения объявляет длину перечня свыше собственного размера: разбору
	 * оно не поддаётся, и опираться на неразобранное сервер не вправе
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона негодного перечня открытых частей ключей обмена
 */
TEST(ContextTest, Malshare){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::MALSHARE, &credentials);
	/**
	 * Тело расширения объявляет длину перечня свыше собственного размера: разбору
	 * оно не поддаётся, и опираться на неразобранное сервер не вправе
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона негодного перечня кривых обмена ключами
 */
TEST(ContextTest, Malgroups){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::MALGROUPS, &credentials);
	/**
	 * Тело расширения объявляет длину перечня свыше собственного размера: разбору
	 * оно не поддаётся, и опираться на неразобранное сервер не вправе
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона негодного перечня кривых обмена при неназванных долях
 */
TEST(ContextTest, Malcurves){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::MALCURVES, &credentials);
	/**
	 * Тело расширения объявляет длину перечня свыше собственного размера: разбору
	 * оно не поддаётся, и опираться на неразобранное сервер не вправе
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона негодного имени запрашиваемого узла
 */
TEST(ContextTest, Malname){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::MALNAME, &credentials);
	/**
	 * Тело расширения объявляет длину перечня свыше собственного размера: разбору
	 * оно не поддаётся, и опираться на неразобранное сервер не вправе
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона негодного перечня прикладных протоколов
 */
TEST(ContextTest, Malprotocol){
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
	/**
	 * Прикладные протоколы сервером признаются нарочно: перечень клиента он
	 * разбирает лишь тогда, когда есть с чем его сличать
	 */
	server.protocols({"h2"});
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::MALPROTOCOL, &credentials);
	/**
	 * Тело расширения объявляет длину перечня свыше собственного размера: разбору
	 * оно не поддаётся, и опираться на неразобранное сервер не вправе
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона набора шифрования вне предложения клиента
 */
TEST(ContextTest, Oddset){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::ODDSUITE));
	/**
	 * Раздел 4.1.3 RFC 8446: сервер вправе выбрать лишь тот набор шифрования, какой
	 * клиент ему предложил
	 */
	ASSERT_EQ(client.error(), context::error_t::SUITE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона выбора ключа просьбой о повторе приветствия
 */
TEST(ContextTest, Prepicked){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::PICKEDEARLY));
	/**
	 * Раздел 4.1.4 RFC 8446: просьба о повторе приветствия заранее разделённого ключа
	 * ещё не выбирает, и расширение это в ней не своё
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	/**
	 * Раздел 4.2 RFC 8446 разводит ДВА извещения: расширение, стороне известное, но
	 * пришедшее не в своём сообщении, обрывает связь извещением «illegal_parameter», а
	 * расширение, о котором сторона не просила вовсе, - «unsupported_extension». Здесь
	 * расширение известно и предлагалось, а негодно одним лишь своим местом
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона метки возврата состояния в самом приветствии сервера
 */
TEST(ContextTest, Belated){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::LATECOOKIE));
	/**
	 * Раздел 4.2.2 RFC 8446: метку возврата состояния несёт просьба о повторе, и в
	 * самом приветствии сервера ей места нет
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	/**
	 * Раздел 4.2 RFC 8446 разводит ДВА извещения: расширение, стороне известное, но
	 * пришедшее не в своём сообщении, обрывает связь извещением «illegal_parameter», а
	 * расширение, о котором сторона не просила вовсе, - «unsupported_extension». Здесь
	 * расширение известно и предлагалось, а негодно одним лишь своим местом
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона негодной выбранной кривой в просьбе о повторе
 */
TEST(ContextTest, Malselect){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::MALSELECT));
	/**
	 * Тело расширения выбранной кривой объявляет длину свыше собственного размера:
	 * разбору оно не поддаётся
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона негодного издания протокола в приветствии сервера
 */
TEST(ContextTest, Maledition){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::MALEDITION));
	/**
	 * Тело расширения издания протокола объявляет длину свыше собственного размера:
	 * разбору оно не поддаётся
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона негодного выбора заранее разделённого ключа
 */
TEST(ContextTest, Malchosen){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::MALCHOSEN));
	/**
	 * Тело расширения выбранного ключа объявляет длину свыше собственного размера:
	 * разбору оно не поддаётся
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона негодной открытой части ключа обмена сервера
 */
TEST(ContextTest, Malsharing){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера искажённым приветствием
	ASSERT_TRUE(adversary(client, distortion_t::MALSHARING));
	/**
	 * Тело расширения открытой части ключа объявляет длину свыше собственного
	 * размера: разбору оно не поддаётся
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона неразборчивого приветствия сервера
 */
TEST(ContextTest, Muddled){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	/**
	 * Тело приветствия сервера подаётся негодным целиком: составителем такого не
	 * сложить, и оттого сообщение подаётся отдельно от враждебного сервера
	 */
	const uint8_t grain[3] = {0x03, 0x03, 0xFF};
	// Накопитель, в который складывается подаваемая запись связи
	vector <uint8_t> wire;
	// Выполняем составление подаваемой записи связи
	ASSERT_TRUE(sole(handshake::type_t::SERVER, view_t(grain, sizeof(grain)), wire));
	// Выполняем подачу составленной записи связи
	client.push(view_t(wire.data(), wire.size()));
	/**
	 * Раздел 4.1.3 RFC 8446 кладёт приветствию сервера строгий состав, и обрубок
	 * его разбору не подлежит
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона второго приветствия клиента одною записью
 */
TEST(ContextTest, Twice){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь на втором
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит
	 */
	(void) intruder(server, distortion_t::TWICE, &credentials);
	/**
	 * Раздел 4.1.2 RFC 8446: приветствие клиент шлёт единожды, а повторное - лишь
	 * по просьбе сервера о повторе, каковой здесь не было
	 */
	ASSERT_EQ(server.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона второго приветствия сервера одною записью
 */
TEST(ContextTest, Doubled){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера двойным приветствием
	ASSERT_TRUE(adversary(client, distortion_t::DOUBLED));
	/**
	 * Раздел 4.1.3 RFC 8446: приветствие сервер шлёт единожды, и второе им же
	 * увело бы стороны в разные ключи
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона повторных защищённых расширений сервера
 */
TEST(ContextTest, Twinned){
	// Подлинность сторон связи
	context::credential_t credentials;
	// Выполняем выработку подлинности сторон связи
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера повторными расширениями
	ASSERT_TRUE(adversary(client, distortion_t::TWINNED, &credentials));
	/**
	 * Раздел 4.3.1 RFC 8446 кладёт защищённым расширениям единственное место в
	 * рукопожатии, и второе их появление есть приход сообщения не в свой черёд
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона негодного прикладного протокола в защищённых расширениях
 */
TEST(ContextTest, Malalpn){
	// Связь стороны клиента
	client::context_t client;
	/**
	 * Прикладные протоколы связью предлагаются нарочно: выбор сервера она разбирает
	 * лишь тогда, когда сама протоколы объявляла
	 */
	client.protocols({"h2"});
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера негодным прикладным протоколом
	ASSERT_TRUE(adversary(client, distortion_t::MALALPN));
	/**
	 * Тело расширения прикладного протокола объявляет длину свыше собственного
	 * размера: разбору оно не поддаётся
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона негодного предела упреждающих данных в билете
 */
TEST(ContextTest, Maladvance){
	// Подлинность сторон связи
	context::credential_t credentials;
	// Выполняем выработку подлинности сторон связи
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера билетом с негодным пределом
	ASSERT_TRUE(adversary(client, distortion_t::MALADVANCE, &credentials));
	/**
	 * Раздел 4.6.1 RFC 8446: предел упреждающих данных объявляется расширением
	 * билета, и неразобранным он к упреждению не годится
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
}

/**
 * Проверка просьбы сервера о повторе приветствия
 */
TEST(ContextTest, Unsettled){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_TRUE(intruder(server, distortion_t::UNSETTLED, &credentials));
	/**
	 * Раздел 4.1.4 RFC 8446: общая кривая обмена у сторон есть, а доли по ней клиент
	 * не прислал - сервер просит повтора приветствия. Повторив прежнее, клиент не
	 * оставляет серверу ничего: просить дважды тот не вправе, и связь обрывается
	 */
	ASSERT_EQ(server.error(), context::error_t::GROUP);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона негодной метки возврата состояния в приветствии клиента
 */
TEST(ContextTest, Malcookie){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::MALCOOKIE, &credentials);
	/**
	 * Раздел 4.2.2 RFC 8446: метку сервер складывал сам, но повторённую разобрать
	 * обязан, и неразборчивая означает, что вернулась не она
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона просьбы о повторе за приветствием сервера
 */
TEST(ContextTest, Recurrent){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера приветствием и просьбою о повторе
	ASSERT_TRUE(adversary(client, distortion_t::RECURRENT));
	/**
	 * Раздел 4.1.4 RFC 8446: просьба о повторе идёт вместо приветствия сервера,
	 * а не за ним - приветствием пора обмена ключами уже завершена
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона порченой защиты упреждающих данных
 */
TEST(ContextTest, Spoiled){
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
	const string request = "Упреждающие данные, испорченные по дороге";
	// Выполняем отправку упреждающих данных клиентом
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
	// Получаем байты, отправленные клиентом
	const view_t sending = client.output();
	// Проверяем, что клиенту нашлось что отправить
	ASSERT_GT(sending.size, static_cast <size_t> (record::RECORD_HEADER));
	// Выполняем перенос отправленных клиентом байтов
	vector <uint8_t> wire(sending.data, sending.data + sending.size);
	/**
	 * Первою записью идёт приветствие клиента, а упреждающие данные - за ним: длина
	 * первой записи объявлена двумя байтами её же заголовка
	 */
	const size_t leading = (record::RECORD_HEADER + ((static_cast <size_t> (wire[3]) << 8) | static_cast <size_t> (wire[4])));
	// Проверяем, что за приветствием клиента идёт ещё одна запись
	ASSERT_GT(wire.size(), (leading + record::RECORD_HEADER));
	/**
	 * Портим единственный байт защищённого содержимого упреждающих данных: заслон
	 * снятия защиты обязан на том связь оборвать, а не принять порченое
	 */
	wire[leading + record::RECORD_HEADER] = static_cast <uint8_t> (wire[leading + record::RECORD_HEADER] ^ 0xFF);
	// Выполняем подачу порченых байтов серверу
	server.push(view_t(wire.data(), wire.size()));
	/**
	 * Раздел 5.2 RFC 8446: не снявшаяся защита означает либо подделку, либо порчу
	 * по дороге, и принимать такое содержимое связь не вправе
	 */
	ASSERT_EQ(server.error(), context::error_t::PROTECTION);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::MAC);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона лишнего тела у конца упреждающих данных
 */
TEST(ContextTest, Lingering){
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
	// Связь стороны сервера, признающая выданный билет
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Устанавливаем билеты, признаваемые сервером
	server.resume(issued);
	// Устанавливаем приём упреждающих данных сервером
	server.advance(true);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем возобновление связи враждебным клиентом с упреждающими данными
	ASSERT_TRUE(precursor(server, accepted, distortion_t::LINGERING));
	/**
	 * Раздел 4.5 RFC 8446 кладёт концу упреждающих данных пустое тело: всё, что за
	 * ним идёт, объявляется извещением «decode_error»
	 */
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка билета, выданного позже мига суждения о его сроке
 */
TEST(ContextTest, Backdated){
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
	// Миг выдачи билета возобновления связи
	const int64_t moment = 1800000000;
	// Проставляем мигом выдачи билет, принятый клиентом
	accepted.moment = moment;
	// Проставляем мигом выдачи билет, признаваемый сервером
	issued[0].moment = moment;
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
	 * Миг суждения берётся раньше мига выдачи билета: так выглядит возврат часов
	 * назад, и билет из будущего связи предъявлять нечего
	 */
	client.moment(moment - 3600);
	// Устанавливаем миг, которым сервер судит сроки билетов
	server.moment(moment - 3600);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	/**
	 * Раздел 4.6.1 RFC 8446 велит держать билет не дольше объявленного срока, а
	 * билет из будущего сроку не поддаётся вовсе: связь идёт полным рукопожатием
	 */
	ASSERT_FALSE(client.shared());
	// Проверяем, что и сервер связи билетом не возобновлял
	ASSERT_FALSE(server.shared());
}

/**
 * Проверка отказа упреждающих данных при разошедшемся возрасте билета
 */
TEST(ContextTest, Misaged){
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
	// Миг выдачи билета возобновления связи
	const int64_t moment = 1800000000;
	// Проставляем мигом выдачи билет, принятый клиентом
	accepted.moment = moment;
	// Проставляем мигом выдачи билет, признаваемый сервером
	issued[0].moment = moment;
	/**
	 * Заходов два: первым возраст билета объявляется верно, вторым - разошедшимся.
	 * Без первого захода отказ приёма был бы неотличим от отказа по иной причине
	 */
	for(size_t item = 0; item < 2; item++){
		// Связь стороны сервера, признающая выданный билет
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Устанавливаем билеты, признаваемые сервером
		server.resume(issued);
		// Устанавливаем приём упреждающих данных сервером
		server.advance(true);
		// Устанавливаем миг, которым сервер судит сроки билетов
		server.moment(moment);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE) << "заход " << item;
		// Выполняем возобновление связи враждебным клиентом
		ASSERT_TRUE(precursor(server, accepted, ((item == 0) ? distortion_t::MISAGED : distortion_t::NONE))) << "заход " << item;
		// Проверяем, что связь обоих заходов осталась цела
		ASSERT_EQ(server.error(), context::error_t::NONE) << "заход " << item;
		// Проверяем, что связь билетом возобновлена в обоих заходах
		ASSERT_TRUE(server.shared()) << "заход " << item;
		// Накопитель, в который помещаются принятые упреждающие данные
		vector <uint8_t> received;
		// Выполняем получение принятых сервером упреждающих данных
		(void) server.read(received);
		/**
		 * Раздел 4.2.10 RFC 8446 велит отвергать упреждающие данные при расхождении
		 * объявленного возраста билета с наблюдаемым: расхождение это выдаёт повторную
		 * подачу тех же данных. Самому возобновлению связи оно не мешает
		 */
		ASSERT_EQ(server.accepted(), (item != 0)) << "заход " << item;
		/**
		 * Прочитанное сличается сверх объявленного приёма: отвергнутые записи сервер
		 * пропускает молча, и объявление о приёме обязано сходиться с тем, дошли ли
		 * сами данные
		 */
		ASSERT_EQ(received.empty(), (item == 0)) << "заход " << item;
	}
}

/**
 * Проверка заслона схемы подписи, собеседником не признаваемой
 */
TEST(ContextTest, Discord){
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
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит вовсе
	 */
	(void) intruder(server, distortion_t::DISCORD, &credentials);
	/**
	 * Раздел 4.4.3 RFC 8446: подписывать владение ключом дозволено лишь схемой, какую
	 * собеседник объявил признаваемой, а схемы длинной кривой сертификату на короткой
	 * не отвечают ничем
	 */
	ASSERT_EQ(server.error(), context::error_t::SCHEME);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка заслона расширения, защищённым расширениям не положенного
 */
TEST(ContextTest, Misplaced){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера расширением не в своём месте
	ASSERT_TRUE(adversary(client, distortion_t::MISPLACED));
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	/**
	 * Раздел 4.2 RFC 8446 отводит всякому расширению свой перечень сообщений, и способы
	 * обмена заранее разделённым ключом положены одному лишь приветствию клиента.
	 * Заслон этот сверкой с предложенным НЕ покрывается: связь способы эти предлагает
	 * всякий раз, и негодны они одним своим местом
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона расширения, билету возобновления связи не положенного
 */
TEST(ContextTest, Outplaced){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем рукопожатие враждебного сервера с билетом не в своём расширении
	ASSERT_TRUE(adversary(client, distortion_t::OUTPLACED, &credentials));
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	/**
	 * Раздел 4.2 RFC 8446 кладёт билету возобновления связи одно-единственное
	 * расширение - предел упреждающих данных, - и открытая часть ключа обмена билету
	 * не положена
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
}

/**
 * Проверка заслона расширения, запросу подлинности не положенного
 */
TEST(ContextTest, Offplaced){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера запросом не в своём расширении
	ASSERT_TRUE(adversary(client, distortion_t::OFFPLACED, &credentials));
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.error(), context::error_t::EXTENSION);
	/**
	 * Раздел 4.2 RFC 8446 кладёт запросу подлинности из признаваемых движком
	 * расширений одни лишь схемы подписи. Схемы подписи запрос несёт годными, оттого
	 * задет именно заслон места, а не заслон их отсутствия
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
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
	ASSERT_EQ(client.error(), context::error_t::EXTENSION);
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
		/**
		 * Извещение расходится: негодная цепочка объявляется «bad_certificate», а
		 * пустая цепочка сервера по разделу 4.4.2.4 - «decode_error»
		 */
		ASSERT_EQ(client.alert().description, ((item == 0) ? alert::description_t::BADCERT : alert::description_t::DECODE)) << "искажение " << item;
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
	 * Составляем запись смены набора шифрования не той длины
	 */
	{
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Содержимое записи смены набора шифрования длиною в два байта
		const uint8_t content[2] = {0x01, 0x01};
		// Объект нарезчика отправляемых записей
		record::writer_t writer;
		// Выполняем нарезку записи смены набора шифрования
		ASSERT_EQ(writer.push(record::type_t::CHANGE, record::version_t::TLS12, view_t(content, sizeof(content))), record::error_t::NONE);
		// Выполняем подачу записи смены набора шифрования серверу
		server.push(writer.data());
		/**
		 * Раздел 5 RFC 8446 отводит записи смены набора ровно один байт содержимого.
		 * Длина её сверяется ОТДЕЛЬНОЙ половиной заслона от значения: запись из двух
		 * дозволенных байтов негодна одной лишь своей длиной
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
	/**
	 * Подаём годную запись смены набора шифрования по ходу рукопожатия
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
		// Получаем приветствие, отправляемое клиентом серверу
		const view_t greeting = client.output();
		// Выполняем перенос отправляемого клиентом приветствия
		const vector <uint8_t> message(greeting.data, greeting.data + greeting.size);
		// Снимаем отправленное приветствие с накопителя клиента
		client.consume(message.size());
		// Выполняем подачу приветствия клиента серверу
		ASSERT_EQ(server.push(view_t(message.data(), message.size())), context::error_t::NONE);
		// Содержимое годной записи смены набора шифрования
		const uint8_t content[1] = {0x01};
		// Объект нарезчика отправляемых записей
		record::writer_t writer;
		// Выполняем нарезку годной записи смены набора шифрования
		ASSERT_EQ(writer.push(record::type_t::CHANGE, record::version_t::TLS12, view_t(content, sizeof(content))), record::error_t::NONE);
		/**
		 * Раздел 5 RFC 8446 велит ПРОПУСКАТЬ эту запись по ходу рукопожатия: она
		 * досталась от промежуточных узлов, привыкших к предыдущим изданиям протокола,
		 * и связь обрывать ею нельзя
		 */
		ASSERT_EQ(server.push(writer.data()), context::error_t::NONE);
		// Проверяем, что связь пропущенной записью не оборвана
		ASSERT_NE(server.state(), context::state_t::FAILED);
		// Проверяем, что отказа пропущенная запись не дала
		ASSERT_EQ(server.error(), context::error_t::NONE);
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
 * Проверка заслона способа сжатия, объявленного приветствием сервера
 */
TEST(ContextTest, Compression){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем рукопожатие враждебного сервера, объявившего способ сжатия
	ASSERT_TRUE(adversary(client, distortion_t::METHOD));
	/**
	 * Раздел 4.1.3 RFC 8446: способ сжатия достался изданию 1.3 от предыдущих и
	 * назначения не имеет, оттого серверу и велено слать нуль
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона смены набора шифрования за просьбой о повторе приветствия
 */
TEST(ContextTest, Kept){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем просьбу враждебного сервера о повторе приветствия
	ASSERT_TRUE(adversary(client, distortion_t::PROPOSAL));
	// Проверяем, что связь просьбу о повторе приняла
	ASSERT_EQ(client.error(), context::error_t::NONE);
	// Проверяем отправку повторного приветствия клиентом
	ASSERT_GT(client.output().size, static_cast <size_t> (0));
	// Выполняем ответ враждебного сервера с иным набором шифрования
	ASSERT_TRUE(adversary(client, distortion_t::PROPOSED));
	/**
	 * Раздел 4.1.4 RFC 8446: набор шифрования между просьбой о повторе и самим
	 * приветствием сервер менять не вправе, ибо переписка рукопожатия хешируется им
	 */
	ASSERT_EQ(client.error(), context::error_t::SUITE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * Проверка заслона повторной просьбы о повторе приветствия
 */
TEST(ContextTest, Insistent){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем первую просьбу враждебного сервера о повторе приветствия
	ASSERT_TRUE(adversary(client, distortion_t::PROPOSAL));
	// Проверяем, что связь первую просьбу о повторе приняла
	ASSERT_EQ(client.error(), context::error_t::NONE);
	// Проверяем отправку повторного приветствия клиентом
	ASSERT_GT(client.output().size, static_cast <size_t> (0));
	// Выполняем вторую просьбу враждебного сервера о повторе приветствия
	ASSERT_TRUE(adversary(client, distortion_t::REPEATED));
	/**
	 * Раздел 4.1.4 RFC 8446: просьба о повторе приветствия дозволена за связь лишь
	 * однажды, и второй такой просьбой сервер загнал бы связь в бесконечный круг
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
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
	/**
	 * Раздел 4.2 RFC 8446 разводит ДВА извещения: расширение, стороне известное, но
	 * пришедшее не в своём сообщении, обрывает связь извещением «illegal_parameter», а
	 * расширение, о котором сторона не просила вовсе, - «unsupported_extension». Здесь
	 * расширение известно и предлагалось, а негодно одним лишь своим местом
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
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

/**
 * Проверка отказов связи на нехватку настроек и негодное состояние
 */
TEST(ContextTest, Unprovisioned){
	// Связь стороны клиента
	client::context_t client;
	/**
	 * Пустой список установщики пропускают, сохраняя умолчания: опустошить наборы
	 * шифрования либо кривых обмена ключами через общедоступный договор нельзя, и
	 * заслон нехватки этих настроек оттого проверке не поддаётся
	 */
	client.groups({});
	// Проверяем сохранность умолчаний после подачи пустого списка кривых
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Связь стороны сервера
	server::context_t server;
	/**
	 * Сервер обязан иметь чем себя удостоверить: цепочка сертификатов и секретный ключ
	 * к ней сверяются ОТДЕЛЬНЫМИ половинами заслона, и подлинность с одной лишь
	 * цепочкой трогает ту половину, что стережёт ключ
	 */
	ASSERT_EQ(server.start(), context::error_t::SETTINGS);
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Подлинность, у которой оставлена одна лишь цепочка сертификатов
	context::credential_t keyless;
	// Переносим цепочку сертификатов в подлинность без секретного ключа
	keyless.chain = credentials.chain;
	// Устанавливаем подлинность без секретного ключа
	server.credential(keyless);
	// Проверяем отказ заведения связи сервера без секретного ключа
	ASSERT_EQ(server.start(), context::error_t::SETTINGS);
	// Подлинность, у которой оставлен один лишь секретный ключ
	context::credential_t chainless;
	// Переносим секретный ключ в подлинность без цепочки сертификатов
	chainless.secret = credentials.secret;
	// Устанавливаем подлинность без цепочки сертификатов
	server.credential(chainless);
	// Проверяем отказ заведения связи сервера без цепочки сертификатов
	ASSERT_EQ(server.start(), context::error_t::SETTINGS);
	// Устанавливаем полную подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Проверяем отказ повторного заведения уже заведённой связи
	ASSERT_EQ(server.start(), context::error_t::STATE);
}

/**
 * Проверка отправки и закрытия связи вне положенного состояния
 */
TEST(ContextTest, Premature){
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
	// Отправляемые прикладные данные связи
	const uint8_t payload[] = {0x41, 0x4E, 0x54, 0x53};
	// Проверяем отказ отправки прикладных данных до заведения связи
	ASSERT_EQ(client.write(view_t(payload, sizeof(payload))), context::error_t::STATE);
	/**
	 * Незаведённая связь принимать байты не вправе: незаведённость и оборванность
	 * сверяются РАЗНЫМИ половинами заслона, и всякая отвергает подачу в одиночку
	 */
	ASSERT_EQ(client.push(view_t(payload, sizeof(payload))), context::error_t::STATE);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Проверяем отказ отправки прикладных данных до окончания рукопожатия
	ASSERT_EQ(client.write(view_t(payload, sizeof(payload))), context::error_t::STATE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи стороной клиента
	ASSERT_TRUE(client.established());
	/**
	 * Непереданные прикладные данные отправлять нечего, и отказом это не считается:
	 * связь исправна, отправка пуста
	 */
	ASSERT_EQ(client.write(view_t(nullptr, sizeof(payload))), context::error_t::NONE);
	// Проверяем успешность отправки прикладных данных нулевой длины
	ASSERT_EQ(client.write(view_t(payload, 0)), context::error_t::NONE);
	// Выполняем закрытие связи стороны клиента
	ASSERT_EQ(client.close(), context::error_t::NONE);
	// Проверяем отказ повторного закрытия уже закрытой связи
	ASSERT_EQ(client.close(), context::error_t::CLOSED);
	// Проверяем отказ отправки прикладных данных по закрытой связи
	ASSERT_EQ(client.write(view_t(payload, sizeof(payload))), context::error_t::STATE);
}

/**
 * Проверка возобновления связи билетом без метки времени выдачи
 */
TEST(ContextTest, Timeless){
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
	/**
	 * Метка времени выдачи билета необязательна: потребитель фреймворка волен
	 * хранить билеты без неё, и тогда судить о сроке билета не по чему. Раздел
	 * 4.6.1 RFC 8446 срок этот стороне выдачи и вручает, а без метки обе стороны
	 * обязаны билет принимать, не оценивая возраста
	 */
	accepted.moment = 0;
	// Выполняем обнуление метки времени выдачи билетов стороны сервера
	for(auto & ticket : issued)
		// Обнуляем метку времени выдачи очередного билета
		ticket.moment = 0;
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
	 * Миг суждения о сроках сторонам задан, а вот метки выдачи у билетов нет:
	 * заслон срока сверяет ОБА мига по отдельности, и обнулённая метка выдачи
	 * трогает вторую его половину
	 */
	client.moment(1800000000);
	// Устанавливаем миг суждения о сроках стороне сервера
	server.moment(1800000000);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем возобновление связи заранее разделённым ключом
	ASSERT_TRUE(client.shared() && server.shared());
}

/**
 * @brief Проверка обрыва связи по защищённой записи с пустым содержимым
 *
 */
TEST(ContextTest, Hollow){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера защищённой записью с пустым содержимым
	/**
	 * Враждебный сервер подтверждает себя сертификатом: завершение без сертификата
	 * клиент отвергает раньше, чем дело дошло бы до подделанной записи
	 */
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	ASSERT_TRUE(adversary(client, distortion_t::VACANT, &credentials));
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.error(), context::error_t::RECORD);
	/**
	 * Раздел 5.4 RFC 8446 велит рвать связь извещением unexpected_message по записи
	 * рукопожатия либо извещения с пустым содержимым. Заслон этот стережёт ИМЕННО
	 * защищённый путь: у незащищённой записи пустоту отвергает разбор заголовка, а у
	 * защищённой длину заголовка составляют шифртекст с меткой целостности, и пустота
	 * вскрывается лишь по снятии защиты
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * @brief Проверка заслона издания протокола у просьбы о повторе приветствия
 *
 */
TEST(ContextTest, Retrograde){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем просьбу враждебного сервера о повторе с изданием ниже TLS 1.3
	ASSERT_TRUE(adversary(client, distortion_t::RETROGRADE));
	/**
	 * Раздел 9.2 RFC 8446 требует расширения издания и от просьбы о повторе, а раздел
	 * 4.2.1 велит сверять его ПРЕЖДЕ разбора всего прочего. Стой сверка ниже
	 * разветвления на приветствие и просьбу - просьбу она не задевала бы вовсе, и
	 * связь пошла бы по ней на новый круг, издания так и не сверив
	 */
	ASSERT_EQ(client.error(), context::error_t::VERSION);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * @brief Проверка заслона непомерной длины подписи владения ключом
 *
 */
TEST(ContextTest, Lengthy){
	// Подлинность враждебного сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности враждебного сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера подписью непомерной длины
	ASSERT_TRUE(adversary(client, distortion_t::LENGTHY, &credentials));
	/**
	 * Длина подписи приходит с той стороны связи и пределом сообщения ограничена лишь
	 * сверху: без заслона разворот записи подписи вынес бы её за место, отведённое
	 * подписи на стеке
	 */
	ASSERT_EQ(client.error(), context::error_t::SIGNATURE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::DECRYPT);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * @brief Проверка заслона испорченной подписи владения ключом
 *
 */
TEST(ContextTest, Malsigned){
	// Подлинность враждебного сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности враждебного сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера испорченной подписью владения ключом
	ASSERT_TRUE(adversary(client, distortion_t::MALSIGN, &credentials));
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.error(), context::error_t::SIGNATURE);
	/**
	 * Раздел 4.4.3 RFC 8446 велит рвать связь извещением decrypt_error, если подпись
	 * владения ключом не сошлась. Схема и длина подписи здесь годны нарочно: заслоны
	 * их стоят прежде, и негодными ими проверялся бы не тот заслон
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::DECRYPT);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * @brief Проверка заслона испорченного завершения рукопожатия
 *
 */
TEST(ContextTest, Malfinished){
	// Подлинность враждебного сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности враждебного сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера испорченным завершением рукопожатия
	ASSERT_TRUE(adversary(client, distortion_t::MALFINISH, &credentials));
	// Проверяем обрыв связи стороной клиента
	ASSERT_EQ(client.error(), context::error_t::COMPLETION);
	/**
	 * Раздел 4.4.4 RFC 8446 велит рвать связь извещением decrypt_error, если
	 * завершение рукопожатия собеседника не сошлось
	 */
	ASSERT_EQ(client.alert().description, alert::description_t::DECRYPT);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * @brief Проверка заслона места предложения заранее разделённого ключа
 *
 */
TEST(ContextTest, Misordered){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	/**
	 * Итог враждебного клиента здесь не сличается: сервер обрывает связь ещё на
	 * приветствии, и до ответа, которого клиент ждёт, дело не доходит
	 */
	(void) intruder(server, distortion_t::MISORDER, &credentials);
	// Проверяем обрыв связи стороной сервера
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	/**
	 * Раздел 4.2.11 RFC 8446 велит предложению заранее разделённого ключа идти
	 * последним расширением приветствия, ибо привязка его считается по переписке,
	 * усечённой ровно до начала этого расширения. Сервер обязан сверять место
	 * предложения и отвечать извещением illegal_parameter
	 */
	ASSERT_EQ(server.alert().description, alert::description_t::PARAMETER);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * @brief Проверка заслона доли обмена, кривой не принадлежащей, у клиента
 *
 */
TEST(ContextTest, Offcurve){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера долей обмена вне кривой
	ASSERT_TRUE(adversary(client, distortion_t::OFFCURVE));
	/**
	 * Точка, кривой не принадлежащая, отвергается выработкой общего значения: без
	 * этого сличения подставная точка малого порядка выдала бы секретный ключ своей
	 * стороны. Длина доли и кривая здесь годны нарочно - негодное тело доли
	 * отвергается много раньше, разбором расширения
	 */
	ASSERT_EQ(client.error(), context::error_t::EXCHANGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::HANDSHAKE);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * @brief Проверка заслона доли обмена, кривой не принадлежащей, у сервера
 *
 */
TEST(ContextTest, Offpoint){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем приветствие враждебного клиента долей обмена вне кривой
	(void) intruder(server, distortion_t::OFFPOINT, &credentials);
	// Проверяем обрыв связи стороной сервера
	ASSERT_EQ(server.error(), context::error_t::EXCHANGE);
	// Проверяем извещение, которым связь оборвана сервером
	ASSERT_EQ(server.alert().description, alert::description_t::HANDSHAKE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * @brief Проверка заслона сообщения поддельного вида посреди рукопожатия
 *
 */
TEST(ContextTest, Synthesized){
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем ответ враждебного сервера сообщением поддельного вида
	ASSERT_TRUE(adversary(client, distortion_t::SYNTHETIC));
	/**
	 * Вид message_hash заведён разделом 4.4.1 RFC 8446 для ПОДМЕНЫ первого приветствия
	 * в переписке рукопожатия и по связи идти не вправе вовсе, хотя сборщик сообщений
	 * его и признаёт.
	 *
	 * Проверка эта отлична от ContextTest.Synthetic: та подаёт такое сообщение ПЕРВЫМ,
	 * и его отвергает ход рукопожатия, а здесь оно идёт за приветствием сервера и
	 * доходит до разбора принятого, где его встречает уже иной заслон
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем неустановленность связи стороной клиента
	ASSERT_FALSE(client.established());
}

/**
 * @brief Проверка заслона негодных схем подписи приветствия клиента
 *
 */
TEST(ContextTest, Malschemes){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны сервера
	server::context_t server;
	// Устанавливаем подлинность стороны сервера
	server.credential(credentials);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем приветствие враждебного клиента с негодными схемами подписи
	(void) intruder(server, distortion_t::MALSCHEMES, &credentials);
	// Проверяем обрыв связи стороной сервера
	ASSERT_EQ(server.error(), context::error_t::MESSAGE);
	/**
	 * Расширение объявлено, а телу его разбор не поддаётся: заслон этот отличен от
	 * заслона вовсе не объявленных схем, отвечающего иным извещением
	 */
	ASSERT_EQ(server.alert().description, alert::description_t::DECODE);
	// Проверяем неустановленность связи стороной сервера
	ASSERT_FALSE(server.established());
}

/**
 * Проверка отказа клиента на запрос подлинности с перечнем расширений, оборванным на виде
 */
TEST(ContextTest, Malrequest){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	client::context_t client;
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::MALREQUEST, &credentials));
	// Раздел 4.3.2 RFC 8446: вид расширения объявлен двумя байтами, обрыв на нём - негодное тело
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
	ASSERT_FALSE(client.established());
}

/**
 * Проверка отказа клиента на запрос подлинности с лишним байтом за телом
 */
TEST(ContextTest, Overrequest){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	client::context_t client;
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::OVERREQUEST, &credentials));
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
	ASSERT_FALSE(client.established());
}

/**
 * Проверка отказа клиента на запрос подлинности с негодным перечнем схем подписи
 */
TEST(ContextTest, Malreqschemes){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	client::context_t client;
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::MALREQSCHEMES, &credentials));
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
	ASSERT_FALSE(client.established());
}

/**
 * Проверка отказа клиента на цепочку сертификатов с негодным телом
 */
TEST(ContextTest, Malchain){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	client::context_t client;
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::MALCHAIN, &credentials));
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Раздел 6.2 RFC 8446: негодная цепочка сертификатов извещается как bad_certificate
	ASSERT_EQ(client.alert().description, alert::description_t::BADCERT);
	ASSERT_FALSE(client.established());
}

/**
 * Проверка отказа клиента на подпись владения ключом с негодным телом
 */
TEST(ContextTest, Malverify){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	client::context_t client;
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::MALVERIFY, &credentials));
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Раздел 4.4.3 RFC 8446: негодная подпись владения ключом извещается как decrypt_error
	ASSERT_EQ(client.alert().description, alert::description_t::DECRYPT);
	ASSERT_FALSE(client.established());
}

/**
 * Проверка отказа клиента на запись цепочки, сертификатом не являющуюся
 */
TEST(ContextTest, Garbageleaf){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	client::context_t client;
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::GARBAGELEAF, &credentials));
	ASSERT_EQ(client.error(), context::error_t::CERTIFICATE);
	ASSERT_FALSE(client.established());
}

/**
 * Проверка отказа клиента на подпись владения ключом нечётной длины
 */
TEST(ContextTest, Oddsign){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	client::context_t client;
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::ODDSIGN, &credentials));
	// Раздел 2 RFC 9215: подпись - два числа равной длины, нечётная длина на два не делится
	ASSERT_EQ(client.error(), context::error_t::SIGNATURE);
	ASSERT_FALSE(client.established());
}

/**
 * Проверка отказа клиента на защищённую запись с содержимым неведомого вида
 */
TEST(ContextTest, Alientype){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	client::context_t client;
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::ALIENTYPE, &credentials));
	/**
	 * Раздел 5.2 RFC 8446: истинный вид содержимого обязан быть одним из известных.
	 * Отвергает его снятие защиты записи, ещё до движка: заслон движка на тот же
	 * случай стоит за ним в тени и своего опыта не получает
	 */
	ASSERT_EQ(client.error(), context::error_t::PROTECTION);
	ASSERT_FALSE(client.established());
}

/**
 * Проверка отказов на злоупотребление API: пустые настройки и смена ключа не в свой черёд
 */
TEST(ContextTest, Misused){
	/**
	 * Пустые перечни наборов и кривых фасадом не принимаются вовсе - сеттеры движка
	 * пустой перечень пропускают, оставляя умолчание, - оттого заслон пустых настроек
	 * через фасад недостижим и здесь не проверяется
	 */
	// Смена ключевого материала до установления связи - нарушение порядка: раздел 4.6.3 RFC 8446
	client::context_t hasty;
	ASSERT_EQ(hasty.start(), context::error_t::NONE);
	/**
	 * Отказ приходит состоянием, а не порядком: движок сверяет состояние связи прежде
	 * машины сообщений, и заслон порядка на тот же случай стоит за ним в тени
	 */
	ASSERT_EQ(hasty.update(), context::error_t::STATE);
}

/**
 * Проверка принятия приветствия с неведомым серверу заранее разделённым ключом
 */
TEST(ContextTest, Unknownpsk){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Билеты, выданные сервером: без них запас пуст, и до поиска ключа сервер не доходит
	vector <context::ticket_t> issued;
	{
		client::context_t client;
		server::context_t server;
		server.credential(credentials);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		pump(client, server);
		issued = server.tickets();
		ASSERT_EQ(issued.size(), static_cast <size_t> (1));
	}
	server::context_t server;
	server.credential(credentials);
	server.resume(issued);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Раздел 4.2.11 RFC 8446: неведомый ключ сервер вправе не признать и продолжить полным рукопожатием
	ASSERT_TRUE(intruder(server, distortion_t::UNKNOWNPSK, &credentials));
	ASSERT_EQ(server.error(), context::error_t::NONE);
	ASSERT_FALSE(server.shared());
}

/**
 * Проверка отказа клиента на лист с чужим алгоритмом открытого ключа
 */
TEST(ContextTest, Alienleaf){
	context::credential_t credentials;
	// Удостоверение, ключ которого записан чужим алгоритмом
	ASSERT_TRUE(identity("anyks.com", credentials, true));
	client::context_t client;
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::ALIENLEAF, &credentials));
	// Раздел 4.4.2.2 RFC 8446: сертификат с ключом непригодного алгоритма отвергается
	ASSERT_EQ(client.error(), context::error_t::CERTIFICATE);
	ASSERT_FALSE(client.established());
}

/**
 * Проверка самодеятельной смены ключей движком по счётчику записей
 */
TEST(ContextTest, Automatic){
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
	// Устанавливаем смену ключей клиентом по трём записям
	client.renewal(true, 3);
	// Устанавливаем смену ключей сервером по трём записям
	server.renewal(true, 3);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Проверяем, что счётчики прикладных записей начинаются с нуля
	ASSERT_EQ(client.sequence(), 0);
	ASSERT_EQ(server.sequence(true), 0);
	// Накопитель, в который помещаются принятые прикладные данные
	vector <uint8_t> received;
	// Накопитель, в который складываются все принятые сервером данные
	string gathered;
	/**
	 * Выполняем отправку семи записей: раздел 5.5 RFC 8446 велит сменять ключи
	 * впереди предела, и порог в три записи счётчик своего направления переступать
	 * не должен ни разу
	 */
	for(size_t i = 0; i < 7; i++){
		// Отправляемые прикладные данные
		const string data = ("Запись " + std::to_string(i));
		// Выполняем отправку прикладных данных клиентом
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (data.data()), data.size())), context::error_t::NONE);
		// Проверяем, что счётчик своего направления клиента порога не переступил
		ASSERT_LT(client.sequence(), 3);
		// Выполняем передачу байтов между сторонами, пока им есть что сказать
		converse(client, server);
		// Проверяем сохранность связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем, что счётчик направления клиента у сервера порога не переступил
		ASSERT_LT(server.sequence(true), 3);
		// Выполняем получение принятых сервером прикладных данных
		ASSERT_EQ(server.read(received), context::error_t::NONE);
		// Выполняем складывание принятых данных
		gathered.append(received.begin(), received.end());
	}
	// Проверяем схождение принятых данных с отправленными
	ASSERT_EQ(gathered, "Запись 0Запись 1Запись 2Запись 3Запись 4Запись 5Запись 6");
	// Проверяем, что связь по-прежнему пригодна к обмену в обе стороны
	ASSERT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> ("ok"), 2)), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	converse(client, server);
	// Выполняем получение принятых клиентом прикладных данных
	ASSERT_EQ(client.read(received), context::error_t::NONE);
	// Проверяем схождение принятых данных с отправленными
	ASSERT_EQ(string(received.begin(), received.end()), "ok");
}

/**
 * Проверка ручного порядка смены ключей: движок счётчика не трогает
 */
TEST(ContextTest, Manual){
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
	// Устанавливаем ручной порядок смены ключей клиентом с порогом в три записи
	client.renewal(false, 3);
	// Устанавливаем ручной порядок смены ключей сервером с порогом в три записи
	server.renewal(false, 3);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	/**
	 * Выполняем отправку пяти записей: в ручном порядке порог движку не указ,
	 * и счётчики обоих концов направления доходят до пяти
	 */
	for(size_t i = 0; i < 5; i++)
		// Выполняем отправку прикладных данных клиентом
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("x"), 1)), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами, пока им есть что сказать
	converse(client, server);
	// Проверяем, что счётчик своего направления клиента дошёл до пяти
	ASSERT_EQ(client.sequence(), 5);
	// Проверяем, что счётчик направления клиента у сервера дошёл до пяти
	ASSERT_EQ(server.sequence(true), 5);
	// Проверяем, что своё направление сервер не сменял
	ASSERT_EQ(server.sequence(), 0);
	// Выполняем смену ключей вручную тем, кто связь ведёт
	ASSERT_EQ(client.update(false), context::error_t::NONE);
	// Выполняем передачу байтов между сторонами связи
	converse(client, server);
	// Проверяем, что счётчики направления клиента начались заново
	ASSERT_EQ(client.sequence(), 0);
	ASSERT_EQ(server.sequence(true), 0);
	// Проверяем сохранность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
}

/**
 * Проверка просьбы о встречной смене ключей у собеседника, ведущего ручной порядок
 */
TEST(ContextTest, Requested){
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
	// Устанавливаем ручной порядок смены ключей клиентом: сам он ключи не сменит
	client.renewal(false);
	// Устанавливаем смену ключей сервером по трём записям
	server.renewal(true, 3);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем проведение рукопожатия сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	/**
	 * Выполняем два круга по четыре записи: сервер обязан испросить смену ключей
	 * направления клиента на третьей записи каждого круга, а клиент по разделу
	 * 4.6.3 RFC 8446 обязан на просьбу ответить и в ручном порядке
	 */
	for(size_t round = 0; round < 2; round++){
		// Выполняем отправку четырёх записей клиентом
		for(size_t i = 0; i < 4; i++){
			// Выполняем отправку прикладных данных клиентом
			ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("x"), 1)), context::error_t::NONE);
			// Выполняем передачу байтов между сторонами, пока им есть что сказать
			converse(client, server);
		}
		// Проверяем сохранность связи обеими сторонами
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем, что счётчик направления клиента у сервера сменою обнулён
		ASSERT_LT(server.sequence(true), 3);
		// Проверяем, что и клиент своё направление сменил по просьбе
		ASSERT_LT(client.sequence(), 3);
	}
}

/**
 * Проверка отказа клиента на завершение без сертификата в полном рукопожатии
 */
TEST(ContextTest, Unattested){
	client::context_t client;
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::UNATTESTED));
	/**
	 * Раздел 4.4.2 RFC 8446: сервер обязан предъявить сертификат во всяком
	 * рукопожатии, кроме связи на заранее разделённом ключе. Посредник, знающий обмен
	 * как его сторона, сходящееся завершение составит - а подпись владения нет
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	ASSERT_FALSE(client.established());
	ASSERT_TRUE(client.peer().empty());
	// Сброс возвращает извещение и набор шифрования в исходное
	client.clear();
	ASSERT_EQ(client.alert().description, alert::alert_t().description);
	ASSERT_EQ(client.suite(), protect::suite_t::NONE);
	ASSERT_EQ(client.error(), context::error_t::NONE);
}

/**
 * Проверка отказа сервера на сертификат клиента без подписи владения
 */
TEST(ContextTest, Unproven){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	server::context_t server;
	server.credential(credentials);
	server.request(true);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_TRUE(intruder(server, distortion_t::UNPROVEN, &credentials));
	// Раздел 4.4.3 RFC 8446: за непустым сертификатом обязана идти подпись владения
	ASSERT_EQ(server.error(), context::error_t::ORDER);
	ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	ASSERT_FALSE(server.established());
}

/**
 * Проверка отказа на сообщение, пересекающее смену ключей
 */
TEST(ContextTest, Spanning){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	client::context_t client;
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::SPANNING, &credentials));
	// Раздел 5.1 RFC 8446: сообщение перед сменой ключей кончается на границе записи
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	ASSERT_FALSE(client.established());
}

/**
 * Проверка отказа на объявление упреждения без выбранного заранее разделённого ключа
 */
TEST(ContextTest, Unpicked){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	vector <context::ticket_t> issued;
	context::ticket_t accepted;
	ASSERT_TRUE(granted(credentials, issued, accepted));
	client::context_t client;
	client.resume(accepted);
	client.advance(true);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::UNPICKED, &credentials));
	// Раздел 4.2.11 RFC 8446: упреждение принимается лишь при выбранном ключе
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	ASSERT_FALSE(client.established());
}

/**
 * Проверка отказа сервера на завершение ключами упреждения без его конца
 */
TEST(ContextTest, Endless){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	vector <context::ticket_t> issued;
	context::ticket_t accepted;
	ASSERT_TRUE(granted(credentials, issued, accepted));
	server::context_t server;
	server.credential(credentials);
	server.resume(issued);
	server.advance(true);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_TRUE(precursor(server, accepted, distortion_t::ENDLESS));
	// Раздел 4.5 RFC 8446: конец упреждающих данных обязателен прежде завершения
	ASSERT_EQ(server.error(), context::error_t::ORDER);
	ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
	ASSERT_FALSE(server.established());
}

/**
 * Проверка отказа на выбор сервером билета, срок которого вышел и который не предлагался
 */
TEST(ContextTest, Stale){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	const int64_t issued = 1800000000;
	context::ticket_t ticket;
	{
		client::context_t client;
		server::context_t server;
		server.credential(credentials);
		server.moment(issued);
		client.moment(issued);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		pump(client, server);
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		ticket = client.tickets()[0];
	}
	client::context_t client;
	// Билет предъявлен позже своего срока: приветствие его не несёт
	client.resume(ticket);
	client.moment(issued + static_cast <int64_t> (ticket.lifetime) + 1);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	ASSERT_TRUE(adversary(client, distortion_t::UNOFFERED));
	/**
	 * Раздел 4.2.11 RFC 8446: выбранный ключ обязан лежать в пределах предложенного,
	 * а предложено не было ничего - место нулевое тут ничем не лучше иного
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	ASSERT_EQ(client.alert().description, alert::description_t::PARAMETER);
	ASSERT_FALSE(client.shared());
	ASSERT_FALSE(client.established());
}

/**
 * Проверка того, что расхождение возраста билета одной связи не гасит упреждение у следующей
 */
TEST(ContextTest, Recovered){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	const int64_t issued = 1800000000;
	vector <context::ticket_t> tickets;
	{
		client::context_t client;
		server::context_t server;
		server.credential(credentials);
		server.moment(issued);
		client.moment(issued);
		server.advance(true);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		pump(client, server);
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
		tickets = server.tickets();
		tickets.push_back(client.tickets()[0]);
	}
	// Один и тот же сервер ведёт обе связи подряд
	server::context_t server;
	server.credential(credentials);
	server.advance(true);
	for(size_t item = 0; item < 2; item++){
		const int64_t drift = ((item == 0) ? 30 : 0);
		client::context_t client;
		server.clear();
		server.moment(issued + 3600 + drift);
		client.moment(issued + 3600);
		server.resume(vector <context::ticket_t> (1, tickets[0]));
		client.resume(tickets[1]);
		client.advance(true);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		const string request = "Упреждающие данные";
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established()) << "круг " << item;
		/**
		 * Раздел 4.2.10 RFC 8446 велит отвергнуть упреждение ЭТОЙ связи при
		 * расхождении возраста, а не настройку сервера: следующая связь с честным
		 * возрастом упреждение получает
		 */
		ASSERT_EQ(client.accepted(), (item == 1)) << "круг " << item;
	}
}

/**
 * Проверка упреждающих данных вместе с просьбой о повторе приветствия
 */
TEST(ContextTest, Hastened){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	vector <context::ticket_t> issued;
	context::ticket_t accepted;
	ASSERT_TRUE(granted(credentials, issued, accepted));
	for(size_t item = 0; item < 2; item++){
		client::context_t client;
		server::context_t server;
		server.credential(credentials);
		server.resume(issued);
		server.advance(item == 0);
		client.resume(accepted);
		client.advance(true);
		client.groups({extension::group_t::GC256B, extension::group_t::GC512C});
		server.groups({extension::group_t::GC512C});
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		const string request = "Упреждающие данные до просьбы о повторе";
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		converse(client, server);
		/**
		 * Разделы 4.1.2 и 4.2.10 RFC 8446: за просьбою о повторе упреждение не идёт,
		 * повторное приветствие уходит открытой записью, а уже ушедшие записи
		 * упреждения сервер пропускает. Связь устанавливается, упреждение отвергнуто
		 */
		ASSERT_TRUE(client.established() && server.established()) << "круг " << item;
		ASSERT_TRUE(client.shared() && server.shared()) << "круг " << item;
		ASSERT_FALSE(client.accepted()) << "круг " << item;
		vector <uint8_t> received;
		ASSERT_EQ(server.read(received), context::error_t::NONE);
		ASSERT_TRUE(received.empty()) << "круг " << item;
		const string repeated = "Данные по установленной связи";
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (repeated.data()), repeated.size())), context::error_t::NONE);
		pump(client, server);
		ASSERT_EQ(server.read(received), context::error_t::NONE);
		ASSERT_EQ(string(received.begin(), received.end()), repeated) << "круг " << item;
	}
}

/**
 * Проверка пропуска отвергнутого упреждения, нарезанного на множество записей
 */
TEST(ContextTest, Shredded){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	vector <context::ticket_t> issued;
	context::ticket_t accepted;
	ASSERT_TRUE(granted(credentials, issued, accepted));
	client::context_t client;
	server::context_t server;
	server.credential(credentials);
	server.resume(issued);
	server.advance(false);
	client.resume(accepted);
	client.advance(true);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	/**
	 * Раздел 4.2.10 RFC 8446 ограничивает пропуск объёмом упреждения в байтах, а
	 * клиент вправе нарезать его сколь угодно мелко: сорок записей по байту
	 */
	for(size_t i = 0; i < 40; i++)
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("x"), 1)), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established());
	ASSERT_FALSE(client.accepted());
}

/**
 * Проверка предела хранимых клиентом билетов
 */
TEST(ContextTest, Hoarded){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	client::context_t client;
	server::context_t server;
	server.credential(credentials);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established());
	// Сервер вправе слать билеты без счёта, клиент хранит последние шестнадцать
	for(size_t i = 0; i < 24; i++)
		ASSERT_EQ(server.issue(), context::error_t::NONE);
	pump(client, server);
	ASSERT_TRUE(client.established());
	ASSERT_EQ(client.tickets().size(), static_cast <size_t> (16));
	// Хранятся последние билеты: старейшие вытеснены
	ASSERT_EQ(client.tickets().front().identity, server.tickets()[8].identity);
	ASSERT_EQ(client.tickets().back().identity, server.tickets()[23].identity);
}

/**
 * Проверка единственного ответа на пачку просьб о смене ключей
 */
TEST(ContextTest, Amplified){
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	client::context_t client;
	server::context_t server;
	server.credential(credentials);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	converse(client, server);
	ASSERT_TRUE(client.established() && server.established());
	// Восемь просьб о встречной смене ключей одной подачей
	for(size_t i = 0; i < 8; i++)
		ASSERT_EQ(server.update(true), context::error_t::NONE);
	const view_t asked = server.output();
	ASSERT_EQ(client.push(asked), context::error_t::NONE);
	server.consume(asked.size);
	/**
	 * Раздел 4.6.3 RFC 8446: сторона, получившая несколько просьб, пока молчала,
	 * отвечает одной сменой - иначе каждая просьба усиливалась бы целой выработкой
	 * ключей и записью в ответ. Одна запись смены ключей короче полусотни байтов
	 */
	const view_t answered = client.output();
	ASSERT_GT(answered.size, static_cast <size_t> (0));
	ASSERT_LT(answered.size, static_cast <size_t> (64));
	ASSERT_EQ(server.push(answered), context::error_t::NONE);
	client.consume(answered.size);
	ASSERT_TRUE(client.established() && server.established());
	// Связь пригодна к обмену новыми ключами в обе стороны
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> ("ok"), 2)), context::error_t::NONE);
	pump(client, server);
	vector <uint8_t> received;
	ASSERT_EQ(server.read(received), context::error_t::NONE);
	ASSERT_EQ(string(received.begin(), received.end()), "ok");
}

/**
 * Проверка закрытия незаведённой связи и смены шифра до приветствия клиента
 */
TEST(ContextTest, Unopened){
	client::context_t idle;
	// Закрывать незаведённую связь нечего
	ASSERT_EQ(idle.close(), context::error_t::STATE);
	ASSERT_EQ(idle.state(), context::state_t::NONE);
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	server::context_t server;
	server.credential(credentials);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Запись смены шифра, пришедшая серверу прежде приветствия клиента
	const uint8_t change[6] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
	server.push(view_t(change, sizeof(change)));
	// Раздел 5 RFC 8446: смена шифра до первого приветствия - неожиданная запись
	ASSERT_EQ(server.error(), context::error_t::RECORD);
	ASSERT_EQ(server.alert().description, alert::description_t::UNEXPECTED);
}

/**
 * Проверка половинного закрытия связи
 */
TEST(ContextTest, Halfclosed){
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
	// Выполняем рукопожатие сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Прикладные данные, отправляемые сервером до сведений о закрытии
	const string answer = "Ответ, разошедшийся с закрытием";
	// Выполняем отправку прикладных данных сервером
	ASSERT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())), context::error_t::NONE);
	// Выполняем закрытие своей передачи стороной клиента
	ASSERT_EQ(client.close(), context::error_t::NONE);
	// Проверяем состояние закрытия связи стороной клиента
	ASSERT_EQ(client.state(), context::state_t::CLOSED);
	// Проверяем отказ отправки данных после закрытия своей передачи
	ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())), context::error_t::STATE);
	// Размер накопителя сервера до принятия извещения о закрытии
	const size_t before = server.output().size;
	// Извещение о закрытии, отправляемое клиентом
	const view_t closing = client.output();
	// Выполняем подачу извещения о закрытии серверу
	ASSERT_EQ(server.push(closing), context::error_t::NONE);
	// Выполняем снятие отправленного извещения с накопителя клиента
	client.consume(closing.size);
	/**
	 * Принявший извещение о закрытии обязан ответить своим: ответ сложен в
	 * накопитель самой связью, без участия того, кто её ведёт
	 */
	ASSERT_GT(server.output().size, before);
	// Проверяем состояние закрытия связи стороной сервера
	ASSERT_EQ(server.state(), context::state_t::CLOSED);
	// Проверяем отказ отправки данных принявшим извещение о закрытии
	ASSERT_EQ(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())), context::error_t::STATE);
	// Проверяем отказ повторного закрытия уже завершённой передачи
	ASSERT_EQ(server.close(), context::error_t::CLOSED);
	// Выполняем передачу разошедшихся данных и ответного извещения клиенту
	pump(client, server);
	// Накопитель, в который помещаются принятые прикладные данные
	vector <uint8_t> received;
	/**
	 * Раздел 6.1 RFC 8446: закрывший передачу читать вправе, пока собеседник не
	 * завершит свою; данные, разошедшиеся с извещением о закрытии, теряться не должны
	 */
	ASSERT_EQ(client.read(received), context::error_t::NONE);
	// Проверяем схождение принятых данных с отправленными сервером
	ASSERT_EQ(string(received.begin(), received.end()), answer);
	// Проверяем состояние закрытия связи стороной клиента
	ASSERT_EQ(client.state(), context::state_t::CLOSED);
	// Проверяем отказ повторного закрытия стороной клиента
	ASSERT_EQ(client.close(), context::error_t::CLOSED);
	// Проверяем, что закрытие связь отказом не считается
	ASSERT_EQ(client.error(), context::error_t::NONE);
	// Проверяем, что закрытие связь отказом не считается
	ASSERT_EQ(server.error(), context::error_t::NONE);
}

/**
 * Проверка установки срока жизни выдаваемых билетов
 */
TEST(ContextTest, Termed){
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
	// Устанавливаем срок жизни выдаваемых билетов в минуту
	server.lifetime(60);
	// Выполняем заведение связи стороны сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем рукопожатие сторон связи
	converse(client, server);
	// Проверяем установленность связи обеими сторонами
	ASSERT_TRUE(client.established() && server.established());
	// Выполняем выдачу билета со сроком в минуту
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Устанавливаем срок жизни выдаваемых билетов выше предела стандарта
	server.lifetime(700000);
	// Выполняем выдачу билета с усечённым сроком
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Возвращаем срок жизни выдаваемых билетов к принятому по умолчанию
	server.lifetime(0);
	// Выполняем выдачу билета со сроком по умолчанию
	ASSERT_EQ(server.issue(), context::error_t::NONE);
	// Выполняем передачу билетов клиенту
	pump(client, server);
	// Проверяем число принятых клиентом билетов
	ASSERT_EQ(client.tickets().size(), 3);
	// Проверяем срок билета, выданного со сроком в минуту
	ASSERT_EQ(client.tickets()[0].lifetime, 60);
	// Раздел 4.6.1 RFC 8446: срок билета не выше семи суток
	ASSERT_EQ(client.tickets()[1].lifetime, 604800);
	// Проверяем срок билета, выданного со сроком по умолчанию
	ASSERT_EQ(client.tickets()[2].lifetime, 7200);
}

/**
 * Проверка обрыва связи по сообщению рукопожатия непомерной длины после установления
 */
TEST(ContextTest, Overgrown){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем рукопожатие враждебного сервера с непомерным сообщением после
	ASSERT_TRUE(adversary(client, distortion_t::OVERGROWN, &credentials));
	/**
	 * После установления связи сообщения рукопожатия шире билета не ходят: связь
	 * обрывается по одной обвязке, не копя мегабайты чужого мусора
	 */
	ASSERT_EQ(client.error(), context::error_t::MESSAGE);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::DECODE);
	// Проверяем состояние обрыва связи стороной клиента
	ASSERT_EQ(client.state(), context::state_t::FAILED);
}

/**
 * Проверка обрыва связи по цепочке сертификатов, присланной после установления
 */
TEST(ContextTest, Impostor){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Связь стороны клиента
	client::context_t client;
	// Выполняем заведение связи стороны клиента
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Выполняем рукопожатие враждебного сервера с повторной цепочкой после
	ASSERT_TRUE(adversary(client, distortion_t::IMPOSTOR, &credentials));
	/**
	 * За установленной связью законны лишь смена ключей и билеты: цепочка
	 * сертификатов после установления - сообщение не в свой черёд, и принятая
	 * цепочка подменяться не должна
	 */
	ASSERT_EQ(client.error(), context::error_t::ORDER);
	// Проверяем извещение, которым связь оборвана клиентом
	ASSERT_EQ(client.alert().description, alert::description_t::UNEXPECTED);
	// Проверяем состояние обрыва связи стороной клиента
	ASSERT_EQ(client.state(), context::state_t::FAILED);
	// Проверяем, что принятая цепочка сертификатов подменена не была
	ASSERT_FALSE(client.peer().empty());
}

/**
 * Проверка ведения связи при нехватке памяти
 */
TEST(ContextTest, Starved){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Верхний край запаса выделений: полное ведение связи с заведением сторон, их
	 * рукопожатием, обменом прикладными данными и закрытием укладывается в 244
	 * выделения, и на верхнем краю связь обязана пройти без единого отказа памяти
	 */
	const size_t top = 512;
	/**
	 * Выполняем перебор запасов выделений: до трёхсот по одному, дальше шагом в
	 * пятьдесят три до самого верха (полный путь связи укладывается в 244 выделения,
	 * и всякий перехват задевается первой сотней с лишним). На всяком запасе связь
	 * обязана ответить либо успехом, либо отказом памяти, но не прерыванием
	 * исполнения, а обрыв связи дозволен лишь нехваткой памяти с извещением о
	 * внутреннем отказе
	 */
	for(size_t budget = 0; budget <= top; budget += ((budget < 300) ? 1 : 53)){
		// Обнаруженное нарушение договора связи
		breach_t breach = breach_t::NONE;
		// Признак того, что нехватка памяти объявлена отказом на этом запасе
		bool hungry = false;
		{
			// Связь стороны клиента, заведённая вне запаса
			client::context_t client;
			// Связь стороны сервера, заведённая вне запаса
			server::context_t server;
			// Отмеряем запас выделений на время ведения связи
			starve::ration_t ration(budget);
			// Выполняем ведение связи при отмеренном запасе выделений
			breach = starving(client, server, credentials, hungry);
			// Снимаем запас: дальнейшие выделения принадлежат проверке, а не связи
			ration.stop();
			/**
			 * На верхнем краю запаса связь обязана пройти весь путь без единого отказа
			 * памяти и кончиться закрытием обеих сторон, а не обрывом
			 */
			if((budget == top) && (hungry || (client.state() != context::state_t::CLOSED) || (server.state() != context::state_t::CLOSED)))
				// Запоминаем нарушение прохождения связи
				breach = breach_t::FINISHED;
			// Проверяем, что договор связи при заведённых вне запаса сторонах соблюдён
			ASSERT_EQ(breach, breach_t::NONE) << "запас " << budget << " вне: клиент "
				<< static_cast <int> (client.state()) << "/" << static_cast <int> (client.error()) << "/" << static_cast <int> (client.alert().description)
				<< " сервер " << static_cast <int> (server.state()) << "/" << static_cast <int> (server.error()) << "/" << static_cast <int> (server.alert().description);
		}
		// Запоминаем объявленный отказ памяти
		starved = (starved || hungry);
		// Сбрасываем признак отказа памяти на этом запасе
		hungry = false;
		{
			// Отмеряем запас выделений на время ведения связи
			starve::ration_t ration(budget);
			// Связь стороны клиента, заведённая внутри запаса
			client::context_t client;
			// Связь стороны сервера, заведённая внутри запаса
			server::context_t server;
			// Выполняем ведение связи при отмеренном запасе выделений
			breach = starving(client, server, credentials, hungry);
			// Снимаем запас: дальнейшие выделения принадлежат проверке, а не связи
			ration.stop();
			/**
			 * На верхнем краю запаса связь обязана пройти весь путь без единого отказа
			 * памяти и кончиться закрытием обеих сторон, а не обрывом
			 */
			if((budget == top) && (hungry || (client.state() != context::state_t::CLOSED) || (server.state() != context::state_t::CLOSED)))
				// Запоминаем нарушение прохождения связи
				breach = breach_t::FINISHED;
			// Проверяем, что договор связи при заведённых внутри запаса сторонах соблюдён
			ASSERT_EQ(breach, breach_t::NONE) << "запас " << budget << " внутри: клиент "
				<< static_cast <int> (client.state()) << "/" << static_cast <int> (client.error()) << "/" << static_cast <int> (client.alert().description)
				<< " сервер " << static_cast <int> (server.state()) << "/" << static_cast <int> (server.error()) << "/" << static_cast <int> (server.alert().description);
		}
		// Запоминаем объявленный отказ памяти
		starved = (starved || hungry);
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}
