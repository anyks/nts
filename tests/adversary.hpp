/**
 * @file adversary.hpp
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
 * @brief Общий для проверок заголовочный файл враждебного сервера протокола TLS 1.3
 *
 * @details Клиент судит сервера по сообщениям, идущим под защитой рукопожатия, и
 *          подделать их в потоке байтов нельзя: подделка не расшифруется вовсе, а
 *          отказ придёт не от того заслона, который проверяется. Враждебный сервер
 *          обходит это тем, что ведёт свою сторону сам: он выводит ключи рукопожатия
 *          по-настоящему и складывает ими сообщение, искажённое по заказу проверки.
 *
 * @note Рукопожатие здесь не доводится до конца: всякий проверяемый заслон обрывает
 *       клиента раньше подписи владения ключом, и складывать её незачем
 *
 * @note Всё содержимое лежит в безымянном пространстве имён: у всякой проверки своя
 *       программа, но правило это блюдётся и здесь - так заголовочный файл годится и
 *       для набора, собранного единой программой
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию заголовочного файла
 */
#ifndef __ANTS_TESTS_ADVERSARY__
#define __ANTS_TESTS_ADVERSARY__

/**
 * Стандартные заголовочные файлы
 */
#include <vector>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <curve/parameters.hpp>
#include <hello/hello.hpp>
#include <flow/flow.hpp>
#include <record/record.hpp>
#include <message/message.hpp>
#include <session/session.hpp>
#include <protect/protect.hpp>
#include <schedule/schedule.hpp>
#include <agreement/ecdhe.hpp>
#include <x509/x509.hpp>
#include <x509/signature.hpp>
#include <math/number.hpp>
#include <sign/gost.hpp>
#include <alert/alert.hpp>
#include <field/field.hpp>
#include <digest/streebog.hpp>
#include <extension/extension.hpp>
#include <handshake/handshake.hpp>
#include <context/context.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * @brief Служебные объекты враждебного сервера проверок
 *
 */
namespace {
	/**
	 * Подписываемся на пространство имён проекта
	 */
	using namespace anyks;
	/**
	 * @brief Искажения, вносимые враждебным сервером
	 *
	 */
	enum class distortion_t : uint8_t {
		NONE      = 0x00, // Искажение не вносится
		EXTENSION = 0x01, // Защищённые расширения несут непрошенное расширение
		CONTEXT   = 0x02, // Цепочка сертификатов несёт непустой опознаватель запроса
		EMPTINESS = 0x03, // Цепочка сертификатов не несёт ни одного сертификата
		SCHEME    = 0x04, // Подпись владения ключом объявлена неизвестной схемой
		FOREIGN   = 0x05, // Подпись владения ключом объявлена схемой чужой кривой
		LIFETIME  = 0x06, // Билет возобновления связи объявлен сроком свыше семи суток
		INTERLEAVE = 0x07, // Сообщение рукопожатия разорвано записью извещения
		COOKIE    = 0x08, // Просьба о повторе приветствия несёт метку возврата состояния
		GREETING  = 0x09  // Приветствие сервера несёт расширение не своего сообщения
	};
	/**
	 * @brief Заранее назначенное случайное значение просьбы о повторе приветствия
	 *
	 * @note Раздел 4.1.3 RFC 8446 объявляет просьбу о повторе именно этим значением
	 *
	 */
	static const uint8_t RETRY[32] = {
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
		0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
	};
	/**
	 * @brief Метод отправки сообщения рукопожатия враждебным сервером
	 *
	 * @param protection защита записей враждебного сервера
	 * @param transcript переписка рукопожатия враждебного сервера
	 * @param type       вид отправляемого сообщения рукопожатия
	 * @param body       тело отправляемого сообщения рукопожатия
	 * @param result     накопитель, в который складывается защищённая запись
	 *
	 * @return           признак успешности отправки сообщения рукопожатия
	 *
	 */
	bool deliver(protect::protection_t & protection, session::transcript_t & transcript, const handshake::type_t type, const view_t & body, vector <uint8_t> & result) noexcept {
		// Объект составителя отправляемых сообщений рукопожатия
		handshake::writer_t writer;
		// Если сообщение рукопожатия составить не удалось
		if(writer.push(type, body) != handshake::error_t::NONE)
			// Выводим отказ отправки сообщения рукопожатия
			return false;
		// Если сообщение в переписку рукопожатия добавить не удалось
		if(transcript.update(writer.data()) != session::error_t::NONE)
			// Выводим отказ отправки сообщения рукопожатия
			return false;
		// Накопитель, в который складывается защищённая запись
		vector <uint8_t> sealed;
		// Если наложить защиту на сообщение рукопожатия не удалось
		if(protection.seal(record::type_t::HANDSHAKE, writer.data(), sealed) != protect::error_t::NONE)
			// Выводим отказ отправки сообщения рукопожатия
			return false;
		// Складываем защищённую запись в накопитель ответа
		result.insert(result.end(), sealed.begin(), sealed.end());
		// Выводим успешность отправки сообщения рукопожатия
		return true;
	}
	/**
	 * @brief Метод выработки подписи владения ключом враждебного сервера
	 *
	 * @param credential подлинность подписывающей стороны
	 * @param transcript переписка рукопожатия подписывающей стороны
	 * @param server     признак того, что подпись кладёт сторона сервера
	 * @param result     накопитель, в который складывается тело подписи
	 *
	 * @return           признак успешности выработки подписи владения ключом
	 *
	 */
	bool possession(const context::credential_t & credential, const session::transcript_t & transcript, const bool server, vector <uint8_t> & result) noexcept {
		// Объект разбора сертификата враждебного сервера
		x509::certificate_t leaf;
		// Если сертификат враждебного сервера разобрать не удалось
		if(leaf.parse(view_t(credential.chain[0].data(), credential.chain[0].size())) != x509::error_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Опознаватель набора параметров кривой своего ключа
		string oid;
		// Если опознаватель набора параметров кривой извлечь не удалось
		if(!x509::identifier(leaf.key(), oid))
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Схема подписи владения ключом враждебного сервера
		extension::scheme_t chosen = extension::scheme_t::NONE;
		// Схемы подписи, известные протоколу
		const extension::scheme_t schemes[] = {
			extension::scheme_t::S256A, extension::scheme_t::S256B,
			extension::scheme_t::S256C, extension::scheme_t::S256D,
			extension::scheme_t::S512A, extension::scheme_t::S512B,
			extension::scheme_t::S512C
		};
		/**
		 * Выполняем перебор схем подписи, известных протоколу
		 */
		for(size_t i = 0; (i < (sizeof(schemes) / sizeof(extension::scheme_t))) && (chosen == extension::scheme_t::NONE); i++){
			// Получаем опознаватель кривой очередной схемы подписи
			const char * item = extension::curve(schemes[i]);
			// Если опознаватель кривой схемы совпал с искомым
			if((item != nullptr) && (oid.compare(item) == 0))
				// Запоминаем схему подписи владения ключом
				chosen = schemes[i];
		}
		// Если схему подписи подобрать не удалось
		if(chosen == extension::scheme_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Эллиптическая кривая подписи владения ключом
		curve::curve_t signing;
		// Если кривую своего ключа завести не удалось
		if(!x509::parameters(leaf.key(), signing))
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t hash[schedule::SCHEDULE_SECRET];
		// Если хеш переписки рукопожатия получить не удалось
		if(transcript.digest(hash) != session::error_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Накопитель, в который складывается подписываемое содержимое
		vector <uint8_t> content;
		// Если подписываемое содержимое составить не удалось
		if(message::content(view_t(hash, sizeof(hash)), server, content) != message::error_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Место, в которое помещается хеш подписываемого содержимого
		uint8_t digest[64];
		// Определяем длину хеша подписываемого содержимого
		const digest::type_t kind = ((signing.size() == 32) ? digest::type_t::SHORT : digest::type_t::LONG);
		// Если хеш подписываемого содержимого выработать не удалось
		if(!digest::streebog(kind, view_t(content.data(), content.size()), digest, signing.size(), digest::order_t::VECTOR))
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Объект модуля электронной подписи
		sign::gost_t gost;
		// Если эллиптическую кривую подписи установить не удалось
		if(!gost.start(signing))
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Если секретный ключ враждебного сервера установить не удалось
		if(!gost.secret(view_t(credential.secret.data(), credential.secret.size())))
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Место, в которое помещается выработанная подпись владения ключом
		uint8_t signature[math::NUMBER_SIZE * 2];
		// Если подпись владения ключом выработать не удалось
		if(!gost.make(view_t(digest, signing.size()), signature))
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Место, в которое помещается подпись в записи протокола
		uint8_t reversed[math::NUMBER_SIZE * 2];
		// Если запись подписи развернуть не удалось
		if(message::reverse(view_t(signature, gost.size()), reversed) != message::error_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Составляемое сообщение подписи владения ключом
		message::verify_t verify;
		// Устанавливаем схему подписи владения ключом
		verify.scheme = chosen;
		// Устанавливаем значение подписи владения ключом
		verify.signature = view_t(reversed, gost.size());
		// Выводим итог составления тела подписи владения ключом
		return (message::build(verify, result) == message::error_t::NONE);
	}
	/**
	 * @brief Метод ответа враждебного сервера на приветствие клиента
	 *
	 * @param client     связь стороны клиента
	 * @param distortion искажение, вносимое враждебным сервером
	 * @param credential подлинность враждебного сервера, нужная искажению подписи
	 *
	 * @return           признак успешности ответа враждебного сервера
	 *
	 * @note Итог отвечает лишь за то, что ответ составлен и подан клиенту: суждение
	 *       о заслоне снимается с самого клиента
	 *
	 */
	bool adversary(client::context_t & client, const distortion_t distortion, const context::credential_t * credential = nullptr) noexcept {
		// Получаем байты, отправляемые клиентом серверу
		const view_t sending = client.output();
		// Если клиент серверу ничего не отправил
		if(sending.size == 0)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Выполняем перенос отправленных клиентом байтов
		const vector <uint8_t> wire(sending.data, sending.data + sending.size);
		// Снимаем отправленные байты с накопителя клиента
		client.consume(wire.size());
		// Объект сборщика принимаемых записей связи
		record::reader_t records;
		// Если принятые байты сборщику записей подать не удалось
		if(records.push(view_t(wire.data(), wire.size())) != record::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Заголовок принятой записи связи
		record::header_t header;
		// Содержимое принятой записи связи
		view_t payload;
		// Если запись приветствия клиента прочитать не удалось
		if(records.next(header, payload) != record::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Объект сборщика принимаемых сообщений рукопожатия
		handshake::reader_t messages;
		// Если содержимое записи сборщику сообщений подать не удалось
		if(messages.push(payload) != handshake::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Заголовок принятого сообщения рукопожатия
		handshake::header_t message;
		// Тело принятого сообщения рукопожатия
		view_t body;
		// Если сообщение приветствия клиента прочитать не удалось
		if(messages.next(message, body) != handshake::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Если принято не приветствие клиента
		if(message.type != handshake::type_t::CLIENT)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Разбираемое приветствие клиента
		hello::client_t greeting;
		// Если приветствие клиента разобрать не удалось
		if(hello::parse(body, greeting) != hello::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Разыскиваем расширение открытых частей ключей обмена клиента
		const hello::extension_t * extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
		// Если открытых частей ключей обмена приветствие не несёт
		if((extension == nullptr) || greeting.suites.empty())
			// Выводим отказ ответа враждебного сервера
			return false;
		// Открытые части ключей обмена, предложенные клиентом
		vector <extension::share_t> shares;
		// Если открытые части ключей обмена разобрать не удалось
		if((extension::shares(extension->data, shares) != extension::error_t::NONE) || shares.empty())
			// Выводим отказ ответа враждебного сервера
			return false;
		// Получаем опознаватель набора параметров кривой обмена ключами
		const char * oid = extension::curve(shares[0].group);
		// Объект кривой обмена мимолётными ключами
		curve::curve_t elliptic;
		// Если кривую обмена мимолётными ключами завести не удалось
		if((oid == nullptr) || !curve::parameters(oid, elliptic))
			// Выводим отказ ответа враждебного сервера
			return false;
		// Секретный мимолётный ключ враждебного сервера
		vector <uint8_t> secret(elliptic.size(), 0);
		// Открытый мимолётный ключ враждебного сервера
		vector <uint8_t> opened(elliptic.size() * 2, 0);
		// Если мимолётную пару ключей враждебного сервера выработать не удалось
		if(!agreement::generate(elliptic, secret.data(), opened.data()))
			// Выводим отказ ответа враждебного сервера
			return false;
		// Объект переписки рукопожатия враждебного сервера
		session::transcript_t transcript;
		// Заводим переписку рукопожатия враждебного сервера
		transcript.start();
		// Если приветствие клиента в переписку добавить не удалось
		if(transcript.update(messages.message()) != session::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Составляемое приветствие враждебного сервера
		hello::server_t answer;
		// Устанавливаем версию протокола, доставшуюся от предыдущих изданий
		answer.version = 0x0303;
		// Устанавливаем опознаватель связи, повторяемый за приветствием клиента
		answer.session = greeting.session;
		// Устанавливаем набор шифрования, первым предложенный клиентом
		answer.suite = greeting.suites[0];
		// Устанавливаем выбранный способ сжатия
		answer.method = 0x00;
		/**
		 * Выполняем набивку случайного значения приветствия враждебного сервера
		 */
		for(size_t i = 0; i < sizeof(answer.random); i++)
			// Записываем очередной байт случайного значения приветствия
			answer.random[i] = static_cast <uint8_t> (0x10 + i);
		// Накопители, в которых лежат тела расширений приветствия
		vector <uint8_t> version, share;
		// Если издание протокола составить не удалось
		if(extension::version(0x0304, version) != extension::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Открытая часть ключа обмена враждебного сервера
		const extension::share_t item(shares[0].group, view_t(opened.data(), opened.size()));
		// Если открытую часть ключа обмена составить не удалось
		if(extension::share(item, share) != extension::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Добавляем расширение издания протокола
		answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(version.data(), version.size())));
		// Накопитель, в котором лежит тело расширения просьбы о повторе
		vector <uint8_t> selected;
		// Метка возврата состояния, объявляемая просьбой о повторе
		const vector <uint8_t> label = {0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
		// Если враждебный сервер просит повтора приветствия с меткой
		if(distortion == distortion_t::COOKIE){
			// Переносим случайное значение просьбы о повторе приветствия
			::memcpy(answer.random, RETRY, sizeof(RETRY));
			/**
			 * Просить повтора вправе лишь на кривой, которую клиент предложил и ключа
			 * по которой ещё не прислал: берём вторую из предложенных
			 */
			if(extension::selected(extension::group_t::GC512A, selected) != extension::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Добавляем расширение выбранной кривой обмена ключами
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(selected.data(), selected.size())));
			// Добавляем расширение метки возврата состояния сервера
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::COOKIE), view_t(label.data(), label.size())));
		// Если враждебный сервер отвечает самим приветствием
		} else {
			// Добавляем расширение открытой части ключа обмена
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(share.data(), share.size())));
			// Если приветствие сервера несёт расширение не своего сообщения
			if(distortion == distortion_t::GREETING)
				// Добавляем расширение, приветствию сервера не положенное
				answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(nullptr, 0)));
		}
		// Накопитель, в который складывается тело приветствия сервера
		vector <uint8_t> greeted;
		// Если тело приветствия враждебного сервера составить не удалось
		if(hello::build(answer, greeted) != hello::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Объект составителя отправляемых сообщений рукопожатия
		handshake::writer_t writer;
		// Если приветствие враждебного сервера составить не удалось
		if(writer.push(handshake::type_t::SERVER, view_t(greeted.data(), greeted.size())) != handshake::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Получаем составленное приветствие враждебного сервера
		const view_t greeter = writer.data();
		// Если приветствие сервера в переписку добавить не удалось
		if(transcript.update(greeter) != session::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Объект нарезчика отправляемых записей
		record::writer_t plain;
		// Если приветствие враждебного сервера на записи нарезать не удалось
		if(plain.push(record::type_t::HANDSHAKE, record::version_t::TLS12, greeter) != record::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Получаем нарезанные записи приветствия враждебного сервера
		const view_t plaintext = plain.data();
		// Накопитель, в который складывается ответ враждебного сервера
		vector <uint8_t> answered(plaintext.data, plaintext.data + plaintext.size);
		// Если враждебный сервер искажает само приветствие
		if((distortion == distortion_t::COOKIE) || (distortion == distortion_t::GREETING)){
			// Выполняем подачу приветствия враждебного сервера клиенту
			client.push(view_t(answered.data(), answered.size()));
			// Выводим успешность ответа враждебного сервера
			return true;
		}
		// Место, в которое помещается общее значение обмена мимолётными ключами
		uint8_t common[64];
		// Если общее значение обмена мимолётными ключами выработать не удалось
		if(!agreement::ecdhe(elliptic, view_t(secret.data(), secret.size()), shares[0].key, common))
			// Выводим отказ ответа враждебного сервера
			return false;
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t digest[schedule::SCHEDULE_SECRET];
		// Если хеш переписки рукопожатия получить не удалось
		if(transcript.digest(digest) != session::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Объект значений расписания ключей враждебного сервера
		session::secrets_t secrets;
		// Если начальную ступень расписания ключей завести не удалось
		if(secrets.start(view_t(nullptr, 0)) != session::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Если ступень рукопожатия расписания ключей вывести не удалось
		if(secrets.handshake(view_t(common, elliptic.size()), view_t(digest, sizeof(digest))) != session::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Получаем набор шифрования, выбранный враждебным сервером
		const protect::suite_t suite = static_cast <protect::suite_t> (answer.suite);
		// Корневой ключ направления связи враждебного сервера
		uint8_t material[protect::PROTECT_KEY];
		// Вектор замены направления связи враждебного сервера
		uint8_t element[protect::PROTECT_VECTOR];
		// Если ключевой материал направления связи вывести не удалось
		if(secrets.material(session::side_t::SERVER, suite, material, element) != session::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Объект защиты записей враждебного сервера
		protect::protection_t protection;
		// Если ключевой материал направления связи установить не удалось
		if(!protection.start(suite, view_t(material, sizeof(material)), view_t(element, protect::block(suite))))
			// Выводим отказ ответа враждебного сервера
			return false;
		// Перечень расширений, объявляемых враждебным сервером
		vector <hello::extension_t> items;
		// Если защищённые расширения несут непрошенное расширение
		if(distortion == distortion_t::EXTENSION)
			// Добавляем расширение, которого клиент не предлагал вовсе
			items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MODES), view_t(nullptr, 0)));
		// Объект составителя перечня расширений сообщения
		field::builder_t fields;
		// Если перечень расширений открыть не удалось
		if(fields.open(2) != field::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		/**
		 * Выполняем перебор расширений, объявляемых враждебным сервером
		 */
		for(size_t i = 0; i < items.size(); i++){
			// Если вид расширения записать не удалось
			if(fields.number(items[i].type, 2) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если тело расширения открыть не удалось
			if(fields.open(2) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если тело расширения записать не удалось
			if((items[i].data.size > 0) && (fields.bytes(items[i].data) != field::error_t::NONE))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если тело расширения закрыть не удалось
			if(fields.close() != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
		}
		// Если перечень расширений закрыть не удалось
		if(fields.close() != field::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Получаем составленный перечень расширений
		const view_t list = fields.data();
		// Накопитель, в который складывается тело защищённых расширений сервера
		const vector <uint8_t> extensions(list.data, list.data + list.size);
		// Если враждебный сервер рвёт сообщение рукопожатия чужой записью
		if(distortion == distortion_t::INTERLEAVE){
			// Объект составителя защищённых расширений враждебного сервера
			handshake::writer_t divided;
			// Если защищённые расширения враждебного сервера составить не удалось
			if(divided.push(handshake::type_t::EXTENSIONS, view_t(extensions.data(), extensions.size())) != handshake::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Получаем составленное сообщение защищённых расширений
			const view_t whole = divided.data();
			// Если сообщение защищённых расширений разрывать не на чем
			if(whole.size < 4)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Накопитель, в который складывается первая половина сообщения
			vector <uint8_t> leading;
			// Если наложить защиту на первую половину сообщения не удалось
			if(protection.seal(record::type_t::HANDSHAKE, view_t(whole.data, 2), leading) != protect::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Складываем защищённую запись в ответ враждебного сервера
			answered.insert(answered.end(), leading.begin(), leading.end());
			// Составляемое извещение, разрывающее сообщение рукопожатия
			alert::alert_t notice;
			// Устанавливаем уровень составляемого извещения
			notice.level = alert::level_t::WARNING;
			/**
			 * Извещение берётся несмертельным нарочно: смертельное оборвало бы связь
			 * само по себе, и заслон разрыва проверен бы не был
			 */
			notice.description = alert::description_t::CANCELED;
			// Место, в которое складывается тело составляемого извещения
			uint8_t noticed[2];
			// Если тело извещения составить не удалось
			if(alert::build(notice, noticed) != alert::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Накопитель, в который складывается запись извещения
			vector <uint8_t> noticing;
			// Если наложить защиту на извещение не удалось
			if(protection.seal(record::type_t::ALERT, view_t(noticed, sizeof(noticed)), noticing) != protect::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Складываем защищённую запись в ответ враждебного сервера
			answered.insert(answered.end(), noticing.begin(), noticing.end());
			// Выполняем подачу ответа враждебного сервера клиенту
			client.push(view_t(answered.data(), answered.size()));
			// Выводим успешность ответа враждебного сервера
			return true;
		}
		// Если защищённые расширения враждебного сервера отправить не удалось
		if(!deliver(protection, transcript, handshake::type_t::EXTENSIONS, view_t(extensions.data(), extensions.size()), answered))
			// Выводим отказ ответа враждебного сервера
			return false;
		// Опознаватель запроса подлинности, набиваемый враждебным сервером
		const uint8_t identifier[] = {0x0A, 0x0B, 0x0C, 0x0D};
		// Если враждебный сервер искажает цепочку сертификатов
		if((distortion == distortion_t::CONTEXT) || (distortion == distortion_t::EMPTINESS)){
			// Составляемая цепочка сертификатов враждебного сервера
			message::certificate_t certificate;
			// Если цепочка сертификатов несёт непустой опознаватель запроса
			if(distortion == distortion_t::CONTEXT){
				// Устанавливаем непустой опознаватель запроса подлинности
				certificate.context = view_t(identifier, sizeof(identifier));
				// Запись цепочки сертификатов враждебного сервера
				message::entry_t entry;
				// Устанавливаем тело сертификата записи цепочки
				entry.data = view_t(identifier, sizeof(identifier));
				// Добавляем запись в цепочку сертификатов
				certificate.entries.push_back(entry);
			}
			// Накопитель, в который складывается тело цепочки сертификатов
			vector <uint8_t> chain;
			// Если тело цепочки сертификатов составить не удалось
			if(message::build(certificate, chain) != message::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если цепочку сертификатов враждебного сервера отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::CERTIFICATE, view_t(chain.data(), chain.size()), answered))
				// Выводим отказ ответа враждебного сервера
				return false;
		// Если враждебный сервер доводит рукопожатие до подписи владения ключом
		} else if((distortion == distortion_t::SCHEME) || (distortion == distortion_t::FOREIGN) || (distortion == distortion_t::LIFETIME)) {
			// Если подлинность враждебного сервера проверкой не задана
			if((credential == nullptr) || credential->chain.empty())
				// Выводим отказ ответа враждебного сервера
				return false;
			// Составляемая цепочка сертификатов враждебного сервера
			message::certificate_t certificate;
			// Запись цепочки сертификатов враждебного сервера
			message::entry_t entry;
			// Устанавливаем тело сертификата записи цепочки
			entry.data = view_t(credential->chain[0].data(), credential->chain[0].size());
			// Добавляем запись в цепочку сертификатов
			certificate.entries.push_back(entry);
			// Накопитель, в который складывается тело цепочки сертификатов
			vector <uint8_t> chain;
			// Если тело цепочки сертификатов составить не удалось
			if(message::build(certificate, chain) != message::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если цепочку сертификатов враждебного сервера отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::CERTIFICATE, view_t(chain.data(), chain.size()), answered))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Накопитель, в который складывается тело подписи владения ключом
			vector <uint8_t> witnessed;
			// Если враждебный сервер искажает схему подписи владения ключом
			if((distortion == distortion_t::SCHEME) || (distortion == distortion_t::FOREIGN)){
				// Составляемая подпись владения ключом враждебного сервера
				message::verify_t witness;
				/**
				 * Схема подписи объявляется либо неизвестной вовсе, либо известной, но
				 * положенной чужой кривой: сама подпись при этом не важна, ибо заслон
				 * схемы стоит прежде её проверки
				 */
				witness.scheme = ((distortion == distortion_t::SCHEME) ? static_cast <extension::scheme_t> (0x0403) : extension::scheme_t::S512A);
				// Место, в которое кладётся ничего не значащая запись подписи
				const vector <uint8_t> nothing(64, 0x5A);
				// Устанавливаем запись подписи владения ключом
				witness.signature = view_t(nothing.data(), nothing.size());
				// Если тело подписи владения ключом составить не удалось
				if(message::build(witness, witnessed) != message::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
			// Если враждебный сервер подписывает владение ключом по-настоящему
			} else if(!possession(* credential, transcript, true, witnessed))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если подпись владения ключом враждебного сервера отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::VERIFY, view_t(witnessed.data(), witnessed.size()), answered))
				// Выводим отказ ответа враждебного сервера
				return false;
		}
		// Если враждебный сервер доводит рукопожатие до билета возобновления связи
		if(distortion == distortion_t::LIFETIME){
			// Место, в которое помещается ключ завершения рукопожатия сервера
			uint8_t completion[schedule::SCHEDULE_SECRET];
			// Если ключ завершения рукопожатия вывести не удалось
			if(secrets.finished(session::side_t::SERVER, completion) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Корневой ключ направления связи клиента
			uint8_t material[protect::PROTECT_KEY];
			// Вектор замены направления связи клиента
			uint8_t element[protect::PROTECT_VECTOR];
			/**
			 * Ключи рукопожатия клиента снимаются заранее: переход к ступени
			 * прикладных данных значения направлений связи переписывает
			 */
			if(secrets.material(session::side_t::CLIENT, suite, material, element) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Объект защиты записей, принимаемых от клиента
			protect::protection_t incoming;
			// Если ключевой материал направления связи клиента установить не удалось
			if(!incoming.start(suite, view_t(material, sizeof(material)), view_t(element, protect::block(suite))))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Место, в которое помещается хеш переписки рукопожатия
			uint8_t hash[schedule::SCHEDULE_SECRET];
			// Если хеш переписки рукопожатия получить не удалось
			if(transcript.digest(hash) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Место, в которое помещается завершение рукопожатия сервером
			uint8_t completed[32];
			// Если завершение рукопожатия выработать не удалось
			if(message::finished(view_t(completion, sizeof(completion)), view_t(hash, sizeof(hash)), completed) != message::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если завершение рукопожатия враждебного сервера отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::FINISHED, view_t(completed, sizeof(completed)), answered))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если хеш переписки рукопожатия получить не удалось
			if(transcript.digest(hash) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если ступень прикладных данных расписания ключей вывести не удалось
			if(secrets.application(view_t(hash, sizeof(hash))) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если ключевой материал прикладных данных сервера вывести не удалось
			if(secrets.material(session::side_t::SERVER, suite, material, element) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Объект защиты записей прикладных данных враждебного сервера
			protect::protection_t outgoing;
			// Если ключевой материал прикладных данных установить не удалось
			if(!outgoing.start(suite, view_t(material, sizeof(material)), view_t(element, protect::block(suite))))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Выполняем подачу рукопожатия враждебного сервера клиенту
			client.push(view_t(answered.data(), answered.size()));
			// Получаем байты, отправленные клиентом в ответ
			const view_t completing = client.output();
			// Если клиент рукопожатие не договорил
			if(completing.size == 0)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Выполняем перенос отправленных клиентом байтов
			const vector <uint8_t> stream(completing.data, completing.data + completing.size);
			// Снимаем отправленные байты с накопителя клиента
			client.consume(stream.size());
			// Объект сборщика записей, принятых от клиента
			record::reader_t taken;
			// Если принятые байты сборщику записей подать не удалось
			if(taken.push(view_t(stream.data(), stream.size())) != record::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			/**
			 * Выполняем перебор записей, принятых от клиента
			 */
			while(taken.pending() > 0){
				// Заголовок очередной принятой записи
				record::header_t taking;
				// Содержимое очередной принятой записи
				view_t sealed;
				// Если очередную запись прочитать не удалось
				if(taken.next(taking, sealed) != record::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Вид содержимого, вскрытого из принятой записи
				record::type_t kind = record::type_t::NONE;
				// Накопитель, в который складывается вскрытое содержимое
				vector <uint8_t> opened;
				// Если снять защиту с принятой записи не удалось
				if(incoming.open(taking, sealed, kind, opened) != protect::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Если вскрытое содержимое сообщением рукопожатия не является
				if(kind != record::type_t::HANDSHAKE)
					// Переходим к следующей принятой записи
					continue;
				// Объект сборщика сообщений, принятых от клиента
				handshake::reader_t taker;
				// Если вскрытое содержимое сборщику сообщений подать не удалось
				if(taker.push(view_t(opened.data(), opened.size())) != handshake::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Заголовок очередного принятого сообщения рукопожатия
				handshake::header_t taken_header;
				// Тело очередного принятого сообщения рукопожатия
				view_t taken_body;
				/**
				 * Выполняем перебор сообщений рукопожатия, принятых от клиента
				 */
				while(taker.next(taken_header, taken_body) == handshake::error_t::NONE){
					// Если сообщение в переписку рукопожатия добавить не удалось
					if(transcript.update(taker.message()) != session::error_t::NONE)
						// Выводим отказ ответа враждебного сервера
						return false;
				}
			}
			// Если хеш переписки рукопожатия получить не удалось
			if(transcript.digest(hash) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если значение возобновления связи вывести не удалось
			if(secrets.resumption(view_t(hash, sizeof(hash))) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Составляемый билет возобновления связи враждебного сервера
			message::ticket_t ticket;
			/**
			 * Срок билета объявляется свыше семи суток: раздел 4.6.1 RFC 8446 кладёт
			 * сроку билета именно этот предел
			 */
			ticket.lifetime = 604801;
			// Устанавливаем добавку к возрасту составляемого билета
			ticket.age = 0;
			// Неповторимое значение составляемого билета
			const uint8_t nonce[4] = {0x00, 0x00, 0x00, 0x00};
			// Устанавливаем неповторимое значение составляемого билета
			ticket.nonce = view_t(nonce, sizeof(nonce));
			// Устанавливаем тело составляемого билета
			ticket.data = view_t(identifier, sizeof(identifier));
			// Накопитель, в который складывается тело билета возобновления связи
			vector <uint8_t> issued;
			// Если тело билета возобновления связи составить не удалось
			if(message::build(ticket, issued) != message::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Выполняем сброс накопителя ответа враждебного сервера
			answered.clear();
			// Если билет возобновления связи отправить не удалось
			if(!deliver(outgoing, transcript, handshake::type_t::TICKET, view_t(issued.data(), issued.size()), answered))
				// Выводим отказ ответа враждебного сервера
				return false;
		}
		// Выполняем подачу ответа враждебного сервера клиенту
		client.push(view_t(answered.data(), answered.size()));
		// Выводим успешность ответа враждебного сервера
		return true;
	}
	/**
	 * @brief Метод рукопожатия враждебного клиента с сервером
	 *
	 * @param server     связь стороны сервера
	 * @param distortion искажение, вносимое враждебным клиентом
	 * @param credential подлинность враждебного клиента
	 *
	 * @return           признак успешности рукопожатия враждебного клиента
	 *
	 * @details Зеркало враждебного сервера: приветствие складывается своё, ключи
	 *          рукопожатия выводятся по-настоящему, и подделывается уже то, что идёт
	 *          под их защитой, - иначе заслоны сервера за приветствием не проверить.
	 *
	 * @note Итог отвечает лишь за то, что рукопожатие составлено и подано серверу:
	 *       суждение о заслоне снимается с самого сервера
	 *
	 */
	bool intruder(server::context_t & server, const distortion_t distortion, const context::credential_t * credential = nullptr) noexcept {
		// Кривая обмена ключами враждебного клиента
		const extension::group_t group = extension::group_t::GC256B;
		// Получаем опознаватель набора параметров кривой обмена ключами
		const char * oid = extension::curve(group);
		// Объект кривой обмена мимолётными ключами
		curve::curve_t elliptic;
		// Если кривую обмена мимолётными ключами завести не удалось
		if((oid == nullptr) || !curve::parameters(oid, elliptic))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Секретный мимолётный ключ враждебного клиента
		vector <uint8_t> secret(elliptic.size(), 0);
		// Открытый мимолётный ключ враждебного клиента
		vector <uint8_t> opened(elliptic.size() * 2, 0);
		// Если мимолётную пару ключей враждебного клиента выработать не удалось
		if(!agreement::generate(elliptic, secret.data(), opened.data()))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Составляемое приветствие враждебного клиента
		hello::client_t greeting;
		// Устанавливаем издание протокола, доставшееся от предыдущих изданий
		greeting.version = 0x0303;
		// Устанавливаем опознаватель связи приветствия
		greeting.session.assign(hello::HELLO_SESSION, 0x33);
		// Устанавливаем предлагаемый набор шифрования
		greeting.suites.push_back(static_cast <uint16_t> (protect::suite_t::MAGMA_MGM_L));
		// Устанавливаем перечень способов сжатия
		greeting.methods.assign(1, 0x00);
		/**
		 * Выполняем набивку случайного значения приветствия
		 */
		for(size_t i = 0; i < hello::HELLO_RANDOM; i++)
			// Записываем очередной байт случайного значения приветствия
			greeting.random[i] = static_cast <uint8_t> (0x40 + i);
		// Накопители, в которых лежат тела расширений приветствия
		vector <vector <uint8_t>> bodies(4);
		// Если перечень изданий протокола составить не удалось
		if(extension::versions(vector <uint16_t> (1, 0x0304), bodies[0]) != extension::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Добавляем расширение перечня изданий протокола
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(bodies[0].data(), bodies[0].size())));
		// Если перечень кривых обмена ключами составить не удалось
		if(extension::groups(vector <extension::group_t> (1, group), bodies[1]) != extension::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Добавляем расширение перечня кривых обмена ключами
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS), view_t(bodies[1].data(), bodies[1].size())));
		// Схемы подписи, предлагаемые враждебным клиентом
		const vector <extension::scheme_t> schemes = {
			extension::scheme_t::S256A, extension::scheme_t::S256B,
			extension::scheme_t::S256C, extension::scheme_t::S256D,
			extension::scheme_t::S512A, extension::scheme_t::S512B,
			extension::scheme_t::S512C
		};
		// Если перечень схем подписи составить не удалось
		if(extension::schemes(schemes, bodies[2]) != extension::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Добавляем расширение перечня схем подписи
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(bodies[2].data(), bodies[2].size())));
		// Если перечень открытых частей ключей обмена составить не удалось
		if(extension::shares(vector <extension::share_t> (1, extension::share_t(group, view_t(opened.data(), opened.size()))), bodies[3]) != extension::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Добавляем расширение открытых частей ключей обмена
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(bodies[3].data(), bodies[3].size())));
		// Накопитель, в который складывается тело приветствия клиента
		vector <uint8_t> body;
		// Если тело приветствия враждебного клиента составить не удалось
		if(hello::build(greeting, body) != hello::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект составителя отправляемых сообщений рукопожатия
		handshake::writer_t writer;
		// Если приветствие враждебного клиента составить не удалось
		if(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())) != handshake::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект переписки рукопожатия враждебного клиента
		session::transcript_t transcript;
		// Заводим переписку рукопожатия враждебного клиента
		transcript.start();
		// Если приветствие клиента в переписку добавить не удалось
		if(transcript.update(writer.data()) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект нарезчика отправляемых записей
		record::writer_t plain;
		// Если приветствие враждебного клиента на записи нарезать не удалось
		if(plain.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()) != record::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Выполняем подачу приветствия враждебного клиента серверу
		if(server.push(plain.data()) != context::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Получаем байты, отправленные сервером в ответ
		const view_t sending = server.output();
		// Если сервер приветствию не ответил
		if(sending.size == 0)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Выполняем перенос отправленных сервером байтов
		const vector <uint8_t> wire(sending.data, sending.data + sending.size);
		// Снимаем отправленные байты с накопителя сервера
		server.consume(wire.size());
		// Объект сборщика записей, принятых от сервера
		record::reader_t records;
		// Если принятые байты сборщику записей подать не удалось
		if(records.push(view_t(wire.data(), wire.size())) != record::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Заголовок записи приветствия сервера
		record::header_t header;
		// Содержимое записи приветствия сервера
		view_t payload;
		// Если запись приветствия сервера прочитать не удалось
		if(records.next(header, payload) != record::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект сборщика принимаемых сообщений рукопожатия
		handshake::reader_t messages;
		// Если содержимое записи сборщику сообщений подать не удалось
		if(messages.push(payload) != handshake::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Заголовок принятого сообщения рукопожатия
		handshake::header_t message;
		// Тело принятого сообщения рукопожатия
		view_t taken;
		// Если приветствие сервера прочитать не удалось
		if((messages.next(message, taken) != handshake::error_t::NONE) || (message.type != handshake::type_t::SERVER))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Если приветствие сервера в переписку добавить не удалось
		if(transcript.update(messages.message()) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Разбираемое приветствие сервера
		hello::server_t answer;
		// Если приветствие сервера разобрать не удалось
		if(hello::parse(taken, answer) != hello::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Разыскиваем расширение открытой части ключа обмена сервера
		const hello::extension_t * extension = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
		// Если открытой части ключа обмена приветствие сервера не несёт
		if(extension == nullptr)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Открытая часть ключа обмена, присланная сервером
		extension::share_t share(extension::group_t::NONE, view_t(nullptr, 0));
		// Если открытую часть ключа обмена разобрать не удалось
		if(extension::share(extension->data, share) != extension::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Место, в которое помещается общее значение обмена мимолётными ключами
		uint8_t common[64];
		// Если общее значение обмена мимолётными ключами выработать не удалось
		if(!agreement::ecdhe(elliptic, view_t(secret.data(), secret.size()), share.key, common))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t digest[schedule::SCHEDULE_SECRET];
		// Если хеш переписки рукопожатия получить не удалось
		if(transcript.digest(digest) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект значений расписания ключей враждебного клиента
		session::secrets_t secrets;
		// Если начальную ступень расписания ключей завести не удалось
		if(secrets.start(view_t(nullptr, 0)) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Если ступень рукопожатия расписания ключей вывести не удалось
		if(secrets.handshake(view_t(common, elliptic.size()), view_t(digest, sizeof(digest))) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Получаем набор шифрования, выбранный сервером
		const protect::suite_t suite = static_cast <protect::suite_t> (answer.suite);
		// Место, в которое помещается ключ завершения рукопожатия клиента
		uint8_t completion[schedule::SCHEDULE_SECRET];
		// Если ключ завершения рукопожатия вывести не удалось
		if(secrets.finished(session::side_t::CLIENT, completion) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Корневой ключ направления связи
		uint8_t material[protect::PROTECT_KEY];
		// Вектор замены направления связи
		uint8_t element[protect::PROTECT_VECTOR];
		// Если ключевой материал направления связи сервера вывести не удалось
		if(secrets.material(session::side_t::SERVER, suite, material, element) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект защиты записей, принимаемых от сервера
		protect::protection_t incoming;
		// Если ключевой материал направления связи сервера установить не удалось
		if(!incoming.start(suite, view_t(material, sizeof(material)), view_t(element, protect::block(suite))))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		/**
		 * Выполняем перебор записей рукопожатия, принятых от сервера
		 */
		while(records.pending() > 0){
			// Заголовок очередной принятой записи
			record::header_t taking;
			// Содержимое очередной принятой записи
			view_t sealed;
			// Если очередную запись прочитать не удалось
			if(records.next(taking, sealed) != record::error_t::NONE)
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Вид содержимого, вскрытого из принятой записи
			record::type_t kind = record::type_t::NONE;
			// Накопитель, в который складывается вскрытое содержимое
			vector <uint8_t> unsealed;
			// Если снять защиту с принятой записи не удалось
			if(incoming.open(taking, sealed, kind, unsealed) != protect::error_t::NONE)
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Если вскрытое содержимое сообщением рукопожатия не является
			if(kind != record::type_t::HANDSHAKE)
				// Переходим к следующей принятой записи
				continue;
			// Объект сборщика сообщений, принятых от сервера
			handshake::reader_t taker;
			// Если вскрытое содержимое сборщику сообщений подать не удалось
			if(taker.push(view_t(unsealed.data(), unsealed.size())) != handshake::error_t::NONE)
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Заголовок очередного принятого сообщения рукопожатия
			handshake::header_t item;
			// Тело очередного принятого сообщения рукопожатия
			view_t content;
			/**
			 * Выполняем перебор сообщений рукопожатия, принятых от сервера
			 */
			while(taker.next(item, content) == handshake::error_t::NONE){
				// Если сообщение в переписку рукопожатия добавить не удалось
				if(transcript.update(taker.message()) != session::error_t::NONE)
					// Выводим отказ рукопожатия враждебного клиента
					return false;
			}
		}
		// Если ключевой материал направления связи клиента вывести не удалось
		if(secrets.material(session::side_t::CLIENT, suite, material, element) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект защиты записей враждебного клиента
		protect::protection_t protection;
		// Если ключевой материал направления связи клиента установить не удалось
		if(!protection.start(suite, view_t(material, sizeof(material)), view_t(element, protect::block(suite))))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Накопитель, в который складывается ответ враждебного клиента
		vector <uint8_t> answered;
		// Если враждебный клиент предъявляет свою подлинность
		if(distortion == distortion_t::CONTEXT){
			// Если подлинность враждебного клиента проверкой не задана
			if((credential == nullptr) || credential->chain.empty())
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Составляемая цепочка сертификатов враждебного клиента
			message::certificate_t certificate;
			// Опознаватель запроса подлинности, набиваемый враждебным клиентом
			const uint8_t identifier[] = {0x0A, 0x0B, 0x0C, 0x0D};
			/**
			 * Раздел 4.4.2 RFC 8446 велит клиенту повторять опознаватель запроса,
			 * присланный сервером, а сервер шлёт его пустым: опознаватель, взятый
			 * с потолка, отвечает не тому запросу, который был сделан
			 */
			certificate.context = view_t(identifier, sizeof(identifier));
			// Запись цепочки сертификатов враждебного клиента
			message::entry_t entry;
			// Устанавливаем тело сертификата записи цепочки
			entry.data = view_t(credential->chain[0].data(), credential->chain[0].size());
			// Добавляем запись в цепочку сертификатов
			certificate.entries.push_back(entry);
			// Накопитель, в который складывается тело цепочки сертификатов
			vector <uint8_t> chain;
			// Если тело цепочки сертификатов составить не удалось
			if(message::build(certificate, chain) != message::error_t::NONE)
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Если цепочку сертификатов враждебного клиента отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::CERTIFICATE, view_t(chain.data(), chain.size()), answered))
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Накопитель, в который складывается тело подписи владения ключом
			vector <uint8_t> witnessed;
			// Если подпись владения ключом враждебного клиента выработать не удалось
			if(!possession(* credential, transcript, false, witnessed))
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Если подпись владения ключом враждебного клиента отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::VERIFY, view_t(witnessed.data(), witnessed.size()), answered))
				// Выводим отказ рукопожатия враждебного клиента
				return false;
		}
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t hash[schedule::SCHEDULE_SECRET];
		// Если хеш переписки рукопожатия получить не удалось
		if(transcript.digest(hash) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Место, в которое помещается завершение рукопожатия клиентом
		uint8_t completed[32];
		// Если завершение рукопожатия выработать не удалось
		if(message::finished(view_t(completion, sizeof(completion)), view_t(hash, sizeof(hash)), completed) != message::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Если завершение рукопожатия враждебного клиента отправить не удалось
		if(!deliver(protection, transcript, handshake::type_t::FINISHED, view_t(completed, sizeof(completed)), answered))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Выполняем подачу ответа враждебного клиента серверу
		server.push(view_t(answered.data(), answered.size()));
		// Выводим успешность рукопожатия враждебного клиента
		return true;
	}
};

#endif // __ANTS_TESTS_ADVERSARY__
