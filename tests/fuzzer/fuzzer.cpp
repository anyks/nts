/**
 * @file fuzzer.cpp
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
 * @brief Исходный файл ворошителя разборщиков недоверенных данных
 *
 * @details Всё, что приходит связи по сети, приходит от того, кто её и ломает: разборщики
 *          записей, сообщений рукопожатия, расширений и сертификатов работают по данным,
 *          которых никто не обещал. Ворошитель эти данные и подделывает - искажением
 *          настоящего потока и подачей случайного.
 *
 * @note Ворошитель ходит по одному и тому же ряду значений при всяком прогоне: своё зерно
 *       задано числом, и находка его повторима. Случайное зерно давало бы находку, которую
 *       нельзя ни воспроизвести, ни закрепить проверкой
 *
 * @note Забор случайного значения идёт отдельным действием: два забора внутри одного
 *       вызова легли бы порядком, который стандарт языка не определяет, и ряд значений
 *       разошёлся бы между собирателями
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <identity.hpp>
#include <pem/pem.hpp>
#include <x509/x509.hpp>
#include <alert/alert.hpp>
#include <hello/hello.hpp>
#include <record/record.hpp>
#include <message/message.hpp>
#include <handshake/handshake.hpp>
#include <extension/extension.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * @brief Служебные объекты ворошителя
 *
 */
namespace {
	/**
	 * @brief Направление передачи байтов между сторонами связи
	 *
	 */
	enum class course_t : uint8_t {
		NONE   = 0x00, // Ворошение потока не ведётся
		CLIENT = 0x01, // Ворошится поток, идущий от клиента к серверу
		SERVER = 0x02  // Ворошится поток, идущий от сервера к клиенту
	};

	/**
	 * @brief Источник повторимых случайных значений
	 *
	 */
	typedef class Random {
		private:
			// Состояние источника случайных значений
			uint64_t _state;
		public:
			/**
			 * @brief Метод получения очередного случайного значения
			 *
			 * @return очередное случайное значение источника
			 *
			 */
			uint64_t next() noexcept {
				// Выполняем перемешивание состояния источника
				this->_state ^= (this->_state << 13);
				// Выполняем перемешивание состояния источника
				this->_state ^= (this->_state >> 7);
				// Выполняем перемешивание состояния источника
				this->_state ^= (this->_state << 17);
				// Выводим очередное случайное значение источника
				return this->_state;
			}
			/**
			 * @brief Метод получения случайного значения ниже предела
			 *
			 * @param limit предел получаемого случайного значения
			 *
			 * @return      случайное значение ниже переданного предела
			 *
			 */
			size_t below(const size_t limit) noexcept {
				// Если предел случайного значения не задан
				if(limit == 0)
					// Выводим нулевое случайное значение
					return 0;
				// Выводим случайное значение ниже переданного предела
				return static_cast <size_t> (this->next() % limit);
			}
		public:
			/**
			 * @brief Конструктор
			 *
			 * @param seed зерно источника случайных значений
			 *
			 */
			Random(const uint64_t seed) noexcept : _state(seed | 0x01) {}
	} random_t;

	/**
	 * @brief Метод передачи накопленных байтов между сторонами связи
	 *
	 * @param client  связь стороны клиента
	 * @param server  связь стороны сервера
	 * @param course  направление, поток которого ворошится
	 * @param target  место ворошимого байта в потоке направления
	 * @param mask    разряды, которыми ворошится байт потока
	 * @param streams потоки байтов направлений передачи
	 * @param chunk   размер куска, которым байты подаются встречной стороне
	 *
	 * @return        признак того, что байты между сторонами передавались
	 *
	 * @note Поток каждого направления складывается таким, каким он ушёл встречной
	 *       стороне: ворошение ложится в него вместе с байтами
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server, const course_t course, const size_t target, const uint8_t mask, vector <uint8_t> (& streams)[2], const size_t chunk) noexcept {
		// Признак того, что байты между сторонами передавались
		bool moved = false;
		/**
		 * Выполняем перебор направлений передачи байтов между сторонами связи
		 */
		for(size_t i = 0; i < 2; i++){
			// Получаем байты, отправляемые стороной связи
			const view_t data = ((i == 0) ? client.output() : server.output());
			// Если стороне связи отправлять нечего
			if(data.size == 0)
				// Переходим к встречному направлению передачи байтов
				continue;
			// Выполняем перенос отправляемых байтов
			vector <uint8_t> buffer(data.data, data.data + data.size);
			// Если байты клиента снять с накопителя не удалось
			if(i == 0)
				// Снимаем отправленные байты с накопителя клиента
				client.consume(buffer.size());
			// Снимаем отправленные байты с накопителя сервера
			else server.consume(buffer.size());
			// Получаем направление передачи переносимых байтов
			const course_t moving = ((i == 0) ? course_t::CLIENT : course_t::SERVER);
			// Если ворошится именно это направление передачи байтов
			if((course == moving) && (target >= streams[i].size()) && (target < (streams[i].size() + buffer.size())))
				// Выполняем ворошение байта потока направления
				buffer[target - streams[i].size()] ^= mask;
			// Складываем переносимые байты в поток направления
			streams[i].insert(streams[i].end(), buffer.begin(), buffer.end());
			/**
			 * Выполняем подачу отправленных байтов встречной стороне кусками
			 */
			for(size_t offset = 0; offset < buffer.size(); offset += chunk){
				// Получаем размер очередного подаваемого куска
				const size_t size = (((buffer.size() - offset) < chunk) ? (buffer.size() - offset) : chunk);
				// Если байты клиента подаются серверу
				if(i == 0)
					// Выполняем подачу очередного куска стороне сервера
					server.push(view_t(buffer.data() + offset, size));
				// Выполняем подачу очередного куска стороне клиента
				else client.push(view_t(buffer.data() + offset, size));
			}
			// Запоминаем, что байты между сторонами передавались
			moved = true;
		}
		// Выводим признак того, что байты между сторонами передавались
		return moved;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон связи
	 *
	 * @param credentials подлинность стороны сервера
	 * @param course      направление, поток которого ворошится
	 * @param target      место ворошимого байта в потоке направления
	 * @param mask        разряды, которыми ворошится байт потока
	 * @param streams     потоки байтов направлений передачи
	 * @param chunk       размер куска, которым байты подаются встречной стороне
	 * @param established признаки установленности связи сторонами
	 *
	 */
	void converse(const context::credential_t & credentials, const course_t course, const size_t target, const uint8_t mask, vector <uint8_t> (& streams)[2], const size_t chunk, bool (& established)[2]) noexcept {
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Выполняем сброс потока байтов клиента
		streams[0].clear();
		// Выполняем сброс потока байтов сервера
		streams[1].clear();
		// Выполняем сброс признака установленности связи клиентом
		established[0] = false;
		// Выполняем сброс признака установленности связи сервером
		established[1] = false;
		// Если связь стороны сервера завести не удалось
		if(server.start() != context::error_t::NONE)
			// Выходим из проведения рукопожатия сторон связи
			return;
		// Если связь стороны клиента завести не удалось
		if(client.start() != context::error_t::NONE)
			// Выходим из проведения рукопожатия сторон связи
			return;
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server, course, target, mask, streams, chunk); i++)
			// Продолжаем передачу байтов между сторонами связи
			continue;
		// Запоминаем установленность связи стороной клиента
		established[0] = client.established();
		// Запоминаем установленность связи стороной сервера
		established[1] = server.established();
	}
	/**
	 * @brief Метод проверки того, что ворошение хода рукопожатия не меняет
	 *
	 * @param stream ворошимый поток байтов направления
	 * @param target место ворошимого байта в потоке направления
	 *
	 * @return       признак того, что ворошение хода рукопожатия не меняет
	 *
	 * @details Раздел 5.1 RFC 8446 велит издание записи протокола пропускать без разбора:
	 *          два его байта - единственные в потоке, ворошение которых ход рукопожатия
	 *          оставляет прежним
	 *
	 */
	bool ignorable(const vector <uint8_t> & stream, const size_t target) noexcept {
		/**
		 * Выполняем перебор записей потока направления
		 */
		for(size_t offset = 0; (offset + record::RECORD_HEADER) <= stream.size();){
			// Если ворошимый байт лежит в издании записи протокола
			if((target == (offset + 1)) || (target == (offset + 2)))
				// Выводим признак того, что ворошение хода рукопожатия не меняет
				return true;
			// Получаем длину тела очередной записи потока
			const size_t length = ((static_cast <size_t> (stream[offset + 3]) << 8) | static_cast <size_t> (stream[offset + 4]));
			// Переходим к следующей записи потока направления
			offset += (record::RECORD_HEADER + length);
		}
		// Выводим признак того, что ворошение ход рукопожатия меняет
		return false;
	}
	/**
	 * @brief Метод выработки случайной области байтов
	 *
	 * @param roller источник случайных значений
	 * @param size   размер вырабатываемой области байтов
	 *
	 * @return       выработанная область байтов
	 *
	 */
	vector <uint8_t> blob(random_t & roller, const size_t size) noexcept {
		// Заводим вырабатываемую область байтов
		vector <uint8_t> result(size, 0);
		/**
		 * Выполняем заполнение вырабатываемой области байтов
		 */
		for(size_t i = 0; i < size; i++)
			// Записываем очередной случайный байт области
			result[i] = static_cast <uint8_t> (roller.next() & 0xFF);
		// Выводим выработанную область байтов
		return result;
	}
	/**
	 * @brief Метод обхода записи ASN.1 во всю её глубину
	 *
	 * @param reader разборщик обходимой записи ASN.1
	 * @param depth  глубина, на которой ведётся обход записи
	 *
	 */
	void walk(asn1::Reader & reader, const size_t depth) noexcept {
		// Если предельная глубина обхода записи превышена
		if(depth > 8)
			// Выходим из обхода записи ASN.1
			return;
		// Разбираемый элемент записи ASN.1
		asn1::element_t element;
		/**
		 * Выполняем перебор всех элементов записи ASN.1
		 */
		while(reader.next(element)){
			// Если элемент записи имеет составной вид метки
			if(element.constructed){
				// Заводим разборщик содержимого составного элемента
				asn1::Reader inner = reader.enter(element);
				// Выполняем обход содержимого составного элемента
				walk(inner, depth + 1);
			}
		}
	}
	/**
	 * @brief Метод подачи области байтов всем разборщикам недоверенных данных
	 *
	 * @param data подаваемая разборщикам область байтов
	 *
	 */
	void feed(const view_t & data) noexcept {
		// Заводим разборщик записи ASN.1
		asn1::Reader reader(data);
		// Выполняем обход записи ASN.1 во всю её глубину
		walk(reader, 0);
		// Разбираемый сертификат стороны связи
		x509::certificate_t certificate;
		// Выполняем разбор сертификата стороны связи
		certificate.parse(data);
		// Разбираемый заголовок записи протокола
		record::header_t header;
		// Выполняем разбор заголовка записи протокола
		record::parse(data, header);
		// Разбираемый заголовок сообщения рукопожатия
		handshake::header_t heading;
		// Выполняем разбор заголовка сообщения рукопожатия
		handshake::parse(data, heading);
		// Разбираемое извещение связи
		alert::alert_t notice;
		// Выполняем разбор извещения связи
		alert::parse(data, notice);
		// Разбираемое приветствие клиента
		hello::client_t greeting;
		// Выполняем разбор приветствия клиента
		hello::parse(data, greeting);
		// Разбираемое приветствие сервера
		hello::server_t answer;
		// Выполняем разбор приветствия сервера
		hello::parse(data, answer);
		// Разбираемая цепочка сертификатов собеседника
		message::certificate_t chain;
		// Выполняем разбор цепочки сертификатов собеседника
		message::parse(data, chain);
		// Разбираемая подпись владения ключом
		message::verify_t signature;
		// Выполняем разбор подписи владения ключом
		message::parse(data, signature);
		// Разбираемый билет возобновления связи
		message::ticket_t ticket;
		// Выполняем разбор билета возобновления связи
		message::parse(data, ticket);
		// Разбираемое требование смены ключей
		message::update_t update;
		// Выполняем разбор требования смены ключей
		message::parse(data, update);
		// Разбираемое имя запрашиваемого узла
		view_t name;
		// Выполняем разбор имени запрашиваемого узла
		extension::name(data, name);
		// Разбираемый перечень прикладных протоколов
		vector <string> protocols;
		// Выполняем разбор перечня прикладных протоколов
		extension::protocols(data, protocols);
		// Разбираемый перечень открытых частей ключей обмена
		vector <extension::share_t> shares;
		// Выполняем разбор перечня открытых частей ключей обмена
		extension::shares(data, shares);
		// Разбираемый перечень кривых обмена ключами
		vector <extension::group_t> groups;
		// Выполняем разбор перечня кривых обмена ключами
		extension::groups(data, groups);
		// Разбираемый перечень заранее разделённых ключей
		vector <extension::identity_t> identities;
		// Разбираемые привязки заранее разделённых ключей
		vector <view_t> binders;
		// Место, по которое переписка привязки идёт
		size_t truncation = 0;
		// Выполняем разбор предложения заранее разделённых ключей
		extension::identities(data, identities, binders, truncation);
	}
};

/**
 * Проверка независимости разбора потока от нарезки его на куски
 */
TEST(FuzzerTest, Chunks){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Потоки байтов направлений передачи
	vector <uint8_t> streams[2];
	// Признаки установленности связи сторонами
	bool established[2] = {false, false};
	// Длины потоков направлений при подаче их целиком
	size_t lengths[2] = {0, 0};
	/**
	 * Выполняем перебор размеров куска, которыми байты подаются стороне
	 */
	for(const size_t chunk : {static_cast <size_t> (4096), static_cast <size_t> (1), static_cast <size_t> (2), static_cast <size_t> (3), static_cast <size_t> (5), static_cast <size_t> (7), static_cast <size_t> (13), static_cast <size_t> (64)}){
		// Выполняем проведение рукопожатия сторон связи
		converse(credentials, course_t::NONE, 0, 0, streams, chunk, established);
		/**
		 * Разбор потока обязан не зависеть от того, какими кусками поток пришёл: границ
		 * записей связь не выбирает, и приход потока по одному байту от прихода целиком
		 * ничем отличаться не вправе
		 */
		ASSERT_TRUE(established[0]) << "размер куска " << chunk;
		// Проверяем установленность связи стороной сервера
		ASSERT_TRUE(established[1]) << "размер куска " << chunk;
		// Если поток направлений подавался целиком
		if(chunk == 4096){
			// Запоминаем длину потока стороны клиента
			lengths[0] = streams[0].size();
			// Запоминаем длину потока стороны сервера
			lengths[1] = streams[1].size();
		// Проверяем схождение длины потока клиента с подачей потока целиком
		} else ASSERT_EQ(streams[0].size(), lengths[0]) << "размер куска " << chunk;
	}
}

/**
 * Проверка отвержения искажённого потока рукопожатия
 */
TEST(FuzzerTest, Corruption){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Потоки байтов направлений передачи
	vector <uint8_t> streams[2];
	// Признаки установленности связи сторонами
	bool established[2] = {false, false};
	// Выполняем проведение чистого рукопожатия сторон связи
	converse(credentials, course_t::NONE, 0, 0, streams, 4096, established);
	// Проверяем установленность связи сторонами при чистом рукопожатии
	ASSERT_TRUE(established[0] && established[1]);
	// Запоминаем чистые потоки байтов направлений передачи
	const vector <uint8_t> clean[2] = {streams[0], streams[1]};
	// Заводим источник повторимых случайных значений
	random_t roller(0x414E594B53544C53);
	/**
	 * Выполняем перебор ворошений потока рукопожатия
	 */
	for(size_t i = 0; i < 128; i++){
		// Получаем направление, поток которого ворошится
		const course_t course = (((i % 2) == 0) ? course_t::CLIENT : course_t::SERVER);
		// Получаем место ворошимого потока среди направлений
		const size_t side = ((course == course_t::CLIENT) ? 0 : 1);
		// Получаем место ворошимого байта в потоке направления
		const size_t target = roller.below(clean[side].size());
		// Получаем разряд, которым ворошится байт потока
		const uint8_t mask = static_cast <uint8_t> (1 << roller.below(8));
		// Если ворошение хода рукопожатия менять не должно
		if(ignorable(clean[side], target))
			// Переходим к следующему ворошению потока рукопожатия
			continue;
		// Выполняем проведение рукопожатия сторон связи с ворошением потока
		converse(credentials, course, target, mask, streams, 4096, established);
		/**
		 * Всякий байт потока, кроме издания записи, прикрыт: приветствия ложатся в
		 * переписку и сличаются завершением рукопожатия, а всё, что идёт за ними,
		 * прикрыто защитой записей
		 */
		ASSERT_FALSE(established[(side == 0) ? 1 : 0]) << "место " << target << " разряд " << static_cast <uint16_t> (mask);
	}
}

/**
 * Проверка подачи связи случайного потока байтов
 */
TEST(FuzzerTest, Garbage){
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Выполняем выработку подлинности стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Заводим источник повторимых случайных значений
	random_t roller(0x5F4C4F42415245);
	/**
	 * Выполняем перебор подач случайного потока байтов
	 */
	for(size_t i = 0; i < 256; i++){
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Выполняем заведение связи стороны сервера
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Получаем размер вырабатываемого потока байтов
		const size_t size = roller.below(512);
		// Вырабатываем случайный поток байтов
		const vector <uint8_t> data = blob(roller, size + 1);
		// Выполняем подачу случайного потока байтов связи
		server.push(view_t(data.data(), data.size()));
		/**
		 * Случайный поток связи не установит: до установления её ведёт рукопожатие, а
		 * пройти его случайными байтами нельзя ни при какой их череде
		 */
		ASSERT_FALSE(server.established());
		/**
		 * Оборванная связь обязана назвать отказ, которым она оборвана: молчаливый
		 * обрыв неотличим от обрыва по причине, которой не разобрали
		 */
		ASSERT_TRUE((server.state() != context::state_t::FAILED) || (server.error() != context::error_t::NONE));
	}
}

/**
 * Проверка подачи разборщикам случайных областей байтов
 */
TEST(FuzzerTest, Parsers){
	// Заводим источник повторимых случайных значений
	random_t roller(0x504152534552);
	/**
	 * Выполняем перебор подач случайных областей байтов
	 */
	for(size_t i = 0; i < 2048; i++){
		// Получаем размер вырабатываемой области байтов
		const size_t size = roller.below(256);
		// Вырабатываем случайную область байтов
		const vector <uint8_t> data = blob(roller, size);
		// Выполняем подачу случайной области байтов всем разборщикам
		feed(view_t(data.data(), data.size()));
	}
	/**
	 * Непереданная область байтов - это тоже недоверенные данные: разборщик обязан
	 * ответить на неё отказом, а не разбирать её вовсе
	 */
	feed(view_t(nullptr, 0));
}

/**
 * Проверка подачи разборщику записей PEM случайного текста
 */
TEST(FuzzerTest, Storage){
	// Заводим источник повторимых случайных значений
	random_t roller(0x50454D5F464B);
	/**
	 * Выполняем перебор подач случайного текста
	 */
	for(size_t i = 0; i < 512; i++){
		// Заводим подаваемый разборщику текст
		string text = "-----BEGIN ";
		// Получаем размер вырабатываемой метки записи
		const size_t title = roller.below(16);
		// Вырабатываем случайную область байтов метки записи
		const vector <uint8_t> label = blob(roller, title);
		/**
		 * Выполняем перебор случайной области байтов метки записи
		 */
		for(size_t j = 0; j < label.size(); j++)
			// Записываем очередной знак метки записи
			text.append(1, static_cast <char> (0x20 + (label[j] % 0x5F)));
		// Записываем ограду рамки начала записи
		text.append("-----\n");
		// Получаем размер вырабатываемого тела записи
		const size_t length = roller.below(128);
		// Вырабатываем случайную область байтов тела записи
		const vector <uint8_t> body = blob(roller, length);
		/**
		 * Выполняем перебор случайной области байтов тела записи
		 */
		for(size_t j = 0; j < body.size(); j++)
			// Записываем очередной знак тела записи
			text.append(1, static_cast <char> (0x20 + (body[j] % 0x5F)));
		// Записываем рамку конца записи
		text.append("\n-----END DATA-----\n");
		// Разобранные записи текста
		vector <pem::block_t> blocks;
		// Выполняем разбор случайного текста
		pem::decode(text, blocks);
		// Извлечённый из случайного текста секретный ключ
		vector <uint8_t> secret;
		// Выполняем извлечение секретного ключа из случайного текста
		pem::secret(text, secret);
	}
}

/**
 * Проверка отвержения разборщиками непереданной области байтов
 */
TEST(FuzzerTest, Emptiness){
	// Область байтов, у которой нет ни начала, ни длины
	const view_t empty(nullptr, 0);
	// Разбираемый сертификат стороны связи
	x509::certificate_t certificate;
	/**
	 * Непереданная область байтов - это тоже недоверенные данные: разбор её обязан
	 * ответить отказом, а не разобрать в пустую, но годную запись
	 */
	ASSERT_NE(certificate.parse(empty), x509::error_t::NONE);
	// Разбираемый заголовок записи протокола
	record::header_t header;
	// Проверяем отказ разбора заголовка записи протокола
	ASSERT_NE(record::parse(empty, header), record::error_t::NONE);
	// Разбираемый заголовок сообщения рукопожатия
	handshake::header_t heading;
	// Проверяем отказ разбора заголовка сообщения рукопожатия
	ASSERT_NE(handshake::parse(empty, heading), handshake::error_t::NONE);
	// Разбираемое извещение связи
	alert::alert_t notice;
	// Проверяем отказ разбора извещения связи
	ASSERT_NE(alert::parse(empty, notice), alert::error_t::NONE);
	// Разбираемое приветствие клиента
	hello::client_t greeting;
	// Проверяем отказ разбора приветствия клиента
	ASSERT_NE(hello::parse(empty, greeting), hello::error_t::NONE);
	// Разбираемое приветствие сервера
	hello::server_t answer;
	// Проверяем отказ разбора приветствия сервера
	ASSERT_NE(hello::parse(empty, answer), hello::error_t::NONE);
	// Разбираемая цепочка сертификатов собеседника
	message::certificate_t chain;
	// Проверяем отказ разбора цепочки сертификатов собеседника
	ASSERT_NE(message::parse(empty, chain), message::error_t::NONE);
	// Разбираемая подпись владения ключом
	message::verify_t signature;
	// Проверяем отказ разбора подписи владения ключом
	ASSERT_NE(message::parse(empty, signature), message::error_t::NONE);
	// Разбираемый билет возобновления связи
	message::ticket_t ticket;
	// Проверяем отказ разбора билета возобновления связи
	ASSERT_NE(message::parse(empty, ticket), message::error_t::NONE);
	// Разбираемое требование смены ключей
	message::update_t update;
	// Проверяем отказ разбора требования смены ключей
	ASSERT_NE(message::parse(empty, update), message::error_t::NONE);
	// Разбираемое имя запрашиваемого узла
	view_t name;
	// Проверяем отказ разбора имени запрашиваемого узла
	ASSERT_NE(extension::name(empty, name), extension::error_t::NONE);
	// Разбираемый перечень прикладных протоколов
	vector <string> protocols;
	// Проверяем отказ разбора перечня прикладных протоколов
	ASSERT_NE(extension::protocols(empty, protocols), extension::error_t::NONE);
	// Разбираемый перечень открытых частей ключей обмена
	vector <extension::share_t> shares;
	// Проверяем отказ разбора перечня открытых частей ключей обмена
	ASSERT_NE(extension::shares(empty, shares), extension::error_t::NONE);
	// Разбираемый перечень кривых обмена ключами
	vector <extension::group_t> groups;
	// Проверяем отказ разбора перечня кривых обмена ключами
	ASSERT_NE(extension::groups(empty, groups), extension::error_t::NONE);
	// Извлечённый из пустого текста секретный ключ
	vector <uint8_t> secret;
	// Проверяем отказ извлечения секретного ключа из пустого текста
	ASSERT_NE(pem::secret(string(), secret), pem::error_t::NONE);
	// Заводим разборщик пустой записи ASN.1
	asn1::Reader reader(empty);
	// Разбираемый элемент записи ASN.1
	asn1::element_t element;
	// Проверяем отсутствие элементов у пустой записи ASN.1
	ASSERT_FALSE(reader.next(element));
}
