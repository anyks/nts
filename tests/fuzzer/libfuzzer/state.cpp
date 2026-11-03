/**
 * @file state.cpp
 * @date 2026-11-02
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
 * @brief Ворошитель машин состояний TLS и DTLS с управлением от покрытия
 *
 * @note Первые байты входа выбирают протокол, нарезку потока либо размер MTU,
 *       потери, повторы, обрыв и порчу, а остаток идёт в прикладной обмен.
 *       Чистый сценарий обязан установить связь; отрицательный лишь не должен
 *       нарушить память, состояние отказа либо диагностику
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>

/**
 * Подключаем заголовочные файлы проекта и проверочной оснастки
 */
#include <gost.hpp>
#include <identity.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Служебные объекты ворошителя машин состояний
 */
namespace {
	/**
	 * Управляющие разряды сценария
	 */
	// Намеренный обрыв рукопожатия
	static constexpr uint8_t TRUNCATE  = 0x01;
	// Повтор приветствия TLS либо перестановка дейтаграмм
	static constexpr uint8_t REORDER   = 0x02;
	// Смена ключей клиентом либо повтор дейтаграммы
	static constexpr uint8_t DUPLICATE = 0x04;
	// Смена ключей сервером либо периодические потери
	static constexpr uint8_t LOSS      = 0x08;
	// Намеренная порча байта переноса
	static constexpr uint8_t DAMAGE    = 0x10;
	// Закрытие связи после прикладного обмена
	static constexpr uint8_t CLOSE     = 0x20;
	// Выдача и проверка билета возобновления
	static constexpr uint8_t RESUME    = 0x40;
	// Смена ключей обеими сторонами DTLS
	static constexpr uint8_t UPDATE    = 0x80;
	/**
	 * Подлинность сторон, вырабатываемая один раз на процесс ворошителя
	 */
	context::credential_t credentials;
	/**
	 * Признак готовности подлинности сторон
	 */
	bool ready = false;
	/**
	 * Настройки переноса одного сценария
	 */
	typedef struct Settings {
		// Управляющие разряды сценария
		uint8_t flags;
		// Длина куска потока TLS
		size_t chunk;
		// Размер дейтаграммы DTLS
		size_t mtu;
		// Круг намеренного обрыва
		size_t stop;
		// Круг повтора либо порчи
		size_t special;
		// Период потерь DTLS
		size_t period;
		// Смещение портимого байта
		size_t offset;
	} settings_t;
	/**
	 * @brief Функция настройки пары связей одного сценария
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param datagram признак переноса дейтаграммами
	 * @param mtu      размер дейтаграммы
	 *
	 */
	void configure(client::context_t & client, server::context_t & server, const bool datagram, const size_t mtu) noexcept {
		// Объявляем ГОСТ в настройках клиента
		gosting(client);
		// Объявляем ГОСТ в настройках сервера
		gosting(server);
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Если выбран перенос дейтаграммами
		if(datagram){
			// Устанавливаем перенос дейтаграммами клиенту
			client.transport(context::transport_t::DATAGRAMS);
			// Устанавливаем перенос дейтаграммами серверу
			server.transport(context::transport_t::DATAGRAMS);
			// Ограничиваем размер дейтаграмм обеих сторон
			client.mtu(mtu);
			// Ограничиваем размер дейтаграмм сервера
			server.mtu(mtu);
			// Адрес собеседника для метки возврата состояния
			static const uint8_t ADDRESS[] = {10, 0, 0, 1, 0x12, 0x34};
			// Устанавливаем адрес собеседника серверу
			server.address(view_t(ADDRESS, sizeof(ADDRESS)));
		}
	}
	/**
	 * @brief Функция передачи потока между сторонами с заданной нарезкой
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param settings настройки переноса сценария
	 * @param round    номер текущего круга
	 * @param damaged  признак уже выполненной порчи
	 * @return         признак передачи хотя бы одного выходного потока
	 *
	 */
	bool pumpStream(client::context_t & client, server::context_t & server, const settings_t & settings, const size_t round, bool & damaged) noexcept {
		// Признак передачи хотя бы одного выходного потока
		bool moved = false;
		/**
		 * Выполняем перебор направлений передачи
		 */
		for(size_t i = 0; i < 2; i++){
			// Получаем выходной поток очередной стороны
			const view_t data = ((i == 0) ? client.output() : server.output());
			// Если стороне отправлять нечего
			if(data.size == 0)
				// Переходим к встречному направлению
				continue;
			// Переносим выходной поток, чтобы снять его с накопителя
			std::vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем выходной поток с накопителя его стороны
			if(i == 0)
				// Снимаем выходной поток клиента
				client.consume(buffer.size());
			else
				// Снимаем выходной поток сервера
				server.consume(buffer.size());
			// Если в этом круге заказана порча потока
			if(((settings.flags & DAMAGE) != 0) && !damaged && (round == settings.special)){
				// Портим выбранный байт выходного потока
				buffer[settings.offset % buffer.size()] ^= 0x01;
				// Запоминаем, что порча уже выполнена
				damaged = true;
			}
			/**
			 * Выполняем подачу потока кусками заданной длины
			 */
			for(size_t offset = 0; offset < buffer.size(); offset += settings.chunk){
				// Определяем длину очередного куска
				const size_t size = std::min(settings.chunk, buffer.size() - offset);
				// Подаём кусок встречной стороне
				if(i == 0)
					// Подаём кусок клиента серверу
					server.push(view_t(buffer.data() + offset, size));
				else
					// Подаём кусок сервера клиенту
					client.push(view_t(buffer.data() + offset, size));
			}
			// Запоминаем передачу выходного потока
			moved = true;
		}
		// Выводим признак передачи потоков
		return moved;
	}
	/**
	 * @brief Функция проведения потокового рукопожатия с управляемыми повреждениями
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param settings настройки переноса сценария
	 *
	 */
	void converseStream(client::context_t & client, server::context_t & server, const settings_t & settings) noexcept {
		// Сохраняем первое приветствие клиента для повторной подачи
		const view_t greeting = client.output();
		// Переносим приветствие до снятия его с накопителя, если оно уже выдано
		const std::vector <uint8_t> repeated = ((greeting.size > 0) ? std::vector <uint8_t> (greeting.data, greeting.data + greeting.size) : std::vector <uint8_t> ());
		// Признак уже выполненной порчи
		bool damaged = false;
		/**
		 * Выполняем передачу потоков ограниченное число кругов
		 */
		for(size_t round = 0; round < 16; round++){
			// Если связь одной из сторон оборвана
			if((client.state() == context::state_t::FAILED) || (server.state() == context::state_t::FAILED))
				// Прекращаем перенос
				break;
			// Если заказан намеренный обрыв на этом круге
			if(((settings.flags & TRUNCATE) != 0) && (round == settings.stop))
				// Прекращаем перенос без завершения рукопожатия
				break;
			// Если заказана повторная подача первого приветствия
			if(((settings.flags & REORDER) != 0) && (round == settings.special) && !repeated.empty())
				// Подаём сохранённое приветствие повторно
				server.push(view_t(repeated.data(), repeated.size()));
			// Если потоки на этом круге не переносились
			if(!pumpStream(client, server, settings, round, damaged))
				// Прекращаем перенос
				break;
		}
	}
	/**
	 * @brief Функция передачи дейтаграмм одного направления
	 *
	 * @tparam A тип связи отправляющей стороны
	 * @tparam B тип связи принимающей стороны
	 * @param from      отправляющая сторона
	 * @param to        принимающая сторона
	 * @param settings  настройки переноса сценария
	 * @param round     номер текущего круга
	 * @param direction направление переноса для счётчика
	 * @param counters  счётчики дейтаграмм направлений
	 * @param damaged   признак уже выполненной порчи
	 * @return          признак снятия хотя бы одной дейтаграммы
	 *
	 */
	template <typename A, typename B>
	bool carry(A & from, B & to, const settings_t & settings, const size_t round, const size_t direction, size_t (& counters)[2], bool & damaged) noexcept {
		// Снятые дейтаграммы направления
		std::vector <std::vector <uint8_t>> datagrams;
		/**
		 * Выполняем снятие всех готовых дейтаграмм стороны
		 */
		while(from.output().size > 0){
			// Получаем очередную дейтаграмму
			const view_t data = from.output();
			// Переносим дейтаграмму в перечень
			datagrams.push_back(std::vector <uint8_t> (data.data, data.data + data.size));
			// Снимаем дейтаграмму с накопителя
			from.consume(data.size);
		}
		// Если переносить нечего
		if(datagrams.empty())
			// Выводим отсутствие переноса
			return false;
		// Если заказана перестановка дейтаграмм
		if((settings.flags & REORDER) != 0)
			// Переворачиваем порядок переноса
			std::reverse(datagrams.begin(), datagrams.end());
		/**
		 * Выполняем перебор снятых дейтаграмм
		 */
		for(size_t i = 0; i < datagrams.size(); i++){
			// Считаем дейтаграмму направления
			counters[direction]++;
			// Если заказана порча именно на этом круге
			if(((settings.flags & DAMAGE) != 0) && !damaged && (round == settings.special)){
				// Портим выбранный байт дейтаграммы
				datagrams[i][settings.offset % datagrams[i].size()] ^= 0x01;
				// Запоминаем, что порча уже выполнена
				damaged = true;
			}
			// Если дейтаграмма попадает в период потерь
			if(((settings.flags & LOSS) != 0) && ((counters[direction] % settings.period) == 0))
				// Пропускаем её, имитируя потерю переносом
				continue;
			// Подаём дейтаграмму принимающей стороне
			to.push(view_t(datagrams[i].data(), datagrams[i].size()));
			// Если заказан повтор дейтаграммы
			if((settings.flags & DUPLICATE) != 0)
				// Подаём ту же дейтаграмму повторно
				to.push(view_t(datagrams[i].data(), datagrams[i].size()));
		}
		// Выводим признак снятия дейтаграмм
		return true;
	}
	/**
	 * @brief Функция проведения рукопожатия поверх дейтаграмм
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param settings настройки переноса сценария
	 *
	 */
	void converseDatagrams(client::context_t & client, server::context_t & server, const settings_t & settings) noexcept {
		// Счётчики дейтаграмм направлений
		size_t counters[2] = {0, 0};
		// Признак уже выполненной порчи
		bool damaged = false;
		/**
		 * Выполняем перенос дейтаграмм и ход часов ограниченное число кругов
		 */
		for(size_t round = 0; round < 64; round++){
			// Если связь одной из сторон оборвана
			if((client.state() == context::state_t::FAILED) || (server.state() == context::state_t::FAILED))
				// Прекращаем перенос
				break;
			// Если заказан намеренный обрыв на этом круге
			if(((settings.flags & TRUNCATE) != 0) && (round == settings.stop))
				// Прекращаем перенос без завершения рукопожатия
				break;
			// Переносим дейтаграммы клиента серверу
			bool moved = carry(client, server, settings, round, 0, counters, damaged);
			// Переносим дейтаграммы сервера клиенту
			moved = (carry(server, client, settings, round, 1, counters, damaged) || moved);
			// Если дейтаграммы переносились
			if(moved)
				// Переходим к следующему кругу
				continue;
			// Признак срабатывания часов ожидания
			bool fired = false;
			// Если клиент ждёт повторной передачи
			if(client.timeout() > 0){
				// Извещаем клиента об истечении срока
				client.elapsed();
				// Запоминаем ход часов
				fired = true;
			}
			// Если сервер ждёт повторной передачи
			if(server.timeout() > 0){
				// Извещаем сервера об истечении срока
				server.elapsed();
				// Запоминаем ход часов
				fired = true;
			}
			// Если ожидание закончилось
			if(!fired)
				// Прекращаем перенос
				break;
		}
	}
	/**
	 * @brief Функция проведения связи выбранным переносом
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param settings настройки переноса сценария
	 * @param datagram признак переноса дейтаграммами
	 *
	 */
	void converse(client::context_t & client, server::context_t & server, const settings_t & settings, const bool datagram) noexcept {
		// Если выбран перенос дейтаграммами
		if(datagram)
			// Проводим связь поверх дейтаграмм
			converseDatagrams(client, server, settings);
		else
			// Проводим связь поверх потока
			converseStream(client, server, settings);
	}
	/**
	 * @brief Функция прикладного обмена в обе стороны
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param payload  данные, отправляемые клиентом
	 * @param settings настройки переноса сценария
	 * @param datagram признак переноса дейтаграммами
	 * @return         признак получения обоих сообщений без искажения
	 *
	 */
	bool exchange(client::context_t & client, server::context_t & server, const view_t & payload, const settings_t & settings, const bool datagram) noexcept {
		// Ответ сервера контрольного обмена
		static const uint8_t RESPONSE[] = {'p', 'o', 'n', 'g'};
		// Отправляем данные клиента
		if(client.write(payload) != context::error_t::NONE)
			// Выводим отказ отправки
			return false;
		// Отправляем ответ сервера
		if(server.write(view_t(RESPONSE, sizeof(RESPONSE))) != context::error_t::NONE)
			// Выводим отказ отправки
			return false;
		// Переносим прикладные записи
		converse(client, server, settings, datagram);
		// Принятые данные направлений
		std::vector <uint8_t> request, response;
		// Если сервер не принял данные клиента без искажения
		if((server.read(request) != context::error_t::NONE) || (request.size() != payload.size) || (::memcmp(request.data(), payload.data, payload.size) != 0))
			// Выводим нарушение обмена
			return false;
		// Если клиент не принял ответ сервера без искажения
		if((client.read(response) != context::error_t::NONE) || (response.size() != sizeof(RESPONSE)) || (::memcmp(response.data(), RESPONSE, sizeof(RESPONSE)) != 0))
			// Выводим нарушение обмена
			return false;
		// Выводим успешность обмена
		return true;
	}
	/**
	 * @brief Функция выдачи и проверки билета возобновления
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param payload  данные для проверки возобновлённой связи
	 * @param settings настройки переноса сценария
	 * @param datagram признак переноса дейтаграммами
	 * @return         признак успешного возобновления и прикладного обмена
	 *
	 */
	bool resumeConnection(client::context_t & client, server::context_t & server, const view_t & payload, const settings_t & settings, const bool datagram) noexcept {
		// Выдаём билет возобновления
		if(server.issue() != context::error_t::NONE)
			// Выводим отказ выдачи билета
			return false;
		// Доставляем билет клиенту
		converse(client, server, settings, datagram);
		// Если клиент билета не получил
		if(client.tickets().empty())
			// Выводим отсутствие билета
			return false;
		// Связи нового возобновления
		client::context_t resuming;
		// Связь сервера нового возобновления
		server::context_t resumed;
		// Настраиваем новые стороны тем же переносом
		configure(resuming, resumed, datagram, settings.mtu);
		// Передаём клиенту билет прежней связи
		resuming.resume(client.tickets()[0]);
		// Передаём серверу признаваемые им билеты
		resumed.resume(server.tickets());
		// Заводим сервер возобновления
		if(resumed.start() != context::error_t::NONE)
			// Выводим отказ заведения
			return false;
		// Заводим клиента возобновления
		if(resuming.start() != context::error_t::NONE)
			// Выводим отказ заведения
			return false;
		// Проводим возобновление сторон
		converse(resuming, resumed, settings, datagram);
		// Если возобновление не подтверждено обеими сторонами
		if(!resuming.established() || !resumed.established() || !resuming.shared() || !resumed.shared())
			// Выводим отказ возобновления
			return false;
		// Проверяем прикладной обмен возобновлённой связи
		return exchange(resuming, resumed, payload, settings, datagram);
	}
	/**
	 * @brief Функция выполнения одного сценария машины состояний
	 *
	 * @param payload  данные прикладного обмена
	 * @param settings настройки переноса сценария
	 * @param datagram признак переноса дейтаграммами
	 * @return         признак успешного завершения всех заказанных стадий
	 *
	 */
	bool run(const view_t & payload, const settings_t & settings, const bool datagram) noexcept {
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны выбранным переносом
		configure(client, server, datagram, settings.mtu);
		// Заводим сервер
		if(server.start() != context::error_t::NONE)
			// Выводим отказ заведения
			return false;
		// Заводим клиента
		if(client.start() != context::error_t::NONE)
			// Выводим отказ заведения
			return false;
		// Проводим начальное рукопожатие
		converse(client, server, settings, datagram);
		// Если рукопожатие не установилось
		if(!client.established() || !server.established())
			// Выводим отсутствие установления
			return false;
		// Чистые настройки для стадий после рукопожатия
		settings_t clean = settings;
		// Снимаем управляющие разряды повреждений
		clean.flags = 0;
		// Если заказано возобновление
		if((settings.flags & RESUME) != 0){
			// Выполняем возобновление и проверяем его итог
			const bool resumed = resumeConnection(client, server, payload, clean, datagram);
			// Если возобновление не удалось
			if(!resumed)
				// Выводим отказ возобновления
				return false;
		}
		// Если клиенту заказана смена ключей
		if((settings.flags & DUPLICATE) != 0){
			// Запрашиваем смену ключей клиентом
			const context::error_t updated = client.update(true);
			// Если смена ключей не удалась
			if(updated != context::error_t::NONE)
				// Выводим отказ смены ключей
				return false;
			// Доставляем первую смену до заказа следующей
			converse(client, server, clean, datagram);
		}
		// Если серверу заказана смена ключей
		if((settings.flags & LOSS) != 0){
			// Запрашиваем смену ключей сервером
			const context::error_t updated = server.update(true);
			// Если смена ключей не удалась
			if(updated != context::error_t::NONE)
				// Выводим отказ смены ключей
				return false;
			// Доставляем смену ключей до следующей стадии
			converse(client, server, clean, datagram);
		}
		// Если переносу дейтаграмм заказана смена ключей
		if(datagram && ((settings.flags & UPDATE) != 0)){
			// Запрашиваем смену ключей клиентом
			const context::error_t updatedClient = client.update(true);
			// Если смена ключей клиента не удалась
			if(updatedClient != context::error_t::NONE)
				// Выводим отказ смены ключей
				return false;
			// Доставляем смену клиента до запроса смены сервером
			converse(client, server, clean, datagram);
			// Запрашиваем смену ключей сервером
			const context::error_t updatedServer = server.update(true);
			// Если смена ключей сервера не удалась
			if(updatedServer != context::error_t::NONE)
				// Выводим отказ смены ключей
				return false;
			// Доставляем смену сервера до прикладного обмена
			converse(client, server, clean, datagram);
		}
		// Доставляем сообщения смены ключей
		converse(client, server, clean, datagram);
		// Проверяем прикладной обмен после всех смен ключей
		const bool exchanged = exchange(client, server, payload, clean, datagram);
		// Если прикладной обмен не удался
		if(!exchanged)
			// Выводим нарушение прикладного обмена
			return false;
		// Если заказано закрытие связи
		if((settings.flags & CLOSE) != 0){
			// Закрываем связь клиентом
			if(client.close() != context::error_t::NONE)
				// Выводим отказ закрытия
				return false;
			// Доставляем извещение о закрытии
			converse(client, server, clean, datagram);
			// Если сервер не подтвердил закрытие
			if(server.state() != context::state_t::CLOSED)
				// Выводим отсутствие закрытия
				return false;
		}
		// Выводим успешность всех заказанных стадий
		return true;
	}
}

/**
 * Поверхность вызова ворошителя
 */
extern "C" {
	/**
	 * @brief Функция подачи управляющего сценария машинам состояний
	 *
	 * @param data начало сценария
	 * @param size размер сценария
	 * @return     нулевой код продолжения ворошения
	 *
	 */
	int LLVMFuzzerTestOneInput(const uint8_t * data, const size_t size) noexcept {
		// Если подлинность ещё не выработана
		if(!ready){
			// Вырабатываем подлинность сторон один раз на процесс
			ready = identity("anyks.com", credentials);
			// Если подлинность не выработана, выполнять сценарии бессмысленно
			if(!ready)
				// Останавливаем ворошитель на отказе инициализации
				std::abort();
		}
		// Если сценарий короче управляющей части
		if(size < 8)
			// Продолжаем ворошение без выполнения сценария
			return 0;
		// Признак переноса дейтаграммами
		const bool datagram = ((data[0] & 0x01) != 0);
		// Настройки сценария из управляющих байтов
		settings_t settings;
		// Читаем управляющие разряды сценария
		settings.flags = data[2];
		// Выбираем длину куска потока
		settings.chunk = (1 + (data[1] % 64));
		// Выбираем размер дейтаграммы в дозволенных пределах
		settings.mtu = (256 + (data[1] % 945));
		// Выбираем круг намеренного обрыва
		settings.stop = (data[3] % (datagram ? 64 : 16));
		// Выбираем круг повтора либо порчи
		settings.special = (data[4] % (datagram ? 64 : 16));
		// Выбираем период потерь дейтаграмм
		settings.period = (2 + (data[5] % 5));
		// Читаем смещение портимого байта
		settings.offset = (static_cast <size_t> (data[6]) | (static_cast <size_t> (data[7]) << 8));
		// Контрольный байт сценария без прикладных данных
		static const uint8_t FALLBACK = 0x42;
		// Определяем данные прикладного обмена
		const view_t payload = ((size > 8) ? view_t(data + 8, std::min(size - 8, static_cast <size_t> (256))) : view_t(&FALLBACK, 1));
		// Выполняем сценарий машины состояний
		const bool result = run(payload, settings, datagram);
		// Признак сценария с транспортными помехами, которым установление не обещано
		const bool disturbed = (datagram && ((settings.flags & (REORDER | DUPLICATE | LOSS)) != 0));
		// Признак сценария, которому отказ разрешён самим замыслом
		const bool negative = ((settings.flags & (TRUNCATE | DAMAGE)) != 0) || (!datagram && ((settings.flags & REORDER) != 0)) || disturbed;
		// Если чистый сценарий не выполнил обязательные стадии
		if(!negative && !result)
			// Останавливаем ворошитель на нарушении договора драйвера
			std::abort();
		// Выводим код продолжения ворошения
		return 0;
	}
}
