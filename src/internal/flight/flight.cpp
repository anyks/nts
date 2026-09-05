/**
 * @file flight.cpp
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
 * @brief Исходный файл внутреннего модуля переноса рукопожатия дейтаграммами по DTLS 1.3
 *
 * @section Намеренные решения
 *
 * 1. Сборка принимаемого сообщения привязана к поре ключей: открытые куски по
 *    появлении ключей чтения принимаются лишь повтором уже разобранного сообщения
 *    (номер меньше ожидаемого), иначе подделанная открытая запись рвала бы идущее
 *    защищённое рукопожатие. Повтор открытого сообщения от подделки неотличим по
 *    устройству протокола, и вызванный им повтор своего залпа - цена стандарта.
 *
 * 2. Признак повтора собеседника ставится лишь куском уже разобранного сообщения
 *    (раздел 5.8.1 RFC 9147, выход 3), а не всякой записью без продвижения: новые
 *    куски раздробленного залпа и подделки повтора не вызывают.
 *
 * 3. Номер записи ложится под подтверждение лишь тогда, когда хоть один её кусок
 *    принят сборкой либо повторяет разобранное за установленной связью: раздел 7
 *    RFC 9147 запрещает подтверждать отброшенное.
 *
 * 4. Открытой порой принимается лишь пустое подтверждение (раздел 7.1 RFC 9147) и
 *    лишь при залпе, ждущем часов: номера в открытом подтверждении ничем не
 *    подписаны, а пустое при просьбе о повторе усиливало бы чужой поток.
 *
 * 5. Срок ожидания держится, пока залп не подтверждён без повторов (раздел 5.8.2),
 *    и лишь тогда возвращается к начальному; попытки считаются по залпу.
 *
 * 6. Повтор по частичному подтверждению (SHOULD раздела 7.2) ведут часы: подтверждения
 *    шлются на всякую дейтаграмму без выдержки в четверть срока, и немедленный
 *    повтор по ним был бы ложным при перестановке дейтаграмм.
 *
 * 7. Сообщение рукопожатия длиннее DATAGRAM_ASSEMBLY байтов не собирается ни в одной
 *    поре: память под сборку занимается по чужому слову.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <internal/flight/flight.hpp>
#include <digest/hash.hpp>
#include <digest/hmac.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Затирание областей памяти берётся из открытого API библиотеки
	 */
	using nts::sys::wipe;

	/**
	 * Длина метки возврата состояния: поколение, хеш приветствия и имитовставка
	 */
	static constexpr size_t LABEL = (1 + 32 + 32);

	/**
	 * @brief Метод перевода отказа модуля защиты записей в отказ связи
	 *
	 * @param error    отказ модуля защиты записей
	 * @param fallback отказ связи, которым отвечается всякий отказ модуля, кроме нехватки памяти
	 *
	 * @return         отказ связи, отвечающий отказу модуля
	 *
	 */
	static context::error_t translate(const protect::error_t error, const context::error_t fallback) noexcept {
		// Если отказа у модуля нет
		if(error == protect::error_t::NONE)
			// Выводим отсутствие отказа связи
			return context::error_t::NONE;
		// Выводим отказ связи, отвечающий отказу модуля
		return ((error == protect::error_t::MEMORY) ? context::error_t::MEMORY : fallback);
	}
	/**
	 * @brief Метод перевода отказа разбора заголовка записи в причину отброса
	 *
	 * @param error отказ разбора заголовка записи
	 *
	 * @return      причина отброса записи
	 *
	 */
	static datagram::reason_t reason(const datagram::error_t error) noexcept {
		/**
		 * Определяем отказ разбора заголовка
		 */
		switch(static_cast <uint8_t> (error)){
			// Если вид содержимого записи неведом
			case static_cast <uint8_t> (datagram::error_t::TYPE): return datagram::reason_t::TYPE;
			// Если открытая запись несёт ненулевую пору
			case static_cast <uint8_t> (datagram::error_t::EPOCH): return datagram::reason_t::EPOCH;
			// Если запись несёт опознаватель связи
			case static_cast <uint8_t> (datagram::error_t::IDENTIFIER): return datagram::reason_t::IDENTIFIER;
		}
		// Всё прочее - длина: нехватка байтов либо выход за предел
		return datagram::reason_t::LENGTH;
	}
};

/**
 * @brief Конструктор
 *
 */
nts::internal::Era::Era() noexcept : held(false), epoch(0), next(0) {
	// Выполняем обнуление ключа шифрования номера записи
	::memset(this->sn, 0, sizeof(this->sn));
}
/**
 * @brief Метод получения поры ключей записи по её номеру
 *
 * @param direction место направления: ноль у записи, единица у чтения
 * @param epoch     номер поры ключей
 *
 * @return          пора ключей либо nullptr, если пора связью не держится
 *
 */
nts::internal::era_t * nts::internal::Flight::era(const size_t direction, const uint16_t epoch) noexcept {
	// Нулевая пора держится всегда: записи в ней защиты не несут, и ключей ей не надо
	if(epoch == 0)
		// Выводим нулевую пору направления
		return &this->_plains[direction];
	/**
	 * Выполняем перебор мест пор ключей направления от текущего к прежнему
	 */
	for(size_t i = 0; i < 2; i++){
		// Пора ключей очередного места
		era_t & item = this->_eras[direction][(this->_slots[direction] + i) % 2];
		// Если пора заведена и её номер совпал
		if(item.held && (item.epoch == epoch))
			// Выводим найденную пору ключей
			return &item;
	}
	// Выводим отсутствие поры ключей
	return nullptr;
}
/**
 * @brief Метод получения текущей поры ключей направления
 *
 * @param direction место направления: ноль у записи, единица у чтения
 *
 * @return          текущая защищённая пора либо нулевая, пока защищённой нет
 *
 */
nts::internal::era_t & nts::internal::Flight::current(const size_t direction) noexcept {
	// Текущее место защищённых пор направления
	era_t & item = this->_eras[direction][this->_slots[direction]];
	// Выводим защищённую пору, если она заведена, иначе нулевую
	return (item.held ? item : this->_plains[direction]);
}
/**
 * @brief Метод составления записи поверх дейтаграммы
 *
 * @param type   вид содержимого записи
 * @param data   содержимое записи
 * @param era    пора ключей, которой запись защищается
 * @param result накопитель, в конец которого дописывается запись
 *
 * @return       отказ составления записи
 *
 */
context::error_t nts::internal::Flight::shield(const record::type_t type, const view_t & data, era_t & era, vector <uint8_t> & result) noexcept {
	// Если порядковые номера записей поры исчерпаны
	if(era.next > datagram::DATAGRAM_SEQUENCE)
		// Выводим отказ защиты записи
		return context::error_t::PROTECTION;
	// Заголовок составляемой записи
	datagram::header_t header;
	// Устанавливаем пору ключей записи
	header.epoch = era.epoch;
	// Устанавливаем порядковый номер записи
	header.sequence = era.next;
	// Устанавливаем вид содержимого записи
	header.type = type;
	// Место, в которое записывается заголовок записи
	uint8_t buffer[datagram::DATAGRAM_PLAIN_HEADER];
	// Длина записанного заголовка
	size_t length = 0;
	// Смещение записи в накопителе
	const size_t offset = result.size();
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Если запись идёт нулевой порой ключей
		if(era.epoch == 0){
			// Запись идёт открытым заголовком
			header.unified = false;
			// Устанавливаем длину содержимого записи
			header.size = data.size;
			// Если заголовок открытой записи составить не удалось
			if(datagram::build(header, buffer, length) != datagram::error_t::NONE)
				// Выводим отказ составления записи
				return context::error_t::RECORD;
			// Складываем заголовок открытой записи в накопитель
			result.insert(result.end(), buffer, buffer + length);
			// Складываем содержимое открытой записи в накопитель
			result.insert(result.end(), data.data, data.data + data.size);
			// Продвигаем счёт записей поры
			era.next++;
			// Выводим успешность составления открытой записи
			return context::error_t::NONE;
		}
		// Если ключевой материал поры не установлен
		if(!era.protection.ready())
			// Выводим отказ негодного состояния связи
			return context::error_t::STATE;
		// Запись идёт объединённым заголовком
		header.unified = true;
		// Устанавливаем длину защищённого содержимого: содержимое, вид и метка целостности
		header.size = (data.size + 1 + protect::tag(this->_suite));
		// Если объединённый заголовок составить не удалось
		if(datagram::build(header, buffer, length) != datagram::error_t::NONE)
			// Выводим отказ составления записи
			return context::error_t::RECORD;
		// Складываем объединённый заголовок в накопитель
		result.insert(result.end(), buffer, buffer + length);
		// Отказ наложения защиты на запись: заголовок служит связанными данными
		const context::error_t failure = translate(era.protection.seal(view_t(buffer, length), era.next, type, data, result, 0), context::error_t::PROTECTION);
		// Если защиту на запись наложить не удалось
		if(failure != context::error_t::NONE){
			// Возвращаем накопитель к прежней длине
			result.resize(offset);
			// Выводим отказ наложения защиты
			return failure;
		}
		// Место, в которое помещается маска номера записи
		uint8_t mask[datagram::DATAGRAM_MASK];
		/**
		 * Раздел 4.2.3 RFC 9147: номер записи шифруется маской от первых байтов
		 * шифртекста уже после наложения защиты, оттого связанные данные несут номер открытым
		 */
		if(!datagram::mask(this->_suite, view_t(era.sn, protect::key(this->_suite)), result.data() + offset + length, mask)){
			// Возвращаем накопитель к прежней длине
			result.resize(offset);
			// Выводим отказ шифрования номера записи
			return context::error_t::PROTECTION;
		}
		// Накладываем маску на старший байт номера записи
		result[offset + 1] ^= mask[0];
		// Накладываем маску на младший байт номера записи
		result[offset + 2] ^= mask[1];
		// Выполняем затирание маски номера записи
		wipe(mask, sizeof(mask));
	/**
	 * Если памяти под запись не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Продвигаем счёт записей поры
	era.next++;
	// Выводим успешность составления защищённой записи
	return context::error_t::NONE;
}
/**
 * @brief Метод вскрытия защищённой записи
 *
 * @param header  заголовок записи
 * @param rest    остаток дейтаграммы от начала записи
 * @param result  запись, в которую помещается открытое содержимое
 * @param failure место, в которое помещается отказ нехватки памяти
 *
 * @return        признак того, что запись вскрыта и принята окном
 *
 */
bool nts::internal::Flight::unveil(const datagram::header_t & header, const view_t & rest, opened_t & result, context::error_t & failure) noexcept {
	// Защищённое содержимое записи
	const view_t payload(rest.data + header.length, header.size);
	// Пора ключей чтения, отвечающая младшим разрядам заголовка
	era_t * keys = nullptr;
	/**
	 * Выполняем перебор пор ключей чтения от текущей к прежней
	 */
	for(size_t i = 0; (i < 2) && (keys == nullptr); i++){
		// Пора ключей очередного места
		era_t & item = this->_eras[1][(this->_slots[1] + i) % 2];
		// Если пора заведена, защищена и её младшие разряды совпали
		if(item.held && (item.epoch != 0) && ((item.epoch & 0x03) == header.epoch))
			// Запоминаем найденную пору ключей
			keys = &item;
	}
	// Если пора ключей записи не найдена
	if(keys == nullptr){
		/**
		 * Раздел 4.2.1 RFC 9147: за нулевой порой идёт вторая - первая отдана
		 * упреждающим данным, которых связь не ведёт; за защищённой - следующая по счёту
		 */
		const uint16_t following = ((this->current(1).epoch == 0) ? 2 : static_cast <uint16_t> (this->current(1).epoch + 1));
		/**
		 * Раздел 4.2.2 RFC 9147: запись следующей поры обогнала ключи - дейтаграммы
		 * приходят не по порядку, и запись откладывается до прихода ключей
		 */
		if((static_cast <uint16_t> (following & 0x03) == header.epoch) && (this->_deferred.size() < datagram::DATAGRAM_DEFERRED)){
			/**
			 * Выполняем перехват ошибок работы с памятью
			 */
			try {
				// Откладываем запись вместе с заголовком
				this->_deferred.push_back(vector <uint8_t> (rest.data, rest.data + header.length + header.size));
			/**
			 * Если памяти под отложенную запись не хватило
			 */
			} catch(const bad_alloc &) {
				// Запоминаем отказ нехватки памяти
				failure = context::error_t::MEMORY;
				// Выводим признак того, что запись не принята
				return false;
			}
			// Запоминаем, что запись отложена
			this->_deferring = true;
			// Выводим признак того, что запись не принята
			return false;
		}
		/**
		 * Раздел 4.2.2 RFC 9147: запись неведомой поры отбрасывается молча - она
		 * либо запоздала на две смены ключей, либо пришла из чужой связи
		 */
		this->discard(datagram::reason_t::EPOCH);
		// Выводим признак того, что запись не принята
		return false;
	}
	// Если ключевой материал поры не установлен
	if(!keys->protection.ready()){
		// Считаем отброшенную запись
		this->discard(datagram::reason_t::EPOCH);
		// Выводим признак того, что запись не принята
		return false;
	}
	// Раздел 4.2.3 RFC 9147: маска берётся от образца шифртекста, а сам он не короче метки
	if((payload.size < datagram::DATAGRAM_SAMPLE) || (payload.size <= protect::tag(this->_suite))){
		// Считаем отброшенную запись
		this->discard(datagram::reason_t::LENGTH);
		// Выводим признак того, что запись не принята
		return false;
	}
	// Заголовок записи с расшифрованным номером: связанные данные защиты
	uint8_t associated[datagram::DATAGRAM_PLAIN_HEADER];
	// Переносим заголовок записи как он пришёл
	::memcpy(associated, rest.data, header.length);
	// Место, в которое помещается маска номера записи
	uint8_t mask[datagram::DATAGRAM_MASK];
	// Если маску номера записи выработать не удалось
	if(!datagram::mask(this->_suite, view_t(keys->sn, protect::key(this->_suite)), payload.data, mask)){
		// Считаем отброшенную запись
		this->discard(datagram::reason_t::DAMAGE);
		// Выводим признак того, что запись не принята
		return false;
	}
	// Снимаем маску со старшего байта номера
	associated[1] ^= mask[0];
	// Если номер записи занимает два байта
	if(header.bits == 16)
		// Снимаем маску с младшего байта номера
		associated[2] ^= mask[1];
	// Выполняем затирание маски номера записи
	wipe(mask, sizeof(mask));
	// Младшие разряды номера записи
	const uint64_t junior = ((header.bits == 16) ? ((static_cast <uint64_t> (associated[1]) << 8) | associated[2]) : associated[1]);
	// Восстанавливаем полный номер записи по ожидаемому
	const uint64_t sequence = datagram::restore(keys->window.expected(), junior, header.bits);
	// Раздел 4.5.1 RFC 9147: повтор и запись позади окна отбрасываются до снятия защиты
	if(keys->window.stale(sequence)){
		// Считаем отброшенную запись
		this->discard(datagram::reason_t::REPLAY);
		// Выводим признак того, что запись не принята
		return false;
	}
	// Отказ снятия защиты с записи
	const context::error_t opened = translate(keys->protection.open(view_t(associated, header.length), sequence, payload, result.type, result.content), context::error_t::PROTECTION);
	// Нехватка памяти к защите записи не относится и пропуском не лечится
	if(opened == context::error_t::MEMORY){
		// Запоминаем отказ нехватки памяти
		failure = opened;
		// Выводим признак того, что запись не принята
		return false;
	}
	// Раздел 4.5.2 RFC 9147: порченая запись отбрасывается молча, извещение не идёт
	if(opened != context::error_t::NONE){
		// Считаем отброшенную запись
		this->discard(datagram::reason_t::DAMAGE);
		// Выводим признак того, что запись не принята
		return false;
	}
	// Отмечаем запись принятой лишь после снятия защиты
	keys->window.mark(sequence);
	// Запоминаем пору ключей записи
	result.epoch = keys->epoch;
	// Запоминаем порядковый номер записи
	result.sequence = sequence;
	// Выводим признак того, что запись принята
	return true;
}
/**
 * @brief Метод закрытия собираемой дейтаграммы
 *
 * @return отказ закрытия дейтаграммы
 *
 */
context::error_t nts::internal::Flight::settle() noexcept {
	// Если собираемая дейтаграмма пуста
	if(this->_packet.empty())
		// Выводим успешность: закрывать нечего
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Переносим собранную дейтаграмму в готовые
		this->_datagrams.push_back(::move(this->_packet));
	/**
	 * Если памяти под дейтаграмму не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выполняем сброс собираемой дейтаграммы
	this->_packet.clear();
	// Выводим успешность закрытия дейтаграммы
	return context::error_t::NONE;
}
/**
 * @brief Метод нарезки области сообщения залпа на записи дейтаграмм
 *
 * @param index  место сообщения в залпе
 * @param offset смещение области в теле сообщения
 * @param length длина области в байтах
 *
 * @return       отказ нарезки области сообщения
 *
 */
context::error_t nts::internal::Flight::carve(const size_t index, const size_t offset, const size_t length) noexcept {
	// Если место сообщения вышло за залп
	if(index >= this->_flight.size())
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Сообщение залпа, область которого нарезается
	const dispatch_t & item = this->_flight[index];
	// Пора ключей, которой сообщение отправляется
	era_t * keys = this->era(0, item.epoch);
	/**
	 * Пора ключей сообщения уже отброшена двумя сменами ключей: повторить его нечем,
	 * а собеседник, сменивший ключи дважды, сообщение это давно получил
	 */
	if(keys == nullptr)
		// Выводим успешность: повторять нечего
		return context::error_t::NONE;
	// Длина тела сообщения без обвязки TLS
	const size_t total = (item.message.size() - handshake::HANDSHAKE_HEADER);
	// Если область вышла за тело сообщения
	if((offset > total) || (length > (total - offset)))
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Накладные байты записи с куском: заголовок записи, обвязка куска, вид и метка
	const size_t overhead = (((item.epoch == 0) ? datagram::DATAGRAM_PLAIN_HEADER : (datagram::DATAGRAM_UNIFIED_HEADER + 1 + protect::tag(this->_suite))) + datagram::DATAGRAM_FRAGMENT_HEADER);
	// Наименьший кусок, ради которого стоит дописывать запись в дейтаграмму
	static constexpr size_t SLIVER = 16;
	// Наибольший кусок, входящий в одну запись вместе с обвязкой
	static constexpr size_t WIDEST = (record::RECORD_PLAINTEXT - datagram::DATAGRAM_FRAGMENT_HEADER);
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Длина уже нарезанной части области
		size_t done = 0;
		/**
		 * Выполняем нарезку области на куски по размеру дейтаграммы
		 */
		while(done < length){
			/**
			 * Раздел 4.4 RFC 9147: дейтаграмма несёт записи одной поры ключей, а кусок
			 * короче считанных байтов дейтаграмму не заполняет, а лишь дробит сообщение
			 */
			if(!this->_packet.empty() && ((this->_bundle != item.epoch) || ((this->_packet.size() + overhead + SLIVER) > this->_mtu))){
				// Отказ закрытия собираемой дейтаграммы
				const context::error_t closed = this->settle();
				// Если дейтаграмму закрыть не удалось
				if(closed != context::error_t::NONE)
					// Выводим отказ закрытия дейтаграммы
					return closed;
			}
			// Если и пустая дейтаграмма куска не вмещает
			if(this->_mtu < (this->_packet.size() + overhead + 1))
				// Выводим отказ составления записи
				return context::error_t::RECORD;
			// Место, остающееся в дейтаграмме под кусок, не шире записи
			const size_t room = ((((this->_mtu - this->_packet.size() - overhead) > WIDEST) ? WIDEST : (this->_mtu - this->_packet.size() - overhead)));
			// Длина очередного куска
			const size_t take = (((length - done) < room) ? (length - done) : room);
			// Обвязка очередного куска
			datagram::fragment_t fragment;
			// Устанавливаем вид сообщения куска
			fragment.type = static_cast <handshake::type_t> (item.message[0]);
			// Устанавливаем длину целого сообщения
			fragment.size = total;
			// Устанавливаем порядковый номер сообщения
			fragment.sequence = item.sequence;
			// Устанавливаем смещение куска
			fragment.offset = (offset + done);
			// Устанавливаем длину куска
			fragment.length = take;
			// Кусок сообщения вместе с обвязкой
			vector <uint8_t> chunk(datagram::DATAGRAM_FRAGMENT_HEADER + take, 0);
			// Если обвязку куска записать не удалось
			if(datagram::build(fragment, chunk.data()) != datagram::error_t::NONE)
				// Выводим отказ составления записи
				return context::error_t::RECORD;
			// Переносим тело куска следом за обвязкой
			::memcpy(chunk.data() + datagram::DATAGRAM_FRAGMENT_HEADER, item.message.data() + handshake::HANDSHAKE_HEADER + offset + done, take);
			// Кусок залпа, уходящий записью
			piece_t piece;
			// Запоминаем пору ключей записи куска
			piece.epoch = item.epoch;
			// Запоминаем порядковый номер записи куска
			piece.sequence = keys->next;
			// Запоминаем место сообщения куска
			piece.index = index;
			// Запоминаем смещение куска
			piece.offset = (offset + done);
			// Запоминаем длину куска
			piece.length = take;
			// Отказ составления записи с куском
			const context::error_t error = this->shield(record::type_t::HANDSHAKE, view_t(chunk.data(), chunk.size()), *keys, this->_packet);
			// Если запись с куском составить не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ составления записи
				return error;
			// Запоминаем пору ключей собираемой дейтаграммы
			this->_bundle = item.epoch;
			// Запоминаем кусок залпа
			this->_pieces.push_back(piece);
			// Увеличиваем длину нарезанной части области
			done += take;
		}
	/**
	 * Если памяти под нарезку не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность нарезки области сообщения
	return context::error_t::NONE;
}
/**
 * @brief Метод составления записи подтверждения принятых записей
 *
 * @param settled признак того, что связь установлена
 *
 * @return        отказ составления подтверждения
 *
 */
context::error_t nts::internal::Flight::acknowledge(const bool settled) noexcept {
	// Признак того, что подтверждение с номерами положено
	const bool listed = (!this->_acknowledgeable.empty() && (!this->_replied || settled));
	/**
	 * Раздел 7.1 RFC 9147: запись, вскрыть которую нечем, подтверждается пустым
	 * подтверждением - оно сокращает собеседнику ожидание повтора потерянного
	 * приветствия; но лишь тогда, когда сказать больше нечего
	 */
	const bool hollow = (!listed && this->_deferring && this->_acknowledgeable.empty() && !this->_replied);
	// Если подтверждать нечего
	if(!listed && !hollow){
		// Принятые записи подтверждены своим залпом
		this->_acknowledgeable.clear();
		// Выводим успешность: подтверждение не положено
		return context::error_t::NONE;
	}
	/**
	 * Раздел 7 RFC 9147: номера записей перечисляются по возрастанию - перечень
	 * невелик, и простой перестановки соседей ему довольно
	 */
	for(size_t i = 1; listed && (i < this->_acknowledgeable.size()); i++){
		/**
		 * Выполняем сдвиг номера к своему месту по возрастанию поры и номера
		 */
		for(size_t j = i; (j > 0) && ((this->_acknowledgeable[j].epoch < this->_acknowledgeable[j - 1].epoch) || ((this->_acknowledgeable[j].epoch == this->_acknowledgeable[j - 1].epoch) && (this->_acknowledgeable[j].sequence < this->_acknowledgeable[j - 1].sequence))); j--){
			// Переставляемый номер
			const datagram::number_t item = this->_acknowledgeable[j];
			// Сдвигаем соседний номер назад
			this->_acknowledgeable[j] = this->_acknowledgeable[j - 1];
			// Ставим номер на своё место
			this->_acknowledgeable[j - 1] = item;
		}
	}
	// Накопитель, в который складывается тело подтверждения
	vector <uint8_t> body;
	// Если тело подтверждения составить не удалось
	if(datagram::build((listed ? this->_acknowledgeable : vector <datagram::number_t> ()), body) != datagram::error_t::NONE)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Раздел 7 RFC 9147: подтверждение идёт наивысшей порой записи
	era_t & keys = this->current(0);
	// Если собираемая дейтаграмма идёт иной порой ключей
	if(!this->_packet.empty() && (this->_bundle != keys.epoch)){
		// Отказ закрытия собираемой дейтаграммы
		const context::error_t closed = this->settle();
		// Если дейтаграмму закрыть не удалось
		if(closed != context::error_t::NONE)
			// Выводим отказ закрытия дейтаграммы
			return closed;
	}
	// Отказ составления записи подтверждения
	const context::error_t error = this->shield(record::type_t::ACK, view_t(body.data(), body.size()), keys, this->_packet);
	// Если запись подтверждения составить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ составления подтверждения
		return error;
	// Запоминаем пору ключей собираемой дейтаграммы
	this->_bundle = keys.epoch;
	// Принятые записи подтверждены
	this->_acknowledgeable.clear();
	// Выводим успешность составления подтверждения
	return context::error_t::NONE;
}
/**
 * @brief Метод заведения поры ключей направления
 *
 * @param incoming  заводится ли пора направления собеседника
 * @param handshake заводится ли пора ключей рукопожатия
 * @param suite     набор шифрования связи
 * @param key       ключ защиты записей поры
 * @param vector    вектор замены защиты записей поры
 * @param sn        ключ шифрования номера записи поры
 *
 * @return          отказ заведения поры ключей
 *
 */
context::error_t nts::internal::Flight::adopt(const bool incoming, const bool handshake, const protect::suite_t suite, const view_t & key, const view_t & vector, const view_t & sn) noexcept {
	// Место направления: запись у своей стороны, чтение у собеседника
	const size_t direction = (incoming ? 1 : 0);
	// Текущая пора ключей направления
	const era_t & latest = this->current(direction);
	/**
	 * Раздел 4.2.1 RFC 9147: ключи рукопожатия открывают вторую пору, прикладные -
	 * третью, всякая смена ключей - следующую по счёту
	 */
	const uint32_t epoch = (handshake ? 2 : ((latest.epoch < 3) ? 3 : (static_cast <uint32_t> (latest.epoch) + 1)));
	// Если поры ключей исчерпаны
	if(epoch > 0xFFFF)
		// Выводим отказ вывода ключевого материала
		return context::error_t::SCHEDULE;
	// Если ключ шифрования номера не сходится длиной с ключом набора
	if((sn.data == nullptr) || (sn.size != protect::key(suite)))
		// Выводим отказ вывода ключевого материала
		return context::error_t::SCHEDULE;
	// Место новой поры: прежняя пора остаётся ради запоздалых записей и повторов
	const uint8_t slot = static_cast <uint8_t> (1 - this->_slots[direction]);
	// Новая пора ключей направления
	era_t & fresh = this->_eras[direction][slot];
	// Выполняем сброс защиты записей новой поры
	fresh.protection.clear();
	// Выполняем затирание ключа шифрования номера новой поры
	wipe(fresh.sn, sizeof(fresh.sn));
	// Выполняем сброс окна повторов новой поры
	fresh.window.clear();
	// Сбрасываем счёт записей новой поры
	fresh.next = 0;
	// Снимаем признак заведённости новой поры
	fresh.held = false;
	// Если ключевой материал установить не удалось
	if(!fresh.protection.start(suite, key, vector))
		// Выводим отказ установки ключевого материала
		return context::error_t::SCHEDULE;
	// Переносим ключ шифрования номера записи
	::memcpy(fresh.sn, sn.data, sn.size);
	// Запоминаем набор шифрования связи
	this->_suite = suite;
	// Запоминаем номер новой поры ключей
	fresh.epoch = static_cast <uint16_t> (epoch);
	// Отмечаем заведённость новой поры
	fresh.held = true;
	// Делаем новую пору текущей
	this->_slots[direction] = slot;
	/**
	 * Ключи чтения появились: открытые куски отныне принимаются лишь повтором
	 * разобранного, а недособранные открытые сообщения - чужой мусор
	 */
	for(size_t i = this->_assemblies.size(); incoming && (i > 0); i--){
		// Если сборка ведётся открытыми кусками
		if(this->_assemblies[i - 1].epoch == 0)
			// Снимаем сборку с перечня
			this->_assemblies.erase(this->_assemblies.begin() + (i - 1));
	}
	// Выводим успешность заведения поры ключей
	return context::error_t::NONE;
}
/**
 * @brief Метод получения номера текущей поры ключей направления
 *
 * @param incoming запрашивается ли направление собеседника
 *
 * @return         номер текущей поры, ноль до появления ключей
 *
 */
uint16_t nts::internal::Flight::epoch(const bool incoming) const noexcept {
	// Место направления
	const size_t direction = (incoming ? 1 : 0);
	// Текущее место защищённых пор направления
	const era_t & item = this->_eras[direction][this->_slots[direction]];
	// Выводим номер защищённой поры, если она заведена, иначе ноль
	return (item.held ? item.epoch : 0);
}
/**
 * @brief Метод получения счётчика записей направления
 *
 * @param incoming запрашивается ли направление собеседника
 *
 * @return         число записей направления на текущих ключах
 *
 */
uint64_t nts::internal::Flight::sequence(const bool incoming) const noexcept {
	// Место направления
	const size_t direction = (incoming ? 1 : 0);
	// Текущее место защищённых пор направления
	const era_t & item = this->_eras[direction][this->_slots[direction]];
	// Текущая пора направления: защищённая, если заведена, иначе нулевая
	const era_t & keys = (item.held ? item : this->_plains[direction]);
	// Выводим счёт записей текущей поры направления
	return (incoming ? keys.window.expected() : keys.next);
}
/**
 * @brief Метод складывания записи в дейтаграммы
 *
 * @param type вид содержимого записи
 * @param data содержимое записи: сообщение рукопожатия вместе с обвязкой TLS
 *
 * @return     отказ складывания записи
 *
 */
context::error_t nts::internal::Flight::emit(const record::type_t type, const view_t & data) noexcept {
	// Текущая пора ключей записи
	era_t & keys = this->current(0);
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Если складывается сообщение рукопожатия
		if(type == record::type_t::HANDSHAKE){
			// Сообщение залпа
			dispatch_t item;
			// Запоминаем пору ключей сообщения
			item.epoch = keys.epoch;
			// Раздел 5.2 RFC 9147: всякое сообщение рукопожатия несёт свой порядковый номер
			item.sequence = this->_outgoing++;
			// Переносим сообщение вместе с обвязкой TLS
			item.message.assign(data.data, data.data + data.size);
			// Добавляем сообщение в залп
			this->_flight.push_back(::move(item));
			// Запоминаем, что залп пополнился
			this->_replied = true;
			// Выводим успешность складывания сообщения в залп
			return context::error_t::NONE;
		}
	/**
	 * Если памяти под сообщение залпа не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Накладные байты записи: заголовок, вид содержимого и метка целостности
	const size_t overhead = ((keys.epoch == 0) ? datagram::DATAGRAM_PLAIN_HEADER : (datagram::DATAGRAM_UNIFIED_HEADER + 1 + protect::tag(this->_suite)));
	// Если и пустая дейтаграмма записи не вмещает
	if(this->_mtu <= overhead)
		// Выводим отказ составления записи
		return context::error_t::RECORD;
	// Наибольшее содержимое записи, входящее в дейтаграмму и не шире записи протокола
	const size_t room = (((this->_mtu - overhead) > record::RECORD_PLAINTEXT) ? record::RECORD_PLAINTEXT : (this->_mtu - overhead));
	// Смещение очередной записи в содержимом
	size_t offset = 0;
	/**
	 * Выполняем нарезку содержимого на записи по размеру дейтаграммы
	 */
	do {
		// Длина содержимого очередной записи
		const size_t size = (((data.size - offset) < room) ? (data.size - offset) : room);
		// Отказ закрытия собираемой дейтаграммы: запись уходит своей дейтаграммой
		context::error_t failure = this->settle();
		// Если дейтаграмму закрыть не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ закрытия дейтаграммы
			return failure;
		// Отказ составления записи
		failure = this->shield(type, view_t(data.data + offset, size), keys, this->_packet);
		// Если запись составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления записи
			return failure;
		// Запоминаем пору ключей собираемой дейтаграммы
		this->_bundle = keys.epoch;
		// Отказ закрытия дейтаграммы с записью
		failure = this->settle();
		// Если дейтаграмму закрыть не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ закрытия дейтаграммы
			return failure;
		// Сдвигаем смещение на следующую запись
		offset += size;
	} while(offset < data.size);
	// Выводим успешность складывания записей в дейтаграммы
	return context::error_t::NONE;
}
/**
 * @brief Метод раскладки залпа по дейтаграммам
 *
 * @param resend признак повторной передачи неподтверждённых кусков
 *
 * @return       отказ раскладки залпа
 *
 */
context::error_t nts::internal::Flight::dispatch(const bool resend) noexcept {
	// Признаки подачи сняты: раскладка кончает круг подачи либо отправки
	this->_replied = false;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Если повторяются неподтверждённые куски залпа
		if(resend){
			// Куски залпа, ждущие повторной передачи
			vector <piece_t> pending;
			// Куски залпа, подтверждённые собеседником
			vector <piece_t> settled;
			/**
			 * Выполняем перебор кусков залпа
			 */
			for(size_t i = 0; i < this->_pieces.size(); i++){
				// Если кусок подтверждён собеседником
				if(this->_pieces[i].acked)
					// Оставляем кусок подтверждённым
					settled.push_back(this->_pieces[i]);
				// Если кусок собеседником не подтверждён
				else pending.push_back(this->_pieces[i]);
			}
			// Оставляем в залпе лишь подтверждённые куски
			this->_pieces = ::move(settled);
			/**
			 * Раздел 5.8 RFC 9147: повтор нарезается заново новыми номерами записей и
			 * защищается заново, ибо запись с прежним номером окно повторов отбросит
			 */
			for(size_t i = 0; i < pending.size(); i++){
				// Отказ нарезки области сообщения
				const context::error_t error = this->carve(pending[i].index, pending[i].offset, pending[i].length);
				// Если область сообщения нарезать не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ нарезки области сообщения
					return error;
			}
		}
		/**
		 * Выполняем перебор сообщений залпа
		 */
		for(size_t i = 0; i < this->_flight.size(); i++){
			// Если сообщение уже нарезано на записи
			if(this->_flight[i].dispatched)
				// Переходим к следующему сообщению залпа
				continue;
			// Отмечаем сообщение нарезанным
			this->_flight[i].dispatched = true;
			// Отказ нарезки сообщения целиком
			const context::error_t error = this->carve(i, 0, (this->_flight[i].message.size() - handshake::HANDSHAKE_HEADER));
			// Если сообщение нарезать не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ нарезки сообщения
				return error;
		}
		// Отказ закрытия собираемой дейтаграммы
		const context::error_t closed = this->settle();
		// Если дейтаграмму закрыть не удалось
		if(closed != context::error_t::NONE)
			// Выводим отказ закрытия дейтаграммы
			return closed;
		// Признак того, что залп ждёт подтверждения
		bool waiting = false;
		/**
		 * Выполняем перебор кусков залпа
		 */
		for(size_t i = 0; (i < this->_pieces.size()) && !waiting; i++)
			// Запоминаем наличие неподтверждённого куска
			waiting = !this->_pieces[i].acked;
		/**
		 * Раздел 5.8.2 RFC 9147: часы заводятся с отправкой залпа и идут, пока залп не
		 * подтверждён; срок ожидания от залпа к залпу держится, а попытки считаются
		 * заново; просьба о повторе приветствия часов не ждёт - её повторяет
		 * повторное приветствие клиента
		 */
		if(waiting && !this->_challenged){
			// Если часы ещё не идут
			if(!this->_timing)
				// Сбрасываем число попыток повторной передачи
				this->_attempts = 0;
			// Заводим часы
			this->_timing = true;
		// Если ждать нечего
		} else this->_timing = false;
	/**
	 * Если памяти под раскладку залпа не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность раскладки залпа
	return context::error_t::NONE;
}
/**
 * @brief Метод повторной передачи залпа по истечении срока
 *
 * @return отказ повторной передачи: TIMEOUT по исчерпании попыток
 *
 */
context::error_t nts::internal::Flight::retransmit() noexcept {
	// Если часы не идут
	if(!this->_timing)
		// Выводим успешность: повторять нечего
		return context::error_t::NONE;
	// Раздел 5.8.2 RFC 9147: по исчерпании попыток связь обрывается
	if(this->_attempts >= datagram::DATAGRAM_ATTEMPTS){
		// Останавливаем часы повторной передачи
		this->_timing = false;
		// Выводим отказ исчерпания попыток
		return context::error_t::TIMEOUT;
	}
	// Считаем попытку повторной передачи
	this->_attempts++;
	// Удваиваем срок ожидания до предела
	this->_timeout = (((this->_timeout * 2) > datagram::DATAGRAM_TIMEOUT_LIMIT) ? datagram::DATAGRAM_TIMEOUT_LIMIT : (this->_timeout * 2));
	// Выводим итог повторной раскладки залпа
	return this->dispatch(true);
}
/**
 * @brief Метод разбора принятой дейтаграммы
 *
 * @param data   принятая дейтаграмма
 * @param result перечень, в который помещаются вскрытые записи
 *
 * @return       отказ разбора: лишь нехватка памяти
 *
 */
context::error_t nts::internal::Flight::receive(const view_t & data, vector <opened_t> & result) noexcept {
	/**
	 * Пустая дейтаграмма либо длиннее принимаемой означает чужой перенос: раздел
	 * 4.5.2 RFC 9147 велит отбрасывать негодное молча, извещений не слать
	 */
	if((data.data == nullptr) || (data.size == 0) || (data.size > datagram::DATAGRAM_LONGEST)){
		// Считаем отброшенную дейтаграмму
		this->discard(datagram::reason_t::LENGTH);
		// Выводим успешность: дейтаграмма отброшена
		return context::error_t::NONE;
	}
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Смещение очередной записи в дейтаграмме
		size_t offset = 0;
		/**
		 * Выполняем перебор записей дейтаграммы
		 */
		while(offset < data.size){
			// Заголовок очередной записи
			datagram::header_t header;
			// Остаток дейтаграммы от начала записи
			const view_t rest(data.data + offset, data.size - offset);
			// Отказ разбора заголовка записи
			const datagram::error_t parsed = datagram::parse(rest, header);
			/**
			 * Негодный заголовок обрывает разбор дейтаграммы: границы следующей записи
			 * по нему не найти, а порча записи по разделу 4.5.2 RFC 9147 не смертельна
			 */
			if(parsed != datagram::error_t::NONE){
				// Считаем отброшенный остаток дейтаграммы
				this->discard(reason(parsed));
				// Прекращаем разбор дейтаграммы
				break;
			}
			// Сдвигаем смещение на следующую запись
			offset += (header.length + header.size);
			// Вскрытая запись
			opened_t item;
			// Устанавливаем вид содержимого записи
			item.type = header.type;
			// Если запись открытая
			if(!header.unified){
				// Нулевая пора чтения
				era_t & keys = this->_plains[1];
				/**
				 * Открытое извещение ничем не подписано и принимается лишь до ключей
				 * чтения; открытые куски рукопожатия судит сборка по своему номеру
				 */
				if((header.type == record::type_t::ALERT) && (this->epoch(true) != 0)){
					// Считаем отброшенную запись
					this->discard(datagram::reason_t::PLAIN);
					// Переходим к следующей записи
					continue;
				}
				// Раздел 4.5.1 RFC 9147: повтор и запись позади окна отбрасываются
				if(keys.window.stale(header.sequence)){
					// Считаем отброшенную запись
					this->discard(datagram::reason_t::REPLAY);
					// Переходим к следующей записи
					continue;
				}
				// Отмечаем открытую запись принятой
				keys.window.mark(header.sequence);
				// Запоминаем порядковый номер записи
				item.sequence = header.sequence;
				// Переносим содержимое открытой записи
				item.content.assign(rest.data + header.length, rest.data + header.length + header.size);
			// Если запись защищена
			} else {
				// Отказ нехватки памяти при вскрытии
				context::error_t failure = context::error_t::NONE;
				// Если запись не вскрыта
				if(!this->unveil(header, rest, item, failure)){
					// Если памяти под вскрытие не хватило
					if(failure != context::error_t::NONE)
						// Выводим отказ нехватки памяти
						return failure;
					// Переходим к следующей записи
					continue;
				}
			}
			// Если содержимое пусто, а вид записи пустоты не дозволяет
			if(item.content.empty() && !record::empty(item.type)){
				// Считаем отброшенную запись
				this->discard(datagram::reason_t::LENGTH);
				// Переходим к следующей записи
				continue;
			}
			// Переносим вскрытую запись в перечень
			result.push_back(::move(item));
		}
	/**
	 * Если памяти под разбор дейтаграммы не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность разбора дейтаграммы
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора кусков сообщений рукопожатия из принятой записи
 *
 * @param content  открытое содержимое записи рукопожатия
 * @param epoch    пора ключей принятой записи
 * @param sequence порядковый номер принятой записи
 * @param settled  признак того, что связь установлена
 *
 * @return         отказ разбора кусков: MESSAGE у порченого защищённого куска
 *
 */
context::error_t nts::internal::Flight::fragments(const view_t & content, const uint16_t epoch, const uint64_t sequence, const bool settled) noexcept {
	// Признак того, что хоть один кусок записи принят сборкой либо разобран прежде
	bool taken = false;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Смещение очередного куска в содержимом записи
		size_t offset = 0;
		/**
		 * Выполняем перебор кусков сообщений записи
		 */
		while(offset < content.size){
			// Обвязка очередного куска
			datagram::fragment_t fragment;
			// Остаток содержимого записи от начала куска
			const view_t rest(content.data + offset, content.size - offset);
			/**
			 * Негодный кусок открытой записи отбрасывается молча, а защищённой - подписан
			 * собеседником и означает его оплошность
			 */
			if(datagram::parse(rest, fragment) != datagram::error_t::NONE){
				// Если запись защищена
				if(epoch != 0)
					// Выводим отказ разбора куска сообщения
					return context::error_t::MESSAGE;
				// Считаем отброшенный остаток записи
				this->discard(datagram::reason_t::FRAMING);
				// Прекращаем разбор записи
				break;
			}
			// Тело куска сообщения
			const view_t body(rest.data + datagram::DATAGRAM_FRAGMENT_HEADER, fragment.length);
			// Сдвигаем смещение на следующий кусок
			offset += (datagram::DATAGRAM_FRAGMENT_HEADER + fragment.length);
			/**
			 * Раздел 5.8.1 RFC 9147: уже разобранное сообщение повторяется собеседником,
			 * не дождавшимся ответа, - ждущий залп повторяется ему раскладкой; за
			 * установленной связью повтор подтверждается явно (раздел 7)
			 */
			if(fragment.sequence < this->_incoming){
				// Если свой залп ждёт подтверждения
				if(!this->_flight.empty())
					// Запоминаем повтор собеседника
					this->_repeated = true;
				// Если связь установлена
				if(settled)
					// Запоминаем, что запись подлежит подтверждению
					taken = true;
				// Переходим к следующему куску
				continue;
			}
			/**
			 * Открытый кусок нового сообщения по появлении ключей чтения - подделка:
			 * настоящий собеседник шлёт новое защищённым
			 */
			if((epoch == 0) && (this->epoch(true) != 0)){
				// Считаем отброшенный кусок
				this->discard(datagram::reason_t::PLAIN);
				// Переходим к следующему куску
				continue;
			}
			// Если сообщение слишком далеко впереди ожидаемого
			if(static_cast <uint16_t> (fragment.sequence - this->_incoming) >= datagram::DATAGRAM_AHEAD){
				// Считаем отброшенный кусок
				this->discard(datagram::reason_t::AHEAD);
				// Переходим к следующему куску
				continue;
			}
			// Если сообщение длиннее собираемого
			if(fragment.size > datagram::DATAGRAM_ASSEMBLY){
				// Если запись защищена
				if(epoch != 0)
					// Выводим отказ длины сообщения
					return context::error_t::MESSAGE;
				// Считаем отброшенный кусок
				this->discard(datagram::reason_t::LENGTH);
				// Переходим к следующему куску
				continue;
			}
			// Сборка сообщения куска
			assembly_t * assembly = nullptr;
			/**
			 * Выполняем перебор сборок принимаемых сообщений
			 */
			for(size_t i = 0; (i < this->_assemblies.size()) && (assembly == nullptr); i++){
				// Если сборка ведёт сообщение куска
				if(this->_assemblies[i].sequence == fragment.sequence)
					// Запоминаем найденную сборку
					assembly = &this->_assemblies[i];
			}
			// Сборка привязана к поре: кусок иной поры к ней не подходит
			if((assembly != nullptr) && (assembly->epoch != epoch)){
				// Считаем отброшенный кусок
				this->discard(datagram::reason_t::EPOCH);
				// Переходим к следующему куску
				continue;
			}
			// Если сборка сообщения ещё не заведена
			if(assembly == nullptr){
				// Новая сборка сообщения
				assembly_t item;
				// Устанавливаем вид сообщения сборки
				item.type = fragment.type;
				// Устанавливаем пору ключей сборки
				item.epoch = epoch;
				// Устанавливаем порядковый номер сообщения сборки
				item.sequence = fragment.sequence;
				// Занимаем место под тело сообщения
				item.body.assign(fragment.size, 0);
				// Добавляем сборку в перечень
				this->_assemblies.push_back(::move(item));
				// Запоминаем заведённую сборку
				assembly = &this->_assemblies.back();
			}
			/**
			 * Куски одного сообщения обязаны сходиться видом и длиной: расхождение в
			 * открытой записи отбрасывается, в защищённой - оплошность собеседника
			 */
			if((assembly->type != fragment.type) || (assembly->body.size() != fragment.size)){
				// Если запись защищена
				if(epoch != 0)
					// Выводим отказ расхождения кусков сообщения
					return context::error_t::MESSAGE;
				// Считаем отброшенный кусок
				this->discard(datagram::reason_t::FRAMING);
				// Переходим к следующему куску
				continue;
			}
			// Если кусок несёт тело
			if(fragment.length > 0)
				// Переносим тело куска на своё место в сообщении
				::memcpy(assembly->body.data() + fragment.offset, body.data, fragment.length);
			// Добавляем область куска в покрытие сообщения
			assembly->spans.push_back(span_t(fragment.offset, fragment.length));
			/**
			 * Раздел 5.5 RFC 9147: куски приходят с любым перекрытием - покрытие держится
			 * упорядоченным по смещению, и соседние области сливаются
			 */
			for(size_t i = assembly->spans.size() - 1; (i > 0) && (assembly->spans[i].offset < assembly->spans[i - 1].offset); i--){
				// Область, переставляемая вперёд
				const span_t item = assembly->spans[i];
				// Сдвигаем соседнюю область назад
				assembly->spans[i] = assembly->spans[i - 1];
				// Ставим область на своё место
				assembly->spans[i - 1] = item;
			}
			// Покрытие сообщения после слияния областей
			vector <span_t> merged;
			/**
			 * Выполняем перебор областей покрытия по возрастанию смещения
			 */
			for(size_t i = 0; i < assembly->spans.size(); i++){
				// Если область примыкает к последней слитой либо перекрывает её
				if(!merged.empty() && (assembly->spans[i].offset <= (merged.back().offset + merged.back().length))){
					// Конец области после слияния
					const size_t end = (assembly->spans[i].offset + assembly->spans[i].length);
					// Если область выходит за последнюю слитую
					if(end > (merged.back().offset + merged.back().length))
						// Растягиваем последнюю слитую область
						merged.back().length = (end - merged.back().offset);
				// Если область стоит особняком
				} else merged.push_back(assembly->spans[i]);
			}
			// Заменяем покрытие сообщения слитым
			assembly->spans = ::move(merged);
			// Запоминаем, что кусок принят сборкой
			taken = true;
		}
		/**
		 * Раздел 7 RFC 9147: подтверждаются лишь записи, куски которых разобраны либо
		 * сложены в сборку; запись, отброшенная целиком, подтверждения не получает
		 */
		if(taken && (this->_acknowledgeable.size() < datagram::DATAGRAM_WINDOW))
			// Запоминаем номер записи под подтверждение
			this->_acknowledgeable.push_back(datagram::number_t(epoch, sequence));
	/**
	 * Если памяти под сборку сообщений не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность разбора кусков
	return context::error_t::NONE;
}
/**
 * @brief Метод выдачи собранного сообщения рукопожатия по порядку
 *
 * @param type вид, в который помещается вид собранного сообщения
 * @param body накопитель, в который переносится тело сообщения
 *
 * @return     признак того, что ожидаемое сообщение собрано и выдано
 *
 */
bool nts::internal::Flight::deliver(handshake::type_t & type, vector <uint8_t> & body) noexcept {
	// Место сборки ожидаемого сообщения
	size_t place = this->_assemblies.size();
	/**
	 * Выполняем перебор сборок принимаемых сообщений
	 */
	for(size_t i = 0; (i < this->_assemblies.size()) && (place == this->_assemblies.size()); i++){
		// Если сборка ведёт ожидаемое сообщение
		if(this->_assemblies[i].sequence == this->_incoming)
			// Запоминаем место сборки
			place = i;
	}
	// Если ожидаемое сообщение ещё не начато
	if(place == this->_assemblies.size())
		// Выводим признак того, что выдавать нечего
		return false;
	// Сборка ожидаемого сообщения
	assembly_t & assembly = this->_assemblies[place];
	// Признак того, что сообщение собрано целиком
	const bool whole = (assembly.body.empty() ? !assembly.spans.empty() : ((assembly.spans.size() == 1) && (assembly.spans[0].offset == 0) && (assembly.spans[0].length == assembly.body.size())));
	// Если сообщение собрано не целиком
	if(!whole)
		// Выводим признак того, что выдавать нечего
		return false;
	// Выводим вид собранного сообщения
	type = assembly.type;
	// Переносим тело собранного сообщения
	body = ::move(assembly.body);
	// Снимаем сборку с перечня
	this->_assemblies.erase(this->_assemblies.begin() + place);
	// Продвигаем порядковый номер ожидаемого сообщения
	this->_incoming++;
	// Выводим признак того, что сообщение выдано
	return true;
}
/**
 * @brief Метод неявного подтверждения залпа ответом собеседника
 *
 */
void nts::internal::Flight::answered() noexcept {
	// Выполняем сброс подтверждённого залпа
	this->_flight.clear();
	// Выполняем сброс кусков подтверждённого залпа
	this->_pieces.clear();
	// Раздел 5.8.2 RFC 9147: залп, подтверждённый без повторов, возвращает срок к начальному
	if(this->_timing && (this->_attempts == 0))
		// Устанавливаем начальный срок ожидания
		this->_timeout = datagram::DATAGRAM_TIMEOUT;
	// Останавливаем часы повторной передачи
	this->_timing = false;
	// Снимаем признак залпа просьбы о повторе
	this->_challenged = false;
}
/**
 * @brief Метод возврата порядкового номера отброшенному сообщению
 *
 */
void nts::internal::Flight::retract() noexcept {
	// Если порядковый номер уже продвинут
	if(this->_incoming > 0)
		// Возвращаем порядковый номер ожидаемого сообщения
		this->_incoming--;
	// Отброшенное сообщение не подтверждается: раздел 7 RFC 9147
	this->_acknowledgeable.clear();
}
/**
 * @brief Метод остановки повторной передачи по обрыву связи
 *
 */
void nts::internal::Flight::halt() noexcept {
	// Выполняем сброс залпа: повторять его некому
	this->_flight.clear();
	// Выполняем сброс кусков залпа
	this->_pieces.clear();
	// Останавливаем часы повторной передачи
	this->_timing = false;
}
/**
 * @brief Метод разбора принятого подтверждения записей
 *
 * @param body   тело принятого сообщения подтверждения
 * @param epoch  пора ключей записи подтверждения
 * @param rotate место, в которое помещается признак вступления своей смены ключей
 *
 * @return       отказ разбора подтверждения
 *
 */
context::error_t nts::internal::Flight::acknowledged(const view_t & body, const uint16_t epoch, bool & rotate) noexcept {
	// Своя смена ключей не вступает
	rotate = false;
	// Подтверждённые номера записей
	vector <datagram::number_t> numbers;
	// Отказ разбора тела подтверждения
	const datagram::error_t parsed = datagram::parse(body, numbers);
	// Если памяти под номера записей не хватило
	if(parsed == datagram::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Если подтверждение пришло открытой порой
	if(epoch == 0){
		/**
		 * Раздел 7.1 RFC 9147: открытой порой принимается лишь пустое подтверждение и лишь
		 * при залпе, ждущем часов, - номера в нём ничем не подписаны, а просьба о
		 * повторе часов не ждёт и повторяется лишь повтором приветствия
		 */
		if((parsed != datagram::error_t::NONE) || !numbers.empty() || !this->_timing){
			// Считаем отброшенную запись
			this->discard(datagram::reason_t::PLAIN);
			// Выводим успешность: подтверждение отброшено
			return context::error_t::NONE;
		}
		// Запоминаем просьбу собеседника о повторе залпа
		this->_nudged = true;
		// Выводим успешность разбора подтверждения
		return context::error_t::NONE;
	}
	// Подтверждение защищено собеседником: негодное означает его оплошность
	if(parsed != datagram::error_t::NONE)
		// Выводим отказ разбора подтверждения
		return context::error_t::MESSAGE;
	// Если подтверждение пусто: собеседнику нечем вскрыть принятое, и он просит повтора
	if(numbers.empty()){
		// Если залп ждёт часов
		if(this->_timing)
			// Запоминаем просьбу собеседника о повторе залпа
			this->_nudged = true;
		// Выводим успешность разбора подтверждения
		return context::error_t::NONE;
	}
	/**
	 * Выполняем перебор подтверждённых номеров записей
	 */
	for(size_t i = 0; i < numbers.size(); i++){
		/**
		 * Выполняем перебор кусков залпа
		 */
		for(size_t j = 0; j < this->_pieces.size(); j++){
			// Если кусок ушёл подтверждённой записью
			if(!this->_pieces[j].acked && (this->_pieces[j].epoch == numbers[i].epoch) && (this->_pieces[j].sequence == numbers[i].sequence))
				// Отмечаем кусок подтверждённым
				this->_pieces[j].acked = true;
		}
	}
	// Признак того, что залп подтверждён целиком
	bool whole = !this->_flight.empty();
	/**
	 * Выполняем перебор сообщений залпа
	 */
	for(size_t i = 0; (i < this->_flight.size()) && whole; i++)
		// Запоминаем, нарезано ли сообщение на записи
		whole = this->_flight[i].dispatched;
	/**
	 * Выполняем перебор кусков залпа
	 */
	for(size_t i = 0; (i < this->_pieces.size()) && whole; i++)
		// Запоминаем, подтверждён ли кусок
		whole = this->_pieces[i].acked;
	// Если залп подтверждён не целиком: повтор остатка ведут часы
	if(!whole)
		// Выводим успешность разбора подтверждения
		return context::error_t::NONE;
	// Выполняем сброс подтверждённого залпа
	this->_flight.clear();
	// Выполняем сброс кусков подтверждённого залпа
	this->_pieces.clear();
	// Раздел 5.8.2 RFC 9147: залп, подтверждённый без повторов, возвращает срок к начальному
	if(this->_attempts == 0)
		// Устанавливаем начальный срок ожидания
		this->_timeout = datagram::DATAGRAM_TIMEOUT;
	// Останавливаем часы повторной передачи
	this->_timing = false;
	/**
	 * Раздел 8 RFC 9147: своя смена ключей вступает лишь по подтверждении сообщения о
	 * ней - до того собеседник читал бы новую пору прежними ключами
	 */
	if(this->_rotating){
		// Снимаем признак ожидающей смены ключей
		this->_rotating = false;
		// Своя смена ключей вступает
		rotate = true;
	}
	// Выводим успешность разбора подтверждения
	return context::error_t::NONE;
}
/**
 * @brief Метод изъятия отложенных записей по смене поры чтения
 *
 * @param before пора чтения до подачи дейтаграммы
 * @param result перечень, в который переносятся отложенные записи
 *
 * @return       признак того, что записи изъяты и подлежат разбору заново
 *
 */
bool nts::internal::Flight::pending(const uint16_t before, vector <vector <uint8_t>> & result) noexcept {
	// Если отложенных записей нет либо пора чтения не сменилась
	if(this->_deferred.empty() || (this->epoch(true) == before))
		// Выводим признак того, что разбирать нечего
		return false;
	// Забираем отложенные записи: разбор вправе отложить их вновь
	result.swap(this->_deferred);
	// Выводим признак того, что записи изъяты
	return true;
}
/**
 * @brief Метод завершения подачи дейтаграммы
 *
 * @param settled признак того, что связь установлена
 *
 * @return        отказ завершения: TIMEOUT по исчерпании попыток повтора
 *
 */
context::error_t nts::internal::Flight::complete(const bool settled) noexcept {
	// Отказ составления подтверждения
	const context::error_t error = this->acknowledge(settled);
	// Если подтверждение составить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ составления подтверждения
		return error;
	// Признак того, что собеседник просит повтора ждущего залпа
	const bool nudged = (this->_nudged && this->_timing);
	// Признак того, что собеседник повторил своё
	const bool repeated = this->_repeated;
	// Снимаем признак просьбы о повторе
	this->_nudged = false;
	// Снимаем признак повтора собеседника
	this->_repeated = false;
	// Снимаем признак отложенной записи
	this->_deferring = false;
	/**
	 * Раздел 7.2 RFC 9147: пустое подтверждение просит повтора залпа тотчас же, а
	 * повтор собеседника повторяет свой залп раскладкой без счёта попыток
	 */
	return (nudged ? this->retransmit() : this->dispatch(repeated));
}
/**
 * @brief Метод получения срока ожидания повторной передачи
 *
 * @return срок в миллисекундах, ноль, когда повторять нечего
 *
 */
uint32_t nts::internal::Flight::timeout() const noexcept {
	// Выводим срок ожидания, когда часы идут
	return (this->_timing ? this->_timeout : 0);
}
/**
 * @brief Метод проверки ожидания подтверждения своей смены ключей
 *
 * @return признак того, что смена ключей ждёт подтверждения
 *
 */
bool nts::internal::Flight::rotating() const noexcept {
	// Выводим признак ожидающей смены ключей
	return this->_rotating;
}
/**
 * @brief Метод отметки своей смены ключей, ждущей подтверждения
 *
 * @param rotating ждёт ли смена ключей подтверждения
 *
 */
void nts::internal::Flight::rotating(const bool rotating) noexcept {
	// Запоминаем ожидание подтверждения смены ключей
	this->_rotating = rotating;
}
/**
 * @brief Метод отметки залпа просьбою о повторе приветствия
 *
 */
void nts::internal::Flight::challenge() noexcept {
	// Запоминаем, что залп составлен просьбою о повторе
	this->_challenged = true;
}
/**
 * @brief Метод составления метки возврата состояния сервера
 *
 * @param message принятое приветствие клиента вместе с обвязкой
 * @param result  накопитель, в который складывается метка
 *
 * @return        отказ составления метки
 *
 */
context::error_t nts::internal::Flight::stamp(const view_t & message, vector <uint8_t> & result) noexcept {
	// Если хеш приветствия клиента выработать не удалось
	if(!digest::hash(digest::hash_t::SHA256, message, this->_digest, sizeof(this->_digest)))
		// Выводим отказ составления метки
		return context::error_t::MESSAGE;
	// Запоминаем, что хеш приветствия сложен в метку
	this->_digested = true;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Выполняем сброс накопителя метки
		result.clear();
		// Записываем поколение секрета метки
		result.push_back(this->_generation);
		// Записываем хеш приветствия клиента
		result.insert(result.end(), this->_digest, this->_digest + sizeof(this->_digest));
		// Данные, покрываемые имитовставкой: поколение, хеш и адрес собеседника
		vector <uint8_t> covered(result);
		// Добавляем адрес собеседника к покрываемым данным
		covered.insert(covered.end(), this->_address.begin(), this->_address.end());
		// Место, в которое помещается имитовставка метки
		uint8_t mac[32];
		// Если имитовставку метки выработать не удалось
		if(!digest::hmac(digest::hash_t::SHA256, view_t(this->_stamps[this->_generation % 2], sizeof(this->_stamps[0])), view_t(covered.data(), covered.size()), mac, sizeof(mac)))
			// Выводим отказ составления метки
			return context::error_t::MESSAGE;
		// Записываем имитовставку метки
		result.insert(result.end(), mac, mac + sizeof(mac));
		// Выполняем затирание имитовставки
		wipe(mac, sizeof(mac));
	/**
	 * Если памяти под метку не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность составления метки
	return context::error_t::NONE;
}
/**
 * @brief Метод проверки метки возврата состояния сервера
 *
 * @param label проверяемая метка, повторённая клиентом
 *
 * @return      признак того, что метка сложена сервером для этого собеседника
 *
 */
bool nts::internal::Flight::verify(const view_t & label) const noexcept {
	/**
	 * Без адреса собеседника метку привязать не к чему, а без выданной метки сверять
	 * её не с чем: приветствие с нею отвергается
	 */
	if(this->_address.empty() || !this->_digested)
		// Выводим отказ проверки метки
		return false;
	// Если метка не сходится длиной
	if((label.data == nullptr) || (label.size != LABEL))
		// Выводим отказ проверки метки
		return false;
	// Поколение секрета метки
	const uint8_t generation = label.data[0];
	// Раздел 5.1 RFC 9147: живы два поколения секрета - нынешнее и предыдущее
	if((generation != this->_generation) && (generation != static_cast <uint8_t> (this->_generation - 1)))
		// Выводим отказ проверки метки
		return false;
	// Данные, покрываемые имитовставкой: поколение, хеш и адрес собеседника
	uint8_t covered[1 + 32 + datagram::DATAGRAM_ADDRESS];
	// Переносим поколение и хеш приветствия
	::memcpy(covered, label.data, 33);
	// Переносим адрес собеседника: длиннее предела он не бывает
	::memcpy(covered + 33, this->_address.data(), this->_address.size());
	// Место, в которое помещается имитовставка метки
	uint8_t mac[32];
	// Если имитовставку метки выработать не удалось
	if(!digest::hmac(digest::hash_t::SHA256, view_t(this->_stamps[generation % 2], sizeof(this->_stamps[0])), view_t(covered, 33 + this->_address.size()), mac, sizeof(mac)))
		// Выводим отказ проверки метки
		return false;
	// Расхождение имитовставок и хешей приветствия
	uint8_t difference = 0;
	/**
	 * Выполняем сличение имитовставок за постоянное время
	 */
	for(size_t i = 0; i < sizeof(mac); i++)
		// Накапливаем расхождение очередного байта
		difference |= static_cast <uint8_t> (mac[i] ^ label.data[33 + i]);
	/**
	 * Выполняем сличение хеша приветствия с выданным: метка чужой связи с того же
	 * адреса сходится имитовставкой, но не хешем
	 */
	for(size_t i = 0; i < sizeof(this->_digest); i++)
		// Накапливаем расхождение очередного байта
		difference |= static_cast <uint8_t> (this->_digest[i] ^ label.data[1 + i]);
	// Выполняем затирание имитовставки
	wipe(mac, sizeof(mac));
	// Выводим итог сличения
	return (difference == 0);
}
/**
 * @brief Метод установки секрета метки возврата состояния
 *
 * @param secret устанавливаемый секрет
 *
 */
void nts::internal::Flight::stamp(const vector <uint8_t> & secret) noexcept {
	// Если секрет не передан
	if(secret.empty())
		// Выходим из метода
		return;
	// Место, в которое помещается свёрнутый секрет
	uint8_t digest[32];
	// Секрет сворачивается хешем: длина его у потребителя любая, а ключ имитовставки постоянен
	if(!digest::hash(digest::hash_t::SHA256, view_t(secret.data(), secret.size()), digest, sizeof(digest)))
		// Выходим из метода
		return;
	// Переносим секрет нынешнему поколению
	::memcpy(this->_stamps[this->_generation % 2], digest, sizeof(digest));
	// Выполняем затирание свёрнутого секрета
	wipe(digest, sizeof(digest));
	// Отмечаем, что секрет метки задан
	this->_stamped = true;
}
/**
 * @brief Метод смены поколения секрета метки возврата состояния
 *
 */
void nts::internal::Flight::restamp() noexcept {
	// Переходим к следующему поколению секрета
	this->_generation++;
	// Если секрет нового поколения выработать не удалось
	if(!entropy::bytes(this->_stamps[this->_generation % 2], sizeof(this->_stamps[0])))
		// Возвращаемся к прежнему поколению
		this->_generation--;
}
/**
 * @brief Метод выработки секретов метки, если они не заданы
 *
 * @return признак того, что секреты метки готовы
 *
 */
bool nts::internal::Flight::prepare() noexcept {
	// Если секрет метки уже задан
	if(this->_stamped)
		// Выводим готовность секретов
		return true;
	// Если секреты обоих поколений выработать не удалось
	if(!entropy::bytes(this->_stamps[0], sizeof(this->_stamps[0])) || !entropy::bytes(this->_stamps[1], sizeof(this->_stamps[1])))
		// Выводим отказ выработки секретов
		return false;
	// Отмечаем, что секрет метки задан
	this->_stamped = true;
	// Выводим готовность секретов
	return true;
}
/**
 * @brief Метод установки адреса собеседника для метки возврата состояния
 *
 * @param address адрес либо иной опознаватель собеседника
 *
 * @return        признак того, что адрес принят
 *
 */
bool nts::internal::Flight::address(const view_t & address) noexcept {
	// Если адрес собеседника снимается
	if((address.data == nullptr) || (address.size == 0)){
		// Выполняем сброс адреса собеседника
		this->_address.clear();
		// Выводим успешность снятия адреса
		return true;
	}
	// Если адрес длиннее покрываемого меткой
	if(address.size > datagram::DATAGRAM_ADDRESS)
		// Выводим отказ установки адреса
		return false;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Переносим адрес собеседника
		this->_address.assign(address.data, address.data + address.size);
	/**
	 * Если памяти под адрес не хватило
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс адреса собеседника
		this->_address.clear();
		// Выводим отказ установки адреса
		return false;
	}
	// Выводим успешность установки адреса
	return true;
}
/**
 * @brief Метод проверки наличия адреса собеседника
 *
 * @return признак того, что адрес собеседника задан
 *
 */
bool nts::internal::Flight::addressed() const noexcept {
	// Выводим признак наличия адреса собеседника
	return !this->_address.empty();
}
/**
 * @brief Метод установки размера дейтаграммы связи
 *
 * @param mtu устанавливаемый размер дейтаграммы в байтах
 *
 */
void nts::internal::Flight::mtu(const size_t mtu) noexcept {
	// Устанавливаем размер дейтаграммы не ниже наименьшего дозволенного
	this->_mtu = ((mtu < datagram::DATAGRAM_MTU_LEAST) ? datagram::DATAGRAM_MTU_LEAST : mtu);
}
/**
 * @brief Метод получения размера дейтаграммы связи
 *
 * @return размер дейтаграммы в байтах
 *
 */
size_t nts::internal::Flight::mtu() const noexcept {
	// Выводим размер дейтаграммы связи
	return this->_mtu;
}
/**
 * @brief Метод учёта молча отброшенной записи либо дейтаграммы
 *
 * @param reason причина отброса
 *
 */
void nts::internal::Flight::discard(const datagram::reason_t reason) noexcept {
	// Если причина известна
	if(static_cast <size_t> (reason) < datagram::DATAGRAM_REASONS)
		// Считаем отброшенное по причине
		this->_discarded[static_cast <size_t> (reason)]++;
}
/**
 * @brief Метод получения числа молча отброшенных записей и дейтаграмм
 *
 * @return число отброшенного по всем причинам
 *
 */
uint64_t nts::internal::Flight::discarded() const noexcept {
	// Число отброшенного по всем причинам
	uint64_t result = 0;
	/**
	 * Выполняем перебор причин отброса
	 */
	for(size_t i = 0; i < datagram::DATAGRAM_REASONS; i++)
		// Прибавляем отброшенное по очередной причине
		result += this->_discarded[i];
	// Выводим число отброшенного
	return result;
}
/**
 * @brief Метод получения числа отброшенного по причине
 *
 * @param reason причина отброса
 *
 * @return       число отброшенного по причине
 *
 */
uint64_t nts::internal::Flight::discarded(const datagram::reason_t reason) const noexcept {
	// Выводим число отброшенного по причине, ноль у неведомой причины
	return ((static_cast <size_t> (reason) < datagram::DATAGRAM_REASONS) ? this->_discarded[static_cast <size_t> (reason)] : 0);
}
/**
 * @brief Метод получения готовой дейтаграммы
 *
 * @return первая готовая дейтаграмма либо пустой просмотр
 *
 */
view_t nts::internal::Flight::output() const noexcept {
	// Выводим первую готовую дейтаграмму либо пустой просмотр
	return (this->_datagrams.empty() ? view_t() : view_t(this->_datagrams.front().data(), this->_datagrams.front().size()));
}
/**
 * @brief Метод снятия первой готовой дейтаграммы
 *
 */
void nts::internal::Flight::consume() noexcept {
	// Если готовые дейтаграммы есть
	if(!this->_datagrams.empty())
		// Снимаем первую готовую дейтаграмму
		this->_datagrams.erase(this->_datagrams.begin());
}
/**
 * @brief Метод затирания ключевого материала пор
 *
 */
void nts::internal::Flight::shred() noexcept {
	/**
	 * Выполняем перебор направлений связи
	 */
	for(size_t i = 0; i < 2; i++){
		/**
		 * Выполняем перебор мест пор ключей направления
		 */
		for(size_t j = 0; j < 2; j++){
			// Выполняем сброс защиты записей поры
			this->_eras[i][j].protection.clear();
			// Выполняем затирание ключа шифрования номера поры
			wipe(this->_eras[i][j].sn, sizeof(this->_eras[i][j].sn));
		}
	}
}
/**
 * @brief Метод сброса состояния переноса
 *
 */
void nts::internal::Flight::clear() noexcept {
	// Выполняем затирание ключевого материала пор
	this->shred();
	/**
	 * Выполняем перебор направлений связи
	 */
	for(size_t i = 0; i < 2; i++){
		/**
		 * Выполняем перебор мест пор ключей направления
		 */
		for(size_t j = 0; j < 2; j++){
			// Выполняем сброс окна повторов поры
			this->_eras[i][j].window.clear();
			// Сбрасываем счёт записей поры
			this->_eras[i][j].next = 0;
			// Сбрасываем номер поры
			this->_eras[i][j].epoch = 0;
			// Защищённые поры пусты
			this->_eras[i][j].held = false;
		}
		// Сбрасываем место защищённой поры
		this->_slots[i] = 0;
		// Выполняем сброс окна повторов нулевой поры
		this->_plains[i].window.clear();
		// Сбрасываем счёт записей нулевой поры
		this->_plains[i].next = 0;
	}
	// Выполняем сброс набора шифрования
	this->_suite = protect::suite_t::NONE;
	// Останавливаем часы повторной передачи
	this->_timing = false;
	// Сбрасываем срок ожидания повторной передачи
	this->_timeout = datagram::DATAGRAM_TIMEOUT;
	// Сбрасываем число попыток повторной передачи
	this->_attempts = 0;
	// Сбрасываем признак залпа просьбы о повторе
	this->_challenged = false;
	// Сбрасываем признак пополнения залпа
	this->_replied = false;
	// Сбрасываем признак ожидающей смены ключей
	this->_rotating = false;
	// Сбрасываем признак повтора собеседника
	this->_repeated = false;
	// Сбрасываем признак просьбы о повторе
	this->_nudged = false;
	// Сбрасываем признак отложенной записи
	this->_deferring = false;
	// Сбрасываем признак выданной метки
	this->_digested = false;
	// Выполняем затирание хеша приветствия
	wipe(this->_digest, sizeof(this->_digest));
	// Выполняем сброс залпа
	this->_flight.clear();
	// Выполняем сброс кусков залпа
	this->_pieces.clear();
	// Сбрасываем порядковый номер отправляемого сообщения
	this->_outgoing = 0;
	// Сбрасываем порядковый номер ожидаемого сообщения
	this->_incoming = 0;
	// Выполняем сброс сборок принимаемых сообщений
	this->_assemblies.clear();
	// Выполняем сброс номеров записей, ждущих подтверждения
	this->_acknowledgeable.clear();
	// Выполняем сброс собираемой дейтаграммы
	this->_packet.clear();
	// Сбрасываем пору ключей собираемой дейтаграммы
	this->_bundle = 0;
	// Выполняем сброс готовых дейтаграмм
	this->_datagrams.clear();
	// Выполняем сброс отложенных записей
	this->_deferred.clear();
	// Выполняем обнуление счётчиков отброшенного
	::memset(this->_discarded, 0, sizeof(this->_discarded));
	// Выполняем сброс адреса собеседника: он принадлежит связи, а не настройкам
	this->_address.clear();
}
/**
 * @brief Конструктор
 *
 */
nts::internal::Flight::Flight() noexcept :
	_suite(protect::suite_t::NONE), _mtu(datagram::DATAGRAM_MTU), _timeout(datagram::DATAGRAM_TIMEOUT), _attempts(0),
	_timing(false), _challenged(false), _replied(false), _rotating(false), _repeated(false), _nudged(false), _deferring(false),
	_stamped(false), _digested(false), _generation(0), _outgoing(0), _incoming(0), _bundle(0) {
	// Выполняем обнуление секретов метки возврата состояния
	::memset(this->_stamps, 0, sizeof(this->_stamps));
	// Выполняем обнуление хеша приветствия
	::memset(this->_digest, 0, sizeof(this->_digest));
	// Выполняем обнуление счётчиков отброшенного
	::memset(this->_discarded, 0, sizeof(this->_discarded));
	// Нулевая пора записи заведена с самого начала
	this->_plains[0].held = true;
	// Нулевая пора чтения заведена с самого начала
	this->_plains[1].held = true;
	// Место защищённой поры записи
	this->_slots[0] = 0;
	// Место защищённой поры чтения
	this->_slots[1] = 0;
}
