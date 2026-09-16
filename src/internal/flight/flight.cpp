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
 * @brief Исходный файл внутреннего модуля переноса рукопожатия дейтаграммами по DTLS 1.3 и DTLS 1.2
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
 * 8. Издание DTLS 1.2 (RFC 6347) ведётся тем же переносом по признаку legacy: всякая
 *    запись, и защищённая тоже, идёт открытым заголовком с порой и 48-разрядным номером
 *    (раздел 4.1), защита - записями издания TLS 1.2 с порой и номером в связанных
 *    данных (раздел 4.1.2.1), поры лишь две - нулевая до смены набора шифрования и первая
 *    за нею; подтверждений, шифрования номера и просьбы о повторе приветствия у издания
 *    нет. Смена набора шифрования ложится в залп записью и повторяется вместе с ним
 *    (раздел 4.2.4). Запись первой поры, обогнавшая смену набора, откладывается до неё.
 *
 * 9. Сервер издания DTLS 1.2 до принятой метки состояния по связи не держит (раздел 4.2.1):
 *    залп с HelloVerifyRequest сбрасывается по раскладке, номер сообщения возвращается к
 *    нулю, а приветствие клиента принимается номером 0 (первое) либо 1 (с меткой); чужой
 *    кусок и запись первой поры до метки отбрасываются молча (GREETING, EPOCH), отложенных
 *    записей не заводится; дроблёное приветствие собирается под пределами решения 13, а у
 *    строгого сервера (strict) отбрасывается, как у DTLSv1_listen; метка сверяется по хешу,
 *    посчитанному заново из повторённого приветствия, а не по запомненному, и хеш её
 *    составление не запоминает. По принятой метке запись приветствия отмечается в окне
 *    нулевой поры: повтор её - REPLAY. Последний залп сервера (смена набора и завершение)
 *    часов не ждёт и повторяется лишь по повтору завершения клиента (раздел 4.2.4).
 *
 * 10. Метка издания DTLS 1.2 короткая: поколение и имитовставка, 33 байта, ибо просьба о
 *    подтверждении адреса обязана быть короче наименьшего приветствия клиента (69 байтов)
 *    - иначе сервер усиливал бы чужой поток; хеш приветствия покрыт имитовставкой и в
 *    метке не повторяется. Метка издания 1.3 (65 байтов, с хешем) не тронута.
 *
 * 11. За появлением ключей чтения открытый кусок с прежним номером у издания 1.2
 *    отбрасывается (PLAIN), а не повторяет свой залп: последний залп сервера повторяется
 *    лишь по повтору ЗАЩИЩЁННОГО завершения клиента - подделать его нечем. У издания 1.3
 *    открытый повтор разобранного остаётся (решение 1): повторное приветствие клиента там
 *    открытое, и потеря ответа лечится лишь его повтором.
 *
 * 12. Повторная просьба о подтверждении адреса (номером ноль при ожидаемой единице)
 *    выдаётся клиенту как ожидаемая: сервер, сменивший секрет метки, вправе спросить
 *    заново; число таких просьб ограничивает движок.
 *
 * 13. Дроблёное приветствие клиента до принятой метки СОБИРАЕТСЯ умолчанием, ибо чужие
 *    клиенты дробят повторное приветствие умолчанием (openssl: 232 байта тела кусками
 *    203 + 29 без единого ключа - начальный MTU у него 256), и строгий отказ означал бы
 *    «клиент openssl со стандартными настройками не связывается никогда»; эталонный
 *    сервер openssl (без -listen, с состоянием) дроблёное собирает. Сборка ведётся под
 *    жёсткими пределами, ибо память занимается по чужому слову: приветствие не длиннее
 *    DATAGRAM_GREETING, сборок не больше DATAGRAM_GREETINGS (старейшая снимается), каждая
 *    привязана к адресу собеседника - куски разных адресов не смешиваются, выдаче подлежит
 *    сборка адреса принятой дейтаграммы, а по принятой метке чужие сборки снимаются; срок
 *    жизни сборки ограничен вытеснением и меткой, а не часами. Строгий сервер (strict)
 *    принимает приветствие лишь целиком, как DTLSv1_listen, - для связи своих клиентов со
 *    своими серверами, где дробления не бывает. Заголовок записи с HelloVerifyRequest
 *    несёт издание DTLS 1.0 (0xFEFF), как и её тело и как у openssl: просьба уходит до
 *    согласования издания и обязана быть понятна клиенту одного лишь DTLS 1.0.
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
	 * Длина метки возврата состояния издания DTLS 1.3: поколение, хеш приветствия и имитовставка
	 */
	static constexpr size_t LABEL = (1 + 32 + 32);

	/**
	 * Длина метки возврата состояния издания DTLS 1.2: поколение и имитовставка (раздел 4.2.1 RFC 6347)
	 */
	static constexpr size_t TOKEN = (1 + 32);

	/**
	 * Тело записи смены набора шифрования: раздел 7.1 RFC 5246 - единственный байт со значением один
	 */
	static const uint8_t CHANGE[1] = {0x01};

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
			// Если заголовок издания DTLS 1.2 несёт чужое издание протокола
			case static_cast <uint8_t> (datagram::error_t::VERSION): return datagram::reason_t::VERSION;
		}
		// Всё прочее - длина: нехватка байтов либо выход за предел
		return datagram::reason_t::LENGTH;
	}
};

/**
 * @brief Конструктор
 *
 */
nts::internal::Era::Era() noexcept : held(false), epoch(0), next(0), forged(0) {
	// Выполняем обнуление ключа шифрования номера записи
	::memset(this->sn, 0, sizeof(this->sn));
}
/**
 * @brief Метод сброса поры ключей перед заведением
 *
 * @param era пора ключей, приводимая к пустой
 *
 */
void nts::internal::Flight::refresh(era_t & era) noexcept {
	// Выполняем сброс защиты записей поры
	era.protection.clear();
	// Выполняем затирание ключа шифрования номера поры: изданию 1.2 он не нужен, изданию 1.3 ляжет новый
	wipe(era.sn, sizeof(era.sn));
	// Выполняем сброс окна повторов поры
	era.window.clear();
	// Сбрасываем счёт записей поры
	era.next = 0;
	// Сбрасываем счёт подделок поры
	era.forged = 0;
	// Снимаем признак заведённости поры
	era.held = false;
}
/**
 * @brief Метод чистки открытых сборок по появлении ключей чтения
 *
 */
void nts::internal::Flight::purge() noexcept {
	/**
	 * Ключи чтения появились: открытые куски отныне принимаются лишь повтором
	 * разобранного, а недособранные открытые сообщения - чужой мусор
	 */
	for(size_t i = this->_assemblies.size(); i > 0; i--){
		// Если сборка ведётся открытыми кусками
		if(this->_assemblies[i - 1].epoch == 0)
			// Снимаем сборку с перечня
			this->_assemblies.erase(this->_assemblies.begin() + (i - 1));
	}
}
/**
 * @brief Метод получения накладных байтов записи поры
 *
 * @param epoch пора ключей записи
 *
 * @return      накладные байты записи поры
 *
 */
size_t nts::internal::Flight::overhead(const uint16_t epoch) const noexcept {
	// Открытая запись нулевой поры несёт лишь заголовок
	if(epoch == 0)
		// Выводим длину заголовка открытой записи
		return datagram::DATAGRAM_PLAIN_HEADER;
	// Раздел 4.1 RFC 6347: у DTLS 1.2 открытый заголовок, явная часть и метка целостности
	if(this->_legacy)
		// Выводим накладные байты защищённой записи издания DTLS 1.2: у наборов CBC ещё и дополнение до блока с байтом длины (раздел 6.2.3.2 RFC 5246)
		return (datagram::DATAGRAM_PLAIN_HEADER + protect::prefix(this->_suite) + protect::tag(this->_suite) + ((protect::mac(this->_suite) != digest::hash_t::NONE) ? 16 : 0));
	// Раздел 4 RFC 9147: объединённый заголовок, вид содержимого и метка целостности
	return (datagram::DATAGRAM_UNIFIED_HEADER + 1 + protect::tag(this->_suite));
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
 * @param type    вид содержимого записи
 * @param data    содержимое записи
 * @param era     пора ключей, которой запись защищается
 * @param result  накопитель, в конец которого дописывается запись
 * @param ancient издание заголовка записи DTLS 1.0: просьба о подтверждении адреса (раздел 4.2.1 RFC 6347)
 *
 * @return        отказ составления записи
 *
 */
context::error_t nts::internal::Flight::shield(const record::type_t type, const view_t & data, era_t & era, vector <uint8_t> & result, const bool ancient) noexcept {
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
		/**
		 * Раздел 4.1 RFC 6347: у издания DTLS 1.2 всякая запись идёт открытым заголовком с
		 * порой и номером, а защищённое содержимое складывается записью издания TLS 1.2 с
		 * порой и номером в связанных данных (раздел 4.1.2.1)
		 */
		if(this->_legacy){
			// Если запись идёт нулевой порой ключей: содержимое открыто
			if(era.epoch == 0){
				// Раздел 6.2.1 RFC 5246: открытая запись не пуста и не шире 2^14
				if((data.size == 0) || (data.size > record::RECORD_PLAINTEXT))
					// Выводим отказ составления записи
					return context::error_t::RECORD;
				// Устанавливаем длину содержимого записи
				header.size = data.size;
				// Если заголовок открытой записи составить не удалось
				if(datagram::build(header, buffer, length, true, ancient) != datagram::error_t::NONE)
					// Выводим отказ составления записи
					return context::error_t::RECORD;
				// Складываем заголовок открытой записи в накопитель
				result.insert(result.end(), buffer, buffer + length);
				// Складываем содержимое открытой записи в накопитель
				result.insert(result.end(), data.data, data.data + data.size);
			// Если запись идёт первой порой ключей: содержимое защищено
			} else {
				// Если ключевой материал поры не установлен
				if(!era.protection.ready())
					// Выводим отказ негодного состояния связи
					return context::error_t::STATE;
				// Занимаем место под заголовок: длина содержимого известна лишь по наложении защиты
				result.insert(result.end(), buffer, buffer + datagram::DATAGRAM_PLAIN_HEADER);
				// Номер записи в связанных данных: пора и порядковый номер (раздел 4.1.2.1 RFC 6347)
				const uint64_t number = ((static_cast <uint64_t> (era.epoch) << 48) | era.next);
				// Отказ наложения защиты на запись
				const context::error_t failure = translate(era.protection.wrap(number, (ancient ? record::version_t::DTLS10 : record::version_t::DTLS12), type, data, result), context::error_t::PROTECTION);
				// Если защиту на запись наложить не удалось
				if(failure != context::error_t::NONE){
					// Возвращаем накопитель к прежней длине
					result.resize(offset);
					// Выводим отказ наложения защиты
					return failure;
				}
				// Устанавливаем длину защищённого содержимого
				header.size = (result.size() - offset - datagram::DATAGRAM_PLAIN_HEADER);
				// Если заголовок защищённой записи составить не удалось
				if(datagram::build(header, result.data() + offset, length, true, ancient) != datagram::error_t::NONE){
					// Возвращаем накопитель к прежней длине
					result.resize(offset);
					// Выводим отказ составления записи
					return context::error_t::RECORD;
				}
			}
			// Продвигаем счёт записей поры
			era.next++;
			// Выводим успешность составления записи издания DTLS 1.2
			return context::error_t::NONE;
		}
		// Если запись идёт нулевой порой ключей
		if(era.epoch == 0){
			// Запись идёт открытым заголовком
			header.unified = false;
			// Устанавливаем длину содержимого записи
			header.size = data.size;
			/**
			 * Раздел 4.2.1 RFC 6347: просьба о подтверждении адреса уходит до согласования
			 * издания заголовком DTLS 1.0 (0xFEFF) - раскладка открытого заголовка у изданий
			 * одна, различается лишь издание (решение 13)
			 */
			if((ancient ? datagram::build(header, buffer, length, true, true) : datagram::build(header, buffer, length)) != datagram::error_t::NONE)
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
	// Раздел 4.1.2.1 RFC 6347: защищённая запись издания DTLS 1.2 вскрывается своим путём
	if(this->_legacy)
		// Выводим итог вскрытия записи издания DTLS 1.2
		return this->uncover(header, rest, result, failure);
	// Защищённое содержимое записи
	const view_t payload(rest.data + header.length, header.size);
	/**
	 * Раздел 4.2.3 RFC 9147: маска берётся от образца шифртекста, а сам он не короче метки -
	 * суд длины идёт до откладывания записи следующей поры, иначе чужие обрывки с угаданной
	 * порой занимали бы все места отложенных записей и рождали бы пустые подтверждения
	 */
	if((payload.size < datagram::DATAGRAM_SAMPLE) || (payload.size <= protect::tag(this->_suite))){
		// Считаем отброшенную запись
		this->discard(datagram::reason_t::LENGTH);
		// Выводим признак того, что запись не принята
		return false;
	}
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
		// Раздел 4.5.3 RFC 9147: по достижении предела подделок на ключе связь закрывается
		if(++keys->forged >= datagram::DATAGRAM_FORGERY)
			// Запоминаем отказ защиты: пропуском он не лечится
			failure = context::error_t::PROTECTION;
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
 * @brief Метод вскрытия защищённой записи издания DTLS 1.2
 *
 * @param header  заголовок записи
 * @param rest    остаток дейтаграммы от начала записи
 * @param result  запись, в которую помещается открытое содержимое
 * @param failure место, в которое помещается отказ нехватки памяти
 *
 * @return        признак того, что запись вскрыта и принята окном
 *
 */
bool nts::internal::Flight::uncover(const datagram::header_t & header, const view_t & rest, opened_t & result, context::error_t & failure) noexcept {
	// Защищённое содержимое записи
	const view_t payload(rest.data + header.length, header.size);
	// Пора ключей чтения, названная заголовком
	era_t * keys = this->era(1, header.epoch);
	// Если пора ключей записи не найдена
	if(keys == nullptr){
		/**
		 * Раздел 4.1 RFC 6347: запись первой поры, обогнавшая смену набора шифрования,
		 * откладывается до неё - завершение собеседника приходит одной дейтаграммой со сменой;
		 * сервер без состояния (раздел 4.2.1) не откладывает ничего - память под чужое слово
		 */
		if(!this->_stateless && (header.epoch == 1) && (this->current(1).epoch == 0) && (this->_deferred.size() < datagram::DATAGRAM_DEFERRED)){
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
		// Раздел 4.1.2.7 RFC 6347: запись неведомой поры отбрасывается молча
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
	// Защищённое содержимое не короче явной части и метки целостности
	if(payload.size < (protect::prefix(this->_suite) + protect::tag(this->_suite))){
		// Считаем отброшенную запись
		this->discard(datagram::reason_t::LENGTH);
		// Выводим признак того, что запись не принята
		return false;
	}
	// Раздел 4.1.2.6 RFC 6347: повтор и запись позади окна отбрасываются до снятия защиты
	if(keys->window.stale(header.sequence)){
		// Считаем отброшенную запись
		this->discard(datagram::reason_t::REPLAY);
		// Выводим признак того, что запись не принята
		return false;
	}
	// Издание протокола из заголовка по проводу: оно входит в связанные данные как есть
	const record::version_t version = static_cast <record::version_t> (header.version);
	// Номер записи в связанных данных: пора и порядковый номер (раздел 4.1.2.1 RFC 6347)
	const uint64_t number = ((static_cast <uint64_t> (header.epoch) << 48) | header.sequence);
	// Отказ снятия защиты с записи
	const context::error_t opened = translate(keys->protection.unwrap(number, version, header.type, payload, result.content), context::error_t::PROTECTION);
	// Нехватка памяти к защите записи не относится и пропуском не лечится
	if(opened == context::error_t::MEMORY){
		// Запоминаем отказ нехватки памяти
		failure = opened;
		// Выводим признак того, что запись не принята
		return false;
	}
	// Раздел 4.1.2.1 RFC 6347: порченая запись отбрасывается молча, извещение не идёт
	if(opened != context::error_t::NONE){
		// Считаем отброшенную запись
		this->discard(datagram::reason_t::DAMAGE);
		// Раздел 4.5.3 RFC 9147 (тот же предел и у издания 1.2): по достижении предела подделок связь закрывается
		if(++keys->forged >= datagram::DATAGRAM_FORGERY)
			// Запоминаем отказ защиты: пропуском он не лечится
			failure = context::error_t::PROTECTION;
		// Выводим признак того, что запись не принята
		return false;
	}
	// Отмечаем запись принятой лишь после снятия защиты
	keys->window.mark(header.sequence);
	// Вид содержимого у издания 1.2 идёт открытым заголовком
	result.type = header.type;
	// Запоминаем пору ключей записи
	result.epoch = keys->epoch;
	// Запоминаем порядковый номер записи
	result.sequence = header.sequence;
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
	/**
	 * Раздел 4.2.4 RFC 6347: смена набора шифрования идёт в залпе своей записью нулевой
	 * поры и повторяется вместе с ним; дейтаграмма с нею закрывается сменой поры
	 */
	if(item.change){
		// Накладные байты записи смены набора: заголовок открытой записи
		const size_t overhead = datagram::DATAGRAM_PLAIN_HEADER;
		// Если собираемая дейтаграмма идёт иной порой либо запись в неё не входит
		if(!this->_packet.empty() && ((this->_bundle != item.epoch) || ((this->_packet.size() + overhead + sizeof(CHANGE)) > this->_mtu))){
			// Отказ закрытия собираемой дейтаграммы
			const context::error_t closed = this->settle();
			// Если дейтаграмму закрыть не удалось
			if(closed != context::error_t::NONE)
				// Выводим отказ закрытия дейтаграммы
				return closed;
		}
		// Кусок залпа, уходящий записью смены набора
		piece_t piece;
		// Запоминаем пору ключей записи
		piece.epoch = item.epoch;
		// Запоминаем порядковый номер записи
		piece.sequence = keys->next;
		// Запоминаем место записи в залпе
		piece.index = index;
		// Запоминаем смещение: единственный байт
		piece.offset = 0;
		// Запоминаем длину: единственный байт
		piece.length = sizeof(CHANGE);
		// Отказ составления записи смены набора шифрования
		const context::error_t error = this->shield(record::type_t::CHANGE, view_t(CHANGE, sizeof(CHANGE)), *keys, this->_packet, this->_ancient);
		// Если запись составить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ составления записи
			return error;
		// Запоминаем пору ключей собираемой дейтаграммы
		this->_bundle = item.epoch;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Запоминаем кусок залпа
			this->_pieces.push_back(piece);
		/**
		 * Если памяти под кусок не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		}
		// Выводим успешность составления записи смены набора
		return context::error_t::NONE;
	}
	// Длина тела сообщения без обвязки TLS
	const size_t total = (item.message.size() - handshake::HANDSHAKE_HEADER);
	// Если область вышла за тело сообщения
	if((offset > total) || (length > (total - offset)))
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Накладные байты записи с куском: заголовок записи с видом и меткой по поре и обвязка куска
	const size_t overhead = (this->overhead(item.epoch) + datagram::DATAGRAM_FRAGMENT_HEADER);
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
		 * Признак того, что кусок ещё не ушёл: пустое сообщение (конец приветствия сервера
		 * издания 1.2) уходит единственным пустым куском, иначе оно не ушло бы вовсе
		 */
		bool pending = true;
		/**
		 * Выполняем нарезку области на куски по размеру дейтаграммы
		 */
		while((done < length) || pending){
			// Кусок уходит
			pending = false;
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
			// Наибольший кусок: не шире записи протокола и не шире предела собеседника за вычетом обвязки куска
			const size_t widest = (((this->_limit - datagram::DATAGRAM_FRAGMENT_HEADER) > WIDEST) ? WIDEST : (this->_limit - datagram::DATAGRAM_FRAGMENT_HEADER));
			// Место, остающееся в дейтаграмме под кусок, не шире наибольшего куска
			const size_t room = ((((this->_mtu - this->_packet.size() - overhead) > widest) ? widest : (this->_mtu - this->_packet.size() - overhead)));
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
			const context::error_t error = this->shield(record::type_t::HANDSHAKE, view_t(chunk.data(), chunk.size()), *keys, this->_packet, (this->_ancient || item.ancient));
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
	/**
	 * Раздел 4.2.4 RFC 6347: у издания DTLS 1.2 подтверждений нет - залп подтверждается
	 * лишь ответным залпом; сервер без состояния (раздел 4.2.1) не подтверждает ничего
	 */
	if(this->_legacy || this->_stateless){
		// Принятые записи подтверждать нечем
		this->_acknowledgeable.clear();
		// Выводим успешность: подтверждение не положено
		return context::error_t::NONE;
	}
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
	// Пустой перечень номеров: подтверждение без номеров
	static const vector <datagram::number_t> NOTHING;
	/**
	 * Перечень берётся ссылкой, а не условным выражением с временным перечнем: то
	 * копировало бы принятые номера, и копия под нехваткой памяти бросала бы мимо
	 * перехвата (вскрыто голоданием DtlsTest.Starved при сдвиге номеров выделений)
	 */
	const vector <datagram::number_t> & numbers = (listed ? this->_acknowledgeable : NOTHING);
	// Раздел 7 RFC 9147: подтверждение идёт наивысшей порой записи
	era_t & keys = this->current(0);
	// Обвязка записи в дейтаграмме
	const size_t overhead = this->overhead(keys.epoch);
	// Место под содержимое записи подтверждения: дейтаграмма за вычетом обвязки, не шире предела собеседника (RFC 8449 §4)
	const size_t room = (((this->_mtu > overhead) ? (this->_mtu - overhead) : 0) > this->_limit) ? this->_limit : ((this->_mtu > overhead) ? (this->_mtu - overhead) : 0);
	// Число номеров, умещающихся в одну запись подтверждения: место за вычетом длины перечня, не меньше одного
	const size_t portion = ((room > (2 + 16)) ? ((room - 2) / 16) : 1);
	// Число записей подтверждения: пустое подтверждение - одна запись
	const size_t records = (numbers.empty() ? 1 : ((numbers.size() + portion - 1) / portion));
	/**
	 * Выполняем составление записей подтверждения: перечень дробится по месту в дейтаграмме
	 * (раздел 4.4 RFC 9147: дейтаграмма не шире PMTU), каждая порция - своей дейтаграммой
	 */
	for(size_t i = 0; i < records; i++){
		/**
		 * Выполняем перехват ошибок работы с памятью: порция копируется
		 */
		try {
			// Порция номеров
			const vector <datagram::number_t> slice(numbers.begin() + (i * portion), numbers.begin() + (((i + 1) * portion < numbers.size()) ? ((i + 1) * portion) : numbers.size()));
			// Сбрасываем тело прежней порции
			body.clear();
			// Если тело порции составить не удалось
			if(datagram::build(slice, body) != datagram::error_t::NONE)
				// Выводим отказ нехватки памяти
				return context::error_t::MEMORY;
		/**
		 * Если памяти под порцию не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		}
		// Если собираемая дейтаграмма идёт иной порой ключей либо в ней уже лежит порция подтверждения
		if(!this->_packet.empty() && ((this->_bundle != keys.epoch) || (i > 0))){
			// Отказ закрытия собираемой дейтаграммы
			const context::error_t closed = this->settle();
			// Если дейтаграмму закрыть не удалось
			if(closed != context::error_t::NONE)
				// Выводим отказ закрытия дейтаграммы
				return closed;
		}
		// Отказ составления записи подтверждения
		const context::error_t error = this->shield(record::type_t::ACK, view_t(body.data(), body.size()), keys, this->_packet, this->_ancient);
		// Если запись подтверждения составить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ составления подтверждения
			return error;
		// Запоминаем пору ключей собираемой дейтаграммы
		this->_bundle = keys.epoch;
	}
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
	// Выполняем сброс новой поры перед заведением
	this->refresh(fresh);
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
	// Ключи чтения появились: открытые сборки - чужой мусор
	if(incoming)
		// Выполняем чистку открытых сборок
		this->purge();
	// Выводим успешность заведения поры ключей
	return context::error_t::NONE;
}
/**
 * @brief Метод заведения поры ключей направления изданием DTLS 1.2
 *
 * @param incoming заводится ли пора направления собеседника
 * @param suite    набор шифрования связи издания TLS 1.2
 * @param key      ключ защиты записей поры
 * @param vector   вектор замены защиты записей поры
 * @param mac      ключ имитовставки поры у наборов CBC, пустой у наборов AEAD
 * @param etm      ведётся ли защита CBC в порядке «шифрование, затем имитовставка»
 *
 * @return         отказ заведения поры ключей
 *
 */
context::error_t nts::internal::Flight::adopt(const bool incoming, const protect::suite_t suite, const view_t & key, const view_t & vector, const view_t & mac, const bool etm) noexcept {
	// Место направления: запись у своей стороны, чтение у собеседника
	const size_t direction = (incoming ? 1 : 0);
	// Раздел 4.1 RFC 6347: за нулевой порой идёт первая, а пересогласований связь не ведёт
	if(!this->_legacy || (this->current(direction).epoch != 0))
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Изданию 1.2 годны лишь его наборы
	if(!protect::legacy(suite))
		// Выводим отказ вывода ключевого материала
		return context::error_t::SCHEDULE;
	// Место новой поры
	const uint8_t slot = static_cast <uint8_t> (1 - this->_slots[direction]);
	// Новая пора ключей направления
	era_t & fresh = this->_eras[direction][slot];
	// Выполняем сброс новой поры перед заведением
	this->refresh(fresh);
	// Если ключевой материал установить не удалось
	if(!fresh.protection.start(suite, key, vector, mac))
		// Выводим отказ установки ключевого материала
		return context::error_t::SCHEDULE;
	// Раздел 3 RFC 7366: согласованный порядок защиты CBC ставится поре
	fresh.protection.etm(etm);
	// Запоминаем набор шифрования связи
	this->_suite = suite;
	// Раздел 4.1 RFC 6347: смена набора шифрования открывает первую пору
	fresh.epoch = 1;
	// Отмечаем заведённость новой поры
	fresh.held = true;
	// Делаем новую пору текущей
	this->_slots[direction] = slot;
	// Ключи чтения появились: открытые сборки - чужой мусор
	if(incoming)
		// Выполняем чистку открытых сборок
		this->purge();
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
		/**
		 * Раздел 4.2.4 RFC 6347: смена набора шифрования у издания DTLS 1.2 ложится в залп
		 * записью нулевой поры и повторяется вместе с ним; изданию 1.3 она неведома
		 */
		if(this->_legacy && (type == record::type_t::CHANGE)){
			// Запись залпа
			dispatch_t item;
			// Запись идёт сменой набора, а не сообщением
			item.change = true;
			// Запоминаем пору ключей записи
			item.epoch = keys.epoch;
			// Переносим тело смены набора шифрования
			item.message.assign(CHANGE, CHANGE + sizeof(CHANGE));
			// Добавляем запись в залп
			this->_flight.push_back(::move(item));
			// Запоминаем, что залп пополнился
			this->_replied = true;
			// Выводим успешность складывания смены набора в залп
			return context::error_t::NONE;
		}
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
			// Раздел 4.2.1 RFC 6347: просьба о подтверждении адреса уходит заголовком записи издания DTLS 1.0, как её тело и как у openssl (решение 13)
			item.ancient = ((data.size > 0) && (data.data[0] == static_cast <uint8_t> (handshake::type_t::VERIFY_REQUEST)));
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
	// Накладные байты записи: заголовок, вид содержимого и метка целостности по поре
	const size_t overhead = this->overhead(keys.epoch);
	// Если и пустая дейтаграмма записи не вмещает
	if(this->_mtu <= overhead)
		// Выводим отказ составления записи
		return context::error_t::RECORD;
	// Наибольшее содержимое записи, входящее в дейтаграмму и не шире предела собеседника (RFC 8449, RFC 6066)
	const size_t room = (((this->_mtu - overhead) > this->_limit) ? this->_limit : (this->_mtu - overhead));
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
		failure = this->shield(type, view_t(data.data + offset, size), keys, this->_packet, this->_ancient);
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
				// Число кусков залпа до нарезки
				const size_t before = this->_pieces.size();
				// Отказ нарезки области сообщения
				const context::error_t error = this->carve(pending[i].index, pending[i].offset, pending[i].length);
				// Если область сообщения нарезать не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ нарезки области сообщения
					return error;
				/**
				 * Запоминаем у новых кусков номер прежней записи: подтверждение на неё,
				 * задержавшееся за повтором, подтверждает тот же кусок, а не теряется
				 */
				for(size_t j = before; j < this->_pieces.size(); j++){
					// Отмечаем, что кусок уже уходил
					this->_pieces[j].former = true;
					// Запоминаем пору прежней записи
					this->_pieces[j].formerEpoch = pending[i].epoch;
					// Запоминаем номер прежней записи
					this->_pieces[j].formerSequence = pending[i].sequence;
				}
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
		/**
		 * Раздел 4.2.1 RFC 6347: сервер без состояния залп с просьбой о подтверждении адреса
		 * не держит и не повторяет - её повторяет повторное приветствие клиента, а номер
		 * сообщения у просьбы всегда нулевой
		 */
		if(this->_stateless){
			// Выполняем сброс залпа
			this->_flight.clear();
			// Выполняем сброс кусков залпа
			this->_pieces.clear();
			// Просьба о подтверждении адреса идёт нулевым номером всякий раз
			this->_outgoing = 0;
			// Часы не идут
			this->_timing = false;
			// Выводим успешность раскладки залпа
			return context::error_t::NONE;
		}
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
		 * повторное приветствие клиента; последний залп издания 1.2 часов не ждёт
		 * (раздел 4.2.4 RFC 6347) - повторяется он лишь по повтору собеседника
		 */
		if(waiting && !this->_challenged && !this->_concluded){
			// Если часы ещё не идут
			if(!this->_timing){
				// Сбрасываем число попыток повторной передачи
				this->_attempts = 0;
				// Новый срок - ранний повтор дозволен; по идущим часам срок прежний, и гейт держится
				this->_prodded = false;
			}
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
	// Новый срок - новый ранний повтор дозволен
	this->_prodded = false;
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
	if((data.data == nullptr) || (data.size == 0) || (data.size > (this->_legacy ? (datagram::DATAGRAM_PLAIN_HEADER + record::RECORD_PROTECTED) : datagram::DATAGRAM_LONGEST))){
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
			// Отказ разбора заголовка записи по изданию переноса: у издания 1.2 заголовок свой (раздел 4.1 RFC 6347)
			const datagram::error_t parsed = datagram::parse(rest, header, this->_legacy, this->_ancient);
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
				// Раздел 4 RFC 9147: прикладные данные и сердцебиение открытой записью не ходят - открытый текст приложению не впрыскивается
				if((header.type == record::type_t::APPLICATION) || (header.type == record::type_t::HEARTBEAT)){
					// Считаем отброшенную запись
					this->discard(datagram::reason_t::PLAIN);
					// Переходим к следующей записи
					continue;
				}
				if((header.type == record::type_t::ALERT) && (this->epoch(true) != 0)){
					// Считаем отброшенную запись
					this->discard(datagram::reason_t::PLAIN);
					// Переходим к следующей записи
					continue;
				}
				/**
				 * Раздел 4.5.1 RFC 9147: повтор и запись позади окна отбрасываются; сервер до
				 * подтверждения адреса (раздел 4.2.1 RFC 6347, раздел 5.1 RFC 9147) окна не ведёт -
				 * открытые записи идут к нему от всякого собеседника своим счётом, и судить их
				 * окном одной связи нельзя, а чужой большой номер закрыл бы окном настоящее приветствие
				 */
				if(this->_verified && keys.window.stale(header.sequence)){
					// Считаем отброшенную запись
					this->discard(datagram::reason_t::REPLAY);
					// Переходим к следующей записи
					continue;
				}
				/**
				 * Отмечаем открытую запись принятой (до подтверждения адреса сервер ничего
				 * не помнит), но окно не двигаем дальше ожидаемого номера на его ширину:
				 * открытая запись ничем не подписана, и чужая запись с номером 2^48 - 1
				 * закрыла бы иначе все настоящие открытые записи собеседника
				 */
				if(this->_verified && (header.sequence < (keys.window.expected() + datagram::DATAGRAM_WINDOW)))
					// Отмечаем запись в окне
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
			// Признак того, что кусок несёт приветствие клиента целиком
			const bool whole = ((fragment.type == handshake::type_t::CLIENT) && (fragment.offset == 0) && (fragment.length == fragment.size));
			// Признак того, что кусок несёт приветствие клиента до подтверждения адреса: первое либо повторённое с меткой
			const bool greeting = ((fragment.type == handshake::type_t::CLIENT) && (fragment.sequence <= 1));
			/**
			 * Раздел 4.2.1 RFC 6347: сервер без состояния до принятой метки принимает лишь
			 * приветствие клиента номером 0 либо 1 - всё прочее отбрасывается молча. Строгий
			 * сервер принимает его лишь целиком одним куском, как DTLSv1_listen; иначе дроблёное
			 * приветствие собирается под пределами решения 13: чужие клиенты дробят повторное
			 * приветствие умолчанием
			 */
			if(this->_stateless && (!greeting || (this->_strict && !whole))){
				// Считаем отброшенный кусок
				this->discard(datagram::reason_t::GREETING);
				// Переходим к следующему куску
				continue;
			}
			/**
			 * Раздел 4.2.1 RFC 6347: сервер без состояния принимает приветствие клиента
			 * номером 0 (первое) либо 1 (повторённое с меткой) от всякого собеседника, а не
			 * по счёту своей связи; так же принимает его и сервер, ещё ничего не принявший:
			 * метку мог выдать соседний сервер с тем же секретом. Целое приветствие
			 * вытесняет чужую сборку того же номера. Повторная просьба о подтверждении
			 * адреса приходит клиенту номером ноль при ожидаемой единице (решение 12)
			 */
			const bool fresh = (((this->_stateless || (this->_incoming == 0)) && (fragment.type == handshake::type_t::CLIENT) && (fragment.sequence <= 1)) || ((fragment.type == handshake::type_t::VERIFY_REQUEST) && (fragment.sequence == 0) && (this->_incoming == 1)));
			// До подтверждения адреса запоминается номер записи приветствия клиента: по принятой метке он ляжет в окно
			if(!this->_verified && (fragment.type == handshake::type_t::CLIENT))
				// Запоминаем номер записи приветствия
				this->_greeted = sequence;
			/**
			 * За появлением ключей чтения открытый кусок с прежним номером у издания 1.2 -
			 * подделка либо повтор, от подделки неотличимый: последний залп повторяется лишь по
			 * повтору защищённого завершения (решение 11)
			 */
			if(this->_legacy && (epoch == 0) && (this->epoch(true) != 0)){
				// Считаем отброшенный кусок
				this->discard(datagram::reason_t::PLAIN);
				// Переходим к следующему куску
				continue;
			}
			/**
			 * Выполняем снятие чужой сборки того же номера, вытесняемой целым приветствием
			 */
			for(size_t i = this->_assemblies.size(); fresh && (fragment.offset == 0) && (fragment.length == fragment.size) && (i > 0); i--){
				// Если сборка ведёт сообщение того же номера
				if((this->_assemblies[i - 1].sequence == fragment.sequence) && (!this->_assemblies[i - 1].greeting || (this->_assemblies[i - 1].address == this->_address)))
					// Снимаем сборку с перечня
					this->_assemblies.erase(this->_assemblies.begin() + (i - 1));
			}
			/**
			 * За установленной связью открытых сообщений рукопожатия собеседник не шлёт
			 * никогда: повтор приветствия кончается с подтверждением завершения. Открытый
			 * кусок с любым номером - подделка: ни повтора залпа, ни подтверждения ему
			 */
			if(settled && (epoch == 0) && (this->epoch(true) != 0)){
				// Считаем отброшенный кусок
				this->discard(datagram::reason_t::PLAIN);
				// Переходим к следующему куску
				continue;
			}
			/**
			 * Раздел 5.8.1 RFC 9147: уже разобранное сообщение повторяется собеседником,
			 * не дождавшимся ответа, - ждущий залп повторяется ему раскладкой; за
			 * установленной связью повтор подтверждается явно (раздел 7)
			 */
			if(!fresh && (fragment.sequence < this->_incoming)){
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
			if(!fresh && (static_cast <uint16_t> (fragment.sequence - this->_incoming) >= datagram::DATAGRAM_AHEAD)){
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
			/**
			 * Решение 13: приветствие клиента до подтверждения адреса собирается лишь под
			 * пределом длины - память под сборку занимается по чужому слову
			 */
			if(this->_stateless && (fragment.size > datagram::DATAGRAM_GREETING)){
				// Считаем отброшенный кусок
				this->discard(datagram::reason_t::GREETING);
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
				if((this->_assemblies[i].sequence == fragment.sequence) && (!this->_assemblies[i].greeting || (this->_assemblies[i].address == this->_address)))
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
				/**
				 * Решение 13: сборок приветствий до подтверждения адреса не больше предела -
				 * по его достижении старейшая снимается: память ограничена постоянной, а
				 * честный клиент повторит приветствие по своим часам
				 */
				if(this->_stateless){
					// Число сборок приветствий до подтверждения адреса
					size_t held = 0;
					// Место старейшей сборки приветствия
					size_t eldest = this->_assemblies.size();
					/**
					 * Выполняем счёт сборок приветствий: перечень растёт в конец, старейшая - первая
					 */
					for(size_t i = 0; i < this->_assemblies.size(); i++){
						// Если сборка ведёт приветствие до подтверждения адреса
						if(this->_assemblies[i].greeting){
							// Считаем сборку
							held++;
							// Если старейшая ещё не найдена
							if(eldest == this->_assemblies.size())
								// Запоминаем старейшую
								eldest = i;
						}
					}
					// Если предел сборок приветствий достигнут
					if((held >= datagram::DATAGRAM_GREETINGS) && (eldest < this->_assemblies.size())){
						// Считаем снятую сборку
						this->discard(datagram::reason_t::GREETING);
						// Снимаем старейшую сборку приветствия
						this->_assemblies.erase(this->_assemblies.begin() + eldest);
					}
				}
				// Новая сборка сообщения
				assembly_t item;
				// Устанавливаем вид сообщения сборки
				item.type = fragment.type;
				// Устанавливаем пору ключей сборки
				item.epoch = epoch;
				// Устанавливаем порядковый номер сообщения сборки
				item.sequence = fragment.sequence;
				// Сборка приветствия до подтверждения адреса привязывается к адресу собеседника (решение 13)
				item.greeting = this->_stateless;
				// Если сборка ведёт приветствие до подтверждения адреса
				if(item.greeting)
					// Запоминаем адрес собеседника сборки
					item.address = this->_address;
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
			/**
			 * Покрытие сообщения ограничено числом несмежных областей: подделка кусками по
			 * байту через один давала бы десятки тысяч областей и квадратичное слияние на
			 * открытой нулевой поре; честный отправитель режет сообщение подряд
			 */
			if(assembly->spans.size() >= datagram::DATAGRAM_SPANS){
				// Считаем отброшенную запись
				this->discard(datagram::reason_t::FRAMING);
				// Кусок не принят
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
		if(taken && !this->_legacy && !this->_stateless && (this->_acknowledgeable.size() < datagram::DATAGRAM_WINDOW))
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
bool nts::internal::Flight::deliver(handshake::type_t & type, vector <uint8_t> & body, uint16_t & sequence) noexcept {
	// Место сборки ожидаемого сообщения
	size_t place = this->_assemblies.size();
	/**
	 * Выполняем перебор сборок принимаемых сообщений
	 */
	for(size_t i = 0; (i < this->_assemblies.size()) && (place == this->_assemblies.size()); i++){
		// Решение 13: сборка приветствия чужого адреса выдаче не подлежит - метка сверяется по адресу принятой дейтаграммы
		if(this->_assemblies[i].greeting && (this->_assemblies[i].address != this->_address))
			// Переходим к следующей сборке
			continue;
		// Если сборка ведёт ожидаемое сообщение, приветствие клиента серверу без состояния (раздел 4.2.1 RFC 6347) либо повторную просьбу о подтверждении адреса
		if((this->_assemblies[i].sequence == this->_incoming) || ((this->_stateless || (this->_incoming == 0)) && (this->_assemblies[i].type == handshake::type_t::CLIENT) && (this->_assemblies[i].sequence <= 1)) || ((this->_assemblies[i].type == handshake::type_t::VERIFY_REQUEST) && (this->_assemblies[i].sequence == 0) && (this->_incoming == 1)))
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
	// Выводим порядковый номер собранного сообщения
	sequence = assembly.sequence;
	// Переносим тело собранного сообщения
	body = ::move(assembly.body);
	// Снимаем сборку с перечня
	this->_assemblies.erase(this->_assemblies.begin() + place);
	// Ожидаемым становится сообщение, следующее за выданным
	this->_incoming = static_cast <uint16_t> (sequence + 1);
	// Выводим признак того, что сообщение выдано
	return true;
}
/**
 * @brief Метод получения порядкового номера очередного отправляемого сообщения
 *
 * @return порядковый номер, которым уйдёт следующее сообщение рукопожатия
 *
 */
uint16_t nts::internal::Flight::outgoing() const noexcept {
	// Выводим порядковый номер очередного отправляемого сообщения
	return this->_outgoing;
}
/**
 * @brief Метод установки порядкового номера очередного отправляемого сообщения
 *
 * @param sequence порядковый номер, которым уйдёт следующее сообщение рукопожатия
 *
 */
void nts::internal::Flight::outgoing(const uint16_t sequence) noexcept {
	// Устанавливаем порядковый номер очередного отправляемого сообщения
	this->_outgoing = sequence;
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
			// Если кусок ушёл подтверждённой записью: нынешней либо прежней, до повтора
			if(!this->_pieces[j].acked && (((this->_pieces[j].epoch == numbers[i].epoch) && (this->_pieces[j].sequence == numbers[i].sequence)) ||
			   (this->_pieces[j].former && (this->_pieces[j].formerEpoch == numbers[i].epoch) && (this->_pieces[j].formerSequence == numbers[i].sequence))))
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
	/**
	 * Раздел 7.3 RFC 9147: пустое подтверждение просит ранний повтор. Он не расходует
	 * попыток и не удваивает срока - иначе девять открытых двухбайтовых подтверждений
	 * рвали бы рукопожатие по TIMEOUT; и не чаще одного на срок, иначе усилитель
	 */
	/**
	 * Оба рычага раннего повтора - пустое подтверждение и повтор собеседником своего
	 * залпа - идут через один гейт: не чаще одного повтора на срок (иначе раздробленный
	 * повтор собеседника из N дейтаграмм давал бы N повторов своего залпа - усилитель), а
	 * раскладка идёт всегда, чтобы уже сложенное подтверждение ушло сейчас, а не потом
	 */
	const bool resend = (repeated || (nudged && !this->_prodded));
	// Если просили пустым подтверждением - отмечаем ранний повтор
	if(nudged)
		this->_prodded = true;
	// Раскладка идёт всегда: уже сложенное подтверждение уходит сейчас (повтор по повтору собеседника не сдерживается: путь с потерями на него опирается - записано долгом)
	return this->dispatch(resend);
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
 * @brief Метод установки переноса изданием DTLS 1.2
 *
 * @param legacy ведётся ли перенос изданием DTLS 1.2
 *
 */
void nts::internal::Flight::legacy(const bool legacy) noexcept {
	// Запоминаем издание переноса
	this->_legacy = legacy;
}
/**
 * @brief Метод установки переноса изданием DTLS 1.0
 *
 * @param ancient ведётся ли перенос изданием DTLS 1.0
 *
 */
void nts::internal::Flight::ancient(const bool ancient) noexcept {
	// Запоминаем издание переноса
	this->_ancient = ancient;
}
/**
 * @brief Метод проверки переноса изданием DTLS 1.2
 *
 * @return признак того, что перенос ведётся изданием DTLS 1.2
 *
 */
bool nts::internal::Flight::legacy() const noexcept {
	// Выводим издание переноса
	return this->_legacy;
}
/**
 * @brief Метод установки сервера без состояния изданием DTLS 1.2
 *
 * @param stateless ждётся ли приветствие клиента заново после HelloVerifyRequest
 *
 */
void nts::internal::Flight::stateless(const bool stateless) noexcept {
	// Запоминаем признак сервера без состояния
	this->_stateless = stateless;
	// Раздел 4.2.2 RFC 6347: за просьбой о подтверждении адреса приветствие сервера идёт номером один
	if(!stateless){
		// Устанавливаем номер следующего отправляемого сообщения
		this->_outgoing = 1;
		/**
		 * Решение 13: по принятой метке сборки приветствий снимаются - состояние держится
		 * лишь по подтверждённому собеседнику; выданная сборка снята выдачей раньше
		 */
		for(size_t i = this->_assemblies.size(); i > 0; i--){
			// Если сборка ведёт приветствие до подтверждения адреса
			if(this->_assemblies[i - 1].greeting)
				// Снимаем сборку с перечня
				this->_assemblies.erase(this->_assemblies.begin() + (i - 1));
		}
	}
}
/**
 * @brief Метод установки строгого сервера без состояния издания DTLS 1.2
 *
 * @param strict принимается ли приветствие клиента до метки лишь целиком одним куском
 *
 */
void nts::internal::Flight::strict(const bool strict) noexcept {
	// Запоминаем строгость сервера без состояния
	this->_strict = strict;
}
/**
 * @brief Метод проверки строгости сервера без состояния издания DTLS 1.2
 *
 * @return признак того, что приветствие клиента до метки принимается лишь целиком
 *
 */
bool nts::internal::Flight::strict() const noexcept {
	// Выводим строгость сервера без состояния
	return this->_strict;
}
/**
 * @brief Метод отметки подтверждённости адреса собеседника меткой возврата состояния
 *
 * @param verified подтверждён ли адрес собеседника
 *
 */
void nts::internal::Flight::verified(const bool verified) noexcept {
	// Признак того, что адрес подтверждён только что
	const bool settled = (!this->_verified && verified);
	// Запоминаем подтверждённость адреса
	this->_verified = verified;
	// Если адрес подтверждён только что: до того окно не велось
	if(settled){
		/**
		 * Раздел 4.1.2.6 RFC 6347: запись принятого приветствия и всё, что шло перед нею,
		 * ложатся в окно нулевой поры - записи до подтверждения адреса неподтверждённые, и
		 * повтор любой из них, как и повтор самого приветствия, отбрасывается
		 */
		for(uint64_t i = ((this->_greeted >= datagram::DATAGRAM_WINDOW) ? (this->_greeted - datagram::DATAGRAM_WINDOW + 1) : 0); i <= this->_greeted; i++)
			// Отмечаем запись в окне
			this->_plains[1].window.mark(i);
	}
}
/**
 * @brief Метод отметки последнего залпа рукопожатия
 *
 */
void nts::internal::Flight::conclude() noexcept {
	// Запоминаем, что залп последний и часов не ждёт
	this->_concluded = true;
	// Останавливаем часы повторной передачи
	this->_timing = false;
}
/**
 * @brief Метод выработки имитовставки метки возврата состояния
 *
 * @param generation поколение секрета метки
 * @param digest     хеш приветствия клиента: 32 байта
 * @param mac        место, в которое помещается имитовставка: 32 байта
 *
 * @return           признак того, что имитовставка выработана
 *
 */
bool nts::internal::Flight::imprint(const uint8_t generation, const uint8_t * digest, uint8_t * mac) const noexcept {
	// Данные, покрываемые имитовставкой: поколение, хеш и адрес собеседника
	uint8_t covered[1 + 32 + datagram::DATAGRAM_ADDRESS];
	// Переносим поколение секрета
	covered[0] = generation;
	// Переносим хеш приветствия
	::memcpy(covered + 1, digest, 32);
	// Переносим адрес собеседника: длиннее предела он не бывает
	::memcpy(covered + 33, this->_address.data(), this->_address.size());
	// Выводим итог выработки имитовставки по секрету поколения
	return digest::hmac(digest::hash_t::SHA256, view_t(this->_stamps[generation % 2], sizeof(this->_stamps[0])), view_t(covered, 33 + this->_address.size()), mac, 32);
}
/**
 * @brief Метод сверки имитовставки метки возврата состояния
 *
 * @param generation поколение секрета из метки
 * @param digest     хеш приветствия клиента, покрываемый меткой: 32 байта
 * @param mac        имитовставка из метки: 32 байта
 *
 * @return           признак того, что метка сложена сервером для этого собеседника
 *
 */
bool nts::internal::Flight::attest(const uint8_t generation, const uint8_t * digest, const uint8_t * mac) const noexcept {
	// Без адреса собеседника метку привязать не к чему
	if(this->_address.empty())
		// Выводим отказ проверки метки
		return false;
	// Раздел 5.1 RFC 9147: живы два поколения секрета - нынешнее и предыдущее
	if((generation != this->_generation) && (generation != static_cast <uint8_t> (this->_generation - 1)))
		// Выводим отказ проверки метки
		return false;
	// Место, в которое помещается ожидаемая имитовставка метки
	uint8_t expected[32];
	// Если имитовставку метки выработать не удалось
	if(!this->imprint(generation, digest, expected))
		// Выводим отказ проверки метки
		return false;
	// Расхождение имитовставок
	uint8_t difference = 0;
	/**
	 * Выполняем сличение имитовставок за постоянное время
	 */
	for(size_t i = 0; i < sizeof(expected); i++)
		// Накапливаем расхождение очередного байта
		difference |= static_cast <uint8_t> (expected[i] ^ mac[i]);
	// Выполняем затирание ожидаемой имитовставки
	wipe(expected, sizeof(expected));
	// Выводим итог сличения
	return (difference == 0);
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
	// Место, в которое помещается имитовставка метки
	uint8_t mac[32];
	// Если имитовставку метки выработать не удалось
	if(!this->imprint(this->_generation, this->_digest, mac))
		// Выводим отказ составления метки
		return context::error_t::MESSAGE;
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
		// Записываем имитовставку метки
		result.insert(result.end(), mac, mac + sizeof(mac));
	/**
	 * Если памяти под метку не хватило
	 */
	} catch(const bad_alloc &) {
		// Выполняем затирание имитовставки
		wipe(mac, sizeof(mac));
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выполняем затирание имитовставки
	wipe(mac, sizeof(mac));
	// Выводим успешность составления метки
	return context::error_t::NONE;
}
/**
 * @brief Метод составления метки возврата состояния сервера издания DTLS 1.2
 *
 * @param message принятое приветствие клиента без метки
 * @param result  накопитель, в который складывается метка
 *
 * @return        отказ составления метки
 *
 */
context::error_t nts::internal::Flight::token(const view_t & message, vector <uint8_t> & result) const noexcept {
	// Место, в которое помещается хеш приветствия клиента: в метку он не ложится и не запоминается
	uint8_t digest[32];
	// Если хеш приветствия клиента выработать не удалось
	if(!digest::hash(digest::hash_t::SHA256, message, digest, sizeof(digest)))
		// Выводим отказ составления метки
		return context::error_t::MESSAGE;
	// Место, в которое помещается имитовставка метки
	uint8_t mac[32];
	// Если имитовставку метки выработать не удалось
	if(!this->imprint(this->_generation, digest, mac))
		// Выводим отказ составления метки
		return context::error_t::MESSAGE;
	/**
	 * Выполняем перехват ошибок работы с памятью
	 */
	try {
		// Выполняем сброс накопителя метки
		result.clear();
		// Записываем поколение секрета метки
		result.push_back(this->_generation);
		// Записываем имитовставку метки: хеш приветствия ею покрыт и в метке не повторяется
		result.insert(result.end(), mac, mac + sizeof(mac));
	/**
	 * Если памяти под метку не хватило
	 */
	} catch(const bad_alloc &) {
		// Выполняем затирание имитовставки
		wipe(mac, sizeof(mac));
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выполняем затирание имитовставки
	wipe(mac, sizeof(mac));
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
	// Без выданной метки сверять её не с чем: приветствие с нею отвергается
	if(!this->_digested)
		// Выводим отказ проверки метки
		return false;
	// Если метка не сходится длиной
	if((label.data == nullptr) || (label.size != LABEL))
		// Выводим отказ проверки метки
		return false;
	// Признак того, что имитовставка метки сошлась с поколением, хешем из метки и адресом
	const bool attested = this->attest(label.data[0], label.data + 1, label.data + 33);
	// Расхождение хешей приветствия
	uint8_t difference = 0;
	/**
	 * Выполняем сличение хеша приветствия с выданным: метка чужой связи с того же
	 * адреса сходится имитовставкой, но не хешем
	 */
	for(size_t i = 0; i < sizeof(this->_digest); i++)
		// Накапливаем расхождение очередного байта
		difference |= static_cast <uint8_t> (this->_digest[i] ^ label.data[1 + i]);
	// Выводим итог сличения
	return (attested && (difference == 0));
}
/**
 * @brief Метод проверки метки возврата состояния без своего состояния
 *
 * @param label   проверяемая метка, повторённая клиентом
 * @param message приветствие клиента без метки, по которому она сложена
 *
 * @return        признак того, что метка сложена сервером для этого собеседника и приветствия
 *
 */
bool nts::internal::Flight::verify(const view_t & label, const view_t & message) const noexcept {
	// Если метка не сходится длиной
	if((label.data == nullptr) || (label.size != TOKEN))
		// Выводим отказ проверки метки
		return false;
	// Место, в которое помещается хеш повторённого приветствия
	uint8_t digest[32];
	// Если хеш приветствия клиента выработать не удалось
	if(!digest::hash(digest::hash_t::SHA256, message, digest, sizeof(digest)))
		// Выводим отказ проверки метки
		return false;
	// Выводим итог сверки имитовставки: хеш повторённого приветствия покрыт ею, и отдельно не сличается
	return this->attest(label.data[0], digest, label.data + 1);
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
	/**
	 * Прежнее поколение: свёртка от свёртки. Оставить второй слот нулевым нельзя:
	 * attest() принимает метку и поколением «на одно назад», а нулевой ключ HMAC
	 * известен всякому - подделка метки обходила бы подтверждение адреса (раздел
	 * 5.1 RFC 9147, раздел 4.2.1 RFC 6347). Так оба поколения выводятся из секрета
	 * потребителя, и смена процесса не рвёт меток, выданных прежним
	 */
	if(!digest::hash(digest::hash_t::SHA256, view_t(digest, sizeof(digest)), this->_stamps[(this->_generation + 1) % 2], sizeof(digest))){
		// Выполняем затирание свёрнутого секрета
		wipe(digest, sizeof(digest));
		// Затираем нынешнее поколение: половинной установки быть не должно
		wipe(this->_stamps[this->_generation % 2], sizeof(this->_stamps[0]));
		// Выходим из метода
		return;
	}
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
	// Секрет нового поколения вырабатывается в отдельное место: отказ энтропии не тронет слот прежнего поколения
	uint8_t fresh[32];
	// Если секрет нового поколения выработать не удалось: поколения не меняются
	if(!entropy::bytes(fresh, sizeof(fresh)))
		// Выходим из метода
		return;
	// Переходим к следующему поколению секрета
	this->_generation++;
	// Переносим секрет в слот нового поколения
	::memcpy(this->_stamps[this->_generation % 2], fresh, sizeof(fresh));
	// Затираем отдельное место
	wipe(fresh, sizeof(fresh));
}
/**
 * @brief Деструктор: секреты метки возврата состояния и свёрнутый секрет затираются - они общие для всех связей сервера
 *
 */
nts::internal::Flight::~Flight() noexcept {
	// Затираем ключевой материал связи
	this->shred();
	// Затираем секреты метки
	wipe(this->_stamps, sizeof(this->_stamps));
	// Затираем свёрнутый секрет
	wipe(this->_digest, sizeof(this->_digest));
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
	// Устанавливаем размер дейтаграммы не ниже наименьшего дозволенного и не выше принимаемого собеседником (DATAGRAM_LONGEST): шире он отбросил бы дейтаграмму целиком
	this->_mtu = ((mtu < datagram::DATAGRAM_MTU_LEAST) ? datagram::DATAGRAM_MTU_LEAST : ((mtu > datagram::DATAGRAM_LONGEST) ? datagram::DATAGRAM_LONGEST : mtu));
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
 * @brief Метод установки предела содержимого записи, объявленного собеседником на приём
 *
 * @param limit предел содержимого одной записи в байтах (RFC 8449, RFC 6066)
 *
 */
void nts::internal::Flight::limit(const size_t limit) noexcept {
	// Устанавливаем предел не выше записи протокола и не ниже обвязки куска с одним байтом
	this->_limit = ((limit > record::RECORD_PLAINTEXT) ? record::RECORD_PLAINTEXT : ((limit <= datagram::DATAGRAM_FRAGMENT_HEADER) ? (datagram::DATAGRAM_FRAGMENT_HEADER + 1) : limit));
}
/**
 * @brief Метод получения места под содержимое одной записи в дейтаграмме
 *
 * @return место в байтах: размер дейтаграммы за вычетом обвязки записи текущей поры записи
 *
 */
size_t nts::internal::Flight::room() noexcept {
	// Обвязка записи текущей поры записи
	const size_t overhead = this->overhead(this->current(0).epoch);
	// Место в дейтаграмме: не меньше нуля
	const size_t room = ((this->_mtu > overhead) ? (this->_mtu - overhead) : 0);
	// Выводим место, не шире предела собеседника
	return ((room > this->_limit) ? this->_limit : room);
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
	// Сбрасываем издание переноса
	this->_legacy = false;
	// Выполняем сброс издания DTLS 1.0
	this->_ancient = false;
	// Сбрасываем признак сервера без состояния
	this->_stateless = false;
	// Адрес собеседника считается подтверждённым, пока сервер не скажет иного
	this->_verified = true;
	// Сбрасываем признак последнего залпа
	this->_concluded = false;
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
	// Сбрасываем признак раннего повтора
	this->_prodded = false;
	// Сбрасываем признак отложенной записи
	this->_deferring = false;
	// Сбрасываем признак выданной метки
	this->_digested = false;
	// Сбрасываем номер записи приветствия сервера без состояния
	this->_greeted = 0;
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
	_suite(protect::suite_t::NONE), _legacy(false), _ancient(false), _stateless(false), _strict(false), _verified(true), _concluded(false), _mtu(datagram::DATAGRAM_MTU), _limit(record::RECORD_PLAINTEXT), _timeout(datagram::DATAGRAM_TIMEOUT), _attempts(0),
	_timing(false), _challenged(false), _replied(false), _rotating(false), _repeated(false), _nudged(false), _prodded(false), _deferring(false),
	_stamped(false), _digested(false), _generation(0), _greeted(0), _outgoing(0), _incoming(0), _bundle(0) {
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
