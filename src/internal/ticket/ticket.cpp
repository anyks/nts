/**
 * @file ticket.cpp
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
 * @brief Исходный файл внутреннего модуля билетов сеансов издания TLS 1.2 по RFC 5077
 *
 * @section Намеренные решения
 *
 *  1. Запись состояния несёт своё издание: билет прежнего издания распечатывается
 *    ключом, но состоянием не признаётся - рукопожатие идёт полным, а не отказом.
 *
 *  2. Имитовставка сличается прежде расшифрования и за постоянное время, а дополнение
 *    состояния судится уже под сошедшейся имитовставкой: порча любого байта билета
 *    отсеивается до шифра, и утечки по времени расшифрования нет.
 *
 *  3. Состояние помнит порядок RFC 7366, подлинность клиента (с его сертификатом) и имя
 *    узла: возобновлённая связь обязана наследовать проверенное выдавшей, а не обходить
 *    его сокращённым рукопожатием.
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
#include <sys/wipe.hpp>
#include <field/field.hpp>
#include <cipher/aes.hpp>
#include <cipher/mode.hpp>
#include <digest/hmac.hpp>
#include <message/message.hpp>
#include <entropy/entropy.hpp>
#include <internal/ticket/ticket.hpp>

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
	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;

	/**
	 * Длина блока AES-128 и вектора замены билета: раздел 4 RFC 5077
	 */
	static constexpr size_t BLOCK = 16;

	/**
	 * Издание записи состояния билета: второе несёт порядок RFC 7366, подлинность
	 * клиента, имя узла и сертификат клиента; третье добавило издание выдавшей связи
	 * (DTLS 1.0/TLS 1.1) между порядком и подлинностью - билет прежней раскладки
	 * распечатывается ключом, но состоянием не признаётся
	 */
	static constexpr uint8_t STATE = 0x04;

	/**
	 * Метки вывода частей ключа билетов из секрета потребителя
	 */
	static const char * LABELS[3] = {"session ticket key name", "session ticket key aes", "session ticket key mac"};

	/**
	 * Наименьшая длина билета: имя ключа, вектор, длина, хоть один блок и имитовставка
	 */
	static constexpr size_t LEAST = (internal::ticket::TICKET_NAME + BLOCK + 2 + BLOCK + internal::ticket::TICKET_MAC);

	/**
	 * @brief Функция вывода ключа билетов из секрета потребителя
	 *
	 * @param secret секрет любой длины
	 * @param result место, в которое помещаются имя ключа, ключ шифрования и ключ имитовставки подряд
	 * @return       признак успешности вывода
	 *
	 * @details Три значения HMAC-SHA256 от секрета своими метками: имя ключа - первые
	 *          шестнадцать байтов первого, ключ AES - первые шестнадцать второго, ключ
	 *          имитовставки - третье целиком
	 *
	 */
	static bool keyring(const view_t & secret, uint8_t * result) noexcept {
		// Длины частей ключа билетов
		static const size_t widths[3] = {internal::ticket::TICKET_NAME, internal::ticket::TICKET_KEY, internal::ticket::TICKET_MAC};
		// Смещение очередной части в месте итога
		size_t offset = 0;
		/**
		 * Выполняем перебор частей ключа билетов
		 */
		for(size_t i = 0; i < 3; i++){
			// Если очередную часть вывести не удалось
			if(!digest::hmac(digest::hash_t::SHA256, secret, view_t(reinterpret_cast <const uint8_t *> (LABELS[i]), ::strlen(LABELS[i])), result + offset, widths[i]))
				// Выводим отказ вывода
				return false;
			// Переходим к следующей части
			offset += widths[i];
		}
		// Выводим успешность вывода
		return true;
	}
	/**
	 * @brief Функция записи состояния связи в октеты
	 *
	 * @param state   записываемое состояние
	 * @param builder составитель, в который складывается запись
	 * @return        отказ составителя полей
	 *
	 */
	static field::error_t compose(const internal::ticket::state_t & state, field::builder_t & builder) noexcept {
		// Миг выдачи билета в записи без знака
		const uint64_t moment = static_cast <uint64_t> (state.moment);
		// Записываем издание записи состояния
		field::error_t outcome = builder.number(STATE, 1);
		// Если издание записано
		if(outcome == field::error_t::NONE)
			// Записываем набор шифрования связи
			outcome = builder.number(static_cast <uint32_t> (state.suite), 2);
		// Если набор записан
		if(outcome == field::error_t::NONE)
			// Записываем главный секрет связи
			outcome = builder.bytes(view_t(state.master, sizeof(state.master)));
		// Если главный секрет записан: раздел 5.3 RFC 7627 велит помнить признак расширенного главного секрета
		if(outcome == field::error_t::NONE)
			// Записываем признак расширенного главного секрета: у связи он безусловен
			outcome = builder.number(1, 1);
		// Если признак записан
		if(outcome == field::error_t::NONE)
			// Записываем старшую половину мига выдачи
			outcome = builder.number(static_cast <uint32_t> (moment >> 32), 4);
		// Если старшая половина записана
		if(outcome == field::error_t::NONE)
			// Записываем младшую половину мига выдачи
			outcome = builder.number(static_cast <uint32_t> (moment & 0xFFFFFFFF), 4);
		// Если миг записан
		if(outcome == field::error_t::NONE)
			// Записываем срок жизни билета
			outcome = builder.number(state.lifetime, 4);
		// Миг первичного удостоверения в записи
		const uint64_t authenticated = static_cast <uint64_t> (state.authenticated);
		// Если срок записан
		if(outcome == field::error_t::NONE)
			// Записываем старшую половину мига удостоверения
			outcome = builder.number(static_cast <uint32_t> (authenticated >> 32), 4);
		// Если старшая половина записана
		if(outcome == field::error_t::NONE)
			// Записываем младшую половину мига удостоверения
			outcome = builder.number(static_cast <uint32_t> (authenticated & 0xFFFFFFFF), 4);
		// Если срок записан: раздел 3.1 RFC 7366 велит помнить порядок защиты записей
		if(outcome == field::error_t::NONE)
			// Записываем признак порядка «шифрование, затем имитовставка»
			outcome = builder.number((state.etm ? 1 : 0), 1);
		// Если порядок записан
		if(outcome == field::error_t::NONE)
			// Записываем признак издания выдавшей связи
			outcome = builder.number((state.ancient ? 1 : 0), 1);
		// Если порядок записан
		if(outcome == field::error_t::NONE)
			// Записываем признак проверенной подлинности клиента
			outcome = builder.number((state.verified ? 1 : 0), 1);
		// Если признак записан
		if(outcome == field::error_t::NONE)
			// Занимаем место под длину прикладного протокола
			outcome = builder.open(1);
		// Если место занято
		if(outcome == field::error_t::NONE)
			// Записываем прикладной протокол связи
			outcome = builder.bytes(view_t(reinterpret_cast <const uint8_t *> (state.protocol.data()), state.protocol.size()));
		// Если протокол записан
		if(outcome == field::error_t::NONE)
			// Проставляем длину прикладного протокола
			outcome = builder.close();
		// Если протокол записан
		if(outcome == field::error_t::NONE)
			// Занимаем место под длину имени узла: раздел 3 RFC 6066 даёт имени двухбайтовую длину
			outcome = builder.open(2);
		// Если место занято
		if(outcome == field::error_t::NONE)
			// Записываем имя узла
			outcome = builder.bytes(view_t(reinterpret_cast <const uint8_t *> (state.name.data()), state.name.size()));
		// Если имя записано
		if(outcome == field::error_t::NONE)
			// Проставляем длину имени узла
			outcome = builder.close();
		// Если имя записано
		if(outcome == field::error_t::NONE)
			// Занимаем место под длину сертификата клиента: раздел 7.4.2 RFC 5246 даёт сертификату трёхбайтовую длину
			outcome = builder.open(3);
		// Если место занято
		if(outcome == field::error_t::NONE)
			// Записываем сертификат клиента
			outcome = builder.bytes(view_t(state.leaf.data(), state.leaf.size()));
		// Если сертификат записан
		if(outcome == field::error_t::NONE)
			// Проставляем длину сертификата клиента
			outcome = builder.close();
		// Выводим итог составления записи
		return outcome;
	}
	/**
	 * @brief Функция чтения состояния связи из октетов
	 *
	 * @param data   читаемая запись состояния без дополнения
	 * @param result состояние, в которое помещается прочитанное
	 * @return       признак того, что запись сложена по правилам нынешнего издания
	 *
	 */
	static bool decompose(const view_t & data, internal::ticket::state_t & result) noexcept {
		// Объект разборщика состояния билета
		field::scanner_t scanner;
		// Устанавливаем разбираемое состояние
		scanner.start(data);
		// Издание записи, набор, признак расширенного главного секрета, половины мига, срок, порядок и подлинность
		uint32_t edition = 0, suite = 0, extended = 0, upper = 0, lower = 0, lifetime = 0, senior = 0, junior = 0, etm = 0, ancient = 0, verified = 0;
		// Главный секрет, прикладной протокол, имя узла и сертификат клиента
		view_t master, protocol, name, leaf;
		// Разбираем состояние поле за полем: чужое издание, лишние байты и негодные признаки отвергаются
		const bool valid = ((scanner.number(edition, 1) == field::error_t::NONE) && (edition == STATE) &&
			(scanner.number(suite, 2) == field::error_t::NONE) &&
			(scanner.bytes(master, internal::ticket::TICKET_MASTER) == field::error_t::NONE) &&
			(scanner.number(extended, 1) == field::error_t::NONE) && (extended == 1) &&
			(scanner.number(upper, 4) == field::error_t::NONE) && (scanner.number(lower, 4) == field::error_t::NONE) &&
			(scanner.number(lifetime, 4) == field::error_t::NONE) &&
			(scanner.number(senior, 4) == field::error_t::NONE) && (scanner.number(junior, 4) == field::error_t::NONE) &&
			(scanner.number(etm, 1) == field::error_t::NONE) && (etm <= 1) &&
			(scanner.number(ancient, 1) == field::error_t::NONE) && (ancient <= 1) &&
			(scanner.number(verified, 1) == field::error_t::NONE) && (verified <= 1) &&
			(scanner.vector(protocol, 1) == field::error_t::NONE) &&
			(scanner.vector(name, 2) == field::error_t::NONE) &&
			(scanner.vector(leaf, 3) == field::error_t::NONE) && (scanner.left() == 0));
		// Если запись сложена не по правилам
		if(!valid)
			// Выводим негодность записи
			return false;
		// Раздел 7.4.2 RFC 5246: у проверенной подлинности сертификат непуст, без неё - пуст
		if((verified == 1) == (leaf.size == 0))
			// Выводим негодность записи
			return false;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Переносим прикладной протокол
			result.protocol.assign(reinterpret_cast <const char *> (protocol.data), protocol.size);
			// Переносим имя узла
			result.name.assign(reinterpret_cast <const char *> (name.data), name.size);
			// Переносим сертификат клиента
			result.leaf.assign(leaf.data, leaf.data + leaf.size);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Сброс состояния
			result.clear();
			// Выводим негодность записи
			return false;
		}
		// Переносим набор шифрования
		result.suite = static_cast <protect::suite_t> (suite);
		// Переносим главный секрет
		::memcpy(result.master, master.data, sizeof(result.master));
		// Переносим порядок защиты записей
		result.etm = (etm == 1);
		// Переносим признак издания выдавшей связи
		result.ancient = (ancient == 1);
		// Переносим признак подлинности клиента
		result.verified = (verified == 1);
		// Переносим миг выдачи
		result.moment = static_cast <int64_t> ((static_cast <uint64_t> (upper) << 32) | lower);
		// Переносим срок жизни
		result.lifetime = lifetime;
		// Переносим миг первичного удостоверения
		result.authenticated = static_cast <int64_t> ((static_cast <uint64_t> (senior) << 32) | junior);
		// Выводим годность записи
		return true;
	}
};

/**
 * @brief Метод сброса состояния с затиранием главного секрета
 *
 */
void nts::internal::ticket::State::clear() noexcept {
	// Сбрасываем набор шифрования
	this->suite = protect::suite_t::NONE;
	// Затирание главного секрета
	wipe(this->master, sizeof(this->master));
	// Сбрасываем порядок защиты записей
	this->etm = false;
	// Сбрасываем признак издания
	this->ancient = false;
	// Сбрасываем признак подлинности клиента
	this->verified = false;
	// Сбрасываем миг выдачи
	this->moment = 0;
	// Сбрасываем миг первичного удостоверения
	this->authenticated = 0;
	// Сбрасываем срок жизни
	this->lifetime = 0;
	// Сбрасываем прикладной протокол
	this->protocol.clear();
	// Сбрасываем имя узла
	this->name.clear();
	// Сбрасываем сертификат клиента
	this->leaf.clear();
}
/**
 * @brief Конструктор
 *
 */
nts::internal::ticket::State::State() noexcept : suite(protect::suite_t::NONE), etm(false), ancient(false), verified(false), moment(0), authenticated(0), lifetime(0) {
	// Обнуление главного секрета
	::memset(this->master, 0, sizeof(this->master));
}
/**
 * @brief Деструктор
 *
 */
nts::internal::ticket::State::~State() noexcept {
	// Затирание главного секрета
	wipe(this->master, sizeof(this->master));
}
/**
 * @brief Метод проверки того, что ключ нынешнего поколения заведён
 *
 * @return признак заведённости ключа нынешнего поколения
 *
 */
bool nts::internal::ticket::Keeper::ready() const noexcept {
	// Выводим признак заведённости нынешнего поколения
	return this->_vaulted[0];
}
/**
 * @brief Метод заведения ключа билетов нового поколения из секрета
 *
 * @param secret секрет любой длины
 * @return       признак успешности заведения ключа
 *
 */
bool nts::internal::ticket::Keeper::stash(const view_t & secret) noexcept {
	// Если укрытой памяти под ключи билетов нет
	if(this->_keys == nullptr)
		// Выводим отказ заведения ключа
		return false;
	// Место, в которое помещается ключ нового поколения
	uint8_t fresh[TICKET_VAULT];
	// Если ключ из секрета вывести не удалось
	if(!keyring(secret, fresh)){
		// Затирание места ключа
		wipe(fresh, sizeof(fresh));
		// Выводим отказ заведения ключа
		return false;
	}
	// Если нынешнее поколение заведено
	if(this->_vaulted[0])
		// Переносим нынешнее поколение в предыдущее
		::memcpy(this->_keys->vault[1], this->_keys->vault[0], sizeof(this->_keys->vault[1]));
	// Отмечаем заведённость предыдущего поколения по нынешнему
	this->_vaulted[1] = this->_vaulted[0];
	// Переносим ключ нового поколения в нынешнее
	::memcpy(this->_keys->vault[0], fresh, sizeof(this->_keys->vault[0]));
	// Отмечаем заведённость нынешнего поколения
	this->_vaulted[0] = true;
	// Затирание места ключа
	wipe(fresh, sizeof(fresh));
	// Выводим успешность заведения ключа
	return true;
}
/**
 * @brief Метод запечатывания состояния связи в октеты билета ключом нынешнего поколения
 *
 * @param state  запечатываемое состояние связи
 * @param result накопитель, в который помещаются октеты билета
 * @return       отказ запечатывания
 *
 */
nts::internal::ticket::error_t nts::internal::ticket::Keeper::mint(const state_t & state, vector <uint8_t> & result) noexcept {
	// Если ключ билетов нынешнего поколения не заведён
	if(!this->_vaulted[0])
		// Выводим отказ отсутствия ключа
		return error_t::VAULT;
	// Ключ билетов нынешнего поколения: имя, ключ шифрования и ключ имитовставки
	const uint8_t * vault = this->_keys->vault[0];
	// Объект составителя состояния билета: накопитель затирается им самим
	field::builder_t builder;
	// Если состояние в запись сложить не удалось
	if(compose(state, builder) != field::error_t::NONE)
		// Выводим отказ нехватки памяти: составитель отказывает лишь ею, поля состояния в ширину входят
		return error_t::MEMORY;
	// Получаем составленное состояние билета
	const view_t record = builder.data();
	// Место, в которое помещается вектор замены билета
	uint8_t iv[BLOCK];
	// Раздел 4 RFC 5077: вектор замены случаен на всякий билет
	if(!entropy::bytes(iv, sizeof(iv)))
		// Выводим отказ шифра
		return error_t::CIPHER;
	// Объект базового шифра AES-128 билета
	cipher::aes_t aes;
	// Если ключ шифрования билета установить не удалось
	if(!aes.key(view_t(vault + TICKET_NAME, TICKET_KEY)))
		// Выводим отказ шифра
		return error_t::CIPHER;
	// Объект режима простой замены с зацеплением
	cipher::chaining_t chaining;
	// Если режим запустить не удалось
	if(!chaining.start(cipher::block_t(aes), view_t(iv, sizeof(iv))))
		// Выводим отказ шифра
		return error_t::CIPHER;
	// Длина дополнения состояния до блока без байта длины
	const size_t padding = ((BLOCK - ((record.size + 1) % BLOCK)) % BLOCK);
	// Итог запечатывания билета
	error_t failure = error_t::NONE;
	// Открытый текст состояния: живёт вне перехвата, чтобы затираться и при нехватке памяти
	vector <uint8_t> plain;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Занимаем место под открытый текст с дополнением по образцу раздела 6.2.3.2 RFC 5246
		plain.assign(record.size + 1 + padding, static_cast <uint8_t> (padding));
		// Переносим состояние билета
		::memcpy(plain.data(), record.data, record.size);
		// Сброс накопителя билета
		result.clear();
		// Записываем имя ключа билета
		result.insert(result.end(), vault, vault + TICKET_NAME);
		// Записываем вектор замены
		result.insert(result.end(), iv, iv + sizeof(iv));
		// Записываем старший байт длины шифртекста
		result.push_back(static_cast <uint8_t> ((plain.size() >> 8) & 0xFF));
		// Записываем младший байт длины шифртекста
		result.push_back(static_cast <uint8_t> (plain.size() & 0xFF));
		// Смещение шифртекста в билете
		const size_t offset = result.size();
		// Занимаем место под шифртекст
		result.resize(offset + plain.size(), 0);
		// Если состояние зашифровать не удалось
		if(!chaining.encrypt(view_t(plain.data(), plain.size()), result.data() + offset))
			// Запоминаем отказ шифра
			failure = error_t::CIPHER;
		// Если состояние зашифровано
		else {
			// Место, в которое помещается имитовставка билета
			uint8_t stamp[TICKET_MAC];
			// Раздел 4 RFC 5077: имитовставка над именем ключа, вектором, длиной и шифртекстом
			if(!digest::hmac(digest::hash_t::SHA256, view_t(vault + TICKET_NAME + TICKET_KEY, TICKET_MAC), view_t(result.data(), result.size()), stamp, sizeof(stamp)))
				// Запоминаем отказ имитовставки
				failure = error_t::CIPHER;
			// Если имитовставка выработана
			else
				// Записываем имитовставку билета
				result.insert(result.end(), stamp, stamp + sizeof(stamp));
		}
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Запоминаем отказ нехватки памяти
		failure = error_t::MEMORY;
	}
	// Если открытый текст состояния занят
	if(!plain.empty())
		// Затирание открытого текста состояния
		wipe(plain.data(), plain.size());
	// Если билет запечатать не удалось
	if(failure != error_t::NONE)
		// Сброс накопителя билета
		result.clear();
	// Раздел 3.3 RFC 5077: билет идёт с двухбайтовой длиной
	else if(result.size() > TICKET_LONGEST){
		// Сброс накопителя билета
		result.clear();
		// Запоминаем отказ длины
		failure = error_t::LENGTH;
	}
	// Выводим итог запечатывания билета
	return failure;
}
/**
 * @brief Метод распечатывания предъявленного билета ключом ведомого поколения
 *
 * @param ticket октеты предъявленного билета
 * @param result состояние, в которое помещается распечатанное
 * @return       признак того, что билет запечатан ведомым ключом и цел
 *
 */
bool nts::internal::ticket::Keeper::redeem(const view_t & ticket, state_t & result) noexcept {
	// Сброс состояния
	result.clear();
	// Раздел 4 RFC 5077: имя ключа, вектор, длина, хоть один блок шифртекста и имитовставка
	if((ticket.data == nullptr) || (ticket.size < LEAST) || (ticket.size > TICKET_LONGEST))
		// Выводим негодность билета
		return false;
	// Место ключа билетов, которым сложен билет
	size_t generation = 2;
	/**
	 * Выполняем перебор поколений ключей билетов: нынешнего и предыдущего
	 */
	for(size_t i = 0; (i < 2) && (generation == 2); i++){
		// Если поколение заведено и имя ключа сошлось
		if(this->_vaulted[i] && (::memcmp(ticket.data, this->_keys->vault[i], TICKET_NAME) == 0))
			// Запоминаем поколение
			generation = i;
	}
	// Если ключ билета неведом
	if(generation == 2)
		// Выводим негодность билета
		return false;
	// Ключ билетов найденного поколения
	const uint8_t * vault = this->_keys->vault[generation];
	// Длина шифртекста по билету
	const size_t length = ((static_cast <size_t> (ticket.data[TICKET_NAME + BLOCK]) << 8) | ticket.data[TICKET_NAME + BLOCK + 1]);
	// Если длина шифртекста не сходится с билетом либо не кратна блоку
	if((length == 0) || ((length % BLOCK) != 0) || (ticket.size != (TICKET_NAME + BLOCK + 2 + length + TICKET_MAC)))
		// Выводим негодность билета
		return false;
	// Место, в которое помещается ожидаемая имитовставка билета
	uint8_t stamp[TICKET_MAC];
	// Раздел 4 RFC 5077: имитовставка сличается прежде расшифрования
	if(!digest::hmac(digest::hash_t::SHA256, view_t(vault + TICKET_NAME + TICKET_KEY, TICKET_MAC), view_t(ticket.data, ticket.size - TICKET_MAC), stamp, sizeof(stamp)))
		// Выводим негодность билета
		return false;
	// Если имитовставка не сошлась: сличение за постоянное время
	if(!message::compare(view_t(ticket.data + ticket.size - TICKET_MAC, TICKET_MAC), view_t(stamp, sizeof(stamp))))
		// Выводим негодность билета
		return false;
	// Объект базового шифра AES-128 билета
	cipher::aes_t aes;
	// Если ключ шифрования билета установить не удалось
	if(!aes.key(view_t(vault + TICKET_NAME, TICKET_KEY)))
		// Выводим негодность билета
		return false;
	// Объект режима простой замены с зацеплением
	cipher::chaining_t chaining;
	// Если режим запустить не удалось
	if(!chaining.start(cipher::block_t(aes), view_t(ticket.data + TICKET_NAME, BLOCK)))
		// Выводим негодность билета
		return false;
	// Признак годности билета
	bool valid = false;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Открытый текст состояния с дополнением
		vector <uint8_t> plain(length, 0);
		// Если состояние расшифровано
		if(chaining.decrypt(view_t(ticket.data + TICKET_NAME + BLOCK + 2, length), plain.data())){
			// Длина дополнения без байта длины
			const size_t padding = plain[length - 1];
			// Если дополнение умещается в открытый текст: разбираем состояние без дополнения
			if((padding + 1) <= length)
				// Разбираем запись состояния
				valid = decompose(view_t(plain.data(), length - padding - 1), result);
		}
		// Затирание открытого текста
		wipe(plain.data(), plain.size());
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим негодность билета
		return false;
	}
	// Если билет негоден
	if(!valid)
		// Сброс состояния
		result.clear();
	// Выводим признак годности билета
	return valid;
}
/**
 * @brief Метод затирания ключей обоих поколений
 *
 */
void nts::internal::ticket::Keeper::clear() noexcept {
	// Затирание ключей билетов
	this->_shelter.wipe();
	// Сбрасываем заведённость нынешнего поколения
	this->_vaulted[0] = false;
	// Сбрасываем заведённость предыдущего поколения
	this->_vaulted[1] = false;
}
/**
 * @brief Конструктор
 *
 */
nts::internal::ticket::Keeper::Keeper() noexcept : _keys(nullptr) {
	// Заводим участок укрытой памяти под ключи билетов; без него ключи не заводятся
	if(this->_shelter.reserve(sizeof(keys_t)))
		// Запоминаем ключи билетов
		this->_keys = reinterpret_cast <keys_t *> (this->_shelter.data());
	// Нынешнее поколение не заведено
	this->_vaulted[0] = false;
	// Предыдущее поколение не заведено
	this->_vaulted[1] = false;
}
/**
 * @brief Деструктор
 *
 */
nts::internal::ticket::Keeper::~Keeper() noexcept {
	// Затирание ключей билетов
	this->clear();
}
