/**
 * @file session.cpp
 * @date 2026-08-30
 *
 * @license{LicenseRef-A-NTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @brief Исходный файл модуля состояния связи протокола TLS 1.3
 *
 * @section Намеренные решения
 *
 * 1. Переписка рукопожатия не хранится, а хешируется потоком. Промежуточный хеш берётся
 *    со снимка состояния хеширования, снимок этот стоит копирования одной структуры. Иначе
 *    связь держала бы у себя всю цепочку сертификатов собеседника до конца рукопожатия -
 *    а объявить цепочку в шестнадцать мегабайтов дешевле, чем её прислать.
 *
 * 2. Ступени расписания проходятся только вперёд и только по порядку. Раздел 7.1 RFC 8446
 *    выводит всякую следующую ступень из предыдущей, и вызов не в свой черёд означает
 *    дефект в состоянии рукопожатия, а не в расписании: такой вызов отвергается.
 *
 * 3. Отказы выработки значений расписания и хеширования переписки недостижимы данными.
 *    Длины всех доводов задаются самим расписанием: значения ступеней держатся полями
 *    объявленного размера, метки вывода заданы постоянными, а хеш переписки берётся со
 *    снимка состояния. Заслоны на них стоят ради связности вывода: молчаливое употребление
 *    значения, выработанного лишь наполовину, было бы хуже отказа. Охват их не задевает, и
 *    это не пробел проверок - потому отдельно они и не помечаются.
 *
 * 4. Значения обоих направлений связи лежат в одном объекте. Направления различаются лишь
 *    меткою вывода и выводятся из одного и того же значения ступени: два одинаковых
 *    объекта под них только развели бы состояние надвое.
 *
 * 5. Хеш переписки задаётся набором шифрования, а приветствие клиента входит в переписку
 *    прежде выбора набора. Оттого переписка до выбора ведётся всеми хешами наборов разом
 *    (SHA-256, SHA-384 и «Стрибог»-256), а выбор лишь оставляет один: сообщений
 *    рукопожатия до выбора мало, и три хеша стоят дешевле, чем хранить приветствие.
 *    Переписка и расписание без выбранного хеша отвечают «Стрибогом»-256: так сложена
 *    ветвь ГОСТ, и всякое её значение сходится с прежним байт в байт.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/hmac.hpp>
#include <session/session.hpp>
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
	 * Пространство имён модуля
	 */
	using namespace nts::session;

	/**
	 * Отказы модуля
	 */
	typedef session::error_t error_t;

	/**
	 * @brief Вид сообщения, несущего хеш замещённой переписки
	 *
	 * @details Раздел 4.4.1 RFC 8446: сообщение это по связи не ходит и служит лишь
	 *          для переписки, оттого вида его среди сообщений рукопожатия нет
	 *
	 */
	static constexpr uint8_t DIGEST = 0xFE;

	/**
	 * Хеши, которыми переписка ведётся до выбора набора шифрования
	 */
	static const digest::hash_t CANDIDATES[session::Transcript::CANDIDATES] = {
		digest::hash_t::STREEBOG256, digest::hash_t::SHA256, digest::hash_t::SHA384, digest::hash_t::SM3
	};

	/**
	 * Хеш, которым переписка и расписание ведутся, пока набор шифрования не выбран
	 */
	static constexpr digest::hash_t DEFAULT = digest::hash_t::STREEBOG256;

	/**
	 * Метка вывода значения направления связи от клиента на ступени рукопожатия
	 */
	static const char * CLIENT_HANDSHAKE = "c hs traffic";

	/**
	 * Метка вывода значения направления связи от сервера на ступени рукопожатия
	 */
	static const char * SERVER_HANDSHAKE = "s hs traffic";

	/**
	 * Метка вывода значения направления связи от клиента на ступени прикладных данных
	 */
	static const char * CLIENT_APPLICATION = "c ap traffic";

	/**
	 * Метка вывода значения направления связи от сервера на ступени прикладных данных
	 */
	static const char * SERVER_APPLICATION = "s ap traffic";

	/**
	 * Метка вывода промежуточного значения между ступенями расписания
	 */
	static const char * DERIVED = "derived";

	/**
	 * Метка смены значения направления связи
	 */
	static const char * UPDATE = "traffic upd";

	/**
	 * Метка вывода значения возобновления связи
	 */
	static const char * RESUMPTION = "res master";

	/**
	 * Метка вывода заранее разделённого ключа билета
	 */
	static const char * TICKET = "resumption";

	/**
	 * Метка вывода ключа привязки заранее разделённого ключа
	 */
	static const char * BINDER = "res binder";

	/**
	 * Метка вывода значения упреждающих данных связи
	 */
	static const char * EARLY = "c e traffic";

	/**
	 * Метка вывода значения экспорта ключевого материала связи
	 */
	static const char * EXPORTER = "exp master";

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
	/**
	 * @brief Метод получения просмотра метки вывода
	 *
	 * @param label метка вывода
	 *
	 * @return      просмотр метки вывода
	 *
	 */
	static view_t label(const char * label) noexcept {
		// Выводим просмотр метки вывода
		return view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label));
	}
	/**
	 * @brief Метод вывода промежуточного значения между ступенями расписания
	 *
	 * @param algorithm хеш, которым ведётся расписание ключей
	 * @param secret    значение расписания ключей текущей ступени
	 * @param result    место, в которое помещается промежуточное значение
	 *
	 * @return          признак успешности вывода промежуточного значения
	 *
	 */
	static bool stepping(const digest::hash_t algorithm, const uint8_t * secret, uint8_t * result) noexcept {
		// Получаем длину хеша расписания ключей
		const size_t length = digest::length(algorithm);
		// Место, в которое помещается хеш пустой переписки
		uint8_t empty[schedule::SCHEDULE_WIDEST];
		// Если хеш пустой переписки вычислить не удалось
		if((length == 0) || !digest::hash(algorithm, view_t(nullptr, 0), empty, sizeof(empty)))
			// Выводим отказ вывода промежуточного значения
			return false;
		// Выводим итог вывода промежуточного значения по хешу пустой переписки
		return schedule::secret(algorithm, view_t(secret, length), ::label(DERIVED), view_t(empty, length), result);
	}
};

/**
 * @brief Метод получения объекта хеширования переписки по хешу
 *
 * @param algorithm хеш, чей объект хеширования запрашивается
 *
 * @return          объект хеширования переписки либо nullptr у неведомого хеша
 *
 */
const nts::digest::hasher_t * nts::session::Transcript::hasher(const digest::hash_t algorithm) const noexcept {
	/**
	 * Выполняем перебор хешей, которыми ведётся переписка
	 */
	for(size_t i = 0; i < CANDIDATES; i++){
		// Если искомый хеш найден
		if(::CANDIDATES[i] == algorithm)
			// Выводим объект хеширования переписки этим хешем
			return &this->_hashers[i];
	}
	// Выводим отсутствие объекта хеширования
	return nullptr;
}
/**
 * @brief Метод получения хеша, которым ведётся переписка рукопожатия
 *
 * @return хеш переписки рукопожатия
 *
 */
nts::digest::hash_t nts::session::Transcript::algorithm() const noexcept {
	// Выводим выбранный хеш переписки либо хеш ветви ГОСТ до выбора
	return ((this->_selected != digest::hash_t::NONE) ? this->_selected : DEFAULT);
}
/**
 * @brief Метод получения длины хеша переписки рукопожатия в байтах
 *
 * @return длина хеша переписки рукопожатия
 *
 */
size_t nts::session::Transcript::size() const noexcept {
	// Выводим длину хеша переписки рукопожатия
	return digest::length(this->algorithm());
}
/**
 * @brief Метод начала переписки рукопожатия
 *
 */
void nts::session::Transcript::start() noexcept {
	// Сбрасываем выбор хеша переписки
	this->_selected = digest::hash_t::NONE;
	/**
	 * Выполняем перебор хешей, которыми ведётся переписка
	 */
	for(size_t i = 0; i < CANDIDATES; i++)
		// Выполняем сброс объекта хеширования переписки очередным хешем
		this->_hashers[i].reset(::CANDIDATES[i]);
}
/**
 * @brief Метод начала переписки рукопожатия выбранным хешем
 *
 * @param algorithm хеш, которым ведётся переписка рукопожатия
 *
 * @return          отказ начала переписки на неведомом хеше
 *
 */
nts::session::error_t nts::session::Transcript::start(const digest::hash_t algorithm) noexcept {
	// Выполняем начало переписки всеми хешами
	this->start();
	// Выводим итог выбора хеша переписки
	return this->select(algorithm);
}
/**
 * @brief Метод выбора хеша переписки рукопожатия
 *
 * @param algorithm хеш, выбранный набором шифрования
 *
 * @return          отказ выбора хеша переписки
 *
 */
nts::session::error_t nts::session::Transcript::select(const digest::hash_t algorithm) noexcept {
	// Если хеш переписке неведом
	if(this->hasher(algorithm) == nullptr)
		// Выводим отказ выбора хеша переписки
		return error_t::DIGEST;
	// Если хеш переписки уже выбран
	if(this->_selected != digest::hash_t::NONE)
		// Выводим итог сличения выбранного хеша с прежним выбором
		return ((this->_selected == algorithm) ? error_t::NONE : error_t::STATE);
	// Запоминаем выбранный хеш переписки
	this->_selected = algorithm;
	// Выводим успешность выбора хеша переписки
	return error_t::NONE;
}
/**
 * @brief Метод сброса переписки рукопожатия
 *
 */
void nts::session::Transcript::clear() noexcept {
	// Выполняем начало переписки заново
	this->start();
}
/**
 * @brief Метод добавления сообщения в переписку рукопожатия
 *
 * @param message добавляемое сообщение вместе с его обвязкой
 *
 * @return        отказ добавления сообщения в переписку
 *
 */
nts::session::error_t nts::session::Transcript::update(const view_t & message) noexcept {
	// Если сообщение не передано
	if((message.data == nullptr) || (message.size == 0))
		// Выводим отказ добавления сообщения в переписку
		return error_t::EMPTY;
	// Если хеш переписки выбран
	if(this->_selected != digest::hash_t::NONE){
		/**
		 * Выполняем перебор хешей, которыми ведётся переписка
		 */
		for(size_t i = 0; i < CANDIDATES; i++){
			// Если хеш переписки выбранный
			if(::CANDIDATES[i] == this->_selected)
				// Добавляем сообщение в переписку выбранным хешем
				this->_hashers[i].update(message);
		}
	// Если хеш переписки ещё не выбран
	} else {
		/**
		 * Выполняем перебор хешей, которыми ведётся переписка
		 */
		for(size_t i = 0; i < CANDIDATES; i++)
			// Добавляем сообщение в переписку очередным хешем
			this->_hashers[i].update(message);
	}
	// Выводим успешность добавления сообщения в переписку
	return error_t::NONE;
}
/**
 * @brief Метод получения хеша переписки рукопожатия
 *
 * @param result место, в которое помещается хеш переписки
 *
 * @return       отказ получения хеша переписки
 *
 */
nts::session::error_t nts::session::Transcript::digest(uint8_t * result) const noexcept {
	// Выводим итог получения хеша переписки без довеска
	return this->digest(this->algorithm(), view_t(nullptr, 0), result);
}
/**
 * @brief Метод получения хеша переписки рукопожатия с довеском
 *
 * @param suffix довесок, дописываемый к переписке лишь на этот хеш
 * @param result место, в которое помещается хеш переписки с довеском
 *
 * @return       отказ получения хеша переписки с довеском
 *
 */
nts::session::error_t nts::session::Transcript::digest(const view_t & suffix, uint8_t * result) const noexcept {
	// Выводим итог получения хеша переписки с довеском ведущим хешем
	return this->digest(this->algorithm(), suffix, result);
}
/**
 * @brief Метод получения хеша переписки рукопожатия с довеском заданным хешем
 *
 * @param algorithm хеш, которым берётся хеш переписки
 * @param suffix    довесок, дописываемый к переписке лишь на этот хеш
 * @param result    место, в которое помещается хеш переписки с довеском
 *
 * @return          отказ получения хеша переписки с довеском
 *
 */
nts::session::error_t nts::session::Transcript::digest(const digest::hash_t algorithm, const view_t & suffix, uint8_t * result) const noexcept {
	// Если место для хеша переписки не передано
	if(result == nullptr)
		// Выводим отказ получения хеша переписки
		return error_t::EMPTY;
	// Если хеш переписки выбран, а запрошен иной
	if((this->_selected != digest::hash_t::NONE) && (algorithm != this->_selected))
		// Выводим отказ получения хеша переписки чужим хешем
		return error_t::DIGEST;
	// Получаем объект хеширования переписки запрошенным хешем
	const digest::hasher_t * item = this->hasher(algorithm);
	// Если хеш переписке неведом
	if(item == nullptr)
		// Выводим отказ получения хеша переписки
		return error_t::DIGEST;
	// Получаем снимок состояния хеширования переписки
	digest::hasher_t hash = (* item);
	// Если довесок передан
	if((suffix.data != nullptr) && (suffix.size > 0))
		// Добавляем довесок в снимок переписки
		hash.update(suffix);
	// Если хеш переписки получить не удалось
	if(!hash.finish(result, digest::length(algorithm)))
		// Выводим отказ получения хеша переписки
		return error_t::DIGEST;
	// Выводим успешность получения хеша переписки
	return error_t::NONE;
}
/**
 * @brief Метод замены накопленной переписки её хешем
 *
 * @return отказ замены накопленной переписки
 *
 */
nts::session::error_t nts::session::Transcript::replace() noexcept {
	// Хеш, которым ведётся переписка
	const digest::hash_t algorithm = this->algorithm();
	/**
	 * Замена закрепляет хеш переписки: прочие хеши от неё отстают безвозвратно
	 */
	const error_t chosen = this->select(algorithm);
	// Если хеш переписки закрепить не удалось
	if(chosen != error_t::NONE)
		// Выводим отказ замены накопленной переписки
		return chosen;
	// Место, в которое помещается хеш накопленной переписки
	uint8_t digest[schedule::SCHEDULE_WIDEST];
	// Выполняем получение хеша накопленной переписки
	const error_t error = this->digest(digest);
	// Если хеш накопленной переписки получить не удалось
	if(error != error_t::NONE)
		// Выводим отказ замены накопленной переписки
		return error;
	// Длина хеша накопленной переписки
	const size_t length = digest::length(algorithm);
	// Обвязка сообщения, несущего хеш переписки
	uint8_t header[4];
	// Записываем вид сообщения, несущего хеш переписки
	header[0] = DIGEST;
	// Записываем старший байт длины сообщения
	header[1] = 0x00;
	// Записываем средний байт длины сообщения
	header[2] = 0x00;
	// Записываем младший байт длины сообщения
	header[3] = static_cast <uint8_t> (length);
	/**
	 * Выполняем перебор хешей, которыми ведётся переписка
	 */
	for(size_t i = 0; i < CANDIDATES; i++){
		// Если хеш переписки выбранный
		if(::CANDIDATES[i] == algorithm){
			// Выполняем начало переписки заново выбранным хешем
			this->_hashers[i].reset(algorithm);
			// Добавляем в переписку обвязку сообщения с хешем
			this->_hashers[i].update(view_t(header, sizeof(header)));
			// Добавляем в переписку хеш замещённой переписки
			this->_hashers[i].update(view_t(digest, length));
		}
	}
	// Выполняем затирание хеша замещённой переписки
	wipe(digest, sizeof(digest));
	// Выводим успешность замены накопленной переписки
	return error_t::NONE;
}
/**
 * @brief Конструктор
 *
 */
nts::session::Transcript::Transcript() noexcept : _selected(digest::hash_t::NONE) {
	// Выполняем начало переписки всеми хешами
	this->start();
}
/**
 * @brief Метод получения хеша, которым ведётся расписание ключей
 *
 * @return хеш расписания ключей
 *
 */
nts::digest::hash_t nts::session::Secrets::algorithm() const noexcept {
	// Выводим хеш расписания ключей
	return this->_algorithm;
}
/**
 * @brief Метод получения длины значения расписания ключей в байтах
 *
 * @return длина значения расписания ключей
 *
 */
size_t nts::session::Secrets::size() const noexcept {
	// Выводим длину значения расписания ключей
	return this->_length;
}
/**
 * @brief Метод получения пройденной ступени расписания ключей
 *
 * @return пройденная ступень расписания ключей
 *
 */
stage_t nts::session::Secrets::stage() const noexcept {
	// Выводим пройденную ступень расписания ключей
	return this->_stage;
}
/**
 * @brief Метод сброса значений расписания ключей
 *
 */
void nts::session::Secrets::clear() noexcept {
	// Выполняем затирание всех значений расписания ключей в укрытой памяти
	this->_shelter.wipe();
	// Сбрасываем хеш расписания ключей на хеш ветви ГОСТ
	this->_algorithm = DEFAULT;
	// Сбрасываем длину значения расписания ключей
	this->_length = digest::length(DEFAULT);
	// Сбрасываем пройденную ступень расписания ключей
	this->_stage = stage_t::NONE;
}
/**
 * @brief Метод заведения начальной ступени расписания ключей
 *
 * @param secret заранее разделённый ключ связи
 *
 * @return       отказ заведения начальной ступени
 *
 */
nts::session::error_t nts::session::Secrets::start(const view_t & secret) noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Выводим итог заведения начальной ступени расписания «Стрибогом»-256
	return this->start(DEFAULT, secret);
}
/**
 * @brief Метод заведения начальной ступени расписания ключей выбранным хешем
 *
 * @param algorithm хеш набора шифрования, которым ведётся расписание
 * @param secret    заранее разделённый ключ связи
 *
 * @return          отказ заведения начальной ступени
 *
 */
nts::session::error_t nts::session::Secrets::start(const digest::hash_t algorithm, const view_t & secret) noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Выполняем сброс значений расписания ключей
	this->clear();
	// Получаем длину хеша расписания ключей
	const size_t length = digest::length(algorithm);
	// Если хеш расписания не установлен либо шире места под значение
	if((length == 0) || (length > schedule::SCHEDULE_WIDEST))
		// Выводим отказ заведения начальной ступени
		return error_t::DIGEST;
	// Запоминаем хеш расписания ключей
	this->_algorithm = algorithm;
	// Запоминаем длину значения расписания ключей
	this->_length = length;
	// Строка нулей длиною в хеш
	uint8_t zeroes[schedule::SCHEDULE_WIDEST];
	// Обнуляем строку нулей
	::memset(zeroes, 0, sizeof(zeroes));
	// Ключевой материал начальной ступени: заранее разделённый ключ либо нули
	const view_t material = (((secret.data != nullptr) && (secret.size > 0)) ? secret : view_t(zeroes, length));
	// Если начальное значение расписания извлечь не удалось
	if(!schedule::extract(algorithm, view_t(zeroes, length), material, this->_keys->secret)){
		// Выполняем сброс значений расписания ключей
		this->clear();
		// Выводим отказ заведения начальной ступени
		return error_t::SCHEDULE;
	}
	// Отмечаем прохождение начальной ступени
	this->_stage = stage_t::EARLY;
	// Выводим успешность заведения начальной ступени
	return error_t::NONE;
}
/**
 * @brief Метод вывода ступени рукопожатия расписания ключей
 *
 * @param shared     общее значение обмена ключами
 * @param transcript хеш переписки рукопожатия на миг вывода
 *
 * @return           отказ вывода ступени рукопожатия
 *
 */
nts::session::error_t nts::session::Secrets::handshake(const view_t & shared, const view_t & transcript) noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Если начальная ступень не пройдена
	if(this->_stage != stage_t::EARLY)
		// Выводим отказ вывода ступени рукопожатия
		return error_t::STATE;
	// Если общее значение либо хеш переписки не переданы
	if((shared.data == nullptr) || (shared.size == 0) || (transcript.data == nullptr) || (transcript.size == 0))
		// Выводим отказ вывода ступени рукопожатия
		return error_t::EMPTY;
	// Место, в которое помещается промежуточное значение
	uint8_t derived[schedule::SCHEDULE_WIDEST];
	// Если промежуточное значение вывести не удалось
	if(!stepping(this->_algorithm, this->_keys->secret, derived)){
		// Выполняем затирание промежуточного значения
		wipe(derived, sizeof(derived));
		// Выводим отказ вывода ступени рукопожатия
		return error_t::SCHEDULE;
	}
	// Если значение ступени рукопожатия извлечь не удалось
	if(!schedule::extract(this->_algorithm, view_t(derived, this->_length), shared, this->_keys->secret)){
		// Выполняем затирание промежуточного значения
		wipe(derived, sizeof(derived));
		// Выводим отказ вывода ступени рукопожатия
		return error_t::SCHEDULE;
	}
	// Выполняем затирание промежуточного значения
	wipe(derived, sizeof(derived));
	// Если значение направления связи от клиента вывести не удалось
	if(!schedule::secret(this->_algorithm, view_t(this->_keys->secret, this->_length), ::label(CLIENT_HANDSHAKE), transcript, this->_keys->client))
		// Выводим отказ вывода ступени рукопожатия
		return error_t::SCHEDULE;
	// Если значение направления связи от сервера вывести не удалось
	if(!schedule::secret(this->_algorithm, view_t(this->_keys->secret, this->_length), ::label(SERVER_HANDSHAKE), transcript, this->_keys->server))
		// Выводим отказ вывода ступени рукопожатия
		return error_t::SCHEDULE;
	// Отмечаем прохождение ступени рукопожатия
	this->_stage = stage_t::HANDSHAKE;
	// Выводим успешность вывода ступени рукопожатия
	return error_t::NONE;
}
/**
 * @brief Метод вывода ступени прикладных данных расписания ключей
 *
 * @param transcript хеш переписки рукопожатия на миг вывода
 *
 * @return           отказ вывода ступени прикладных данных
 *
 */
nts::session::error_t nts::session::Secrets::application(const view_t & transcript) noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Если ступень рукопожатия не пройдена
	if(this->_stage != stage_t::HANDSHAKE)
		// Выводим отказ вывода ступени прикладных данных
		return error_t::STATE;
	// Если хеш переписки не передан
	if((transcript.data == nullptr) || (transcript.size == 0))
		// Выводим отказ вывода ступени прикладных данных
		return error_t::EMPTY;
	// Место, в которое помещается промежуточное значение
	uint8_t derived[schedule::SCHEDULE_WIDEST];
	// Если промежуточное значение вывести не удалось
	if(!stepping(this->_algorithm, this->_keys->secret, derived)){
		// Выполняем затирание промежуточного значения
		wipe(derived, sizeof(derived));
		// Выводим отказ вывода ступени прикладных данных
		return error_t::SCHEDULE;
	}
	// Строка нулей длиною в хеш на место ключевого материала
	uint8_t zeroes[schedule::SCHEDULE_WIDEST];
	// Обнуляем строку нулей
	::memset(zeroes, 0, sizeof(zeroes));
	// Если значение ступени прикладных данных извлечь не удалось
	if(!schedule::extract(this->_algorithm, view_t(derived, this->_length), view_t(zeroes, this->_length), this->_keys->secret)){
		// Выполняем затирание промежуточного значения
		wipe(derived, sizeof(derived));
		// Выводим отказ вывода ступени прикладных данных
		return error_t::SCHEDULE;
	}
	// Выполняем затирание промежуточного значения
	wipe(derived, sizeof(derived));
	// Если значение направления связи от клиента вывести не удалось
	if(!schedule::secret(this->_algorithm, view_t(this->_keys->secret, this->_length), ::label(CLIENT_APPLICATION), transcript, this->_keys->client))
		// Выводим отказ вывода ступени прикладных данных
		return error_t::SCHEDULE;
	// Если значение направления связи от сервера вывести не удалось
	if(!schedule::secret(this->_algorithm, view_t(this->_keys->secret, this->_length), ::label(SERVER_APPLICATION), transcript, this->_keys->server))
		// Выводим отказ вывода ступени прикладных данных
		return error_t::SCHEDULE;
	// Если значение экспорта ключевого материала вывести не удалось
	if(!schedule::secret(this->_algorithm, view_t(this->_keys->secret, this->_length), ::label(EXPORTER), transcript, this->_keys->exporter))
		// Выводим отказ вывода ступени прикладных данных
		return error_t::SCHEDULE;
	// Отмечаем прохождение ступени прикладных данных
	this->_stage = stage_t::APPLICATION;
	// Выводим успешность вывода ступени прикладных данных
	return error_t::NONE;
}
/**
 * @brief Метод получения значения направления связи
 *
 * @param side   сторона, чьё направление связи запрашивается
 * @param result место, в которое помещается значение направления связи
 *
 * @return       отказ получения значения направления связи
 *
 */
nts::session::error_t nts::session::Secrets::traffic(const side_t side, uint8_t * result) const noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Если ступень рукопожатия ещё не пройдена
	if((this->_stage != stage_t::HANDSHAKE) && (this->_stage != stage_t::APPLICATION))
		// Выводим отказ получения значения направления связи
		return error_t::STATE;
	// Если место для значения направления связи не передано
	if(result == nullptr)
		// Выводим отказ получения значения направления связи
		return error_t::EMPTY;
	// Переносим значение направления связи запрошенной стороны
	::memcpy(result, ((side == side_t::CLIENT) ? this->_keys->client : this->_keys->server), this->_length);
	// Выводим успешность получения значения направления связи
	return error_t::NONE;
}
/**
 * @brief Метод вывода ключевого материала из значения направления связи
 *
 * @param traffic значение направления связи, из которого выводится материал
 * @param suite   набор шифрования, которым защищаются записи
 * @param key     место, в которое помещается корневой ключ направления
 * @param vector  место, в которое помещается вектор замены направления
 *
 * @return        отказ вывода ключевого материала направления связи
 *
 */
nts::session::error_t nts::session::material(const view_t & traffic, const protect::suite_t suite, uint8_t * key, uint8_t * vector) noexcept {
	// Получаем хеш набора шифрования
	const digest::hash_t algorithm = protect::hash(suite);
	// Получаем длину вектора замены набора шифрования
	const size_t size = protect::block(suite);
	// Если набор шифрования неизвестен
	if((size == 0) || (algorithm == digest::hash_t::NONE))
		// Выводим отказ вывода ключевого материала
		return error_t::SUITE;
	// Если значение направления связи не передано либо не сходится с хешем набора
	if((traffic.data == nullptr) || (traffic.size != digest::length(algorithm)))
		// Выводим отказ вывода ключевого материала
		return error_t::EMPTY;
	// Если места для ключевого материала не переданы
	if((key == nullptr) || (vector == nullptr))
		// Выводим отказ вывода ключевого материала
		return error_t::EMPTY;
	// Выполняем вывод корневого ключа направления связи
	bool ok = schedule::derive(algorithm, traffic, ::label("key"), view_t(nullptr, 0), key, protect::key(suite));
	// Если корневой ключ выведен
	if(ok)
		// Выполняем вывод вектора замены направления связи
		ok = schedule::derive(algorithm, traffic, ::label("iv"), view_t(nullptr, 0), vector, size);
	// Выводим итог вывода ключевого материала направления связи
	return (ok ? error_t::NONE : error_t::SCHEDULE);
}
/**
 * @brief Метод вывода ключевого материала направления связи
 *
 * @param side   сторона, чьё направление связи запрашивается
 * @param suite  набор шифрования, которым защищаются записи
 * @param key    место, в которое помещается корневой ключ направления
 * @param vector место, в которое помещается вектор замены направления
 *
 * @return       отказ вывода ключевого материала направления связи
 *
 */
nts::session::error_t nts::session::Secrets::material(const side_t side, const protect::suite_t suite, uint8_t * key, uint8_t * vector) const noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Место, в которое помещается значение направления связи
	uint8_t traffic[schedule::SCHEDULE_WIDEST];
	// Выполняем получение значения направления связи
	const error_t error = this->traffic(side, traffic);
	// Если значение направления связи получить не удалось
	if(error != error_t::NONE)
		// Выводим отказ вывода ключевого материала
		return error;
	/**
	 * Хеш набора шифрования обязан сходиться с хешем расписания: раздел 7.1 RFC 8446
	 * ведёт расписание хешем набора, и материал под набор с иным хешем невыводим
	 */
	if(protect::hash(suite) != this->_algorithm){
		// Выполняем затирание значения направления связи
		wipe(traffic, sizeof(traffic));
		// Выводим отказ вывода ключевого материала
		return error_t::SUITE;
	}
	// Выполняем вывод ключевого материала направления связи
	const error_t outcome = nts::session::material(view_t(traffic, this->_length), suite, key, vector);
	// Выполняем затирание значения направления связи
	wipe(traffic, sizeof(traffic));
	// Выводим итог вывода ключевого материала направления связи
	return outcome;
}
/**
 * @brief Метод вывода значения упреждающих данных связи
 *
 * @param transcript хеш переписки рукопожатия на миг вывода
 *
 * @return           отказ вывода значения упреждающих данных
 *
 */
nts::session::error_t nts::session::Secrets::early(const view_t & transcript) noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Если начальная ступень не пройдена
	if(this->_stage != stage_t::EARLY)
		// Выводим отказ вывода значения упреждающих данных
		return error_t::STATE;
	// Если хеш переписки не передан
	if((transcript.data == nullptr) || (transcript.size == 0))
		// Выводим отказ вывода значения упреждающих данных
		return error_t::EMPTY;
	// Если значение упреждающих данных вывести не удалось
	if(!schedule::secret(this->_algorithm, view_t(this->_keys->secret, this->_length), ::label(EARLY), transcript, this->_keys->early))
		// Выводим отказ вывода значения упреждающих данных
		return error_t::SCHEDULE;
	// Выводим успешность вывода значения упреждающих данных
	return error_t::NONE;
}
/**
 * @brief Метод получения значения упреждающих данных связи
 *
 * @param result место, в которое помещается значение упреждающих данных
 *
 * @return       отказ получения значения упреждающих данных
 *
 */
nts::session::error_t nts::session::Secrets::early(uint8_t * result) const noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Если место для значения упреждающих данных не передано
	if(result == nullptr)
		// Выводим отказ получения значения упреждающих данных
		return error_t::EMPTY;
	// Если расписание ключей не заведено
	if(this->_stage == stage_t::NONE)
		// Выводим отказ получения значения упреждающих данных
		return error_t::STATE;
	// Переносим значение упреждающих данных связи
	::memcpy(result, this->_keys->early, this->_length);
	// Выводим успешность получения значения упреждающих данных
	return error_t::NONE;
}
/**
 * @brief Метод вывода экспортируемого ключевого материала связи
 *
 * @param label   метка назначения экспортируемого материала
 * @param context привязка экспортируемого материала к потребителю
 * @param result  место, в которое помещается экспортируемый материал
 * @param size    требуемая длина экспортируемого материала в байтах
 *
 * @return        отказ вывода экспортируемого материала
 *
 */
nts::session::error_t nts::session::Secrets::exporting(const view_t & label, const view_t & context, uint8_t * result, const size_t size) const noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Если ступень прикладных данных не пройдена
	if(this->_stage != stage_t::APPLICATION)
		// Выводим отказ вывода экспортируемого материала
		return error_t::STATE;
	// Если метка назначения либо место итога не переданы
	if((label.data == nullptr) || (label.size == 0) || (result == nullptr) || (size == 0))
		// Выводим отказ вывода экспортируемого материала
		return error_t::EMPTY;
	// Место, в которое помещается хеш пустой переписки
	uint8_t empty[schedule::SCHEDULE_WIDEST];
	// Если хеш пустой переписки вычислить не удалось
	if(!digest::hash(this->_algorithm, view_t(nullptr, 0), empty, sizeof(empty)))
		// Выводим отказ вывода экспортируемого материала
		return error_t::SCHEDULE;
	// Место, в которое помещается значение по метке назначения
	uint8_t secret[schedule::SCHEDULE_WIDEST];
	// Если значение по метке назначения вывести не удалось
	if(!schedule::secret(this->_algorithm, view_t(this->_keys->exporter, this->_length), label, view_t(empty, this->_length), secret)){
		// Выполняем затирание значения по метке назначения
		wipe(secret, sizeof(secret));
		// Выводим отказ вывода экспортируемого материала
		return error_t::SCHEDULE;
	}
	// Место, в которое помещается хеш привязки потребителя
	uint8_t hashed[schedule::SCHEDULE_WIDEST];
	// Если привязка не задана, хеш берётся от пустой переписки
	const view_t binding(((context.data != nullptr) && (context.size > 0)) ? context : view_t(nullptr, 0));
	// Если хеш привязки вычислить не удалось
	if(!digest::hash(this->_algorithm, binding, hashed, sizeof(hashed))){
		// Выполняем затирание значения по метке назначения
		wipe(secret, sizeof(secret));
		// Выводим отказ вывода экспортируемого материала
		return error_t::SCHEDULE;
	}
	// Выполняем растяжение значения по метке хешем привязки до требуемой длины
	const bool ok = schedule::expand(this->_algorithm, view_t(secret, this->_length), view_t(hashed, this->_length), result, size);
	// Выполняем затирание значения по метке назначения
	wipe(secret, sizeof(secret));
	// Выводим итог вывода экспортируемого материала
	return (ok ? error_t::NONE : error_t::SCHEDULE);
}
/**
 * @brief Метод вывода ключа завершения рукопожатия
 *
 * @param side   сторона, чей ключ завершения запрашивается
 * @param result место, в которое помещается ключ завершения рукопожатия
 *
 * @return       отказ вывода ключа завершения рукопожатия
 *
 */
nts::session::error_t nts::session::Secrets::finished(const side_t side, uint8_t * result) const noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Место, в которое помещается значение направления связи
	uint8_t traffic[schedule::SCHEDULE_WIDEST];
	// Выполняем получение значения направления связи
	const error_t error = this->traffic(side, traffic);
	// Если значение направления связи получить не удалось
	if(error != error_t::NONE)
		// Выводим отказ вывода ключа завершения
		return error;
	// Если место для ключа завершения не передано
	if(result == nullptr){
		// Выполняем затирание значения направления связи
		wipe(traffic, sizeof(traffic));
		// Выводим отказ вывода ключа завершения
		return error_t::EMPTY;
	}
	// Выполняем вывод ключа завершения рукопожатия
	const bool ok = schedule::derive(this->_algorithm, view_t(traffic, this->_length), ::label("finished"), view_t(nullptr, 0), result, this->_length);
	// Выполняем затирание значения направления связи
	wipe(traffic, sizeof(traffic));
	// Выводим итог вывода ключа завершения рукопожатия
	return (ok ? error_t::NONE : error_t::SCHEDULE);
}
/**
 * @brief Метод вывода значения возобновления связи
 *
 * @param transcript хеш переписки рукопожатия на миг вывода
 *
 * @return           отказ вывода значения возобновления связи
 *
 */
nts::session::error_t nts::session::Secrets::resumption(const view_t & transcript) noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Если ступень прикладных данных не пройдена
	if(this->_stage != stage_t::APPLICATION)
		// Выводим отказ вывода значения возобновления связи
		return error_t::STATE;
	// Если хеш переписки не передан
	if((transcript.data == nullptr) || (transcript.size == 0))
		// Выводим отказ вывода значения возобновления связи
		return error_t::EMPTY;
	// Если значение возобновления связи вывести не удалось
	if(!schedule::secret(this->_algorithm, view_t(this->_keys->secret, this->_length), ::label(RESUMPTION), transcript, this->_keys->resumption))
		// Выводим отказ вывода значения возобновления связи
		return error_t::SCHEDULE;
	// Выводим успешность вывода значения возобновления связи
	return error_t::NONE;
}
/**
 * @brief Метод вывода заранее разделённого ключа билета
 *
 * @param nonce  одноразовое значение билета
 * @param result место, в которое помещается заранее разделённый ключ
 *
 * @return       отказ вывода заранее разделённого ключа билета
 *
 */
nts::session::error_t nts::session::Secrets::ticket(const view_t & nonce, uint8_t * result) const noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Если ступень прикладных данных не пройдена
	if(this->_stage != stage_t::APPLICATION)
		// Выводим отказ вывода заранее разделённого ключа
		return error_t::STATE;
	// Если место для заранее разделённого ключа не передано
	if(result == nullptr)
		// Выводим отказ вывода заранее разделённого ключа
		return error_t::EMPTY;
	// Если заранее разделённый ключ билета вывести не удалось
	if(!schedule::derive(this->_algorithm, view_t(this->_keys->resumption, this->_length), ::label(TICKET), nonce, result, this->_length))
		// Выводим отказ вывода заранее разделённого ключа
		return error_t::SCHEDULE;
	// Выводим успешность вывода заранее разделённого ключа
	return error_t::NONE;
}
/**
 * @brief Метод выработки привязки заранее разделённого ключа
 *
 * @param transcript хеш переписки с усечённым приветствием клиента
 * @param result     место, в которое помещается привязка ключа
 *
 * @return           отказ выработки привязки заранее разделённого ключа
 *
 */
nts::session::error_t nts::session::Secrets::binder(const view_t & transcript, uint8_t * result) const noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Если начальная ступень не пройдена
	if(this->_stage != stage_t::EARLY)
		// Выводим отказ выработки привязки
		return error_t::STATE;
	// Если хеш переписки либо место для привязки не переданы
	if((transcript.data == nullptr) || (transcript.size == 0) || (result == nullptr))
		// Выводим отказ выработки привязки
		return error_t::EMPTY;
	// Место, в которое помещается хеш пустой переписки
	uint8_t empty[schedule::SCHEDULE_WIDEST];
	// Если хеш пустой переписки вычислить не удалось
	if(!digest::hash(this->_algorithm, view_t(nullptr, 0), empty, sizeof(empty)))
		// Выводим отказ выработки привязки
		return error_t::SCHEDULE;
	// Место, в которое помещается значение привязки
	uint8_t secret[schedule::SCHEDULE_WIDEST];
	// Если значение привязки вывести не удалось
	if(!schedule::secret(this->_algorithm, view_t(this->_keys->secret, this->_length), ::label(BINDER), view_t(empty, this->_length), secret)){
		// Выполняем затирание значения привязки
		wipe(secret, sizeof(secret));
		// Выводим отказ выработки привязки
		return error_t::SCHEDULE;
	}
	// Место, в которое помещается ключ привязки
	uint8_t key[schedule::SCHEDULE_WIDEST];
	// Если ключ привязки вывести не удалось
	if(!schedule::derive(this->_algorithm, view_t(secret, this->_length), ::label("finished"), view_t(nullptr, 0), key, this->_length)){
		// Выполняем затирание ключа привязки
		wipe(key, sizeof(key));
		// Выполняем затирание значения привязки
		wipe(secret, sizeof(secret));
		// Выводим отказ выработки привязки
		return error_t::SCHEDULE;
	}
	// Выполняем выработку привязки имитовставкой от хеша переписки
	const bool ok = digest::hmac(this->_algorithm, view_t(key, this->_length), transcript, result, this->_length);
	// Выполняем затирание ключа привязки
	wipe(key, sizeof(key));
	// Выполняем затирание значения привязки
	wipe(secret, sizeof(secret));
	// Выводим итог выработки привязки заранее разделённого ключа
	return (ok ? error_t::NONE : error_t::DIGEST);
}
/**
 * @brief Метод смены значения направления связи
 *
 * @param side сторона, чьё направление связи сменяется
 *
 * @return     отказ смены значения направления связи
 *
 */
nts::session::error_t nts::session::Secrets::renew(const side_t side) noexcept {
	// Если укрытой памяти под значения расписания нет
	if(this->_keys == nullptr)
		// Выводим отказ состояния расписания
		return error_t::STATE;
	// Если ступень прикладных данных не пройдена
	if(this->_stage != stage_t::APPLICATION)
		// Выводим отказ смены значения направления связи
		return error_t::STATE;
	// Сменяемое значение направления связи
	uint8_t * traffic = ((side == side_t::CLIENT) ? this->_keys->client : this->_keys->server);
	// Место, в которое помещается новое значение направления связи
	uint8_t result[schedule::SCHEDULE_WIDEST];
	// Если новое значение направления связи вывести не удалось
	if(!schedule::derive(this->_algorithm, view_t(traffic, this->_length), ::label(UPDATE), view_t(nullptr, 0), result, this->_length)){
		// Выполняем затирание нового значения направления связи
		wipe(result, sizeof(result));
		// Выводим отказ смены значения направления связи
		return error_t::SCHEDULE;
	}
	// Переносим новое значение направления связи на место прежнего
	::memcpy(traffic, result, this->_length);
	// Выполняем затирание нового значения направления связи
	wipe(result, sizeof(result));
	// Выводим успешность смены значения направления связи
	return error_t::NONE;
}
/**
 * @brief Конструктор
 *
 */
nts::session::Secrets::Secrets() noexcept : _stage(stage_t::NONE), _algorithm(DEFAULT), _length(digest::length(DEFAULT)), _keys(nullptr) {
	/**
	 * Заводим участок укрытой памяти под значения расписания; без участка расписание
	 * вести нечем, и всякая ступень отвечает отказом состояния
	 */
	if(this->_shelter.reserve(sizeof(keys_t)))
		// Запоминаем значения расписания ключей
		this->_keys = reinterpret_cast <keys_t *> (this->_shelter.data());
}
/**
 * @brief Деструктор
 *
 */
nts::session::Secrets::~Secrets() noexcept {
	// Выполняем сброс значений расписания ключей
	this->clear();
}
