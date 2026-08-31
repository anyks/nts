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
 * 3. Значения обоих направлений связи лежат в одном объекте. Направления различаются лишь
 *    меткою вывода и выводятся из одного и того же значения ступени: два одинаковых
 *    объекта под них только развели бы состояние надвое.
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
	 * @brief Вид сообщения, несущего хеш приветствия клиента
	 *
	 * @details Раздел 4.4.1 RFC 8446: значение message_hash перечисления видов сообщений
	 *
	 */
	static constexpr uint8_t DIGEST = 0xFE;

	/**
	 * @brief Метка вывода значения направления связи от клиента на поре рукопожатия
	 *
	 */
	static const char * CLIENT_HANDSHAKE = "c hs traffic";

	/**
	 * @brief Метка вывода значения направления связи от сервера на поре рукопожатия
	 *
	 */
	static const char * SERVER_HANDSHAKE = "s hs traffic";

	/**
	 * @brief Метка вывода значения направления связи от клиента на поре прикладных данных
	 *
	 */
	static const char * CLIENT_APPLICATION = "c ap traffic";

	/**
	 * @brief Метка вывода значения направления связи от сервера на поре прикладных данных
	 *
	 */
	static const char * SERVER_APPLICATION = "s ap traffic";

	/**
	 * @brief Метка вывода значения перехода к следующей ступени расписания
	 *
	 */
	static const char * DERIVED = "derived";

	/**
	 * @brief Метка вывода нового значения направления связи
	 *
	 */
	static const char * UPDATE = "traffic upd";

	/**
	 * @brief Метка вывода значения возобновления связи
	 *
	 */
	static const char * RESUMPTION = "res master";

	/**
	 * @brief Метка вывода ключа билета возобновления связи
	 *
	 */
	static const char * TICKET = "resumption";

	/**
	 * @brief Метка вывода ключа привязки заранее разделённого ключа
	 *
	 */
	static const char * BINDER = "res binder";

	/**
	 * @brief Метка вывода значения упреждающих данных связи
	 *
	 */
	static const char * EARLY = "c e traffic";

	/**
	 * @brief Метод затирания области памяти
	 *
	 * @param data затираемая область памяти
	 * @param size размер затираемой области памяти
	 *
	 */
	static void wipe(void * data, const size_t size) noexcept {
		// Получаем изменчивый указатель на затираемую область памяти
		volatile uint8_t * item = static_cast <volatile uint8_t *> (data);
		/**
		 * Выполняем перебор байтов затираемой области памяти
		 */
		for(size_t i = 0; i < size; i++)
			// Обнуляем очередной байт области памяти
			item[i] = 0;
	}
	/**
	 * @brief Метод получения просмотра метки вывода значения
	 *
	 * @param label метка вывода значения расписания ключей
	 *
	 * @return      просмотр области байтов метки вывода
	 *
	 */
	static view_t label(const char * label) noexcept {
		// Выводим просмотр области байтов метки вывода значения
		return view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label));
	}
	/**
	 * @brief Метод перехода к следующей ступени расписания ключей
	 *
	 * @details Раздел 7.1 RFC 8446: перед всяким извлечением значение предыдущей ступени
	 *          выводится меткою «derived», а привязкою ему служит хеш пустой переписки
	 *
	 * @param secret значение ступени, из которой ведётся переход
	 * @param result место, в которое помещается значение перехода
	 *
	 * @return       признак успешности перехода к следующей ступени
	 *
	 */
	static bool stepping(const uint8_t * secret, uint8_t * result) noexcept {
		// Хеш пустой переписки рукопожатия
		uint8_t empty[schedule::SCHEDULE_SECRET];
		// Если хеш пустой переписки выработать не удалось
		if(!digest::streebog(digest::type_t::SHORT, view_t(nullptr, 0), empty, sizeof(empty)))
			// Выводим отказ перехода к следующей ступени
			return false;
		// Выводим итог вывода значения перехода к следующей ступени
		return schedule::secret(view_t(secret, schedule::SCHEDULE_SECRET), ::label(DERIVED), view_t(empty, sizeof(empty)), result);
	}
};

/**
 * @brief Метод начала переписки рукопожатия
 *
 */
void nts::session::Transcript::start() noexcept {
	// Выполняем сброс объекта хеширования переписки рукопожатия
	this->_hash.reset(digest::type_t::SHORT);
}
/**
 * @brief Метод сброса переписки рукопожатия
 *
 */
void nts::session::Transcript::clear() noexcept {
	// Выполняем сброс объекта хеширования переписки рукопожатия
	this->_hash.reset(digest::type_t::SHORT);
}
/**
 * @brief Метод добавления сообщения в переписку рукопожатия
 *
 * @param message добавляемое сообщение вместе с его обвязкой
 *
 * @return        отказ добавления сообщения в переписку
 *
 */
error_t nts::session::Transcript::update(const view_t & message) noexcept {
	// Если добавляемое сообщение не передано
	if((message.data == nullptr) || (message.size == 0))
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	// Выполняем добавление сообщения в переписку рукопожатия
	this->_hash.update(message);
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
error_t nts::session::Transcript::digest(uint8_t * result) const noexcept {
	// Если место для хеша переписки не передано
	if(result == nullptr)
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	/**
	 * Снимаем состояние хеширования переписки рукопожатия
	 *
	 * @note Хеш закрывает поданное ему, и закрыть саму переписку значило бы прекратить
	 *       её на первом же промежуточном хеше - а их за рукопожатие берётся пять
	 */
	digest::streebog_t hash = this->_hash;
	// Если хеш переписки рукопожатия выработать не удалось
	if(!hash.finish(result, static_cast <size_t> (digest::type_t::SHORT)))
		// Выводим отказ хеширования переписки рукопожатия
		return error_t::DIGEST;
	// Выводим успешность получения хеша переписки
	return error_t::NONE;
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
error_t nts::session::Transcript::digest(const view_t & suffix, uint8_t * result) const noexcept {
	// Если место для хеша переписки не передано
	if(result == nullptr)
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	// Если довесок переписки не передан
	if((suffix.data == nullptr) || (suffix.size == 0))
		// Выводим итог получения хеша переписки без довеска
		return this->digest(result);
	/**
	 * Снимаем состояние хеширования переписки рукопожатия: довесок ложится на снятое
	 * состояние, а сама переписка остаётся нетронутой
	 */
	digest::streebog_t hash = this->_hash;
	// Выполняем подачу довеска снятому состоянию хеширования
	hash.update(suffix);
	// Если хеш переписки с довеском выработать не удалось
	if(!hash.finish(result, static_cast <size_t> (digest::type_t::SHORT)))
		// Выводим отказ хеширования переписки рукопожатия
		return error_t::DIGEST;
	// Выводим успешность получения хеша переписки с довеском
	return error_t::NONE;
}
/**
 * @brief Метод замены накопленной переписки её хешем
 *
 * @return отказ замены накопленной переписки
 *
 */
error_t nts::session::Transcript::replace() noexcept {
	// Хеш накопленной переписки рукопожатия
	uint8_t digest[schedule::SCHEDULE_SECRET];
	// Выполняем получение хеша накопленной переписки рукопожатия
	const error_t error = this->digest(digest);
	// Если хеш накопленной переписки получить не удалось
	if(error != error_t::NONE)
		// Выводим отказ замены накопленной переписки
		return error;
	// Обвязка сообщения, несущего хеш приветствия клиента
	uint8_t header[4];
	// Записываем вид сообщения, несущего хеш приветствия клиента
	header[0] = DIGEST;
	// Записываем старший байт длины тела сообщения
	header[1] = 0x00;
	// Записываем средний байт длины тела сообщения
	header[2] = 0x00;
	// Записываем младший байт длины тела сообщения
	header[3] = static_cast <uint8_t> (sizeof(digest));
	// Выполняем начало переписки рукопожатия заново
	this->start();
	// Добавляем в переписку обвязку сообщения с хешем приветствия
	this->_hash.update(view_t(header, sizeof(header)));
	// Добавляем в переписку хеш приветствия клиента
	this->_hash.update(view_t(digest, sizeof(digest)));
	// Выполняем затирание хеша накопленной переписки
	wipe(digest, sizeof(digest));
	// Выводим успешность замены накопленной переписки
	return error_t::NONE;
}
/**
 * @brief Конструктор
 *
 */
nts::session::Transcript::Transcript() noexcept : _hash(digest::type_t::SHORT) {}
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
	// Выполняем затирание значения расписания ключей текущей ступени
	wipe(this->_secret, sizeof(this->_secret));
	// Выполняем затирание значения направления связи от клиента
	wipe(this->_client, sizeof(this->_client));
	// Выполняем затирание значения направления связи от сервера
	wipe(this->_server, sizeof(this->_server));
	// Выполняем затирание значения возобновления связи
	wipe(this->_resumption, sizeof(this->_resumption));
	// Выполняем затирание значения упреждающих данных связи
	wipe(this->_early, sizeof(this->_early));
	// Выполняем сброс пройденной ступени расписания ключей
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
error_t nts::session::Secrets::start(const view_t & secret) noexcept {
	// Выполняем сброс прежних значений расписания ключей
	this->clear();
	// Нули, идущие на место отсутствующего ключевого материала
	uint8_t zeroes[schedule::SCHEDULE_SECRET];
	// Выполняем обнуление отсутствующего ключевого материала
	::memset(zeroes, 0, sizeof(zeroes));
	// Получаем заранее разделённый ключ связи либо нули на его место
	const view_t material = (((secret.data != nullptr) && (secret.size > 0)) ? secret : view_t(zeroes, sizeof(zeroes)));
	// Если начальное значение расписания ключей извлечь не удалось
	if(!schedule::extract(view_t(zeroes, sizeof(zeroes)), material, this->_secret)){
		// Выполняем сброс значений расписания ключей
		this->clear();
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	}
	// Запоминаем пройденную ступень расписания ключей
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
error_t nts::session::Secrets::handshake(const view_t & shared, const view_t & transcript) noexcept {
	// Если начальная ступень расписания ключей ещё не пройдена
	if(this->_stage != stage_t::EARLY)
		// Выводим отказ нарушения порядка вывода значений
		return error_t::STATE;
	// Если общее значение обмена либо хеш переписки не переданы
	if((shared.data == nullptr) || (shared.size == 0) || (transcript.data == nullptr) || (transcript.size == 0))
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	// Значение перехода к ступени рукопожатия
	uint8_t derived[schedule::SCHEDULE_SECRET];
	// Если значение перехода к ступени рукопожатия вывести не удалось
	if(!stepping(this->_secret, derived)){
		// Выполняем затирание значения перехода к ступени
		wipe(derived, sizeof(derived));
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	}
	// Если значение ступени рукопожатия извлечь не удалось
	if(!schedule::extract(view_t(derived, sizeof(derived)), shared, this->_secret)){
		// Выполняем затирание значения перехода к ступени
		wipe(derived, sizeof(derived));
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	}
	// Выполняем затирание значения перехода к ступени
	wipe(derived, sizeof(derived));
	// Если значение направления связи от клиента вывести не удалось
	if(!schedule::secret(view_t(this->_secret, sizeof(this->_secret)), ::label(CLIENT_HANDSHAKE), transcript, this->_client))
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	// Если значение направления связи от сервера вывести не удалось
	if(!schedule::secret(view_t(this->_secret, sizeof(this->_secret)), ::label(SERVER_HANDSHAKE), transcript, this->_server))
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	// Запоминаем пройденную ступень расписания ключей
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
error_t nts::session::Secrets::application(const view_t & transcript) noexcept {
	// Если ступень рукопожатия расписания ключей ещё не пройдена
	if(this->_stage != stage_t::HANDSHAKE)
		// Выводим отказ нарушения порядка вывода значений
		return error_t::STATE;
	// Если хеш переписки рукопожатия не передан
	if((transcript.data == nullptr) || (transcript.size == 0))
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	// Значение перехода к ступени прикладных данных
	uint8_t derived[schedule::SCHEDULE_SECRET];
	// Если значение перехода к ступени вывести не удалось
	if(!stepping(this->_secret, derived)){
		// Выполняем затирание значения перехода к ступени
		wipe(derived, sizeof(derived));
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	}
	// Нули, идущие на место ключевого материала этой ступени
	uint8_t zeroes[schedule::SCHEDULE_SECRET];
	// Выполняем обнуление ключевого материала этой ступени
	::memset(zeroes, 0, sizeof(zeroes));
	// Если значение ступени прикладных данных извлечь не удалось
	if(!schedule::extract(view_t(derived, sizeof(derived)), view_t(zeroes, sizeof(zeroes)), this->_secret)){
		// Выполняем затирание значения перехода к ступени
		wipe(derived, sizeof(derived));
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	}
	// Выполняем затирание значения перехода к ступени
	wipe(derived, sizeof(derived));
	// Если значение направления связи от клиента вывести не удалось
	if(!schedule::secret(view_t(this->_secret, sizeof(this->_secret)), ::label(CLIENT_APPLICATION), transcript, this->_client))
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	// Если значение направления связи от сервера вывести не удалось
	if(!schedule::secret(view_t(this->_secret, sizeof(this->_secret)), ::label(SERVER_APPLICATION), transcript, this->_server))
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	// Запоминаем пройденную ступень расписания ключей
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
error_t nts::session::Secrets::traffic(const side_t side, uint8_t * result) const noexcept {
	// Если значения направлений связи ещё не выведены
	if((this->_stage != stage_t::HANDSHAKE) && (this->_stage != stage_t::APPLICATION))
		// Выводим отказ нарушения порядка вывода значений
		return error_t::STATE;
	// Если место для значения направления связи не передано
	if(result == nullptr)
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	// Записываем значение запрашиваемого направления связи
	::memcpy(result, ((side == side_t::CLIENT) ? this->_client : this->_server), schedule::SCHEDULE_SECRET);
	// Выводим успешность получения значения направления связи
	return error_t::NONE;
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
error_t nts::session::material(const view_t & traffic, const protect::suite_t suite, uint8_t * key, uint8_t * vector) noexcept {
	// Если значение направления связи не передано
	if((traffic.data == nullptr) || (traffic.size != schedule::SCHEDULE_SECRET))
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	// Получаем длину вектора замены набора шифрования
	const size_t size = protect::block(suite);
	// Если набор шифрования протоколом не определён
	if(size == 0)
		// Выводим отказ неизвестности набора шифрования
		return error_t::SUITE;
	// Если место для ключевого материала не передано
	if((key == nullptr) || (vector == nullptr))
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	// Признак успешности вывода ключевого материала направления
	bool ok = schedule::derive(traffic, ::label("key"), view_t(nullptr, 0), key, protect::PROTECT_KEY);
	// Если корневой ключ направления связи выведен
	if(ok)
		// Выполняем вывод вектора замены направления связи
		ok = schedule::derive(traffic, ::label("iv"), view_t(nullptr, 0), vector, size);
	// Выводим отказ вывода ключевого материала направления связи
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
error_t nts::session::Secrets::material(const side_t side, const protect::suite_t suite, uint8_t * key, uint8_t * vector) const noexcept {
	// Значение запрашиваемого направления связи
	uint8_t traffic[schedule::SCHEDULE_SECRET];
	// Выполняем получение значения запрашиваемого направления связи
	const error_t error = this->traffic(side, traffic);
	// Если значение направления связи получить не удалось
	if(error != error_t::NONE)
		// Выводим отказ вывода ключевого материала направления
		return error;
	// Выполняем вывод ключевого материала из значения направления связи
	const error_t outcome = nts::session::material(view_t(traffic, sizeof(traffic)), suite, key, vector);
	// Выполняем затирание значения направления связи
	wipe(traffic, sizeof(traffic));
	// Выводим отказ вывода ключевого материала направления связи
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
error_t nts::session::Secrets::early(const view_t & transcript) noexcept {
	// Если начальная ступень расписания ключей ещё не заведена
	if(this->_stage != stage_t::EARLY)
		// Выводим отказ нарушения порядка вывода значений
		return error_t::STATE;
	// Если хеш переписки рукопожатия не передан
	if((transcript.data == nullptr) || (transcript.size == 0))
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	// Если значение упреждающих данных вывести не удалось
	if(!schedule::secret(view_t(this->_secret, sizeof(this->_secret)), ::label(EARLY), transcript, this->_early))
		// Выводим отказ вывода значения расписания ключей
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
error_t nts::session::Secrets::early(uint8_t * result) const noexcept {
	// Если место для значения упреждающих данных не передано
	if(result == nullptr)
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	// Записываем значение упреждающих данных связи
	::memcpy(result, this->_early, schedule::SCHEDULE_SECRET);
	// Выводим успешность получения значения упреждающих данных
	return error_t::NONE;
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
error_t nts::session::Secrets::finished(const side_t side, uint8_t * result) const noexcept {
	// Значение запрашиваемого направления связи
	uint8_t traffic[schedule::SCHEDULE_SECRET];
	// Выполняем получение значения запрашиваемого направления связи
	const error_t error = this->traffic(side, traffic);
	// Если значение направления связи получить не удалось
	if(error != error_t::NONE)
		// Выводим отказ вывода ключа завершения рукопожатия
		return error;
	// Если место для ключа завершения рукопожатия не передано
	if(result == nullptr){
		// Выполняем затирание значения направления связи
		wipe(traffic, sizeof(traffic));
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	}
	// Выполняем вывод ключа завершения рукопожатия
	const bool ok = schedule::derive(view_t(traffic, sizeof(traffic)), ::label("finished"), view_t(nullptr, 0), result, schedule::SCHEDULE_SECRET);
	// Выполняем затирание значения направления связи
	wipe(traffic, sizeof(traffic));
	// Выводим отказ вывода ключа завершения рукопожатия
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
error_t nts::session::Secrets::resumption(const view_t & transcript) noexcept {
	// Если ступень прикладных данных расписания ключей ещё не пройдена
	if(this->_stage != stage_t::APPLICATION)
		// Выводим отказ нарушения порядка вывода значений
		return error_t::STATE;
	// Если хеш переписки рукопожатия не передан
	if((transcript.data == nullptr) || (transcript.size == 0))
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	// Если значение возобновления связи вывести не удалось
	if(!schedule::secret(view_t(this->_secret, sizeof(this->_secret)), ::label(RESUMPTION), transcript, this->_resumption))
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	// Выводим успешность вывода значения возобновления связи
	return error_t::NONE;
}
/**
 * @brief Метод вывода ключа билета возобновления связи
 *
 * @param nonce  неповторимое значение билета, назначенное сервером
 * @param result место, в которое помещается ключ билета
 *
 * @return       отказ вывода ключа билета возобновления связи
 *
 */
error_t nts::session::Secrets::ticket(const view_t & nonce, uint8_t * result) const noexcept {
	// Если ступень прикладных данных расписания ключей ещё не пройдена
	if(this->_stage != stage_t::APPLICATION)
		// Выводим отказ нарушения порядка вывода значений
		return error_t::STATE;
	// Если место для ключа билета не передано
	if(result == nullptr)
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	// Если ключ билета возобновления связи вывести не удалось
	if(!schedule::derive(view_t(this->_resumption, sizeof(this->_resumption)), ::label(TICKET), nonce, result, schedule::SCHEDULE_SECRET))
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	// Выводим успешность вывода ключа билета возобновления связи
	return error_t::NONE;
}
/**
 * @brief Метод выработки привязки заранее разделённого ключа
 *
 * @param transcript хеш усечённого приветствия клиента
 * @param result     место, в которое помещается привязка ключа
 *
 * @return           отказ выработки привязки заранее разделённого ключа
 *
 */
error_t nts::session::Secrets::binder(const view_t & transcript, uint8_t * result) const noexcept {
	// Если начальная ступень расписания ключей ещё не заведена
	if(this->_stage != stage_t::EARLY)
		// Выводим отказ нарушения порядка вывода значений
		return error_t::STATE;
	// Если хеш усечённого приветствия либо место итога не переданы
	if((transcript.data == nullptr) || (transcript.size == 0) || (result == nullptr))
		// Выводим отказ отсутствия обязательного довода
		return error_t::EMPTY;
	// Хеш пустой переписки, идущий выводу ключа привязки
	uint8_t empty[schedule::SCHEDULE_SECRET];
	// Если хеш пустой переписки выработать не удалось
	if(!digest::streebog(digest::type_t::SHORT, view_t(nullptr, 0), empty, sizeof(empty)))
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	// Значение привязки заранее разделённого ключа
	uint8_t secret[schedule::SCHEDULE_SECRET];
	// Если значение привязки ключа вывести не удалось
	if(!schedule::secret(view_t(this->_secret, sizeof(this->_secret)), ::label(BINDER), view_t(empty, sizeof(empty)), secret)){
		// Выполняем затирание значения привязки ключа
		wipe(secret, sizeof(secret));
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	}
	// Ключ выработки привязки заранее разделённого ключа
	uint8_t key[schedule::SCHEDULE_SECRET];
	// Если ключ выработки привязки вывести не удалось
	if(!schedule::derive(view_t(secret, sizeof(secret)), ::label("finished"), view_t(nullptr, 0), key, sizeof(key))){
		// Выполняем затирание ключа выработки привязки
		wipe(key, sizeof(key));
		// Выполняем затирание значения привязки ключа
		wipe(secret, sizeof(secret));
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	}
	// Признак успешности выработки привязки заранее разделённого ключа
	const bool ok = digest::hmac(digest::type_t::SHORT, view_t(key, sizeof(key)), transcript, result, schedule::SCHEDULE_SECRET);
	// Выполняем затирание ключа выработки привязки
	wipe(key, sizeof(key));
	// Выполняем затирание значения привязки ключа
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
error_t nts::session::Secrets::renew(const side_t side) noexcept {
	// Если ступень прикладных данных расписания ключей ещё не пройдена
	if(this->_stage != stage_t::APPLICATION)
		// Выводим отказ нарушения порядка вывода значений
		return error_t::STATE;
	// Получаем значение сменяемого направления связи
	uint8_t * traffic = ((side == side_t::CLIENT) ? this->_client : this->_server);
	// Новое значение направления связи
	uint8_t result[schedule::SCHEDULE_SECRET];
	// Если новое значение направления связи вывести не удалось
	if(!schedule::derive(view_t(traffic, schedule::SCHEDULE_SECRET), ::label(UPDATE), view_t(nullptr, 0), result, sizeof(result))){
		// Выполняем затирание нового значения направления связи
		wipe(result, sizeof(result));
		// Выводим отказ вывода значения расписания ключей
		return error_t::SCHEDULE;
	}
	// Записываем новое значение направления связи
	::memcpy(traffic, result, sizeof(result));
	// Выполняем затирание нового значения направления связи
	wipe(result, sizeof(result));
	// Выводим успешность смены значения направления связи
	return error_t::NONE;
}
/**
 * @brief Конструктор
 *
 */
nts::session::Secrets::Secrets() noexcept : _stage(stage_t::NONE) {
	// Выполняем обнуление значения расписания ключей текущей ступени
	::memset(this->_secret, 0, sizeof(this->_secret));
	// Выполняем обнуление значения направления связи от клиента
	::memset(this->_client, 0, sizeof(this->_client));
	// Выполняем обнуление значения направления связи от сервера
	::memset(this->_server, 0, sizeof(this->_server));
	// Выполняем обнуление значения возобновления связи
	::memset(this->_resumption, 0, sizeof(this->_resumption));
	// Выполняем обнуление значения упреждающих данных связи
	::memset(this->_early, 0, sizeof(this->_early));
}
/**
 * @brief Деструктор
 *
 */
nts::session::Secrets::~Secrets() noexcept {
	// Выполняем сброс значений расписания ключей
	this->clear();
}
