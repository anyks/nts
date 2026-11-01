/**
 * @file handshake.cpp
 * @date 2026-09-07
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
 * @brief Модуль состояния рукопожатия Noise (HandshakeState) и PQNoise
 *
 * @details Машина ведёт узор по таблице знаков: сообщение с чётным номером пишет инициатор,
 *          с нечётным - отвечающий. Заранее разделённые ключи вставляются по видоизменению:
 *          psk0 - в начало первого сообщения, pskN - в конец сообщения N-1. DH по знаку зависит
 *          от роли (§7.1): es у инициатора это DH(e, rs), у отвечающего - DH(s, re).
 *          У PQNoise (Angel и др., CCS 2022, Algorithm 1) знаки ekem и skem - разные операции у
 *          сторон: отправитель упаковывает к временному либо постоянному ключу получателя,
 *          получатель распаковывает своим закрытым; шифртекст ekem идёт в открытом виде и
 *          примешивается в хеш, шифртекст skem - через EncryptAndHash; затем MixKey секрета
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
#include <noise/handshake.hpp>
#include <sys/wipe.hpp>

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Подписываемся на метод затирания памяти
	 */
	using nts::sys::wipe;
	/**
	 * @brief Функция сличения двух ключей за постоянное время
	 *
	 * @param one   первый ключ
	 * @param two   второй ключ
	 * @param size  длина ключей
	 * @return      признак совпадения
	 *
	 */
	static bool alike(const uint8_t * one, const uint8_t * two, const size_t size) noexcept {
		// Накопитель различий
		uint8_t diff = 0;
		/**
		 * Выполняем перебор байтов
		 */
		for(size_t i = 0; i < size; i++)
			// Накапливаем различие
			diff |= (one[i] ^ two[i]);
		// Выводим итог
		return (diff == 0);
	}
};

/**
 * @brief Метод поглощения предсообщений и проверки полноты ключей
 *
 * @return признак готовности к первому сообщению
 *
 */
bool nts::noise::Handshake::ready() noexcept {
	// Если предсообщения уже поглощены
	if(this->_started)
		// Выводим готовность
		return true;
	// Признак роли инициатора
	const bool initiator = (this->_role == role_t::INITIATOR);
	// Число положений заранее разделённых ключей
	size_t positions = 0;
	/**
	 * Выполняем счёт положений
	 */
	for(size_t i = 0; i < PSKS_MAX; i++)
		// Считаем положение
		positions += ((this->_psks >> i) & 1);
	// Если ключей задано не по числу положений
	if(positions != this->_pskCount)
		// Выводим отрицательный результат - ключи не по числу положений
		return false;
	// Знаки и их число
	const token_t * list = nullptr;
	// Число знаков
	size_t count = 0;
	/**
	 * Выполняем проверку, что свой постоянный ключ есть, если узор велит его слать либо принимать skem
	 */
	for(size_t i = 0; i < this->_count; i++){
		// Признак нашего сообщения
		const bool ours = (((i % 2) == 0) == initiator);
		// Получаем знаки
		if(!tokens(this->_pattern, i, list, count))
			// Выводим отрицательный результат - знаки не получены
			return false;
		/**
		 * Выполняем перебор знаков
		 */
		for(size_t j = 0; j < count; j++){
			// Признак того, что знак требует своего постоянного ключа
			bool needed = false;
			// Если сообщение наше
			if(ours)
				// Свой постоянный ключ шлётся, участвует в DH либо не нужен
				needed = ((list[j] == token_t::S) || (list[j] == token_t::SS) || (initiator ? (list[j] == token_t::SE) : (list[j] == token_t::ES)));
			// Иначе чужой skem распаковывается нашим постоянным ключом
			else needed = (list[j] == token_t::SKEM);
			// Если ключ нужен, а его нет
			if(needed && !this->_hasS)
				// Выводим отрицательный результат - нужный ключ не задан
				return false;
		}
	}
	/**
	 * Выполняем проверку предсообщений обеих сторон до всякого хеширования: отказ
	 * на второй стороне после примешивания первой оставил бы h изменённым, и повтор
	 * после дозаведения ключей разошёлся бы с h собеседника
	 */
	for(uint8_t side = 0; side < 2; side++){
		// Признак предсообщения инициатора
		const bool first = (side == 0);
		// Получаем знаки предсообщения
		if(!premessage(this->_pattern, first, list, count))
			// Выводим отрицательный результат - знаки предсообщения не получены
			return false;
		/**
		 * Выполняем перебор знаков
		 */
		for(size_t j = 0; j < count; j++){
			// Если знак не постоянный ключ
			if(list[j] != token_t::S)
				// Выводим отрицательный результат - знак предсообщения не ключ
				return false;
			// Если нужного ключа нет
			if((first == initiator) ? !this->_hasS : !this->_hasRS)
				// Выводим отрицательный результат - ключ предсообщения не задан
				return false;
		}
	}
	/**
	 * Выполняем поглощение предсообщений: сперва инициатора, затем отвечающего
	 */
	for(uint8_t side = 0; side < 2; side++){
		// Признак предсообщения инициатора
		const bool first = (side == 0);
		// Получаем знаки предсообщения
		if(!premessage(this->_pattern, first, list, count))
			// Выводим отрицательный результат - знаки второго предсообщения не получены
			return false;
		/**
		 * Выполняем перебор знаков
		 */
		for(size_t j = 0; j < count; j++){
			// Признак того, что ключ наш
			const bool own = (first == initiator);
			// Примешиваем открытый ключ
			if(!this->_symmetric.hash(view_t(own ? this->_sPublic : this->_rs, this->_public)))
				// Выводим отрицательный результат - открытый ключ не примешан
				return false;
		}
	}
	// Устанавливаем признак поглощённых предсообщений
	this->_started = true;
	// Выводим готовность
	return true;
}
/**
 * @brief Метод примешивания DH по знаку с учётом роли
 *
 * @param token знак: EE, ES, SE либо SS
 * @return      признак того, что секрет примешан
 *
 */
bool nts::noise::Handshake::mix(const token_t token) noexcept {
	// У PQNoise знаков DH нет
	if(this->_suite.dh == dh_t::NONE)
		// Выводим отрицательный результат - обмен DH не применим к PQNoise
		return false;
	// Признак роли инициатора
	const bool initiator = (this->_role == role_t::INITIATOR);
	// Свой закрытый ключ и чужой открытый
	const uint8_t * secret = nullptr;
	// Чужой открытый ключ
	const uint8_t * point = nullptr;
	// Признаки наличия
	bool own = false, peer = false;
	/**
	 * Определяем знак
	 */
	switch(token){
		// DH временных ключей
		case token_t::EE: { secret = this->_e; own = this->_hasE; point = this->_re; peer = this->_hasRE; } break;
		// DH временного ключа инициатора и постоянного отвечающего
		case token_t::ES: {
			// Выбираем ключи по роли
			if(initiator){ secret = this->_e; own = this->_hasE; point = this->_rs; peer = this->_hasRS; }
			else { secret = this->_s; own = this->_hasS; point = this->_re; peer = this->_hasRE; }
		} break;
		// DH постоянного ключа инициатора и временного отвечающего
		case token_t::SE: {
			// Выбираем ключи по роли
			if(initiator){ secret = this->_s; own = this->_hasS; point = this->_re; peer = this->_hasRE; }
			else { secret = this->_e; own = this->_hasE; point = this->_rs; peer = this->_hasRS; }
		} break;
		// DH постоянных ключей
		case token_t::SS: { secret = this->_s; own = this->_hasS; point = this->_rs; peer = this->_hasRS; } break;
		// Прочее
		default: return false;
	}
	// Если ключей нет
	if(!own || !peer)
		// Выводим отрицательный результат - ключ не задан
		return false;
	// Общий секрет
	uint8_t shared[KEY];
	// Вычисляем DH и примешиваем секрет
	const bool status = (agree(this->_suite.dh, view_t(secret, KEY), view_t(point, KEY), shared) && this->_symmetric.key(view_t(shared, KEY)));
	// Затираем секрет
	wipe(shared, KEY);
	// Возвращаем итог примешивания
	return status;
}
/**
 * @brief Метод упаковки по знаку KEM у отправителя
 *
 * @param token      знак: EKEM либо SKEM
 * @param ciphertext место шифртекста
 * @param shared     место общего секрета
 * @return           признак того, что секрет упакован
 *
 */
bool nts::noise::Handshake::wrap(const token_t token, uint8_t * ciphertext, uint8_t * shared) noexcept {
	// У классики знаков KEM нет
	if(this->_suite.kem == kem_t::NONE)
		// Выводим отрицательный результат - обмен KEM не применим к классике
		return false;
	// Открытый ключ получателя: временный у ekem, постоянный у skem
	const uint8_t * key = ((token == token_t::EKEM) ? this->_re : this->_rs);
	// Признак его наличия
	const bool known = ((token == token_t::EKEM) ? this->_hasRE : this->_hasRS);
	// Если знак чужой либо ключа нет
	if(((token != token_t::EKEM) && (token != token_t::SKEM)) || !known)
		// Выводим отрицательный результат - капсула не выработана
		return false;
	// Если случайности заданы явно (корпус), упаковываем на очередной; исчерпаны - отказ, а не переход на энтропию
	if(this->_coinCount > 0){
		// Если случайности исчерпаны
		if(this->_coinUsed >= this->_coinCount)
			// Выводим отрицательный результат - случайность не задана
			return false;
		// Выводим итог детерминированной упаковки
		return encapsulateDeterministic(this->_suite.kem, view_t(key, this->_public), view_t(this->_coin[this->_coinUsed++], kemlength(this->_suite.kem, part_t::COINS)), ciphertext, shared);
	}
	// Иначе упаковываем на энтропии
	return encapsulate(this->_suite.kem, view_t(key, this->_public), ciphertext, shared);
}
/**
 * @brief Метод распаковки по знаку KEM у получателя
 *
 * @param token      знак: EKEM либо SKEM
 * @param ciphertext шифртекст
 * @param shared     место общего секрета
 * @return           признак того, что секрет распакован
 *
 */
bool nts::noise::Handshake::unwrap(const token_t token, const uint8_t * ciphertext, uint8_t * shared) noexcept {
	// У классики знаков KEM нет
	if(this->_suite.kem == kem_t::NONE)
		// Выводим отрицательный результат - обмен KEM не применим к классике
		return false;
	// Свой закрытый ключ: временный у ekem, постоянный у skem
	const uint8_t * secret = ((token == token_t::EKEM) ? this->_e : this->_s);
	// Признак его наличия
	const bool own = ((token == token_t::EKEM) ? this->_hasE : this->_hasS);
	// Если знак чужой либо ключа нет
	if(((token != token_t::EKEM) && (token != token_t::SKEM)) || !own)
		// Выводим отрицательный результат - секрет не извлечён
		return false;
	// Выводим итог распаковки
	return decapsulate(this->_suite.kem, view_t(secret, this->_secret), view_t(ciphertext, kemlength(this->_suite.kem, part_t::CIPHERTEXT)), shared);
}
/**
 * @brief Метод проверки, что в узоре есть заранее разделённые ключи
 *
 * @return признак наличия
 *
 */
bool nts::noise::Handshake::preshared() const noexcept {
	// Выводим признак
	return (this->_psks != 0);
}
/**
 * @brief Метод примешивания очередного заранее разделённого ключа
 *
 * @return признак того, что ключ примешан
 *
 */
bool nts::noise::Handshake::psk() noexcept {
	// Если ключи исчерпаны
	if(this->_pskUsed >= this->_pskCount)
		// Выводим отрицательный результат - предразделённые ключи исчерпаны
		return false;
	// Примешиваем ключ и сдвигаем счёт
	return this->_symmetric.blend(view_t(this->_psk[this->_pskUsed++], PSK));
}
/**
 * @brief Метод заведения рукопожатия перечислениями
 *
 * @param pattern  узор рукопожатия
 * @param psks     положения заранее разделённых ключей
 * @param suite    набор примитивов
 * @param role     роль стороны
 * @param prologue пролог, вправе быть пустым
 * @return         признак того, что рукопожатие заведено
 *
 */
bool nts::noise::Handshake::start(const pattern_t pattern, const psk_t psks, const suite_t & suite, const role_t role, const view_t & prologue) noexcept {
	// Затираем прежнее состояние
	this->clear();
	// Число сообщений узора
	const size_t count = messages(pattern);
	// Если узор, роль, набор либо пролог негодны
	if((count == 0) || ((role != role_t::INITIATOR) && (role != role_t::RESPONDER)) || !valid(suite) || ((prologue.size > 0) && (prologue.data == nullptr)))
		// Выводим отрицательный результат - параметры рукопожатия негодны
		return false;
	// Положения заранее разделённых ключей не дальше числа сообщений: pskN при N <= count
	if((psks >> PSKS_MAX) != 0 || (psks >> (count + 1)) != 0)
		// Выводим отрицательный результат - положения видоизменений не по числу сообщений
		return false;
	// Имя протокола и его длина: name сам отвергает узор и набор разных семейств и psk у PQNoise
	char text[NAME_LIMIT];
	// Длина имени
	size_t length = NAME_LIMIT;
	// Составляем имя
	if(!name(pattern, psks, suite, text, length))
		// Выводим отрицательный результат - имя протокола не составлено
		return false;
	// Заводим симметричное состояние и примешиваем пролог
	if(!this->_symmetric.start(view_t(reinterpret_cast <const uint8_t *> (text), length), suite) || !this->_symmetric.hash(prologue)){
		// Затираем состояние
		this->clear();
		// Выводим отрицательный результат - заведение прервано
		return false;
	}
	// Запоминаем устройство рукопожатия
	this->_pattern = pattern;
	// Запоминаем положения ключей
	this->_psks = psks;
	// Запоминаем набор
	this->_suite = suite;
	// Запоминаем роль
	this->_role = role;
	// Запоминаем число сообщений
	this->_count = count;
	// Длины ключей по набору: KEY у классики, по KEM у PQNoise
	if(suite.kem == kem_t::NONE){
		// Длина открытого ключа
		this->_public = KEY;
		// Длина закрытого ключа
		this->_secret = KEY;
		// Длина зерна
		this->_seed = KEY;
	} else {
		// Длина открытого ключа
		this->_public = kemlength(suite.kem, part_t::PUBLIC);
		// Длина закрытого ключа
		this->_secret = kemlength(suite.kem, part_t::SECRET);
		// Длина зерна
		this->_seed = kemlength(suite.kem, part_t::SEED);
	}
	// Сообщаем длину зерна
	return true;
}
/**
 * @brief Метод заведения рукопожатия именем протокола
 *
 * @param name     имя протокола вида «Noise_XX_25519_ChaChaPoly_SHA256»
 * @param role     роль стороны
 * @param prologue пролог, вправе быть пустым
 * @return         признак того, что рукопожатие заведено
 *
 */
bool nts::noise::Handshake::start(const view_t & name, const role_t role, const view_t & prologue) noexcept {
	// Разобранные узор, положения и набор
	pattern_t pattern = pattern_t::NONE;
	// Положения заранее разделённых ключей
	psk_t psks = 0;
	// Набор шифров
	suite_t suite;
	// Если имя не разобрано
	if(!parse(name, pattern, psks, suite)){
		// Затираем состояние
		this->clear();
		// Выводим отрицательный результат - имя не разобрано
		return false;
	}
	// Заводим рукопожатие перечислениями
	return this->start(pattern, psks, suite, role, prologue);
}
/**
 * @brief Метод установки своего постоянного ключа
 *
 * @param secret закрытый ключ в KEY байтов у классики либо зерно KEM у PQNoise (детерминированно), открытый выводится
 * @return       признак того, что ключ установлен
 *
 */
bool nts::noise::Handshake::statics(const view_t & secret) noexcept {
	// Если рукопожатие не заведено, уже идёт либо ключ негоден
	if((this->_count == 0) || this->_started || (secret.data == nullptr) || (secret.size != this->_seed))
		// Выводим отрицательный результат - постоянный ключ не принят
		return false;
	// Если набор PQNoise, пара порождается из зерна
	if(this->_suite.kem != kem_t::NONE){
		// Если пара не порождена
		if(!kemgenerateDeterministic(this->_suite.kem, secret, this->_sPublic, this->_s))
			// Выводим отрицательный результат - пара ключей не порождена
			return false;
	// Иначе открытый ключ выводится из закрытого
	} else {
		// Если открытый ключ не выведен
		if(!derive(this->_suite.dh, secret, this->_sPublic))
			// Выводим отрицательный результат - открытый ключ не выведен
			return false;
		// Запоминаем закрытый ключ
		::memcpy(this->_s, secret.data, KEY);
	}
	// Устанавливаем признак
	this->_hasS = true;
	// Сообщаем об успешной установке постоянного ключа
	return true;
}
/**
 * @brief Метод явной установки своего временного ключа
 *
 * @param secret закрытый ключ в KEY байтов у классики либо зерно KEM у PQNoise, открытый выводится
 * @return       признак того, что ключ установлен
 *
 */
bool nts::noise::Handshake::ephemeral(const view_t & secret) noexcept {
	// Если рукопожатие не заведено, уже идёт либо ключ негоден
	if((this->_count == 0) || this->_started || (secret.data == nullptr) || (secret.size != this->_seed))
		// Выводим отрицательный результат - временный ключ не принят
		return false;
	// Если набор PQNoise, пара порождается из зерна
	if(this->_suite.kem != kem_t::NONE){
		// Если пара не порождена
		if(!kemgenerateDeterministic(this->_suite.kem, secret, this->_ePublic, this->_e))
			// Выводим отрицательный результат - пара ключей не порождена
			return false;
	// Иначе открытый ключ выводится из закрытого
	} else {
		// Если открытый ключ не выведен
		if(!derive(this->_suite.dh, secret, this->_ePublic))
			// Выводим отрицательный результат - открытый ключ не выведен
			return false;
		// Запоминаем закрытый ключ
		::memcpy(this->_e, secret.data, KEY);
	}
	// Устанавливаем признак
	this->_hasE = true;
	// Сообщаем об успешной установке временного ключа
	return true;
}
/**
 * @brief Метод установки постоянного открытого ключа собеседника
 *
 * @param key открытый ключ в KEY байтов у классики либо длиной открытого ключа KEM у PQNoise
 * @return    признак того, что ключ установлен
 *
 */
bool nts::noise::Handshake::remote(const view_t & key) noexcept {
	// Если рукопожатие не заведено, уже идёт либо ключ негоден
	if((this->_count == 0) || this->_started || (key.data == nullptr) || (key.size != this->_public))
		// Выводим отрицательный результат - чужой ключ не принят
		return false;
	// Запоминаем ключ
	::memcpy(this->_rs, key.data, this->_public);
	// Устанавливаем признак
	this->_hasRS = true;
	// Сообщаем об успешной установке чужого ключа
	return true;
}
/**
 * @brief Метод установки заранее разделённых ключей в порядке появления в узоре
 *
 * @param keys  ключи, каждый ровно PSK байтов
 * @param count число ключей, не больше PSKS_MAX
 * @return      признак того, что ключи установлены
 *
 */
bool nts::noise::Handshake::psks(const view_t * keys, const size_t count) noexcept {
	// Если рукопожатие не заведено, уже идёт, набор PQNoise (psk там не заведён) либо ключи негодны
	if((this->_count == 0) || this->_started || (this->_suite.kem != kem_t::NONE) || (count == 0) || (count > PSKS_MAX) || (keys == nullptr))
		// Выводим отрицательный результат - предразделённые ключи не приняты
		return false;
	/**
	 * Выполняем проверку каждого ключа
	 */
	for(size_t i = 0; i < count; i++){
		// Если ключ негоден
		if((keys[i].data == nullptr) || (keys[i].size != PSK))
			// Выводим отрицательный результат - ключ негоден
			return false;
	}
	// Затираем прежние ключи
	wipe(this->_psk, sizeof(this->_psk));
	/**
	 * Выполняем запись ключей
	 */
	for(size_t i = 0; i < count; i++)
		// Записываем ключ
		::memcpy(this->_psk[i], keys[i].data, PSK);
	// Запоминаем число ключей
	this->_pskCount = count;
	// Сбрасываем число использованных ключей
	this->_pskUsed = 0;
	// Сообщаем об успешной установке предразделённых ключей
	return true;
}
/**
 * @brief Метод явной установки случайностей упаковки KEM по порядку своих знаков ekem/skem (PQNoise; только корпусам)
 *
 * @param coins случайности, каждая длиной COINS набора
 * @param count число случайностей, не больше PSKS_MAX
 * @return      признак того, что случайности установлены
 *
 */
bool nts::noise::Handshake::coinsDeterministic(const view_t * coins, const size_t count) noexcept {
	// Длина случайности набора
	const size_t length = kemlength(this->_suite.kem, part_t::COINS);
	// Если рукопожатие не заведено, не PQNoise, уже идёт либо случайности негодны
	if((this->_count == 0) || (length == 0) || this->_started || (count == 0) || (count > PSKS_MAX) || (coins == nullptr))
		// Выводим отрицательный результат - случайности не приняты
		return false;
	/**
	 * Выполняем проверку каждой случайности
	 */
	for(size_t i = 0; i < count; i++){
		// Если случайность негодна
		if((coins[i].data == nullptr) || (coins[i].size != length))
			// Выводим отрицательный результат - случайность негодна
			return false;
	}
	// Затираем прежние случайности
	wipe(this->_coin, sizeof(this->_coin));
	/**
	 * Выполняем запись случайностей
	 */
	for(size_t i = 0; i < count; i++)
		// Записываем случайность
		::memcpy(this->_coin[i], coins[i].data, length);
	// Запоминаем число случайностей
	this->_coinCount = count;
	// Сбрасываем число использованных случайностей
	this->_coinUsed = 0;
	// Сообщаем об успешной установке случайностей
	return true;
}
/**
 * @brief Метод получения хода
 *
 * @return ход рукопожатия
 *
 */
nts::noise::step_t nts::noise::Handshake::step() const noexcept {
	// Если рукопожатие не заведено либо неисправно
	if((this->_count == 0) || this->_broken)
		// Выводим отсутствие хода
		return step_t::NONE;
	// Если сообщения исчерпаны
	if(this->_index >= this->_count)
		// Выводим завершение
		return step_t::DONE;
	// Чётное сообщение пишет инициатор
	const bool ours = (((this->_index % 2) == 0) == (this->_role == role_t::INITIATOR));
	// Выводим ход
	return (ours ? step_t::WRITE : step_t::READ);
}
/**
 * @brief Метод записи сообщения (WriteMessage)
 *
 * @param payload полезная часть, вправе быть пустой
 * @param result  место сообщения
 * @param size    на входе вместимость места, на выходе длина сообщения
 * @return        признак того, что сообщение записано
 *
 */
bool nts::noise::Handshake::write(const view_t & payload, uint8_t * result, size_t & size) noexcept {
	// Вместимость места
	const size_t capacity = size;
	// Сбрасываем длину
	size = 0;
	// Если не наш ход, полезная часть либо место негодны, либо предсообщения не поглощены
	if((this->step() != step_t::WRITE) || ((payload.size > 0) && (payload.data == nullptr)) || ((capacity > 0) && (result == nullptr)) || !this->ready())
		// Выводим отрицательный результат - запись невозможна
		return false;
	// Знаки сообщения и их число
	const token_t * list = nullptr;
	// Число знаков
	size_t count = 0;
	// Получаем знаки
	if(!tokens(this->_pattern, this->_index, list, count))
		// Выводим отрицательный результат - знаки не получены
		return false;
	// Длина шифртекста KEM
	const size_t ciphertext = kemlength(this->_suite.kem, part_t::CIPHERTEXT);
	// Длина записанного
	size_t offset = 0;
	// Признак успешности
	bool status = true;
	// Если ключ psk0 стоит в начале первого сообщения
	if((this->_index == 0) && (this->_psks & 1))
		// Примешиваем ключ
		status = this->psk();
	/**
	 * Выполняем перебор знаков
	 */
	for(size_t i = 0; status && (i < count); i++){
		/**
		 * Определяем знак
		 */
		switch(list[i]){
			// Временный ключ
			case token_t::E: {
				// Если ключ не задан явно, вырабатываем его
				if(!this->_hasE){
					// Вырабатываем пару: KEM у PQNoise, DH у классики
					status = ((this->_suite.kem != kem_t::NONE) ? kemgenerate(this->_suite.kem, this->_ePublic, this->_e) : generate(this->_suite.dh, this->_e, this->_ePublic));
					// Устанавливаем признак
					this->_hasE = status;
				}
				// Если места мало
				if(status && ((capacity - offset) < this->_public))
					// Отмечаем нехватку места
					status = false;
				// Если всё готово
				if(status){
					// Записываем открытый ключ
					::memcpy(result + offset, this->_ePublic, this->_public);
					// Сдвигаем длину
					offset += this->_public;
					// Примешиваем ключ в хеш и, при psk, в ключ
					status = (this->_symmetric.hash(view_t(this->_ePublic, this->_public)) && (!this->preshared() || this->_symmetric.key(view_t(this->_ePublic, this->_public))));
				}
			} break;
			// Постоянный ключ
			case token_t::S: {
				// Вместимость остатка
				size_t room = (capacity - offset);
				// Шифруем открытый ключ в место
				status = (this->_hasS && this->_symmetric.seal(view_t(this->_sPublic, this->_public), result + offset, room));
				// Сдвигаем длину
				offset += room;
			} break;
			// Шифртекст к временному ключу получателя: в открытом виде, MixHash, MixKey
			case token_t::EKEM: {
				// Общий секрет
				uint8_t shared[KEM_SHARED_MAX];
				// Если места мало либо упаковка не удалась
				if(((capacity - offset) < ciphertext) || !this->wrap(list[i], result + offset, shared))
					// Отмечаем нехватку места либо неудачу упаковки
					status = false;
				// Иначе примешиваем шифртекст и секрет
				else {
					// Примешиваем шифртекст в хеш и секрет в ключ
					status = (this->_symmetric.hash(view_t(result + offset, ciphertext)) && this->_symmetric.key(view_t(shared, kemlength(this->_suite.kem, part_t::SHARED))));
					// Сдвигаем длину
					offset += ciphertext;
				}
				// Затираем секрет
				wipe(shared, sizeof(shared));
			} break;
			// Шифртекст к постоянному ключу получателя: EncryptAndHash, MixKey
			case token_t::SKEM: {
				// Шифртекст и общий секрет
				uint8_t plain[KEM_CIPHERTEXT_MAX], shared[KEM_SHARED_MAX];
				// Вместимость остатка
				size_t room = (capacity - offset);
				// Упаковываем, шифруем шифртекст в место и примешиваем секрет
				status = (this->wrap(list[i], plain, shared) && this->_symmetric.seal(view_t(plain, ciphertext), result + offset, room) && this->_symmetric.key(view_t(shared, kemlength(this->_suite.kem, part_t::SHARED))));
				// Сдвигаем длину
				offset += room;
				// Затираем шифртекст и секрет
				wipe(plain, sizeof(plain));
				wipe(shared, sizeof(shared));
			} break;
			// Заранее разделённый ключ - только видоизменением, в таблице его нет
			case token_t::PSK: status = false; break;
			// DH
			default: status = this->mix(list[i]); break;
		}
	}
	// Если ключ pskN стоит в конце сообщения N-1
	if(status && ((this->_psks >> (this->_index + 1)) & 1))
		// Примешиваем ключ
		status = this->psk();
	// Если знаки пройдены, шифруем полезную часть
	if(status){
		// Вместимость остатка
		size_t room = (capacity - offset);
		// Шифруем полезную часть
		status = this->_symmetric.seal(payload, result + offset, room);
		// Сдвигаем длину
		offset += room;
	}
	// Если сообщение длиннее предела
	if(status && (offset > MESSAGE))
		// Отмечаем превышение предела
		status = false;
	// Если что-то не удалось, состояние неисправно
	if(!status){
		// Устанавливаем признак неисправности
		this->_broken = true;
		// Выводим отрицательный результат - запись прервана
		return false;
	}
	// Сдвигаем номер сообщения
	this->_index++;
	// Выводим длину
	size = offset;
	// Сообщаем длину записанного сообщения
	return true;
}
/**
 * @brief Метод чтения сообщения (ReadMessage)
 *
 * @param message сообщение
 * @param result  место полезной части
 * @param size    на входе вместимость места, на выходе длина полезной части
 * @return        признак того, что сообщение подлинно и прочитано
 *
 */
bool nts::noise::Handshake::read(const view_t & message, uint8_t * result, size_t & size) noexcept {
	// Вместимость места
	const size_t capacity = size;
	// Сбрасываем длину
	size = 0;
	// Если не наш ход, сообщение либо место негодны, либо предсообщения не поглощены
	if((this->step() != step_t::READ) || ((message.size > 0) && (message.data == nullptr)) || (message.size > MESSAGE) || ((capacity > 0) && (result == nullptr)) || !this->ready())
		// Выводим отрицательный результат - чтение невозможно
		return false;
	// Знаки сообщения и их число
	const token_t * list = nullptr;
	// Число знаков
	size_t count = 0;
	// Получаем знаки
	if(!tokens(this->_pattern, this->_index, list, count))
		// Выводим отрицательный результат - знаки не получены
		return false;
	// Длина шифртекста KEM
	const size_t ciphertext = kemlength(this->_suite.kem, part_t::CIPHERTEXT);
	// Положение чтения
	size_t offset = 0;
	// Признак успешности
	bool status = true;
	// Если ключ psk0 стоит в начале первого сообщения
	if((this->_index == 0) && (this->_psks & 1))
		// Примешиваем ключ
		status = this->psk();
	/**
	 * Выполняем перебор знаков
	 */
	for(size_t i = 0; status && (i < count); i++){
		/**
		 * Определяем знак
		 */
		switch(list[i]){
			// Временный ключ
			case token_t::E: {
				// Если сообщение короче ключа
				if((message.size - offset) < this->_public)
					// Отмечаем сообщение короче ключа
					status = false;
				// Если ключ есть
				if(status){
					// Запоминаем чужой временный ключ
					::memcpy(this->_re, message.data + offset, this->_public);
					// Устанавливаем признак
					this->_hasRE = true;
					// Сдвигаем положение
					offset += this->_public;
					// Примешиваем ключ в хеш и, при psk, в ключ
					status = (this->_symmetric.hash(view_t(this->_re, this->_public)) && (!this->preshared() || this->_symmetric.key(view_t(this->_re, this->_public))));
				}
			} break;
			// Постоянный ключ
			case token_t::S: {
				// Длина ключа в сообщении: с меткой при ключе шифра
				const size_t length = (this->_public + (this->_symmetric.has() ? TAG : 0));
				// Если сообщение короче
				if((message.size - offset) < length)
					// Отмечаем короткое сообщение
					status = false;
				// Если ключ есть
				if(status){
					// Принятый ключ и его длина
					uint8_t key[KEM_PUBLIC_MAX];
					// Вместимость принятого ключа
					size_t room = this->_public;
					// Расшифровываем ключ
					status = this->_symmetric.open(view_t(message.data + offset, length), key, room);
					// Сдвигаем положение
					offset += length;
					// Если ключ задан заранее, он обязан совпасть
					if(status && this->_hasRS)
						// Сличаем ключи
						status = alike(key, this->_rs, this->_public);
					// Иначе запоминаем принятый
					else if(status){
						// Запоминаем ключ
						::memcpy(this->_rs, key, this->_public);
						// Устанавливаем признак
						this->_hasRS = true;
					}
					// Затираем принятый ключ
					wipe(key, sizeof(key));
				}
			} break;
			// Шифртекст к своему временному ключу: MixHash, распаковка, MixKey
			case token_t::EKEM: {
				// Общий секрет
				uint8_t shared[KEM_SHARED_MAX];
				// Если сообщение короче шифртекста
				if((message.size - offset) < ciphertext)
					// Отмечаем сообщение короче шифртекста
					status = false;
				// Иначе примешиваем шифртекст, распаковываем и примешиваем секрет
				else {
					// Примешиваем шифртекст в хеш, распаковываем и примешиваем секрет в ключ
					status = (this->_symmetric.hash(view_t(message.data + offset, ciphertext)) && this->unwrap(list[i], message.data + offset, shared) && this->_symmetric.key(view_t(shared, kemlength(this->_suite.kem, part_t::SHARED))));
					// Сдвигаем положение
					offset += ciphertext;
				}
				// Затираем секрет
				wipe(shared, sizeof(shared));
			} break;
			// Шифртекст к своему постоянному ключу: DecryptAndHash, распаковка, MixKey
			case token_t::SKEM: {
				// Длина шифртекста в сообщении: с меткой при ключе шифра
				const size_t length = (ciphertext + (this->_symmetric.has() ? TAG : 0));
				// Шифртекст и общий секрет
				uint8_t plain[KEM_CIPHERTEXT_MAX], shared[KEM_SHARED_MAX];
				// Вместимость шифртекста
				size_t room = ciphertext;
				// Если сообщение короче
				if((message.size - offset) < length)
					// Отмечаем короткое сообщение
					status = false;
				// Иначе расшифровываем, распаковываем и примешиваем секрет
				else {
					// Расшифровываем шифртекст, распаковываем и примешиваем секрет
					status = (this->_symmetric.open(view_t(message.data + offset, length), plain, room) && this->unwrap(list[i], plain, shared) && this->_symmetric.key(view_t(shared, kemlength(this->_suite.kem, part_t::SHARED))));
					// Сдвигаем положение
					offset += length;
				}
				// Затираем шифртекст и секрет
				wipe(plain, sizeof(plain));
				wipe(shared, sizeof(shared));
			} break;
			// Заранее разделённый ключ - только видоизменением
			case token_t::PSK: status = false; break;
			// DH
			default: status = this->mix(list[i]); break;
		}
	}
	// Если ключ pskN стоит в конце сообщения N-1
	if(status && ((this->_psks >> (this->_index + 1)) & 1))
		// Примешиваем ключ
		status = this->psk();
	// Если знаки пройдены, расшифровываем полезную часть
	if(status){
		// Вместимость места
		size_t room = capacity;
		// Расшифровываем полезную часть
		status = this->_symmetric.open(view_t(message.data + offset, message.size - offset), result, room);
		// Выводим длину
		size = (status ? room : 0);
	}
	// Если что-то не удалось, состояние неисправно
	if(!status){
		// Устанавливаем признак неисправности
		this->_broken = true;
		// Выводим отрицательный результат - чтение прервано
		return false;
	}
	// Сдвигаем номер сообщения
	this->_index++;
	// Сообщаем об успешном чтении
	return true;
}
/**
 * @brief Метод раскола на транспортные состояния (Split), после завершения рукопожатия
 *
 * @param one состояние от инициатора к отвечающему
 * @param two состояние от отвечающего к инициатору; у односторонних узоров остаётся без ключа
 * @return    признак того, что раскол выполнен
 *
 */
bool nts::noise::Handshake::split(cipher_t & one, cipher_t & two) noexcept {
	// Если рукопожатие не завершено либо раскол уже выполнен (раздел 5.3 Noise r34: после Split состояние рукопожатия удаляется)
	if((this->step() != step_t::DONE) || this->_split)
		// Выводим отрицательный результат - раскол невозможен
		return false;
	// Раскол выполнен: повтор отвергается
	this->_split = true;
	// Раскалываем симметричное состояние
	if(!this->_symmetric.split(one, two))
		// Выводим отрицательный результат - состояние не расколото
		return false;
	// У односторонних узоров второе состояние остаётся без ключа
	if(this->_count == 1)
		// Затираем второе состояние
		two.clear();
	// Сообщаем об успешном расколе
	return true;
}
/**
 * @brief Метод получения хеша рукопожатия для привязки канала
 *
 * @param result место хеша в длину хеша набора
 * @return       признак того, что хеш выдан
 *
 */
bool nts::noise::Handshake::digest(uint8_t * result) const noexcept {
	// Выводим хеш симметричного состояния
	return this->_symmetric.digest(result);
}
/**
 * @brief Метод получения постоянного открытого ключа собеседника, заданного либо принятого
 *
 * @param result место ключа длиной keylength()
 * @return       признак того, что ключ известен и выдан
 *
 */
bool nts::noise::Handshake::peer(uint8_t * result) const noexcept {
	// Если ключа нет либо места нет
	if(!this->_hasRS || (result == nullptr))
		// Выводим отрицательный результат - ключ собеседника не выдан
		return false;
	// Выдаём ключ
	::memcpy(result, this->_rs, this->_public);
	// Сообщаем об успешной выдаче ключа собеседника
	return true;
}
/**
 * @brief Метод получения своего постоянного открытого ключа
 *
 * @param result место ключа длиной keylength()
 * @return       признак того, что ключ задан и выдан
 *
 */
bool nts::noise::Handshake::self(uint8_t * result) const noexcept {
	// Если ключа нет либо места нет
	if(!this->_hasS || (result == nullptr))
		// Выводим отрицательный результат - свой ключ не выдан
		return false;
	// Выдаём ключ
	::memcpy(result, this->_sPublic, this->_public);
	// Сообщаем об успешной выдаче своего ключа
	return true;
}
/**
 * @brief Метод получения длины открытого ключа набора: KEY у классики, длина открытого ключа KEM у PQNoise
 *
 * @return длина либо нуль до заведения
 *
 */
size_t nts::noise::Handshake::keylength() const noexcept {
	// Выводим длину
	return this->_public;
}
/**
 * @brief Метод получения длины хеша набора
 *
 * @return длина хеша либо нуль до заведения
 *
 */
size_t nts::noise::Handshake::length() const noexcept {
	// Выводим длину
	return this->_symmetric.length();
}
/**
 * @brief Метод затирания состояния
 *
 */
void nts::noise::Handshake::clear() noexcept {
	// Затираем ключи
	wipe(this->_s, sizeof(this->_s));
	wipe(this->_sPublic, sizeof(this->_sPublic));
	wipe(this->_e, sizeof(this->_e));
	wipe(this->_ePublic, sizeof(this->_ePublic));
	wipe(this->_rs, sizeof(this->_rs));
	wipe(this->_re, sizeof(this->_re));
	wipe(this->_psk, sizeof(this->_psk));
	wipe(this->_coin, sizeof(this->_coin));
	// Затираем симметричное состояние
	this->_symmetric.clear();
	// Сбрасываем устройство
	this->_pattern = pattern_t::NONE;
	// Сбрасываем положения ключей
	this->_psks = 0;
	// Сбрасываем роль
	this->_role = role_t::NONE;
	// Сбрасываем набор
	this->_suite = suite_t();
	// Сбрасываем положение сообщения
	this->_index = 0;
	// Сбрасываем число сообщений
	this->_count = 0;
	// Сбрасываем признак начала
	this->_started = false;
	// Сбрасываем признак раскола
	this->_split = false;
	// Сбрасываем признак поломки
	this->_broken = false;
	// Сбрасываем признак своего постоянного ключа
	this->_hasS = false;
	// Сбрасываем признак своего временного ключа
	this->_hasE = false;
	// Сбрасываем признак чужого постоянного ключа
	this->_hasRS = false;
	// Сбрасываем признак чужого временного ключа
	this->_hasRE = false;
	// Сбрасываем число ключей
	this->_pskCount = 0;
	// Сбрасываем число использованных ключей
	this->_pskUsed = 0;
	// Сбрасываем число случайностей
	this->_coinCount = 0;
	// Сбрасываем число использованных случайностей
	this->_coinUsed = 0;
	// Сбрасываем длину открытого ключа
	this->_public = 0;
	// Сбрасываем длину закрытого ключа
	this->_secret = 0;
	// Сбрасываем длину зерна
	this->_seed = 0;
}
/**
 * @brief Конструктор
 *
 */
nts::noise::Handshake::Handshake() noexcept :
 _pattern(pattern_t::NONE), _psks(0), _role(role_t::NONE), _index(0), _count(0),
 _started(false), _split(false), _broken(false), _hasS(false), _hasE(false), _hasRS(false), _hasRE(false),
 _pskCount(0), _pskUsed(0), _coinCount(0), _coinUsed(0), _public(0), _secret(0), _seed(0) {
	// Обнуляем ключи
	::memset(this->_s, 0, sizeof(this->_s));
	::memset(this->_sPublic, 0, sizeof(this->_sPublic));
	::memset(this->_e, 0, sizeof(this->_e));
	::memset(this->_ePublic, 0, sizeof(this->_ePublic));
	::memset(this->_rs, 0, sizeof(this->_rs));
	::memset(this->_re, 0, sizeof(this->_re));
	::memset(this->_psk, 0, sizeof(this->_psk));
	::memset(this->_coin, 0, sizeof(this->_coin));
}
/**
 * @brief Деструктор
 *
 */
nts::noise::Handshake::~Handshake() noexcept {
	// Затираем состояние
	this->clear();
}
