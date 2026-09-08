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
	 * @brief Метод сличения двух ключей за постоянное время
	 *
	 * @param one   первый ключ
	 * @param two   второй ключ
	 * @param size  длина ключей
	 *
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
		// Выводим отказ
		return false;
	// Знаки и их число
	const token_t * list = nullptr;
	size_t count = 0;
	/**
	 * Выполняем проверку, что свой постоянный ключ есть, если узор велит его слать либо принимать skem
	 */
	for(size_t i = 0; i < this->_count; i++){
		// Признак нашего сообщения
		const bool ours = (((i % 2) == 0) == initiator);
		// Получаем знаки
		if(!tokens(this->_pattern, i, list, count))
			// Выводим отказ
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
				// Выводим отказ
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
			// Выводим отказ
			return false;
		/**
		 * Выполняем перебор знаков
		 */
		for(size_t j = 0; j < count; j++){
			// Если знак не постоянный ключ
			if(list[j] != token_t::S)
				// Выводим отказ
				return false;
			// Признак того, что ключ наш
			const bool own = (first == initiator);
			// Если нужного ключа нет
			if(own ? !this->_hasS : !this->_hasRS)
				// Выводим отказ
				return false;
			// Примешиваем открытый ключ
			if(!this->_symmetric.hash(view_t(own ? this->_sPublic : this->_rs, this->_public)))
				// Выводим отказ
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
 *
 * @return      признак того, что секрет примешан
 *
 */
bool nts::noise::Handshake::mix(const token_t token) noexcept {
	// У PQNoise знаков DH нет
	if(this->_suite.dh == dh_t::NONE)
		// Выводим отказ
		return false;
	// Признак роли инициатора
	const bool initiator = (this->_role == role_t::INITIATOR);
	// Свой закрытый ключ и чужой открытый
	const uint8_t * secret = nullptr;
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
			if(initiator){ secret = this->_e; own = this->_hasE; point = this->_rs; peer = this->_hasRS; }
			else { secret = this->_s; own = this->_hasS; point = this->_re; peer = this->_hasRE; }
		} break;
		// DH постоянного ключа инициатора и временного отвечающего
		case token_t::SE: {
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
		// Выводим отказ
		return false;
	// Общий секрет
	uint8_t shared[KEY];
	// Вычисляем DH и примешиваем секрет
	const bool status = (agree(this->_suite.dh, view_t(secret, KEY), view_t(point, KEY), shared) && this->_symmetric.key(view_t(shared, KEY)));
	// Затираем секрет
	wipe(shared, KEY);
	// Выводим успешность
	return status;
}
/**
 * @brief Метод упаковки по знаку KEM у отправителя
 *
 * @param token      знак: EKEM либо SKEM
 * @param ciphertext место шифртекста
 * @param shared     место общего секрета
 *
 * @return           признак того, что секрет упакован
 *
 */
bool nts::noise::Handshake::wrap(const token_t token, uint8_t * ciphertext, uint8_t * shared) noexcept {
	// У классики знаков KEM нет
	if(this->_suite.kem == kem_t::NONE)
		// Выводим отказ
		return false;
	// Открытый ключ получателя: временный у ekem, постоянный у skem
	const uint8_t * key = ((token == token_t::EKEM) ? this->_re : this->_rs);
	// Признак его наличия
	const bool known = ((token == token_t::EKEM) ? this->_hasRE : this->_hasRS);
	// Если знак чужой либо ключа нет
	if(((token != token_t::EKEM) && (token != token_t::SKEM)) || !known)
		// Выводим отказ
		return false;
	// Если случайности заданы явно (корпус), упаковываем на очередной; исчерпаны - отказ, а не переход на энтропию
	if(this->_coinCount > 0){
		// Если случайности исчерпаны
		if(this->_coinUsed >= this->_coinCount)
			// Выводим отказ
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
 *
 * @return           признак того, что секрет распакован
 *
 */
bool nts::noise::Handshake::unwrap(const token_t token, const uint8_t * ciphertext, uint8_t * shared) noexcept {
	// У классики знаков KEM нет
	if(this->_suite.kem == kem_t::NONE)
		// Выводим отказ
		return false;
	// Свой закрытый ключ: временный у ekem, постоянный у skem
	const uint8_t * secret = ((token == token_t::EKEM) ? this->_e : this->_s);
	// Признак его наличия
	const bool own = ((token == token_t::EKEM) ? this->_hasE : this->_hasS);
	// Если знак чужой либо ключа нет
	if(((token != token_t::EKEM) && (token != token_t::SKEM)) || !own)
		// Выводим отказ
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
		// Выводим отказ
		return false;
	// Примешиваем ключ и сдвигаем счёт
	return this->_symmetric.blend(view_t(this->_psk[this->_pskUsed++], PSK));
}
/**
 * \~russian
 * @brief Метод заведения рукопожатия перечислениями
 *
 * @param pattern  узор рукопожатия
 * @param psks     положения заранее разделённых ключей
 * @param suite    набор примитивов
 * @param role     роль стороны
 * @param prologue пролог
 *
 * @return         признак того, что рукопожатие заведено
 *
 * \~english
 * @brief Method of starting a handshake by enumerations
 *
 * @param pattern  handshake pattern
 * @param psks     positions of pre-shared keys
 * @param suite    suite of primitives
 * @param role     side role
 * @param prologue prologue
 *
 * @return         sign that the handshake is started
 *
 * \~
 */
bool nts::noise::Handshake::start(const pattern_t pattern, const psk_t psks, const suite_t & suite, const role_t role, const view_t & prologue) noexcept {
	// Затираем прежнее состояние
	this->clear();
	// Число сообщений узора
	const size_t count = messages(pattern);
	// Если узор, роль, набор либо пролог негодны
	if((count == 0) || ((role != role_t::INITIATOR) && (role != role_t::RESPONDER)) || !valid(suite) || ((prologue.size > 0) && (prologue.data == nullptr)))
		// Выводим отказ
		return false;
	// Положения заранее разделённых ключей не дальше числа сообщений: pskN при N <= count
	if((psks >> PSKS_MAX) != 0 || (psks >> (count + 1)) != 0)
		// Выводим отказ
		return false;
	// Имя протокола и его длина: name сам отвергает узор и набор разных семейств и psk у PQNoise
	char text[NAME_LIMIT];
	size_t length = NAME_LIMIT;
	// Составляем имя
	if(!name(pattern, psks, suite, text, length))
		// Выводим отказ
		return false;
	// Заводим симметричное состояние и примешиваем пролог
	if(!this->_symmetric.start(view_t(reinterpret_cast <const uint8_t *> (text), length), suite) || !this->_symmetric.hash(prologue)){
		// Затираем состояние
		this->clear();
		// Выводим отказ
		return false;
	}
	// Запоминаем устройство рукопожатия
	this->_pattern = pattern;
	this->_psks = psks;
	this->_suite = suite;
	this->_role = role;
	this->_count = count;
	// Длины ключей по набору: KEY у классики, по KEM у PQNoise
	if(suite.kem == kem_t::NONE){
		this->_public = KEY;
		this->_secret = KEY;
		this->_seed = KEY;
	} else {
		this->_public = kemlength(suite.kem, part_t::PUBLIC);
		this->_secret = kemlength(suite.kem, part_t::SECRET);
		this->_seed = kemlength(suite.kem, part_t::SEED);
	}
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод заведения рукопожатия именем протокола
 *
 * @param name     имя протокола
 * @param role     роль стороны
 * @param prologue пролог
 *
 * @return         признак того, что рукопожатие заведено
 *
 * \~english
 * @brief Method of starting a handshake by the protocol name
 *
 * @param name     protocol name
 * @param role     side role
 * @param prologue prologue
 *
 * @return         sign that the handshake is started
 *
 * \~
 */
bool nts::noise::Handshake::start(const view_t & name, const role_t role, const view_t & prologue) noexcept {
	// Разобранные узор, положения и набор
	pattern_t pattern = pattern_t::NONE;
	psk_t psks = 0;
	suite_t suite;
	// Если имя не разобрано
	if(!parse(name, pattern, psks, suite)){
		// Затираем состояние
		this->clear();
		// Выводим отказ
		return false;
	}
	// Заводим рукопожатие перечислениями
	return this->start(pattern, psks, suite, role, prologue);
}
/**
 * \~russian
 * @brief Метод установки своего постоянного ключа
 *
 * @param secret закрытый ключ либо зерно KEM
 *
 * @return       признак того, что ключ установлен
 *
 * \~english
 * @brief Method of setting the own static key
 *
 * @param secret private key or the KEM seed
 *
 * @return       sign that the key is set
 *
 * \~
 */
bool nts::noise::Handshake::statics(const view_t & secret) noexcept {
	// Если рукопожатие не заведено, уже идёт либо ключ негоден
	if((this->_count == 0) || this->_started || (secret.data == nullptr) || (secret.size != this->_seed))
		// Выводим отказ
		return false;
	// Если набор PQNoise, пара порождается из зерна
	if(this->_suite.kem != kem_t::NONE){
		// Если пара не порождена
		if(!kemgenerateDeterministic(this->_suite.kem, secret, this->_sPublic, this->_s))
			// Выводим отказ
			return false;
	// Иначе открытый ключ выводится из закрытого
	} else {
		// Если открытый ключ не выведен
		if(!derive(this->_suite.dh, secret, this->_sPublic))
			// Выводим отказ
			return false;
		// Запоминаем закрытый ключ
		::memcpy(this->_s, secret.data, KEY);
	}
	// Устанавливаем признак
	this->_hasS = true;
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод явной установки своего временного ключа
 *
 * @param secret закрытый ключ либо зерно KEM
 *
 * @return       признак того, что ключ установлен
 *
 * \~english
 * @brief Method of setting the own ephemeral key explicitly
 *
 * @param secret private key or the KEM seed
 *
 * @return       sign that the key is set
 *
 * \~
 */
bool nts::noise::Handshake::ephemeral(const view_t & secret) noexcept {
	// Если рукопожатие не заведено, уже идёт либо ключ негоден
	if((this->_count == 0) || this->_started || (secret.data == nullptr) || (secret.size != this->_seed))
		// Выводим отказ
		return false;
	// Если набор PQNoise, пара порождается из зерна
	if(this->_suite.kem != kem_t::NONE){
		// Если пара не порождена
		if(!kemgenerateDeterministic(this->_suite.kem, secret, this->_ePublic, this->_e))
			// Выводим отказ
			return false;
	// Иначе открытый ключ выводится из закрытого
	} else {
		// Если открытый ключ не выведен
		if(!derive(this->_suite.dh, secret, this->_ePublic))
			// Выводим отказ
			return false;
		// Запоминаем закрытый ключ
		::memcpy(this->_e, secret.data, KEY);
	}
	// Устанавливаем признак
	this->_hasE = true;
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод установки постоянного открытого ключа собеседника
 *
 * @param key открытый ключ
 *
 * @return    признак того, что ключ установлен
 *
 * \~english
 * @brief Method of setting the peer static public key
 *
 * @param key public key
 *
 * @return    sign that the key is set
 *
 * \~
 */
bool nts::noise::Handshake::remote(const view_t & key) noexcept {
	// Если рукопожатие не заведено, уже идёт либо ключ негоден
	if((this->_count == 0) || this->_started || (key.data == nullptr) || (key.size != this->_public))
		// Выводим отказ
		return false;
	// Запоминаем ключ
	::memcpy(this->_rs, key.data, this->_public);
	// Устанавливаем признак
	this->_hasRS = true;
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод установки заранее разделённых ключей
 *
 * @param keys  ключи
 * @param count число ключей
 *
 * @return      признак того, что ключи установлены
 *
 * \~english
 * @brief Method of setting pre-shared keys
 *
 * @param keys  keys
 * @param count number of keys
 *
 * @return      sign that the keys are set
 *
 * \~
 */
bool nts::noise::Handshake::psks(const view_t * keys, const size_t count) noexcept {
	// Если рукопожатие не заведено, уже идёт, набор PQNoise (psk там не заведён) либо ключи негодны
	if((this->_count == 0) || this->_started || (this->_suite.kem != kem_t::NONE) || (count == 0) || (count > PSKS_MAX) || (keys == nullptr))
		// Выводим отказ
		return false;
	/**
	 * Выполняем проверку каждого ключа
	 */
	for(size_t i = 0; i < count; i++){
		// Если ключ негоден
		if((keys[i].data == nullptr) || (keys[i].size != PSK))
			// Выводим отказ
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
	this->_pskUsed = 0;
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод явной установки случайностей упаковки KEM
 *
 * @param coins случайности
 * @param count число случайностей
 *
 * @return      признак того, что случайности установлены
 *
 * \~english
 * @brief Method of setting KEM encapsulation randomness explicitly
 *
 * @param coins randomness values
 * @param count number of values
 *
 * @return      sign that the values are set
 *
 * \~
 */
bool nts::noise::Handshake::coinsDeterministic(const view_t * coins, const size_t count) noexcept {
	// Длина случайности набора
	const size_t length = kemlength(this->_suite.kem, part_t::COINS);
	// Если рукопожатие не заведено, не PQNoise, уже идёт либо случайности негодны
	if((this->_count == 0) || (length == 0) || this->_started || (count == 0) || (count > PSKS_MAX) || (coins == nullptr))
		// Выводим отказ
		return false;
	/**
	 * Выполняем проверку каждой случайности
	 */
	for(size_t i = 0; i < count; i++){
		// Если случайность негодна
		if((coins[i].data == nullptr) || (coins[i].size != length))
			// Выводим отказ
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
	this->_coinUsed = 0;
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод получения хода
 *
 * @return ход рукопожатия
 *
 * \~english
 * @brief Method of getting the turn
 *
 * @return handshake turn
 *
 * \~
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
 * \~russian
 * @brief Метод записи сообщения
 *
 * @param payload полезная часть
 * @param result  место сообщения
 * @param size    на входе вместимость места, на выходе длина сообщения
 *
 * @return        признак того, что сообщение записано
 *
 * \~english
 * @brief Method of writing a message
 *
 * @param payload payload
 * @param result  place of the message
 * @param size    the capacity of the place on input, the message length on output
 *
 * @return        sign that the message is written
 *
 * \~
 */
bool nts::noise::Handshake::write(const view_t & payload, uint8_t * result, size_t & size) noexcept {
	// Вместимость места
	const size_t capacity = size;
	// Сбрасываем длину
	size = 0;
	// Если не наш ход, полезная часть либо место негодны, либо предсообщения не поглощены
	if((this->step() != step_t::WRITE) || ((payload.size > 0) && (payload.data == nullptr)) || ((capacity > 0) && (result == nullptr)) || !this->ready())
		// Выводим отказ
		return false;
	// Знаки сообщения и их число
	const token_t * list = nullptr;
	size_t count = 0;
	// Получаем знаки
	if(!tokens(this->_pattern, this->_index, list, count))
		// Выводим отказ
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
					// Выводим отказ
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
					// Выводим отказ
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
		// Выводим отказ
		status = false;
	// Если что-то не удалось, состояние неисправно
	if(!status){
		// Устанавливаем признак неисправности
		this->_broken = true;
		// Выводим отказ
		return false;
	}
	// Сдвигаем номер сообщения
	this->_index++;
	// Выводим длину
	size = offset;
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод чтения сообщения
 *
 * @param message сообщение
 * @param result  место полезной части
 * @param size    на входе вместимость места, на выходе длина полезной части
 *
 * @return        признак того, что сообщение подлинно и прочитано
 *
 * \~english
 * @brief Method of reading a message
 *
 * @param message message
 * @param result  place of the payload
 * @param size    the capacity of the place on input, the payload length on output
 *
 * @return        sign that the message is authentic and read
 *
 * \~
 */
bool nts::noise::Handshake::read(const view_t & message, uint8_t * result, size_t & size) noexcept {
	// Вместимость места
	const size_t capacity = size;
	// Сбрасываем длину
	size = 0;
	// Если не наш ход, сообщение либо место негодны, либо предсообщения не поглощены
	if((this->step() != step_t::READ) || ((message.size > 0) && (message.data == nullptr)) || (message.size > MESSAGE) || ((capacity > 0) && (result == nullptr)) || !this->ready())
		// Выводим отказ
		return false;
	// Знаки сообщения и их число
	const token_t * list = nullptr;
	size_t count = 0;
	// Получаем знаки
	if(!tokens(this->_pattern, this->_index, list, count))
		// Выводим отказ
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
					// Выводим отказ
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
					// Выводим отказ
					status = false;
				// Если ключ есть
				if(status){
					// Принятый ключ и его длина
					uint8_t key[KEM_PUBLIC_MAX];
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
					// Выводим отказ
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
					// Выводим отказ
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
		// Выводим отказ
		return false;
	}
	// Сдвигаем номер сообщения
	this->_index++;
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод раскола на транспортные состояния
 *
 * @param one состояние от инициатора к отвечающему
 * @param two состояние от отвечающего к инициатору
 *
 * @return    признак того, что раскол выполнен
 *
 * \~english
 * @brief Method of splitting into transport states
 *
 * @param one state from the initiator to the responder
 * @param two state from the responder to the initiator
 *
 * @return    sign that the split is done
 *
 * \~
 */
bool nts::noise::Handshake::split(cipher_t & one, cipher_t & two) const noexcept {
	// Если рукопожатие не завершено
	if(this->step() != step_t::DONE)
		// Выводим отказ
		return false;
	// Раскалываем симметричное состояние
	if(!this->_symmetric.split(one, two))
		// Выводим отказ
		return false;
	// У односторонних узоров второе состояние остаётся без ключа
	if(this->_count == 1)
		// Затираем второе состояние
		two.clear();
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод получения хеша рукопожатия
 *
 * @param result место хеша
 *
 * @return       признак того, что хеш выдан
 *
 * \~english
 * @brief Method of getting the handshake hash
 *
 * @param result place of the hash
 *
 * @return       sign that the hash is given
 *
 * \~
 */
bool nts::noise::Handshake::digest(uint8_t * result) const noexcept {
	// Выводим хеш симметричного состояния
	return this->_symmetric.digest(result);
}
/**
 * \~russian
 * @brief Метод получения постоянного открытого ключа собеседника
 *
 * @param result место ключа
 *
 * @return       признак того, что ключ известен и выдан
 *
 * \~english
 * @brief Method of getting the peer static public key
 *
 * @param result place of the key
 *
 * @return       sign that the key is known and given
 *
 * \~
 */
bool nts::noise::Handshake::peer(uint8_t * result) const noexcept {
	// Если ключа нет либо места нет
	if(!this->_hasRS || (result == nullptr))
		// Выводим отказ
		return false;
	// Выдаём ключ
	::memcpy(result, this->_rs, this->_public);
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод получения своего постоянного открытого ключа
 *
 * @param result место ключа
 *
 * @return       признак того, что ключ задан и выдан
 *
 * \~english
 * @brief Method of getting the own static public key
 *
 * @param result place of the key
 *
 * @return       sign that the key is set and given
 *
 * \~
 */
bool nts::noise::Handshake::self(uint8_t * result) const noexcept {
	// Если ключа нет либо места нет
	if(!this->_hasS || (result == nullptr))
		// Выводим отказ
		return false;
	// Выдаём ключ
	::memcpy(result, this->_sPublic, this->_public);
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод получения длины открытого ключа набора
 *
 * @return длина либо нуль до заведения
 *
 * \~english
 * @brief Method of getting the suite public key length
 *
 * @return length or zero before start
 *
 * \~
 */
size_t nts::noise::Handshake::keylength() const noexcept {
	// Выводим длину
	return this->_public;
}
/**
 * \~russian
 * @brief Метод получения длины хеша набора
 *
 * @return длина хеша либо нуль до заведения
 *
 * \~english
 * @brief Method of getting the suite hash length
 *
 * @return hash length or zero before start
 *
 * \~
 */
size_t nts::noise::Handshake::length() const noexcept {
	// Выводим длину
	return this->_symmetric.length();
}
/**
 * \~russian
 * @brief Метод затирания состояния
 *
 * \~english
 * @brief Method of wiping the state
 *
 * \~
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
	this->_psks = 0;
	this->_role = role_t::NONE;
	this->_suite = suite_t();
	this->_index = 0;
	this->_count = 0;
	this->_started = false;
	this->_broken = false;
	this->_hasS = false;
	this->_hasE = false;
	this->_hasRS = false;
	this->_hasRE = false;
	this->_pskCount = 0;
	this->_pskUsed = 0;
	this->_coinCount = 0;
	this->_coinUsed = 0;
	this->_public = 0;
	this->_secret = 0;
	this->_seed = 0;
}
/**
 * \~russian
 * @brief Конструктор
 *
 * \~english
 * @brief Constructor
 *
 * \~
 */
nts::noise::Handshake::Handshake() noexcept :
 _pattern(pattern_t::NONE), _psks(0), _role(role_t::NONE), _index(0), _count(0),
 _started(false), _broken(false), _hasS(false), _hasE(false), _hasRS(false), _hasRE(false),
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
 * \~russian
 * @brief Деструктор
 *
 * \~english
 * @brief Destructor
 *
 * \~
 */
nts::noise::Handshake::~Handshake() noexcept {
	// Затираем состояние
	this->clear();
}
