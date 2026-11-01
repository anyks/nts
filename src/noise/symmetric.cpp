/**
 * @file symmetric.cpp
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
 * @brief Модуль симметричного состояния Noise (SymmetricState)
 *
 * @details HKDF Noise (§4.3): temp = HMAC(ck, ikm); out1 = HMAC(temp, 0x01);
 *          out2 = HMAC(temp, out1 ‖ 0x02); out3 = HMAC(temp, out2 ‖ 0x03) - ровно extract с
 *          солью ck и expand с пустой привязкой. Первый выход всегда становится ck, ключ шифра
 *          усекается до KEY байтов при длине хеша 64
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
#include <noise/symmetric.hpp>
#include <digest/hkdf.hpp>
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
};

/**
 * @brief Метод вывода ключевого материала (HKDF Noise)
 *
 * @param material входной ключевой материал
 * @param result   место материала в count длин хеша
 * @param count    число выходов: 2 либо 3
 * @return         признак того, что материал выведен
 *
 */
bool nts::noise::Symmetric::kdf(const view_t & material, uint8_t * result, const size_t count) const noexcept {
	// Псевдослучайный ключ
	uint8_t key[HASH_MAX];
	// Извлекаем ключ с солью ck и развёртываем без привязки
	const bool status = (digest::extract(this->_hash, view_t(this->_chain, this->_length), material, key, HASH_MAX) && digest::expand(this->_hash, view_t(key, this->_length), view_t(), result, count * this->_length));
	// Затираем псевдослучайный ключ
	wipe(key, HASH_MAX);
	// Возвращаем итог развёртывания
	return status;
}
/**
 * @brief Метод заведения состояния (InitializeSymmetric)
 *
 * @param name  имя протокола
 * @param suite набор примитивов
 * @return      признак того, что состояние заведено
 *
 */
bool nts::noise::Symmetric::start(const view_t & name, const suite_t & suite) noexcept {
	// Затираем прежнее состояние
	this->clear();
	// Если имя либо набор негодны
	if((name.data == nullptr) || (name.size == 0) || !valid(suite) || !this->_cipher.start(suite.aead))
		// Выводим отрицательный результат - состояние не заведено
		return false;
	// Запоминаем функцию шифрования, хеш и его длину
	this->_aead = suite.aead;
	// Запоминаем хеш
	this->_hash = suite.hash;
	// Запоминаем длину хеша
	this->_length = digest::length(suite.hash);
	// Если имя не длиннее хеша, оно дополняется нулями
	if(name.size <= this->_length){
		// Обнуляем хеш
		::memset(this->_digest, 0, HASH_MAX);
		// Записываем имя
		::memcpy(this->_digest, name.data, name.size);
	// Иначе имя хешируется
	} else if(!digest::hash(this->_hash, name, this->_digest, HASH_MAX)){
		// Затираем состояние
		this->clear();
		// Выводим отрицательный результат - имя не захешировано
		return false;
	}
	// Цепной ключ равен хешу
	::memcpy(this->_chain, this->_digest, HASH_MAX);
	// Сообщаем об успешном заведении
	return true;
}
/**
 * @brief Метод примешивания ключевого материала (MixKey)
 *
 * @param material входной ключевой материал
 * @return         признак того, что материал примешан
 *
 */
bool nts::noise::Symmetric::key(const view_t & material) noexcept {
	// Если состояние не заведено
	if(this->_length == 0)
		// Выводим отрицательный результат - ключ не примешан
		return false;
	// Два выхода
	uint8_t output[2 * HASH_MAX];
	// Выводим материал: новый ck и ключ шифра
	bool status = this->kdf(material, output, 2);
	// Если материал выведен
	if(status){
		// Новый цепной ключ - первый выход целиком
		::memcpy(this->_chain, output, this->_length);
		// Ключ шифра - второй выход, усечённый до KEY байтов при длине 64
		status = this->_cipher.key(view_t(output + this->_length, KEY));
	}
	// Затираем выходы
	wipe(output, sizeof(output));
	// Возвращаем итог примешивания ключа
	return status;
}
/**
 * @brief Метод примешивания данных в хеш (MixHash)
 *
 * @param data данные
 * @return     признак того, что данные примешаны
 *
 */
bool nts::noise::Symmetric::hash(const view_t & data) noexcept {
	// Если состояние не заведено либо данные негодны
	if((this->_length == 0) || ((data.size > 0) && (data.data == nullptr)))
		// Выводим отрицательный результат - данные не примешаны
		return false;
	// Объект хеширования
	digest::hasher_t hasher(this->_hash);
	// Подаём прежний хеш
	hasher.update(view_t(this->_digest, this->_length));
	// Подаём данные
	hasher.update(data);
	// Выводим итог: новый хеш на месте прежнего
	return hasher.finish(this->_digest, HASH_MAX);
}
/**
 * @brief Метод примешивания заранее разделённого ключа (MixKeyAndHash)
 *
 * @param material входной ключевой материал
 * @return         признак того, что материал примешан
 *
 */
bool nts::noise::Symmetric::blend(const view_t & material) noexcept {
	// Если состояние не заведено
	if(this->_length == 0)
		// Выводим отрицательный результат - заранее разделённый ключ не примешан
		return false;
	// Три выхода
	uint8_t output[3 * HASH_MAX];
	// Выводим материал: новый ck, добавка к хешу и ключ шифра
	bool status = this->kdf(material, output, 3);
	// Если материал выведен
	if(status){
		// Новый цепной ключ - первый выход целиком
		::memcpy(this->_chain, output, this->_length);
		// Второй выход примешивается в хеш
		status = this->hash(view_t(output + this->_length, this->_length));
		// Ключ шифра - третий выход, усечённый до KEY байтов при длине 64
		status = (status && this->_cipher.key(view_t(output + (2 * this->_length), KEY)));
	}
	// Затираем выходы
	wipe(output, sizeof(output));
	// Возвращаем итог примешивания
	return status;
}
/**
 * @brief Метод шифрования с примешиванием (EncryptAndHash)
 *
 * @param source открытые данные
 * @param result место выхода: при отсутствии ключа - те же данные, иначе шифротекст с меткой
 * @param size   на входе вместимость места, на выходе длина выхода
 * @return       признак того, что выход получен
 *
 */
bool nts::noise::Symmetric::seal(const view_t & source, uint8_t * result, size_t & size) noexcept {
	// Длина выхода: с меткой при ключе
	const size_t length = (source.size + (this->_cipher.has() ? TAG : 0));
	// Если состояние не заведено, данные негодны либо место мало
	if((this->_length == 0) || ((source.size > 0) && (source.data == nullptr)) || (length > MESSAGE) || (size < length) || ((length > 0) && (result == nullptr))){
		// Сбрасываем длину
		size = 0;
		// Выводим отрицательный результат - печать невозможна
		return false;
	}
	// Если ключ есть, шифруем с h как сопутствующими данными
	if(this->_cipher.has()){
		// Если шифрование не удалось
		if(!this->_cipher.encrypt(view_t(this->_digest, this->_length), source, result, result + source.size)){
			// Сбрасываем длину
			size = 0;
			// Выводим отрицательный результат - шифрование не выполнено
			return false;
		}
	// Иначе выход равен входу
	} else if(source.size > 0)
		// Переносим данные: области вправе совпадать
		::memmove(result, source.data, source.size);
	// Примешиваем выход в хеш
	if(!this->hash(view_t(result, length))){
		// Сбрасываем длину
		size = 0;
		// Выводим отрицательный результат - выход не примешан
		return false;
	}
	// Выводим длину выхода
	size = length;
	// Длина выхода выведена
	return true;
}
/**
 * @brief Метод расшифрования с примешиванием (DecryptAndHash)
 *
 * @param source вход: при отсутствии ключа - открытые данные, иначе шифротекст с меткой
 * @param result место открытых данных
 * @param size   на входе вместимость места, на выходе длина открытых данных
 * @return       признак того, что данные подлинны и получены
 *
 */
bool nts::noise::Symmetric::open(const view_t & source, uint8_t * result, size_t & size) noexcept {
	// Длина метки при ключе
	const size_t tag = (this->_cipher.has() ? TAG : 0);
	// Если состояние не заведено, вход короче метки, негоден либо место мало
	if((this->_length == 0) || (source.size < tag) || ((source.size > 0) && (source.data == nullptr)) || (source.size > MESSAGE) || (size < (source.size - tag)) || (((source.size - tag) > 0) && (result == nullptr))){
		// Сбрасываем длину
		size = 0;
		// Выводим отрицательный результат - вскрытие невозможно
		return false;
	}
	// Длина открытых данных
	const size_t length = (source.size - tag);
	// Если ключ есть, расшифровываем с h как сопутствующими данными: h не тронут до подлинности
	if(this->_cipher.has()){
		/**
		 * Новый хеш считается до расшифрования в отдельное место: области входа и итога
		 * вправе совпадать, и после расшифрования на месте входа лежал бы открытый текст
		 */
		uint8_t mixed[HASH_MAX];
		// Объект хеширования
		digest::hasher_t hasher(this->_hash);
		// Подаём прежний хеш
		hasher.update(view_t(this->_digest, this->_length));
		// Подаём шифртекст с меткой
		hasher.update(source);
		// Если хеш снять не удалось
		if(!hasher.finish(mixed, HASH_MAX)){
			// Сбрасываем длину
			size = 0;
			// Выводим отрицательный результат - хеш не снят
			return false;
		}
		// Если подлинность не сошлась: прежний h нетронут
		if(!this->_cipher.decrypt(view_t(this->_digest, this->_length), view_t(source.data, length), view_t(source.data + length, TAG), result)){
			// Затираем новый хеш
			sys::wipe(mixed, sizeof(mixed));
			// Сбрасываем длину
			size = 0;
			// Выводим отрицательный результат - подлинность не сошлась
			return false;
		}
		// Переносим новый хеш на место прежнего
		::memcpy(this->_digest, mixed, HASH_MAX);
		// Затираем отдельное место
		sys::wipe(mixed, sizeof(mixed));
	// Иначе выход равен входу
	} else {
		// Примешиваем вход в хеш до переноса: области вправе совпадать
		if(!this->hash(source)){
			// Сбрасываем длину
			size = 0;
			// Выводим отрицательный результат - вход не примешан
			return false;
		}
		// Переносим данные
		if(length > 0)
			// Сдвигаем данные в итог
			::memmove(result, source.data, length);
	}
	// Выводим длину
	size = length;
	// Длина открытых данных выведена
	return true;
}
/**
 * @brief Метод раскола на два состояния шифра (Split)
 *
 * @param one состояние от инициатора к отвечающему
 * @param two состояние от отвечающего к инициатору
 * @return    признак того, что раскол выполнен
 *
 */
bool nts::noise::Symmetric::split(cipher_t & one, cipher_t & two) const noexcept {
	// Если состояние не заведено
	if(this->_length == 0)
		// Выводим отрицательный результат - раскол невозможен
		return false;
	// Два выхода
	uint8_t output[2 * HASH_MAX];
	// Выводим материал из пустого входа и заводим оба состояния функцией набора
	const bool status = (this->kdf(view_t(), output, 2) && one.start(this->_aead) && two.start(this->_aead) && one.key(view_t(output, KEY)) && two.key(view_t(output + this->_length, KEY)));
	// Затираем выходы
	wipe(output, sizeof(output));
	// Возвращаем итог раскола
	return status;
}
/**
 * @brief Метод получения хеша рукопожатия (GetHandshakeHash)
 *
 * @param result место хеша в длину хеша набора
 * @return       признак того, что хеш выдан
 *
 */
bool nts::noise::Symmetric::digest(uint8_t * result) const noexcept {
	// Если состояние не заведено либо места нет
	if((this->_length == 0) || (result == nullptr))
		// Выводим отрицательный результат - хеш не выдан
		return false;
	// Выдаём хеш
	::memcpy(result, this->_digest, this->_length);
	// Хеш выдан
	return true;
}
/**
 * @brief Метод получения длины хеша набора
 *
 * @return длина хеша либо нуль до заведения
 *
 */
size_t nts::noise::Symmetric::length() const noexcept {
	// Выводим длину
	return this->_length;
}
/**
 * @brief Метод проверки наличия ключа шифра
 *
 * @return признак того, что ключ установлен
 *
 */
bool nts::noise::Symmetric::has() const noexcept {
	// Выводим признак
	return this->_cipher.has();
}
/**
 * @brief Метод затирания состояния
 *
 */
void nts::noise::Symmetric::clear() noexcept {
	// Затираем цепной ключ и хеш
	wipe(this->_chain, HASH_MAX);
	wipe(this->_digest, HASH_MAX);
	// Затираем состояние шифра
	this->_cipher.clear();
	// Сбрасываем хеш и длину
	this->_hash = digest::hash_t::NONE;
	// Сбрасываем длину
	this->_length = 0;
	// Сбрасываем вид шифра AEAD
	this->_aead = aead_t::NONE;
}
/**
 * @brief Конструктор
 *
 */
nts::noise::Symmetric::Symmetric() noexcept : _hash(digest::hash_t::NONE), _aead(aead_t::NONE), _length(0) {
	// Обнуляем цепной ключ и хеш
	::memset(this->_chain, 0, HASH_MAX);
	::memset(this->_digest, 0, HASH_MAX);
}
/**
 * @brief Деструктор
 *
 */
nts::noise::Symmetric::~Symmetric() noexcept {
	// Затираем состояние
	this->clear();
}
