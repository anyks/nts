/**
 * @file cipher.cpp
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
 * @brief Модуль состояния шифра Noise (CipherState)
 *
 * @details Нонс в 96 разрядов: четыре нулевых байта и счётчик - от младшего у ChaChaPoly
 *          (§12.3), от старшего у AESGCM (§12.4). Ключ AES разворачивается один раз при
 *          установке; ChaChaPoly заводится на каждое вложение по ключу и нонсу
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
#include <noise/cipher.hpp>
#include <cipher/gcm.hpp>
#include <cipher/chachapoly.hpp>
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
	 * @brief Запретное значение счётчика
	 *
	 */
	static constexpr uint64_t FORBIDDEN = 0xFFFFFFFFFFFFFFFFULL;
	/**
	 * @brief Длина нонса в байтах
	 *
	 */
	static constexpr size_t NONCE = 12;
	/**
	 * @brief Функция заполнения нонса по счётчику
	 *
	 * @param aead   функция шифрования
	 * @param nonce  счётчик вложений
	 * @param result место нонса в NONCE байтов
	 *
	 */
	static void fill(const nts::noise::aead_t aead, const uint64_t nonce, uint8_t * result) noexcept {
		// Четыре нулевых байта
		::memset(result, 0, 4);
		/**
		 * Выполняем запись счётчика по восьми байтам
		 */
		for(size_t i = 0; i < 8; i++){
			// У ChaChaPoly от младшего, у AESGCM от старшего
			if(aead == nts::noise::aead_t::CHACHAPOLY)
				// Записываем байт счётчика от младшего
				result[4 + i] = static_cast <uint8_t> (nonce >> (8 * i));
			else result[4 + i] = static_cast <uint8_t> (nonce >> (8 * (7 - i)));
		}
	}
};

/**
 * @brief Метод шифрования с явным счётчиком
 *
 * @param nonce      счётчик вложений
 * @param associated сопутствующие данные
 * @param source     открытые данные
 * @param result     место шифротекста
 * @param tag        место метки в TAG байтов
 * @return           признак того, что данные зашифрованы
 *
 */
bool nts::noise::Cipher::seal(const uint64_t nonce, const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) const noexcept {
	// Если ключа нет, счётчик запретен, длины либо места негодны
	if(!this->_has || (nonce == FORBIDDEN) || (tag == nullptr) || (source.size > (MESSAGE - TAG)) || ((source.size > 0) && ((source.data == nullptr) || (result == nullptr))) || ((associated.size > 0) && (associated.data == nullptr)))
		// Выводим отрицательный результат - печать невозможна
		return false;
	// Нонс
	uint8_t iv[NONCE];
	// Заполняем нонс
	fill(this->_aead, nonce, iv);
	// Признак успешности
	bool status = false;
	/**
	 * Выбираем шифр по установленному виду AEAD
	 */
	switch(this->_aead){
		// ChaCha20-Poly1305
		case aead_t::CHACHAPOLY: {
			// Объект шифра
			cipher::chachapoly_t aead;
			// Заводим и шифруем
			status = (aead.start(view_t(this->_key, KEY), view_t(iv, NONCE)) && aead.encrypt(associated, source, result, tag));
		} break;
		// AES-256-GCM
		case aead_t::AESGCM: {
			// Объект режима
			cipher::gcm_t aead;
			// Заводим и шифруем
			status = (aead.start(cipher::block_t(this->_aes), view_t(iv, NONCE), TAG) && aead.encrypt(associated, source, result, tag));
		} break;
		// Прочее
		default: break;
	}
	// Возвращаем итог печати
	return status;
}
/**
 * @brief Метод расшифрования с явным счётчиком
 *
 * @param nonce      счётчик вложений
 * @param associated сопутствующие данные
 * @param source     шифротекст
 * @param tag        метка в TAG байтов
 * @param result     место открытых данных
 * @return           признак того, что данные подлинны и расшифрованы
 *
 */
bool nts::noise::Cipher::open(const uint64_t nonce, const view_t & associated, const view_t & source, const view_t & tag, uint8_t * result) const noexcept {
	// Если ключа нет, счётчик запретен, длины либо места негодны
	if(!this->_has || (nonce == FORBIDDEN) || (tag.data == nullptr) || (tag.size != TAG) || (source.size > (MESSAGE - TAG)) || ((source.size > 0) && ((source.data == nullptr) || (result == nullptr))) || ((associated.size > 0) && (associated.data == nullptr)))
		// Выводим отрицательный результат - вскрытие невозможно
		return false;
	// Нонс
	uint8_t iv[NONCE];
	// Заполняем нонс
	fill(this->_aead, nonce, iv);
	// Признак успешности
	bool status = false;
	/**
	 * Выбираем шифр по установленному виду AEAD
	 */
	switch(this->_aead){
		// ChaCha20-Poly1305
		case aead_t::CHACHAPOLY: {
			// Объект шифра
			cipher::chachapoly_t aead;
			// Заводим и расшифровываем
			status = (aead.start(view_t(this->_key, KEY), view_t(iv, NONCE)) && aead.decrypt(associated, source, result, tag));
		} break;
		// AES-256-GCM
		case aead_t::AESGCM: {
			// Объект режима
			cipher::gcm_t aead;
			// Заводим и расшифровываем
			status = (aead.start(cipher::block_t(this->_aes), view_t(iv, NONCE), TAG) && aead.decrypt(associated, source, result, tag));
		} break;
		// Прочее
		default: break;
	}
	// Если подлинность не сошлась, выход обнуляется - кроме вскрытия на месте, где выход и есть вход вызывающего
	if(!status && (result != nullptr) && (result != source.data) && (source.size > 0))
		// Обнуляем выход от частично расшифрованных данных
		::memset(result, 0, source.size);
	// Возвращаем итог вскрытия
	return status;
}
/**
 * @brief Метод установки функции шифрования
 *
 * @param aead функция шифрования с подлинностью
 * @return     признак того, что функция поддержана
 *
 */
bool nts::noise::Cipher::start(const aead_t aead) noexcept {
	// Если функция не поддержана
	if((aead != aead_t::CHACHAPOLY) && (aead != aead_t::AESGCM))
		// Выводим отрицательный результат - функция не поддержана
		return false;
	// Затираем прежнее состояние
	this->clear();
	// Запоминаем функцию
	this->_aead = aead;
	// Сообщаем об успешном заведении
	return true;
}
/**
 * @brief Метод установки ключа (InitializeKey): счётчик обнуляется
 *
 * @param key ключ в KEY байтов
 * @return    признак того, что ключ установлен
 *
 */
bool nts::noise::Cipher::key(const view_t & key) noexcept {
	// Если функция не установлена либо ключ негоден
	if((this->_aead == aead_t::NONE) || (key.data == nullptr) || (key.size != KEY))
		// Выводим отрицательный результат - ключ не принят
		return false;
	// Затираем прежний ключ
	wipe(this->_key, KEY);
	// Запоминаем ключ
	::memcpy(this->_key, key.data, KEY);
	// Если функция AESGCM, разворачиваем ключ AES
	if((this->_aead == aead_t::AESGCM) && !this->_aes.key(view_t(this->_key, KEY))){
		// Затираем ключ
		wipe(this->_key, KEY);
		// Снимаем признак ключа
		this->_has = false;
		// Выводим отрицательный результат - ключ не установлен
		return false;
	}
	// Устанавливаем признак ключа
	this->_has = true;
	// Сбрасываем счётчик
	this->_nonce = 0;
	// Сообщаем об успешной установке ключа
	return true;
}
/**
 * @brief Метод выдачи ключа наружу (для таблиц пар WireGuard)
 *
 * @param result место ключа в KEY байтов
 * @return       признак того, что ключ есть и выдан
 *
 */
bool nts::noise::Cipher::key(uint8_t * result) const noexcept {
	// Если ключа нет либо места нет
	if(!this->_has || (result == nullptr))
		// Выводим отрицательный результат - ключ не выдан
		return false;
	// Выдаём ключ
	::memcpy(result, this->_key, KEY);
	// Сообщаем об успешной выдаче ключа
	return true;
}
/**
 * @brief Метод проверки наличия ключа (HasKey)
 *
 * @return признак того, что ключ установлен
 *
 */
bool nts::noise::Cipher::has() const noexcept {
	// Выводим признак
	return this->_has;
}
/**
 * @brief Метод получения счётчика вложений
 *
 * @return счётчик вложений
 * @param nonce nonce counter
 * @param nonce nonce counter
 *
 */
uint64_t nts::noise::Cipher::nonce() const noexcept {
	// Выводим счётчик
	return this->_nonce;
}
/**
 * @brief Метод установки счётчика вложений (SetNonce)
 *
 * @param nonce счётчик вложений, 2^64-1 запретно
 * @return      признак того, что счётчик установлен
 *
 */
bool nts::noise::Cipher::nonce(const uint64_t nonce) noexcept {
	// Если значение запретно
	if(nonce == FORBIDDEN)
		// Выводим отрицательный результат - счётчик не установлен
		return false;
	// Устанавливаем счётчик
	this->_nonce = nonce;
	// Сообщаем об успешной установке счётчика
	return true;
}
/**
 * @brief Метод шифрования по счётчику (EncryptWithAd): счётчик растёт на единицу
 *
 * @param associated сопутствующие данные
 * @param source     открытые данные, не длиннее MESSAGE - TAG
 * @param result     место шифротекста той же длины
 * @param tag        место метки в TAG байтов
 * @return           признак того, что данные зашифрованы
 *
 */
bool nts::noise::Cipher::encrypt(const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) noexcept {
	// Если шифрование по текущему счётчику не удалось
	if(!this->seal(this->_nonce, associated, source, result, tag))
		// Выводим отрицательный результат - шифрование не выполнено
		return false;
	// Растим счётчик
	this->_nonce++;
	// Сообщаем об успешном шифровании
	return true;
}
/**
 * @brief Метод расшифрования по счётчику (DecryptWithAd): счётчик растёт только при подлинности
 *
 * @param associated сопутствующие данные
 * @param source     шифротекст, не длиннее MESSAGE - TAG
 * @param tag        метка в TAG байтов
 * @param result     место открытых данных той же длины
 * @return           признак того, что данные подлинны и расшифрованы
 *
 */
bool nts::noise::Cipher::decrypt(const view_t & associated, const view_t & source, const view_t & tag, uint8_t * result) noexcept {
	// Если расшифрование по текущему счётчику не удалось, счётчик остаётся
	if(!this->open(this->_nonce, associated, source, tag, result))
		// Выводим отрицательный результат - расшифрование не выполнено
		return false;
	// Растим счётчик
	this->_nonce++;
	// Сообщаем об успешном расшифровании
	return true;
}
/**
 * @brief Метод шифрования с явным счётчиком: внутренний счётчик не трогается
 *
 * @param nonce      счётчик вложений, 2^64-1 запретно
 * @param associated сопутствующие данные
 * @param source     открытые данные
 * @param result     место шифротекста
 * @param tag        место метки в TAG байтов
 * @return           признак того, что данные зашифрованы
 *
 */
bool nts::noise::Cipher::encrypt(const uint64_t nonce, const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) const noexcept {
	// Выводим итог шифрования по явному счётчику
	return this->seal(nonce, associated, source, result, tag);
}
/**
 * @brief Метод расшифрования с явным счётчиком: внутренний счётчик не трогается
 *
 * @param nonce      счётчик вложений, 2^64-1 запретно
 * @param associated сопутствующие данные
 * @param source     шифротекст
 * @param tag        метка в TAG байтов
 * @param result     место открытых данных
 * @return           признак того, что данные подлинны и расшифрованы
 *
 */
bool nts::noise::Cipher::decrypt(const uint64_t nonce, const view_t & associated, const view_t & source, const view_t & tag, uint8_t * result) const noexcept {
	// Выводим итог расшифрования по явному счётчику
	return this->open(nonce, associated, source, tag, result);
}
/**
 * @brief Метод перевыработки ключа (Rekey): k = ENCRYPT(k, 2^64-1, пусто, нули); счётчик не сбрасывается
 *
 * @return признак того, что ключ перевыработан
 *
 */
bool nts::noise::Cipher::rekey() noexcept {
	// Если ключа нет
	if(!this->_has)
		// Выводим отрицательный результат - перевыработка невозможна
		return false;
	// Нули, новый ключ и отбрасываемая метка
	uint8_t zeros[KEY], fresh[KEY], tag[TAG];
	// Заполняем нули
	::memset(zeros, 0, KEY);
	// Нонс запретного значения: заполняется напрямую, минуя запрет счётчика
	uint8_t iv[NONCE];
	// Заполняем нонс
	fill(this->_aead, FORBIDDEN, iv);
	// Признак успешности
	bool status = false;
	/**
	 * Выбираем шифр для выработки нового ключа
	 */
	switch(this->_aead){
		// ChaCha20-Poly1305
		case aead_t::CHACHAPOLY: {
			// Объект шифра
			cipher::chachapoly_t aead;
			// Заводим и шифруем нули
			status = (aead.start(view_t(this->_key, KEY), view_t(iv, NONCE)) && aead.encrypt(view_t(), view_t(zeros, KEY), fresh, tag));
		} break;
		// AES-256-GCM
		case aead_t::AESGCM: {
			// Объект режима
			cipher::gcm_t aead;
			// Заводим и шифруем нули
			status = (aead.start(cipher::block_t(this->_aes), view_t(iv, NONCE), TAG) && aead.encrypt(view_t(), view_t(zeros, KEY), fresh, tag));
		} break;
		// Прочее
		default: break;
	}
	// Счётчик сохраняется: ключ ставится в обход установки
	const uint64_t nonce = this->_nonce;
	// Если шифрование удалось, ставим новый ключ
	status = (status && this->key(view_t(fresh, KEY)));
	// Восстанавливаем счётчик
	this->_nonce = nonce;
	// Затираем новый ключ и метку
	wipe(fresh, KEY);
	wipe(tag, TAG);
	// Возвращаем итог перевыработки
	return status;
}
/**
 * @brief Метод затирания состояния
 *
 */
void nts::noise::Cipher::clear() noexcept {
	// Затираем ключ
	wipe(this->_key, KEY);
	// Затираем развёрнутый ключ AES
	this->_aes.clear();
	// Сбрасываем признак ключа
	this->_has = false;
	// Сбрасываем счётчик
	this->_nonce = 0;
}
/**
 * @brief Конструктор
 *
 */
nts::noise::Cipher::Cipher() noexcept : _aead(aead_t::NONE), _has(false), _nonce(0) {
	// Обнуляем ключ
	::memset(this->_key, 0, KEY);
}
/**
 * @brief Деструктор
 *
 */
nts::noise::Cipher::~Cipher() noexcept {
	// Затираем состояние
	this->clear();
}
