/**
 * @file chachapoly.cpp
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
 * @brief Шифрование с проверкой целостности AEAD_CHACHA20_POLY1305 по RFC 8439
 *
 * @details Поток ведётся теми же ступенями, что у GCM: связанные данные, данные,
 *          закрыт. На переходе к данным связанные данные дополняются нулями до
 *          16 байтов, на завершении так же дополняется шифртекст, и в имитовставку
 *          уходят длины обоих по 64 разряда от младшего байта. Ключ Poly1305
 *          вырабатывается на каждом сбросе потока блоком ChaCha20 на счётчике ноль,
 *          после чего шифр стоит на счётчике один - там и начинаются данные
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
#include <cipher/chachapoly.hpp>
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
	using namespace nts::cipher;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
	/**
	 * @brief Функция записи слова в 64 разряда от младшего байта
	 *
	 * @param value записываемое слово
	 * @param data  место, в которое записываются байты
	 *
	 */
	static void store(const uint64_t value, uint8_t * data) noexcept {
		/**
		 * Выполняем перебор байтов слова
		 */
		for(size_t i = 0; i < 8; i++)
			// Записываем очередной байт от младшего
			data[i] = static_cast <uint8_t> (value >> (i * 8));
	}
	/**
	 * @brief Функция сличения двух областей байтов за постоянное время
	 *
	 * @param first  первая область
	 * @param second вторая область
	 * @param size   размер областей
	 * @return       признак совпадения областей
	 *
	 */
	static bool same(const uint8_t * first, const uint8_t * second, const size_t size) noexcept {
		// Накопленное различие
		uint8_t difference = 0;
		/**
		 * Выполняем перебор байтов областей
		 */
		for(size_t i = 0; i < size; i++)
			// Накапливаем различие байтов
			difference = static_cast <uint8_t> (difference | (first[i] ^ second[i]));
		// Выводим признак отсутствия различий
		return (difference == 0);
	}
};

/**
 * @brief Метод дополнения имитовставки нулями до целого блока
 *
 * @param size длина поданных байтов, по которой считается дополнение
 * @return     признак успешности дополнения
 *
 */
bool nts::cipher::Chachapoly::pad(const uint64_t size) noexcept {
	// Число байтов сверх целого блока
	const size_t rest = static_cast <size_t> (size % POLY1305_TAG);
	// Если поданные байты кратны блоку
	if(rest == 0)
		// Дополнение не нужно
		return true;
	// Нули дополнения
	static const uint8_t zeros[POLY1305_TAG] = {0};
	// Выводим итог подачи дополнения
	return this->_mac.update(view_t(zeros, POLY1305_TAG - rest));
}
/**
 * @brief Метод вычисления метки целостности по накопленному потоку
 *
 * @param result место в 16 байтов, в которое записывается метка
 * @return       признак успешности вычисления
 *
 */
bool nts::cipher::Chachapoly::authenticate(uint8_t * result) noexcept {
	// Если шифртекст дополнить не удалось
	if(!this->pad(this->_sealed))
		// Выводим отказ вычисления
		return false;
	// Блок длин: связанные данные и шифртекст в байтах от младшего байта
	uint8_t lengths[16];
	// Записываем длину связанных данных
	store(this->_associated, lengths);
	// Записываем длину шифртекста
	store(this->_sealed, lengths + 8);
	// Если блок длин подать не удалось
	if(!this->_mac.update(view_t(lengths, sizeof(lengths))))
		// Выводим отказ вычисления
		return false;
	// Выводим итог снятия метки
	return this->_mac.finish(result);
}
/**
 * @brief Метод сброса состояния потока
 *
 * @return признак успешности сброса
 *
 */
bool nts::cipher::Chachapoly::reset() noexcept {
	// Сбрасываем ступень потока
	this->_stage = 0;
	// Сбрасываем направление потока
	this->_direction = 0;
	// Сбрасываем длину связанных данных
	this->_associated = 0;
	// Сбрасываем длину шифртекста
	this->_sealed = 0;
	// Если режим не заведён, ключа нет и заводить нечего
	if(!this->_ready){
		// Сбрасываем шифр
		this->_cipher.clear();
		// Сбрасываем имитовставку
		this->_mac.clear();
		// Выводим успешность сброса
		return true;
	}
	// Если шифр запустить не удалось
	if(!this->_cipher.start(view_t(this->_key, sizeof(this->_key)), view_t(this->_nonce, sizeof(this->_nonce)), 0))
		// Выводим отказ сброса
		return false;
	// Блок гаммы на счётчике ноль: первые 32 байта - ключ имитовставки
	uint8_t block[CHACHA_BLOCK];
	// Если блок выработать не удалось
	if(!this->_cipher.block(block)){
		// Выполняем затирание блока
		wipe(block, sizeof(block));
		// Выводим отказ сброса
		return false;
	}
	// Признак запуска имитовставки одноразовым ключом
	const bool started = this->_mac.start(view_t(block, POLY1305_KEY));
	// Выполняем затирание блока
	wipe(block, sizeof(block));
	// Выводим итог запуска имитовставки
	return started;
}
/**
 * @brief Метод перехода потока к данным
 *
 * @param direction направление потока: единица - зашифрование, двойка - расшифрование
 * @return          признак допустимости перехода
 *
 */
bool nts::cipher::Chachapoly::proceed(const uint8_t direction) noexcept {
	/**
	 * Выполняем разбор ступени потока
	 */
	switch(this->_stage){
		// Если поток на связанных данных либо ещё не начат
		case 0:
		case 1: {
			// Если направление - зашифрование, а заполнение израсходовано
			if((direction == 1) && this->_spent)
				// Выводим недопустимость перехода
				return false;
			// Если направление - зашифрование
			if(direction == 1)
				// Запоминаем, что заполнение израсходовано
				this->_spent = true;
			// Если связанные данные дополнить не удалось
			if(!this->pad(this->_associated))
				// Выводим недопустимость перехода
				return false;
			// Запоминаем направление потока
			this->_direction = direction;
			// Переводим поток на данные
			this->_stage = 2;
			// Выводим допустимость перехода
			return true;
		}
		// Если поток на данных
		case 2:
			// Выводим допустимость лишь того же направления
			return (this->_direction == direction);
	}
	// Поток закрыт: перехода нет
	return false;
}
/**
 * @brief Метод проверки готовности режима к работе
 *
 * @return признак готовности режима
 *
 */
bool nts::cipher::Chachapoly::ready() const noexcept {
	// Выводим признак готовности режима
	return this->_ready;
}
/**
 * @brief Метод получения длины метки целостности
 *
 * @return длина метки в байтах: всегда 16
 *
 */
size_t nts::cipher::Chachapoly::size() const noexcept {
	// Выводим длину метки целостности
	return CHACHAPOLY_TAG;
}
/**
 * @brief Метод запуска режима
 *
 * @param key   ключ в 32 байта
 * @param nonce начальное заполнение в 12 байтов либо в 24 байта (XChaCha20-Poly1305, draft-irtf-cfrg-xchacha)
 * @return      признак успешности запуска
 *
 */
bool nts::cipher::Chachapoly::start(const view_t & key, const view_t & nonce) noexcept {
	// Выполняем сброс прежнего состояния
	this->clear();
	// Если ключ либо заполнение не той длины либо не переданы
	if((key.data == nullptr) || (key.size != CHACHA_KEY) || (nonce.data == nullptr) || ((nonce.size != CHACHA_NONCE) && (nonce.size != CHACHA_XNONCE)))
		// Выводим отказ запуска
		return false;
	// Если заполнение в 24 байта: XChaCha20-Poly1305 - подключ HChaCha20, заполнение из нулей и хвоста
	if(nonce.size == CHACHA_XNONCE){
		// Если подключ вывести не удалось
		if(!Chacha::hchacha(key, view_t(nonce.data, HCHACHA_NONCE), this->_key))
			// Выводим отказ запуска
			return false;
		// Обнуляем начало заполнения
		::memset(this->_nonce, 0, 4);
		// Переносим хвост заполнения
		::memcpy(this->_nonce + 4, nonce.data + HCHACHA_NONCE, 8);
	// Иначе ключ и заполнение как есть
	} else {
		// Переносим ключ
		::memcpy(this->_key, key.data, sizeof(this->_key));
		// Переносим заполнение
		::memcpy(this->_nonce, nonce.data, sizeof(this->_nonce));
	}
	// Запоминаем готовность режима: сброс потока заводит шифр и имитовставку
	this->_ready = true;
	// Если поток сбросить не удалось
	if(!this->reset()){
		// Выполняем сброс режима
		this->clear();
		// Выводим отказ запуска
		return false;
	}
	// Выводим успешность запуска
	return true;
}
/**
 * @brief Метод смены начального заполнения у запущенного режима
 *
 * @param nonce начальное заполнение в 12 байтов
 * @return      признак успешности смены
 *
 */
bool nts::cipher::Chachapoly::restart(const view_t & nonce) noexcept {
	// Если режим не запущен: ключа нет
	if(!this->_ready)
		// Выводим отказ смены заполнения
		return false;
	// Если заполнение не передано либо не той длины: смена ведётся лишь по заполнению в 12 байтов
	if((nonce.data == nullptr) || (nonce.size != CHACHA_NONCE))
		// Выводим отказ смены заполнения
		return false;
	// Заполнение новое: прежнее израсходованным более не считается
	this->_spent = false;
	// Переносим заполнение
	::memcpy(this->_nonce, nonce.data, sizeof(this->_nonce));
	// Выполняем сброс состояния потока от нового заполнения: шифр и одноразовый ключ имитовставки заводятся заново
	return this->reset();
}
/**
 * @brief Метод сброса режима
 *
 */
void nts::cipher::Chachapoly::clear() noexcept {
	// Сбрасываем признак готовности
	this->_ready = false;
	// Сбрасываем признак израсходованного заполнения
	this->_spent = false;
	// Выполняем затирание ключа
	wipe(this->_key, sizeof(this->_key));
	// Выполняем затирание заполнения
	wipe(this->_nonce, sizeof(this->_nonce));
	// Выполняем сброс состояния потока: без ключа он лишь затирает шифр и имитовставку
	this->reset();
}
/**
 * @brief Метод подачи связанных данных потока
 *
 * @param associated связанные данные, защищаемые лишь меткой
 * @return           признак успешности подачи
 *
 */
bool nts::cipher::Chachapoly::associate(const view_t & associated) noexcept {
	// Если режим не готов либо поток уже перешёл к данным
	if(!this->_ready || (this->_stage > 1))
		// Выводим отказ подачи
		return false;
	// Если связанные данные объявлены непустыми, но не переданы
	if((associated.size > 0) && (associated.data == nullptr))
		// Выводим отказ подачи
		return false;
	// Переводим поток на связанные данные
	this->_stage = 1;
	// Если связанные данные подать имитовставке не удалось
	if(!this->_mac.update(associated))
		// Выводим отказ подачи
		return false;
	// Увеличиваем длину связанных данных
	this->_associated += static_cast <uint64_t> (associated.size);
	// Выводим успешность подачи
	return true;
}
/**
 * @brief Метод поточного зашифрования куска
 *
 * @param source открытый текст
 * @param result место, в которое записывается шифртекст той же длины
 * @return       признак успешности зашифрования
 *
 */
bool nts::cipher::Chachapoly::encrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов
	if(!this->_ready)
		// Выводим отказ зашифрования
		return false;
	// Если текст объявлен непустым, но не передан
	if((source.size > 0) && ((source.data == nullptr) || (result == nullptr)))
		// Выводим отказ зашифрования
		return false;
	// Если переход потока к зашифрованию недопустим
	if(!this->proceed(1))
		// Выводим отказ зашифрования
		return false;
	// Если гамму наложить не удалось
	if(!this->_cipher.encrypt(source, result)){
		// Закрываем поток
		this->_stage = 3;
		// Выводим отказ зашифрования
		return false;
	}
	// Если шифртекст подать имитовставке не удалось
	if(!this->_mac.update(view_t(result, source.size))){
		// Закрываем поток
		this->_stage = 3;
		// Выводим отказ зашифрования
		return false;
	}
	// Увеличиваем длину шифртекста
	this->_sealed += static_cast <uint64_t> (source.size);
	// Выводим успешность зашифрования
	return true;
}
/**
 * @brief Метод поточного расшифрования куска
 *
 * @param source шифртекст
 * @param result место, в которое записывается открытый текст той же длины
 * @return       признак успешности расшифрования
 *
 */
bool nts::cipher::Chachapoly::decrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов
	if(!this->_ready)
		// Выводим отказ расшифрования
		return false;
	// Если текст объявлен непустым, но не передан
	if((source.size > 0) && ((source.data == nullptr) || (result == nullptr)))
		// Выводим отказ расшифрования
		return false;
	// Если переход потока к расшифрованию недопустим
	if(!this->proceed(2))
		// Выводим отказ расшифрования
		return false;
	// Если шифртекст подать имитовставке не удалось
	if(!this->_mac.update(source)){
		// Закрываем поток
		this->_stage = 3;
		// Выводим отказ расшифрования
		return false;
	}
	// Увеличиваем длину шифртекста
	this->_sealed += static_cast <uint64_t> (source.size);
	// Если гамму снять не удалось
	if(!this->_cipher.decrypt(source, result)){
		// Выполняем затирание неполного открытого текста
		wipe(result, source.size);
		// Закрываем поток
		this->_stage = 3;
		// Выводим отказ расшифрования
		return false;
	}
	// Выводим успешность расшифрования
	return true;
}
/**
 * @brief Метод завершения поточного зашифрования выработкой метки
 *
 * @param tag место, в которое записывается метка в 16 байтов
 * @return    признак успешности завершения; поток закрывается
 *
 */
bool nts::cipher::Chachapoly::finish(uint8_t * tag) noexcept {
	// Если режим не готов либо места под метку нет
	if(!this->_ready || (tag == nullptr))
		// Выводим отказ завершения
		return false;
	// Если переход потока к зашифрованию недопустим: пустой текст тоже расходует заполнение
	if(!this->proceed(1))
		// Выводим отказ завершения
		return false;
	// Закрываем поток
	this->_stage = 3;
	// Выводим итог вычисления метки
	return this->authenticate(tag);
}
/**
 * @brief Метод завершения поточного расшифрования сличением метки
 *
 * @param tag проверяемая метка в 16 байтов
 * @return    признак схождения метки за постоянное время; поток закрывается
 *
 */
bool nts::cipher::Chachapoly::verify(const view_t & tag) noexcept {
	// Если режим не готов либо метка не установленной длины
	if(!this->_ready || (tag.data == nullptr) || (tag.size != CHACHAPOLY_TAG))
		// Выводим отказ сличения
		return false;
	// Если переход потока к расшифрованию недопустим
	if(!this->proceed(2))
		// Выводим отказ сличения
		return false;
	// Закрываем поток
	this->_stage = 3;
	// Вычисленная метка
	uint8_t buffer[CHACHAPOLY_TAG];
	// Если метку вычислить не удалось
	if(!this->authenticate(buffer)){
		// Выполняем затирание метки
		wipe(buffer, sizeof(buffer));
		// Выводим отказ сличения
		return false;
	}
	// Признак схождения метки за постоянное время
	const bool matched = same(buffer, tag.data, CHACHAPOLY_TAG);
	// Выполняем затирание вычисленной метки
	wipe(buffer, sizeof(buffer));
	// Выводим признак схождения метки
	return matched;
}
/**
 * @brief Метод зашифрования с выработкой метки целостности
 *
 * @param associated связанные данные, защищаемые лишь меткой
 * @param source     открытый текст
 * @param result     место, в которое записывается шифртекст той же длины
 * @param tag        место, в которое записывается метка в 16 байтов
 * @return           признак успешности зашифрования
 *
 */
bool nts::cipher::Chachapoly::encrypt(const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) noexcept {
	// Если режим не готов, либо места под метку нет, либо заполнение израсходовано
	if(!this->_ready || (tag == nullptr) || this->_spent)
		// Выводим отказ зашифрования
		return false;
	// Если текст объявлен непустым, но не передан
	if((source.size > 0) && ((source.data == nullptr) || (result == nullptr)))
		// Выводим отказ зашифрования
		return false;
	// Если связанные данные объявлены непустыми, но не переданы
	if((associated.size > 0) && (associated.data == nullptr))
		// Выводим отказ зашифрования
		return false;
	// Если поток сбросить не удалось: разовый вызов не зависит от прежнего
	if(!this->reset())
		// Выводим отказ зашифрования
		return false;
	// Если связанные данные подать не удалось
	if(!this->associate(associated))
		// Выводим отказ зашифрования
		return false;
	// Если текст зашифровать не удалось
	if(!this->encrypt(source, result))
		// Выводим отказ зашифрования
		return false;
	// Выводим итог выработки метки
	return this->finish(tag);
}
/**
 * @brief Метод расшифрования с проверкой метки целостности
 *
 * @param associated связанные данные
 * @param source     шифртекст
 * @param result     место, в которое записывается открытый текст той же длины
 * @param tag        проверяемая метка в 16 байтов
 * @return           признак схождения метки; при расхождении открытый текст не тронут
 *
 */
bool nts::cipher::Chachapoly::decrypt(const view_t & associated, const view_t & source, uint8_t * result, const view_t & tag) noexcept {
	// Если режим не готов либо метка не установленной длины
	if(!this->_ready || (tag.data == nullptr) || (tag.size != CHACHAPOLY_TAG))
		// Выводим отказ расшифрования
		return false;
	// Если текст объявлен непустым, но не передан
	if((source.size > 0) && ((source.data == nullptr) || (result == nullptr)))
		// Выводим отказ расшифрования
		return false;
	// Если связанные данные объявлены непустыми, но не переданы
	if((associated.size > 0) && (associated.data == nullptr))
		// Выводим отказ расшифрования
		return false;
	// Если поток сбросить не удалось: разовый вызов не зависит от прежнего
	if(!this->reset())
		// Выводим отказ расшифрования
		return false;
	// Если связанные данные подать не удалось
	if(!this->associate(associated))
		// Выводим отказ расшифрования
		return false;
	/**
	 * Метка сличается прежде снятия гаммы, чтобы при расхождении не раскрыть ни
	 * байта: шифртекст подаётся имитовставке без наложения гаммы, а гамма снимается
	 * лишь после схождения метки шифром, стоящим на счётчике один
	 */
	if(!this->proceed(2))
		// Выводим отказ расшифрования
		return false;
	// Если шифртекст подать имитовставке не удалось
	if(!this->_mac.update(source))
		// Выводим отказ расшифрования
		return false;
	// Увеличиваем длину шифртекста
	this->_sealed += static_cast <uint64_t> (source.size);
	// Если метка не сошлась
	if(!this->verify(tag))
		// Выводим отказ расшифрования, не раскрывая ни байта
		return false;
	// Если гамму снять не удалось
	if(!this->_cipher.decrypt(source, result)){
		// Выполняем затирание неполного открытого текста
		wipe(result, source.size);
		// Выводим отказ расшифрования
		return false;
	}
	// Выводим успешность расшифрования
	return true;
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Chachapoly::Chachapoly() noexcept : _ready(false), _spent(false), _stage(0), _direction(0), _associated(0), _sealed(0) {
	// Выполняем затирание ключа
	wipe(this->_key, sizeof(this->_key));
	// Выполняем затирание заполнения
	wipe(this->_nonce, sizeof(this->_nonce));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Chachapoly::~Chachapoly() noexcept {
	// Выполняем сброс режима
	this->clear();
}
