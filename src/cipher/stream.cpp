/**
 * @file stream.cpp
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
 * @brief Поточная обёртка шифрования: вектор в голове потока, метка GCM в хвосте
 *
 * @details Голова и хвост потока служебные. При расшифровании вектор копится из
 *          первых байтов, а последние байты длиной метки удерживаются в хвосте: до
 *          завершения неизвестно, данные это или метка, оттого наружу уходит лишь то,
 *          что метку заведомо не задевает. Итог дописывается в накопитель вызывающего,
 *          и нехватка памяти у него отвечает отказом
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
#include <cipher/stream.hpp>
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

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
};

/**
 * @brief Метод пропуска куска через режим с дописыванием в выход
 *
 * @param source пропускаемый кусок
 * @param result накопитель выхода, в который дописывается итог
 *
 * @return       признак успешности пропуска
 *
 */
bool nts::cipher::Stream::pass(const view_t & source, vector <uint8_t> & result) noexcept {
	// Если кусок пуст
	if(source.size == 0)
		// Выводим успешность пропуска: выдача пуста
		return true;
	// Прежняя длина накопителя выхода
	const size_t offset = result.size();
	/**
	 * Накопитель выхода растёт под кусок: нехватка памяти отвечает отказом
	 */
	try {
		// Выполняем рост накопителя под кусок
		result.resize(offset + source.size);
	/**
	 * Если памяти под накопитель не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ пропуска
		return false;
	}
	// Место записи итога
	uint8_t * output = (result.data() + offset);
	// Признак успешности пропуска
	bool passed = false;
	/**
	 * Выполняем разбор режима потока
	 */
	switch(static_cast <uint8_t> (this->_mode)){
		// Если режим гаммирования с обратной связью
		case static_cast <uint8_t> (regime_t::FEEDBACK):
			// Пропускаем кусок по направлению потока
			passed = ((this->_direction == direction_t::ENCRYPT) ? this->_feedback.encrypt(source, output) : this->_feedback.decrypt(source, output));
		break;
		// Если режим GCM
		case static_cast <uint8_t> (regime_t::GCM):
			// Пропускаем кусок по направлению потока
			passed = ((this->_direction == direction_t::ENCRYPT) ? this->_gcm.encrypt(source, output) : this->_gcm.decrypt(source, output));
		break;
	}
	// Если пропуск не удался
	if(!passed){
		// Выполняем затирание недописанного итога
		wipe(output, source.size);
		// Возвращаем накопителю прежнюю длину
		result.resize(offset);
		// Выводим отказ пропуска
		return false;
	}
	// Выводим успешность пропуска
	return true;
}
/**
 * @brief Метод запуска режима на собранном векторе
 *
 * @return признак успешности запуска
 *
 */
bool nts::cipher::Stream::launch() noexcept {
	/**
	 * Выполняем разбор режима потока
	 */
	switch(static_cast <uint8_t> (this->_mode)){
		// Если режим гаммирования с обратной связью
		case static_cast <uint8_t> (regime_t::FEEDBACK):
			// Выводим итог запуска режима на векторе длиной в блок
			return this->_feedback.start(this->_block, view_t(this->_vector, this->_head));
		// Если режим GCM
		case static_cast <uint8_t> (regime_t::GCM):
			// Выводим итог запуска режима на векторе с установленной длиной метки
			return this->_gcm.start(this->_block, view_t(this->_vector, this->_head), this->_tag);
	}
	// Выводим отказ запуска
	return false;
}
/**
 * @brief Метод проверки готовности потока к работе
 *
 * @return признак готовности потока
 *
 */
bool nts::cipher::Stream::ready() const noexcept {
	// Выводим признак готовности потока
	return this->_ready;
}
/**
 * @brief Метод заведения потока
 *
 * @param direction направление потока
 * @param block     блочный шифр с блоком в 16 байтов и установленным ключом
 * @param mode      режим шифрования потока
 * @param tag       длина метки GCM от 4 до 16 байтов, у режима без метки не учитывается
 *
 * @return          признак успешности заведения
 *
 */
bool nts::cipher::Stream::start(const direction_t direction, const block_t & block, const regime_t mode, const size_t tag) noexcept {
	// Выполняем сброс прежнего потока
	this->clear();
	// Если направление не установлено
	if((direction != direction_t::ENCRYPT) && (direction != direction_t::DECRYPT))
		// Выводим отказ заведения
		return false;
	// Если режим не установлен
	if((mode != regime_t::FEEDBACK) && (mode != regime_t::GCM))
		// Выводим отказ заведения
		return false;
	// Если шифр не с блоком в 16 байтов либо без ключа
	if((block.size != MODE_BLOCK) || (block.cipher == nullptr) || (block.encrypt == nullptr))
		// Выводим отказ заведения
		return false;
	// Если у GCM длина метки негодна
	if((mode == regime_t::GCM) && ((tag < 4) || (tag > GCM_TAG)))
		// Выводим отказ заведения
		return false;
	// Запоминаем направление потока
	this->_direction = direction;
	// Запоминаем режим потока
	this->_mode = mode;
	// Запоминаем базовый шифр
	this->_block = block;
	// Запоминаем длину метки: у режима без метки ноль
	this->_tag = ((mode == regime_t::GCM) ? tag : 0);
	// Запоминаем длину вектора: у GCM 12 байтов, у остальных блок
	this->_head = ((mode == regime_t::GCM) ? STREAM_NONCE : block.size);
	// Если поток на зашифрование
	if(direction == direction_t::ENCRYPT){
		// Если вектор из энтропии выработать не удалось
		if(!entropy::bytes(this->_vector, this->_head)){
			// Выполняем сброс потока
			this->clear();
			// Выводим отказ заведения
			return false;
		}
		// Если режим на выработанном векторе не запустился
		if(!this->launch()){
			// Выполняем сброс потока
			this->clear();
			// Выводим отказ заведения
			return false;
		}
	// Иначе вектор придёт из головы потока
	} else {
		/**
		 * Удерживаемый хвост заводится сразу, чтобы подача куска памяти не просила
		 */
		try {
			// Выполняем заготовку места под удерживаемый хвост
			this->_tail.reserve(this->_tag);
		/**
		 * Если памяти под хвост не хватило
		 */
		} catch(const bad_alloc &) {
			// Выполняем сброс потока
			this->clear();
			// Выводим отказ заведения
			return false;
		}
	}
	// Запоминаем готовность потока
	this->_ready = true;
	// Выводим успешность заведения
	return true;
}
/**
 * @brief Метод сброса потока
 *
 */
void nts::cipher::Stream::clear() noexcept {
	// Сбрасываем признак готовности
	this->_ready = false;
	// Сбрасываем признак выданного вектора
	this->_headed = false;
	// Сбрасываем направление потока
	this->_direction = direction_t::NONE;
	// Сбрасываем режим потока
	this->_mode = regime_t::NONE;
	// Сбрасываем длину метки
	this->_tag = 0;
	// Сбрасываем длину вектора
	this->_head = 0;
	// Сбрасываем число накопленных байтов вектора
	this->_gathered = 0;
	// Выполняем затирание вектора
	wipe(this->_vector, sizeof(this->_vector));
	// Если удерживаемый хвост непуст
	if(!this->_tail.empty())
		// Выполняем затирание удерживаемого хвоста
		wipe(this->_tail.data(), this->_tail.size());
	// Сбрасываем удерживаемый хвост, память остаётся за ним
	this->_tail.clear();
	// Сбрасываем базовый шифр
	this->_block = block_t();
	// Выполняем сброс режима гаммирования с обратной связью
	this->_feedback.clear();
	// Выполняем сброс режима GCM
	this->_gcm.clear();
}
/**
 * @brief Метод подачи куска потока
 *
 * @param source кусок любой длины, включая пустой
 * @param result накопитель выхода, в который дописывается итог
 *
 * @return       признак успешности подачи
 *
 */
bool nts::cipher::Stream::update(const view_t & source, vector <uint8_t> & result) noexcept {
	// Если поток не готов
	if(!this->_ready)
		// Выводим отказ подачи
		return false;
	// Если кусок объявлен непустым, но не передан
	if((source.size > 0) && (source.data == nullptr))
		// Выводим отказ подачи
		return false;
	// Если поток на зашифрование
	if(this->_direction == direction_t::ENCRYPT){
		// Если вектор ещё не выдан
		if(!this->_headed){
			/**
			 * Вектор уходит первым в выход: нехватка памяти отвечает отказом
			 */
			try {
				// Дописываем вектор в накопитель выхода
				result.insert(result.end(), this->_vector, this->_vector + this->_head);
			/**
			 * Если памяти под накопитель не хватило
			 */
			} catch(const bad_alloc &) {
				// Выводим отказ подачи
				return false;
			}
			// Запоминаем, что вектор выдан
			this->_headed = true;
		}
		// Итог пропуска куска через режим: отказ закрывает поток
		const bool passed = this->pass(source, result);
		// Если пропустить не удалось
		if(!passed)
			// Закрываем поток
			this->_ready = false;
		// Выводим итог
		return passed;
	}
	// Число ещё не разобранных байтов куска
	size_t left = source.size;
	// Позиция чтения куска
	const uint8_t * cursor = source.data;
	// Если вектор ещё не собран из головы потока
	if(this->_gathered < this->_head){
		// Число байтов, дополняющих вектор
		const size_t taken = (((this->_head - this->_gathered) < left) ? (this->_head - this->_gathered) : left);
		// Переносим байты в вектор
		::memcpy(this->_vector + this->_gathered, cursor, taken);
		// Увеличиваем число накопленных байтов вектора
		this->_gathered += taken;
		// Сдвигаем позицию чтения
		cursor += taken;
		// Уменьшаем число не разобранных байтов
		left -= taken;
		// Если вектор так и не собран
		if(this->_gathered < this->_head)
			// Выводим успешность подачи: выдача пуста
			return true;
		// Если режим на собранном векторе не запустился
		if(!this->launch()){
			// Закрываем поток
			this->_ready = false;
			// Выводим отказ подачи
			return false;
		}
	}
	// Если метки у режима нет
	if(this->_tag == 0){
		// Итог пропуска остатка куска через режим
		const bool passed = this->pass(view_t(cursor, left), result);
		// Если пропустить не удалось
		if(!passed)
			// Закрываем поток
			this->_ready = false;
		// Выводим итог
		return passed;
	}
	// Число байтов, заведомо не задевающих метку
	const size_t release = (((this->_tail.size() + left) > this->_tag) ? ((this->_tail.size() + left) - this->_tag) : 0);
	// Если выдавать нечего
	if(release == 0){
		/**
		 * Кусок целиком ложится в удерживаемый хвост: место под него заготовлено
		 */
		try {
			// Дописываем кусок в удерживаемый хвост
			this->_tail.insert(this->_tail.end(), cursor, cursor + left);
		/**
		 * Если памяти под хвост не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ подачи
			return false;
		}
		// Выводим успешность подачи: выдача пуста
		return true;
	}
	// Число выдаваемых байтов из удерживаемого хвоста
	const size_t held = ((release < this->_tail.size()) ? release : this->_tail.size());
	// Если из хвоста выдаётся хоть байт и пропустить его не удалось: режим уже продвинут, поток негоден
	if((held > 0) && !this->pass(view_t(this->_tail.data(), held), result)){
		// Закрываем поток: повторная подача пропустила бы удержанные байты дважды
		this->_ready = false;
		// Выводим отказ подачи
		return false;
	}
	// Число выдаваемых байтов из куска
	const size_t fresh = (release - held);
	// Если из куска выдаётся хоть байт и пропустить его не удалось
	if((fresh > 0) && !this->pass(view_t(cursor, fresh), result)){
		// Закрываем поток
		this->_ready = false;
		// Выводим отказ подачи
		return false;
	}
	// Если хвост выдан не целиком
	if(held < this->_tail.size())
		// Сдвигаем остаток хвоста к началу
		::memmove(this->_tail.data(), this->_tail.data() + held, this->_tail.size() - held);
	// Выполняем затирание выданной части хвоста
	wipe(this->_tail.data() + (this->_tail.size() - held), held);
	// Укорачиваем хвост на выданное
	this->_tail.resize(this->_tail.size() - held);
	/**
	 * Остаток куска ложится в удерживаемый хвост: длина его теперь ровно метка
	 */
	try {
		// Дописываем остаток куска в удерживаемый хвост
		this->_tail.insert(this->_tail.end(), cursor + fresh, cursor + left);
	/**
	 * Если памяти под хвост не хватило: байты куска потеряны, поток закрывается
	 */
	} catch(const bad_alloc &) {
		// Закрываем поток
		this->_ready = false;
		// Выводим отказ подачи
		return false;
	}
	// Выводим успешность подачи
	return true;
}
/**
 * @brief Метод завершения потока
 *
 * @param result накопитель выхода, в который дописывается хвост
 *
 * @return       признак успешности завершения
 *
 */
bool nts::cipher::Stream::finish(vector <uint8_t> & result) noexcept {
	// Если поток не готов
	if(!this->_ready)
		// Выводим отказ завершения
		return false;
	// Признак успешности завершения
	bool finished = false;
	// Если поток на зашифрование
	if(this->_direction == direction_t::ENCRYPT){
		// Если вектор ещё не выдан: данных не было вовсе
		if(!this->_headed){
			/**
			 * Вектор уходит первым в выход и у пустого потока
			 */
			try {
				// Дописываем вектор в накопитель выхода
				result.insert(result.end(), this->_vector, this->_vector + this->_head);
			/**
			 * Если памяти под накопитель не хватило
			 */
			} catch(const bad_alloc &) {
				// Выводим отказ завершения
				return false;
			}
			// Запоминаем, что вектор выдан
			this->_headed = true;
		}
		// Если метки у режима нет
		if(this->_tag == 0)
			// Завершение сводится к закрытию потока
			finished = true;
		// Иначе метка дописывается в хвост
		else {
			// Полная метка
			uint8_t tag[GCM_TAG];
			// Если метку снять удалось
			if(this->_gcm.finish(tag)){
				/**
				 * Метка дописывается в выход: нехватка памяти отвечает отказом
				 */
				try {
					// Дописываем метку в накопитель выхода
					result.insert(result.end(), tag, tag + this->_tag);
					// Запоминаем успешность завершения
					finished = true;
				/**
				 * Если памяти под накопитель не хватило
				 */
				} catch(const bad_alloc &) {
					// Оставляем отказ завершения
					finished = false;
				}
			}
			// Выполняем затирание метки
			wipe(tag, sizeof(tag));
		}
	// Иначе поток на расшифрование
	} else {
		// Если вектор собран и метки у режима нет
		if((this->_gathered == this->_head) && (this->_tag == 0))
			// Завершение сводится к закрытию потока
			finished = true;
		// Если вектор собран и удержана вся метка
		else if((this->_gathered == this->_head) && (this->_tail.size() == this->_tag))
			// Сличаем удержанную метку
			finished = this->_gcm.verify(view_t(this->_tail.data(), this->_tail.size()));
	}
	// Выполняем сброс потока: завершение закрывает его
	this->clear();
	// Выводим признак успешности завершения
	return finished;
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Stream::Stream() noexcept : _ready(false), _headed(false), _direction(direction_t::NONE), _mode(regime_t::NONE), _tag(0), _head(0), _gathered(0) {
	// Выполняем затирание вектора
	wipe(this->_vector, sizeof(this->_vector));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Stream::~Stream() noexcept {
	// Выполняем сброс потока
	this->clear();
}
