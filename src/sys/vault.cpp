/**
 * @file vault.cpp
 * @date 2026-09-17
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
 * \~russian
 * @brief Исходный файл укрытого хранилища ключевого материала
 *
 * \~english
 * @brief Source file of the sheltered storage of the key material
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Системные заголовочные файлы
 */
#if defined(_WIN32)
	#include <windows.h>
#else
	#include <unistd.h>
	#include <pthread.h>
	#include <sys/mman.h>
#endif

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/vault.hpp>
#include <sys/wipe.hpp>
#include <sys/log.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * \~russian
 * @brief Наименьшая длина куска, берущегося у системы
 *
 * @note Кусок в 64 КБ вмещает ключевой материал сотни связей; меньший дробил бы право
 *       на запрет подкачки впустую, больший тратил бы его наперёд
 *
 * \~english
 * @brief Minimum length of a chunk taken from the system
 */
static constexpr size_t VAULT_CHUNK = 65536;

/**
 * \~russian
 * @brief Выравнивание участка: довольно любому значению ключа и векторных команд
 *
 * \~english
 * @brief Alignment of a piece: enough for any key value and the vector instructions
 */
static constexpr size_t VAULT_ALIGN = 16;

/**
 * \~russian
 * @brief Функция получения длины страницы памяти
 *
 * @return длина страницы памяти в байтах
 *
 * \~english
 * @brief Function of getting the length of the memory page
 * @return the length of the memory page in bytes
 */
static size_t page() noexcept {
	/**
	 * Для операционной системы MS Windows
	 */
	#if defined(_WIN32)
		// Сведения о системе
		SYSTEM_INFO info;
		// Получаем сведения о системе
		::GetSystemInfo(&info);
		// Выводим длину страницы
		return static_cast <size_t> (info.dwPageSize);
	/**
	 * Для операционных систем POSIX
	 */
	#else
		// Запрашиваем длину страницы у системы
		const long result = ::sysconf(_SC_PAGESIZE);
		// Выводим длину страницы, отступая к обычной при отказе
		return ((result > 0) ? static_cast <size_t> (result) : 4096);
	#endif
}

/**
 * \~russian
 * @brief Функция обработки разветвления процесса у потомка
 *
 * @details Там, где система сама не даёт потомку затёртую память, затираем её сами.
 *          Замок хранилища у потомка не берётся: потомок однопоточен, а замок мог
 *          остаться взятым потоком родителя, которого у потомка нет
 *
 * \~english
 * @brief Function of the handling of the fork at the child
 */
static void forked() noexcept {
	// Затираем всю память хранилища у потомка
	sys::Vault::instance().wipe();
}

/**
 * instance Метод получения хранилища процесса
 */
sys::Vault & sys::Vault::instance() noexcept {
	// Хранилище процесса: живёт до завершения процесса
	static Vault vault;
	// Выводим хранилище процесса
	return vault;
}
/**
 * grow Метод взятия куска у системы
 */
bool sys::Vault::grow(const size_t size) noexcept {
	// Длина страницы памяти
	const size_t granule = page();
	// Наименьшая длина куска: не меньше страницы и не меньше запроса
	size_t length = ((size > VAULT_CHUNK) ? size : VAULT_CHUNK);
	// Округляем длину куска вверх до страницы
	length = (((length + granule - 1) / granule) * granule);
	// Кусок памяти
	chunk_t chunk;
	/**
	 * Для операционной системы MS Windows
	 */
	#if defined(_WIN32)
		// Берём кусок у системы, минуя кучу
		chunk.base = static_cast <uint8_t *> (::VirtualAlloc(nullptr, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		// Если кусок не выдан
		if(chunk.base == nullptr)
			// Сообщаем об отказе
			return false;
		// Запрещаем подкачку куска
		chunk.shelter.wired = (::VirtualLock(chunk.base, length) != 0);
		// Разветвления процесса у системы нет: потомку нечего наследовать
		chunk.shelter.forked = true;
		// Укрытия от снимков памяти система не даёт
		chunk.shelter.hidden = false;
		// Если запрет подкачки требуется, а не дан
		if(this->_demand && !chunk.shelter.wired){
			// Возвращаем кусок системе
			::VirtualFree(chunk.base, 0, MEM_RELEASE);
			// Сообщаем в сток журнала об отказе под требованием
			sys::log::emitf(sys::log::level_t::CRITICAL, "A-NTS: vault chunk of %zu bytes refused: swap prohibition demanded but not granted", length);
			// Сообщаем об отказе
			return false;
		}
	/**
	 * Для операционных систем POSIX
	 */
	#else
		// Берём кусок у системы, минуя кучу
		void * result = ::mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		// Если кусок не выдан
		if(result == MAP_FAILED)
			// Сообщаем об отказе
			return false;
		// Запоминаем адрес куска
		chunk.base = static_cast <uint8_t *> (result);
		// Запрещаем подкачку куска: право ограничено пределом RLIMIT_MEMLOCK
		chunk.shelter.wired = (::mlock(chunk.base, length) == 0);
		/**
		 * Укрываем кусок от снимков памяти процесса: у Linux совет MADV_DONTDUMP, у
		 * FreeBSD и DragonFly - MADV_NOCORE; у macOS, NetBSD, OpenBSD и Sun такого нет
		 */
		#if defined(MADV_DONTDUMP)
			chunk.shelter.hidden = (::madvise(chunk.base, length, MADV_DONTDUMP) == 0);
		#elif defined(MADV_NOCORE)
			chunk.shelter.hidden = (::madvise(chunk.base, length, MADV_NOCORE) == 0);
		#else
			chunk.shelter.hidden = false;
		#endif
		/**
		 * Затираем кусок у потомка: у Linux совет MADV_WIPEONFORK, у BSD наследование
		 * INHERIT_ZERO; где нет ни того, ни другого, затирает обработчик pthread_atfork
		 */
		#if defined(MADV_WIPEONFORK)
			chunk.shelter.forked = (::madvise(chunk.base, length, MADV_WIPEONFORK) == 0);
		#elif defined(INHERIT_ZERO)
			chunk.shelter.forked = (::minherit(chunk.base, length, INHERIT_ZERO) == 0);
		#elif defined(MAP_INHERIT_ZERO)
			chunk.shelter.forked = (::minherit(chunk.base, length, MAP_INHERIT_ZERO) == 0);
		#else
			chunk.shelter.forked = false;
		#endif
		// Если система потомка сама не затирает
		if(!chunk.shelter.forked){
			// Если обработчик разветвления ещё не заведён
			if(!this->_guarded)
				// Заводим обработчик разветвления: потомок затирает хранилище сам
				this->_guarded = (::pthread_atfork(nullptr, nullptr, &forked) == 0);
			// Затирание обработчиком - то же укрытие, если он заведён
			chunk.shelter.forked = this->_guarded;
		}
		// Если запрет подкачки требуется, а не дан
		if(this->_demand && !chunk.shelter.wired){
			// Возвращаем кусок системе
			::munmap(chunk.base, length);
			// Сообщаем в сток журнала об отказе под требованием
			sys::log::emitf(sys::log::level_t::CRITICAL, "A-NTS: vault chunk of %zu bytes refused: swap prohibition demanded but not granted", length);
			// Сообщаем об отказе
			return false;
		}
	#endif
	// Запоминаем длину куска
	chunk.size = length;
	// Если укрытие понижено: не отказ, но и не молчание
	if(!chunk.shelter.wired || !chunk.shelter.hidden || !chunk.shelter.forked)
		// Сообщаем в сток журнала, что именно не состоялось
		sys::log::emitf(sys::log::level_t::WARNING, "A-NTS: vault chunk of %zu bytes sheltered partially: wired %s, hidden %s, forked %s", length, (chunk.shelter.wired ? "yes" : "no"), (chunk.shelter.hidden ? "yes" : "no"), (chunk.shelter.forked ? "yes" : "no"));
	/**
	 * Заводим запись куска и его единственный свободный участок: контейнеры берут память у
	 * кучи, и нехватка обращается в отказ взятия
	 */
	try {
		// Заводим свободный участок на весь кусок
		chunk.spans.emplace_back(0, length);
		// Запоминаем кусок
		this->_chunks.push_back(::move(chunk));
	// Перехватываем нехватку памяти
	} catch(const bad_alloc &){
		/**
		 * Для операционной системы MS Windows
		 */
		#if defined(_WIN32)
			// Возвращаем кусок системе
			::VirtualFree(chunk.base, 0, MEM_RELEASE);
		/**
		 * Для операционных систем POSIX
		 */
		#else
			// Возвращаем кусок системе
			::munmap(chunk.base, length);
		#endif
		// Сообщаем об отказе
		return false;
	}
	// Сообщаем об успехе
	return true;
}
/**
 * take Метод взятия участка укрытой памяти
 */
void * sys::Vault::take(const size_t size) noexcept {
	// Если длина участка не задана либо не умещается в выравнивание
	if((size == 0) || (size > (numeric_limits <size_t>::max() - VAULT_ALIGN)))
		// Сообщаем об отказе
		return nullptr;
	// Округляем длину участка вверх до выравнивания
	const size_t length = (((size + VAULT_ALIGN - 1) / VAULT_ALIGN) * VAULT_ALIGN);
	// Берём замок хранилища
	const lock_guard <mutex> lock(this->_lock);
	/**
	 * Ищем свободный участок первой подходящей длины; не найдя - берём новый кусок и ищем
	 * повторно: новый кусок лежит последним, и повторный поиск найдёт его
	 */
	for(uint8_t attempt = 0; attempt < 2; attempt++){
		/**
		 * Выполняем перебор кусков
		 */
		for(auto & chunk : this->_chunks){
			/**
			 * Выполняем перебор свободных участков куска
			 */
			for(auto i = chunk.spans.begin(); i != chunk.spans.end(); ++i){
				// Если участок вмещает запрос
				if(i->size >= length){
					// Адрес выдаваемого участка
					uint8_t * result = (chunk.base + i->offset);
					// Если участок уходит целиком
					if(i->size == length)
						// Убираем свободный участок
						chunk.spans.erase(i);
					// Если участок уходит частично
					else {
						// Сдвигаем начало свободного участка
						i->offset += length;
						// Укорачиваем свободный участок
						i->size -= length;
					}
					// Выводим адрес участка
					return result;
				}
			}
		}
		// Если нового куска взять не удалось
		if((attempt == 0) && !this->grow(length))
			// Сообщаем об отказе
			return nullptr;
	}
	// Сообщаем об отказе
	return nullptr;
}
/**
 * give Метод возврата участка укрытой памяти с затиранием
 */
void sys::Vault::give(void * data, const size_t size) noexcept {
	// Если участок не задан
	if((data == nullptr) || (size == 0))
		// Выходим из метода
		return;
	// Округляем длину участка вверх до выравнивания
	const size_t length = (((size + VAULT_ALIGN - 1) / VAULT_ALIGN) * VAULT_ALIGN);
	// Затираем участок прежде возврата: между возвратом и повторной выдачей открытым не лежит
	sys::wipe(data, length);
	// Адрес участка
	uint8_t * address = static_cast <uint8_t *> (data);
	// Берём замок хранилища
	const lock_guard <mutex> lock(this->_lock);
	/**
	 * Выполняем перебор кусков
	 */
	for(auto & chunk : this->_chunks){
		// Если участок принадлежит куску
		if((address >= chunk.base) && ((address + length) <= (chunk.base + chunk.size))){
			// Смещение участка от начала куска
			const size_t offset = static_cast <size_t> (address - chunk.base);
			// Место свободного участка, идущего следом за возвращаемым
			auto next = chunk.spans.begin();
			// Ищем первый свободный участок за возвращаемым
			while((next != chunk.spans.end()) && (next->offset < offset))
				++next;
			// Признак слияния со следующим свободным участком
			const bool after = ((next != chunk.spans.end()) && (next->offset == (offset + length)));
			// Признак слияния с предыдущим свободным участком
			const bool before = ((next != chunk.spans.begin()) && (((next - 1)->offset + (next - 1)->size) == offset));
			// Если участок смыкается с обоими соседями
			if(before && after){
				// Расширяем предыдущий участок на возвращаемый и следующий
				(next - 1)->size += (length + next->size);
				// Убираем следующий участок
				chunk.spans.erase(next);
			// Если участок смыкается с предыдущим
			} else if(before)
				// Расширяем предыдущий участок на возвращаемый
				(next - 1)->size += length;
			// Если участок смыкается со следующим
			else if(after){
				// Сдвигаем начало следующего участка
				next->offset = offset;
				// Расширяем следующий участок на возвращаемый
				next->size += length;
			// Если соседей нет
			} else {
				/**
				 * Заводим свободный участок; нехватка памяти кучи под запись оставляет участок
				 * невыданным навсегда - затёртым и потерянным, но не открытым
				 */
				try {
					// Заводим свободный участок на месте возвращаемого
					chunk.spans.emplace(next, offset, length);
				// Перехватываем нехватку памяти
				} catch(const bad_alloc &){}
			}
			// Выходим из метода
			return;
		}
	}
}
/**
 * wipe Метод затирания всей памяти хранилища
 */
void sys::Vault::wipe() noexcept {
	/**
	 * Выполняем перебор кусков без замка: зовётся у потомка процесса, где замок мог
	 * остаться взятым исчезнувшим потоком родителя
	 */
	for(auto & chunk : this->_chunks)
		// Затираем кусок целиком
		sys::wipe(chunk.base, chunk.size);
}
/**
 * shelter Метод получения сведений об укрытии хранилища
 */
sys::shelter_t sys::Vault::shelter() const noexcept {
	// Сведения об укрытии: без кусков признаки подняты - понижения не было
	shelter_t result;
	// Берём замок хранилища
	const lock_guard <mutex> lock(this->_lock);
	// Поднимаем признаки
	result.hidden = result.wired = result.forked = true;
	/**
	 * Выполняем перебор кусков
	 */
	for(const auto & chunk : this->_chunks){
		// Опускаем признак укрытия от снимков, если у куска его нет
		result.hidden = (result.hidden && chunk.shelter.hidden);
		// Опускаем признак запрета подкачки, если у куска его нет
		result.wired = (result.wired && chunk.shelter.wired);
		// Опускаем признак затирания у потомка, если у куска его нет
		result.forked = (result.forked && chunk.shelter.forked);
	}
	// Выводим сведения об укрытии
	return result;
}
/**
 * owns Метод проверки принадлежности адреса хранилищу
 */
bool sys::Vault::owns(const void * data) const noexcept {
	// Если адрес не задан
	if(data == nullptr)
		// Хранилищу не принадлежит
		return false;
	// Проверяемый адрес
	const uint8_t * address = static_cast <const uint8_t *> (data);
	// Берём замок хранилища
	const lock_guard <mutex> lock(this->_lock);
	/**
	 * Выполняем перебор кусков
	 */
	for(const auto & chunk : this->_chunks){
		// Если адрес лежит внутри куска
		if((address >= chunk.base) && (address < (chunk.base + chunk.size)))
			// Хранилищу принадлежит
			return true;
	}
	// Хранилищу не принадлежит
	return false;
}
/**
 * chunks Метод получения числа кусков, взятых у системы
 */
size_t sys::Vault::chunks() const noexcept {
	// Берём замок хранилища
	const lock_guard <mutex> lock(this->_lock);
	// Выводим число кусков
	return this->_chunks.size();
}
/**
 * demand Метод установки требования укрытия
 */
void sys::Vault::demand(const bool mode) noexcept {
	// Берём замок хранилища
	const lock_guard <mutex> lock(this->_lock);
	// Запоминаем требование укрытия
	this->_demand = mode;
}
/**
 * demand Метод получения требования укрытия
 */
bool sys::Vault::demand() const noexcept {
	// Берём замок хранилища
	const lock_guard <mutex> lock(this->_lock);
	// Выводим требование укрытия
	return this->_demand;
}
/**
 * @brief Конструктор
 *
 */
sys::Vault::Vault() noexcept : _demand(false), _guarded(false) {}
/**
 * @brief Деструктор
 *
 */
sys::Vault::~Vault() noexcept {
	/**
	 * Выполняем перебор кусков: хранилище живёт до завершения процесса, и возврат кусков
	 * системе - забота порядка; затирание - забота тайны
	 */
	for(auto & chunk : this->_chunks){
		// Затираем кусок целиком
		sys::wipe(chunk.base, chunk.size);
		/**
		 * Для операционной системы MS Windows
		 */
		#if defined(_WIN32)
			// Возвращаем кусок системе
			::VirtualFree(chunk.base, 0, MEM_RELEASE);
		/**
		 * Для операционных систем POSIX
		 */
		#else
			// Возвращаем кусок системе
			::munmap(chunk.base, chunk.size);
		#endif
	}
}
/**
 * reserve Метод заведения участка
 */
bool sys::Secret::reserve(const size_t size) noexcept {
	// Возвращаем прежний участок, если он заведён
	this->release();
	// Если длина участка не задана
	if(size == 0)
		// Сообщаем об отказе
		return false;
	// Берём участок хранилища
	this->_data = static_cast <uint8_t *> (Vault::instance().take(size));
	// Если участок не выдан
	if(this->_data == nullptr)
		// Сообщаем об отказе
		return false;
	// Запоминаем длину участка
	this->_size = size;
	// Обнуляем участок: прежнее содержимое затёрто возвратом, но обещание даётся здесь
	sys::wipe(this->_data, this->_size);
	// Сообщаем об успехе
	return true;
}
/**
 * wipe Метод затирания участка без возврата
 */
void sys::Secret::wipe() noexcept {
	// Затираем участок, если он заведён
	sys::wipe(this->_data, this->_size);
}
/**
 * release Метод возврата участка хранилищу с затиранием
 */
void sys::Secret::release() noexcept {
	// Если участок заведён
	if(this->_data != nullptr){
		// Возвращаем участок хранилищу с затиранием
		Vault::instance().give(this->_data, this->_size);
		// Сбрасываем адрес участка
		this->_data = nullptr;
		// Сбрасываем длину участка
		this->_size = 0;
	}
}
/**
 * data Метод получения адреса участка
 */
uint8_t * sys::Secret::data() noexcept {
	// Выводим адрес участка
	return this->_data;
}
/**
 * data Метод получения адреса участка
 */
const uint8_t * sys::Secret::data() const noexcept {
	// Выводим адрес участка
	return this->_data;
}
/**
 * size Метод получения длины участка
 */
size_t sys::Secret::size() const noexcept {
	// Выводим длину участка
	return this->_size;
}
/**
 * @brief Оператор переноса
 *
 * @param other переносимый участок; после переноса пуст
 * @return      текущий участок
 *
 */
sys::Secret & sys::Secret::operator = (Secret && other) noexcept {
	// Если переносится не сам участок
	if(this != &other){
		// Возвращаем прежний участок, если он заведён
		this->release();
		// Забираем адрес участка
		this->_data = other._data;
		// Забираем длину участка
		this->_size = other._size;
		// Опустошаем переносимый участок
		other._data = nullptr;
		// Сбрасываем длину переносимого участка
		other._size = 0;
	}
	// Выводим текущий участок
	return (* this);
}
/**
 * @brief Конструктор переноса
 *
 * @param other переносимый участок; после переноса пуст
 *
 */
sys::Secret::Secret(Secret && other) noexcept : _data(other._data), _size(other._size) {
	// Опустошаем переносимый участок
	other._data = nullptr;
	// Сбрасываем длину переносимого участка
	other._size = 0;
}
/**
 * @brief Деструктор
 *
 */
sys::Secret::~Secret() noexcept {
	// Возвращаем участок хранилищу с затиранием
	this->release();
}
