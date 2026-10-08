/**
 * @file vault.hpp
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
 * @brief Заголовочный файл укрытого хранилища ключевого материала
 *
 * \~english
 * @brief Header file of the sheltered storage of the key material
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#pragma once

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <mutex>
#include <vector>
#include <limits>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён служебных средств
	 *
	 * \~english
	 * @brief Namespace of the utility means
	 *
	 * \~
	 */
	namespace sys {
		/**
		 * \~russian
		 * @brief Сведения об укрытии памяти хранилища
		 *
		 * @note Признаки отвечают о том, что состоялось НА ДЕЛЕ, а не о том, о чём
		 *       просили: умеет такое не всякая система, а право на запрет подкачки к
		 *       тому же ограничено пределом (RLIMIT_MEMLOCK). Молчаливое понижение
		 *       укрытия хуже честного отказа - решать, годится ли оно, обязан звавший;
		 *       кто не мирится с понижением, зовёт Vault::demand(true)
		 *
		 * \~english
		 * @brief Information about the sheltering of the storage memory
		 * @note The flags report what has happened IN FACT, not what was asked for: not every
		 *       system is able to do it, and the right to forbid the swapping is besides limited
		 *       (RLIMIT_MEMLOCK). A silent lowering of the sheltering is worse than an honest refusal;
		 *       who does not accept the lowering calls Vault::demand(true)
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Shelter {
			// Признак памяти, укрытой от снимков памяти процесса
			bool hidden;
			// Признак памяти, которой запрещено уходить в подкачку
			bool wired;
			// Признак памяти, которую потомок процесса получает затёртой
			bool forked;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 */
			Shelter() noexcept : hidden(false), wired(false), forked(false) {}
		} shelter_t;
		/**
		 * \~russian
		 * @brief Класс укрытого хранилища ключевого материала
		 *
		 * @details Хранилище одно на процесс. Память берётся у системы кусками прямо,
		 *          минуя кучу: куску запрещается подкачка, он укрывается от снимков
		 *          памяти, а потомку процесса достаётся затёртым. Куски режутся на
		 *          участки под запросы, освобождённый участок затирается и отдаётся
		 *          следующему запросу; системе куски не возвращаются никогда, потому
		 *          что их число мало (десятки соединений на кусок), а право на запрет
		 *          подкачки дорого и терять его перезаведением куска незачем
		 *
		 * @note Намеренные решения:
		 *       1. Хранилище общее на процесс, а не своё у каждой связи: право на запрет
		 *          подкачки ограничено пределом RLIMIT_MEMLOCK (у Linux умолчанием 64 КБ
		 *          либо 8 МБ), и страница на связь исчерпала бы его на десятке связей.
		 *          Один кусок в 64 КБ вмещает ключевой материал сотни связей
		 *       2. Понижение укрытия умолчанием не отказ, а честный доклад shelter():
		 *          библиотека работает и там, где запрет подкачки не дан, но не молчит об
		 *          этом. Кому понижение непозволительно, тот зовёт demand(true) - тогда
		 *          кусок без запрета подкачки не принимается и запрос отвечается отказом
		 *       3. Освобождённый участок затирается изменчивой записью в момент
		 *          освобождения, а не при повторной выдаче: между освобождением и выдачей
		 *          ключ не должен лежать открытым ни мгновения
		 *
		 * \~english
		 * @brief Class of the sheltered storage of the key material
		 * @details The storage is one per process. The memory is taken from the system by chunks
		 *          directly, bypassing the heap: the chunk is forbidden to swap, hidden from the
		 *          memory dumps, and a child process gets it wiped. The chunks are cut into pieces
		 *          for the requests, a released piece is wiped and given to the next request; the
		 *          chunks are never returned to the system
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Vault {
			private:
				/**
				 * \~russian
				 * @brief Структура свободного участка куска
				 *
				 * \~english
				 * @brief Structure of a free piece of a chunk
				 *
				 * \~
				 */
				typedef struct Span {
					// Смещение участка от начала куска
					size_t offset;
					// Длина участка в байтах
					size_t size;
					/**
					 * \~russian
					 * @brief Конструктор
					 *
					 * @param offset смещение участка от начала куска
					 * @param size   длина участка в байтах
					 *
					 * \~english
					 * @brief Constructor
					 * @param offset the offset of the piece from the beginning of the chunk
					 * @param size   the length of the piece in bytes
					 *
					 * \~
					 */
					Span(const size_t offset, const size_t size) noexcept : offset(offset), size(size) {}
				} span_t;
				/**
				 * \~russian
				 * @brief Структура куска памяти, взятого у системы
				 *
				 * \~english
				 * @brief Structure of a chunk of the memory taken from the system
				 *
				 * \~
				 */
				typedef struct Chunk {
					// Адрес начала куска
					uint8_t * base;
					// Длина куска в байтах
					size_t size;
					// Сведения об укрытии куска
					shelter_t shelter;
					// Свободные участки куска по возрастанию смещения
					vector <span_t> spans;
					/**
					 * \~russian
					 * @brief Конструктор
					 *
					 * \~english
					 * @brief Constructor
					 *
					 * \~
					 */
					Chunk() noexcept : base(nullptr), size(0) {}
				} chunk_t;
			private:
				// Признак того, что понижение укрытия отвечается отказом
				bool _demand;
				// Признак того, что обработчик разветвления процесса заведён
				bool _guarded;
			private:
				// Куски памяти, взятые у системы
				vector <chunk_t> _chunks;
			private:
				// Замок хранилища: связи живут в разных потоках
				mutable mutex _lock;
			private:
				/**
				 * \~russian
				 * @brief Метод взятия куска у системы
				 *
				 * @param size наименьшая длина куска в байтах
				 * @return     признак того, что кусок взят и принят
				 *
				 * \~english
				 * @brief Method of the taking of a chunk from the system
				 * @param size the minimum length of the chunk in bytes
				 * @return     the flag of the chunk being taken and accepted
				 *
				 * \~
				 */
				bool grow(const size_t size) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения хранилища процесса
				 *
				 * @return хранилище процесса
				 *
				 * \~english
				 * @brief Method of getting the storage of the process
				 * @return the storage of the process
				 *
				 * \~
				 */
				static Vault & instance() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод взятия участка укрытой памяти
				 *
				 * @param size длина участка в байтах
				 * @return     адрес участка либо nullptr при отказе
				 *
				 * \~english
				 * @brief Method of the taking of a piece of the sheltered memory
				 * @param size the length of the piece in bytes
				 * @return     the address of the piece or nullptr on a refusal
				 *
				 * \~
				 */
				void * take(const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод возврата участка укрытой памяти с затиранием
				 *
				 * @param data адрес участка, выданного take()
				 * @param size длина участка в байтах, переданная take()
				 *
				 * \~english
				 * @brief Method of the return of a piece of the sheltered memory with the wiping
				 * @param data the address of the piece given by take()
				 * @param size the length of the piece in bytes passed to take()
				 *
				 * \~
				 */
				void give(void * data, const size_t size) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод затирания всей памяти хранилища
				 *
				 * @details Зовётся у потомка процесса после разветвления там, где система
				 *          сама затёртой памяти не даёт; участки остаются выданными, но пустыми
				 *
				 * \~english
				 * @brief Method of the wiping of the whole memory of the storage
				 * @details Called at the child process after the fork where the system does not give
				 *          the wiped memory itself; the pieces remain given but empty
				 *
				 * \~
				 */
				void wipe() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения сведений об укрытии хранилища
				 *
				 * @return худшее по всем кускам: признак поднят, лишь если поднят у каждого
				 *
				 * \~english
				 * @brief Method of getting the information about the sheltering of the storage
				 * @return the worst over all the chunks: a flag is set only if it is set at every one
				 *
				 * \~
				 */
				shelter_t shelter() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки принадлежности адреса хранилищу
				 *
				 * @details Потребителю - убедиться, что байты ключа лежат в укрытой памяти
				 *          (например, `secret.data()` у билета); проверкам - закрепить это
				 *
				 * @param data проверяемый адрес
				 * @return     признак того, что адрес лежит внутри куска хранилища
				 *
				 * \~english
				 * @brief Method of checking whether an address belongs to the storage
				 * @param data the address being checked
				 * @return     the flag of the address lying inside a chunk of the storage
				 *
				 * \~
				 */
				bool owns(const void * data) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа кусков, взятых у системы
				 *
				 * @return число кусков
				 *
				 * \~english
				 * @brief Method of getting the number of the chunks taken from the system
				 * @return the number of the chunks
				 *
				 * \~
				 */
				size_t chunks() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки требования укрытия
				 *
				 * @param mode признак того, что кусок без запрета подкачки не принимается
				 *
				 * \~english
				 * @brief Method of setting the demand of the sheltering
				 * @param mode the flag of a chunk without the swap prohibition being not accepted
				 *
				 * \~
				 */
				void demand(const bool mode) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения требования укрытия
				 *
				 * @return признак того, что кусок без запрета подкачки не принимается
				 *
				 * \~english
				 * @brief Method of getting the demand of the sheltering
				 * @return the flag of a chunk without the swap prohibition being not accepted
				 *
				 * \~
				 */
				bool demand() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Vault() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Vault() noexcept;
		} vault_t;
		/**
		 * \~russian
		 * @brief Класс участка укрытой памяти
		 *
		 * @details Владеет участком хранилища: заводится reserve(), затирается wipe(),
		 *          возвращается release() либо разрушением. Копирования нет - у тайны
		 *          один владелец; перенос дозволен
		 *
		 * \~english
		 * @brief Class of a piece of the sheltered memory
		 * @details Owns a piece of the storage: created by reserve(), wiped by wipe(), returned by
		 *          release() or by the destruction. There is no copying, a secret has one owner;
		 *          the move is allowed
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Secret {
			private:
				// Адрес участка
				uint8_t * _data;
				// Длина участка в байтах
				size_t _size;
			public:
				/**
				 * \~russian
				 * @brief Метод заведения участка
				 *
				 * @param size длина участка в байтах
				 * @return     признак того, что участок заведён и обнулён
				 *
				 * \~english
				 * @brief Method of the reservation of the piece
				 * @param size the length of the piece in bytes
				 * @return     the flag of the piece being reserved and zeroed
				 *
				 * \~
				 */
				bool reserve(const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод затирания участка без возврата
				 *
				 * \~english
				 * @brief Method of the wiping of the piece without the return
				 *
				 * \~
				 */
				void wipe() noexcept;
				/**
				 * \~russian
				 * @brief Метод возврата участка хранилищу с затиранием
				 *
				 * \~english
				 * @brief Method of the return of the piece to the storage with the wiping
				 *
				 * \~
				 */
				void release() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения адреса участка
				 *
				 * @return адрес участка либо nullptr, если участок не заведён
				 *
				 * \~english
				 * @brief Method of getting the address of the piece
				 * @return the address of the piece or nullptr if the piece is not reserved
				 *
				 * \~
				 */
				uint8_t * data() noexcept;
				/**
				 * \~russian
				 * @brief Метод получения адреса участка
				 *
				 * @return адрес участка либо nullptr, если участок не заведён
				 *
				 * \~english
				 * @brief Method of getting the address of the piece
				 * @return the address of the piece or nullptr if the piece is not reserved
				 *
				 * \~
				 */
				const uint8_t * data() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения длины участка
				 *
				 * @return длина участка в байтах
				 *
				 * \~english
				 * @brief Method of getting the length of the piece
				 * @return the length of the piece in bytes
				 *
				 * \~
				 */
				size_t size() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Оператор переноса
				 *
				 * @param other переносимый участок; после переноса пуст
				 * @return      текущий участок
				 *
				 * \~english
				 * @brief Move operator
				 * @param other the piece being moved; empty after the move
				 * @return      the current piece
				 *
				 * \~
				 */
				Secret & operator = (Secret && other) noexcept;
				/**
				 * \~russian
				 * @brief Конструктор переноса
				 *
				 * @param other переносимый участок; после переноса пуст
				 *
				 * \~english
				 * @brief Move constructor
				 * @param other the piece being moved; empty after the move
				 *
				 * \~
				 */
				Secret(Secret && other) noexcept;
				/**
				 * \~russian
				 * @brief Копирование запрещено: у тайны один владелец
				 *
				 * \~english
				 * @brief The copying is forbidden: a secret has one owner
				 *
				 * \~
				 */
				Secret(const Secret &) = delete;
				Secret & operator = (const Secret &) = delete;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Secret() noexcept : _data(nullptr), _size(0) {}
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Secret() noexcept;
		} secret_t;
		/**
		 * \~russian
		 * @brief Распределитель контейнеров языка над укрытым хранилищем
		 *
		 * @details Даёт контейнерам стандартной библиотеки память хранилища; освобождение
		 *          затирает. Отказ хранилища обращается в bad_alloc, как у обычного
		 *          распределителя, - контейнер о причине не знает и знать не должен
		 *
		 * \~english
		 * @brief Allocator of the containers of the language over the sheltered storage
		 * @details Gives the containers of the standard library the memory of the storage; the
		 *          deallocation wipes. A refusal of the storage turns into bad_alloc, as at the
		 *          ordinary allocator
		 *
		 * \~
		 */
		template <typename T>
		class Allocator {
			public:
				// Тип значения распределителя
				typedef T value_type;
			public:
				/**
				 * \~russian
				 * @brief Метод выделения памяти
				 *
				 * @param count число значений
				 * @return      адрес памяти
				 *
				 * \~english
				 * @brief Method of the allocation of the memory
				 * @param count the number of the values
				 * @return      the address of the memory
				 *
				 * \~
				 */
				T * allocate(const size_t count){
					// Если запрошенная длина не умещается в размер
					if(count > ((numeric_limits <size_t>::max)() / sizeof(T)))
						// Сообщаем об отказе выделения
						throw bad_alloc();
					// Берём участок хранилища
					void * result = Vault::instance().take(count * sizeof(T));
					// Если участок не выдан
					if(result == nullptr)
						// Сообщаем об отказе выделения
						throw bad_alloc();
					// Выводим адрес участка
					return static_cast <T *> (result);
				}
				/**
				 * \~russian
				 * @brief Метод освобождения памяти с затиранием
				 *
				 * @param data  адрес памяти
				 * @param count число значений
				 *
				 * \~english
				 * @brief Method of the deallocation of the memory with the wiping
				 * @param data  the address of the memory
				 * @param count the number of the values
				 *
				 * \~
				 */
				void deallocate(T * data, const size_t count) noexcept {
					// Возвращаем участок хранилищу
					Vault::instance().give(data, count * sizeof(T));
				}
			public:
				/**
				 * \~russian
				 * @brief Оператор сличения: все распределители равны, память общая
				 *
				 * \~english
				 * @brief Comparison operator: all the allocators are equal, the memory is shared
				 *
				 * \~
				 */
				template <typename U>
				bool operator == (const Allocator <U> &) const noexcept { return true; }
				template <typename U>
				bool operator != (const Allocator <U> &) const noexcept { return false; }
			public:
				/**
				 * \~russian
				 * @brief Конструкторы
				 *
				 * \~english
				 * @brief Constructors
				 *
				 * \~
				 */
				Allocator() noexcept = default;
				template <typename U>
				Allocator(const Allocator <U> &) noexcept {}
		};
		// Набор байтов на укрытой памяти: освобождение затирает
		typedef vector <uint8_t, Allocator <uint8_t>> bytes_t;
	};
};

