/**
 * @file trace.cpp
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
 * @brief Проверка следа ключа билета в обычной куче: перехват new/delete ловит проход ключа
 *        через кучу детерминированно, а не по частоте переиспользования освобождённого
 *
 * @details Всякий блок кучи учитывается при выдаче и целиком переписывается в журнал при
 *          освобождении; после выдачи билетов и возобновления ключи билетов ищутся и в живых
 *          блоках, и в журнале освобождённых. Находка внешнего щупа на Alpine (musl): третья
 *          копия ключа в обычной куче, вне хранилища, до 5 из 10 прогонов
 *
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#if defined(_WIN32)
	#include <windows.h>
/** Иначе: POSIX-системы */
#else
	#include <pthread.h>
	/** Для FreeBSD и DragonFly подключаем расширения потоков */
	#if defined(__FreeBSD__) || defined(__DragonFly__)
		#include <pthread_np.h>
	#endif
	/** Для OpenBSD подключаем сигналы и расширения потоков */
	#if defined(__OpenBSD__)
		#include <signal.h>
		#include <pthread_np.h>
	#endif
#endif
/** Для Эльбруса подключаем встроенные функции */
#if defined(__e2k__)
	#include <e2kintrin.h>
#endif
#include <main.hpp>
#include <identity.hpp>
#include <gost.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * Учёт кучи: без замка, проверки однопоточны
 */
namespace {
	// Число ячеек таблицы живых блоков
	constexpr size_t CELLS = (1u << 20);
	// Длина журнала освобождённых блоков
	constexpr size_t JOURNAL = (64u << 20);
	// Наибольшая длина блока, переписываемого в журнал целиком
	constexpr size_t LARGEST = 65536;
	/**
	 * Ячейка таблицы живых блоков
	 */
	struct cell_t {
		// Адрес блока
		void * ptr;
		// Длина блока
		size_t size;
	};
	// Таблица живых блоков
	cell_t cells[CELLS];
	// Журнал освобождённых блоков: содержимое подряд
	uint8_t journal[JOURNAL];
	// Заполненность журнала
	size_t filled = 0;
	// Признак переполнения журнала
	bool overflowed = false;
	// Признак ведения учёта
	bool recording = false;
	/**
	 * Ячейка по адресу
	 */
	size_t slot(const void * ptr) noexcept {
		// Смешиваем адрес
		uintptr_t h = reinterpret_cast <uintptr_t> (ptr);
		// Домешиваем адрес сдвигами и умножением
		h ^= (h >> 33); h *= 0xff51afd7ed558ccdULL; h ^= (h >> 33);
		// Возвращаем номер ячейки
		return static_cast <size_t> (h & (CELLS - 1));
	}
	/**
	 * Учёт выдачи блока
	 */
	void track(void * ptr, const size_t size) noexcept {
		// Пропускаем запись без учёта и нулевые адреса
		if(!recording || (ptr == nullptr)) return;
		// Вычисляем начальную ячейку
		size_t i = slot(ptr);
		/** Перебираем ячейки открытой адресации, пока не найдём пустую */
		for(size_t n = 0; n < CELLS; n++, i = ((i + 1) & (CELLS - 1))){
			// Вписываем блок в пустую ячейку
			if(cells[i].ptr == nullptr){ cells[i].ptr = ptr; cells[i].size = size; return; }
		}
	}
	/**
	 * Чтение байта чужой памяти. У Эльбруса память меченая: слово, оставшееся от
	 * неинициализированного значения, несёт диагностическую метку, и всякое действие
	 * над ним роняет процесс сигналом SIGILL. Мера читает отработавшие кадры стека и
	 * освобождённые блоки, где такие слова законны, - оттого у Эльбруса байт берётся из
	 * выровненного слова, прочитанного с очисткой метки
	 */
	#if defined(__e2k__)
		// Читаем байт из выровненного слова с очисткой метки
		static uint8_t peek(const uint8_t * data) noexcept {
			// Берём адрес байта
			const uintptr_t address = reinterpret_cast <uintptr_t> (data);
			// Читаем выровненное слово с очисткой метки
			const uint64_t word = __builtin_e2k_ld_64s_cleartag(reinterpret_cast <const void *> (address & ~static_cast <uintptr_t> (7)), 0);
			// Выделяем требуемый байт из слова
			return static_cast <uint8_t> (word >> ((address & 7) * 8));
		}
	/** Иначе: обычное чтение байта */
	#else
		/** Если компилятор поддерживает проверку атрибутов */
		#if defined(__has_attribute)
			/** Если есть атрибут no_sanitize: читаем без перехвата санитайзером */
			#if __has_attribute(no_sanitize)
				// Отключаем перехват чтения санитайзером
				__attribute__((no_sanitize("address")))
			#endif
		#endif
		// Читаем байт напрямую
		static inline uint8_t peek(const uint8_t * data) noexcept { return *data; }
	#endif
	/**
	 * Сличение байтов без перехватчиков санитайзера: мера читает блоки целиком, включая
	 * хвост вектора между размером и ёмкостью, который ASan помечает переполнением
	 * контейнера; для меры это законное чтение своей же учтённой области
	 */
	#if defined(__has_attribute)
		/** Если есть атрибут no_sanitize: сличаем без перехвата санитайзером */
		#if __has_attribute(no_sanitize)
			// Отключаем перехват сличения санитайзером
			__attribute__((no_sanitize("address")))
		#endif
	#endif
	// Сличаем блоки байт в байт
	static bool same(const uint8_t * data, const uint8_t * key, const size_t size) noexcept {
		// Накапливаем различия байтов
		uint8_t diff = 0;
		/** Перебираем байты блока, накапливая различия с образцом */
		for(size_t i = 0; i < size; i++) diff |= static_cast <uint8_t> (peek(data + i) ^ key[i]);
		// Блоки совпадают, если различий нет
		return (diff == 0);
	}
	/**
	 * Копирование байтов без перехватчиков санитайзера: журнал снимает освобождаемый блок целиком
	 */
	#if defined(__has_attribute)
		/** Если есть атрибут no_sanitize: копируем без перехвата санитайзером */
		#if __has_attribute(no_sanitize)
			// Отключаем перехват копирования санитайзером
			__attribute__((no_sanitize("address")))
		#endif
	#endif
	// Копируем блок байт в байт
	static void copy(uint8_t * to, const void * from, const size_t size) noexcept {
		// Приводим источник к массиву байтов
		const uint8_t * data = static_cast <const uint8_t *> (from);
		/** Перебираем байты блока, переписывая их в журнал */
		for(size_t i = 0; i < size; i++) to[i] = peek(data + i);
	}
	/**
	 * Снятие блока с учёта с переписыванием содержимого в журнал
	 */
	void untrack(void * ptr) noexcept {
		// Пропускаем запись без учёта и нулевые адреса
		if(!recording || (ptr == nullptr)) return;
		// Вычисляем начальную ячейку
		size_t i = slot(ptr);
		/** Перебираем ячейки открытой адресации, пока не найдём блок */
		for(size_t n = 0; n < CELLS; n++, i = ((i + 1) & (CELLS - 1))){
			// Дошли до пустой ячейки: блок не учтён
			if(cells[i].ptr == nullptr) return;
			if(cells[i].ptr == ptr){
				// Ограничиваем длину снимаемого содержимого
				const size_t size = ((cells[i].size > LARGEST) ? LARGEST : cells[i].size);
				// Переписываем содержимое блока в журнал
				if((filled + size) <= JOURNAL){ copy(journal + filled, ptr, size); filled += size; }
				else overflowed = true;
				// Удаление из открытой адресации: помечаем надгробием (адрес 1), поиск его пропускает
				cells[i].ptr = reinterpret_cast <void *> (1);
				// Обнуляем длину ячейки
				cells[i].size = 0;
				// Блок снят с учёта
				return;
			}
		}
	}
	/**
	 * Поиск образца среди живых блоков: число вхождений
	 */
	size_t alive(const uint8_t * key, const size_t size, size_t * where) noexcept {
		// Инициализируем счётчик вхождений
		size_t count = 0;
		/** Перебираем ячейки таблицы живых блоков */
		for(size_t i = 0; i < CELLS; i++){
			// Пропускаем пустые ячейки, надгробия и короткие блоки
			if((cells[i].ptr == nullptr) || (cells[i].ptr == reinterpret_cast <void *> (1)) || (cells[i].size < size)) continue;
			// Берём адрес блока
			const uint8_t * data = static_cast <const uint8_t *> (cells[i].ptr);
			/** Перебираем смещения в блоке, пока образец помещается */
			for(size_t j = 0; (j + size) <= cells[i].size; j++){
				// Считаем вхождение и запоминаем длину блока
				if(same(data + j, key, size)){ if(where != nullptr) *where = cells[i].size; count++; break; }
			}
		}
		// Возвращаем число вхождений среди живых блоков
		return count;
	}
	/**
	 * Поиск образца в журнале освобождённых: число вхождений
	 */
	size_t buried(const uint8_t * key, const size_t size) noexcept {
		// Инициализируем счётчик вхождений
		size_t count = 0;
		/** Перебираем смещения в журнале, пока образец помещается */
		for(size_t j = 0; (j + size) <= filled; j++)
			// Считаем вхождение в журнале
			if(same(journal + j, key, size)) count++;
		// Возвращаем число вхождений в журнале
		return count;
	}
	/**
	 * Поиск образца на стеке ниже текущего кадра до основания стека: число вхождений
	 */
	size_t stacked(const uint8_t * key, const size_t size, const uint8_t * skip, const size_t span) noexcept {
		/**
		 * Стек сканируется НИЖЕ текущего кадра, до предела стека: там лежат отработавшие
		 * кадры, чьи местные буферы с ключом должны были быть затёрты; живые кадры выше
		 * несут лишь свой образец
		 */
		volatile uint8_t marker = 0;
		// Верхняя граница: адрес помеченного байта
		const uint8_t * high = const_cast <const uint8_t *> (&marker);
		// Нижнюю границу выясняем по платформе
		const uint8_t * low = nullptr;
		/** В Windows нижнюю границу даёт VirtualQuery */
		#if defined(_WIN32)
			/**
			 * Нижняя граница: начало ОТОБРАЖЁННОЙ области стека, в которой лежит текущий кадр
			 * (годно и MinGW, и MSVC любого издания). Ниже неё - сторожевая страница и
			 * неотображённый запас: чтение туда роняет процесс, а отработавшие кадры лежат
			 * в той же отображённой области, что и живые
			 */
			MEMORY_BASIC_INFORMATION region;
			// Запрашиваем границы отображённой области стека
			if(::VirtualQuery(const_cast <uint8_t *> (high), &region, sizeof(region)) != 0)
				// Берём начало отображённой области как нижнюю границу
				low = static_cast <const uint8_t *> (region.BaseAddress);
		/** В macOS границы стека даёт pthread */
		#elif defined(__APPLE__)
			// Запрашиваем вершину и размер стека потока
			const uint8_t * top = static_cast <const uint8_t *> (pthread_get_stackaddr_np(pthread_self()));
			// Вычисляем нижнюю границу стека
			low = (top - pthread_get_stacksize_np(pthread_self()));
		/** В OpenBSD границы стека даёт pthread_stackseg_np */
		#elif defined(__OpenBSD__)
			// У OpenBSD границы стека даёт pthread_stackseg_np: вершина и длина
			stack_t segment;
			// Запрашиваем границы стека потока
			if(pthread_stackseg_np(pthread_self(), &segment) == 0)
				// Вычисляем нижнюю границу стека
				low = (static_cast <const uint8_t *> (segment.ss_sp) - segment.ss_size);
		/** Во FreeBSD и DragonFly признаки потока даёт pthread_attr_get_np */
		#elif defined(__FreeBSD__) || defined(__DragonFly__)
			// У FreeBSD и DragonFly признаки потока берутся pthread_attr_get_np
			pthread_attr_t attr;
			// Готовим приёмники границ стека
			void * base = nullptr; size_t length = 0;
			// Инициализируем атрибуты потока
			pthread_attr_init(&attr);
			// Запрашиваем признаки и границы стека потока
			if((pthread_attr_get_np(pthread_self(), &attr) == 0) && (pthread_attr_getstack(&attr, &base, &length) == 0))
				// Берём начало стека как нижнюю границу
				low = static_cast <const uint8_t *> (base);
			// Освобождаем атрибуты потока
			pthread_attr_destroy(&attr);
		/** Иначе: границы стека даёт pthread_getattr_np */
		#else
			// Linux, NetBSD, Solaris: pthread_getattr_np
			pthread_attr_t attr;
			// Готовим приёмники границ стека
			void * base = nullptr; size_t length = 0;
			// Запрашиваем границы стека потока
			if((pthread_getattr_np(pthread_self(), &attr) == 0) && (pthread_attr_getstack(&attr, &base, &length) == 0))
				// Берём начало стека как нижнюю границу
				low = static_cast <const uint8_t *> (base);
			// Освобождаем атрибуты потока
			pthread_attr_destroy(&attr);
		#endif
		// Без нижней границы либо пустой диапазон: искать негде
		if((low == nullptr) || (high <= low)) return 0;
		// Ниже сегодняшнего кадра на глубину до 1 МБ: глубже рукопожатие не ходило
		if((high - low) > (1u << 20)) low = (high - (1u << 20));
		// Инициализируем счётчик вхождений
		size_t count = 0;
		/** Перебираем стек от нижней границы до текущего кадра */
		for(const uint8_t * p = low; (p + size) <= high; p++){
			// Пропускаем живую область с собственным образцом
			if((p >= skip) && (p < (skip + span))) continue;
			// Считаем вхождение и печатаем смещение ниже кадра
			if(same(p, key, size)){ count++; ::printf("след ключа на стеке: %td байтов ниже кадра\n", high - p); }
		}
		// Возвращаем число вхождений на стеке
		return count;
	}
	/**
	 * Помощники связи: как в проверках контекста
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Признак передачи данных между сторонами
		bool moved = false;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Берём исходящие данные клиента
			view_t data = client.output();
			// Пересылаем данные, если они есть
			if(data.size > 0){
				// Копируем данные в буфер
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Убираем данные из исходящей очереди клиента
				client.consume(buffer.size());
				// Передаём данные серверу
				server.push(view_t(buffer.data(), buffer.size()));
				// Отмечаем передачу данных
				moved = true;
			}
			// Берём исходящие данные сервера
			data = server.output();
			// Пересылаем данные, если они есть
			if(data.size > 0){
				// Копируем данные в буфер
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Убираем данные из исходящей очереди сервера
				server.consume(buffer.size());
				// Передаём данные клиенту
				client.push(view_t(buffer.data(), buffer.size()));
				// Отмечаем передачу данных
				moved = true;
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) { return false; }
		// Возвращаем признак передачи данных
		return moved;
	}
	// Прокачиваем данные между сторонами до установления связи
	void converse(client::context_t & client, server::context_t & server) noexcept {
		/** Прокачиваем данные между сторонами, пока связь двигается */
		for(size_t i = 0; (i < 16) && pump(client, server); i++) continue;
	}
};

/**
 * Перехват выдачи и освобождения кучи
 */
void * operator new(size_t size){ void * p = ::malloc(size ? size : 1); if(p == nullptr) throw bad_alloc(); track(p, size); return p; }
// Перехватываем выдачу массива кучи: выделяем, учитываем, возвращаем
void * operator new[](size_t size){ void * p = ::malloc(size ? size : 1); if(p == nullptr) throw bad_alloc(); track(p, size); return p; }
// Перехватываем выдачу кучи без исключений: выделяем и учитываем
void * operator new(size_t size, const nothrow_t &) noexcept { void * p = ::malloc(size ? size : 1); track(p, size); return p; }
// Перехватываем выдачу массива кучи без исключений: выделяем и учитываем
void * operator new[](size_t size, const nothrow_t &) noexcept { void * p = ::malloc(size ? size : 1); track(p, size); return p; }
// Перехватываем освобождение кучи: снимаем с учёта и отдаём
void operator delete(void * p) noexcept { untrack(p); ::free(p); }
// Перехватываем освобождение массива кучи: снимаем с учёта и отдаём
void operator delete[](void * p) noexcept { untrack(p); ::free(p); }
// Перехватываем освобождение кучи с размером: снимаем с учёта и отдаём
void operator delete(void * p, size_t) noexcept { untrack(p); ::free(p); }
// Перехватываем освобождение массива кучи с размером: снимаем с учёта и отдаём
void operator delete[](void * p, size_t) noexcept { untrack(p); ::free(p); }

/**
 * Проверка: ключ билета не проходит через обычную кучу ни живым, ни освобождённым
 */
TEST(TraceTest, TicketKey) {
	// Объявляем учётные данные
	context::credential_t credentials;
	// Загружаем личность сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Ключи выданных билетов: на стеке, чтобы искать их в куче
	uint8_t keys[2][64];
	// Объявляем длину ключа билета
	size_t width = 0;
	// Включаем учёт
	recording = true;
	{
		// Объявляем контекст клиента
		client::context_t client;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(client);
		// Объявляем контекст сервера
		server::context_t server;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(server);
		// Назначаем серверу учётные данные
		server.credential(credentials);
		// Запускаем сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Прокачиваем рукопожатие
		converse(client, server);
		// Проверяем установление связи
		ASSERT_TRUE(client.established() && server.established());
		// Выдаём первый билет
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		// Доставляем билет клиенту
		pump(client, server);
		// Проверяем число полученных билетов
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (2));
		// Берём длину ключа билета
		width = client.tickets()[0].secret.size();
		// Проверяем нижнюю границу длины ключа
		ASSERT_GE(width, static_cast <size_t> (32));
		// Проверяем верхнюю границу длины ключа
		ASSERT_LE(width, static_cast <size_t> (64));
		::memcpy(keys[0], client.tickets()[0].secret.data(), width);
		::memcpy(keys[1], client.tickets()[1].secret.data(), width);
		/**
		 * Живая связь: ключей в обычной куче нет
		 */
		for(size_t i = 0; i < 2; i++){
			// Объявляем длину блока с найденным ключом
			size_t where = 0;
			// Проверяем отсутствие ключа в живых блоках кучи
			EXPECT_EQ(alive(keys[i], width, &where), 0u) << "ключ " << i << " живёт в блоке кучи длиной " << where;
			EXPECT_EQ(buried(keys[i], width), 0u) << "ключ " << i << " лежит в освобождённом блоке кучи";
			EXPECT_EQ(stacked(keys[i], width, &keys[0][0], sizeof(keys)), 0u) << "ключ " << i << " остался на стеке";
		}
		// Возобновление: билет проходит resume() у обеих сторон
		client::context_t again;
		// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
		gosting(again);
		// Объявляем контекст сервера для возобновления
		server::context_t peer;
		// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
		gosting(peer);
		// Назначаем серверу учётные данные
		peer.credential(credentials);
		// Отправляем серверу билет для возобновления
		peer.resume(vector <context::ticket_t> {server.tickets()[0]});
		// Отправляем клиенту билет для возобновления
		again.resume(client.tickets()[0]);
		// Запускаем сервер
		ASSERT_EQ(peer.start(), context::error_t::NONE);
		ASSERT_EQ(again.start(), context::error_t::NONE);
		// Прокачиваем возобновление
		converse(again, peer);
		// Проверяем установление связи
		ASSERT_TRUE(again.established() && peer.established());
		/** Перебираем ключи билетов после возобновления */
		for(size_t i = 0; i < 2; i++){
			// Объявляем длину блока с найденным ключом
			size_t where = 0;
			// Проверяем отсутствие ключа в живых блоках кучи
			EXPECT_EQ(alive(keys[i], width, &where), 0u) << "после возобновления ключ " << i << " живёт в блоке кучи длиной " << where;
			EXPECT_EQ(buried(keys[i], width), 0u) << "после возобновления ключ " << i << " лежит в освобождённом блоке кучи";
			EXPECT_EQ(stacked(keys[i], width, &keys[0][0], sizeof(keys)), 0u) << "после возобновления ключ " << i << " остался на стеке";
		}
	}
	/**
	 * После разрушения связей
	 */
	for(size_t i = 0; i < 2; i++){
		// Объявляем длину блока с найденным ключом
		size_t where = 0;
		// Проверяем отсутствие ключа в живых блоках кучи
		EXPECT_EQ(alive(keys[i], width, &where), 0u) << "после разрушения ключ " << i << " живёт в блоке кучи длиной " << where;
		EXPECT_EQ(buried(keys[i], width), 0u) << "после разрушения ключ " << i << " лежит в освобождённом блоке кучи";
		EXPECT_EQ(stacked(keys[i], width, &keys[0][0], sizeof(keys)), 0u) << "после разрушения ключ " << i << " остался на стеке";
	}
	// Проверяем, что журнал освобождённых не переполнен
	EXPECT_FALSE(overflowed) << "журнал освобождённых переполнен: проверка слепа";
	// Выключаем учёт кучи
	recording = false;
}
