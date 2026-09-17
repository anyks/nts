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
 * \~russian
 * @brief Проверка следа ключа билета в обычной куче: перехват new/delete ловит проход ключа
 *        через кучу детерминированно, а не по частоте переиспользования освобождённого
 *
 * @details Всякий блок кучи учитывается при выдаче и целиком переписывается в журнал при
 *          освобождении; после выдачи билетов и возобновления ключи билетов ищутся и в живых
 *          блоках, и в журнале освобождённых. Находка щупа Григория на Alpine (musl): третья
 *          копия ключа в обычной куче, вне хранилища, до 5 из 10 прогонов
 *
 * \~english
 * @brief Test of the trace of the ticket key in the ordinary heap by hooking new/delete
 *
 * \~
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
#else
	#include <pthread.h>
	#if defined(__FreeBSD__) || defined(__DragonFly__)
		#include <pthread_np.h>
	#endif
	#if defined(__OpenBSD__)
		#include <signal.h>
		#include <pthread_np.h>
	#endif
#endif
#include <main.hpp>
#include <identity.hpp>
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
		h ^= (h >> 33); h *= 0xff51afd7ed558ccdULL; h ^= (h >> 33);
		return static_cast <size_t> (h & (CELLS - 1));
	}
	/**
	 * Учёт выдачи блока
	 */
	void track(void * ptr, const size_t size) noexcept {
		if(!recording || (ptr == nullptr)) return;
		size_t i = slot(ptr);
		for(size_t n = 0; n < CELLS; n++, i = ((i + 1) & (CELLS - 1))){
			if(cells[i].ptr == nullptr){ cells[i].ptr = ptr; cells[i].size = size; return; }
		}
	}
	/**
	 * Сличение байтов без перехватчиков санитайзера: мера читает блоки целиком, включая
	 * хвост вектора между размером и ёмкостью, который ASan помечает переполнением
	 * контейнера; для меры это законное чтение своей же учтённой области
	 */
	#if defined(__clang__) || defined(__GNUC__)
		__attribute__((no_sanitize("address")))
	#endif
	static bool same(const uint8_t * data, const uint8_t * key, const size_t size) noexcept {
		uint8_t diff = 0;
		for(size_t i = 0; i < size; i++) diff |= static_cast <uint8_t> (data[i] ^ key[i]);
		return (diff == 0);
	}
	/**
	 * Копирование байтов без перехватчиков санитайзера: журнал снимает освобождаемый блок целиком
	 */
	#if defined(__clang__) || defined(__GNUC__)
		__attribute__((no_sanitize("address")))
	#endif
	static void copy(uint8_t * to, const void * from, const size_t size) noexcept {
		const uint8_t * data = static_cast <const uint8_t *> (from);
		for(size_t i = 0; i < size; i++) to[i] = data[i];
	}
	/**
	 * Снятие блока с учёта с переписыванием содержимого в журнал
	 */
	void untrack(void * ptr) noexcept {
		if(!recording || (ptr == nullptr)) return;
		size_t i = slot(ptr);
		for(size_t n = 0; n < CELLS; n++, i = ((i + 1) & (CELLS - 1))){
			if(cells[i].ptr == nullptr) return;
			if(cells[i].ptr == ptr){
				const size_t size = ((cells[i].size > LARGEST) ? LARGEST : cells[i].size);
				if((filled + size) <= JOURNAL){ copy(journal + filled, ptr, size); filled += size; }
				else overflowed = true;
				// Удаление из открытой адресации: помечаем надгробием (адрес 1), поиск его пропускает
				cells[i].ptr = reinterpret_cast <void *> (1);
				cells[i].size = 0;
				return;
			}
		}
	}
	/**
	 * Поиск образца среди живых блоков: число вхождений
	 */
	size_t alive(const uint8_t * key, const size_t size, size_t * where) noexcept {
		size_t count = 0;
		for(size_t i = 0; i < CELLS; i++){
			if((cells[i].ptr == nullptr) || (cells[i].ptr == reinterpret_cast <void *> (1)) || (cells[i].size < size)) continue;
			const uint8_t * data = static_cast <const uint8_t *> (cells[i].ptr);
			for(size_t j = 0; (j + size) <= cells[i].size; j++){
				if(same(data + j, key, size)){ if(where != nullptr) *where = cells[i].size; count++; break; }
			}
		}
		return count;
	}
	/**
	 * Поиск образца в журнале освобождённых: число вхождений
	 */
	size_t buried(const uint8_t * key, const size_t size) noexcept {
		size_t count = 0;
		for(size_t j = 0; (j + size) <= filled; j++)
			if(same(journal + j, key, size)) count++;
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
		const uint8_t * high = const_cast <const uint8_t *> (&marker);
		const uint8_t * low = nullptr;
		#if defined(_WIN32)
			/**
			 * Нижняя граница: начало ОТОБРАЖЁННОЙ области стека, в которой лежит текущий кадр
			 * (годно и MinGW, и MSVC любого издания). Ниже неё - сторожевая страница и
			 * неотображённый запас: чтение туда роняет процесс, а отработавшие кадры лежат
			 * в той же отображённой области, что и живые
			 */
			MEMORY_BASIC_INFORMATION region;
			if(::VirtualQuery(const_cast <uint8_t *> (high), &region, sizeof(region)) != 0)
				low = static_cast <const uint8_t *> (region.BaseAddress);
		#elif defined(__APPLE__)
			const uint8_t * top = static_cast <const uint8_t *> (pthread_get_stackaddr_np(pthread_self()));
			low = (top - pthread_get_stacksize_np(pthread_self()));
		#elif defined(__OpenBSD__)
			// У OpenBSD границы стека даёт pthread_stackseg_np: вершина и длина
			stack_t segment;
			if(pthread_stackseg_np(pthread_self(), &segment) == 0)
				low = (static_cast <const uint8_t *> (segment.ss_sp) - segment.ss_size);
		#elif defined(__FreeBSD__) || defined(__DragonFly__)
			// У FreeBSD и DragonFly признаки потока берутся pthread_attr_get_np
			pthread_attr_t attr;
			void * base = nullptr; size_t length = 0;
			pthread_attr_init(&attr);
			if((pthread_attr_get_np(pthread_self(), &attr) == 0) && (pthread_attr_getstack(&attr, &base, &length) == 0))
				low = static_cast <const uint8_t *> (base);
			pthread_attr_destroy(&attr);
		#else
			// Linux, NetBSD, Solaris: pthread_getattr_np
			pthread_attr_t attr;
			void * base = nullptr; size_t length = 0;
			if((pthread_getattr_np(pthread_self(), &attr) == 0) && (pthread_attr_getstack(&attr, &base, &length) == 0))
				low = static_cast <const uint8_t *> (base);
			pthread_attr_destroy(&attr);
		#endif
		if((low == nullptr) || (high <= low)) return 0;
		// Ниже сегодняшнего кадра на глубину до 1 МБ: глубже рукопожатие не ходило
		if((high - low) > (1u << 20)) low = (high - (1u << 20));
		size_t count = 0;
		for(const uint8_t * p = low; (p + size) <= high; p++){
			if((p >= skip) && (p < (skip + span))) continue;
			if(same(p, key, size)){ count++; ::printf("след ключа на стеке: %td байтов ниже кадра\n", high - p); }
		}
		return count;
	}
	/**
	 * Помощники связи: как в проверках контекста
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
		bool moved = false;
		try {
			view_t data = client.output();
			if(data.size > 0){
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				client.consume(buffer.size());
				server.push(view_t(buffer.data(), buffer.size()));
				moved = true;
			}
			data = server.output();
			if(data.size > 0){
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				server.consume(buffer.size());
				client.push(view_t(buffer.data(), buffer.size()));
				moved = true;
			}
		} catch(const bad_alloc &) { return false; }
		return moved;
	}
	void converse(client::context_t & client, server::context_t & server) noexcept {
		for(size_t i = 0; (i < 16) && pump(client, server); i++) continue;
	}
};

/**
 * Перехват выдачи и освобождения кучи
 */
void * operator new(size_t size){ void * p = ::malloc(size ? size : 1); if(p == nullptr) throw bad_alloc(); track(p, size); return p; }
void * operator new[](size_t size){ void * p = ::malloc(size ? size : 1); if(p == nullptr) throw bad_alloc(); track(p, size); return p; }
void * operator new(size_t size, const nothrow_t &) noexcept { void * p = ::malloc(size ? size : 1); track(p, size); return p; }
void * operator new[](size_t size, const nothrow_t &) noexcept { void * p = ::malloc(size ? size : 1); track(p, size); return p; }
void operator delete(void * p) noexcept { untrack(p); ::free(p); }
void operator delete[](void * p) noexcept { untrack(p); ::free(p); }
void operator delete(void * p, size_t) noexcept { untrack(p); ::free(p); }
void operator delete[](void * p, size_t) noexcept { untrack(p); ::free(p); }

/**
 * Проверка: ключ билета не проходит через обычную кучу ни живым, ни освобождённым
 */
TEST(TraceTest, TicketKey) {
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Ключи выданных билетов: на стеке, чтобы искать их в куче
	uint8_t keys[2][64];
	size_t width = 0;
	// Включаем учёт
	recording = true;
	{
		client::context_t client;
		server::context_t server;
		server.credential(credentials);
		ASSERT_EQ(server.start(), context::error_t::NONE);
		ASSERT_EQ(client.start(), context::error_t::NONE);
		converse(client, server);
		ASSERT_TRUE(client.established() && server.established());
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		ASSERT_EQ(server.issue(), context::error_t::NONE);
		pump(client, server);
		ASSERT_EQ(client.tickets().size(), static_cast <size_t> (2));
		width = client.tickets()[0].secret.size();
		ASSERT_GE(width, static_cast <size_t> (32));
		ASSERT_LE(width, static_cast <size_t> (64));
		::memcpy(keys[0], client.tickets()[0].secret.data(), width);
		::memcpy(keys[1], client.tickets()[1].secret.data(), width);
		// Живая связь: ключей в обычной куче нет
		for(size_t i = 0; i < 2; i++){
			size_t where = 0;
			EXPECT_EQ(alive(keys[i], width, &where), 0u) << "ключ " << i << " живёт в блоке кучи длиной " << where;
			EXPECT_EQ(buried(keys[i], width), 0u) << "ключ " << i << " лежит в освобождённом блоке кучи";
			EXPECT_EQ(stacked(keys[i], width, &keys[0][0], sizeof(keys)), 0u) << "ключ " << i << " остался на стеке";
		}
		// Возобновление: билет проходит resume() у обеих сторон
		client::context_t again;
		server::context_t peer;
		peer.credential(credentials);
		peer.resume(vector <context::ticket_t> {server.tickets()[0]});
		again.resume(client.tickets()[0]);
		ASSERT_EQ(peer.start(), context::error_t::NONE);
		ASSERT_EQ(again.start(), context::error_t::NONE);
		converse(again, peer);
		ASSERT_TRUE(again.established() && peer.established());
		for(size_t i = 0; i < 2; i++){
			size_t where = 0;
			EXPECT_EQ(alive(keys[i], width, &where), 0u) << "после возобновления ключ " << i << " живёт в блоке кучи длиной " << where;
			EXPECT_EQ(buried(keys[i], width), 0u) << "после возобновления ключ " << i << " лежит в освобождённом блоке кучи";
			EXPECT_EQ(stacked(keys[i], width, &keys[0][0], sizeof(keys)), 0u) << "после возобновления ключ " << i << " остался на стеке";
		}
	}
	// После разрушения связей
	for(size_t i = 0; i < 2; i++){
		size_t where = 0;
		EXPECT_EQ(alive(keys[i], width, &where), 0u) << "после разрушения ключ " << i << " живёт в блоке кучи длиной " << where;
		EXPECT_EQ(buried(keys[i], width), 0u) << "после разрушения ключ " << i << " лежит в освобождённом блоке кучи";
		EXPECT_EQ(stacked(keys[i], width, &keys[0][0], sizeof(keys)), 0u) << "после разрушения ключ " << i << " остался на стеке";
	}
	EXPECT_FALSE(overflowed) << "журнал освобождённых переполнен: проверка слепа";
	recording = false;
}
