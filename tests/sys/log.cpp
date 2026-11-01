/**
 * @file log.cpp
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
 * @brief Проверки стока журнала: без стока библиотека молчит, со стоком отдаёт уровень и строку
 *
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstring>

/**
 * Системные заголовочные файлы
 */
#if !defined(_WIN32)
	#include <sys/resource.h>
#endif

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <identity.hpp>
#include <gost.hpp>
#include <sys/log.hpp>
#include <sys/vault.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * Накопитель сообщений проверки
 */
namespace {
	// Запись журнала
	struct entry_t {
		// Объявляем уровень записи
		sys::log::level_t level;
		// Объявляем текст записи
		string text;
	};
	// Накопитель
	struct journal_t {
		// Объявляем накопленные записи
		vector <entry_t> entries;
		// Объявляем контекст стока
		void * context;
		// Обнуляем контекст при создании накопителя
		journal_t() noexcept : context(nullptr) {}
	};
	/**
	 * Сток проверки: складывает сообщения в накопитель из контекста
	 */
	void collect(const sys::log::level_t level, const char * text, void * context) noexcept {
		// Получаем накопитель из контекста
		journal_t * journal = static_cast <journal_t *> (context);
		// Запоминаем контекст в накопителе
		journal->context = context;
		// Добавляем запись в накопитель
		journal->entries.push_back(entry_t{level, string(text)});
	}
	/**
	 * Число записей с подстрокой
	 */
	size_t count(const journal_t & journal, const char * needle) noexcept {
		// Объявляем счётчик найденных записей
		size_t result = 0;
		/**
		 * Перебираем: записи накопителя при условии вхождения подстроки
		 */
		for(const auto & entry : journal.entries)
			// Увеличиваем счётчик при вхождении подстроки
			if(entry.text.find(needle) != string::npos) result++;
		// Возвращаем число найденных записей
		return result;
	}
};

/**
 * Проверка: без стока библиотека молчит и строк не собирает
 */
TEST(LogTest, Silent) {
	// Отключаем сток журнала
	sys::log::sink(nullptr);
	// Проверяем отключение журнала
	EXPECT_FALSE(sys::log::enabled());
	// Вызовы без стока безопасны
	sys::log::emit(sys::log::level_t::INFO, "ничего");
	// Проверяем безопасность образца printf без стока
	sys::log::emitf(sys::log::level_t::WARNING, "%s %d", "ничего", 1);
	// Проверяем безопасность пустой строки без стока
	sys::log::emit(sys::log::level_t::INFO, nullptr);
	// Проверяем безопасность пустого образца без стока
	sys::log::emitf(sys::log::level_t::INFO, nullptr);
}

/**
 * Проверка: сток получает уровень, строку и контекст; образец printf собирается; снятие стока молчит
 */
TEST(LogTest, Sink) {
	// Объявляем накопитель сообщений
	journal_t journal;
	// Устанавливаем проверочный сток
	sys::log::sink(&collect, &journal);
	// Проверяем включение журнала
	ASSERT_TRUE(sys::log::enabled());
	// Отправляем готовую строку в сток
	sys::log::emit(sys::log::level_t::INFO, "готовая строка");
	// Отправляем строку по образцу printf в сток
	sys::log::emitf(sys::log::level_t::CRITICAL, "образец %s %u", "строки", 42u);
	// Проверяем число записей в накопителе
	ASSERT_EQ(journal.entries.size(), 2u);
	// Проверяем уровень первой записи
	EXPECT_EQ(journal.entries[0].level, sys::log::level_t::INFO);
	EXPECT_EQ(journal.entries[0].text, "готовая строка");
	EXPECT_EQ(journal.entries[1].level, sys::log::level_t::CRITICAL);
	EXPECT_EQ(journal.entries[1].text, "образец строки 42");
	EXPECT_EQ(journal.context, &journal);
	// Пустая строка стоку не идёт
	sys::log::emit(sys::log::level_t::INFO, nullptr);
	// Проверяем отсутствие записи пустой строки
	EXPECT_EQ(journal.entries.size(), 2u);
	// Длинное сообщение обрезается, а не переполняет буфер
	const string longer(2000, 'x');
	// Отправляем длинное сообщение в сток
	sys::log::emitf(sys::log::level_t::WARNING, "%s", longer.c_str());
	// Проверяем добавление обрезанной записи
	ASSERT_EQ(journal.entries.size(), 3u);
	// Проверяем обрезку сообщения до предела буфера
	EXPECT_EQ(journal.entries[2].text.size(), 511u);
	// Снятие стока: библиотека снова молчит
	sys::log::sink(nullptr);
	// Проверяем отключение журнала
	EXPECT_FALSE(sys::log::enabled());
	// Проверяем безопасность отправки без стока
	sys::log::emit(sys::log::level_t::INFO, "мимо");
	// Проверяем отсутствие новых записей
	EXPECT_EQ(journal.entries.size(), 3u);
}

/**
 * Проверка: обрыв связи извещением уходит в сток отказом с именем извещения и без тайн
 */
TEST(LogTest, Abort) {
	// Объявляем накопитель сообщений
	journal_t journal;
	// Устанавливаем проверочный сток
	sys::log::sink(&collect, &journal);
	// Объявляем учётные данные
	context::credential_t credentials;
	// Загружаем учётные данные стороны сервера
	ASSERT_TRUE(identity("anyks.com", credentials));
	// Объявляем контекст стороны клиента
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	// Объявляем контекст стороны сервера
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	// Устанавливаем учётные данные сервера
	server.credential(credentials);
	// Запускаем сторону сервера
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Первый залп клиента серверу
	view_t hello = client.output();
	// Проверяем наличие первого залпа клиента
	ASSERT_GT(hello.size, 0u);
	// Копируем приветствие клиента в буфер
	const vector <uint8_t> greeting(hello.data, hello.data + hello.size);
	// Убираем приветствие из вывода клиента
	client.consume(greeting.size());
	// Передаём приветствие серверу
	ASSERT_EQ(server.push(view_t(greeting.data(), greeting.size())), context::error_t::NONE);
	// Ответ сервера с испорченным последним байтом: защита записи не сходится, клиент обрывает связь извещением
	const view_t data = server.output();
	// Проверяем наличие ответа сервера
	ASSERT_GT(data.size, 0u);
	// Копируем ответ сервера в буфер
	vector <uint8_t> buffer(data.data, data.data + data.size);
	// Убираем ответ из вывода сервера
	server.consume(buffer.size());
	// Портим последний байт ответа сервера
	buffer[buffer.size() - 1] ^= 0x01;
	// Передаём порченый ответ клиенту
	client.push(view_t(buffer.data(), buffer.size()));
	// Проверяем обрыв связи у клиента
	ASSERT_EQ(client.state(), context::state_t::FAILED);
	ASSERT_EQ(client.error(), context::error_t::PROTECTION);
	// В стоке сообщение об обрыве у клиента: отказ, имя извещения, без тайн
	ASSERT_EQ(count(journal, "client: connection aborted"), 1u);
	// Объявляем признак критической записи об обрыве
	bool critical = false;
	/**
	 * Перебираем: записи накопителя при условии поиска критической записи об обрыве
	 */
	for(const auto & entry : journal.entries)
		// Отмечаем нахождение критической записи об обрыве
		if((entry.text.find("connection aborted") != string::npos) && (entry.level == sys::log::level_t::CRITICAL)) critical = true;
	// Проверяем наличие критической записи об обрыве
	EXPECT_TRUE(critical);
	// Проверяем запись с именем извещения об обрыве
	EXPECT_EQ(count(journal, "alert bad_record_mac"), 1u);
	EXPECT_EQ(count(journal, "error 5"), 1u);
	/**
	 * Перебираем: записи накопителя при условии проверки длины сообщений
	 */
	for(const auto & entry : journal.entries)
		// Проверяем укладку сообщений в предел длины
		EXPECT_LT(entry.text.size(), 160u) << entry.text;
	// Отключаем сток журнала
	sys::log::sink(nullptr);
}

/**
 * Для операционных систем POSIX
 */
#if !defined(_WIN32)
	/**
	 * Проверка: понижение укрытия хранилища уходит в сток предупреждением
	 */
	TEST(LogTest, Vault) {
		// Объявляем накопитель сообщений
		journal_t journal;
		// Устанавливаем проверочный сток
		sys::log::sink(&collect, &journal);
		// Получаем хранилище укрытия
		sys::vault_t & vault = sys::Vault::instance();
		// Объявляем прежний предел блокировки памяти
		struct rlimit previous;
		// Читаем предел блокировки памяти
		ASSERT_EQ(::getrlimit(RLIMIT_MEMLOCK, &previous), 0);
		// Объявляем нулевой предел блокировки памяти
		struct rlimit zero = previous;
		// Обнуляем текущий предел блокировки
		zero.rlim_cur = 0;
		// Понижаем предел блокировки памяти
		if(::setrlimit(RLIMIT_MEMLOCK, &zero) != 0)
			// Пропускаем проверку при недоступном пределе
			GTEST_SKIP() << "предел RLIMIT_MEMLOCK не устанавливается";
		// Новый кусок под нулевым пределом: понижение и предупреждение
		const size_t length = (65536 * 3);
		// Запрашиваем кусок у хранилища укрытия
		uint8_t * lowered = static_cast <uint8_t *> (vault.take(length));
		// Проверяем обход системой нулевого предела
		if((lowered != nullptr) && vault.shelter().wired){
			// Возвращаем кусок хранилищу
			vault.give(lowered, length);
			::setrlimit(RLIMIT_MEMLOCK, &previous);
			// Отключаем сток журнала
			sys::log::sink(nullptr);
			// Завершаем проверку: система блюдёт предел блокировки
			GTEST_SKIP() << "система предел RLIMIT_MEMLOCK не блюдёт";
		}
		// Проверяем понижение укрытия куска
		ASSERT_NE(lowered, nullptr);
		// Проверяем предупреждение о частичном укрытии
		EXPECT_GE(count(journal, "sheltered partially"), 1u);
		EXPECT_GE(count(journal, "wired no"), 1u);
		// Возвращаем кусок хранилищу
		vault.give(lowered, length);
		// Под требованием: отказ и сообщение об отказе
		vault.demand(true);
		// Проверяем отказ выдачи куска под требованием
		EXPECT_EQ(vault.take(length * 2), nullptr);
		// Проверяем сообщение об отказе
		EXPECT_GE(count(journal, "refused"), 1u);
		// Снимаем требование отказа
		vault.demand(false);
		::setrlimit(RLIMIT_MEMLOCK, &previous);
		// Отключаем сток журнала
		sys::log::sink(nullptr);
	}
#endif
