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
 * \~russian
 * @brief Проверки стока журнала: без стока библиотека молчит, со стоком отдаёт уровень и строку
 *
 * \~english
 * @brief Tests of the log sink
 *
 * \~
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
		sys::log::level_t level;
		string text;
	};
	// Накопитель
	struct journal_t {
		vector <entry_t> entries;
		void * context;
		journal_t() noexcept : context(nullptr) {}
	};
	/**
	 * Сток проверки: складывает сообщения в накопитель из контекста
	 */
	void collect(const sys::log::level_t level, const char * text, void * context) noexcept {
		journal_t * journal = static_cast <journal_t *> (context);
		journal->context = context;
		journal->entries.push_back(entry_t{level, string(text)});
	}
	/**
	 * Число записей с подстрокой
	 */
	size_t count(const journal_t & journal, const char * needle) noexcept {
		size_t result = 0;
		for(const auto & entry : journal.entries)
			if(entry.text.find(needle) != string::npos) result++;
		return result;
	}
};

/**
 * Проверка: без стока библиотека молчит и строк не собирает
 */
TEST(LogTest, Silent) {
	sys::log::sink(nullptr);
	EXPECT_FALSE(sys::log::enabled());
	// Вызовы без стока безопасны
	sys::log::emit(sys::log::level_t::INFO, "ничего");
	sys::log::emitf(sys::log::level_t::WARNING, "%s %d", "ничего", 1);
	sys::log::emit(sys::log::level_t::INFO, nullptr);
	sys::log::emitf(sys::log::level_t::INFO, nullptr);
}

/**
 * Проверка: сток получает уровень, строку и контекст; образец printf собирается; снятие стока молчит
 */
TEST(LogTest, Sink) {
	journal_t journal;
	sys::log::sink(&collect, &journal);
	ASSERT_TRUE(sys::log::enabled());
	sys::log::emit(sys::log::level_t::INFO, "готовая строка");
	sys::log::emitf(sys::log::level_t::CRITICAL, "образец %s %u", "строки", 42u);
	ASSERT_EQ(journal.entries.size(), 2u);
	EXPECT_EQ(journal.entries[0].level, sys::log::level_t::INFO);
	EXPECT_EQ(journal.entries[0].text, "готовая строка");
	EXPECT_EQ(journal.entries[1].level, sys::log::level_t::CRITICAL);
	EXPECT_EQ(journal.entries[1].text, "образец строки 42");
	EXPECT_EQ(journal.context, &journal);
	// Пустая строка стоку не идёт
	sys::log::emit(sys::log::level_t::INFO, nullptr);
	EXPECT_EQ(journal.entries.size(), 2u);
	// Длинное сообщение обрезается, а не переполняет буфер
	const string longer(2000, 'x');
	sys::log::emitf(sys::log::level_t::WARNING, "%s", longer.c_str());
	ASSERT_EQ(journal.entries.size(), 3u);
	EXPECT_EQ(journal.entries[2].text.size(), 511u);
	// Снятие стока: библиотека снова молчит
	sys::log::sink(nullptr);
	EXPECT_FALSE(sys::log::enabled());
	sys::log::emit(sys::log::level_t::INFO, "мимо");
	EXPECT_EQ(journal.entries.size(), 3u);
}

/**
 * Проверка: обрыв связи извещением уходит в сток отказом с именем извещения и без тайн
 */
TEST(LogTest, Abort) {
	journal_t journal;
	sys::log::sink(&collect, &journal);
	context::credential_t credentials;
	ASSERT_TRUE(identity("anyks.com", credentials));
	client::context_t client;
	// Объявляем ГОСТ в настройках связи стороны клиента: умолчания связи - классика без ГОСТ
	gosting(client);
	server::context_t server;
	// Объявляем ГОСТ в настройках связи стороны сервера: умолчания связи - классика без ГОСТ
	gosting(server);
	server.credential(credentials);
	ASSERT_EQ(server.start(), context::error_t::NONE);
	ASSERT_EQ(client.start(), context::error_t::NONE);
	// Первый залп клиента серверу
	view_t hello = client.output();
	ASSERT_GT(hello.size, 0u);
	const vector <uint8_t> greeting(hello.data, hello.data + hello.size);
	client.consume(greeting.size());
	ASSERT_EQ(server.push(view_t(greeting.data(), greeting.size())), context::error_t::NONE);
	// Ответ сервера с испорченным последним байтом: защита записи не сходится, клиент обрывает связь извещением
	const view_t data = server.output();
	ASSERT_GT(data.size, 0u);
	vector <uint8_t> buffer(data.data, data.data + data.size);
	server.consume(buffer.size());
	buffer[buffer.size() - 1] ^= 0x01;
	client.push(view_t(buffer.data(), buffer.size()));
	ASSERT_EQ(client.state(), context::state_t::FAILED);
	ASSERT_EQ(client.error(), context::error_t::PROTECTION);
	// В стоке сообщение об обрыве у клиента: отказ, имя извещения, без тайн
	ASSERT_EQ(count(journal, "client: connection aborted"), 1u);
	bool critical = false;
	for(const auto & entry : journal.entries)
		if((entry.text.find("connection aborted") != string::npos) && (entry.level == sys::log::level_t::CRITICAL)) critical = true;
	EXPECT_TRUE(critical);
	EXPECT_EQ(count(journal, "alert bad_record_mac"), 1u);
	EXPECT_EQ(count(journal, "error 5"), 1u);
	for(const auto & entry : journal.entries)
		EXPECT_LT(entry.text.size(), 160u) << entry.text;
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
		journal_t journal;
		sys::log::sink(&collect, &journal);
		sys::vault_t & vault = sys::Vault::instance();
		struct rlimit previous;
		ASSERT_EQ(::getrlimit(RLIMIT_MEMLOCK, &previous), 0);
		struct rlimit zero = previous;
		zero.rlim_cur = 0;
		if(::setrlimit(RLIMIT_MEMLOCK, &zero) != 0)
			GTEST_SKIP() << "предел RLIMIT_MEMLOCK не устанавливается";
		// Новый кусок под нулевым пределом: понижение и предупреждение
		const size_t length = (65536 * 3);
		uint8_t * lowered = static_cast <uint8_t *> (vault.take(length));
		if((lowered != nullptr) && vault.shelter().wired){
			vault.give(lowered, length);
			::setrlimit(RLIMIT_MEMLOCK, &previous);
			sys::log::sink(nullptr);
			GTEST_SKIP() << "система предел RLIMIT_MEMLOCK не блюдёт";
		}
		ASSERT_NE(lowered, nullptr);
		EXPECT_GE(count(journal, "sheltered partially"), 1u);
		EXPECT_GE(count(journal, "wired no"), 1u);
		vault.give(lowered, length);
		// Под требованием: отказ и сообщение об отказе
		vault.demand(true);
		EXPECT_EQ(vault.take(length * 2), nullptr);
		EXPECT_GE(count(journal, "refused"), 1u);
		vault.demand(false);
		::setrlimit(RLIMIT_MEMLOCK, &previous);
		sys::log::sink(nullptr);
	}
#endif
