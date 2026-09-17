/**
 * @file demand.cpp
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
 * @brief Проверка связи без укрытого участка: требование укрытия при недоступном запрете подкачки
 *
 * @details Отдельная программа: хранилище процесса не должно иметь кусков до проверки, иначе
 *          участок найдётся в уже принятом куске и отказ не воспроизвести
 *
 * \~english
 * @brief Test of a connection without a sheltered piece: the demand of the sheltering when the swap prohibition is unavailable
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

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
#include <sys/vault.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * Для операционных систем POSIX
 */
#if !defined(_WIN32)
	/**
	 * Проверка: под требованием укрытия без права на запрет подкачки связь негодна с рождения, а её разрушение не роняет процесс
	 * (находка Григория на DragonFly: mlock там непривилегированному запрещён вовсе)
	 */
	TEST(DemandTest, Refused) {
		// Хранилище процесса
		sys::vault_t & vault = sys::Vault::instance();
		// Кусков до проверки быть не должно: иначе участок найдётся в принятом куске
		ASSERT_EQ(vault.chunks(), 0u) << "проверка обязана идти первой в своём процессе";
		// Прежний предел запрета подкачки
		struct rlimit previous;
		// Снимаем прежний предел
		ASSERT_EQ(::getrlimit(RLIMIT_MEMLOCK, &previous), 0);
		// Новый предел: запрет подкачки не даётся вовсе
		struct rlimit zero = previous;
		// Обнуляем предел
		zero.rlim_cur = 0;
		// Если предел установить нельзя
		if(::setrlimit(RLIMIT_MEMLOCK, &zero) != 0)
			// Проверку не провести
			GTEST_SKIP() << "предел RLIMIT_MEMLOCK не устанавливается";
		// Требуем укрытие
		vault.demand(true);
		/**
		 * Область жизни связей: заведение, отказ запуска и разрушение
		 */
		{
			// Клиент и сервер
			client::context_t client;
			server::context_t server;
			// Настраиваем клиента
			client.name("example.com");
			client.verification(false, 0, trust::store_t());
			// Если под нулевым пределом участок всё же дан, система предел не блюдёт
			if(client.state() != context::state_t::FAILED){
				// Снимаем требование
				vault.demand(false);
				// Возвращаем прежний предел
				::setrlimit(RLIMIT_MEMLOCK, &previous);
				// Проверку не провести
				GTEST_SKIP() << "система предел RLIMIT_MEMLOCK не блюдёт";
			}
			// Связь негодна с рождения по отказу памяти
			EXPECT_EQ(client.state(), context::state_t::FAILED);
			EXPECT_EQ(client.error(), context::error_t::MEMORY);
			EXPECT_EQ(server.state(), context::state_t::FAILED);
			// Запуск отвечает отказом, а не падением
			EXPECT_NE(client.start(), context::error_t::NONE);
			// Разрушение по выходу из области: было падение в clear() по невыданному указателю
		}
		// Процесс жив: хранилище так и не дало ни куска
		EXPECT_EQ(vault.chunks(), 0u);
		// Снимаем требование
		vault.demand(false);
		// Возвращаем прежний предел
		::setrlimit(RLIMIT_MEMLOCK, &previous);
	}
#endif
