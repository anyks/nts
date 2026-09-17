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
 * @brief Проверки укрытого хранилища ключевого материала
 *
 * \~english
 * @brief Tests of the sheltered storage of the key material
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <vector>
#include <cstdint>
#include <cstring>

/**
 * Системные заголовочные файлы
 */
#if !defined(_WIN32)
	#include <posix.hpp>
	#include <sys/wait.h>
	#include <sys/resource.h>
#endif

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <sys/vault.hpp>

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * Проверка выдачи участка: адрес выровнен, участок обнулён, запись держится
 */
TEST(VaultTest, Take) {
	// Хранилище процесса
	sys::vault_t & vault = sys::Vault::instance();
	// Берём участок
	uint8_t * data = static_cast <uint8_t *> (vault.take(48));
	// Участок обязан быть выдан
	ASSERT_NE(data, nullptr);
	// Адрес участка выровнен на шестнадцать байтов
	EXPECT_EQ((reinterpret_cast <uintptr_t> (data) % 16), 0u);
	// Пишем в участок
	::memset(data, 0x5A, 48);
	// Запись держится
	EXPECT_EQ(data[0], 0x5A);
	EXPECT_EQ(data[47], 0x5A);
	// Пустого запроса нет
	EXPECT_EQ(vault.take(0), nullptr);
	// Возвращаем участок
	vault.give(data, 48);
}

/**
 * Проверка затирания при возврате: повторная выдача того же участка даёт нули
 */
TEST(VaultTest, GiveWipes) {
	// Хранилище процесса
	sys::vault_t & vault = sys::Vault::instance();
	// Берём участок
	uint8_t * first = static_cast <uint8_t *> (vault.take(64));
	// Участок обязан быть выдан
	ASSERT_NE(first, nullptr);
	// Заполняем участок тайной
	::memset(first, 0xC3, 64);
	// Возвращаем участок: он затирается и становится первым свободным нужной длины
	vault.give(first, 64);
	// Берём участок той же длины
	uint8_t * second = static_cast <uint8_t *> (vault.take(64));
	// Участок обязан быть выдан
	ASSERT_NE(second, nullptr);
	// Хранилище отдаёт тот же участок
	EXPECT_EQ(second, first);
	/**
	 * Выполняем перебор байтов участка
	 */
	for(size_t i = 0; i < 64; i++)
		// Байт тайны затёрт
		ASSERT_EQ(second[i], 0) << "байт " << i;
	// Возвращаем участок
	vault.give(second, 64);
}

/**
 * Проверка слияния свободных участков: три соседних возвращены, один на всю длину выдан по адресу первого
 */
TEST(VaultTest, Coalesce) {
	// Хранилище процесса
	sys::vault_t & vault = sys::Vault::instance();
	// Берём три соседних участка
	uint8_t * a = static_cast <uint8_t *> (vault.take(32));
	uint8_t * b = static_cast <uint8_t *> (vault.take(32));
	uint8_t * c = static_cast <uint8_t *> (vault.take(32));
	// Участки обязаны быть выданы
	ASSERT_NE(a, nullptr);
	ASSERT_NE(b, nullptr);
	ASSERT_NE(c, nullptr);
	// Участки идут подряд
	ASSERT_EQ(b, a + 32);
	ASSERT_EQ(c, b + 32);
	// Возвращаем средний, затем крайние: слияние с обоих боков
	vault.give(b, 32);
	vault.give(c, 32);
	vault.give(a, 32);
	// Берём участок на всю длину троих
	uint8_t * whole = static_cast <uint8_t *> (vault.take(96));
	// Слитый участок начинается с первого
	EXPECT_EQ(whole, a);
	// Возвращаем участок
	vault.give(whole, 96);
}

/**
 * Проверка роста хранилища: запрос длиннее куска берёт новый кусок
 */
TEST(VaultTest, Grow) {
	// Хранилище процесса
	sys::vault_t & vault = sys::Vault::instance();
	// Число кусков до запроса
	const size_t before = vault.chunks();
	// Берём участок длиннее куска
	uint8_t * data = static_cast <uint8_t *> (vault.take(65536 * 2 + 1));
	// Участок обязан быть выдан
	ASSERT_NE(data, nullptr);
	// Кусков стало больше
	EXPECT_GT(vault.chunks(), before);
	// Пишем в самый край участка
	data[65536 * 2] = 0x11;
	// Возвращаем участок
	vault.give(data, 65536 * 2 + 1);
}

/**
 * Проверка принадлежности адреса хранилищу: участок - да, стек и куча - нет
 */
TEST(VaultTest, Owns) {
	// Хранилище процесса
	sys::vault_t & vault = sys::Vault::instance();
	// Участок укрытой памяти
	sys::secret_t secret;
	// Заводим участок
	ASSERT_TRUE(secret.reserve(24));
	// Начало и конец участка принадлежат хранилищу
	EXPECT_TRUE(vault.owns(secret.data()));
	EXPECT_TRUE(vault.owns(secret.data() + 23));
	// Набор над хранилищем принадлежит ему
	sys::bytes_t bytes(16, 0x42);
	EXPECT_TRUE(vault.owns(bytes.data()));
	// Стек и обычная куча хранилищу не принадлежат
	uint8_t local[8];
	EXPECT_FALSE(vault.owns(local));
	vector <uint8_t> heap(8, 0);
	EXPECT_FALSE(vault.owns(heap.data()));
	EXPECT_FALSE(vault.owns(nullptr));
}

/**
 * Проверка честности доклада об укрытии
 */
TEST(VaultTest, Shelter) {
	// Хранилище процесса
	sys::vault_t & vault = sys::Vault::instance();
	// Берём участок, чтобы кусок был
	uint8_t * data = static_cast <uint8_t *> (vault.take(16));
	// Участок обязан быть выдан
	ASSERT_NE(data, nullptr);
	// Сведения об укрытии
	const sys::shelter_t shelter = vault.shelter();
	// Показываем, что состоялось на деле
	::printf("shelter: hidden=%d wired=%d forked=%d chunks=%zu\n", shelter.hidden, shelter.wired, shelter.forked, vault.chunks());
	/**
	 * Затирание у потомка обещано везде: либо системой, либо обработчиком разветвления
	 */
	EXPECT_TRUE(shelter.forked);
	/**
	 * У macOS предел запрета подкачки умолчанием не ограничен, и запрет обязан состояться
	 */
	#if defined(__APPLE__)
		EXPECT_TRUE(shelter.wired);
	#endif
	/**
	 * Укрытие от снимков есть у Linux, FreeBSD и DragonFly; прочие честно докладывают отказ
	 */
	#if defined(__linux__) || defined(__FreeBSD__) || defined(__DragonFly__)
		EXPECT_TRUE(shelter.hidden);
	#elif defined(__APPLE__)
		EXPECT_FALSE(shelter.hidden);
	#endif
	// Возвращаем участок
	vault.give(data, 16);
}

/**
 * Проверка участка: заведение обнуляет, затирание держит участок, перенос передаёт владение
 */
TEST(VaultTest, Secret) {
	// Участок укрытой памяти
	sys::secret_t secret;
	// Незаведённый участок пуст
	EXPECT_EQ(secret.data(), nullptr);
	EXPECT_EQ(secret.size(), 0u);
	// Пустого заведения нет
	EXPECT_FALSE(secret.reserve(0));
	// Заводим участок
	ASSERT_TRUE(secret.reserve(40));
	// Участок заведён
	ASSERT_NE(secret.data(), nullptr);
	EXPECT_EQ(secret.size(), 40u);
	/**
	 * Выполняем перебор байтов участка
	 */
	for(size_t i = 0; i < 40; i++)
		// Участок обнулён
		ASSERT_EQ(secret.data()[i], 0) << "байт " << i;
	// Заполняем участок тайной
	::memset(secret.data(), 0x77, 40);
	// Адрес участка
	uint8_t * address = secret.data();
	// Затираем участок без возврата
	secret.wipe();
	// Участок остаётся заведённым
	EXPECT_EQ(secret.data(), address);
	EXPECT_EQ(secret.size(), 40u);
	// Участок затёрт
	EXPECT_EQ(address[0], 0);
	EXPECT_EQ(address[39], 0);
	// Заполняем участок тайной снова
	::memset(secret.data(), 0x33, 40);
	// Переносим участок
	sys::secret_t moved(::move(secret));
	// Владение перешло
	EXPECT_EQ(moved.data(), address);
	EXPECT_EQ(moved.size(), 40u);
	EXPECT_EQ(secret.data(), nullptr);
	EXPECT_EQ(secret.size(), 0u);
	// Тайна на месте
	EXPECT_EQ(address[39], 0x33);
	// Переносим оператором
	secret = ::move(moved);
	// Владение вернулось
	EXPECT_EQ(secret.data(), address);
	EXPECT_EQ(moved.data(), nullptr);
	// Возвращаем участок
	secret.release();
	// Участок пуст
	EXPECT_EQ(secret.data(), nullptr);
	EXPECT_EQ(secret.size(), 0u);
	// Участок затёрт возвратом
	EXPECT_EQ(address[0], 0);
	EXPECT_EQ(address[39], 0);
}

/**
 * Проверка распределителя контейнеров: память из хранилища, освобождение затирает
 */
TEST(VaultTest, Allocator) {
	// Адрес памяти набора
	const uint8_t * address = nullptr;
	/**
	 * Область жизни набора
	 */
	{
		// Набор байтов на укрытой памяти
		sys::bytes_t bytes;
		// Заполняем набор тайной
		bytes.assign(48, 0xE1);
		// Запоминаем адрес памяти набора
		address = bytes.data();
		// Тайна на месте
		EXPECT_EQ(bytes[47], 0xE1);
		// Перекладываем набор: перенос не копирует память хранилища
		sys::bytes_t moved(::move(bytes));
		// Адрес прежний
		EXPECT_EQ(moved.data(), address);
	}
	// Берём участок той же длины: хранилище отдаёт затёртую память набора
	uint8_t * data = static_cast <uint8_t *> (sys::Vault::instance().take(48));
	// Участок обязан быть выдан
	ASSERT_NE(data, nullptr);
	// Участок тот же
	EXPECT_EQ(data, address);
	/**
	 * Выполняем перебор байтов участка
	 */
	for(size_t i = 0; i < 48; i++)
		// Тайна набора затёрта освобождением
		ASSERT_EQ(data[i], 0) << "байт " << i;
	// Возвращаем участок
	sys::Vault::instance().give(data, 48);
}

/**
 * Для операционных систем POSIX
 */
#if !defined(_WIN32)
	/**
	 * Проверка затирания у потомка: после разветвления потомок тайны не видит
	 */
	TEST(VaultTest, Fork) {
		// Участок укрытой памяти
		sys::secret_t secret;
		// Заводим участок
		ASSERT_TRUE(secret.reserve(32));
		// Заполняем участок тайной
		::memset(secret.data(), 0x9B, 32);
		// Разветвляем процесс
		const pid_t pid = ::fork();
		// Разветвление обязано состояться
		ASSERT_GE(pid, 0);
		// Если это потомок
		if(pid == 0){
			// Признак того, что тайна найдена у потомка
			bool leaked = false;
			/**
			 * Выполняем перебор байтов участка
			 */
			for(size_t i = 0; i < 32; i++)
				// Ищем байт тайны
				leaked = (leaked || (secret.data()[i] == 0x9B));
			// Отчитываемся кодом завершения, минуя деструкторы
			::_exit(leaked ? 1 : 0);
		}
		// Код завершения потомка
		int status = 0;
		// Ждём потомка
		ASSERT_EQ(::waitpid(pid, &status, 0), pid);
		// Потомок завершился сам
		ASSERT_TRUE(WIFEXITED(status));
		// Тайны у потомка нет
		EXPECT_EQ(WEXITSTATUS(status), 0);
		// У родителя тайна на месте
		EXPECT_EQ(secret.data()[0], 0x9B);
		EXPECT_EQ(secret.data()[31], 0x9B);
	}
	/**
	 * Проверка требования укрытия: под пределом запрета подкачки в нуль новый кусок отвергается
	 */
	TEST(VaultTest, Demand) {
		// Хранилище процесса
		sys::vault_t & vault = sys::Vault::instance();
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
		// Длина запроса, заведомо требующая нового куска
		const size_t length = (65536 * 3);
		// Сперва без требования: участок даётся, укрытие понижено и доложено
		vault.demand(false);
		// Берём участок
		uint8_t * lowered = static_cast <uint8_t *> (vault.take(length));
		// Если под нулевым пределом запрет подкачки всё же состоялся, система предел не блюдёт
		if((lowered != nullptr) && vault.shelter().wired){
			// Возвращаем участок
			vault.give(lowered, length);
			// Возвращаем прежний предел
			::setrlimit(RLIMIT_MEMLOCK, &previous);
			// Проверку не провести
			GTEST_SKIP() << "система предел RLIMIT_MEMLOCK не блюдёт";
		}
		// Участок дан
		ASSERT_NE(lowered, nullptr);
		// Понижение доложено честно
		EXPECT_FALSE(vault.shelter().wired);
		// Возвращаем участок
		vault.give(lowered, length);
		// Теперь с требованием: кусок без запрета подкачки не принимается
		vault.demand(true);
		// Требование выставлено
		EXPECT_TRUE(vault.demand());
		// Берём участок длиннее любого куска: нужен новый кусок, а он отвергается
		uint8_t * refused = static_cast <uint8_t *> (vault.take(length * 2));
		// Участок не дан
		EXPECT_EQ(refused, nullptr);
		// Если участок всё же дан
		if(refused != nullptr)
			// Возвращаем участок
			vault.give(refused, length * 2);
		// Снимаем требование
		vault.demand(false);
		// Возвращаем прежний предел
		::setrlimit(RLIMIT_MEMLOCK, &previous);
	}
#endif
