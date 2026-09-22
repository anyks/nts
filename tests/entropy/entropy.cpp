/**
 * @file entropy.cpp
 * @date 2026-08-29
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
 * @brief Исходный файл проверок модуля источника случайных значений
 *
 * @note Проверки эти на качество случайности не притязают: сколько-нибудь значимая
 *       её оценка требует наборов статистических испытаний и объёмов, набору
 *       проверок неподъёмных. Здесь ловятся отказы грубые: молчаливая выдача нулей,
 *       повтор одного и того же значения и перекос выпадения разрядов
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <set>
#include <string>
#include <vector>
#include <thread>
#include <cerrno>
#include <cstring>
#include <main.hpp>
#include <entropy/entropy.hpp>
#include <internal/entropy/generator.hpp>

/**
 * Разветвление процесса существует лишь у систем Unix
 */
#if !defined(_WIN32) && !defined(_WIN64)
	#include <unistd.h>
	#include <sys/wait.h>
#endif

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Проверка выдачи случайных байтов
 *
 */
TEST(EntropyTest, Bytes) {
	// Места, в которые помещаются случайные байты
	uint8_t first[64], second[64];
	// Выполняем обнуление мест случайных байтов
	::memset(first, 0, sizeof(first));
	// Выполняем обнуление мест случайных байтов
	::memset(second, 0, sizeof(second));
	// Выполняем получение случайных байтов
	ASSERT_TRUE(entropy::bytes(first, sizeof(first)));
	// Выполняем повторное получение случайных байтов
	ASSERT_TRUE(entropy::bytes(second, sizeof(second)));
	// Собираемое объединение полученных случайных байтов
	uint8_t item = 0;
	/**
	 * Выполняем перебор полученных случайных байтов
	 */
	for(size_t i = 0; i < sizeof(first); i++)
		// Собираем объединение полученных случайных байтов
		item = static_cast <uint8_t> (item | first[i]);
	// Проверяем, что выданные байты нулями не оказались
	ASSERT_NE(item, 0);
	// Проверяем, что два подряд полученных набора байтов различны
	ASSERT_NE(::memcmp(first, second, sizeof(first)), 0);
	// Проверяем успешность получения нулевого числа случайных байтов
	ASSERT_TRUE(entropy::bytes(first, 0));
	// Проверяем отказ получения случайных байтов в непереданное место
	ASSERT_FALSE(entropy::bytes(nullptr, sizeof(first)));
}
/**
 * @brief Проверка выдачи случайных байтов кусками разного размера
 *
 */
TEST(EntropyTest, Chunks) {
	// Место, в которое помещаются случайные байты
	uint8_t buffer[1024];
	// Число подряд идущих выдач, по объединению которых судят о нулевой выдаче
	constexpr size_t ATTEMPTS = 8;
	/**
	 * Выполняем перебор размеров запрашиваемых кусков случайных байтов
	 */
	for(size_t size = 1; size <= sizeof(buffer); size = ((size * 3) + 1)){
		// Собираемое объединение полученных случайных байтов
		uint8_t item = 0;
		/**
		 * Кусок размером в один байт оказывается нулевым у любого исправного источника
		 * раз на двести пятьдесят шесть выдач, оттого судить о молчаливой выдаче нулей
		 * по одной выдаче нельзя: объединение собирается по нескольким подряд. Заслон
		 * своей силы при этом не теряет, а источник, выдающий нули, молчит их все
		 */
		for(size_t attempt = 0; (attempt < ATTEMPTS) && (item == 0); attempt++){
			// Выполняем обнуление места случайных байтов
			::memset(buffer, 0, sizeof(buffer));
			// Выполняем получение случайных байтов
			ASSERT_TRUE(entropy::bytes(buffer, size)) << "Размер куска: " << size;
			/**
			 * Выполняем перебор полученных случайных байтов
			 */
			for(size_t i = 0; i < size; i++)
				// Собираем объединение полученных случайных байтов
				item = static_cast <uint8_t> (item | buffer[i]);
			/**
			 * Проверяем, что выдача не вышла за запрошенный размер куска
			 */
			for(size_t i = size; i < sizeof(buffer); i++)
				// Проверяем неприкосновенность байта за запрошенным куском
				ASSERT_EQ(buffer[i], 0) << "Размер куска: " << size << ", место: " << i;
		}
		// Проверяем, что выданные байты нулями не оказались
		ASSERT_NE(item, 0) << "Размер куска: " << size;
	}
}
/**
 * @brief Проверка перекоса выпадения разрядов
 *
 */
TEST(EntropyTest, Balance) {
	// Место, в которое помещаются случайные байты
	uint8_t buffer[4096];
	// Выполняем получение случайных байтов
	ASSERT_TRUE(entropy::bytes(buffer, sizeof(buffer)));
	// Число выпавших единичных разрядов
	size_t count = 0;
	/**
	 * Выполняем перебор полученных случайных байтов
	 */
	for(size_t i = 0; i < sizeof(buffer); i++){
		/**
		 * Выполняем перебор разрядов очередного байта
		 */
		for(size_t j = 0; j < 8; j++)
			// Считаем очередной единичный разряд
			count += ((buffer[i] >> j) & 0x01);
	}
	// Общее число полученных разрядов
	const size_t total = (sizeof(buffer) * 8);
	/**
	 * Доля единичных разрядов у источника случайности лежит около половины: выход за
	 * пределы от сорока пяти до пятидесяти пяти сотых при таком объёме невероятен
	 */
	ASSERT_GT(count, (total * 45) / 100);
	// Проверяем верхний предел доли единичных разрядов
	ASSERT_LT(count, (total * 55) / 100);
}
/**
 * @brief Проверка выдачи случайных чисел по модулю
 *
 */
TEST(EntropyTest, Number) {
	// Место, в которое помещается разбираемый модуль
	uint8_t buffer[32];
	// Выполняем разбор модуля порядка подгруппы точек кривой
	const char * text = "8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3";
	/**
	 * Выполняем перебор пар знаков разбираемой записи
	 */
	for(size_t i = 0; i < sizeof(buffer); i++){
		// Собираемое значение байта
		uint8_t value = 0;
		/**
		 * Выполняем перебор знаков очередной пары
		 */
		for(size_t j = 0; j < 2; j++){
			// Извлекаем очередной знак записи
			const char letter = text[(i * 2) + j];
			// Дополняем значение байта очередным знаком записи
			value = static_cast <uint8_t> ((value << 4) | ((letter <= '9') ? (letter - '0') : ((letter - 'a') + 10)));
		}
		// Записываем разобранный байт
		buffer[i] = value;
	}
	// Объект арифметики по модулю
	math::modulus_t modulus;
	// Выполняем установку модуля
	ASSERT_TRUE(modulus.start(view_t(buffer, sizeof(buffer))));
	// Набор полученных случайных чисел
	std::set <std::string> items;
	/**
	 * Выполняем получение сотни случайных чисел
	 */
	for(size_t i = 0; i < 100; i++){
		// Получаемое случайное число
		math::number_t value;
		// Выполняем получение случайного числа
		ASSERT_TRUE(entropy::number(modulus, value)) << "Попытка: " << i;
		// Проверяем, что полученное число нулём не оказалось
		ASSERT_FALSE(modulus.zero(value)) << "Попытка: " << i;
		// Место, в которое записывается полученное случайное число
		uint8_t item[32];
		// Выполняем запись полученного случайного числа
		ASSERT_TRUE(modulus.store(value, item, sizeof(item))) << "Попытка: " << i;
		// Записываем полученное случайное число в набор
		items.insert(std::string(reinterpret_cast <const char *> (item), sizeof(item)));
	}
	// Проверяем, что все полученные случайные числа различны
	ASSERT_EQ(items.size(), static_cast <size_t> (100));
	// Объект неустановленной арифметики по модулю
	math::modulus_t empty;
	// Получаемое случайное число
	math::number_t value;
	// Проверяем отказ получения случайного числа по неустановленному модулю
	ASSERT_FALSE(entropy::number(empty, value));
}
/**
 * @brief Проверка затирания выданного и смены ключа при наполнении запаса
 *
 * @details Закрепляет устройство «ключ стирается на ходу»: перенесённые в ключ и
 *          заполнение байты запаса затёрты, выданные потребителю байты затёрты, а ключ
 *          после исчерпания запаса иной, чем до него
 *
 */
TEST(EntropyTest, Erasure) {
	// Порождатель текущего потока
	internal::generator_t & generator = internal::generator();
	// Место, в которое помещаются случайные байты
	uint8_t buffer[64];
	// Выполняем получение случайных байтов: порождатель наполнен
	ASSERT_TRUE(entropy::bytes(buffer, sizeof(buffer)));
	// Проверяем, что порождатель наполнен от системы
	ASSERT_TRUE(generator.seeded);
	/**
	 * Проверяем затирание перенесённых в ключ и заполнение байтов запаса
	 */
	for(size_t i = 0; i < internal::generator_t::TAKEN; i++)
		// Проверяем затирание очередного байта
		ASSERT_EQ(generator.buffer[i], 0) << "Место: " << i;
	// Если запаса на выдачу с остатком не хватает
	if(generator.rest < (2 * sizeof(buffer))){
		// Хвост запаса, исчерпание которого ведёт к наполнению
		std::vector <uint8_t> tail(generator.rest + 1, 0);
		// Выполняем исчерпание запаса: следом идёт наполнение
		ASSERT_TRUE(entropy::bytes(tail.data(), tail.size()));
	}
	// Запас перед выдачей
	const size_t rest = generator.rest;
	// Проверяем, что запаса на выдачу с остатком хватает
	ASSERT_GE(rest, 2 * sizeof(buffer));
	// Ключ перед выдачей
	uint8_t key[internal::generator_t::KEY];
	// Запоминаем ключ
	::memcpy(key, generator.key, sizeof(key));
	// Выполняем получение случайных байтов из запаса
	ASSERT_TRUE(entropy::bytes(buffer, sizeof(buffer)));
	// Проверяем, что выдача взята из запаса
	ASSERT_EQ(generator.rest, rest - sizeof(buffer));
	// Место выданных байтов в запасе
	const uint8_t * place = (generator.buffer + (internal::generator_t::BUFFER - rest));
	/**
	 * Проверяем затирание выданных байтов в запасе
	 */
	for(size_t i = 0; i < sizeof(buffer); i++)
		// Проверяем затирание очередного выданного байта
		ASSERT_EQ(place[i], 0) << "Место: " << i;
	// Собираемое объединение неизрасходованного остатка запаса
	uint8_t item = 0;
	/**
	 * Выполняем перебор неизрасходованного остатка запаса
	 */
	for(size_t i = sizeof(buffer); i < rest; i++)
		// Собираем объединение остатка
		item = static_cast <uint8_t> (item | place[i]);
	// Проверяем, что неизрасходованный остаток нулями не оказался
	ASSERT_NE(item, 0);
	// Проверяем, что выдача из запаса ключа не меняет
	ASSERT_EQ(::memcmp(key, generator.key, sizeof(key)), 0);
	// Хвост запаса, исчерпание которого ведёт к наполнению
	std::vector <uint8_t> tail(generator.rest + 1, 0);
	// Выполняем исчерпание запаса: следом идёт наполнение
	ASSERT_TRUE(entropy::bytes(tail.data(), tail.size()));
	// Проверяем, что наполнение сменило ключ
	ASSERT_NE(::memcmp(key, generator.key, sizeof(key)), 0);
	// Проверяем, что запас наполнен заново
	ASSERT_EQ(generator.rest, internal::generator_t::REST - 1);
}
/**
 * @brief Проверка переналивки от системы по счёту наполнений
 *
 */
TEST(EntropyTest, Reseed) {
	// Порождатель текущего потока
	internal::generator_t & generator = internal::generator();
	// Место, в которое помещаются случайные байты
	uint8_t buffer[16];
	// Выполняем получение случайных байтов: порождатель наполнен
	ASSERT_TRUE(entropy::bytes(buffer, sizeof(buffer)));
	// Число переналивок перед выдачей
	const size_t stirs = generator.stirs;
	// Проверяем, что порождатель хотя бы раз наполнен от системы
	ASSERT_GE(stirs, static_cast <size_t> (1));
	// Выдача, превышающая выдачу между переналивками
	std::vector <uint8_t> big((internal::generator_t::RESEED + 1) * internal::generator_t::REST, 0);
	// Выполняем получение случайных байтов
	ASSERT_TRUE(entropy::bytes(big.data(), big.size()));
	// Проверяем, что переналивка от системы состоялась
	ASSERT_GE(generator.stirs, stirs + 1);
	// Проверяем, что счёт наполнений не перерастает предела переналивки
	ASSERT_LE(generator.refills, internal::generator_t::RESEED);
	// Проверяем, что выдача до и после переналивки различна
	ASSERT_NE(::memcmp(big.data(), big.data() + (big.size() / 2), 64), 0);
}
/**
 * @brief Проверка раздельности порождателей потоков
 *
 */
TEST(EntropyTest, Threads) {
	// Число потоков
	constexpr size_t COUNT = 4;
	// Выдачи потоков
	std::vector <std::vector <uint8_t>> items(COUNT, std::vector <uint8_t> (2048, 0));
	// Итоги выдач потоков
	bool outcomes[COUNT] = {false, false, false, false};
	// Потоки
	std::vector <std::thread> workers;
	/**
	 * Выполняем запуск потоков
	 */
	for(size_t i = 0; i < COUNT; i++)
		// Запускаем очередной поток
		workers.emplace_back([&items, &outcomes, i]() noexcept -> void {
			// Выполняем получение случайных байтов в потоке
			outcomes[i] = entropy::bytes(items[i].data(), items[i].size());
		});
	/**
	 * Выполняем ожидание потоков
	 */
	for(auto & worker : workers)
		// Дожидаемся очередного потока
		worker.join();
	// Место, в которое помещаются случайные байты потока проверки
	uint8_t buffer[64];
	// Выполняем получение случайных байтов в потоке проверки
	ASSERT_TRUE(entropy::bytes(buffer, sizeof(buffer)));
	/**
	 * Выполняем перебор выдач потоков
	 */
	for(size_t i = 0; i < COUNT; i++){
		// Проверяем успешность выдачи потока
		ASSERT_TRUE(outcomes[i]) << "Поток: " << i;
		// Проверяем, что выдача потока отлична от выдачи потока проверки
		ASSERT_NE(::memcmp(buffer, items[i].data(), sizeof(buffer)), 0) << "Поток: " << i;
		/**
		 * Выполняем перебор прочих потоков
		 */
		for(size_t j = (i + 1); j < COUNT; j++)
			// Проверяем, что выдачи потоков различны
			ASSERT_NE(::memcmp(items[i].data(), items[j].data(), sizeof(buffer)), 0) << "Потоки: " << i << " и " << j;
	}
}
/**
 * Разветвление процесса существует лишь у систем Unix
 */
#if !defined(_WIN32) && !defined(_WIN64)
/**
 * @brief Проверка переналивки у потомка после разветвления процесса
 *
 * @details Потомок наследует состояние порождателя родителя: без переналивки его выдача
 *          совпала бы с последующей выдачей родителя. Потомок сообщает выдачу через канал
 *          и завершается без раскрутки набора проверок
 *
 */
TEST(EntropyTest, Fork) {
	// Место, в которое помещаются случайные байты до разветвления
	uint8_t before[64];
	// Выполняем получение случайных байтов: порождатель потока наполнен до разветвления
	ASSERT_TRUE(entropy::bytes(before, sizeof(before)));
	// Канал сообщения выдачи потомка
	int channel[2] = {-1, -1};
	// Заводим канал
	ASSERT_EQ(::pipe(channel), 0);
	// Выполняем разветвление процесса
	const pid_t child = ::fork();
	// Проверяем успешность разветвления
	ASSERT_GE(child, 0);
	// Если это потомок
	if(child == 0){
		// Выдача потомка
		uint8_t mine[sizeof(before)];
		// Итог выдачи потомка
		const uint8_t outcome = (entropy::bytes(mine, sizeof(mine)) ? 1 : 0);
		// Закрываем чтение канала
		::close(channel[0]);
		// Сообщаем итог выдачи
		(void) !::write(channel[1], &outcome, sizeof(outcome));
		// Сообщаем выдачу
		(void) !::write(channel[1], mine, sizeof(mine));
		// Закрываем запись канала
		::close(channel[1]);
		// Завершаем потомка без раскрутки набора проверок
		::_exit(0);
	}
	// Закрываем запись канала
	::close(channel[1]);
	// Сообщение потомка: итог и выдача
	uint8_t message[1 + sizeof(before)];
	// Выполняем обнуление сообщения
	::memset(message, 0, sizeof(message));
	// Число принятых байтов сообщения
	size_t received = 0;
	/**
	 * Выполняем приём сообщения потомка
	 */
	while(received < sizeof(message)){
		// Выполняем чтение очередной части сообщения
		const ssize_t count = ::read(channel[0], message + received, sizeof(message) - received);
		// Если чтение прервано сигналом
		if((count < 0) && (errno == EINTR))
			// Выполняем повторное чтение
			continue;
		// Если сообщение оборвано
		if(count <= 0)
			// Прекращаем приём
			break;
		// Увеличиваем число принятых байтов
		received += static_cast <size_t> (count);
	}
	// Закрываем чтение канала
	::close(channel[0]);
	// Состояние завершения потомка
	int status = 0;
	// Дожидаемся потомка
	ASSERT_EQ(::waitpid(child, &status, 0), child);
	// Место, в которое помещаются случайные байты после разветвления
	uint8_t after[sizeof(before)];
	// Выполняем получение случайных байтов после разветвления
	ASSERT_TRUE(entropy::bytes(after, sizeof(after)));
	// Проверяем, что сообщение потомка принято целиком
	ASSERT_EQ(received, sizeof(message));
	// Проверяем успешность выдачи потомка
	ASSERT_EQ(message[0], 1);
	// Проверяем, что выдача потомка отлична от выдачи родителя после разветвления
	ASSERT_NE(::memcmp(message + 1, after, sizeof(after)), 0);
	// Проверяем, что выдача потомка отлична от выдачи родителя до разветвления
	ASSERT_NE(::memcmp(message + 1, before, sizeof(before)), 0);
}
#endif
