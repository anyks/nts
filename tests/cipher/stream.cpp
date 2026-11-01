/**
 * @file stream.cpp
 * @date 2026-09-04
 *
 * @license{GPL-3.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Исходный файл проверок модуля поточного наложения защиты: режимы GCM и
 *        обратной связи, пути, искажение записи и голодание
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <vector>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <sys/machine.hpp>
#include <cipher/aes.hpp>
#include <cipher/mode.hpp>
#include <cipher/gcm.hpp>
#include <cipher/stream.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Размеры куска приёмки: 1…40 и 63, 64, 65, 333, 8192
 *
 */
static const size_t CHUNKS[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	63, 64, 65, 333, 8192
};

/**
 * @brief Функция порождения открытого текста заданной длины
 *
 * @param size длина текста
 * @return     порождённый текст
 *
 */
static std::vector <uint8_t> plain(const size_t size) {
	// Порождаемый текст
	std::vector <uint8_t> result(size);
	/**
	 * Выполняем заполнение текста
	 */
	for(size_t i = 0; i < size; i++)
		// Записываем очередной байт
		result[i] = static_cast <uint8_t> ((i * 31) + 7);
	// Выводим текст
	return result;
}

/**
 * @brief Функция установки ключа AES-256 шифру
 *
 * @param aes объект шифра
 *
 */
static void key(cipher::aes_t & aes) {
	// Ключ в 32 байта
	uint8_t data[32];
	/**
	 * Выполняем заполнение ключа
	 */
	for(size_t i = 0; i < sizeof(data); i++)
		// Записываем очередной байт
		data[i] = static_cast <uint8_t> (0xA5 ^ (i * 13));
	// Проверяем установку ключа
	ASSERT_TRUE(aes.key(view_t(data, sizeof(data))));
}

/**
 * @brief Функция зашифрования потоком кусками заданного размера
 *
 * @param stream объект потока
 * @param aes    шифр с ключом
 * @param mode   режим потока
 * @param source открытый текст
 * @param chunk  размер куска
 * @param result место под выход потока
 *
 */
static void seal(cipher::stream_t & stream, const cipher::aes_t & aes, const cipher::regime_t mode, const std::vector <uint8_t> & source, const size_t chunk, std::vector <uint8_t> & result) {
	// Опорожняем выход потока перед зашифрованием
	result.clear();
	// Проверяем заведение потока на зашифрование
	ASSERT_TRUE(stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(aes), mode)) << "кусок " << chunk;
	/**
	 * Выполняем подачу текста кусками
	 */
	for(size_t offset = 0; offset < source.size(); offset += chunk){
		// Длина очередного куска
		const size_t size = (((source.size() - offset) < chunk) ? (source.size() - offset) : chunk);
		// Проверяем подачу куска
		ASSERT_TRUE(stream.update(view_t(source.data() + offset, size), result)) << "кусок " << chunk;
	}
	// Проверяем завершение потока
	ASSERT_TRUE(stream.finish(result)) << "кусок " << chunk;
}

/**
 * @brief Функция разового расшифрования выхода потока режимом напрямую
 *
 * @param aes    шифр с ключом
 * @param mode   режим потока
 * @param sealed выход потока: вектор, шифртекст и метка
 * @param result место под открытый текст
 *
 */
static void open(const cipher::aes_t & aes, const cipher::regime_t mode, const std::vector <uint8_t> & sealed, std::vector <uint8_t> & result) {
	// Если режим GCM
	if(mode == cipher::regime_t::GCM){
		// Проверяем, что выход не короче вектора и метки
		ASSERT_GE(sealed.size(), 28u);
		// Длина шифртекста без вектора и метки
		const size_t size = (sealed.size() - 28);
		// Место под открытый текст
		result.assign(size + 1, 0);
		// Объект режима
		cipher::gcm_t gcm;
		// Проверяем запуск режима на векторе из головы
		ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(sealed.data(), 12)));
		// Проверяем разовое расшифрование с меткой из хвоста
		ASSERT_TRUE(gcm.decrypt(view_t(), view_t(sealed.data() + 12, size), result.data(), view_t(sealed.data() + 12 + size, 16)));
		// Убираем запасной байт
		result.resize(size);
	// Иначе режим гаммирования с обратной связью
	} else {
		// Проверяем, что выход не короче вектора
		ASSERT_GE(sealed.size(), 16u);
		// Длина шифртекста без вектора
		const size_t size = (sealed.size() - 16);
		// Место под открытый текст
		result.assign(size + 1, 0);
		// Объект режима
		cipher::feedback_t feedback;
		// Проверяем запуск режима на векторе из головы
		ASSERT_TRUE(feedback.start(cipher::block_t(aes), view_t(sealed.data(), 16)));
		// Проверяем разовое расшифрование
		ASSERT_TRUE(feedback.decrypt(view_t(sealed.data() + 16, size), result.data()));
		// Убираем запасной байт
		result.resize(size);
	}
}

/**
 * @brief Функция расшифрования потоком кусками заданного размера с проверкой отставания
 *
 * @param stream объект потока
 * @param aes    шифр с ключом
 * @param mode   режим потока
 * @param sealed выход зашифрования
 * @param chunk  размер куска
 * @param result место под открытый текст
 *
 */
static void unseal(cipher::stream_t & stream, const cipher::aes_t & aes, const cipher::regime_t mode, const std::vector <uint8_t> & sealed, const size_t chunk, std::vector <uint8_t> & result) {
	// Опорожняем выход потока перед расшифрованием
	result.clear();
	// Длина служебной части: вектор и метка
	const size_t service = ((mode == cipher::regime_t::GCM) ? 28 : 16);
	// Проверяем заведение потока на расшифрование
	ASSERT_TRUE(stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), mode)) << "кусок " << chunk;
	/**
	 * Выполняем подачу выхода кусками
	 */
	for(size_t offset = 0; offset < sealed.size(); offset += chunk){
		// Длина очередного куска
		const size_t size = (((sealed.size() - offset) < chunk) ? (sealed.size() - offset) : chunk);
		// Проверяем подачу куска
		ASSERT_TRUE(stream.update(view_t(sealed.data() + offset, size), result)) << "кусок " << chunk;
		// Число поданных байтов
		const size_t consumed = (offset + size);
		// Проверяем отставание выдачи ровно на служебную часть
		ASSERT_EQ(result.size(), ((consumed > service) ? (consumed - service) : 0)) << "кусок " << chunk << " подано " << consumed;
	}
	// Проверяем завершение потока
	ASSERT_TRUE(stream.finish(result)) << "кусок " << chunk;
	// Проверяем, что метка данными не выдана
	ASSERT_EQ(result.size(), sealed.size() - service) << "кусок " << chunk;
}

/**
 * @brief Функция приёмки режима по всем размерам куска
 *
 * @param mode режим потока
 *
 */
static void accept(const cipher::regime_t mode) {
	// Объект шифра
	cipher::aes_t aes;
	// Устанавливаем ключ
	key(aes);
	// Открытый текст в 1000 байтов
	const std::vector <uint8_t> source = plain(1000);
	// Объект потока
	cipher::stream_t stream;
	// Выход потока, открытый текст режима напрямую и открытый текст потока
	std::vector <uint8_t> sealed, direct, opened;
	/**
	 * Выполняем перебор размеров куска
	 */
	for(const size_t chunk : CHUNKS){
		// Выполняем зашифрование потоком
		seal(stream, aes, mode, source, chunk, sealed);
		// Проверяем длину выхода: вектор впереди и метка позади
		ASSERT_EQ(sealed.size(), source.size() + ((mode == cipher::regime_t::GCM) ? 28 : 16)) << "кусок " << chunk;
		// Выполняем разовое расшифрование режимом напрямую
		open(aes, mode, sealed, direct);
		// Проверяем схождение с разовым вызовом
		ASSERT_EQ(direct, source) << "кусок " << chunk;
		// Выполняем расшифрование потоком тем же куском
		unseal(stream, aes, mode, sealed, chunk, opened);
		// Проверяем схождение открытого текста
		ASSERT_EQ(opened, source) << "кусок " << chunk;
		// Выполняем расшифрование потоком по одному байту
		unseal(stream, aes, mode, sealed, 1, opened);
		// Проверяем схождение открытого текста
		ASSERT_EQ(opened, source) << "кусок " << chunk;
	}
	// Выход зашифрования по одному байту
	std::vector <uint8_t> single;
	// Выполняем зашифрование потоком по одному байту
	seal(stream, aes, mode, source, 1, single);
	// Выполняем расшифрование потоком разом
	unseal(stream, aes, mode, single, single.size(), opened);
	// Проверяем схождение открытого текста
	ASSERT_EQ(opened, source);
}

/**
 * Приёмка GCM: нарезка не влияет на итог, сличение с разовым вызовом
 */
TEST(StreamTest, Gcm){
	// Выполняем приёмку режима
	accept(cipher::regime_t::GCM);
}

/**
 * Приёмка CFB: нарезка не влияет на итог, сличение с разовым вызовом
 */
TEST(StreamTest, Feedback){
	// Выполняем приёмку режима
	accept(cipher::regime_t::FEEDBACK);
}

/**
 * Приёмка GCM на пути таблиц: сличение с путём машинных команд
 */
TEST(StreamTest, Paths){
	// Объект шифра
	cipher::aes_t aes;
	// Устанавливаем ключ
	key(aes);
	// Открытый текст в 333 байта
	const std::vector <uint8_t> source = plain(333);
	// Объект потока
	cipher::stream_t stream;
	// Выход потока и открытый текст
	std::vector <uint8_t> sealed, opened;
	// Выполняем зашифрование потоком на пути, выбранном машиной
	seal(stream, aes, cipher::regime_t::GCM, source, 7, sealed);
	// Запрещаем машинные команды
	machine::allow(false);
	// Выполняем установку ключа заново: таблицы шифра строятся при установке
	key(aes);
	// Выполняем расшифрование потоком таблицами
	unseal(stream, aes, cipher::regime_t::GCM, sealed, 5, opened);
	// Проверяем схождение открытого текста
	ASSERT_EQ(opened, source);
	// Выполняем зашифрование потоком таблицами
	seal(stream, aes, cipher::regime_t::GCM, source, 11, sealed);
	// Возвращаем машинные команды
	machine::allow(true);
	// Выполняем установку ключа заново
	key(aes);
	// Выполняем расшифрование потоком командами
	unseal(stream, aes, cipher::regime_t::GCM, sealed, 3, opened);
	// Проверяем схождение открытого текста
	ASSERT_EQ(opened, source);
}

/**
 * Пустые порции - законный успех, вектор уходит первым и у пустого потока
 */
TEST(StreamTest, Empty){
	// Объект шифра
	cipher::aes_t aes;
	// Устанавливаем ключ
	key(aes);
	// Объект потока
	cipher::stream_t stream;
	// Выход потока
	std::vector <uint8_t> sealed;
	// Проверяем заведение потока на зашифрование
	ASSERT_TRUE(stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(aes), cipher::regime_t::GCM));
	// Проверяем подачу пустого куска
	ASSERT_TRUE(stream.update(view_t(), sealed));
	// Проверяем, что первым вышел вектор
	ASSERT_EQ(sealed.size(), 12u);
	// Проверяем подачу ещё одного пустого куска
	ASSERT_TRUE(stream.update(view_t(), sealed));
	// Проверяем, что выдача не выросла
	ASSERT_EQ(sealed.size(), 12u);
	// Проверяем завершение потока
	ASSERT_TRUE(stream.finish(sealed));
	// Проверяем, что позади вышла метка
	ASSERT_EQ(sealed.size(), 28u);
	// Открытый текст
	std::vector <uint8_t> opened;
	// Проверяем заведение потока на расшифрование
	ASSERT_TRUE(stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), cipher::regime_t::GCM));
	// Проверяем подачу пустого куска до вектора
	ASSERT_TRUE(stream.update(view_t(), opened));
	/**
	 * Выполняем подачу выхода по одному байту
	 */
	for(size_t i = 0; i < sealed.size(); i++){
		// Проверяем подачу байта
		ASSERT_TRUE(stream.update(view_t(sealed.data() + i, 1), opened)) << "байт " << i;
		// Проверяем, что выдача пуста
		ASSERT_TRUE(opened.empty()) << "байт " << i;
	}
	// Проверяем завершение потока: метка сошлась
	ASSERT_TRUE(stream.finish(opened));
	// Проверяем, что данных нет
	ASSERT_TRUE(opened.empty());
	// Проверяем пустой поток без единой подачи: вектор выходит на завершении
	ASSERT_TRUE(stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(aes), cipher::regime_t::FEEDBACK));
	// Опорожняем выход перед завершением пустого потока
	sealed.clear();
	// Проверяем завершение потока
	ASSERT_TRUE(stream.finish(sealed));
	// Проверяем, что вышел один вектор
	ASSERT_EQ(sealed.size(), 16u);
}

/**
 * Порча метки ловится только на завершении, порча данных тоже
 */
TEST(StreamTest, Tamper){
	// Объект шифра
	cipher::aes_t aes;
	// Устанавливаем ключ
	key(aes);
	// Открытый текст в 100 байтов
	const std::vector <uint8_t> source = plain(100);
	// Объект потока
	cipher::stream_t stream;
	// Выход потока и открытый текст
	std::vector <uint8_t> sealed, opened;
	// Выполняем зашифрование потоком
	seal(stream, aes, cipher::regime_t::GCM, source, 17, sealed);
	// Портим последний байт метки
	sealed.back() ^= 0x80;
	// Проверяем заведение потока на расшифрование
	ASSERT_TRUE(stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), cipher::regime_t::GCM));
	/**
	 * Выполняем подачу порченого выхода по одному байту: ни один кусок не отказывает
	 */
	for(size_t i = 0; i < sealed.size(); i++)
		// Проверяем подачу байта
		ASSERT_TRUE(stream.update(view_t(sealed.data() + i, 1), opened)) << "байт " << i;
	// Проверяем, что данные выданы до завершения
	ASSERT_EQ(opened.size(), source.size());
	// Проверяем отказ завершения: метка не сошлась
	ASSERT_FALSE(stream.finish(opened));
	// Проверяем, что поток закрыт
	ASSERT_FALSE(stream.ready());
	// Восстанавливаем метку
	sealed.back() ^= 0x80;
	// Портим байт данных
	sealed[40] ^= 0x01;
	// Опорожняем открытый текст перед повторным заведением потока
	opened.clear();
	// Проверяем заведение потока на расшифрование
	ASSERT_TRUE(stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), cipher::regime_t::GCM));
	// Проверяем подачу порченого выхода разом
	ASSERT_TRUE(stream.update(view_t(sealed.data(), sealed.size()), opened));
	// Проверяем отказ завершения: метка не сошлась
	ASSERT_FALSE(stream.finish(opened));
	// Возвращаем байту данных исходное значение
	sealed[40] ^= 0x01;
	// Портим вектор
	sealed[0] ^= 0x01;
	// Опорожняем открытый текст перед заведением потока на порчу вектора
	opened.clear();
	// Проверяем заведение потока на расшифрование
	ASSERT_TRUE(stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), cipher::regime_t::GCM));
	// Проверяем подачу выхода с порченым вектором
	ASSERT_TRUE(stream.update(view_t(sealed.data(), sealed.size()), opened));
	// Проверяем отказ завершения
	ASSERT_FALSE(stream.finish(opened));
	// Восстанавливаем вектор
	sealed[0] ^= 0x01;
	// Проверяем усечённый поток: метка недобрана
	ASSERT_TRUE(stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), cipher::regime_t::GCM));
	// Опорожняем открытый текст перед проверкой усечённого потока
	opened.clear();
	// Проверяем подачу выхода без последнего байта
	ASSERT_TRUE(stream.update(view_t(sealed.data(), sealed.size() - 1), opened));
	// Проверяем отказ завершения
	ASSERT_FALSE(stream.finish(opened));
	// Проверяем поток короче вектора
	ASSERT_TRUE(stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), cipher::regime_t::FEEDBACK));
	// Проверяем подачу трёх байтов
	ASSERT_TRUE(stream.update(view_t(sealed.data(), 3), opened));
	// Проверяем отказ завершения
	ASSERT_FALSE(stream.finish(opened));
}

/**
 * Заведение поверх незавершённого сбрасывает, один объект в обе стороны
 */
TEST(StreamTest, Restart){
	// Объект шифра
	cipher::aes_t aes;
	// Устанавливаем ключ
	key(aes);
	// Открытый текст в 64 байта
	const std::vector <uint8_t> source = plain(64);
	// Объект потока
	cipher::stream_t stream;
	// Выход потока и открытый текст
	std::vector <uint8_t> sealed, opened, waste;
	// Проверяем заведение потока на зашифрование
	ASSERT_TRUE(stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(aes), cipher::regime_t::GCM));
	// Проверяем подачу части текста
	ASSERT_TRUE(stream.update(view_t(source.data(), 20), waste));
	// Проверяем заведение поверх незавершённого потока
	ASSERT_TRUE(stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(aes), cipher::regime_t::GCM));
	// Проверяем подачу всего текста
	ASSERT_TRUE(stream.update(view_t(source.data(), source.size()), sealed));
	// Проверяем завершение потока, заведённого поверх незавершённого
	ASSERT_TRUE(stream.finish(sealed));
	// Проверяем длину выхода
	ASSERT_EQ(sealed.size(), source.size() + 28);
	// Проверяем заведение того же объекта на расшифрование поверх завершённого
	ASSERT_TRUE(stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), cipher::regime_t::GCM));
	// Проверяем подачу половины выхода
	ASSERT_TRUE(stream.update(view_t(sealed.data(), 40), waste));
	// Проверяем заведение поверх незавершённого расшифрования
	ASSERT_TRUE(stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), cipher::regime_t::GCM));
	// Проверяем подачу всего выхода
	ASSERT_TRUE(stream.update(view_t(sealed.data(), sealed.size()), opened));
	// Проверяем завершение потока после повторного заведения на расшифрование
	ASSERT_TRUE(stream.finish(opened));
	// Проверяем схождение открытого текста
	ASSERT_EQ(opened, source);
	// Проверяем смену режима тем же объектом
	ASSERT_TRUE(stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(aes), cipher::regime_t::FEEDBACK));
	// Опорожняем выход перед подачей текста в режиме гаммирования
	sealed.clear();
	// Проверяем подачу текста
	ASSERT_TRUE(stream.update(view_t(source.data(), source.size()), sealed));
	// Проверяем завершение потока после смены режима
	ASSERT_TRUE(stream.finish(sealed));
	// Проверяем длину выхода: вектор впереди, метки нет
	ASSERT_EQ(sealed.size(), source.size() + 16);
	// Очищаем открытый текст
	opened.clear();
	// Проверяем расшифрование тем же объектом
	ASSERT_TRUE(stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), cipher::regime_t::FEEDBACK));
	// Проверяем подачу выхода
	ASSERT_TRUE(stream.update(view_t(sealed.data(), sealed.size()), opened));
	// Проверяем завершение расшифрования в режиме гаммирования
	ASSERT_TRUE(stream.finish(opened));
	// Проверяем схождение открытого текста
	ASSERT_EQ(opened, source);
}

/**
 * Заслоны договора: мутационная проверка каждого отказа заведения и работы
 */
TEST(StreamTest, Guards){
	// Объект шифра
	cipher::aes_t aes;
	// Объект потока
	cipher::stream_t stream;
	// Выход потока
	std::vector <uint8_t> result;
	// Проверяем неготовность до заведения
	ASSERT_FALSE(stream.ready());
	// Проверяем отказ подачи до заведения
	ASSERT_FALSE(stream.update(view_t(), result));
	// Проверяем отказ завершения до заведения
	ASSERT_FALSE(stream.finish(result));
	// Проверяем отказ заведения на шифре без ключа
	ASSERT_FALSE(stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(aes), cipher::regime_t::GCM));
	// Устанавливаем ключ
	key(aes);
	// Проверяем отказ заведения без направления
	ASSERT_FALSE(stream.start(cipher::direction_t::NONE, cipher::block_t(aes), cipher::regime_t::GCM));
	// Проверяем отказ заведения без режима
	ASSERT_FALSE(stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(aes), cipher::regime_t::NONE));
	// Проверяем отказ заведения с меткой короче четырёх байтов
	ASSERT_FALSE(stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(aes), cipher::regime_t::GCM, 3));
	// Проверяем отказ заведения с меткой длиннее шестнадцати байтов
	ASSERT_FALSE(stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(aes), cipher::regime_t::GCM, 17));
	// Проверяем отказ заведения на пустом шифре
	ASSERT_FALSE(stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(), cipher::regime_t::GCM));
	// Проверяем заведение с меткой в 12 байтов
	ASSERT_TRUE(stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(aes), cipher::regime_t::GCM, 12));
	// Проверяем готовность
	ASSERT_TRUE(stream.ready());
	// Проверяем отказ подачи объявленного непустым, но не переданного куска
	ASSERT_FALSE(stream.update(view_t(nullptr, 5), result));
	// Открытый текст в 50 байтов
	const std::vector <uint8_t> source = plain(50);
	// Проверяем подачу текста
	ASSERT_TRUE(stream.update(view_t(source.data(), source.size()), result));
	// Проверяем завершение потока с усечённой меткой
	ASSERT_TRUE(stream.finish(result));
	// Проверяем длину выхода с усечённой меткой
	ASSERT_EQ(result.size(), source.size() + 24);
	// Проверяем, что завершение закрыло поток
	ASSERT_FALSE(stream.ready());
	// Проверяем отказ подачи после завершения
	ASSERT_FALSE(stream.update(view_t(source.data(), source.size()), result));
	// Проверяем отказ повторного завершения
	ASSERT_FALSE(stream.finish(result));
	// Открытый текст после расшифрования
	std::vector <uint8_t> opened;
	// Проверяем расшифрование с усечённой меткой
	ASSERT_TRUE(stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), cipher::regime_t::GCM, 12));
	// Проверяем подачу выхода
	ASSERT_TRUE(stream.update(view_t(result.data(), result.size()), opened));
	// Проверяем отставание на усечённую метку
	ASSERT_EQ(opened.size(), source.size());
	// Проверяем завершение расшифрования с усечённой меткой
	ASSERT_TRUE(stream.finish(opened));
	// Проверяем схождение открытого текста
	ASSERT_EQ(opened, source);
	// Очищаем открытый текст
	opened.clear();
	// Проверяем расшифрование с меткой не той длины: последние 16 байтов меткой не сходятся
	ASSERT_TRUE(stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), cipher::regime_t::GCM, 16));
	// Проверяем подачу выхода
	ASSERT_TRUE(stream.update(view_t(result.data(), result.size()), opened));
	// Проверяем отказ завершения
	ASSERT_FALSE(stream.finish(opened));
	// Выполняем сброс потока
	stream.clear();
	// Проверяем неготовность после сброса
	ASSERT_FALSE(stream.ready());
}

/**
 * Два зашифрования одним ключом дают разные векторы
 */
TEST(StreamTest, Nonce){
	// Объект шифра
	cipher::aes_t aes;
	// Устанавливаем ключ
	key(aes);
	// Открытый текст в 16 байтов
	const std::vector <uint8_t> source = plain(16);
	// Объект потока
	cipher::stream_t stream;
	// Выходы двух зашифрований
	std::vector <uint8_t> first, second;
	// Выполняем первое зашифрование
	seal(stream, aes, cipher::regime_t::GCM, source, 16, first);
	// Выполняем второе зашифрование
	seal(stream, aes, cipher::regime_t::GCM, source, 16, second);
	// Проверяем, что векторы различны
	ASSERT_NE(::memcmp(first.data(), second.data(), 12), 0);
	// Проверяем, что шифртексты различны
	ASSERT_NE(::memcmp(first.data() + 12, second.data() + 12, 16), 0);
}

/**
 * Нехватка памяти: перебор запасов выделений, только успех либо отказ
 */
TEST(StreamTest, Starved){
	// Объект шифра
	cipher::aes_t aes;
	// Устанавливаем ключ
	key(aes);
	// Открытый текст в 300 байтов
	const std::vector <uint8_t> source = plain(300);
	// Объект потока
	cipher::stream_t stream;
	// Выход исправного зашифрования
	std::vector <uint8_t> sealed;
	// Выполняем зашифрование потоком
	seal(stream, aes, cipher::regime_t::GCM, source, 300, sealed);
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе поток обязан ответить
	 * либо успехом, либо отказом, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 32; budget++){
		// Выход потока
		std::vector <uint8_t> result;
		// Открытый текст
		std::vector <uint8_t> opened;
		// Итог зашифрования при отмеренном запасе
		bool outcome = false;
		// Итог расшифрования при отмеренном запасе
		bool reverse = false;
		{
			// Отмеряем запас выделений на время работы потока
			starve::ration_t ration(budget);
			// Выполняем заведение потока на зашифрование
			outcome = stream.start(cipher::direction_t::ENCRYPT, cipher::block_t(aes), cipher::regime_t::GCM);
			/**
			 * Выполняем подачу текста кусками по 37 байтов
			 */
			for(size_t offset = 0; outcome && (offset < source.size()); offset += 37)
				// Подаём очередной кусок
				outcome = stream.update(view_t(source.data() + offset, (((source.size() - offset) < 37) ? (source.size() - offset) : 37)), result);
			// Если подача прошла
			if(outcome)
				// Завершаем поток
				outcome = stream.finish(result);
			// Выполняем заведение потока на расшифрование
			reverse = stream.start(cipher::direction_t::DECRYPT, cipher::block_t(aes), cipher::regime_t::GCM);
			/**
			 * Выполняем подачу исправного выхода кусками по 37 байтов
			 */
			for(size_t offset = 0; reverse && (offset < sealed.size()); offset += 37)
				// Подаём очередной кусок
				reverse = stream.update(view_t(sealed.data() + offset, (((sealed.size() - offset) < 37) ? (sealed.size() - offset) : 37)), opened);
			// Если подача прошла
			if(reverse)
				// Завершаем поток
				reverse = stream.finish(opened);
		}
		// Если зашифрование прошло
		if(outcome){
			// Проверяем длину выхода
			ASSERT_EQ(result.size(), source.size() + 28) << "запас " << budget;
		}
		// Если расшифрование прошло
		if(reverse){
			// Проверяем схождение открытого текста
			ASSERT_EQ(opened, source) << "запас " << budget;
		}
		// Запоминаем объявленный отказ памяти
		starved = (starved || !outcome || !reverse);
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}
