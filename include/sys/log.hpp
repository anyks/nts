/**
 * @file log.hpp
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
 * @brief Заголовочный файл стока журнала библиотеки
 *
 * @details Библиотека журнала не ведёт - у неё есть лишь СТОК: одна функция, которую
 *          потребитель вправе поставить. Пока сток не поставлен, библиотека молчит, и
 *          цена сообщения - одно сравнение с nullptr: строка не собирается вовсе. AWH
 *          ставит сток переходником на свой журнал при своём старте; чужой проект без
 *          журнала не ставит ничего. Заголовков и определений сборки чужих проектов
 *          здесь нет и не будет: зависимость остаётся односторонней
 *
 * @note Намеренные решения:
 *       1. Сток, а не журнал: ни потоков, ни файлов, ни очередей, ни syslog - это дело
 *          потребителя. Библиотека отдаёт уровень и готовую строку
 *       2. Подключение только во время выполнения: ни слабых символов (в статических
 *          архивах и под MinGW они ненадёжны), ни определений сборки с чужими заголовками
 *          (ломают отсутствие зависимостей)
 *       3. В журнал не идут тайны: ключи, случайные значения, тела записей. Идут отказы,
 *          которые иначе уходят потребителю лишь кодом: обрыв связи извещением, понижение
 *          укрытия хранилища, исчерпание повторов поверх дейтаграмм
 *       4. Сток ставится при старте процесса до заведения связей и живёт до его конца:
 *          смена стока под живыми связями из другого потока не защищена
 *
 * \~english
 * @brief Header file of the log sink of the library
 * @details The library keeps no log - it has only a SINK: one function the consumer may set.
 *          While the sink is not set, the library is silent and a message costs one comparison
 *          with nullptr: the string is not composed at all
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
		 * @brief Пространство имён стока журнала
		 *
		 * \~english
		 * @brief Namespace of the log sink
		 *
		 * \~
		 */
		namespace log {
			/**
			 * \~russian
			 * @brief Уровень сообщения: совпадает с видами сообщений журнала AWH
			 *
			 * \~english
			 * @brief Level of a message: matches the kinds of the messages of the AWH log
			 *
			 * \~
			 */
			enum class level_t : uint8_t {
				INFO     = 0x01, /*!< \~russian Сведение \~english Information \~ */
				WARNING  = 0x02, /*!< \~russian Предупреждение \~english Warning \~ */
				CRITICAL = 0x03  /*!< \~russian Отказ \~english Failure \~ */
			};
			/**
			 * \~russian
			 * @brief Сток журнала: функция потребителя
			 *
			 * @param level   уровень сообщения
			 * @param text    готовая строка сообщения, завершённая нулём
			 * @param context указатель контекста потребителя, переданный при установке
			 *
			 * \~english
			 * @brief Log sink: the function of the consumer
			 * @param level   the level of the message
			 * @param text    the composed null-terminated message string
			 * @param context the pointer of the context of the consumer passed at the setting
			 *
			 * \~
			 */
			typedef void (* sink_t)(const level_t level, const char * text, void * context);
			/**
			 * \~russian
			 * @brief Метод установки стока журнала
			 *
			 * @param sink    функция стока; nullptr снимает сток, и библиотека молчит
			 * @param context указатель контекста потребителя, передаваемый стоку как есть
			 *
			 * \~english
			 * @brief Method of setting the log sink
			 * @param sink    the sink function; nullptr removes the sink and the library is silent
			 * @param context the pointer of the context of the consumer passed to the sink as is
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void sink(const sink_t sink, void * context = nullptr) noexcept;
			/**
			 * \~russian
			 * @brief Метод проверки того, что сток поставлен
			 *
			 * @return признак поставленного стока: без него строки собирать незачем
			 *
			 * \~english
			 * @brief Method of checking that the sink is set
			 * @return the flag of the set sink: without it there is no point composing strings
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ bool enabled() noexcept;
			/**
			 * \~russian
			 * @brief Метод передачи готовой строки в сток
			 *
			 * @param level уровень сообщения
			 * @param text  строка сообщения, завершённая нулём
			 *
			 * \~english
			 * @brief Method of passing a composed string to the sink
			 * @param level the level of the message
			 * @param text  the null-terminated message string
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void emit(const level_t level, const char * text) noexcept;
			/**
			 * \~russian
			 * @brief Метод передачи сообщения по образцу printf
			 *
			 * @details Строка собирается лишь при поставленном стоке, в буфер на стеке
			 *          в 512 байтов; более длинное сообщение обрезается
			 *
			 * @param level  уровень сообщения
			 * @param format образец сообщения
			 *
			 * \~english
			 * @brief Method of passing a message by a printf pattern
			 * @param level  the level of the message
			 * @param format the pattern of the message
			 *
			 * \~
			 */
			__ANTS_SHARED_EXPORT__ void emitf(const level_t level, const char * format, ...) noexcept;
		};
	};
};

