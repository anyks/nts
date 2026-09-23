/**
 * @file wipe.cpp
 * @date 2026-09-23
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
 * @brief Пример затирания памяти с тайнами — область, набор байтов и строка, цена
 *        затирания и классы затирания памяти связи
 *
 * @details Тайна, отжившая своё, не должна оставаться в памяти: её вынесет чужое чтение,
 *          снимок процесса или повторная выдача освобождённого блока. Затирание sys::wipe
 *          собиратель выбросить не вправе: memset зовётся через изменчивый указатель на
 *          функцию, а за вызовом стоит барьер. Что именно затирает связь, выбирается
 *          классами context::wiping_t: секреты всегда дёшевы, открытый текст записей
 *          стоит на каждую запись
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <chrono>
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/wipe.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <entropy/entropy.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Служебные объекты образца
 *
 */
namespace {
	/**
	 * @brief Метод печати области байтов шестнадцатеричной записью
	 *
	 * @param title подпись
	 * @param data  область байтов
	 * @param size  длина области
	 *
	 */
	void print(const char * title, const uint8_t * data, const size_t size) noexcept {
		// Печатаем подпись
		cout << title << ": ";
		/**
		 * Выполняем перебор байтов
		 */
		for(size_t i = 0; i < size; i++)
			// Печатаем байт
			cout << hex << setw(2) << setfill('0') << static_cast <uint32_t> (data[i]);
		// Завершаем строку
		cout << dec << endl;
	}
	/**
	 * @brief Метод проверки обнулённости области байтов
	 *
	 * @param data область байтов
	 * @param size длина области
	 *
	 * @return     признак того, что все байты области нулевые
	 *
	 */
	bool blank(const uint8_t * data, const size_t size) noexcept {
		/**
		 * Выполняем перебор байтов
		 */
		for(size_t i = 0; i < size; i++){
			// Если байт не нулевой
			if(data[i] != 0)
				// Выводим отрицание
				return false;
		}
		// Выводим подтверждение
		return true;
	}
	/**
	 * @brief Метод печати классов затирания памяти связи
	 *
	 * @param title   подпись
	 * @param classes классы затирания
	 *
	 */
	void classes(const char * title, const vector <context::wiping_t> & classes) noexcept {
		// Печатаем подпись
		cout << title << ": ";
		// Если классов нет
		if(classes.empty())
			// Печатаем отсутствие затираний
			cout << "ничего";
		/**
		 * Выполняем перебор классов
		 */
		for(size_t i = 0; i < classes.size(); i++)
			// Печатаем класс
			cout << (i > 0 ? ", " : "") << ((classes[i] == context::wiping_t::SECRETS) ? "секреты" : "открытый текст записей");
		// Завершаем строку
		cout << endl;
	}
};

/**
 * @brief Точка входа образца
 *
 * @param argc число доводов
 * @param argv доводы
 *
 * @return     код завершения: нуль при успехе
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Доводы образцу не нужны
	(void) argc;
	(void) argv;
	/**
	 * Область на стеке: ключ отжил своё, и его затирание обязано состояться, даже если
	 * после него область никто не читает - вызов по изменчивому указателю собиратель
	 * не выбрасывает. Сторожевые байты по краям показывают точность границ
	 */
	uint8_t area[48];
	// Заполняем область сторожевым значением
	::memset(area, 0xA5, sizeof(area));
	// Ключ лежит в середине области
	uint8_t * key = (area + 8);
	// Заполняем ключ энтропией
	if(!entropy::bytes(key, 32))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем ключ
	::print("Ключ до затирания   ", key, 32);
	// Затираем ключ: ровно тридцать два байта, сторожевые остаются
	sys::wipe(key, 32);
	// Печатаем итог затирания
	cout << "Ключ затёрт         : " << (::blank(key, 32) ? "да" : "нет") << ", сторожевые байты целы: " << (((area[7] == 0xA5) && (area[40] == 0xA5)) ? "да" : "нет") << endl;
	/**
	 * Набор байтов и строка затираются с опустошением: буфер остаётся у контейнера
	 * нулевым, а ёмкость не меняется - следующая тайна ляжет в тот же буфер
	 */
	vector <uint8_t> secret(64, 0xC3);
	// Указатель на буфер набора
	const uint8_t * buffer = secret.data();
	// Ёмкость набора до затирания
	const size_t capacity = secret.capacity();
	// Затираем набор
	sys::wipe(secret);
	// Печатаем итог: буфер за размером читать дозволено лишь образцу без ограждения адресов
	cout << "Набор после затирания: длина " << secret.size() << ", ёмкость прежняя - " << ((secret.capacity() == capacity) ? "да" : "нет") << ", буфер тот же - " << ((secret.data() == buffer) ? "да" : "нет") << endl;
	// Пароль в строке
	string password = "пароль, который не должен пережить проверку";
	// Затираем строку
	sys::wipe(password);
	// Печатаем итог
	cout << "Строка после затирания: длина " << password.size() << endl;
	/**
	 * Цена затирания: столько же, сколько у memset - способ через изменчивый указатель
	 * на функцию скорости не отнимает. Замер на 16 КиБ, каким идёт запись TLS
	 */
	vector <uint8_t> record(16384, 0x5A);
	// Число кругов замера
	const size_t rounds = 20000;
	// Миг начала замера
	const auto started = chrono::steady_clock::now();
	/**
	 * Выполняем круги затирания
	 */
	for(size_t i = 0; i < rounds; i++){
		// Портим один байт, чтобы затирание было не пустым
		record[i % record.size()] = static_cast <uint8_t> (i);
		// Затираем запись
		sys::wipe(record.data(), record.size());
	}
	// Длительность замера в секундах
	const double seconds = chrono::duration <double> (chrono::steady_clock::now() - started).count();
	// Печатаем полосу затирания
	cout << "Полоса затирания    : " << fixed << setprecision(1) << ((static_cast <double> (record.size()) * rounds) / seconds / 1e9) << " ГБ/с, на запись 16 КиБ " << setprecision(0) << ((seconds * 1e9) / rounds) << " нс" << endl;
	/**
	 * Классы затирания памяти связи: что связь затирает сама, выбирает потребитель.
	 * Умолчание - только секреты: их затирание одноразово и дёшево. Открытый текст
	 * принятых записей затирается на каждую запись и включается отдельно - как
	 * SSL_OP_CLEANSE_PLAINTEXT у OpenSSL. Пустой перечень выключает затирания связи
	 */
	client::context_t client;
	// Печатаем умолчание
	::classes("Умолчание связи     ", client.wiping());
	// Кому принятые данные - тайна, тот добавляет открытый текст записей
	client.wiping({context::wiping_t::SECRETS, context::wiping_t::PLAINTEXT});
	// Печатаем классы
	::classes("С открытым текстом  ", client.wiping());
	// Кому тайн в связи нет вовсе (замеры, открытые данные), тот выключает всё
	server::context_t server;
	// Выключаем затирания связи
	server.wiping({});
	// Печатаем классы
	::classes("Без затираний       ", server.wiping());
	/**
	 * Копия принятых данных, выданная вызовом read, принадлежит потребителю: связь
	 * своего накопителя касается, а его - нет. Затирание копии за потребителем
	 */
	vector <uint8_t> received;
	// Принятые данные потребитель после разбора затирает сам
	received.assign(32, 0x7E);
	// Затираем копию
	sys::wipe(received);
	// Печатаем итог
	cout << "Копия потребителя   : затёрта и опустошена, длина " << received.size() << endl;
	// Выходим с успехом
	return EXIT_SUCCESS;
}
