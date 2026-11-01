/**
 * @file argon2.cpp
 * @date 2026-09-08
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
 * @brief Пример работы с Argon2 по RFC 9106 — выработка ключа из пароля с памятью, строка PHC
 *        для хранения и проверка пароля по ней
 *
 * @details Argon2id держит перебор на видеокартах ценою памяти: обороты, память и полосы
 *          хранятся рядом с тегом в строке PHC, и проверка пароля читает их оттуда
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstring>
#include <iomanip>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/argon2.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>

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
	 * @brief Функция печати области байтов шестнадцатеричной записью
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
	 * @brief Функция получения просмотра текста
	 *
	 * @param text текст
	 * @return     просмотр
	 *
	 */
	view_t text(const char * text) noexcept {
		// Выводим просмотр текста
		return view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text));
	}
};

/**
 * @brief Точка входа образца
 *
 * @param argc число доводов
 * @param argv доводы
 * @return     код завершения: нуль при успехе
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Доводы образцу не нужны
	(void) argc;
	// Не используем параметры приложения
	(void) argv;
	// Пароль потребителя
	const char * password = "правильная лошадь батарея скрепка";
	// Соль: свежая на каждый пароль, из энтропии
	uint8_t salt[16];
	// Если соль выработать не удалось
	if(!entropy::bytes(salt, sizeof(salt)))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Параметры Argon2id: 64 МиБ памяти, три оборота, четыре полосы (RFC 9106, раздел 4 - второй рекомендованный набор)
	const digest::argon_params_t params(digest::argon_t::ARGON2ID, 65536, 3, 4);
	// Место под ключ
	uint8_t key[32];
	// Если ключ выработать не удалось: память под 64 МиБ отвечает отказом, а не падением
	if(!digest::argon2(params, ::text(password), view_t(salt, sizeof(salt)), view_t(), view_t(), key, sizeof(key))){
		// Печатаем отказ
		cout << "Выработать ключ Argon2id не удалось" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Печатаем ключ
	::print("Ключ Argon2id (64 МиБ, t=3, p=4)", key, sizeof(key));
	// Запись для хранения: параметры, соль и тег - всё, что нужно для проверки
	digest::argon_record_t record;
	// Устанавливаем параметры записи
	record.params = params;
	// Переносим соль
	record.salt.assign(salt, salt + sizeof(salt));
	// Переносим тег
	record.tag.assign(key, key + sizeof(key));
	// Строка PHC для хранилища паролей
	string stored;
	// Если строку составить не удалось
	if(!digest::phc(record, stored))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем строку PHC
	cout << "Строка PHC: " << stored << endl;
	// Проверка пароля по строке: разбираем запись обратно
	digest::argon_record_t parsed;
	// Если строку разобрать не удалось
	if(!digest::phc(stored, parsed))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Место под проверочный тег
	uint8_t probe[32];
	// Если тег по разобранным параметрам выработать не удалось
	if(!digest::argon2(parsed.params, ::text(password), view_t(parsed.salt.data(), parsed.salt.size()), view_t(), view_t(), probe, sizeof(probe)))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Сличаем теги: в настоящем хранилище - за постоянное время
	const bool same = (::memcmp(probe, parsed.tag.data(), sizeof(probe)) == 0);
	// Печатаем итог проверки
	cout << "Проверка верного пароля: " << (same ? "сошлось" : "разошлось") << endl;
	// Если неверный пароль дал тот же тег
	if(digest::argon2(parsed.params, ::text("неверный пароль"), view_t(parsed.salt.data(), parsed.salt.size()), view_t(), view_t(), probe, sizeof(probe)) && (::memcmp(probe, parsed.tag.data(), sizeof(probe)) == 0)){
		// Печатаем отказ
		cout << "Неверный пароль сошёлся - так быть не должно" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Печатаем итог проверки неверного пароля
	cout << "Проверка неверного пароля: разошлось" << endl;
	// Затираем ключ и теги
	sys::wipe(key, sizeof(key));
	sys::wipe(probe, sizeof(probe));
	// Выходим по итогу сличения
	return (same ? EXIT_SUCCESS : EXIT_FAILURE);
}
