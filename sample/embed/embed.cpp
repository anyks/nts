/**
 * @file embed.cpp
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
 * @brief Пример вывода зашитого в образ приложения ключа — из материала, собранного по
 *        образу, и из пароля растяжением Argon2, со связкой версии и участка образа
 *
 * @details Зашитый ключ находят не разбором, а энтропийным разбором образа: тридцать два
 *          случайных байта видны как пятно. Потому в образе лежит рассеянный материал
 *          (сторона AWH, scatter), а ключ ВЫВОДИТСЯ на запуске: HKDF над материалом с
 *          версией и связкой участка образа в сведениях вывода. Подмена участка или
 *          версии даёт иной ключ, и укладка на сборочной машине сходится с запуском
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
#include <embed/embed.hpp>
#include <digest/hash.hpp>
#include <sys/vault.hpp>
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
	/**
	 * Материал, собранный по образу на запуске (у AWH его кладёт scatter_t::gather прямо в
	 * укрытый приёмник); здесь - условные тридцать два байта в укрытой памяти
	 */
	sys::secret_t material;
	// Если участок под материал завести не удалось
	if(!material.reserve(32))
		// Выходим с отказом
		return EXIT_FAILURE;
	/**
	 * Выполняем заполнение материала условными байтами
	 */
	for(size_t i = 0; i < material.size(); i++)
		// Кладём очередной байт
		material.data()[i] = static_cast <uint8_t> (0x40 + i);
	// Соль вывода: открытая, лежит рядом с материалом
	const char * salt = "соль укладки";
	/**
	 * Связка с образом: хеш участка образа, который нельзя менять, не меняя ключа; здесь
	 * участок условный, у настоящего приложения - код и данные носителя
	 */
	uint8_t context[32];
	// Если хеш участка образа вычислить не удалось
	if(!digest::hash(digest::hash_t::SHA256, ::text("участок образа: код носителя"), context, sizeof(context)))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Версия ключа: смена версии даёт иной ключ из того же материала
	const uint64_t version = 1;
	// Ключ: в укрытой памяти, между вызовами в обычной куче не лежит
	sys::secret_t key;
	// Если участок под ключ завести не удалось
	if(!key.reserve(32))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Если ключ вывести не удалось
	if(!embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), ::text(salt), view_t(context, sizeof(context)), version, key.data(), key.size())){
		// Печатаем отказ
		cout << "Вывести ключ из материала не удалось" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Печатаем ключ
	::print("Ключ из материала (версия 1)", key.data(), key.size());
	// Ключ следующей версии из того же материала
	uint8_t next[32];
	// Если ключ вывести не удалось
	if(!embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), ::text(salt), view_t(context, sizeof(context)), version + 1, next, sizeof(next)))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем ключ
	::print("Ключ из материала (версия 2)", next, sizeof(next));
	// Хеш подменённого участка образа
	uint8_t tampered[32];
	// Если хеш подменённого участка вычислить не удалось
	if(!digest::hash(digest::hash_t::SHA256, ::text("участок образа: код носителя, подправленный"), tampered, sizeof(tampered)))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Ключ по подменённому участку
	uint8_t foreign[32];
	// Если ключ вывести не удалось
	if(!embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), ::text(salt), view_t(tampered, sizeof(tampered)), version, foreign, sizeof(foreign)))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем итог подмены
	cout << "Подмена участка образа даёт иной ключ: " << ((::memcmp(foreign, key.data(), sizeof(foreign)) != 0) ? "да" : "нет") << endl;
	/**
	 * Второй путь: ключ из пароля растяжением Argon2id - версия и связка идут в связанные
	 * данные; память уменьшена до 8 МиБ ради скорости образца, у приложения - 64 МиБ
	 */
	const digest::argon_params_t params(digest::argon_t::ARGON2ID, 8192, 3, 4);
	// Ключ из пароля
	uint8_t stretched[32];
	// Если ключ вывести не удалось
	if(!embed::secret(params, ::text("правильная лошадь батарея скрепка"), ::text(salt), view_t(context, sizeof(context)), version, stretched, sizeof(stretched))){
		// Печатаем отказ
		cout << "Вывести ключ из пароля не удалось" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Печатаем ключ
	::print("Ключ из пароля (Argon2id, 8 МиБ)", stretched, sizeof(stretched));
	// Затираем ключи, жившие на стеке
	sys::wipe(next, sizeof(next));
	sys::wipe(foreign, sizeof(foreign));
	sys::wipe(stretched, sizeof(stretched));
	// Материал и ключ в укрытой памяти затираются разрушением
	return EXIT_SUCCESS;
}
