/**
 * @file raw.cpp
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
 * @brief Пример сырого поточного шифра без имитовставки — XChaCha20 с 24-байтовым заполнением
 *        и AES-256-CTR: гамма на месте, неверный ключ даёт неотличимый от случайного мусор, а
 *        не отказ
 *
 * @details Так устроены контейнеры, где метка имитовставки была бы оракулом перебора пароля:
 *          целостность выносится на подпись, а шифр лишь накладывает гамму
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
#include <cipher/aes.hpp>
#include <cipher/mode.hpp>
#include <cipher/chacha.hpp>
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
	 * @brief Метод получения просмотра текста
	 *
	 * @param text текст
	 *
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
 *
 * @return     код завершения: нуль при успехе
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Доводы образцу не нужны
	(void) argc;
	(void) argv;
	// Сообщение
	const view_t message = ::text("сырой поток без имитовставки: целостность на подписи");
	// Ключ и 24-байтовое заполнение XChaCha20: заполнение такой длины позволяет брать его случайно
	uint8_t key[32], nonce[24];
	// Если ключ и заполнение выработать не удалось
	if(!entropy::bytes(key, sizeof(key)) || !entropy::bytes(nonce, sizeof(nonce)))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Шифр XChaCha20: 24-байтовое заполнение включает HChaCha20 (draft-irtf-cfrg-xchacha)
	cipher::chacha_t chacha;
	// Если шифр завести не удалось
	if(!chacha.start(view_t(key, sizeof(key)), view_t(nonce, sizeof(nonce)), 0))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Шифртекст и вскрытое
	uint8_t cipher[128], plain[128];
	// Накладываем гамму
	if(!chacha.encrypt(message, cipher))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем шифртекст
	::print("XChaCha20", cipher, message.size);
	// Снимаем гамму верным ключом: тот же шифр с тем же заполнением и счётчиком
	cipher::chacha_t opener;
	// Если снять гамму не удалось
	if(!opener.start(view_t(key, sizeof(key)), view_t(nonce, sizeof(nonce)), 0) || !opener.decrypt(view_t(cipher, message.size), plain))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем вскрытое
	cout << "Верный ключ: «" << string(reinterpret_cast <const char *> (plain), message.size) << "»" << endl;
	// Неверный ключ: отказа нет, выходит мусор, неотличимый от случайного - оракула у перебора нет
	key[0] ^= 0x01;
	// Шифр на неверном ключе
	cipher::chacha_t wrong;
	// Если снять гамму неверным ключом не удалось: отказа быть не должно
	if(!wrong.start(view_t(key, sizeof(key)), view_t(nonce, sizeof(nonce)), 0) || !wrong.decrypt(view_t(cipher, message.size), plain))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем мусор
	::print("Неверный ключ дал", plain, message.size);
	// Возвращаем ключ
	key[0] ^= 0x01;
	// Подключ HChaCha20 - тот, что XChaCha20 выводит из ключа и первых 16 байтов заполнения
	uint8_t subkey[32];
	// Если подключ вывести не удалось
	if(!cipher::chacha_t::hchacha(view_t(key, sizeof(key)), view_t(nonce, 16), subkey))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем подключ
	::print("HChaCha20", subkey, sizeof(subkey));
	// AES-256-CTR без GCM: блочный шифр под счётчиком, синхропосылка в половину блока - 8 байтов
	cipher::aes_t aes;
	// Если ключ AES установить не удалось
	if(!aes.key(view_t(key, sizeof(key))))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Режим счётчика поверх блочного шифра
	cipher::counter_t counter;
	// Если режим завести не удалось: синхропосылка - первые 8 байтов заполнения, длина гаммы - блок шифра
	if(!counter.start(cipher::block_t(aes), view_t(nonce, 8), 0))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Накладываем гамму AES-CTR
	if(!counter.encrypt(message, cipher))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем шифртекст
	::print("AES-256-CTR", cipher, message.size);
	// Снимаем гамму
	cipher::counter_t reverse;
	// Если снять гамму не удалось
	if(!reverse.start(cipher::block_t(aes), view_t(nonce, 8), 0) || !reverse.decrypt(view_t(cipher, message.size), plain))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Итог сличения
	const bool same = (::memcmp(plain, message.data, message.size) == 0);
	// Печатаем итог
	cout << "AES-256-CTR обратно: " << (same ? "сошлось" : "разошлось") << endl;
	// Затираем тайны
	sys::wipe(key, sizeof(key));
	sys::wipe(subkey, sizeof(subkey));
	// Выходим по итогу
	return (same ? EXIT_SUCCESS : EXIT_FAILURE);
}
