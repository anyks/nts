/**
 * @file hpke.cpp
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
 * @brief Пример гибридного шифрования с открытым ключом HPKE по RFC 9180 — ключ получателя,
 *        запечатывание и вскрытие одним вызовом, поток сообщений через контекст, режим с заранее
 *        разделённым ключом
 *
 * @details HPKE складывает упаковку ключа, выработку и AEAD в один договор: отправитель знает
 *          лишь открытый ключ получателя и шлёт ему упаковку вместе с шифртекстом
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
#include <hpke/hpke.hpp>

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
	// Набор HPKE: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305
	const hpke::suite_t suite(hpke::kem_t::X25519_HKDF_SHA256, hpke::kdf_t::HKDF_SHA256, hpke::aead_t::CHACHA20_POLY1305);
	// Ключ получателя
	hpke::key_t recipient;
	// Если ключ получателя породить не удалось
	if(recipient.generate(hpke::kem_t::X25519_HKDF_SHA256) != hpke::error_t::NONE){
		// Печатаем отказ
		cout << "Породить ключ получателя не удалось" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Печатаем открытый ключ получателя: его отправитель получает заранее
	::print("Открытый ключ получателя", recipient.point().data, recipient.point().size);
	// Сведения о применении, вплетаемые в выработку ключей
	const view_t info = ::text("образец HPKE A-NTS");
	// Открытая присоединённая часть сообщения
	const view_t associated = ::text("заголовок");
	// Секрет, разделённый заранее, - пуст в базовом режиме
	const hpke::shared_t nothing;
	// Упаковка ключа и шифртекст одного вызова
	vector <uint8_t> enc, sealed;
	// Отправитель запечатывает сообщение на открытом ключе получателя
	if(hpke::seal(suite, hpke::regime_t::BASE, recipient.point(), info, nothing, nullptr, associated, ::text("сообщение одним вызовом"), enc, sealed) != hpke::error_t::NONE)
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем упаковку и шифртекст
	::print("Упаковка ключа", enc.data(), enc.size());
	::print("Шифртекст     ", sealed.data(), sealed.size());
	// Вскрытое сообщение
	vector <uint8_t> opened;
	// Получатель вскрывает сообщение своим ключом
	if(hpke::open(suite, hpke::regime_t::BASE, recipient, view_t(enc.data(), enc.size()), info, nothing, view_t(), associated, view_t(sealed.data(), sealed.size()), opened) != hpke::error_t::NONE)
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем вскрытое сообщение
	cout << "Вскрыто: " << string(opened.begin(), opened.end()) << endl;
	// Порча шифртекста: вскрытие отвечает отказом, а не мусором
	sealed[0] ^= 0x01;
	// Если испорченный шифртекст вскрылся
	if(hpke::open(suite, hpke::regime_t::BASE, recipient, view_t(enc.data(), enc.size()), info, nothing, view_t(), associated, view_t(sealed.data(), sealed.size()), opened) == hpke::error_t::NONE)
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем итог
	cout << "Испорченный шифртекст отвергнут" << endl;
	// Поток сообщений: контексты сторон живут дольше одного сообщения, счётчик внутри
	hpke::context_t mine, theirs;
	// Временный ключ отправителя
	hpke::key_t ephemeral;
	// Если временный ключ породить не удалось
	if(ephemeral.generate(hpke::kem_t::X25519_HKDF_SHA256) != hpke::error_t::NONE)
		// Выходим с отказом
		return EXIT_FAILURE;
	// Место под упаковку ключа
	uint8_t packed[32];
	// Заводим контекст отправителя
	if(hpke::sender(suite, hpke::regime_t::BASE, recipient.point(), info, nothing, nullptr, ephemeral, packed, mine) != hpke::error_t::NONE)
		// Выходим с отказом
		return EXIT_FAILURE;
	// Заводим контекст получателя по упаковке
	if(hpke::recipient(suite, hpke::regime_t::BASE, recipient, view_t(packed, sizeof(packed)), info, nothing, view_t(), theirs) != hpke::error_t::NONE)
		// Выходим с отказом
		return EXIT_FAILURE;
	/**
	 * Выполняем передачу трёх сообщений подряд одним контекстом
	 */
	for(size_t i = 0; i < 3; i++){
		// Сообщение потока
		const string message = "сообщение потока " + to_string(i + 1);
		// Шифртекст и вскрытое
		vector <uint8_t> cipher, plain;
		// Если запечатать не удалось
		if(mine.seal(associated, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), cipher) != hpke::error_t::NONE)
			// Выходим с отказом
			return EXIT_FAILURE;
		// Если вскрыть не удалось
		if(theirs.open(associated, view_t(cipher.data(), cipher.size()), plain) != hpke::error_t::NONE)
			// Выходим с отказом
			return EXIT_FAILURE;
		// Печатаем сообщение потока
		cout << "Поток " << (i + 1) << ": " << string(plain.begin(), plain.end()) << endl;
	}
	// Режим PSK: обе стороны знают ещё и разделённый заранее ключ с опознавателем
	hpke::shared_t psk;
	// Устанавливаем ключ и опознаватель
	psk.key = ::text("заранее разделённый ключ достаточной длины");
	psk.identity = ::text("ключ образца");
	// Если запечатать в режиме PSK не удалось
	if(hpke::seal(suite, hpke::regime_t::PSK, recipient.point(), info, psk, nullptr, associated, ::text("сообщение под PSK"), enc, sealed) != hpke::error_t::NONE)
		// Выходим с отказом
		return EXIT_FAILURE;
	// Если вскрыть в режиме PSK не удалось
	if(hpke::open(suite, hpke::regime_t::PSK, recipient, view_t(enc.data(), enc.size()), info, psk, view_t(), associated, view_t(sealed.data(), sealed.size()), opened) != hpke::error_t::NONE)
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем вскрытое сообщение PSK
	cout << "Вскрыто под PSK: " << string(opened.begin(), opened.end()) << endl;
	// Выходим успешно
	return EXIT_SUCCESS;
}
