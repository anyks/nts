/**
 * @file extension.cpp
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
 * @brief Исходный файл проверок модуля расширений приветствий протокола TLS
 *
 * @note Расширения берутся из тех же пяти настоящих приветствий приложения А, на которых
 *       проверялся разбор самих приветствий: всякое известное расширение разбирается,
 *       составляется заново и сличается со своим телом байт в байт
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <vector>
#include <cstring>
#include <main.hpp>
#include <starve.hpp>
#include <hello/hello.hpp>
#include <curve/curve.hpp>
#include <curve/parameters.hpp>
#include <handshake/handshake.hpp>
#include <extension/extension.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Приветствия рукопожатия контрольного примера
 */
static const struct Sample {
	// Вид сообщения рукопожатия приветствия
	uint8_t type;
	// Сообщение приветствия вместе с обвязкой
	const char * message;
} SAMPLES[] = {
	{1, "010000DE03030303030303030303030303030303030303030303030303030303030303030303000002C105010000B3000A000400020028000D0010000E0709070A070B070C070D070E070F002B0003020304002D000201000033008600840028008005EEBDF3DDC1D2F5F3822433241284E77641487938EA88721F26203E9792B5CB97EB70EF02E8F72B7491D4F2CFDC332ADF7F1778E854A88DDC2113FEC527A15171A04CB0C573793A7AEF9BBCA486B6B046B2149B46F4332903E5B7C438ADD05E185EFBF45557475A8CCBF6ACED1A2EB416F916729D7CEF9CBD8334989304AFAE"},
	{2, "020000B60303838383838383838383838383838383838383838383838383838383838383838300C10500008E002B0002030400330084002800802F3C663FE74735A1C421160DF0F43266185FD30B6E5D6E88FC4061FAEACAB338B10A1BD20CB0B4EE757E74A0027D409FE937F01633A1E3F9A5518DEFD0F89F9D3D9F6CC651413DEC2C74366D83C47EE1DE4E421F65CD1163E94EA0C2E19ED45D35558B937D9BFDC5ECC2B2A21B4EC3D53B29579A8FD5E074811028FBCF17994F"},
	{2, "020000340303CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C00C10400000C002B00020304003300020023"},
	{1, "010000BF03030101010101010101010101010101010101010101010101010101010101010101000002C10401000094000A0006000400230028002B0003020304002D0002010100330046004400230040D35AA795C452450949591D60E7D5C076056D6646F3B80708CDC2E7034DE85F68D1122DC32A3B986D40FF910622A06C1226D9EC3A7D3A52E0A37C282C47602A430029002F000A00046550534B000000000021200BF74AA3933B7D1A66961B6E2CFB6A2804D696BB607710E3F56DDA91F56B57CB"},
	{2, "0200007C0303828282828282828282828282828282828282828282828282828282828282828200C104000054002B0002030400330044002300403D2FB067E106CC9980FB8842811164BA708BBB5038D5EDFBEE1D5E5DFBE6F74F1931217C67C2BDF46253DB9CE3487241F2DBD84E2DABDF65455851B0B19AEFEC002900020000"}
};

/**
 * @brief Метод разбора строки шестнадцатеричной записи в область байтов
 *
 * @param text разбираемая строка шестнадцатеричной записи
 *
 * @return     разобранная область байтов
 *
 */
static vector <uint8_t> decode(const char * text) noexcept {
	// Разобранная область байтов
	vector <uint8_t> result;
	// Получаем длину разбираемой строки
	const size_t length = ::strlen(text);
	/**
	 * Выполняем перебор пар знаков шестнадцатеричной записи
	 */
	for(size_t i = 0; (i + 1) < length; i += 2)
		// Добавляем очередной разобранный байт
		result.push_back(static_cast <uint8_t> (::strtoul(string(text + i, 2).c_str(), nullptr, 16)));
	// Выводим разобранную область байтов
	return result;
}

/**
 * Проверка соответствия групп обмена и схем подписи кривым
 */
TEST(ExtensionTest, Curve){
	// Перечень всех групп обмена ключами протокола
	const extension::group_t groups[] = {
		extension::group_t::GC256A, extension::group_t::GC256B,
		extension::group_t::GC256C, extension::group_t::GC256D,
		extension::group_t::GC512A, extension::group_t::GC512B,
		extension::group_t::GC512C
	};
	// Перечень всех схем подписи протокола
	const extension::scheme_t schemes[] = {
		extension::scheme_t::S256A, extension::scheme_t::S256B,
		extension::scheme_t::S256C, extension::scheme_t::S256D,
		extension::scheme_t::S512A, extension::scheme_t::S512B,
		extension::scheme_t::S512C
	};
	/**
	 * Выполняем перебор групп обмена ключами протокола
	 */
	for(size_t i = 0; i < (sizeof(groups) / sizeof(groups[0])); i++){
		// Получаем опознаватель кривой группы обмена ключами
		const char * oid = extension::curve(groups[i]);
		// Проверяем, что опознаватель кривой группы найден
		ASSERT_NE(oid, nullptr) << "группа " << i;
		// Объект кривой группы обмена ключами
		curve::curve_t sample;
		// Проверяем, что кривая набора параметров модулю известна
		ASSERT_TRUE(curve::parameters(oid, sample)) << "группа " << i;
		// Проверяем схождение опознавателя кривой со схемой подписи той же кривой
		ASSERT_STREQ(oid, extension::curve(schemes[i])) << "группа " << i;
		// Проверяем схождение длины ключа схемы подписи с длиной координаты кривой
		ASSERT_EQ(extension::length(schemes[i]), sample.size()) << "группа " << i;
	}
	// Проверяем, что неизвестная группа обмена опознавателя не имеет
	ASSERT_EQ(extension::curve(extension::group_t::NONE), nullptr);
	// Проверяем, что неизвестная схема подписи длины ключа не имеет
	ASSERT_EQ(extension::length(extension::scheme_t::NONE), static_cast <size_t> (0));
}

/**
 * Проверка разбора и составления тел расширений приветствий
 */
TEST(ExtensionTest, Bodies){
	// Число разобранных тел расширений приветствий
	size_t count = 0;
	/**
	 * Выполняем перебор приветствий контрольного примера
	 */
	for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
		// Получаем сообщение приветствия вместе с обвязкой
		const vector <uint8_t> message = decode(SAMPLES[i].message);
		// Получаем тело сообщения приветствия
		const view_t body(message.data() + handshake::HANDSHAKE_HEADER, message.size() - handshake::HANDSHAKE_HEADER);
		// Признак того, что разбирается приветствие клиента
		const bool client = (SAMPLES[i].type == 0x01);
		// Перечень расширений разобранного приветствия
		vector <hello::extension_t> extensions;
		// Признак того, что приветствие есть просьба о повторе
		bool retry = false;
		// Если разбирается приветствие клиента
		if(client){
			// Разобранное приветствие клиента
			hello::client_t hello;
			// Выполняем разбор тела приветствия клиента
			ASSERT_EQ(hello::parse(body, hello), hello::error_t::NONE) << "приветствие " << i;
			// Запоминаем перечень расширений приветствия клиента
			extensions = hello.extensions;
		// Если разбирается приветствие сервера
		} else {
			// Разобранное приветствие сервера
			hello::server_t hello;
			// Выполняем разбор тела приветствия сервера
			ASSERT_EQ(hello::parse(body, hello), hello::error_t::NONE) << "приветствие " << i;
			// Запоминаем перечень расширений приветствия сервера
			extensions = hello.extensions;
			// Запоминаем, есть ли приветствие просьба о повторе
			retry = hello::retry(hello);
		}
		/**
		 * Выполняем перебор расширений разобранного приветствия
		 */
		for(auto & item : extensions){
			// Накопитель, в который складывается составленное тело расширения
			vector <uint8_t> composed;
			/**
			 * Выполняем определение вида расширения приветствия
			 */
			switch(item.type){
				// Если это расширение поддерживаемых изданий протокола
				case static_cast <uint16_t> (extension::type_t::VERSIONS): {
					// Если это расширение приветствия клиента
					if(client){
						// Разобранный перечень поддерживаемых изданий протокола
						vector <uint16_t> versions;
						// Выполняем разбор перечня поддерживаемых изданий
						ASSERT_EQ(extension::versions(item.data, versions), extension::error_t::NONE) << "приветствие " << i;
						// Проверяем, что клиент предлагает издание TLS 1.3
						ASSERT_EQ(versions[0], static_cast <uint16_t> (0x0304)) << "приветствие " << i;
						// Выполняем составление перечня поддерживаемых изданий заново
						ASSERT_EQ(extension::versions(versions, composed), extension::error_t::NONE) << "приветствие " << i;
					// Если это расширение приветствия сервера
					} else {
						// Разобранное выбранное издание протокола
						uint16_t version = 0;
						// Выполняем разбор выбранного издания протокола
						ASSERT_EQ(extension::version(item.data, version), extension::error_t::NONE) << "приветствие " << i;
						// Проверяем, что сервер выбрал издание TLS 1.3
						ASSERT_EQ(version, static_cast <uint16_t> (0x0304)) << "приветствие " << i;
						// Выполняем составление выбранного издания протокола заново
						ASSERT_EQ(extension::version(version, composed), extension::error_t::NONE) << "приветствие " << i;
					}
				} break;
				// Если это расширение поддерживаемых групп обмена ключами
				case static_cast <uint16_t> (extension::type_t::GROUPS): {
					// Разобранный перечень поддерживаемых групп обмена
					vector <extension::group_t> groups;
					// Выполняем разбор перечня поддерживаемых групп обмена
					ASSERT_EQ(extension::groups(item.data, groups), extension::error_t::NONE) << "приветствие " << i;
					// Проверяем, что перечень поддерживаемых групп не пуст
					ASSERT_FALSE(groups.empty()) << "приветствие " << i;
					// Проверяем, что первая предлагаемая группа обмена известна
					ASSERT_NE(extension::curve(groups[0]), nullptr) << "приветствие " << i;
					// Выполняем составление перечня поддерживаемых групп заново
					ASSERT_EQ(extension::groups(groups, composed), extension::error_t::NONE) << "приветствие " << i;
				} break;
				// Если это расширение поддерживаемых схем подписи
				case static_cast <uint16_t> (extension::type_t::SCHEMES): {
					// Разобранный перечень поддерживаемых схем подписи
					vector <extension::scheme_t> schemes;
					// Выполняем разбор перечня поддерживаемых схем подписи
					ASSERT_EQ(extension::schemes(item.data, schemes), extension::error_t::NONE) << "приветствие " << i;
					// Проверяем, что перечень поддерживаемых схем не пуст
					ASSERT_FALSE(schemes.empty()) << "приветствие " << i;
					// Проверяем, что первая предлагаемая схема подписи известна
					ASSERT_NE(extension::length(schemes[0]), static_cast <size_t> (0)) << "приветствие " << i;
					// Выполняем составление перечня поддерживаемых схем заново
					ASSERT_EQ(extension::schemes(schemes, composed), extension::error_t::NONE) << "приветствие " << i;
				} break;
				// Если это расширение открытой части ключа обмена
				case static_cast <uint16_t> (extension::type_t::SHARE): {
					// Если это расширение просьбы о повторе приветствия
					if(retry){
						// Разобранная выбранная сервером группа обмена ключами
						extension::group_t group = extension::group_t::NONE;
						// Выполняем разбор выбранной сервером группы обмена
						ASSERT_EQ(extension::selected(item.data, group), extension::error_t::NONE) << "приветствие " << i;
						// Проверяем, что выбранная сервером группа обмена известна
						ASSERT_NE(extension::curve(group), nullptr) << "приветствие " << i;
						// Выполняем составление выбранной группы обмена заново
						ASSERT_EQ(extension::selected(group, composed), extension::error_t::NONE) << "приветствие " << i;
					// Если это расширение приветствия клиента
					} else if(client){
						// Разобранный перечень открытых частей ключей обмена
						vector <extension::share_t> shares;
						// Выполняем разбор перечня открытых частей ключей обмена
						ASSERT_EQ(extension::shares(item.data, shares), extension::error_t::NONE) << "приветствие " << i;
						// Проверяем, что перечень открытых частей ключей не пуст
						ASSERT_FALSE(shares.empty()) << "приветствие " << i;
						// Проверяем, что открытая часть ключа занимает две координаты кривой
						ASSERT_EQ(shares[0].key.size, (extension::length(static_cast <extension::scheme_t> (0x0709 + (static_cast <uint16_t> (shares[0].group) - 0x22))) * 2)) << "приветствие " << i;
						// Выполняем составление перечня открытых частей ключей заново
						ASSERT_EQ(extension::shares(shares, composed), extension::error_t::NONE) << "приветствие " << i;
					// Если это расширение приветствия сервера
					} else {
						// Разобранная открытая часть ключа обмена сервера
						extension::share_t share;
						// Выполняем разбор открытой части ключа обмена сервера
						ASSERT_EQ(extension::share(item.data, share), extension::error_t::NONE) << "приветствие " << i;
						// Проверяем, что группа обмена открытой части ключа известна
						ASSERT_NE(extension::curve(share.group), nullptr) << "приветствие " << i;
						// Выполняем составление открытой части ключа обмена заново
						ASSERT_EQ(extension::share(share, composed), extension::error_t::NONE) << "приветствие " << i;
					}
				} break;
				// Если это расширение способов обмена с заранее разделённым ключом
				case static_cast <uint16_t> (extension::type_t::MODES): {
					// Разобранный перечень способов обмена
					vector <extension::regime_t> modes;
					// Выполняем разбор перечня способов обмена
					ASSERT_EQ(extension::modes(item.data, modes), extension::error_t::NONE) << "приветствие " << i;
					// Проверяем, что перечень способов обмена не пуст
					ASSERT_FALSE(modes.empty()) << "приветствие " << i;
					// Выполняем составление перечня способов обмена заново
					ASSERT_EQ(extension::modes(modes, composed), extension::error_t::NONE) << "приветствие " << i;
				} break;
				// Если это расширение имени запрашиваемого узла
				case static_cast <uint16_t> (extension::type_t::NAME): {
					// Разобранное имя запрашиваемого узла
					view_t name;
					// Выполняем разбор имени запрашиваемого узла
					ASSERT_EQ(extension::name(item.data, name), extension::error_t::NONE) << "приветствие " << i;
					// Проверяем, что имя запрашиваемого узла не пусто
					ASSERT_GT(name.size, static_cast <size_t> (0)) << "приветствие " << i;
					// Выполняем составление имени запрашиваемого узла заново
					ASSERT_EQ(extension::name(name, composed), extension::error_t::NONE) << "приветствие " << i;
				} break;
				// Если вид расширения этому набору проверок неизвестен
				default: continue;
			}
			// Проверяем схождение длины составленного тела расширения с исходным
			ASSERT_EQ(composed.size(), item.data.size) << "приветствие " << i << " расширение " << item.type;
			// Проверяем схождение составленного тела расширения с исходным
			ASSERT_EQ(::memcmp(composed.data(), item.data.data, composed.size()), 0) << "приветствие " << i << " расширение " << item.type;
			// Увеличиваем число разобранных тел расширений
			count++;
		}
	}
	// Проверяем, что разобранных тел расширений набралось достаточно
	ASSERT_GE(count, static_cast <size_t> (10));
}

/**
 * Проверка разбора усечённых и порченых тел расширений
 *
 * @note Проверка эта итога разбора не судит: усечённое тело вправе и не
 *       разобраться, и разобраться в иное. Судит она лишь того, что всякий
 *       разборщик выдерживает всякое тело - и своё, и чужое, и обрубленное, - не
 *       валясь и за поданную область байтов не выходя. Смысл её раскрывается под
 *       санитайзерами: без них она стережёт лишь отказ работы
 */
TEST(ExtensionTest, Ragged){
	// Набор годных тел расширений, служащий основою порчи
	vector <vector <uint8_t>> corpus(8);
	// Открытая часть ключа обмена, кладомая в долю обмена
	const vector <uint8_t> opened(64, 0x11);
	// Если перечень изданий протокола составить не удалось
	ASSERT_EQ(extension::versions(vector <uint16_t> {0x0304, 0x0303}, corpus[0]), extension::error_t::NONE);
	// Если перечень кривых обмена ключами составить не удалось
	ASSERT_EQ(extension::groups(vector <extension::group_t> {extension::group_t::GC256B, extension::group_t::GC512A}, corpus[1]), extension::error_t::NONE);
	// Если перечень схем подписи составить не удалось
	ASSERT_EQ(extension::schemes(vector <extension::scheme_t> {extension::scheme_t::S256B, extension::scheme_t::S512A}, corpus[2]), extension::error_t::NONE);
	// Если перечень долей обмена ключами составить не удалось
	ASSERT_EQ(extension::shares(vector <extension::share_t> {extension::share_t(extension::group_t::GC256B, view_t(opened.data(), opened.size()))}, corpus[3]), extension::error_t::NONE);
	// Если способы обмена заранее разделённым ключом составить не удалось
	ASSERT_EQ(extension::modes(vector <extension::regime_t> {extension::regime_t::SHARED}, corpus[4]), extension::error_t::NONE);
	// Если перечень прикладных протоколов составить не удалось
	ASSERT_EQ(extension::protocols(vector <string> {"h2", "http/1.1"}, corpus[5]), extension::error_t::NONE);
	// Если метку возврата состояния составить не удалось
	ASSERT_EQ(extension::cookie(view_t(opened.data(), 16), corpus[6]), extension::error_t::NONE);
	// Если предел упреждающих данных составить не удалось
	ASSERT_EQ(extension::early(static_cast <uint32_t> (16384), corpus[7]), extension::error_t::NONE);
	/**
	 * Выполняем перебор годных тел расширений
	 */
	for(size_t body = 0; body < corpus.size(); body++){
		/**
		 * Выполняем перебор длин усечения очередного тела
		 */
		for(size_t size = 0; size <= corpus[body].size(); size++){
			/**
			 * Выполняем перебор порчи очередного байта тела: нулевой круг порчи не
			 * вносит вовсе, и им проверяется само усечение
			 */
			for(size_t place = 0; place <= size; place++){
				// Выполняем перенос очередного годного тела расширения
				vector <uint8_t> item(corpus[body].begin(), corpus[body].begin() + static_cast <ptrdiff_t> (size));
				// Если очередной байт тела портится
				if((place > 0) && (place <= item.size()))
					// Выполняем обращение всех разрядов порченого байта
					item[place - 1] = static_cast <uint8_t> (item[place - 1] ^ 0xFF);
				// Просмотр разбираемого тела расширения
				const view_t data(item.data(), item.size());
				// Место, в которое помещается разобранный перечень изданий протокола
				vector <uint16_t> versions;
				// Место, в которое помещается разобранное издание протокола
				uint16_t version = 0;
				// Место, в которое помещается разобранный перечень кривых
				vector <extension::group_t> groups;
				// Место, в которое помещается разобранная выбранная кривая
				extension::group_t group = extension::group_t::NONE;
				// Место, в которое помещается разобранный перечень схем подписи
				vector <extension::scheme_t> schemes;
				// Место, в которое помещается разобранный перечень долей обмена
				vector <extension::share_t> shares;
				// Место, в которое помещается разобранная доля обмена
				extension::share_t share(extension::group_t::NONE, view_t(nullptr, 0));
				// Место, в которое помещается разобранный перечень способов обмена
				vector <extension::regime_t> modes;
				// Место, в которое помещается разобранный перечень протоколов
				vector <string> protocols;
				// Место, в которое помещается разобранный прикладной протокол
				string protocol;
				// Место, в которое помещается разобранная метка возврата состояния
				view_t cookie;
				// Место, в которое помещается разобранное имя запрашиваемого узла
				view_t name;
				// Место, в которое помещается разобранное место выбранного ключа
				uint16_t chosen = 0;
				// Место, в которое помещается разобранный предел упреждающих данных
				uint32_t limit = 0;
				// Место, в которое помещается разобранный перечень опознавателей
				vector <extension::identity_t> identities;
				// Место, в которое помещается разобранный перечень привязок
				vector <view_t> binders;
				// Место, в которое помещается длина усечения приветствия
				size_t truncation = 0;
				/**
				 * Всякое тело подаётся всякому разборщику: чужое тело для разборщика
				 * ничем не лучше порченого, и выдержать он обязан оба
				 */
				(void) extension::versions(data, versions);
				// Выполняем разбор издания протокола
				(void) extension::version(data, version);
				// Выполняем разбор перечня кривых обмена ключами
				(void) extension::groups(data, groups);
				// Выполняем разбор выбранной кривой обмена ключами
				(void) extension::selected(data, group);
				// Выполняем разбор перечня схем подписи
				(void) extension::schemes(data, schemes);
				// Выполняем разбор перечня долей обмена ключами
				(void) extension::shares(data, shares);
				// Выполняем разбор доли обмена ключами
				(void) extension::share(data, share);
				// Выполняем разбор способов обмена заранее разделённым ключом
				(void) extension::modes(data, modes);
				// Выполняем разбор перечня прикладных протоколов
				(void) extension::protocols(data, protocols);
				// Выполняем разбор выбранного прикладного протокола
				(void) extension::protocol(data, protocol);
				// Выполняем разбор метки возврата состояния сервера
				(void) extension::cookie(data, cookie);
				// Выполняем разбор имени запрашиваемого узла
				(void) extension::name(data, name);
				// Выполняем разбор места выбранного заранее разделённого ключа
				(void) extension::chosen(data, chosen);
				// Выполняем разбор предела упреждающих данных
				(void) extension::early(data, limit);
				// Выполняем разбор предложения заранее разделённых ключей
				(void) extension::identities(data, identities, binders, truncation);
				/**
				 * Итоги разбора чужих тел не сличаются намеренно: чужое тело разборщик
				 * вправе и принять, если оно случаем сошлось с его собственным видом.
				 * Проверяется же ими выдержка разбора: под ASan круги эти ловят всякий
				 * выход за поданное тело.
				 *
				 * А вот СВОЙ разборщик обязан отвергнуть всякий НЕПОЛНЫЙ обрубок своего
				 * же тела: длина всякого перечня объявляется впереди него, и обрубок
				 * объявленной длины не наберёт. Порченые круги сюда не берутся - порча
				 * байта длины вправе дать и годное тело
				 */
				if((place == 0) && (size < corpus[body].size())){
					/**
					 * Выполняем сличение обрубка со своим разборщиком
					 */
					switch(body){
						// Обрубок перечня изданий протокола
						case 0: ASSERT_NE(extension::versions(data, versions), extension::error_t::NONE) << "издания, длина " << size; break;
						// Обрубок перечня кривых обмена ключами
						case 1: ASSERT_NE(extension::groups(data, groups), extension::error_t::NONE) << "кривые, длина " << size; break;
						// Обрубок перечня схем подписи
						case 2: ASSERT_NE(extension::schemes(data, schemes), extension::error_t::NONE) << "схемы, длина " << size; break;
						// Обрубок перечня долей обмена ключами
						case 3: ASSERT_NE(extension::shares(data, shares), extension::error_t::NONE) << "доли, длина " << size; break;
						// Обрубок способов обмена заранее разделённым ключом
						case 4: ASSERT_NE(extension::modes(data, modes), extension::error_t::NONE) << "способы, длина " << size; break;
						// Обрубок перечня прикладных протоколов
						case 5: ASSERT_NE(extension::protocols(data, protocols), extension::error_t::NONE) << "протоколы, длина " << size; break;
						// Обрубок метки возврата состояния сервера
						case 6: ASSERT_NE(extension::cookie(data, cookie), extension::error_t::NONE) << "метка, длина " << size; break;
						// Обрубок предела упреждающих данных
						case 7: ASSERT_NE(extension::early(data, limit), extension::error_t::NONE) << "предел, длина " << size; break;
					}
				}
			}
		}
	}
}

/**
 * Проверка отказов разбора тел расширений
 */
TEST(ExtensionTest, Reject){
	// Разобранный перечень поддерживаемых групп обмена
	vector <extension::group_t> groups;
	// Тело расширения с перечнем, оборванным посреди группы
	const uint8_t broken[] = {0x00, 0x03, 0x00, 0x28, 0x00};
	// Проверяем отказ разбора перечня, оборванного посреди значения
	ASSERT_EQ(extension::groups(view_t(broken, sizeof(broken)), groups), extension::error_t::HUNGRY);
	// Тело расширения с пустым перечнем групп обмена
	const uint8_t empty[] = {0x00, 0x00};
	// Проверяем отказ разбора пустого перечня групп обмена
	ASSERT_EQ(extension::groups(view_t(empty, sizeof(empty)), groups), extension::error_t::EMPTY);
	// Тело расширения с лишними байтами за перечнем
	const uint8_t trailing[] = {0x00, 0x02, 0x00, 0x28, 0xFF};
	// Проверяем отказ разбора перечня с лишними байтами за ним
	ASSERT_EQ(extension::groups(view_t(trailing, sizeof(trailing)), groups), extension::error_t::TRAILING);
	// Тело расширения, объявившее длину перечня сверх своей области
	const uint8_t hungry[] = {0x00, 0x10, 0x00, 0x28};
	// Проверяем отказ разбора перечня, объявившего длину сверх области
	ASSERT_EQ(extension::groups(view_t(hungry, sizeof(hungry)), groups), extension::error_t::HUNGRY);
	// Накопитель, в который складывается составленное тело расширения
	vector <uint8_t> composed;
	// Проверяем отказ составления пустого перечня групп обмена
	ASSERT_EQ(extension::groups(groups, composed), extension::error_t::EMPTY);
	// Разобранное имя запрашиваемого узла
	view_t name;
	// Тело расширения с именем узла неизвестного вида
	const uint8_t foreign[] = {0x00, 0x06, 0x0A, 0x00, 0x03, 0x61, 0x62, 0x63};
	// Проверяем отказ разбора перечня без имени вида «host_name»
	ASSERT_EQ(extension::name(view_t(foreign, sizeof(foreign)), name), extension::error_t::EMPTY);
	// Проверяем отказ составления пустого имени запрашиваемого узла
	ASSERT_EQ(extension::name(view_t(nullptr, 0), composed), extension::error_t::EMPTY);
	/**
	 * Непереданное место при заявленной длине - оплошность потребителя: длина есть,
	 * а читать её не из чего. Переданность и длина сверяются РАЗНЫМИ половинами
	 * условия, и всякая отвергает довод в одиночку
	 */
	ASSERT_EQ(extension::name(view_t(nullptr, 9), composed), extension::error_t::EMPTY);
	// Проверяем отказ составления имени узла нулевой длины
	ASSERT_EQ(extension::name(view_t(foreign, 0), composed), extension::error_t::EMPTY);
	/**
	 * Перечень имён узлов несёт имя вида «host_name» лишь однажды, а сверх него
	 * может нести имена иных видов: разбор берёт ПЕРВОЕ имя своего вида и следующие
	 * за ним уже не трогает
	 */
	const uint8_t twofold[] = {
		0x00, 0x0C, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63,
		0x00, 0x00, 0x03, 0x64, 0x65, 0x66};
	// Выполняем разбор перечня с двумя именами узлов своего вида: раздел 3 RFC 6066 двух имён одного вида не дозволяет (аудит 09.09.2026, прежняя терпимость снята)
	ASSERT_EQ(extension::name(view_t(twofold, sizeof(twofold)), name), extension::error_t::TRAILING);
	// Проверяем, что разобрано именно первое имя узла перечня
	ASSERT_EQ(::memcmp(name.data, "abc", name.size), 0);
	// Разобранная метка возврата состояния сервера
	view_t cookie;
	// Проверяем отказ разбора пустой метки возврата состояния
	ASSERT_EQ(extension::cookie(view_t(empty, sizeof(empty)), cookie), extension::error_t::EMPTY);
	// Накопитель, в который складывается составленная метка возврата
	vector <uint8_t> stated;
	// Проверяем отказ составления непереданной метки возврата состояния
	ASSERT_EQ(extension::cookie(view_t(nullptr, 8), stated), extension::error_t::EMPTY);
	// Проверяем отказ составления метки возврата состояния нулевой длины
	ASSERT_EQ(extension::cookie(view_t(foreign, 0), stated), extension::error_t::EMPTY);
	// Составляемая метка возврата состояния сервера
	const uint8_t sample[] = {0xDE, 0xAD, 0xBE, 0xEF};
	// Выполняем сброс накопителя составленного тела расширения
	composed.clear();
	// Выполняем составление метки возврата состояния сервера
	ASSERT_EQ(extension::cookie(view_t(sample, sizeof(sample)), composed), extension::error_t::NONE);
	// Выполняем разбор составленной метки возврата состояния
	ASSERT_EQ(extension::cookie(view_t(composed.data(), composed.size()), cookie), extension::error_t::NONE);
	// Проверяем схождение разобранной метки с составленной
	ASSERT_EQ(cookie.size, sizeof(sample));
	// Проверяем схождение содержимого разобранной метки с составленной
	ASSERT_EQ(::memcmp(cookie.data, sample, cookie.size), 0);
}

/**
 * Проверка разбора и составления предложения заранее разделённых ключей
 */
TEST(ExtensionTest, Identities){
	// Опознаватели предлагаемых заранее разделённых ключей
	const uint8_t first[4] = {0x01, 0x02, 0x03, 0x04}, second[3] = {0x0A, 0x0B, 0x0C};
	// Привязки предлагаемых заранее разделённых ключей
	uint8_t binder[32], element[32];
	// Выполняем заполнение привязки первого ключа
	::memset(binder, 0x11, sizeof(binder));
	// Выполняем заполнение привязки второго ключа
	::memset(element, 0x22, sizeof(element));
	// Составляемый перечень опознавателей ключей
	const vector <extension::identity_t> identities = {
		extension::identity_t(view_t(first, sizeof(first)), 0x01020304),
		extension::identity_t(view_t(second, sizeof(second)), 0x05060708)
	};
	// Составляемый перечень привязок ключей
	const vector <view_t> binders = {view_t(binder, sizeof(binder)), view_t(element, sizeof(element))};
	// Накопитель, в который складывается тело расширения
	vector <uint8_t> body;
	// Выполняем составление предложения заранее разделённых ключей
	ASSERT_EQ(extension::identities(identities, binders, body), extension::error_t::NONE);
	// Разбираемый перечень опознавателей ключей
	vector <extension::identity_t> parsed;
	// Разбираемый перечень привязок ключей
	vector <view_t> items;
	// Длина усечения приветствия от начала тела расширения
	size_t truncation = 0;
	// Выполняем разбор составленного предложения ключей
	ASSERT_EQ(extension::identities(view_t(body.data(), body.size()), parsed, items, truncation), extension::error_t::NONE);
	// Проверяем число разобранных опознавателей ключей
	ASSERT_EQ(parsed.size(), static_cast <size_t> (2));
	// Проверяем число разобранных привязок ключей
	ASSERT_EQ(items.size(), static_cast <size_t> (2));
	/**
	 * Длина усечения отсчитывается до перечня привязок: за нею идут два байта длины
	 * перечня и сами привязки, длиною в байт и тридцать два байта всякая
	 */
	ASSERT_EQ(truncation, body.size() - (2 + (2 * (1 + 32))));
	// Проверяем длину первого разобранного опознавателя ключа
	ASSERT_EQ(parsed[0].identity.size, sizeof(first));
	// Проверяем схождение первого разобранного опознавателя с составленным
	ASSERT_EQ(::memcmp(parsed[0].identity.data, first, sizeof(first)), 0);
	// Проверяем скрытый возраст первого разобранного билета
	ASSERT_EQ(parsed[0].age, static_cast <uint32_t> (0x01020304));
	// Проверяем схождение второго разобранного опознавателя с составленным
	ASSERT_EQ(::memcmp(parsed[1].identity.data, second, sizeof(second)), 0);
	// Проверяем скрытый возраст второго разобранного билета
	ASSERT_EQ(parsed[1].age, static_cast <uint32_t> (0x05060708));
	// Проверяем схождение первой разобранной привязки с составленной
	ASSERT_EQ(::memcmp(items[0].data, binder, sizeof(binder)), 0);
	// Проверяем схождение второй разобранной привязки с составленной
	ASSERT_EQ(::memcmp(items[1].data, element, sizeof(element)), 0);
	// Проверяем отказ составления предложения с пустым перечнем ключей
	ASSERT_EQ(extension::identities(vector <extension::identity_t> (), binders, body), extension::error_t::EMPTY);
	// Проверяем отказ составления предложения без привязок ключей
	ASSERT_EQ(extension::identities(identities, vector <view_t> (), body), extension::error_t::EMPTY);
}

/**
 * Проверка разбора и составления выбранного сервером ключа
 */
TEST(ExtensionTest, Chosen){
	// Накопитель, в который складывается тело расширения
	vector <uint8_t> body;
	// Выполняем составление выбранного сервером ключа
	ASSERT_EQ(extension::chosen(static_cast <uint16_t> (1), body), extension::error_t::NONE);
	// Проверяем длину составленного тела расширения
	ASSERT_EQ(body.size(), static_cast <size_t> (2));
	// Место выбранного ключа в предложении клиента
	uint16_t chosen = 0;
	// Выполняем разбор составленного тела расширения
	ASSERT_EQ(extension::chosen(view_t(body.data(), body.size()), chosen), extension::error_t::NONE);
	// Проверяем разобранное место выбранного ключа
	ASSERT_EQ(chosen, static_cast <uint16_t> (1));
}

/**
 * Проверка разбора и составления перечня прикладных протоколов
 */
TEST(ExtensionTest, Protocols){
	// Накопитель, в который складывается тело расширения
	vector <uint8_t> body;
	// Перечень составляемых прикладных протоколов
	const vector <string> offer = {"h2", "http/1.1"};
	// Выполняем составление перечня прикладных протоколов
	ASSERT_EQ(extension::protocols(offer, body), extension::error_t::NONE);
	// Проверяем длину составленного тела расширения
	ASSERT_EQ(body.size(), static_cast <size_t> (2 + 1 + 2 + 1 + 8));
	// Проверяем длину перечня прикладных протоколов
	ASSERT_EQ(static_cast <size_t> ((body[0] << 8) | body[1]), body.size() - 2);
	// Перечень разобранных прикладных протоколов
	vector <string> protocols;
	// Выполняем разбор составленного тела расширения
	ASSERT_EQ(extension::protocols(view_t(body.data(), body.size()), protocols), extension::error_t::NONE);
	// Проверяем схождение разобранного перечня с составленным
	ASSERT_EQ(protocols, offer);
	// Проверяем отказ составления перечня из пустого набора протоколов
	ASSERT_EQ(extension::protocols(vector <string> (), body), extension::error_t::EMPTY);
	// Проверяем отказ составления перечня с пустым названием протокола
	ASSERT_EQ(extension::protocols(vector <string> (1, string()), body), extension::error_t::EMPTY);
	// Тело расширения с пустым названием прикладного протокола
	const uint8_t empty[3] = {0x00, 0x01, 0x00};
	// Выполняем сброс перечня разобранных прикладных протоколов
	protocols.clear();
	// Проверяем отказ разбора пустого названия прикладного протокола
	ASSERT_EQ(extension::protocols(view_t(empty, sizeof(empty)), protocols), extension::error_t::EMPTY);
	// Тело расширения, оборванное посреди названия протокола
	const uint8_t torn[4] = {0x00, 0x03, 0x04, 0x68};
	// Проверяем отказ разбора оборванного тела расширения
	ASSERT_EQ(extension::protocols(view_t(torn, sizeof(torn)), protocols), extension::error_t::HUNGRY);
}

/**
 * Проверка разбора и составления перечня записей точек кривой ec_point_formats по разделу
 * 5.1.2 RFC 8422: однобайтовая длина, однобайтовые записи, порядок сохраняется; пустой
 * перечень, лишние байты и обрыв отвергаются
 */
TEST(ExtensionTest, Formats){
	// Накопитель, в который складывается тело расширения
	vector <uint8_t> body;
	// Перечень составляемых записей точек: несжатая и обе сжатые
	const vector <uint8_t> offer = {0x00, 0x01, 0x02};
	// Выполняем составление перечня записей точек
	ASSERT_EQ(extension::formats(offer, body), extension::error_t::NONE);
	// Проверяем тело расширения: длина и три записи
	ASSERT_EQ(body, (vector <uint8_t> {0x03, 0x00, 0x01, 0x02}));
	// Перечень разобранных записей точек
	vector <uint8_t> formats;
	// Выполняем разбор составленного тела расширения
	ASSERT_EQ(extension::formats(view_t(body.data(), body.size()), formats), extension::error_t::NONE);
	// Проверяем схождение разобранного перечня с составленным
	ASSERT_EQ(formats, offer);
	// Проверяем отказ составления пустого перечня
	ASSERT_EQ(extension::formats(vector <uint8_t> (), body), extension::error_t::EMPTY);
	// Тело расширения с пустым перечнем
	const uint8_t empty[1] = {0x00};
	// Проверяем отказ разбора пустого перечня
	ASSERT_EQ(extension::formats(view_t(empty, sizeof(empty)), formats), extension::error_t::EMPTY);
	// Тело расширения с лишним байтом за перечнем
	const uint8_t trailing[3] = {0x01, 0x00, 0x00};
	// Проверяем отказ разбора лишних байтов
	ASSERT_EQ(extension::formats(view_t(trailing, sizeof(trailing)), formats), extension::error_t::TRAILING);
	// Тело расширения, оборванное посреди перечня
	const uint8_t torn[2] = {0x02, 0x00};
	// Проверяем отказ разбора оборванного тела расширения
	ASSERT_EQ(extension::formats(view_t(torn, sizeof(torn)), formats), extension::error_t::HUNGRY);
}

/**
 * Проверка разбора и составления перечня алгоритмов сжатия цепочки сертификатов по
 * разделу 3 RFC 8879: однобайтовая длина, двухбайтовые опознаватели, порядок сохраняется,
 * неведомые значения выдаются как есть
 */
TEST(ExtensionTest, Algorithms){
	// Накопитель, в который складывается тело расширения
	vector <uint8_t> body;
	// Перечень составляемых алгоритмов: zlib, частный и чужой, порядок потребителя
	const vector <uint16_t> offer = {static_cast <uint16_t> (extension::compression_t::ZLIB), 16384, 0x7777};
	// Выполняем составление перечня алгоритмов
	ASSERT_EQ(extension::algorithms(offer, body), extension::error_t::NONE);
	// Проверяем длину составленного тела расширения: длина и три опознавателя
	ASSERT_EQ(body.size(), static_cast <size_t> (1 + 3 * 2));
	// Проверяем однобайтовую длину перечня
	ASSERT_EQ(body[0], static_cast <uint8_t> (6));
	// Проверяем запись первого опознавателя старшим байтом вперёд
	ASSERT_EQ(body[1], static_cast <uint8_t> (0x00));
	// Младший байт первого опознавателя
	ASSERT_EQ(body[2], static_cast <uint8_t> (0x01));
	// Перечень разобранных алгоритмов
	vector <uint16_t> algorithms;
	// Выполняем разбор составленного тела расширения
	ASSERT_EQ(extension::algorithms(view_t(body.data(), body.size()), algorithms), extension::error_t::NONE);
	// Проверяем схождение разобранного перечня с составленным в том же порядке
	ASSERT_EQ(algorithms, offer);
	// Проверяем отказ составления пустого перечня
	ASSERT_EQ(extension::algorithms(vector <uint16_t> (), body), extension::error_t::EMPTY);
	// Тело расширения с пустым перечнем
	const uint8_t empty[1] = {0x00};
	// Проверяем отказ разбора пустого перечня
	ASSERT_EQ(extension::algorithms(view_t(empty, sizeof(empty)), algorithms), extension::error_t::EMPTY);
	// Тело расширения, оборванное посреди опознавателя
	const uint8_t torn[2] = {0x02, 0x00};
	// Проверяем отказ разбора оборванного тела расширения
	ASSERT_EQ(extension::algorithms(view_t(torn, sizeof(torn)), algorithms), extension::error_t::HUNGRY);
	// Тело расширения с нечётной длиной перечня
	const uint8_t odd[4] = {0x03, 0x00, 0x01, 0x00};
	// Проверяем отказ разбора перечня нечётной длины
	ASSERT_NE(extension::algorithms(view_t(odd, sizeof(odd)), algorithms), extension::error_t::NONE);
	// Тело расширения с лишними байтами за перечнем
	const uint8_t trailing[4] = {0x02, 0x00, 0x01, 0x00};
	// Проверяем отказ разбора лишних байтов
	ASSERT_EQ(extension::algorithms(view_t(trailing, sizeof(trailing)), algorithms), extension::error_t::TRAILING);
}

/**
 * Проверка разбора и составления выбранного прикладного протокола
 */
TEST(ExtensionTest, Protocol){
	// Накопитель, в который складывается тело расширения
	vector <uint8_t> body;
	// Выполняем составление выбранного прикладного протокола
	ASSERT_EQ(extension::protocol(string("h2"), body), extension::error_t::NONE);
	// Название разобранного прикладного протокола
	string protocol;
	// Выполняем разбор составленного тела расширения
	ASSERT_EQ(extension::protocol(view_t(body.data(), body.size()), protocol), extension::error_t::NONE);
	// Проверяем схождение разобранного протокола с составленным
	ASSERT_EQ(protocol, "h2");
	// Проверяем отказ составления пустого названия протокола
	ASSERT_EQ(extension::protocol(string(), body), extension::error_t::EMPTY);
	// Выполняем сброс накопителя тела расширения
	body.clear();
	// Выполняем составление перечня из двух прикладных протоколов
	ASSERT_EQ(extension::protocols(vector <string> {"h2", "http/1.1"}, body), extension::error_t::NONE);
	/**
	 * Раздел 3.1 RFC 7301: ответом сервера идёт ровно один протокол, и перечень из
	 * двух в ответе - это уже не выбор
	 */
	ASSERT_EQ(extension::protocol(view_t(body.data(), body.size()), protocol), extension::error_t::LENGTH);
}

/**
 * @brief Проверка границ составления тел расширений
 *
 */
TEST(ExtensionTest, Confines){
	// Накопитель, в который складывается составляемое тело расширения
	vector <uint8_t> body;
	/**
	 * Длина перечня изданий объявляется единственным байтом, и перечень длиннее 255
	 * байтов в неё не входит: 128 изданий занимают 256 байтов
	 */
	ASSERT_EQ(extension::versions(vector <uint16_t> (128, 0x0304), body), extension::error_t::LENGTH);
	// Выполняем очистку накопителя составляемого тела
	body.clear();
	// Проверяем, что перечень изданий предельной длины составляется
	ASSERT_EQ(extension::versions(vector <uint16_t> (127, 0x0304), body), extension::error_t::NONE);
	// Выполняем очистку накопителя составляемого тела
	body.clear();
	// Метка возврата состояния, длину свою в два байта не вмещающая
	const vector <uint8_t> lengthy(65536, 0x5A);
	/**
	 * Длина метки возврата состояния объявляется двумя байтами: метка длиннее 65535
	 * байтов в них не входит
	 */
	ASSERT_EQ(extension::cookie(view_t(lengthy.data(), lengthy.size()), body), extension::error_t::LENGTH);
	// Выполняем очистку накопителя составляемого тела
	body.clear();
	// Проверяем, что метка предельной длины составляется
	ASSERT_EQ(extension::cookie(view_t(lengthy.data(), 65535), body), extension::error_t::NONE);
	// Разбираемое тело выбранной кривой с лишним байтом за ним
	const uint8_t trailing[] = {0x00, 0x22, 0x00};
	// Место, в которое помещается разобранная выбранная кривая
	extension::group_t group = extension::group_t::NONE;
	/**
	 * Тело выбранной кривой занимает ровно два байта, и всякий байт за ними означает
	 * собеседника, складывающего расширение не по правилам
	 */
	ASSERT_EQ(extension::selected(view_t(trailing, sizeof(trailing)), group), extension::error_t::TRAILING);
	// Проверяем разбор тела выбранной кривой без лишних байтов
	ASSERT_EQ(extension::selected(view_t(trailing, 2), group), extension::error_t::NONE);
}

/**
 * @brief Проверка обрыва внутренних записей перечней
 *
 */
TEST(ExtensionTest, Innermost){
	// Открытая часть ключа обмена, кладомая в долю обмена
	const vector <uint8_t> opened(64, 0x11);
	// Накопитель, в который складывается годное тело перечня долей обмена
	vector <uint8_t> body;
	// Выполняем составление годного тела перечня долей обмена
	ASSERT_EQ(extension::shares(vector <extension::share_t> {
		extension::share_t(extension::group_t::GC256B, view_t(opened.data(), 32)),
		extension::share_t(extension::group_t::GC512A, view_t(opened.data(), 64))
	}, body), extension::error_t::NONE);
	// Проверяем, что тело перечня начинается двухбайтовой длиной содержимого
	ASSERT_GT(body.size(), static_cast <size_t> (2));
	/**
	 * Обрубок всего тела отвергается объявленной длиною перечня, и до записей внутри
	 * него разбор не доходит вовсе. Чтобы дойти, длину перечня надлежит ПРАВИТЬ вслед
	 * за обрубанием: тогда обёртка сходится, а обрывается уже запись внутри неё
	 */
	for(size_t cut = 1; cut < (body.size() - 2); cut++){
		// Выполняем перенос годного тела перечня долей обмена
		vector <uint8_t> item(body.begin(), body.end() - static_cast <ptrdiff_t> (cut));
		// Определяем новую длину содержимого перечня
		const size_t length = (item.size() - 2);
		// Записываем старший байт исправленной длины содержимого
		item[0] = static_cast <uint8_t> ((length >> 8) & 0xFF);
		// Записываем младший байт исправленной длины содержимого
		item[1] = static_cast <uint8_t> (length & 0xFF);
		// Место, в которое помещается разобранный перечень долей обмена
		vector <extension::share_t> shares;
		// Выполняем разбор обрубка перечня долей обмена
		const extension::error_t error = extension::shares(view_t(item.data(), item.size()), shares);
		/**
		 * Обрубок, оборвавший запись посреди неё, обязан отвергаться. Обрубок же,
		 * павший ровно на границу записей, годен: перечень тогда просто короче
		 */
		if(error == extension::error_t::NONE){
			// Накопитель, в который складывается тело разобранного перечня
			vector <uint8_t> again;
			// Выполняем обратное составление тела разобранного перечня
			ASSERT_EQ(extension::shares(shares, again), extension::error_t::NONE) << "обрубок " << cut;
			/**
			 * Принятый обрубок обязан быть целым телом: составление по разобранному
			 * даёт ровно то же тело, каким оно и подавалось
			 */
			ASSERT_EQ(again, item) << "обрубок " << cut;
		}
	}
}

/**
 * @brief Проверка отказов разбора предложения заранее разделённых ключей
 *
 * @note Тела эти собираются байтами вручную: составление таких не выдаёт. Путь этот
 *       ведёт к возобновлению связи по билету, и негодное тело его обязано быть
 *       отвергнуто до всякой выработки привязки
 *
 */
TEST(ExtensionTest, Presented){
	// Разобранный перечень опознавателей заранее разделённых ключей
	vector <extension::identity_t> identities;
	// Разобранный перечень привязок заранее разделённых ключей
	vector <view_t> binders;
	// Длина усечения приветствия клиента, взятая разбором
	size_t truncation = 0;
	/**
	 * @brief Метод подачи собранного тела расширения его разбору
	 *
	 * @param body разбираемое тело расширения
	 *
	 * @return     отказ разбора тела расширения
	 *
	 */
	auto parse = [&](const vector <uint8_t> & body) noexcept -> extension::error_t {
		// Сбрасываем разобранный перечень опознавателей ключей
		identities.clear();
		// Сбрасываем разобранный перечень привязок ключей
		binders.clear();
		// Выводим итог разбора поданного тела расширения
		return extension::identities(view_t(body.data(), body.size()), identities, binders, truncation);
	};
	/**
	 * Годное тело: перечень опознавателей из одной записи - опознаватель в четыре
	 * байта и скрытый возраст билета в четыре байта, - а следом перечень привязок
	 * из одной привязки длиною в хеш Стрибог-256
	 */
	vector <uint8_t> sound = {0x00, 0x0A, 0x00, 0x04, 0x41, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x20};
	/**
	 * Выполняем набор привязки заранее разделённого ключа
	 */
	for(size_t i = 0; i < 32; i++)
		// Добавляем очередной байт привязки ключа
		sound.push_back(static_cast <uint8_t> (i));
	// Проверяем успешность разбора годного тела расширения
	ASSERT_EQ(parse(sound), extension::error_t::NONE);
	// Проверяем число разобранных опознавателей заранее разделённых ключей
	ASSERT_EQ(identities.size(), static_cast <size_t> (1));
	// Проверяем число разобранных привязок заранее разделённых ключей
	ASSERT_EQ(binders.size(), static_cast <size_t> (1));
	/**
	 * Длина усечения приветствия берётся местом, где кончился перечень опознавателей:
	 * привязки, идущие за ним, себя самих не покрывают - раздел 4.2.11.2 RFC 8446
	 */
	ASSERT_EQ(truncation, static_cast <size_t> (12));
	// Тело расширения с лишним байтом за своим концом
	vector <uint8_t> trailing = sound;
	// Добавляем лишний байт за конец тела расширения
	trailing.push_back(0x00);
	// Проверяем отказ разбора тела с лишним байтом за своим концом
	ASSERT_EQ(parse(trailing), extension::error_t::TRAILING);
	/**
	 * Всякому опознавателю ключа отвечает своя привязка: перечень привязок, числом
	 * с перечнем опознавателей не сошедшийся, означает ключ, предъявленный не по
	 * правилам - раздел 4.2.11 RFC 8446
	 */
	vector <uint8_t> unpaired = {0x00, 0x14, 0x00, 0x04, 0x41, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00,
	                            0x00, 0x04, 0x45, 0x46, 0x47, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x20};
	/**
	 * Выполняем набор единственной привязки на два опознавателя ключей
	 */
	for(size_t i = 0; i < 32; i++)
		// Добавляем очередной байт привязки ключа
		unpaired.push_back(static_cast <uint8_t> (i));
	// Проверяем отказ разбора тела с числом привязок, не сошедшимся с опознавателями
	ASSERT_EQ(parse(unpaired), extension::error_t::EMPTY);
	/**
	 * Перечень опознавателей, оборванный посреди опознавателя ключа: длина его
	 * объявлена двумя байтами, а содержимого объявленной длины не набирается
	 */
	const vector <uint8_t> ragged = {0x00, 0x03, 0x00, 0x04, 0x41, 0x00, 0x00};
	// Проверяем отказ разбора тела с оборванным опознавателем ключа
	ASSERT_EQ(parse(ragged), extension::error_t::HUNGRY);
	/**
	 * Перечень опознавателей, оборванный посреди скрытого возраста билета: возраст
	 * объявлен четырьмя байтами, а за опознавателем их осталось меньше
	 */
	const vector <uint8_t> ageless = {0x00, 0x08, 0x00, 0x04, 0x41, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00};
	// Проверяем отказ разбора тела с оборванным возрастом билета
	ASSERT_EQ(parse(ageless), extension::error_t::HUNGRY);
	/**
	 * Перечень привязок, оборванный посреди привязки ключа: длина её объявлена одним
	 * байтом, а содержимого объявленной длины не набирается
	 */
	const vector <uint8_t> stumped = {0x00, 0x0A, 0x00, 0x04, 0x41, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x20, 0x41, 0x42};
	// Проверяем отказ разбора тела с оборванной привязкой ключа
	ASSERT_EQ(parse(stumped), extension::error_t::HUNGRY);
}

/**
 * @brief Проверка отказов разбора имени запрашиваемого узла
 *
 */
TEST(ExtensionTest, Requested){
	// Просмотр, в который помещается разобранное имя узла
	view_t name;
	/**
	 * Перечень имён узлов, оборванный посреди вида имени: вид объявлен одним байтом,
	 * а за концом перечня его взять неоткуда
	 */
	const vector <uint8_t> ragged = {0x00, 0x01, 0x00, 0x00, 0x00};
	// Проверяем отказ разбора перечня, оборванного посреди вида имени
	ASSERT_EQ(extension::name(view_t(ragged.data(), 3), name), extension::error_t::HUNGRY);
	/**
	 * Раздел 3 RFC 6066 отводит имени узла значение нуль: перечень, несущий одни
	 * лишь имена иных видов, имени запрашиваемого узла не объявляет вовсе
	 */
	const vector <uint8_t> foreign = {0x00, 0x08, 0x01, 0x00, 0x05, 0x61, 0x6E, 0x79, 0x6B, 0x73};
	// Проверяем отказ разбора перечня без имени запрашиваемого узла
	ASSERT_EQ(extension::name(view_t(foreign.data(), foreign.size()), name), extension::error_t::EMPTY);
	/**
	 * Имя узла берётся первым из объявленных: раздел 3 RFC 6066 не даёт перечню
	 * двух имён одного вида, и второе из них принимать было бы неверно
	 */
	const vector <uint8_t> twofold = {
		0x00, 0x0F, 0x00, 0x00, 0x05, 0x66, 0x69, 0x72, 0x73, 0x74,
		0x00, 0x00, 0x04, 0x6C, 0x61, 0x73, 0x74
	};
	// Перечень из двух имён узлов отвергается: раздел 3 RFC 6066 (аудит 09.09.2026, прежняя терпимость «берётся первое» снята)
	ASSERT_EQ(extension::name(view_t(twofold.data(), twofold.size()), name), extension::error_t::TRAILING);
}

/**
 * @brief Проверка границ длин полей при составлении тел расширений
 *
 * @note Всякое поле тела расширения объявляет длину впереди содержимого, и ширина
 *       объявления задана RFC 8446: содержимое, в неё не входящее, обязано быть
 *       отвергнуто составлением, а не записано усечённой длиной
 *
 */
TEST(ExtensionTest, Bounded){
	// Накопитель, в который складывается тело составленного расширения
	vector <uint8_t> result;
	// Запись, длина которой не входит в объявление одного байта
	const vector <uint8_t> solo(256, 0x41);
	// Запись, длина которой не входит в объявление двух байтов
	const vector <uint8_t> couple(65536, 0x42);
	/**
	 * Значение обмена ключами объявляется двумя байтами: раздел 4.2.8 RFC 8446
	 */
	extension::share_t share;
	// Устанавливаем набор параметров кривой обмена ключами
	share.group = extension::group_t::GC256A;
	// Устанавливаем непомерное значение обмена ключами
	share.key = view_t(couple.data(), couple.size());
	// Проверяем отказ составления обмена ключами непомерной длины
	ASSERT_EQ(extension::share(share, result), extension::error_t::LENGTH);
	// Перечень предложений обмена ключами с непомерным значением
	vector <extension::share_t> shares;
	// Добавляем предложение обмена ключами в перечень
	shares.push_back(share);
	// Проверяем отказ составления перечня с непомерным значением обмена
	ASSERT_EQ(extension::shares(shares, result), extension::error_t::LENGTH);
	/**
	 * Перечень предложений обмена объявляется двумя байтами целиком: два предложения,
	 * всякое из которых в своё объявление входит, вместе в него не входят
	 */
	shares[0].key = view_t(couple.data(), couple.size() / 2);
	// Добавляем в перечень второе предложение обмена ключами
	shares.push_back(shares[0]);
	// Проверяем отказ составления непомерного перечня предложений обмена
	ASSERT_EQ(extension::shares(shares, result), extension::error_t::LENGTH);
	/**
	 * Перечень предлагаемых надстроек объявляется двумя байтами целиком: раздел 3.1
	 * RFC 7301
	 */
	vector <string> protocols;
	// Добавляем первую надстройку в перечень предлагаемых
	protocols.push_back(string(couple.begin(), couple.begin() + (couple.size() / 2)));
	// Добавляем вторую надстройку в перечень предлагаемых
	protocols.push_back(protocols[0]);
	// Проверяем отказ составления непомерного перечня надстроек
	ASSERT_EQ(extension::protocols(protocols, result), extension::error_t::LENGTH);
	/**
	 * Опознаватель заранее разделённого ключа объявляется двумя байтами, а привязка
	 * его - одним: раздел 4.2.11 RFC 8446
	 */
	extension::identity_t identity;
	// Устанавливаем непомерный опознаватель заранее разделённого ключа
	identity.identity = view_t(couple.data(), couple.size());
	// Перечень опознавателей заранее разделённых ключей
	vector <extension::identity_t> identities;
	// Добавляем опознаватель ключа в перечень опознавателей
	identities.push_back(identity);
	// Перечень привязок заранее разделённых ключей
	vector <view_t> binders;
	// Добавляем привязку ключа в перечень привязок
	binders.push_back(view_t(solo.data(), 32));
	// Проверяем отказ составления предложения с непомерным опознавателем
	ASSERT_EQ(extension::identities(identities, binders, result), extension::error_t::LENGTH);
	// Устанавливаем опознаватель ключа длиною в половину объявления перечня
	identities[0].identity = view_t(couple.data(), couple.size() / 2);
	// Добавляем в перечень второй опознаватель ключа
	identities.push_back(identities[0]);
	// Добавляем в перечень привязок вторую привязку ключа
	binders.push_back(binders[0]);
	// Проверяем отказ составления предложения с непомерным перечнем опознавателей
	ASSERT_EQ(extension::identities(identities, binders, result), extension::error_t::LENGTH);
	// Оставляем в перечне опознавателей единственную запись
	identities.pop_back();
	// Оставляем в перечне привязок единственную запись
	binders.pop_back();
	// Устанавливаем годный опознаватель заранее разделённого ключа
	identities[0].identity = view_t(solo.data(), 8);
	// Устанавливаем непомерную привязку заранее разделённого ключа
	binders[0] = view_t(solo.data(), solo.size());
	// Проверяем отказ составления предложения с непомерной привязкой ключа
	ASSERT_EQ(extension::identities(identities, binders, result), extension::error_t::LENGTH);
	// Устанавливаем привязку ключа длиною в половину объявления перечня
	binders[0] = view_t(couple.data(), couple.size() / 2);
	// Добавляем в перечень привязок вторую привязку ключа
	binders.push_back(binders[0]);
	// Добавляем в перечень опознавателей второй опознаватель ключа
	identities.push_back(identities[0]);
	// Проверяем отказ составления предложения с непомерным перечнем привязок
	ASSERT_EQ(extension::identities(identities, binders, result), extension::error_t::LENGTH);
	/**
	 * Имя запрашиваемого узла объявляется двумя байтами, и перечень имён - тоже:
	 * раздел 3 RFC 6066
	 */
	ASSERT_EQ(extension::name(view_t(couple.data(), couple.size()), result), extension::error_t::LENGTH);
}

/**
 * @brief Проверка пустых полей расширений, отвергаемых по длинам записи
 *
 */
TEST(ExtensionTest, Hollowed){
	// Пустые перечни опознавателей и привязок
	const uint8_t vacant[4] = {0x00, 0x00, 0x00, 0x00};
	vector <extension::identity_t> identities;
	vector <view_t> binders;
	size_t truncation = 0;
	// Раздел 4.2.11 RFC 8446: перечни непусты
	ASSERT_EQ(extension::identities(view_t(vacant, sizeof(vacant)), identities, binders, truncation), extension::error_t::EMPTY);
	// Опознаватель с привязкой в один байт
	const uint8_t brief[] = {0x00, 0x07, 0x00, 0x01, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0xA5};
	// Раздел 4.2.11 RFC 8446: привязка не короче 32 байтов
	ASSERT_EQ(extension::identities(view_t(brief, sizeof(brief)), identities, binders, truncation), extension::error_t::EMPTY);
	// Доля обмена с пустой открытой частью ключа
	const uint8_t bare[] = {0x00, 0x04, 0x00, 0x22, 0x00, 0x00};
	vector <extension::share_t> shares;
	// Раздел 4.2.8 RFC 8446: открытая часть ключа непуста
	ASSERT_EQ(extension::shares(view_t(bare, sizeof(bare)), shares), extension::error_t::EMPTY);
	// Имя узла нулевой длины
	const uint8_t nameless[] = {0x00, 0x03, 0x00, 0x00, 0x00};
	view_t name;
	// Раздел 3 RFC 6066: имя узла непусто
	ASSERT_EQ(extension::name(view_t(nameless, sizeof(nameless)), name), extension::error_t::EMPTY);
}

/**
 * @brief Метод разбора и составления расширений заново при отмеренном запасе выделений
 *
 * @param hello      разобранное приветствие клиента, тела расширений которого разбираются
 * @param names      имена прикладных протоколов длиною сверх короткого запаса строки
 * @param identities перечень опознавателей заранее разделённых ключей
 * @param binders    перечень привязок заранее разделённых ключей
 * @param intact     признак схождения составленных тел с исходными
 *
 * @return           отказ, которым завершился первый несостоявшийся шаг
 *
 * @note Всё, что выделяет память само по себе, заведено вызывающим до отмеривания
 *       запаса: под запасом должны выделять только разборщики и составители
 *
 */
static extension::error_t exhaust(const hello::client_t & hello, const vector <string> & names, const vector <extension::identity_t> & identities, const vector <view_t> & binders, bool & intact) noexcept {
	// Считаем составленные тела сходящимися, пока не найдено расхождения
	intact = true;
	// Накопитель, в который складывается составленное тело расширения
	vector <uint8_t> body;
	// Итог очередного шага
	extension::error_t outcome = extension::error_t::NONE;
	// Получаем расширение поддерживаемых изданий протокола
	const hello::extension_t * item = hello::extension(hello.extensions, 0x002B);
	// Если расширение поддерживаемых изданий протокола есть
	if(item != nullptr){
		// Разобранный перечень изданий протокола
		vector <uint16_t> versions;
		// Выполняем разбор перечня изданий протокола
		outcome = extension::versions(item->data, versions);
		// Если разбор не состоялся
		if(outcome != extension::error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Выполняем сброс накопителя
		body.clear();
		// Выполняем составление перечня изданий протокола заново
		outcome = extension::versions(versions, body);
		// Если составление не состоялось
		if(outcome != extension::error_t::NONE)
			// Выводим отказ составления
			return outcome;
		// Запоминаем схождение составленного тела расширения с исходным
		intact = (intact && (body.size() == item->data.size) && (::memcmp(body.data(), item->data.data, item->data.size) == 0));
	}
	// Получаем расширение поддерживаемых групп обмена
	item = hello::extension(hello.extensions, 0x000A);
	// Если расширение поддерживаемых групп обмена есть
	if(item != nullptr){
		// Разобранный перечень групп обмена
		vector <extension::group_t> groups;
		// Выполняем разбор перечня групп обмена
		outcome = extension::groups(item->data, groups);
		// Если разбор не состоялся
		if(outcome != extension::error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Выполняем сброс накопителя
		body.clear();
		// Выполняем составление перечня групп обмена заново
		outcome = extension::groups(groups, body);
		// Если составление не состоялось
		if(outcome != extension::error_t::NONE)
			// Выводим отказ составления
			return outcome;
		// Запоминаем схождение составленного тела расширения с исходным
		intact = (intact && (body.size() == item->data.size) && (::memcmp(body.data(), item->data.data, item->data.size) == 0));
	}
	// Получаем расширение поддерживаемых схем подписи
	item = hello::extension(hello.extensions, 0x000D);
	// Если расширение поддерживаемых схем подписи есть
	if(item != nullptr){
		// Разобранный перечень схем подписи
		vector <extension::scheme_t> schemes;
		// Выполняем разбор перечня схем подписи
		outcome = extension::schemes(item->data, schemes);
		// Если разбор не состоялся
		if(outcome != extension::error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Выполняем сброс накопителя
		body.clear();
		// Выполняем составление перечня схем подписи заново
		outcome = extension::schemes(schemes, body);
		// Если составление не состоялось
		if(outcome != extension::error_t::NONE)
			// Выводим отказ составления
			return outcome;
		// Запоминаем схождение составленного тела расширения с исходным
		intact = (intact && (body.size() == item->data.size) && (::memcmp(body.data(), item->data.data, item->data.size) == 0));
	}
	// Получаем расширение открытых частей ключей обмена
	item = hello::extension(hello.extensions, 0x0033);
	// Если расширение открытых частей ключей обмена есть
	if(item != nullptr){
		// Разобранный перечень открытых частей ключей
		vector <extension::share_t> shares;
		// Выполняем разбор перечня открытых частей ключей
		outcome = extension::shares(item->data, shares);
		// Если разбор не состоялся
		if(outcome != extension::error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Выполняем сброс накопителя
		body.clear();
		// Выполняем составление перечня открытых частей ключей заново
		outcome = extension::shares(shares, body);
		// Если составление не состоялось
		if(outcome != extension::error_t::NONE)
			// Выводим отказ составления
			return outcome;
		// Запоминаем схождение составленного тела расширения с исходным
		intact = (intact && (body.size() == item->data.size) && (::memcmp(body.data(), item->data.data, item->data.size) == 0));
	}
	// Получаем расширение способов обмена ключами возобновления
	item = hello::extension(hello.extensions, 0x002D);
	// Если расширение способов обмена ключами возобновления есть
	if(item != nullptr){
		// Разобранный перечень способов обмена
		vector <extension::regime_t> modes;
		// Выполняем разбор перечня способов обмена
		outcome = extension::modes(item->data, modes);
		// Если разбор не состоялся
		if(outcome != extension::error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Выполняем сброс накопителя
		body.clear();
		// Выполняем составление перечня способов обмена заново
		outcome = extension::modes(modes, body);
		// Если составление не состоялось
		if(outcome != extension::error_t::NONE)
			// Выводим отказ составления
			return outcome;
		// Запоминаем схождение составленного тела расширения с исходным
		intact = (intact && (body.size() == item->data.size) && (::memcmp(body.data(), item->data.data, item->data.size) == 0));
	}
	// Выполняем сброс накопителя
	body.clear();
	// Выполняем составление перечня прикладных протоколов
	outcome = extension::protocols(names, body);
	// Если составление не состоялось
	if(outcome != extension::error_t::NONE)
		// Выводим отказ составления
		return outcome;
	// Разобранный перечень прикладных протоколов
	vector <string> protocols;
	// Выполняем разбор составленного перечня прикладных протоколов
	outcome = extension::protocols(view_t(body.data(), body.size()), protocols);
	// Если разбор не состоялся
	if(outcome != extension::error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Запоминаем схождение разобранного перечня прикладных протоколов с составленным
	intact = (intact && (protocols == names));
	// Выполняем сброс накопителя
	body.clear();
	// Выполняем составление выбранного прикладного протокола
	outcome = extension::protocol(names[0], body);
	// Если составление не состоялось
	if(outcome != extension::error_t::NONE)
		// Выводим отказ составления
		return outcome;
	// Разобранное имя выбранного прикладного протокола
	string protocol;
	// Выполняем разбор выбранного прикладного протокола
	outcome = extension::protocol(view_t(body.data(), body.size()), protocol);
	// Если разбор не состоялся
	if(outcome != extension::error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Запоминаем схождение разобранного названия прикладного протокола с составленным
	intact = (intact && (protocol == names[0]));
	// Выполняем сброс накопителя
	body.clear();
	// Выполняем составление предложения заранее разделённых ключей
	outcome = extension::identities(identities, binders, body);
	// Если составление не состоялось
	if(outcome != extension::error_t::NONE)
		// Выводим отказ составления
		return outcome;
	// Разбираемый перечень опознавателей ключей
	vector <extension::identity_t> parsed;
	// Разбираемый перечень привязок ключей
	vector <view_t> items;
	// Длина усечения приветствия от начала тела расширения
	size_t truncation = 0;
	// Выполняем разбор составленного предложения ключей
	outcome = extension::identities(view_t(body.data(), body.size()), parsed, items, truncation);
	// Если разбор не состоялся
	if(outcome != extension::error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Запоминаем схождение разобранного предложения ключей с составленным
	intact = (intact && (parsed.size() == identities.size()) && (items.size() == binders.size()) && (parsed[0].identity.size == identities[0].identity.size) && (items[0].size == binders[0].size));
	// Имя сервера длиною сверх короткого запаса строки
	const char * name = "very-long-server-name.example.com";
	// Выполняем сброс накопителя
	body.clear();
	// Выполняем составление имени сервера
	outcome = extension::name(view_t(reinterpret_cast <const uint8_t *> (name), ::strlen(name)), body);
	// Если составление не состоялось
	if(outcome != extension::error_t::NONE)
		// Выводим отказ составления
		return outcome;
	// Разобранное имя сервера
	view_t host;
	// Выполняем разбор составленного имени сервера
	outcome = extension::name(view_t(body.data(), body.size()), host);
	// Если разбор не состоялся
	if(outcome != extension::error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Запоминаем схождение разобранного имени сервера с составленным
	intact = (intact && (host.size == ::strlen(name)) && (::memcmp(host.data, name, host.size) == 0));
	// Выводим успешность разбора и составления
	return extension::error_t::NONE;
}

/**
 * Проверка разбора и составления расширений при нехватке памяти
 */
TEST(ExtensionTest, Starved){
	// Получаем сообщение приветствия клиента вместе с обвязкой
	const vector <uint8_t> message = decode(SAMPLES[0].message);
	// Получаем тело приветствия клиента
	const view_t body(message.data() + handshake::HANDSHAKE_HEADER, message.size() - handshake::HANDSHAKE_HEADER);
	// Разобранное приветствие клиента
	hello::client_t hello;
	// Выполняем разбор тела приветствия клиента
	ASSERT_EQ(hello::parse(body, hello), hello::error_t::NONE);
	// Имена прикладных протоколов длиною сверх короткого запаса строки
	const vector <string> names = {"application-protocol-name-first-of-all", "application-protocol-name-second-one"};
	// Опознаватель предлагаемого заранее разделённого ключа
	const uint8_t identity[4] = {0x01, 0x02, 0x03, 0x04};
	// Привязка предлагаемого заранее разделённого ключа
	const uint8_t binder[32] = {0};
	// Составляемый перечень опознавателей ключей
	const vector <extension::identity_t> identities = {extension::identity_t(view_t(identity, sizeof(identity)), 0x01020304)};
	// Составляемый перечень привязок ключей
	const vector <view_t> binders = {view_t(binder, sizeof(binder))};
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе разбор и составление
	 * обязаны ответить либо успехом, либо отказом памяти, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 256; budget++){
		// Итог разбора и составления при отмеренном запасе
		extension::error_t outcome = extension::error_t::NONE;
		// Признак схождения составленных тел с исходными
		bool intact = false;
		{
			// Отмеряем запас выделений на время разбора и составления
			starve::ration_t ration(budget);
			// Выполняем разбор и составление при отмеренном запасе
			outcome = exhaust(hello, names, identities, binders, intact);
		}
		// Проверяем, что разбор и составление ответили успехом либо отказом памяти
		ASSERT_TRUE((outcome == extension::error_t::NONE) || (outcome == extension::error_t::MEMORY)) << "запас " << budget << " отказ " << static_cast <int> (outcome);
		// Проверяем, что успех не скрывает усечённого нехваткой памяти тела
		ASSERT_TRUE((outcome != extension::error_t::NONE) || intact) << "запас " << budget;
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == extension::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}
