/**
 * @file session.cpp
 * @date 2026-08-30
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
 * @brief Исходный файл проверок модуля состояния связи протокола TLS 1.3
 *
 * @note Цепочка расписания ключей проходится целиком на настоящей связи приложения А
 *       описания наборов шифрования TLS 1.3 на алгоритмах ГОСТ: от приветствий сторон до
 *       ключей и векторов замены обоих направлений на обеих порах связи
 *
 * @note Хеш переписки не берётся из черновика, а вырабатывается из самих приветствий:
 *       сходится он с напечатанным там значением TH1
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
#include <session/session.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Приветствие клиента контрольного примера
 */
static const char * CLIENT = "010000DE03030303030303030303030303030303030303030303030303030303030303030303000002C105010000B3000A000400020028000D0010000E0709070A070B070C070D070E070F002B0003020304002D000201000033008600840028008005EEBDF3DDC1D2F5F3822433241284E77641487938EA88721F26203E9792B5CB97EB70EF02E8F72B7491D4F2CFDC332ADF7F1778E854A88DDC2113FEC527A15171A04CB0C573793A7AEF9BBCA486B6B046B2149B46F4332903E5B7C438ADD05E185EFBF45557475A8CCBF6ACED1A2EB416F916729D7CEF9CBD8334989304AFAE";

/**
 * Приветствие сервера контрольного примера
 */
static const char * SERVER = "020000B60303838383838383838383838383838383838383838383838383838383838383838300C10500008E002B0002030400330084002800802F3C663FE74735A1C421160DF0F43266185FD30B6E5D6E88FC4061FAEACAB338B10A1BD20CB0B4EE757E74A0027D409FE937F01633A1E3F9A5518DEFD0F89F9D3D9F6CC651413DEC2C74366D83C47EE1DE4E421F65CD1163E94EA0C2E19ED45D35558B937D9BFDC5ECC2B2A21B4EC3D53B29579A8FD5E074811028FBCF17994F";

/**
 * Общее значение обмена ключами контрольного примера
 */
static const char * SHARED = "4DE60D21EA8FB9220D146423B490DA40CCEBC43BC589DB79B831A47D6B063007DD03405A1B7976B623DCAA69B011AE106E7E4174385F8626E121B5994363C99F";

/**
 * Хеш переписки рукопожатия на миг вывода ключей рукопожатия
 */
static const char * FIRST = "993BA722124AF3CBFD4771E7FAE32AC1D0E9278CF7843FCBC620E1A0085A87A1";

/**
 * Хеш переписки рукопожатия на миг вывода ключей прикладных данных
 */
static const char * SECOND = "9EBC5FBE32D9F40D48F8EECEBB6231A533C2C0EF243277B96D6F7AD3BBFD1494";

/**
 * Значение рукопожатия направления связи от сервера
 */
static const char * SHTS = "70A5F2463DF60DBAA2368B67FD45AEFF7C1A0BA42D8ABD72415ECD1D94E9EF54";

/**
 * Значение рукопожатия направления связи от клиента
 */
static const char * CHTS = "B3F7113D3526554FE655E56FAB79B1A03DE33596E33088C7783719A9A4B0DCCD";

/**
 * Значение прикладных данных направления связи от сервера
 */
static const char * SATS = "87734F4B4CFD17B97B834D822D9D7379F6F5E03B80B52AEB2AFF510EDD83DBD2";

/**
 * Значение прикладных данных направления связи от клиента
 */
static const char * CATS = "8ACF746BEC31176CBD142C75806C270A0AEF6FC38E0D8FDCB5A88525363ADE81";

/**
 * Ключ направления связи от сервера на поре рукопожатия
 */
static const char * SERVER_KEY_HANDSHAKE = "E13764B54B9E1B47D43398D6D216DF24C289A396AB6C5B524BBB9C06F39FEF01";

/**
 * Вектор замены направления связи от сервера на поре рукопожатия
 */
static const char * SERVER_VECTOR_HANDSHAKE = "6969FFAAA4525281EEBBEB4CBD0B640E";

/**
 * Ключ направления связи от клиента на поре рукопожатия
 */
static const char * CLIENT_KEY_HANDSHAKE = "581688D76EFE122BB55F62B38EF01BCC8C88DB83E9EA4D55D3898C53721FC384";

/**
 * Вектор замены направления связи от клиента на поре рукопожатия
 */
static const char * CLIENT_VECTOR_HANDSHAKE = "439A07453D0BEA0C1D1BEB738EB5B8DD";

/**
 * Ключ направления связи от сервера на поре прикладных данных
 */
static const char * SERVER_KEY_APPLICATION = "475E4C514CC6318C3A5F000F1265BD1AB5F0DE1AF357ED0079EC5FF0AFBD030C";

/**
 * Вектор замены направления связи от сервера на поре прикладных данных
 */
static const char * SERVER_VECTOR_APPLICATION = "AFE91F7118354026317E1AB4D82217B8";

/**
 * Ключ направления связи от клиента на поре прикладных данных
 */
static const char * CLIENT_KEY_APPLICATION = "7BE64E2C12787B5B8C8756C43D92FAEF64F15A3A3C1081AD34BCA506F0322415";

/**
 * Вектор замены направления связи от клиента на поре прикладных данных
 */
static const char * CLIENT_VECTOR_APPLICATION = "310957EF71314433F576CC9B00AD9354";

/**
 * Ключ завершения рукопожатия сервером
 */
static const char * SERVER_FINISHED = "53F1C0388F8A70C0BCA0DD21A030F2381C3437CD0E7EC93D0A965E25632DD79A";

/**
 * Ключ завершения рукопожатия клиентом
 */
static const char * CLIENT_FINISHED = "2F21548CF5277869AE490DE7BC15ACE639F657E3582A5A634B0A915695D54C42";

/**
 * Набор шифрования контрольного примера
 */
static const protect::suite_t SUITE = protect::suite_t::KUZNYECHIK_MGM_S;

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
 * Проверка выработки хеша переписки рукопожатия
 */
TEST(SessionTest, Transcript){
	// Объект переписки рукопожатия
	session::transcript_t transcript;
	// Выполняем начало переписки рукопожатия
	transcript.start();
	// Получаем приветствие клиента контрольного примера
	const vector <uint8_t> client = decode(CLIENT);
	// Получаем приветствие сервера контрольного примера
	const vector <uint8_t> server = decode(SERVER);
	// Выполняем добавление приветствия клиента в переписку
	ASSERT_EQ(transcript.update(view_t(client.data(), client.size())), session::error_t::NONE);
	// Выполняем добавление приветствия сервера в переписку
	ASSERT_EQ(transcript.update(view_t(server.data(), server.size())), session::error_t::NONE);
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t result[32];
	// Выполняем получение хеша переписки рукопожатия
	ASSERT_EQ(transcript.digest(result), session::error_t::NONE);
	// Получаем хеш переписки рукопожатия контрольного примера
	const vector <uint8_t> sample = decode(FIRST);
	// Проверяем схождение выработанного хеша переписки с контрольным примером
	ASSERT_EQ(::memcmp(result, sample.data(), sample.size()), 0);
	/**
	 * Хеш берётся со снимка состояния: переписка им не закрывается, и повторный вызов
	 * обязан выдать то же самое значение
	 */
	ASSERT_EQ(transcript.digest(result), session::error_t::NONE);
	// Проверяем схождение повторно выработанного хеша с контрольным примером
	ASSERT_EQ(::memcmp(result, sample.data(), sample.size()), 0);
	// Проверяем отказ добавления пустого сообщения в переписку
	ASSERT_EQ(transcript.update(view_t(nullptr, 0)), session::error_t::EMPTY);
}

/**
 * Проверка замены накопленной переписки её хешем
 */
TEST(SessionTest, Replace){
	// Объект переписки рукопожатия
	session::transcript_t transcript;
	// Выполняем начало переписки рукопожатия
	transcript.start();
	// Получаем приветствие клиента контрольного примера
	const vector <uint8_t> client = decode(CLIENT);
	// Выполняем добавление приветствия клиента в переписку
	transcript.update(view_t(client.data(), client.size()));
	// Место, в которое помещается хеш приветствия клиента
	uint8_t digest[32];
	// Выполняем получение хеша приветствия клиента
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Выполняем замену накопленной переписки её хешем
	ASSERT_EQ(transcript.replace(), session::error_t::NONE);
	// Место, в которое помещается хеш укороченной переписки
	uint8_t result[32];
	// Выполняем получение хеша укороченной переписки
	ASSERT_EQ(transcript.digest(result), session::error_t::NONE);
	// Особое сообщение, несущее хеш приветствия клиента
	vector <uint8_t> message = {0xFE, 0x00, 0x00, 0x20};
	// Дописываем хеш приветствия клиента в особое сообщение
	message.insert(message.end(), digest, digest + sizeof(digest));
	// Место, в которое помещается ожидаемый хеш укороченной переписки
	uint8_t sample[32];
	// Выполняем выработку ожидаемого хеша укороченной переписки
	ASSERT_TRUE(digest::streebog(digest::type_t::SHORT, view_t(message.data(), message.size()), sample, sizeof(sample)));
	// Проверяем схождение хеша укороченной переписки с ожидаемым
	ASSERT_EQ(::memcmp(result, sample, sizeof(sample)), 0);
	// Проверяем расхождение хеша укороченной переписки с хешем приветствия
	ASSERT_NE(::memcmp(result, digest, sizeof(digest)), 0);
}

/**
 * Проверка прохождения цепочки расписания ключей связи
 */
TEST(SessionTest, Schedule){
	// Объект значений расписания ключей связи
	session::secrets_t secrets;
	// Проверяем, что расписание ключей ещё не начато
	ASSERT_EQ(secrets.stage(), session::stage_t::NONE);
	// Получаем общее значение обмена ключами контрольного примера
	const vector <uint8_t> shared = decode(SHARED);
	// Получаем хеш переписки на миг вывода ключей рукопожатия
	const vector <uint8_t> first = decode(FIRST);
	/**
	 * Ступени расписания проходятся только по порядку: вывод ступени рукопожатия до
	 * заведения начальной ступени обязан быть отвергнут
	 */
	ASSERT_EQ(secrets.handshake(view_t(shared.data(), shared.size()), view_t(first.data(), first.size())), session::error_t::STATE);
	/**
	 * Выполняем заведение начальной ступени расписания ключей
	 *
	 * @note Заранее разделённого ключа у связи контрольного примера нет, и на его место
	 *       идут нули длиною в хеш
	 */
	ASSERT_EQ(secrets.start(view_t(nullptr, 0)), session::error_t::NONE);
	// Проверяем пройденную ступень расписания ключей
	ASSERT_EQ(secrets.stage(), session::stage_t::EARLY);
	// Проверяем отказ вывода ступени прикладных данных не в свой черёд
	ASSERT_EQ(secrets.application(view_t(first.data(), first.size())), session::error_t::STATE);
	// Выполняем вывод ступени рукопожатия расписания ключей
	ASSERT_EQ(secrets.handshake(view_t(shared.data(), shared.size()), view_t(first.data(), first.size())), session::error_t::NONE);
	// Проверяем пройденную ступень расписания ключей
	ASSERT_EQ(secrets.stage(), session::stage_t::HANDSHAKE);
	// Место, в которое помещается значение направления связи
	uint8_t traffic[32];
	// Выполняем получение значения направления связи от сервера
	ASSERT_EQ(secrets.traffic(session::side_t::SERVER, traffic), session::error_t::NONE);
	// Получаем значение рукопожатия направления связи от сервера
	const vector <uint8_t> shts = decode(SHTS);
	// Проверяем схождение значения направления связи от сервера
	ASSERT_EQ(::memcmp(traffic, shts.data(), shts.size()), 0);
	// Выполняем получение значения направления связи от клиента
	ASSERT_EQ(secrets.traffic(session::side_t::CLIENT, traffic), session::error_t::NONE);
	// Получаем значение рукопожатия направления связи от клиента
	const vector <uint8_t> chts = decode(CHTS);
	// Проверяем схождение значения направления связи от клиента
	ASSERT_EQ(::memcmp(traffic, chts.data(), chts.size()), 0);
	// Место, в которое помещается корневой ключ направления связи
	uint8_t key[protect::PROTECT_KEY];
	// Место, в которое помещается вектор замены направления связи
	uint8_t replacement[protect::PROTECT_VECTOR];
	// Выполняем вывод ключевого материала направления связи от сервера
	ASSERT_EQ(secrets.material(session::side_t::SERVER, SUITE, key, replacement), session::error_t::NONE);
	// Получаем ключ направления связи от сервера на поре рукопожатия
	const vector <uint8_t> serverKey = decode(SERVER_KEY_HANDSHAKE);
	// Проверяем схождение ключа направления связи от сервера
	ASSERT_EQ(::memcmp(key, serverKey.data(), serverKey.size()), 0);
	// Получаем вектор замены направления связи от сервера на поре рукопожатия
	const vector <uint8_t> serverVector = decode(SERVER_VECTOR_HANDSHAKE);
	// Проверяем схождение вектора замены направления связи от сервера
	ASSERT_EQ(::memcmp(replacement, serverVector.data(), serverVector.size()), 0);
	// Выполняем вывод ключевого материала направления связи от клиента
	ASSERT_EQ(secrets.material(session::side_t::CLIENT, SUITE, key, replacement), session::error_t::NONE);
	// Получаем ключ направления связи от клиента на поре рукопожатия
	const vector <uint8_t> clientKey = decode(CLIENT_KEY_HANDSHAKE);
	// Проверяем схождение ключа направления связи от клиента
	ASSERT_EQ(::memcmp(key, clientKey.data(), clientKey.size()), 0);
	// Получаем вектор замены направления связи от клиента на поре рукопожатия
	const vector <uint8_t> clientVector = decode(CLIENT_VECTOR_HANDSHAKE);
	// Проверяем схождение вектора замены направления связи от клиента
	ASSERT_EQ(::memcmp(replacement, clientVector.data(), clientVector.size()), 0);
	// Место, в которое помещается ключ завершения рукопожатия
	uint8_t finished[32];
	// Выполняем вывод ключа завершения рукопожатия сервером
	ASSERT_EQ(secrets.finished(session::side_t::SERVER, finished), session::error_t::NONE);
	// Получаем ключ завершения рукопожатия сервером
	const vector <uint8_t> serverFinished = decode(SERVER_FINISHED);
	// Проверяем схождение ключа завершения рукопожатия сервером
	ASSERT_EQ(::memcmp(finished, serverFinished.data(), serverFinished.size()), 0);
	// Выполняем вывод ключа завершения рукопожатия клиентом
	ASSERT_EQ(secrets.finished(session::side_t::CLIENT, finished), session::error_t::NONE);
	// Получаем ключ завершения рукопожатия клиентом
	const vector <uint8_t> clientFinished = decode(CLIENT_FINISHED);
	// Проверяем схождение ключа завершения рукопожатия клиентом
	ASSERT_EQ(::memcmp(finished, clientFinished.data(), clientFinished.size()), 0);
	// Получаем хеш переписки на миг вывода ключей прикладных данных
	const vector <uint8_t> second = decode(SECOND);
	// Выполняем вывод ступени прикладных данных расписания ключей
	ASSERT_EQ(secrets.application(view_t(second.data(), second.size())), session::error_t::NONE);
	// Проверяем пройденную ступень расписания ключей
	ASSERT_EQ(secrets.stage(), session::stage_t::APPLICATION);
	// Выполняем получение значения направления связи от сервера
	ASSERT_EQ(secrets.traffic(session::side_t::SERVER, traffic), session::error_t::NONE);
	// Получаем значение прикладных данных направления связи от сервера
	const vector <uint8_t> sats = decode(SATS);
	// Проверяем схождение значения направления связи от сервера
	ASSERT_EQ(::memcmp(traffic, sats.data(), sats.size()), 0);
	// Выполняем получение значения направления связи от клиента
	ASSERT_EQ(secrets.traffic(session::side_t::CLIENT, traffic), session::error_t::NONE);
	// Получаем значение прикладных данных направления связи от клиента
	const vector <uint8_t> cats = decode(CATS);
	// Проверяем схождение значения направления связи от клиента
	ASSERT_EQ(::memcmp(traffic, cats.data(), cats.size()), 0);
	// Выполняем вывод ключевого материала направления связи от сервера
	ASSERT_EQ(secrets.material(session::side_t::SERVER, SUITE, key, replacement), session::error_t::NONE);
	// Получаем ключ направления связи от сервера на поре прикладных данных
	const vector <uint8_t> serverApplication = decode(SERVER_KEY_APPLICATION);
	// Проверяем схождение ключа направления связи от сервера
	ASSERT_EQ(::memcmp(key, serverApplication.data(), serverApplication.size()), 0);
	// Получаем вектор замены направления связи от сервера на поре прикладных данных
	const vector <uint8_t> serverReplacement = decode(SERVER_VECTOR_APPLICATION);
	// Проверяем схождение вектора замены направления связи от сервера
	ASSERT_EQ(::memcmp(replacement, serverReplacement.data(), serverReplacement.size()), 0);
	// Выполняем вывод ключевого материала направления связи от клиента
	ASSERT_EQ(secrets.material(session::side_t::CLIENT, SUITE, key, replacement), session::error_t::NONE);
	// Получаем ключ направления связи от клиента на поре прикладных данных
	const vector <uint8_t> clientApplication = decode(CLIENT_KEY_APPLICATION);
	// Проверяем схождение ключа направления связи от клиента
	ASSERT_EQ(::memcmp(key, clientApplication.data(), clientApplication.size()), 0);
	// Получаем вектор замены направления связи от клиента на поре прикладных данных
	const vector <uint8_t> clientReplacement = decode(CLIENT_VECTOR_APPLICATION);
	// Проверяем схождение вектора замены направления связи от клиента
	ASSERT_EQ(::memcmp(replacement, clientReplacement.data(), clientReplacement.size()), 0);
	// Проверяем отказ вывода ключевого материала неизвестного набора шифрования
	ASSERT_EQ(secrets.material(session::side_t::CLIENT, protect::suite_t::NONE, key, replacement), session::error_t::SUITE);
	// Выполняем сброс значений расписания ключей
	secrets.clear();
	// Проверяем сброс пройденной ступени расписания ключей
	ASSERT_EQ(secrets.stage(), session::stage_t::NONE);
	// Проверяем отказ получения значения направления связи после сброса
	ASSERT_EQ(secrets.traffic(session::side_t::CLIENT, traffic), session::error_t::STATE);
}

/**
 * Проверка связывания ключей связи с перепиской рукопожатия
 */
TEST(SessionTest, Binding){
	// Объект переписки рукопожатия
	session::transcript_t transcript;
	// Выполняем начало переписки рукопожатия
	transcript.start();
	// Получаем приветствие клиента контрольного примера
	vector <uint8_t> client = decode(CLIENT);
	// Получаем приветствие сервера контрольного примера
	const vector <uint8_t> server = decode(SERVER);
	// Портим один байт случайного значения приветствия клиента
	client[10] = static_cast <uint8_t> (client[10] ^ 0x01);
	// Выполняем добавление подменённого приветствия клиента в переписку
	transcript.update(view_t(client.data(), client.size()));
	// Выполняем добавление приветствия сервера в переписку
	transcript.update(view_t(server.data(), server.size()));
	// Место, в которое помещается хеш подменённой переписки
	uint8_t digest[32];
	// Выполняем получение хеша подменённой переписки рукопожатия
	ASSERT_EQ(transcript.digest(digest), session::error_t::NONE);
	// Получаем хеш переписки рукопожатия контрольного примера
	const vector <uint8_t> sample = decode(FIRST);
	// Проверяем расхождение хеша подменённой переписки с контрольным примером
	ASSERT_NE(::memcmp(digest, sample.data(), sample.size()), 0);
	// Объект значений расписания ключей связи
	session::secrets_t secrets;
	// Выполняем заведение начальной ступени расписания ключей
	secrets.start(view_t(nullptr, 0));
	// Получаем общее значение обмена ключами контрольного примера
	const vector <uint8_t> shared = decode(SHARED);
	// Выполняем вывод ступени рукопожатия на подменённой переписке
	ASSERT_EQ(secrets.handshake(view_t(shared.data(), shared.size()), view_t(digest, sizeof(digest))), session::error_t::NONE);
	// Место, в которое помещается значение направления связи
	uint8_t traffic[32];
	// Выполняем получение значения направления связи от сервера
	secrets.traffic(session::side_t::SERVER, traffic);
	// Получаем значение рукопожатия направления связи от сервера
	const vector <uint8_t> shts = decode(SHTS);
	/**
	 * Подмена одного байта приветствия уводит ключи связи целиком: хеш переписки входит
	 * в вывод всякого ключа, и совпасть они уже не могут
	 */
	ASSERT_NE(::memcmp(traffic, shts.data(), shts.size()), 0);
}

/**
 * Проверка смены значения направления связи
 */
TEST(SessionTest, Renew){
	// Значения расписания ключей связи
	session::secrets_t secrets;
	// Проверяем отказ смены значения до заведения расписания ключей
	ASSERT_EQ(secrets.renew(session::side_t::CLIENT), session::error_t::STATE);
	// Выполняем заведение начальной ступени расписания ключей
	ASSERT_EQ(secrets.start(view_t(nullptr, 0)), session::error_t::NONE);
	// Общее значение обмена ключами связи
	uint8_t shared[32];
	// Выполняем заполнение общего значения обмена ключами
	::memset(shared, 0x5A, sizeof(shared));
	// Хеш переписки рукопожатия связи
	uint8_t transcript[32];
	// Выполняем заполнение хеша переписки рукопожатия
	::memset(transcript, 0xA5, sizeof(transcript));
	// Выполняем вывод ступени рукопожатия расписания ключей
	ASSERT_EQ(secrets.handshake(view_t(shared, sizeof(shared)), view_t(transcript, sizeof(transcript))), session::error_t::NONE);
	// Проверяем отказ смены значения на ступени рукопожатия
	ASSERT_EQ(secrets.renew(session::side_t::CLIENT), session::error_t::STATE);
	// Выполняем вывод ступени прикладных данных расписания ключей
	ASSERT_EQ(secrets.application(view_t(transcript, sizeof(transcript))), session::error_t::NONE);
	// Значения направлений связи до смены
	uint8_t first[32], second[32];
	// Выполняем получение значения направления связи от клиента
	ASSERT_EQ(secrets.traffic(session::side_t::CLIENT, first), session::error_t::NONE);
	// Выполняем получение значения направления связи от сервера
	ASSERT_EQ(secrets.traffic(session::side_t::SERVER, second), session::error_t::NONE);
	// Выполняем смену значения направления связи от клиента
	ASSERT_EQ(secrets.renew(session::side_t::CLIENT), session::error_t::NONE);
	// Значения направлений связи после смены
	uint8_t third[32], fourth[32];
	// Выполняем получение значения направления связи от клиента
	ASSERT_EQ(secrets.traffic(session::side_t::CLIENT, third), session::error_t::NONE);
	// Выполняем получение значения направления связи от сервера
	ASSERT_EQ(secrets.traffic(session::side_t::SERVER, fourth), session::error_t::NONE);
	// Проверяем смену значения направления связи от клиента
	ASSERT_NE(::memcmp(first, third, sizeof(first)), 0);
	// Проверяем сохранность значения направления связи от сервера
	ASSERT_EQ(::memcmp(second, fourth, sizeof(second)), 0);
	// Выполняем повторную смену значения направления связи от клиента
	ASSERT_EQ(secrets.renew(session::side_t::CLIENT), session::error_t::NONE);
	// Выполняем получение значения направления связи от клиента
	ASSERT_EQ(secrets.traffic(session::side_t::CLIENT, fourth), session::error_t::NONE);
	// Проверяем смену значения направления связи повторно
	ASSERT_NE(::memcmp(third, fourth, sizeof(third)), 0);
}

/**
 * Проверка вывода ключей билетов возобновления связи
 */
TEST(SessionTest, Resumption){
	// Значения расписания ключей связи
	session::secrets_t secrets;
	// Неповторимые значения билетов возобновления связи
	const uint8_t first[4] = {0x00, 0x00, 0x00, 0x00}, second[4] = {0x00, 0x00, 0x00, 0x01};
	// Место, в которое помещается ключ билета возобновления связи
	uint8_t key[32];
	// Проверяем отказ вывода ключа билета до заведения расписания ключей
	ASSERT_EQ(secrets.ticket(view_t(first, sizeof(first)), key), session::error_t::STATE);
	// Выполняем заведение начальной ступени расписания ключей
	ASSERT_EQ(secrets.start(view_t(nullptr, 0)), session::error_t::NONE);
	// Общее значение обмена ключами связи
	uint8_t shared[32];
	// Выполняем заполнение общего значения обмена ключами
	::memset(shared, 0x3C, sizeof(shared));
	// Хеш переписки рукопожатия связи
	uint8_t transcript[32];
	// Выполняем заполнение хеша переписки рукопожатия
	::memset(transcript, 0xC3, sizeof(transcript));
	// Выполняем вывод ступени рукопожатия расписания ключей
	ASSERT_EQ(secrets.handshake(view_t(shared, sizeof(shared)), view_t(transcript, sizeof(transcript))), session::error_t::NONE);
	// Проверяем отказ вывода значения возобновления на ступени рукопожатия
	ASSERT_EQ(secrets.resumption(view_t(transcript, sizeof(transcript))), session::error_t::STATE);
	// Выполняем вывод ступени прикладных данных расписания ключей
	ASSERT_EQ(secrets.application(view_t(transcript, sizeof(transcript))), session::error_t::NONE);
	// Выполняем вывод значения возобновления связи
	ASSERT_EQ(secrets.resumption(view_t(transcript, sizeof(transcript))), session::error_t::NONE);
	// Выполняем вывод ключа первого билета возобновления связи
	ASSERT_EQ(secrets.ticket(view_t(first, sizeof(first)), key), session::error_t::NONE);
	// Место, в которое помещается ключ второго билета
	uint8_t element[32];
	// Выполняем вывод ключа второго билета возобновления связи
	ASSERT_EQ(secrets.ticket(view_t(second, sizeof(second)), element), session::error_t::NONE);
	/**
	 * Ключи билетов расходятся неповторимым значением билета: без него все билеты
	 * одной связи вышли бы одинаковыми
	 */
	ASSERT_NE(::memcmp(key, element, sizeof(key)), 0);
	// Место, в которое помещается ключ билета, выведенный повторно
	uint8_t repeated[32];
	// Выполняем повторный вывод ключа первого билета
	ASSERT_EQ(secrets.ticket(view_t(first, sizeof(first)), repeated), session::error_t::NONE);
	// Проверяем повторимость вывода ключа билета возобновления связи
	ASSERT_EQ(::memcmp(key, repeated, sizeof(key)), 0);
}

/**
 * Проверка выработки привязки заранее разделённого ключа
 */
TEST(SessionTest, Binder){
	// Значения расписания ключей связи
	session::secrets_t secrets;
	// Хеш усечённого приветствия клиента
	uint8_t transcript[32];
	// Выполняем заполнение хеша усечённого приветствия
	::memset(transcript, 0x7E, sizeof(transcript));
	// Место, в которое помещается привязка заранее разделённого ключа
	uint8_t binder[32];
	// Проверяем отказ выработки привязки до заведения расписания ключей
	ASSERT_EQ(secrets.binder(view_t(transcript, sizeof(transcript)), binder), session::error_t::STATE);
	// Заранее разделённый ключ связи
	uint8_t secret[32];
	// Выполняем заполнение заранее разделённого ключа
	::memset(secret, 0x1F, sizeof(secret));
	// Выполняем заведение начальной ступени расписания ключей
	ASSERT_EQ(secrets.start(view_t(secret, sizeof(secret))), session::error_t::NONE);
	// Выполняем выработку привязки заранее разделённого ключа
	ASSERT_EQ(secrets.binder(view_t(transcript, sizeof(transcript)), binder), session::error_t::NONE);
	// Значения расписания ключей встречной стороны связи
	session::secrets_t opposite;
	// Выполняем заведение начальной ступени расписания ключей
	ASSERT_EQ(opposite.start(view_t(secret, sizeof(secret))), session::error_t::NONE);
	// Место, в которое помещается привязка встречной стороны
	uint8_t element[32];
	// Выполняем выработку привязки встречной стороной связи
	ASSERT_EQ(opposite.binder(view_t(transcript, sizeof(transcript)), element), session::error_t::NONE);
	// Проверяем схождение привязок сторон связи
	ASSERT_EQ(::memcmp(binder, element, sizeof(binder)), 0);
	// Значения расписания ключей с иным заранее разделённым ключом
	session::secrets_t alien;
	// Портим заранее разделённый ключ связи
	secret[0] ^= 0x01;
	// Выполняем заведение начальной ступени расписания ключей
	ASSERT_EQ(alien.start(view_t(secret, sizeof(secret))), session::error_t::NONE);
	// Выполняем выработку привязки на ином заранее разделённом ключе
	ASSERT_EQ(alien.binder(view_t(transcript, sizeof(transcript)), element), session::error_t::NONE);
	// Проверяем расхождение привязок при ином заранее разделённом ключе
	ASSERT_NE(::memcmp(binder, element, sizeof(binder)), 0);
	// Портим хеш усечённого приветствия клиента
	transcript[0] ^= 0x01;
	// Выполняем выработку привязки по иному усечённому приветствию
	ASSERT_EQ(secrets.binder(view_t(transcript, sizeof(transcript)), element), session::error_t::NONE);
	// Проверяем расхождение привязок при ином усечённом приветствии
	ASSERT_NE(::memcmp(binder, element, sizeof(binder)), 0);
}
