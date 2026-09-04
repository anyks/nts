/**
 * @file flow.cpp
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
 * @brief Исходный файл проверок модуля хода рукопожатия протокола TLS 1.3
 *
 * @note Проверяются все четыре хода, дозволенные протоколом: полное рукопожатие с
 *       подлинностью сервера, рукопожатие на заранее разделённом ключе, рукопожатие со
 *       встречной подлинностью клиента и рукопожатие с просьбой о повторе приветствия
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <flow/flow.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Проверка полного рукопожатия с подлинностью сервера
 */
TEST(FlowTest, Complete){
	// Объект хода рукопожатия связи
	flow::machine_t machine;
	// Выполняем заведение хода рукопожатия клиентом
	ASSERT_TRUE(machine.start(flow::role_t::CLIENT));
	// Проверяем роль стороны, ведущей ход рукопожатия
	ASSERT_EQ(machine.role(), flow::role_t::CLIENT);
	// Проверяем ожидание приветствия клиента
	ASSERT_EQ(machine.stage(), flow::stage_t::GREETING);
	// Проверяем, что записи клиента до приветствия идут без защиты
	ASSERT_EQ(machine.epoch(session::side_t::CLIENT), flow::epoch_t::PLAIN);
	// Объявляем приветствие клиента
	ASSERT_EQ(machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT), flow::error_t::NONE);
	// Проверяем, что записи клиента защиты ещё не получили
	ASSERT_EQ(machine.epoch(session::side_t::CLIENT), flow::epoch_t::PLAIN);
	// Объявляем приветствие сервера
	ASSERT_EQ(machine.accept(handshake::type_t::SERVER, session::side_t::SERVER), flow::error_t::NONE);
	// Проверяем переход записей клиента к ключам рукопожатия
	ASSERT_EQ(machine.epoch(session::side_t::CLIENT), flow::epoch_t::HANDSHAKE);
	// Проверяем переход записей сервера к ключам рукопожатия
	ASSERT_EQ(machine.epoch(session::side_t::SERVER), flow::epoch_t::HANDSHAKE);
	// Объявляем защищённые расширения сервера
	ASSERT_EQ(machine.accept(handshake::type_t::EXTENSIONS, session::side_t::SERVER), flow::error_t::NONE);
	// Объявляем цепочку сертификатов сервера
	ASSERT_EQ(machine.accept(handshake::type_t::CERTIFICATE, session::side_t::SERVER), flow::error_t::NONE);
	// Объявляем подпись владения ключом сервера
	ASSERT_EQ(machine.accept(handshake::type_t::VERIFY, session::side_t::SERVER), flow::error_t::NONE);
	// Объявляем завершение рукопожатия сервером
	ASSERT_EQ(machine.accept(handshake::type_t::FINISHED, session::side_t::SERVER), flow::error_t::NONE);
	// Проверяем переход записей сервера к ключам прикладных данных
	ASSERT_EQ(machine.epoch(session::side_t::SERVER), flow::epoch_t::APPLICATION);
	/**
	 * Записи клиента на этот миг всё ещё защищены ключами рукопожатия: сервер уже вправе
	 * слать прикладные данные, а клиент рукопожатие ещё договаривает
	 */
	ASSERT_EQ(machine.epoch(session::side_t::CLIENT), flow::epoch_t::HANDSHAKE);
	// Проверяем, что рукопожатие ещё не завершено
	ASSERT_FALSE(machine.established());
	// Объявляем завершение рукопожатия клиентом
	ASSERT_EQ(machine.accept(handshake::type_t::FINISHED, session::side_t::CLIENT), flow::error_t::NONE);
	// Проверяем завершённость рукопожатия
	ASSERT_TRUE(machine.established());
	// Проверяем переход записей клиента к ключам прикладных данных
	ASSERT_EQ(machine.epoch(session::side_t::CLIENT), flow::epoch_t::APPLICATION);
	// Проверяем, что подлинность клиента не подтверждалась
	ASSERT_FALSE(machine.certified());
	// Объявляем билет на возобновление связи
	ASSERT_EQ(machine.accept(handshake::type_t::TICKET, session::side_t::SERVER), flow::error_t::NONE);
	// Объявляем смену ключевого материала клиентом
	ASSERT_EQ(machine.accept(handshake::type_t::UPDATE, session::side_t::CLIENT), flow::error_t::NONE);
	// Проверяем, что связь по-прежнему установлена
	ASSERT_TRUE(machine.established());
}

/**
 * Проверка рукопожатия на заранее разделённом ключе
 */
TEST(FlowTest, Shared){
	// Объект хода рукопожатия связи
	flow::machine_t machine;
	// Выполняем заведение хода рукопожатия сервером
	ASSERT_TRUE(machine.start(flow::role_t::SERVER));
	// Объявляем приветствие клиента
	ASSERT_EQ(machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT), flow::error_t::NONE);
	// Объявляем приветствие сервера
	ASSERT_EQ(machine.accept(handshake::type_t::SERVER, session::side_t::SERVER), flow::error_t::NONE);
	// Объявляем защищённые расширения сервера
	ASSERT_EQ(machine.accept(handshake::type_t::EXTENSIONS, session::side_t::SERVER), flow::error_t::NONE);
	/**
	 * Связь на заранее разделённом ключе сертификатов не несёт вовсе: сервер переходит
	 * от расширений сразу к завершению рукопожатия
	 */
	ASSERT_EQ(machine.accept(handshake::type_t::FINISHED, session::side_t::SERVER), flow::error_t::NONE);
	// Проверяем переход записей сервера к ключам прикладных данных
	ASSERT_EQ(machine.epoch(session::side_t::SERVER), flow::epoch_t::APPLICATION);
	// Объявляем завершение рукопожатия клиентом
	ASSERT_EQ(machine.accept(handshake::type_t::FINISHED, session::side_t::CLIENT), flow::error_t::NONE);
	// Проверяем завершённость рукопожатия
	ASSERT_TRUE(machine.established());
}

/**
 * Проверка рукопожатия со встречной подлинностью клиента
 */
TEST(FlowTest, Mutual){
	// Объект хода рукопожатия связи
	flow::machine_t machine;
	// Выполняем заведение хода рукопожатия сервером
	ASSERT_TRUE(machine.start(flow::role_t::SERVER));
	// Объявляем приветствие клиента
	machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT);
	// Объявляем приветствие сервера
	machine.accept(handshake::type_t::SERVER, session::side_t::SERVER);
	// Объявляем защищённые расширения сервера
	machine.accept(handshake::type_t::EXTENSIONS, session::side_t::SERVER);
	// Объявляем запрос сертификата клиента
	ASSERT_EQ(machine.accept(handshake::type_t::REQUEST, session::side_t::SERVER), flow::error_t::NONE);
	// Объявляем цепочку сертификатов сервера
	ASSERT_EQ(machine.accept(handshake::type_t::CERTIFICATE, session::side_t::SERVER), flow::error_t::NONE);
	// Объявляем подпись владения ключом сервера
	ASSERT_EQ(machine.accept(handshake::type_t::VERIFY, session::side_t::SERVER), flow::error_t::NONE);
	// Объявляем завершение рукопожатия сервером
	ASSERT_EQ(machine.accept(handshake::type_t::FINISHED, session::side_t::SERVER), flow::error_t::NONE);
	// Проверяем ожидание ответа клиента на запрос сертификата
	ASSERT_EQ(machine.stage(), flow::stage_t::ANSWERING);
	// Объявляем цепочку сертификатов клиента
	ASSERT_EQ(machine.accept(handshake::type_t::CERTIFICATE, session::side_t::CLIENT), flow::error_t::NONE);
	// Объявляем подпись владения ключом клиента
	ASSERT_EQ(machine.accept(handshake::type_t::VERIFY, session::side_t::CLIENT), flow::error_t::NONE);
	// Проверяем, что клиент подтвердил подлинность
	ASSERT_TRUE(machine.certified());
	// Объявляем завершение рукопожатия клиентом
	ASSERT_EQ(machine.accept(handshake::type_t::FINISHED, session::side_t::CLIENT), flow::error_t::NONE);
	// Проверяем завершённость рукопожатия
	ASSERT_TRUE(machine.established());
	// Объект хода рукопожатия с пустой цепочкой клиента
	flow::machine_t empty;
	// Выполняем заведение хода рукопожатия сервером
	empty.start(flow::role_t::SERVER);
	// Объявляем приветствие клиента
	empty.accept(handshake::type_t::CLIENT, session::side_t::CLIENT);
	// Объявляем приветствие сервера
	empty.accept(handshake::type_t::SERVER, session::side_t::SERVER);
	// Объявляем защищённые расширения сервера
	empty.accept(handshake::type_t::EXTENSIONS, session::side_t::SERVER);
	// Объявляем запрос сертификата клиента
	empty.accept(handshake::type_t::REQUEST, session::side_t::SERVER);
	// Объявляем цепочку сертификатов сервера
	empty.accept(handshake::type_t::CERTIFICATE, session::side_t::SERVER);
	// Объявляем подпись владения ключом сервера
	empty.accept(handshake::type_t::VERIFY, session::side_t::SERVER);
	// Объявляем завершение рукопожатия сервером
	empty.accept(handshake::type_t::FINISHED, session::side_t::SERVER);
	// Объявляем пустую цепочку сертификатов клиента
	ASSERT_EQ(empty.accept(handshake::type_t::CERTIFICATE, session::side_t::CLIENT), flow::error_t::NONE);
	/**
	 * Клиент, у которого годного сертификата нет, шлёт пустую цепочку и подписи владения
	 * ключом за нею не шлёт вовсе
	 */
	ASSERT_EQ(empty.accept(handshake::type_t::FINISHED, session::side_t::CLIENT), flow::error_t::NONE);
	// Проверяем завершённость рукопожатия
	ASSERT_TRUE(empty.established());
	// Проверяем, что подлинность клиента подтверждённой не считается
	ASSERT_FALSE(empty.certified());
}

/**
 * Проверка рукопожатия с просьбой о повторе приветствия
 */
TEST(FlowTest, Retry){
	// Объект хода рукопожатия связи
	flow::machine_t machine;
	// Выполняем заведение хода рукопожатия клиентом
	ASSERT_TRUE(machine.start(flow::role_t::CLIENT));
	// Объявляем приветствие клиента
	machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT);
	// Объявляем приветствие сервера
	machine.accept(handshake::type_t::SERVER, session::side_t::SERVER);
	// Объявляем просьбу о повторе приветствия клиента
	ASSERT_EQ(machine.retry(), flow::error_t::NONE);
	// Проверяем возврат к ожиданию приветствия клиента
	ASSERT_EQ(machine.stage(), flow::stage_t::GREETING);
	/**
	 * Просьбою о повторе приветствия обмен ключами отменён, и записи обеих сторон
	 * возвращаются к поре отсутствия защиты
	 */
	ASSERT_EQ(machine.epoch(session::side_t::CLIENT), flow::epoch_t::PLAIN);
	// Проверяем возврат записей сервера к поре отсутствия защиты
	ASSERT_EQ(machine.epoch(session::side_t::SERVER), flow::epoch_t::PLAIN);
	// Объявляем повторное приветствие клиента
	ASSERT_EQ(machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT), flow::error_t::NONE);
	// Объявляем приветствие сервера
	ASSERT_EQ(machine.accept(handshake::type_t::SERVER, session::side_t::SERVER), flow::error_t::NONE);
	// Проверяем отвержение повторной просьбы о повторе приветствия
	ASSERT_EQ(machine.retry(), flow::error_t::REPEAT);
	// Проверяем прерывание хода рукопожатия отказом
	ASSERT_EQ(machine.stage(), flow::stage_t::FAILED);
}

/**
 * Проверка отвержения сообщений не в свой черёд
 */
TEST(FlowTest, Reject){
	// Объект хода рукопожатия связи
	flow::machine_t machine;
	// Проверяем отказ объявления сообщения незаведённому ходу рукопожатия
	ASSERT_EQ(machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT), flow::error_t::STATE);
	// Проверяем отказ заведения хода рукопожатия без роли стороны
	ASSERT_FALSE(machine.start(flow::role_t::NONE));
	// Выполняем заведение хода рукопожатия клиентом
	ASSERT_TRUE(machine.start(flow::role_t::CLIENT));
	// Проверяем отвержение приветствия сервера до приветствия клиента
	ASSERT_EQ(machine.accept(handshake::type_t::SERVER, session::side_t::SERVER), flow::error_t::ORDER);
	// Проверяем, что отказ прервал ход рукопожатия безвозвратно
	ASSERT_EQ(machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT), flow::error_t::STATE);
	/**
	 * Прерванный ход рукопожатия отвергает и просьбу о повторе приветствия: состояние
	 * сверяется отдельной половиной условия, и незаведённость с прерванностью
	 * отвергают просьбу всякая в одиночку
	 */
	ASSERT_EQ(machine.retry(), flow::error_t::STATE);
	// Выполняем заведение хода рукопожатия заново
	ASSERT_TRUE(machine.start(flow::role_t::CLIENT));
	// Проверяем отвержение приветствия клиента, отправленного сервером
	ASSERT_EQ(machine.accept(handshake::type_t::CLIENT, session::side_t::SERVER), flow::error_t::SIDE);
	// Выполняем заведение хода рукопожатия заново
	ASSERT_TRUE(machine.start(flow::role_t::CLIENT));
	// Объявляем приветствие клиента
	machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT);
	// Объявляем приветствие сервера
	machine.accept(handshake::type_t::SERVER, session::side_t::SERVER);
	// Проверяем отвержение подписи владения ключом до цепочки сертификатов
	ASSERT_EQ(machine.accept(handshake::type_t::VERIFY, session::side_t::SERVER), flow::error_t::ORDER);
	// Выполняем заведение хода рукопожатия заново
	ASSERT_TRUE(machine.start(flow::role_t::SERVER));
	// Объявляем приветствие клиента
	machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT);
	// Объявляем приветствие сервера
	machine.accept(handshake::type_t::SERVER, session::side_t::SERVER);
	// Объявляем защищённые расширения сервера
	machine.accept(handshake::type_t::EXTENSIONS, session::side_t::SERVER);
	// Объявляем цепочку сертификатов сервера
	machine.accept(handshake::type_t::CERTIFICATE, session::side_t::SERVER);
	// Объявляем подпись владения ключом сервера
	machine.accept(handshake::type_t::VERIFY, session::side_t::SERVER);
	// Объявляем завершение рукопожатия сервером
	machine.accept(handshake::type_t::FINISHED, session::side_t::SERVER);
	/**
	 * Сертификата сервер не запрашивал, и цепочка сертификатов клиента идти сейчас не
	 * вправе: ожидается одно лишь завершение рукопожатия
	 */
	ASSERT_EQ(machine.accept(handshake::type_t::CERTIFICATE, session::side_t::CLIENT), flow::error_t::ORDER);
	// Выполняем сброс хода рукопожатия
	machine.clear();
	// Проверяем сброс ступени хода рукопожатия
	ASSERT_EQ(machine.stage(), flow::stage_t::NONE);
	// Проверяем сброс роли стороны, ведущей ход рукопожатия
	ASSERT_EQ(machine.role(), flow::role_t::NONE);
	// Проверяем отказ объявления просьбы о повторе сброшенному ходу
	ASSERT_EQ(machine.retry(), flow::error_t::STATE);
}

/**
 * @brief Проверка заслонов повторного запроса подлинности и завершения за запросом
 *
 */
TEST(FlowTest, Unattested){
	flow::machine_t machine;
	ASSERT_TRUE(machine.start(flow::role_t::CLIENT));
	machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT);
	machine.accept(handshake::type_t::SERVER, session::side_t::SERVER);
	machine.accept(handshake::type_t::EXTENSIONS, session::side_t::SERVER);
	ASSERT_EQ(machine.accept(handshake::type_t::REQUEST, session::side_t::SERVER), flow::error_t::NONE);
	/**
	 * Раздел 4.3.2 RFC 8446: запрос подлинности в рукопожатии один, повторный -
	 * сообщение не в свой черёд
	 */
	ASSERT_EQ(machine.accept(handshake::type_t::REQUEST, session::side_t::SERVER), flow::error_t::ORDER);
	ASSERT_EQ(machine.stage(), flow::stage_t::FAILED);
	flow::machine_t hasty;
	ASSERT_TRUE(hasty.start(flow::role_t::CLIENT));
	hasty.accept(handshake::type_t::CLIENT, session::side_t::CLIENT);
	hasty.accept(handshake::type_t::SERVER, session::side_t::SERVER);
	hasty.accept(handshake::type_t::EXTENSIONS, session::side_t::SERVER);
	ASSERT_EQ(hasty.accept(handshake::type_t::REQUEST, session::side_t::SERVER), flow::error_t::NONE);
	/**
	 * Сервер, запросивший подлинность, подтверждает себя сертификатами: завершение
	 * сразу за запросом невозможно ни в сертификатном рукопожатии, ни на PSK
	 */
	ASSERT_EQ(hasty.accept(handshake::type_t::FINISHED, session::side_t::SERVER), flow::error_t::ORDER);
	ASSERT_EQ(hasty.stage(), flow::stage_t::FAILED);
}
