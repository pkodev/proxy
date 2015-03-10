/**
 * Загрузка необходимых модулей
 */
var net = require('net');
var log4js = require('log4js');
var fs = require('fs');

/**
 * Загрузка конфигурации
 */
var config = require('./config.json');

/**
 * Логгеры
 */
log4js.configure({
  appenders: [
    { type: 'console' },
    { type: 'dateFile', filename: 'log/proxy.log', pattern: '-yyyy-MM-dd', category: '[PROXY]' }
  ]
});
var logger = log4js.getLogger('[PROXY]');

/**
 * Вывод ошибок в консоль
 */
process.on('uncaughtException', function(err) {
	logger.error('Caught exception', err);
});

/**
 * Объект текущих соединений
 */
var connections = {}

/**
 * Объект списков блокировок
 */
var denylist = getBlackList()

/**
 * Периодическое обновление установленных переменных
 */
setInterval(function(){
	// Подгрузка черных списков
	denylist = getBlackList()
}, 1000);

/**
 * Запуск сервера
 */
var server = net.createServer(function (socket) {
	
	/**
	 * Максимальное кол-во соединений (ставим как в GateServer-е)
	 */
	server.maxConnections = 1500;
	
	/**
	 * Инициализируем объект клиента
	 */
	var client = {
		addr: socket.remoteAddress,
		port: socket.remotePort,
		key: false,
		sesskey: false,
		login: false,
		chaname: false,
		mac: false,
		packets: {
			amount: {},
			speed: {},
			actions: {}
		}
	}
	
	/**
	 * Блокировка по IP-адресу в момент соединения
	 * @todo Попробовать вернуть сообщение
	 */
	if(client.addr && denylist.ips[client.addr.toLowerCase()]) {
		socket.end();
		return sendMessage(client, 'BLACKLIST_IP', 'ERROR');
	}
	
	/**
	 * Регистрируем клиентское соединение
	 */
	connections[client.addr] = connections[client.addr] ? connections[client.addr] + 1 : 1;
	
	/**
	 * Ограничение кол-ва одновременных соединений с одного IP
	 * @todo Попробовать вернуть сообщение
	 * @todo Также дергается on('error') и в лог пишется еще ошибка. А если сделать return отсюда, то не срабатывает on('end')
	 * @todo CloseConnection использовать нельзя, т.к. мы режем соединение до коннекта к GateServer-у
	 */
	if(connections[client.addr] > config.maxcon) {
		socket.end();
		sendMessage(client, 'MORE_THAN_MAX_CONNECTIONS', 'ERROR');
	}
	
	/**
	 * Инициализируем соединение с GateServer-ом
	 */
	var remote = new net.Socket();
	remote.connect(config.remote.port, config.remote.host);
	
	/**
	 * Ожидание пакета авторизации после установки соединения
	 */
	setTimeout(function () {  
		if(!client.login) {
			closeConnection(socket,remote);
		}
	}, config.timeout * 1000);

	/**
	 * Обрабатываем входящие пакеты
	 */
	
	socket.on('data', function(data) {
		
		/**
		 * Блокировки при установленном соединении
		 * @todo Попробовать вернуть сообщение
		 * @see Также блокировки см. при разборе пакета авторизации
		 */
		if(client.addr && denylist.ips[client.addr.toLowerCase()]) {
			return closeConnection(socket, remote, client, 'BLACKLIST_IP', 'ERROR');
		}
		if(client.mac && denylist.macs[client.mac.toLowerCase()]) {
			return closeConnection(socket, remote, client, 'BLACKLIST_MAC', 'ERROR');
		}
		if(client.login && denylist.logins[client.login.toLowerCase()]) {
			return closeConnection(socket, remote, client, 'BLACKLIST_LOGIN', 'ERROR');
		}
		if(client.chaname && denylist.chars[client.chaname.toLowerCase()]) {
			return closeConnection(socket, remote, client, 'BLACKLIST_CHAR', 'ERROR');
		}
		/**
		 * Регистрируем таймеры
		 */
		var MSEC = new Date().getTime(); // UNIXTIME в миллисекундах
		var FSEC = Math.round(MSEC / 1000); // UNIXTIME в секундах
		
		/**
		 * Проверяем общую частоту передачи пакетов в сек
		 */
		if(client.packets.amount[FSEC]) {
			client.packets.amount[FSEC] += 1;
		} else {
			client.packets.amount = {};
			client.packets.amount[FSEC] = 1;
		}
		if(client.packets.amount[FSEC] > config.maxpkts) {
			return sendMessage(client, 'MANY_PACKETS', 'WARN');
		}
		
		/**
		 * Проверяем объем передаваемых данных в сек
		 */
		var packet_size = data.length;
		if(client.packets.speed[FSEC]) {
			client.packets.speed[FSEC] += packet_size;
		} else {
			client.packets.speed = {};
			client.packets.speed[FSEC] = packet_size;
		}
		if(client.packets.speed[FSEC] > config.maxspeed) {
			return sendMessage(client, 'BIG_SPEED', 'WARN');
		}
		
		/**
		 * Разбираем входящий пакет
		 */
		var buf = new Buffer(data);
		var hex = buf.toString('hex');
		var info = getPacketInfo(hex);
		
		/**
		 * Пинг-пакеты
		 * 0002 - отправляется всегда, с кодом 11(17) когда перс в игре
		 * @see SC_CheckPing, PC_Ping, SC_Ping
		 */
		if(hex === '0002' || info.code === 17 || (info.size === 2 && info.signature === '')) {
			
			remote.write(data);
			return;
			
		/**
		 * Пакет закрытия соединения
		 * Просто отправляем пакет и закрываем соединение
		 */
		} else if (info.signature === '00000001') {
			
			remote.write(data);
			return sendMessage(client, 'LOGOUT', 'INFO');
			//return closeConnection(socket, remote, client, 'LOGOUT', 'INFO'); // Просто закрываем соединение без отправки пакета
			
		/**
		 * Левые пакеты
		 * Просто рвем соединение
		 */
		} else if (info.signature !== '80000000') {
		
			return closeConnection(socket, remote, client, 'INVALID_PACKET', 'ERROR');
			
		/**
		 * Другие пакеты
		 */
		} else {
				
			/**
			 * Проверяем размер пакета (указанный в пакете с реальным)
			 */
			if(info.size !== info.realsize) {
				return closeConnection(socket, remote, client, 'INVALID_PACKET_SIZE', 'ERROR');
			}

			/**
			 * @todo Проверяем, что код пакета находится в списке разрешенных
			 */
			
			/**
			 * Проверяем частоту передачи пакетов одного типа в сек
			 * У пакета действий определяем поддействие
			 */
			var pcode = info.code;
			var limit = config.maxsames;
			if(info.code === 6) {
				var subcode = parseInt(info.body.substring(16, 20), 16);
				pcode = 'a' + subcode;
				/**
				 * Для пакета перемещения увеличиваем лимит в 3 раза из-за того, что при перемещении 
				 * клиент всегда ждет в ответ определенный пакет и если он не приходит, то начинает 
				 * виснуть и перестает отправлять другие пакеты пока не получит свой
				 * @todo Подумать насчет возврата "нужного" пакета
				 */
				if(subcode === 256) {
					limit = config.maxsames * 3;
				}
			}
			if(client.packets.actions[pcode] && client.packets.actions[pcode][FSEC]) {
				client.packets.actions[pcode][FSEC] += 1;
			} else {
				client.packets.actions = {};
				client.packets.actions[pcode] = {};
				client.packets.actions[pcode][FSEC] = 1;
			}
			if(client.packets.actions[pcode][FSEC] > limit) {
				return sendMessage(client, 'SAME_PACKETS', 'WARN');
			}
			
			/**
			 * Обрабатываем правила для отдельных пакетов
			 */
			
			switch(info.code) {
				
				/**
				 * Пакет авторизации
				 * xxxx xxxx 0051 8000 0000 01af 0007 6e6f  .@V..Q........no
				 * 6269 6c6c 0000 0661 646d 696e 0000 182b  bill...admin...+
				 * 58e2 83be 8c88 0197 b4b7 9c98 3fb7 6739  X...........?.g9
				 * a48c c18b cd16 bb00 1830 302d 3235 2d32  .........00-25-2
				 * 322d 4446 2d41 432d 3739 2d30 302d 3030  2-DF-AC-79-00-00
				 * 0003 8f00 88
				 */
				case 431:
					
					// Разбор пакета
					var shift = 18;
					var pkt = { 
						lsize: parseInt(info.body.substring(shift, shift + 4), 16) * 2 };
						shift += 4;
					pkt.login = hex2str(info.body.substring(shift, shift + pkt.lsize - 2));
						shift += pkt.lsize ;
					pkt.psize = parseInt(info.body.substring(shift, shift + 4), 16) * 2;
						shift += 4;
					pkt.passw = info.body.substring(shift, shift + pkt.psize);
						shift += pkt.psize;
					pkt.msize = parseInt(info.body.substring(shift, shift + 4), 16) * 2;
						shift += 4;
					pkt.mac = hex2str(info.body.substring(shift, shift + pkt.msize - 2));
					
					client.login = pkt.login.toLowerCase();
					client.mac = pkt.mac;
					
					// Блокировка по mac-адресу и логину @todo В клиенте не выскакивает окно о разрыве соединения...
					if(denylist.macs[client.mac.toLowerCase()]) {
						return closeConnection(socket, remote, client, 'BLACKLIST_MAC', 'ERROR');
					}
					if(denylist.logins[client.login]) {
						return closeConnection(socket, remote, client, 'BLACKLIST_LOGIN', 'ERROR');
					}
					
					// Проверка заявленных длин реальным
					if (pkt.psize !== 48 || pkt.msize !== 48 || 
						pkt.passw.length !== 48 || pkt.mac.length !== 23 || pkt.login.length > 20 ||
						pkt.lsize/2-1 !== pkt.login.length) {
						return closeConnection(socket, remote, client, 'INVALID_LOGIN_SIZES', 'ERROR');
					}
					
					// Проверка формата мак-адреса
					var re = /^([0-9A-Z]{2}-){7}[0-9A-Z]{2}$/; // 00-25-22-DF-AC-79-00-00
					if (!re.test(client.mac)) {
						return closeConnection(socket, remote, client, 'INVALID_MAC_FORMAT', 'ERROR');
					}
					
					// Проверка формата пароля 
					var re = /^[0-9a-z]{48}$/; // 685ad3bd93f265ce50b94ac314120e363bcb4d0df499d166
					if (!re.test(pkt.passw)) {
						return closeConnection(socket, remote, client, 'INVALID_PASSW_FORMAT', 'ERROR');
					}
					
					// Проверка формата логина
					var re = /^[0-9a-zA-Z]{5,20}$/;
					if (!re.test(client.login)) {
						return closeConnection(socket, remote, client, 'INVALID_LOGIN_FORMAT', 'ERROR');
					}
					
					sendMessage(client, 'LOGIN', 'INFO');
						
					// Модифицируем пакет, добавляя к мак-адресу ip клиента
					if(config.realip) {
						var find = int2hex(pkt.msize / 2) + str2hex(client.mac);
						var replace = str2hex(';' + client.addr);
						var new_pkt = '8000000001af' + 
							info.body.replace(new RegExp(find), int2hex((pkt.msize + replace.length) / 2) + find.substring(4) + replace);
							new_pkt = int2hex(new_pkt.length / 2 + 2) + new_pkt;
						data = new Buffer(new_pkt, 'hex');
					}
						
					remote.write(data);
					
					break;
					
				/**
				 * Пакет установки секретного кода
				 * xxxx xxxx 002b 8000 0000 015a 0021 4531  .s.5.+.....Z.!E1
				 * 3041 4443 3339 3439 4241 3539 4142 4245  0ADC3949BA59ABBE
				 * 3536 4530 3537 4632 3046 3838 3345 00    56E057F20F883E.
				 */
				case 346:
					
					// Пакет имеет фиксированный размер. Проверим это
					if (info.size !== 43) {
						return closeConnection(socket, remote, client, 'INVALID_PACKET_SIZE_346', 'ERROR');
					}
					
					// Разбор пакета
					var pkt = { 
						psize: parseInt(info.body.substring(0, 4), 16) * 2 };
						pkt.pin = hex2str(info.body.substring(4, 4 + pkt.psize - 2));
						
					// Проверка заявленных длин реальным
					if (pkt.psize !== 66 || pkt.pin.length !== 32) {
						return closeConnection(socket, remote, client, 'INVALID_NEWPIN_SIZES', 'ERROR');
					}
					
					// Проверка формата пароля
					var re = /^[0-9A-Z]{32}$/;
					if (!re.test(pkt.pin)) {
						return closeConnection(socket, remote, client, 'INVALID_NEWPIN_FORMAT', 'ERROR');
					}
					
					remote.write(data);
					
					break;
					
				/**
				 * Пакет смены секретного кода
				 * xxxx xxxx 004e 8000 0000 015b 0021 4531  .e...N.....[.!E1
				 * 3041 4443 3339 3439 4241 3539 4142 4245  0ADC3949BA59ABBE
				 * 3536 4530 3537 4632 3046 3838 3345 0000  56E057F20F883E..
				 * 2145 3130 4144 4333 3934 3942 4135 3941  !E10ADC3949BA59A
				 * 4242 4535 3645 3035 3746 3230 4638 3833  BBE56E057F20F883
				 * 4500                                     E.
				 */
				case 347:
					
					// Пакет имеет фиксированный размер. Проверим это
					if (info.size !== 78) {
						return closeConnection(socket, remote, client, 'INVALID_PACKET_SIZE_347', 'ERROR');
					}
					
					// Разбор пакета
					var pkt = {
						oldpin: hex2str(info.body.substring(4, 68)),
						newpin: hex2str(info.body.substring(74, 138))
					}
					
					// Проверка форматов паролей
					var re = /^[0-9A-Z]{32}$/;
					if (!re.test(pkt.oldpin) || !re.test(pkt.newpin)) {
						return closeConnection(socket, remote, client, 'INVALID_CHANGEPIN_FORMAT', 'ERROR');
					}
					
					remote.write(data);
					
					break;
					
				/**
				 * Вход на персонажа
				 * xxxx xxxx 0014 8000 0000 01b1 000a 4265  .6J...........Be
				 * 7461 5465 7374 3300                      taTest3.)
				 */
				case 433:
					
					// Разбор пакета
					var pkt = { 
						nsize: parseInt(info.body.substring(0, 4), 16) * 2 };
						pkt.name = hex2str(info.body.substring(4, 4 + pkt.nsize - 2));
						
					client.chaname = pkt.name;
					
					// Блокировка по имени персонажа
					if(denylist.chars[client.chaname.toLowerCase()]) {
						return closeConnection(socket, remote, client, 'BLACKLIST_CHAR', 'ERROR');
					}
						
					// Проверка заявленных длин реальным
					if (pkt.nsize/2-1 !== pkt.name.length) {
						return closeConnection(socket, remote, client, 'INVALID_CHA_ENTER_SIZES', 'ERROR');
					}
						
					// Проверка формата имени
					//var re = /^[0-9a-zA-Z]{1,20}$/;
					var re = /^[^';]{1,20}$/;
					if (!re.test(pkt.name)) {
						return closeConnection(socket, remote, client, 'INVALID_CHA_ENTER_FORMAT', 'ERROR');
					}
					
					sendMessage(client, 'CHA_ENTER', 'INFO');
						
					remote.write(data);
					
					break;
					
				/**
				 * Пакет создания персонажа
				 * xxxx xxxx 067b 8000 0000 01b3 0005 5265  .o.A.{........Re
				 * 6e64 0000 0e49 6369 636c 6520 4361 7374  nd...Icicle.Cast
				 * 6c65 0006 5a00 0003 0000 0000 0000 0000  le..Z...........
				 */
				case 435:
					
					// Разбор пакета
					var shift = 0;
					var pkt = { 
						nsize: parseInt(info.body.substring(shift, 4), 16) * 2 };
							shift += 4;
						pkt.name = hex2str(info.body.substring(shift, shift + pkt.nsize - 2));
							shift += pkt.nsize;
						pkt.msize = parseInt(info.body.substring(shift, shift + 4), 16) * 2;
							shift += 4;
						pkt.map = hex2str(info.body.substring(shift, shift + pkt.msize - 2));
						
					// Проверка заявленных длин реальным
					if (pkt.nsize/2-1 !== pkt.name.length || pkt.msize/2-1 !== pkt.map.length) {
						return closeConnection(socket, remote, client, 'INVALID_NEWCHA_SIZES', 'ERROR');
					}
					
					// Проверка формата имени
					var re = /^[0-9A-Za-z]{1,20}$/;
					if (!re.test(pkt.name)) {
						return closeConnection(socket, remote, client, 'INVALID_NEWCHA_NAME_FORMAT', 'ERROR');
					}
					
					// Проверка формата карты
					var re = /^[ A-Za-z]+$/;
					if (!re.test(pkt.map)) {
						return closeConnection(socket, remote, client, 'INVALID_NEWCHA_MAP_FORMAT', 'ERROR');
					}
					
					remote.write(data);
					
					break;
					
				/**
				 * Пакет удаления персонажа
				 * xxxx xxxx 0032 8000 0000 01b4 0005 5265  .ip..2........Re
				 * 6e64 0000 2145 3130 4144 4333 3934 3942  nd..!E10ADC3949B
				 * 4135 3941 4242 4535 3645 3035 3746 3230  A59ABBE56E057F20
				 * 4638 3833 4500                           F883E.
				 */
				case 436:
				
					// Разбор пакета
					var shift = 0;
					var pkt = { 
						nsize: parseInt(info.body.substring(shift, 4), 16) * 2 };
							shift += 4;
						pkt.name = hex2str(info.body.substring(shift, shift + pkt.nsize - 2));
							shift += pkt.nsize;
						pkt.psize = parseInt(info.body.substring(shift, shift + 4), 16) * 2;
							shift += 4;
						pkt.pin = hex2str(info.body.substring(shift, shift + pkt.psize - 2));
						
					// Проверка заявленных длин реальным
					if (pkt.nsize > 42 || pkt.name.length > 20 || pkt.psize !== 66 ||
						pkt.nsize/2-1 !== pkt.name.length ||
						pkt.pin.length !== 32) {
						return closeConnection(socket, remote, client, 'INVALID_DELCHA_SIZES', 'ERROR');
					}
					
					// Проверка формата имени
					//var re = /^[0-9A-Za-z]{1,20}$/;
					var re = /^[^';]{1,20}$/;
					if (!re.test(pkt.name)) {
						return closeConnection(socket, remote, client, 'INVALID_DELCHA_NAME_FORMAT', 'ERROR');
					}
					
					// Проверка формата пароля
					var re = /^[0-9A-Z]{32}$/;
					if (!re.test(pkt.pin)) {
						return closeConnection(socket, remote, client, 'INVALID_DELCHA_PIN_FORMAT', 'ERROR');
					}
						
					remote.write(data);
					
					break;
					
				/**
				 * Пакет изучения скилов
				 * 000b 8000 0000 000b 00c9 01
				 */
				case 11:
					
					// Пакет имеет фиксированный размер. Проверим это
					if (info.size !== 11) {
						return closeConnection(socket, remote, client, 'INVALID_PACKET_SIZE_11', 'ERROR');
					}
					
					// Разбор пакета
					var pkt = {
						skid: parseInt(info.body.substring(0, 4), 16),
						sklv: parseInt(info.body.substring(4, 6), 16)
					}
					
					// Уровень скила не может быть отличен от 1
					if (pkt.sklv !== 1) {
						return closeConnection(socket, remote, client, 'INVALID_SKILL_LVL', 'ERROR');
					}
					
					// Id скила не может быть больше 500
					if (pkt.skid > 500) {
						return closeConnection(socket, remote, client, 'INVALID_SKILL_ID', 'ERROR');
					}
					
					// Блочим изучение скилов в обход книг
					// Место, Посешн, РБ-скилы, Самоуничтожение, Кулинария, Анализ, Производство, Ремесло
					switch (pkt.skid) {
						case 202, 280, 455, 456, 457, 458, 459, 311, 321, 322, 323, 324, 338, 339, 340, 341:
							return closeConnection(socket, remote, client, 'INVALID_SKILL_ID', 'ERROR');
							break;
						default:
							remote.write(data);
							break;
					}
					
					break;
					
				/**
				 * Создание гильдии
				 * xxxx xxxx 0017 8000 0000 0191 0100 0554  ...U...........T
				 * 6573 7400 0005 7465 7374 00              est...test.
				 * @todo При создании гильдии лимит пароля 8 символов, при роспуске 12
				 * Проходит любой пароль кроме символов ' и ; (т.е. пароль фильтруется по умолчанию)
				 * Пароль не фильтруется на клиенте поэтому возвращаем нотис
				 */
				case 401:
					
					// Разбор пакета
					var shift = 0;
					var pkt = { 
						nsize: parseInt(info.body.substring(shift, 4), 16) * 2 };
							shift += 4;
						pkt.name = hex2str(info.body.substring(shift, shift + pkt.nsize - 2));
							shift += pkt.nsize;
						pkt.psize = parseInt(info.body.substring(shift, shift + 4), 16) * 2;
							shift += 4;
						pkt.passw = hex2str(info.body.substring(shift, shift + pkt.psize - 2));
						
					// Проверка заявленных длин реальным
					if (pkt.nsize/2-1 !== pkt.name.length) {
						return closeConnection(socket, remote, client, 'INVALID_GUILD_NEW_SIZES', 'ERROR');
					}
						
					// Проверка формата имени 
					var re = /^[0-9a-zA-Z]{1,16}$/;
					if (!re.test(pkt.name)) {
						return closeConnection(socket, remote, client, 'INVALID_GUILD_NEW_NAME_FORMAT', 'ERROR');
					}
					
					// Проверка формата пароля 
					var re = /^[^';]{1,12}$/;
					if (!re.test(pkt.passw)) {
						sendNotice(socket, 'Invalid characters in password');
						return sendMessage(client, 'INVALID_GUILD_NEW_PASSWORD_FORMAT', 'ERROR');
					}
						
					remote.write(data);
					
					break;
					
				/**
				 * Роспуск гильдии
				 * xxxx xxxx 0017 8000 0000 0199 000d 3132  ..]o..........12
				 * 3334 3536 3738 3930 3132 00              3456789012.
				 * @todo При создании гильдии лимит пароля 8 символов, при роспуске 12
				 * Пароль не фильтруется на клиенте поэтому возвращаем нотис
				 */
				case 409:
					
					// Разбор пакета
					var pkt = { 
						psize: parseInt(info.body.substring(0, 4), 16) * 2 };
						pkt.passw = hex2str(info.body.substring(4, 4 + pkt.psize - 2));
						
					// Проверка заявленных длин реальным
					if (pkt.psize/2-1 !== pkt.passw.length) {
						return closeConnection(socket, remote, client, 'INVALID_GUILD_DEL_PASSW_SIZES', 'ERROR');
					}
						
					// Проверка формата пароля 
					var re = /^[^';]{1,12}$/;
					if (!re.test(pkt.passw)) {
						sendNotice(socket, 'Invalid characters in password');
						return sendMessage(client, 'INVALID_GUILD_DEL_PASSW_FORMAT', 'ERROR');
					}
						
					remote.write(data);
					
					break;
					
				/**
				 * Motto гильдии
				 * xxxx xxxx 0013 8000 0000 019a 0009 4d65  ..6...........Me
				 * 6761 5465 7374 00                        gaTest.
				 */
				case 410:
					
					// Разбор пакета
					var pkt = { 
						msize: parseInt(info.body.substring(0, 4), 16) * 2 };
						pkt.motto = hex2str(info.body.substring(4, 4 + pkt.msize - 2));
						
					// Проверка заявленных длин реальным
					if (pkt.msize/2-1 !== pkt.motto.length) {
						return closeConnection(socket, remote, client, 'INVALID_GUILD_MOTTO_SIZES', 'ERROR');
					}
						
					// Проверка формата motto 
					var re = /^[0-9a-zA-Z]{0,30}$/;
					if (!re.test(pkt.motto)) {
						return closeConnection(socket, remote, client, 'INVALID_GUILD_MOTTO_FORMAT', 'ERROR');
					}
						
					remote.write(data);
					
					break;
					
				/**
				 * Motto персонажа
				 * xxxx xxxx 0016 8000 0000 1781 0009 4d65  ..............Me
				 * 6761 5465 7374 0000 0300                 gaTest....
				 */
				case 6017:
					
					// Разбор пакета
					var pkt = { 
						msize: parseInt(info.body.substring(0, 4), 16) * 2 };
						pkt.motto = hex2str(info.body.substring(4, 4 + pkt.msize - 2));
						
					// Проверка заявленных длин реальным
					if (pkt.msize/2-1 !== pkt.motto.length) {
						return closeConnection(socket, remote, client, 'INVALID_CHA_MOTTO_SIZES', 'ERROR');
					}
						
					// Проверка формата motto 
					var re = /^[0-9a-zA-Z]{0,16}$/;
					if (!re.test(pkt.motto)) {
						return closeConnection(socket, remote, client, 'INVALID_CHA_MOTTO_FORMAT', 'ERROR');
					}
						
					remote.write(data);
					
					break;
					
				/**
				 * Поиск персонажа для добавления в друзья
				 * xxxx xxxx 000f 8000 0000 177b 0005 5265  ../........{..Re
				 * 6e64 00                                  nd.
				 * @todo При создании перса лимит имени 20 символов, при поиске 17
				 * @todo Мб убрать вообще проверку этого пакета, т.к. поиск идет только в памяти
				 */
				case 6011:
					
					// Разбор пакета
					var pkt = { 
						nsize: parseInt(info.body.substring(0, 4), 16) * 2 };
						pkt.name = hex2str(info.body.substring(4, 4 + pkt.nsize - 2));
						
					// Проверка заявленных длин реальным
					if (pkt.nsize/2-1 !== pkt.name.length) {
						return closeConnection(socket, remote, client, 'INVALID_CHA_FIND_SIZES', 'ERROR');
					}
						
					// Проверка формата имени 
					//var re = /^[0-9a-zA-Z]{1,17}$/;
					var re = /^[0-9a-zA-Z]{1,20}$/;
					if (!re.test(pkt.name)) {
						return closeConnection(socket, remote, client, 'INVALID_CHA_FIND_FORMAT', 'ERROR');
					}
						
					remote.write(data);
					
					break;
					
				default:
					
					remote.write(data);
					
					break;
				
			}
		
		}
		
	});
	
	socket.on('error', function (e) {
		closeConnection(socket, remote, client, logger.error(e.toString()), 'ERROR');
	});
	
	remote.on('error', function (e) {
		closeConnection(socket, remote, client, logger.error(e.toString()), 'ERROR');
	});
	
	/**
	 * Обрабатываем обратные пакеты от GateServer-а
	 */
	
	remote.on('data', function(data) {
		
		/**
		 * Разбираем входящий пакет
		 */
		var buf = new Buffer(data);
		var hex = buf.toString('hex');
		
		/**
		 * Пинг-пакет
		 */
		if(hex == '0002') {
			
			socket.write(data);
			return;
			
		/**
		 * Другие пакеты
		 */	
		} else {
			
			var info = getPacketInfo(hex);
			
			switch(info.code) {
				
				/**
				 * Первый пакет с датой
				 * Определяем дату как ключ для шифрации пароля аккаунта
				 * @todo Если использовать его не планируется, то удалить
				 */
				case 940:
					
					client.key = hex2str(info.body.substring(4, 44), 'hex');
					
					break;
				
				/**
				 * Список персонажей
				 * Получаем постоянный ключ для шифрации данных
				 */
				case 931:
					
					client.sesskey = info.body.substring(8, 24);
					
					break;
				
			}
			
		}
		
		socket.write(data);
	});
	
	socket.on('close', function(e) {
		remote.end();
	});
	
	remote.on('close', function(e) {
		socket.end();
	});
	
	socket.on('end', function(e) {
		connections[client.addr] = connections[client.addr] - 1;
	});
	
}).listen(config.local.port, config.local.host, function(){
	
	logger.info('ProxyServer accepting connection on %s:%d', config.local.host, config.local.port);
	
});

/**
 * Возвращает базовую информацию о hex-пакете
 * Если содержится несколько логических пакетов, берем только первый
 * Не расклеился пакет вида 0002 0008 8000 0000 0011
 */
function getPacketInfo(hex) {
	var size = parseInt(hex.substring(0, 4), 16);
		hex  = hex.substring(0, size * 2);
	var packet = {
		size: size,
		signature: hex.substring(4, 12),
		code: parseInt(hex.substring(12, 16), 16) || 0,
		body: hex.substring(16, size * 2),
		realsize: hex.length / 2
	}
	return packet;
}

/**
 * Закрывает все соединения с сообщением в лог (если передан клиент и сообщение)
 */
function closeConnection(socket, remote, client, message, level) {
	remote.end();
	socket.end();
	return client && message ? sendMessage(client, message, level ? level : 'WARN') : true;
}

/**
 * Логирует сообщения
 */
function sendMessage(client, message, level) {
	switch (level) {
		case 'WARN':
			logger.warn(message, client.login, client.chaname, client.addr + ':' + client.port, client.mac);
			break;
		case 'ERROR':
			logger.error(message, client.login, client.chaname, client.addr + ':' + client.port, client.mac);
			break;
		default:
			logger.info(message, client.login, client.chaname, client.addr + ':' + client.port, client.mac);
			break;
	}
	return true;
}

/**
 * Отправляет Notice клиенту
 * xxxx xxxx 0013 8000 0000 0205 0009 5465  ...&..........Te
 * 7374 5465 7374 00                        stTest.
 * @todo Добавить поддержку русского языка
 */
function sendNotice(socket, message) {
	var hex = '80000000'
			+ int2hex(517)
			+ int2hex(message.length)
			+ str2ascii(message)
			+ '00';
	hex = int2hex(hex.length / 2 + 2) + hex;
	socket.write(new Buffer(hex, 'hex'));
}

/**
 * Конвертирует число в int16 hex
 */
function int2hex(int) {
	return String('0000' + (int).toString(16)).slice(-4);
}

/**
 * Конвертирует число в int8 hex
 */
function int82hex(int) {
	return String('00' + (int).toString(16)).slice(-2);
}

/**
 * Конвертирует hex-строку в utf
 */
function hex2str(hex) {
	return new Buffer(hex, 'hex').toString();
}

/**
 * Конвертирует utf в hex-строку
 */
function str2hex(str) {
	return new Buffer(str).toString('hex');
}

/**
 * Конвертирует utf в ascii-строку и возвращает ее в hex
 */
function str2ascii(str) {
	var codes = {
		'ё': 184, 'й': 233, 'ц': 246, 'у': 243, 'к': 234, 'е': 229, 'н': 237, 'г': 227, 'ш': 248, 'щ': 249, 'з': 231, 
		'х': 245, 'ъ': 250, 'ф': 244, 'ы': 251, 'в': 226, 'а': 224, 'п': 239, 'р': 240, 'о': 238, 'л': 235, 'д': 228, 
		'ж': 230, 'э': 253, 'я': 255, 'ч': 247, 'с': 241, 'м': 236, 'и': 232, 'т': 242, 'ь': 252, 'б': 225, 'ю': 254,
		'Ё': 168, 'Й': 201, 'Ц': 214, 'У': 211, 'К': 202, 'Е': 197, 'Н': 205, 'Г': 195, 'Ш': 216, 'Щ': 217, 'З': 199, 
		'Х': 213, 'Ъ': 218, 'Ф': 212, 'Ы': 219, 'В': 194, 'А': 192, 'П': 207, 'Р': 208, 'О': 206, 'Л': 203, 'Д': 196, 
		'Ж': 198, 'Э': 221, 'Я': 223, 'Ч': 215, 'С': 209, 'М': 204, 'И': 200, 'Т': 210, 'Ь': 220, 'Б': 193, 'Ю': 222
	}
	var new_str = []
	for(i=0;i<str.length;i++) {
		if(codes[str[i]]) {
			new_str.push(int82hex(codes[str[i]]))
		} else {
			new_str.push(str2hex(str[i]))
		}
	}
	return new_str.join('');
}

/**
 * Возвращает список блокировок по типу
 */
function getBlack(type) {
	var rows = {};
	var lines = fs.readFileSync(__dirname + '/denylist/' + type + '.txt', { encoding: 'utf8' }).trim().split('\n')
	lines.forEach(function (line) { 
		rows[line.trim().toLowerCase()] = true;
	});
	return rows;
}

/**
 * Возвращает объект всех блокировок
 */
function getBlackList() {
	return {
		logins: getBlack('logins'),
		chars: getBlack('chars'),
		ips: getBlack('ips'),
		macs: getBlack('macs')
	}
}

/**
 * Запускаем веб-сервер
 * @todo Сделать отдельным модулем и добавить в конфиг
 */

var express = require('express');
var app = express();
var swig = require('swig');
var bodyParser = require('body-parser');
var postParser = bodyParser.urlencoded({ extended: false })

app.engine('html', swig.renderFile);
app.set('view engine', 'html');
app.set('views', __dirname + '/views');
app.set('view cache', true);
swig.setDefaults({ cache: false });

app.listen(3000, '127.0.0.1', function () {
	logger.info('WebServer accepting connection on %s:%d', '127.0.0.1', 3000);
});

/**
 * Главная страница
 */
app.get('/', function (req, res) {
	res.render(config.lang, { 
		settings: config,
		denylist: {
			logins: fs.readFileSync(__dirname + '/denylist/logins.txt', { encoding: 'utf8' }),
			chars: fs.readFileSync(__dirname + '/denylist/chars.txt', { encoding: 'utf8' }),
			ips: fs.readFileSync(__dirname + '/denylist/ips.txt', { encoding: 'utf8' }),
			macs: fs.readFileSync(__dirname + '/denylist/macs.txt', { encoding: 'utf8' })
		},
		logs: fs.readdirSync(__dirname + '/log/').sort()
	});
});

/**
 * Возврат лога
 */
app.get('/log/:logdate/:lastline/', function (req, res) {
	var lines = fs.readFileSync(__dirname + '/log/' + req.params.logdate, { encoding: 'utf8' })
		.split('\n');
	var expr = /^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+-\s+(.*)?/;
	var rows = [];
	lines.forEach(function (line) { 
		var matches = expr.exec(line);
		if(matches !== null) {
			rows.push({
				date: matches[1],
				type: matches[2],
				category: matches[3],
				message: matches[4]
			});
		}
	});
	res.json(rows.slice(parseInt(req.params.lastline)))
});

/**
 * Сохранение списков блокировок
 */
app.post('/denylist/', postParser, function (req, res) {
	fs.writeFileSync(__dirname + '/denylist/' + req.body.type + '.txt', req.body.list.trim());
	res.json({message: 'OK'});
});

/**
 * Сохранение настроек
 */
app.get('/settings/', function (req, res) {
	if(req.query.maxcon)   config.maxcon   = parseInt(req.query.maxcon);
	if(req.query.maxpkts)  config.maxpkts  = parseInt(req.query.maxpkts);
	if(req.query.maxsames) config.maxsames = parseInt(req.query.maxsames);
	if(req.query.maxspeed) config.maxspeed = parseInt(req.query.maxspeed);
	if(req.query.timeout)  config.timeout  = parseInt(req.query.timeout);
	config.realip = req.query.realip ? true : false;
	res.json({message: 'OK'});
});

