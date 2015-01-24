/**
 * Конфигурация
 */
var config = {
	local: {
		host: '0.0.0.0',
		port: 1973
	},
	remote: {
		host: '192.168.0.100',
		port: 1973
	},
	realip: true, // Добавлять реальный ip-адрес к mac-адресу (true) или нет (false)
}

/**
 * Подгрузка необходимых модулей
 */
var net = require('net');

/**
 * Вывод ошибок в консоль
 */
process.on('uncaughtException', function(err) {
	console.log('Caught exception: ' + err);
});

/**
 * Запуск сервера
 */
var server = net.createServer(function (socket) {
	
	/**
	 * Инициализируем объект клиента
	 */
	var client = {
		addr: socket.remoteAddress,
		port: socket.remotePort,
		key: false,
		sesskey: false,
		packets: {
			amount: {},
			speed: {},
			actions: {}
		}
	}
	
	/**
	 * Инициализируем соединение с GateServer-ом
	 */
	
	var remote = new net.Socket();
		
	remote.connect(config.remote.port, config.remote.host);

	/**
	 * Обрабатываем входящие пакеты
	 */
	
	socket.on('data', function(data) {
		
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
		if(client.packets.amount[FSEC] > 64) {
			return sendMessage(client, 'MANY_PACKETS');
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
		if(client.packets.speed[FSEC] > 5120) {
			return sendMessage(client, 'BIG_SPEED');
		}
		
		/**
		 * Разбираем входящий пакет
		 */
		var buf = new Buffer(data);
		var hex = buf.toString('hex');
		
		/**
		 * Пинг-пакеты
		 * 0002 - отправляется всегда, с кодом 11(17) когда перс в игре (у последнего битый размер...)
		 * @see SC_CheckPing, PC_Ping, SC_Ping
		 * @todo Проверить пинг-пакеты с шифрованием соединения (из-за шифрования они не попадают видимо в условия)
		 */
		if(hex == '0002' || hex == '00088000000000110002' || hex == '0008800000000011') {
			
			remote.write(data);
			return;
			
		/**
		 * Пакет закрытия соединения
		 * Просто закрываем соединение без отправки пакета (т.е. эмулируем закрытие окна клиента). Теоретически, это должно исключить дюпы при ТП
		 * @todo Надо протестировать
		 */
		} else if (hex.substring(0, 12) == '000800000001') {
			
			//remote.write(data);
			return closeConnection(socket, remote, client, 'LOGOUT');
			
		/**
		 * Левые пакеты
		 * Просто рвем соединение
		 */
		} else if (hex.substring(4, 12) != '80000000') {
		
			return closeConnection(socket, remote, client, 'INVALID_PACKET');
			
		/**
		 * Другие пакеты
		 */
		} else {
			
			var info = getPacketInfo(hex);
	
			/**
			 * Проверяем размер пакета (указанный в пакете с реальным)
			 * @todo Убрать пока либо понять на каких пакетах это не работает, либо не рвать соединение
			 * @see Пинг-пакеты
			 */
			if(info.size !== info.realsize) {
				return closeConnection(socket, remote, client, 'INVALID_PACKET_SIZE');
			}

			/**
			 * Проверяем, что код пакета находится в списке разрешенных
			 */
			/*
				191		Создание гильдии (отправка названия и пароля) - Это последний занесенный
				1900	Гм чат
				1901	Торговый чат
				1902	Мир чат
				1903	ЛС
				1904	Пати чат
				1905	Гильд чат
				1906	Создание сессии
				1907	Сообщение в сессиию @see CS_Sess_Say
				1908	Добавление сессии
				1909	Покинуть сессию
				1771	Приглашение в отряд
				1772	Принятие приглашения в отряд
				1773	Отмена приглашения в отряд
				1774	Покинуть отряд
				1775	Кикнуть из отряда
				177B	Приглашение в друзья
				177C	Принятие приглашения в друзья
				177D	Отмена приглашения в друзья
				177E	Удалить из друзей
				1780	Информация о друге
				1781	Изменить перс. инфо (motto, icon)
			 */
			
			/**
			 * Проверяем частоту передачи пакетов одного типа в сек
			 */
			if(client.packets.actions[info.code] && client.packets.actions[info.code][FSEC]) {
				client.packets.actions[info.code][FSEC] += 1;
			} else {
				client.packets.actions = {};
				client.packets.actions[info.code] = {};
				client.packets.actions[info.code][FSEC] = 1;
			}
			if(client.packets.actions[info.code][FSEC] > 3) {
				return sendMessage(client, 'SAME_PACKETS');
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
					var shift = 34;
					var pkt = { 
						lsize: parseInt(hex.substring(shift, shift + 4), 16) * 2 };
						shift += 4;
					pkt.login = hex2str(hex.substring(shift, shift + pkt.lsize - 2));
						shift += pkt.lsize ;
					pkt.psize = parseInt(hex.substring(shift, shift + 4), 16) * 2;
						shift += 4;
					pkt.passw = hex.substring(shift, shift + pkt.psize);
						shift += pkt.psize;
					pkt.msize = parseInt(hex.substring(shift, shift + 4), 16) * 2;
						shift += 4;
					pkt.mac = hex2str(hex.substring(shift, shift + pkt.msize - 2));
					
					client.login = pkt.login;
					client.mac = pkt.mac;
					
					// Проверка заявленных длин реальным
					if (pkt.psize !== 48 || pkt.msize !== 48 || 
						pkt.passw.length !== 48 || pkt.mac.length !== 23 || pkt.login.length > 20 ||
						pkt.lsize/2-1 !== pkt.login.length) {
						return closeConnection(socket, remote, client, 'INVALID_LOGIN_SIZES');
					}
					
					// Проверка формата мак-адреса
					var re = /^([0-9A-Z]{2}-){7}[0-9A-Z]{2}$/; // 00-25-22-DF-AC-79-00-00
					if (!re.test(client.mac)) {
						return closeConnection(socket, remote, client, 'INVALID_MAC_FORMAT');
					}
					
					// Проверка формата пароля 
					// @todo Бесполезно или не работает, видимо, проверить алгоритм шифрации 
					var re = /^[0-9a-z]{48}$/; // 134b8fe72e7e9fcbe0b88b4b3c9c1347c09835507ebd4a61
					if (!re.test(pkt.passw)) {
						return closeConnection(socket, remote, client, 'INVALID_PASSW_FORMAT');
					}
					
					// Проверка формата логина
					var re = /^[0-9a-zA-Z]{5,20}$/;
					if (!re.test(client.login)) {
						return closeConnection(socket, remote, client, 'INVALID_LOGIN_FORMAT');
					}
					
					sendMessage(client, 'LOGIN');
						
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
					if (hex.length !== 43 * 2) {
						return closeConnection(socket, remote, client, 'INVALID_PACKET_SIZE_346');
					}
					
					// Разбор пакета
					var pkt = { 
						psize: parseInt(info.body.substring(0, 4), 16) * 2 };
						pkt.pin = hex2str(info.body.substring(4, 4 + pkt.psize - 2));
						
					// Проверка заявленных длин реальным
					if (pkt.psize !== 66 || pkt.pin.length !== 32) {
						return closeConnection(socket, remote, client, 'INVALID_NEWPIN_SIZES');
					}
					
					// Проверка формата пароля
					var re = /^[0-9A-Z]{32}$/;
					if (!re.test(pkt.pin)) {
						return closeConnection(socket, remote, client, 'INVALID_NEWPIN_FORMAT');
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
					if (hex.length !== 78 * 2) {
						return closeConnection(socket, remote, client, 'INVALID_PACKET_SIZE_347');
					}
					
					// Разбор пакета
					var pkt = {
						oldpin: hex2str(info.body.substring(4, 68)),
						newpin: hex2str(info.body.substring(74, 138))
					}
					
					// Проверка форматов паролей
					var re = /^[0-9A-Z]{32}$/;
					if (!re.test(pkt.oldpin) || !re.test(pkt.newpin)) {
						return closeConnection(socket, remote, client, 'INVALID_CHANGEPIN_FORMAT');
					}
					
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
						return closeConnection(socket, remote, client, 'INVALID_NEWCHA_SIZES');
					}
					
					// Проверка формата имени
					var re = /^[0-9A-Za-z]{1,20}$/;
					if (!re.test(pkt.name)) {
						return closeConnection(socket, remote, client, 'INVALID_NEWCHA_NAME_FORMAT');
					}
					
					// Проверка формата карты
					var re = /^[ A-Za-z]+$/;
					if (!re.test(pkt.map)) {
						return closeConnection(socket, remote, client, 'INVALID_NEWCHA_MAP_FORMAT');
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
						return closeConnection(socket, remote, client, 'INVALID_DELCHA_SIZES');
					}
					
					// Проверка формата имени
					var re = /^[0-9A-Za-z]{1,20}$/;
					if (!re.test(pkt.name)) {
						return closeConnection(socket, remote, client, 'INVALID_DELCHA_NAME_FORMAT');
					}
					
					// Проверка формата пароля
					var re = /^[0-9A-Z]{32}$/;
					if (!re.test(pkt.pin)) {
						return closeConnection(socket, remote, client, 'INVALID_DELCHA_PIN_FORMAT');
					}
						
					remote.write(data);
					
					break;
					
				/**
				 * Пакет изучения скилов
				 * 000b 8000 0000 000b 00c9 01
				 */
				case 11:
					
					// Пакет имеет фиксированный размер. Проверим это
					if (hex.length !== 11 * 2) {
						return closeConnection(socket, remote, client, 'INVALID_PACKET_SIZE_11');
					}
					
					// Разбор пакета
					var pkt = {
						skid: parseInt(info.body.substring(0, 4), 16),
						sklv: parseInt(info.body.substring(4, 6), 16)
					}
					
					// Уровень скила не может быть отличен от 1
					if (pkt.sklv !== 1) {
						return closeConnection(socket, remote, client, 'INVALID_SKILL_LVL');
					}
					
					// Блочим изучение скилов в обход книг
					// Посешн, РБ-скилы, Самоуничтожение, Кулинария, Анализ, Производство, Ремесло
					switch (pkt.skid) {
						case 280, 455, 456, 457, 458, 459, 311, 321, 322, 323, 324, 338, 339, 340, 341:
							return closeConnection(socket, remote, client, 'INVALID_SKILL_ID');
							break;
						default:
							remote.write(data);
							break;
					}
					
					break;
					
				default:
					
					remote.write(data);
					
					break;
				
			}
			
		}
		
		//console.log(hex);
		
	});
	
	socket.on('error', function (e) {
		remote.end();
	});
	
	remote.on('error', function (e) {
		console.log(e.toString());
		socket.end();
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
	
	socket.on('close', function(had_error) {
		remote.end();
	});
	
	remote.on('close', function(had_error) {
		socket.end();
	});
	
}).listen(config.local.port, config.local.host, function(){
	
	console.log('ProxyServer accepting connection on %s:%d', config.local.host, config.local.port);
	
});

/**
 * Возвращает базовую информацию о hex-пакете
 */
function getPacketInfo(hex) {
	return {
		size: parseInt(hex.substring(0, 4), 16),
		signature: hex.substring(4, 12),
		code: parseInt(hex.substring(12, 16), 16),
		realsize: hex.length/2,
		body: hex.substring(16)
	}
}

/**
 * Закрывает все соединения с сообщением в консоль
 */
function closeConnection(socket, remote, client, message) {
	remote.end();
	socket.end();
	return sendMessage(client, message);
}

/**
 * Выводит сообщение в консоль
 */
function sendMessage(client, message) {
	console.log(message, client.login, client.addr, client.port, client.mac);
	return true;
}

/**
 * Конвертирует число в int32 hex
 */
function int2hex(int) {
	return String('0000' + (int).toString(16)).slice(-4);
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


