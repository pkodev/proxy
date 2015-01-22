<h1>Прокси для ММОРПГ Tales of Pirates, Pirate King Online, Пиратия</h1>
<p>Представляет собой прокси-сервер, устанавливаемый перед GateServer-ом и служащий для фильтрации входящих пакетов от клиента. При использовании прокси-сервера нет необходимости устанавливать дополнительные фильтры (Gemini XFail, SQLGuard, FilterServer и др.).</p>
<h3>Основные возможности</h3>
<ul>
	<li>Пропускает только пакеты, используемые в игре (у которых присутствует необходимая сигнатура)</li>
	<li>Осуществляется валидация размеров передаваемых пакетов</li>
	<li>Валидация пинг-пакетов</li>
	<li>Валидация логина и мак-адреса в пакете авторизации</li>
	<li>Валидация пин-кода в пакетах установки и смены секретного пароля</li>
	<li>Валидация имени персонажа при создании</li>
	<li>Ограничение пропускной способности соединения до 5 KB/s</li>
	<li>Ограничение количества проходимых пакетов до 64/s</li>
	<li>Ограничение количества проходимых пакетов одного типа до 3/s</li>
	<li>Блокировка изучения скилов более чем на один пункт</li>
	<li>Блокировка изучения скилов в обход книг (Посешн, РБ-скилы, Самоуничтожение, Кулинария, Анализ, Производство, Ремесло)</li>
</ul>
<h3>Особенности</h3>
<ul>
	<li>Полноценно работает только с незашифрованным соединением</li>
	<li>Теряется реальный IP-адрес клиента, но предусмотрена возможность его передачи для сохранения в базе данных</li>
	<li>Прокси-сервер еще не проходил тестирование при большом количестве клиентов</li>
</ul>
<h1>Установка и настройка</h1>
<p>Для работы прокси-сервера необходим установленный <a href="http://nodejs.org/download/">Node.js</a>. См. также <a href="http://wiki.openwrt.org/doc/howto/nodejs">Node.js для OpenWrt</a></p>
<p>Прокси можно запускать как на той же машине, что и GateServer, так и на любой другой машине. Для возможности передачи реального IP-адреса клиента необходим запуск на устройстве и интерфейсе, имеющих прямой выход в сеть Интернет.</p>
<h3>Файлы конфигурации</h3>
<p>Если вы запускаете прокси-сервер на той же машине, что и GateServer, то GateServer должен быть запущен на внутреннем интерфейсе, а прокси-сервер на внешнем.</p>
<p><b>GateServer.cfg</b></p>
<pre>[ToClient]
IP = 127.0.0.1
Port = 1973
CommEncrypt = 0</pre>
<p><b>proxy.js</b></p>
<pre>var config = {
	local: {
		host: '77.88.99.55', // Внешний Ip-адрес машины
		port: 1973
	},
	remote: {
		host: '127.0.0.1',
		port: 1973
	},
	realip: true
}</pre>
<p>Если вы запускаете прокси-сервер на другой машине, то GateServer и прокси-сервер должны работать на внешних интерфейсах своих машин.</p>
<p><b>GateServer.cfg</b></p>
<pre>[ToClient]
IP = 0.0.0.0
Port = 1973
CommEncrypt = 0</pre>
<p><b>proxy.js</b></p>
<pre>var config = {
	local: {
		host: '0.0.0.0',
		port: 1973
	},
	remote: {
		host: '77.88.99.55', // Ip-адрес машины с GateServer-ом
		port: 1973
	},
	realip: true
}</pre>
<p>Команда запуска сервера</p>
<code>node proxy.js</code>
<p>Реальный ip-адрес клиента записывается в поле БД AccountServer.account_login.last_login_mac в виде мак-адреc;ip-адрес, например <code>00-00-00-00-00-00-00-00;127.0.0.1</code></p>
<h3>TODO лист</h3>
<ul>
	<li>Добавить ограничение на количество одновременных соединений с одного IP-адреса</li>
	<li>Блокировки по ip и mac-адресу</li>
	<li>Добавить проверку имени гильдии при создании, motto персонажа</li>
	<li>Сделать интерфейс для синхронного перевода</li>
	<li>Разобраться с алгоритмом шифрования и сделать поддержку зашифрованного соединения. Перед этим реализовать версию с оптимальной обработкой зашифрованных пакетов без их дешифрации.</li>
	<li>Вынести конфигурацию в отдельный файл</li>
	<li>Сделать логирование в файл (сейчас выводится в консоль приложения)</li>
</ul>
