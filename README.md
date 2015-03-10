<h1>Proxy Server for Tales of Pirates, Pirate King Online, Piratia game servers</h1>
<p>The Proxy is a proxy server that is installed before GateServer and is used to filter incoming packets from the client. When using a proxy server no need to install additional filters (Gemini XFail, SQLGuard, FilterServer and others).</p>
<p>The main purpose of the Proxy is to block unwanted traffic before it reaches the application's server. Also included are tools to extend the control of the game server.</p>
<h3>Features</h3>
<ul>
	<li>Transmits only the packets used in the game (in which there is a signature required)</li>
	<li>Splits a physical packet for logics and transmits only first packet</li>
	<li>Validates the size of transmitted packets</li>
	<li>Validates the ping-packets</li>
	<li>Validates the username and mac-address of authorization packet</li>
	<li>Validates the secret code</li>
	<li>Validates the character name and motto</li>
	<li>Validates the guild name, password and motto</li>
	<li>Limits the bandwidth connection</li>
	<li>Limits the number of transmitted packets per second</li>
	<li>Limits the number of packets transmitted per second of the same type</li>
	<li>Blocks the learn of skill more than one point</li>
	<li>Blocks the learn of skill without skill book (Sit, Fairy body, Rebirth skills, Polliwog Self Explode, Cooking, Manufacturing, Crafting, Analyze)</li>
	<li>Locking in real-time to the player by IP, Mac, username (login), character name</li>
	<li>Has a web interface for viewing logs, locks players and change settings in real time</li>
	<li>Only works with unencrypted connection</li>
	<li>Lost the real IP address of the player, but provides the possibility of transmission to save in the DB</li>
</ul>
<h1>Requirements</h1>
<ul>
	<li>"CommEncrypt = 0" in GateServer.cfg</li>
	<li>Installing <a href="http://nodejs.org/download/">Node.js</a>. For routers you can use <a href="http://wiki.openwrt.org/doc/howto/nodejs">Node.js for OpenWrt</a></li>
	<li>
		Installing Node.js modules
		<ul>
			<li><a href="https://github.com/nomiddlename/log4js-node">log4js</a> <code>npm install log4js</code></li>
			<li><a href="http://expressjs.com/">express</a> <code>npm install express</code></li>
			<li><a href="https://github.com/expressjs/body-parser">body-parser</a> <code>npm install body-parser</code></li>
			<li><a href="http://paularmstrong.github.io/swig/">swig</a> <code>npm install swig</code></li>
		</ul>
	</li>
</ul>
<h1>Settings</h1>
<p>You can install and run the Proxy on the same PC where the Game Server is running, or on any other PC.</p>
<p>For transmitting the real IP address of the player, Proxy must be running on the network interface with direct access to the Internet.</p>
<p>If you running Proxy on the same PC you need run GateServer on inner network interface and Proxy on outer network interface.</p>
<p><b>GateServer.cfg</b></p>
<pre>[ToClient]
IP = 127.0.0.1
Port = 1973
CommEncrypt = 0</pre>
<p><b>config.json</b></p>
<pre>{
	"local": {
		"host": "77.88.99.55", // Public IP address of PC
		"port": 1973
	},
	"remote": {
		"host": "127.0.0.1",
		"port": 1973
	},
	"realip": true
}</pre>
<p>If you running Proxy on the different PCs you need run GateServer on outer network interface and Proxy on outer network interface on another PC.</p>
<p><b>GateServer.cfg</b></p>
<pre>[ToClient]
IP = 0.0.0.0
Port = 1973
CommEncrypt = 0</pre>
<p><b>config.json</b></p>
<pre>{
	"local": {
		"host": "0.0.0.0",
		"port": 1973
	},
	"remote": {
		"host": "77.88.99.55", // GateServer IP address
		"port": 1973
	},
	"realip": true
}</pre>
<p>Set <code>"realip": true</code> in config.json for save real IP address of the player.</p>
<p>If you using FilterServer or another filter between GateServer and GameServer you can not save real ip address and you need set <code>"realip": false</code> in config.json</p>
<p>Real IP address of the player will be saved in AccountServer.account_login.last_login_mac as mac-address;ip-address, i.e. <code>00-00-00-00-00-00-00-00;127.0.0.1</code></p>
<h1>Starting Proxy</h1>
Run <code>node proxy.js</code> with command line
<h1>Web control panel</h1>
<p>You can access the web control panel at the address http://127.0.0.1:3000/ on the PC running Proxy.</p>



