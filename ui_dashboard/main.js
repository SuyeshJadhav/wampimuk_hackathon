const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let flaskProcess = null;
let mitmProcess = null;

function createWindow() {
	const win = new BrowserWindow({
		width: 1280,
		height: 800,
		webPreferences: {
			nodeIntegration: true,
			contextIsolation: false
		},
		titleBarStyle: 'hiddenInset',
		backgroundColor: '#0f172a' // Dark theme bg
	});

	win.loadFile('renderer/index.html');
}

function startBackend() {
	// 1. Spawning Flask API using venv Python
	const flaskPath = path.join(__dirname, 'backend', 'api.py');
	const projectRoot = path.join(__dirname, '..');
	const venvPython = path.join(projectRoot, 'venv', 'Scripts', 'python.exe');
	flaskProcess = spawn(venvPython, [flaskPath], {
		cwd: projectRoot // Run from project root to access modules
	});

	flaskProcess.stdout.on('data', (data) => {
		console.log(`Flask Output: ${data}`);
	});

	flaskProcess.stderr.on('data', (data) => {
		console.log(`Flask Log: ${data}`);
	});

	console.log("Flask backend spawned");

	// 2. Mitmproxy — user runs it manually with the inspect.py addon.
	//    The dashboard reads from intercept_log.json written by the addon.
	//    To start mitmproxy with the addon: mitmproxy -s mitmproxy_addon/inspect.py
	console.log("Dashboard will read traffic from intercept_log.json (run mitmproxy separately)");
}

app.whenReady().then(() => {
	startBackend();
	createWindow();

	app.on('activate', () => {
		if (BrowserWindow.getAllWindows().length === 0) {
			createWindow();
		}
	});
});

app.on('window-all-closed', () => {
	if (process.platform !== 'darwin') {
		app.quit();
	}
});

app.on('will-quit', () => {
	// Kill child processes
	if (flaskProcess) flaskProcess.kill();
	if (mitmProcess) mitmProcess.kill();
});
