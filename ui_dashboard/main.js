const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let backendProcess = null;
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
	// Spawn the FastAPI Risk Engine via uvicorn
	// This replaces the old Flask backend — one unified API on port 8000
	const projectRoot = path.join(__dirname, '..');
	const venvPython = path.join(projectRoot, 'venv', 'Scripts', 'python.exe');

	backendProcess = spawn(venvPython, [
		'-m', 'uvicorn',
		'risk_engine.main:app',
		'--host', '127.0.0.1',
		'--port', '8000',
		'--reload'
	], {
		cwd: projectRoot
	});

	backendProcess.stdout.on('data', (data) => {
		console.log(`[Risk Engine] ${data}`);
	});

	backendProcess.stderr.on('data', (data) => {
		console.log(`[Risk Engine] ${data}`);
	});

	console.log("Risk Engine (FastAPI) spawned on port 8000");

	// Mitmproxy — user runs it manually with the addon.
	// The dashboard reads from intercept_log.json written by the addon.
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
	if (backendProcess) backendProcess.kill();
	if (mitmProcess) mitmProcess.kill();
});
