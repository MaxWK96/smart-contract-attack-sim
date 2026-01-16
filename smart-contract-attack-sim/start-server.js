const { spawn } = require('child_process');
const path = require('path');

const webDir = path.join(__dirname, 'web');
const server = spawn('npx', ['next', 'dev', '-p', '3000'], {
  cwd: webDir,
  stdio: 'inherit',
  shell: true
});

server.on('error', (err) => {
  console.error('Failed to start server:', err);
});

process.on('SIGINT', () => {
  server.kill();
  process.exit();
});
