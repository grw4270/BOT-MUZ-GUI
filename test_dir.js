const fs = require('fs');
const path = require('path');

const dir = process.env.BASE_MUSIC_DIR || 'music';

console.log('Sprawdzam zawartość:', dir);
try {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const d of entries) {
    if (d.isDirectory()) {
      console.log('DIR:', d.name);
    } else {
      console.log('FILE:', d.name);
    }
  }
} catch (e) {
  console.error('Błąd odczytu:', e.message);
}
