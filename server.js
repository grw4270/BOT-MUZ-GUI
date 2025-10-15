const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const multer = require('multer');
require('dotenv').config({ path: '/app/.env' });

const { Client, GatewayIntentBits } = require('discord.js');

// === Discord client (tylko do flagi update) ===
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ],
});

setInterval(async () => {
  const flagFile = path.join(__dirname, 'update_commands.flag');
  if (fs.existsSync(flagFile)) {
    console.log('🌀 Wykryto żądanie aktualizacji komend (plik flagi).');
    fs.unlinkSync(flagFile);
  }
}, 5000);

client.login(process.env.BOT_TOKEN);

// === Environment ===
const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_CALLBACK_URL,
  SESSION_SECRET,
  BASE_MUSIC_DIR,
  BOT_TOKEN,
  OWNER_ID,
  PORT = 3000,
} = process.env;

if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_CALLBACK_URL) {
  console.warn('⚠️ Discord OAuth credentials missing in .env');
}

const SCOPES = ['identify', 'guilds'];

// === Passport ===
passport.serializeUser((user, done) => {
  done(null, {
    id: user.id,
    username: user.username,
    discriminator: user.discriminator,
    avatar: user.avatar,
    accessToken: user.accessToken,
    refreshToken: user.refreshToken,
    guilds: user.guilds,
  });
});
passport.deserializeUser((obj, done) => done(null, obj));

if (DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET && DISCORD_CALLBACK_URL) {
  passport.use(
    new DiscordStrategy(
      {
        clientID: DISCORD_CLIENT_ID,
        clientSecret: DISCORD_CLIENT_SECRET,
        callbackURL: DISCORD_CALLBACK_URL,
        scope: SCOPES,
      },
      (accessToken, refreshToken, profile, done) => {
        profile.accessToken = accessToken;
        profile.refreshToken = refreshToken;
        return done(null, profile);
      }
    )
  );
}

// === Express app ===
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: SESSION_SECRET || 'change-this',
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

const ensureAuth = (req, res, next) => {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  res.status(401).json({ error: 'unauthenticated' });
};

// === Static files ===
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// === Discord OAuth ===
app.get('/auth/discord', passport.authenticate('discord'));
app.get(
  '/auth/callback',
  passport.authenticate('discord', { failureRedirect: '/' }),
  (req, res) => res.redirect('/')
);
app.get('/auth/logout', (req, res) => {
  req.logout?.();
  req.session.destroy(() => res.redirect('/'));
});

// === API: user info ===
app.get('/api/me', ensureAuth, (req, res) => {
  const u = req.user;
  res.json({ id: u.id, username: u.username, guilds: u.guilds });
});

// === Helpers ===
async function botInGuild(guildId) {
  try {
    const resp = await axios.get(`https://discord.com/api/v10/guilds/${guildId}`, {
      headers: { Authorization: `Bot ${BOT_TOKEN}` },
    });
    console.log(`[botInGuild] ✅ ${resp.data.name}`);
    return true;
  } catch {
    return false;
  }
}

function resolveServerDir(serverId) {
  if (!BASE_MUSIC_DIR) return null;
  const entries = fs.readdirSync(BASE_MUSIC_DIR, { withFileTypes: true });
  for (const d of entries) {
    if (d.isDirectory() && d.name.startsWith(serverId)) {
      return path.join(BASE_MUSIC_DIR, d.name);
    }
  }
  return null;
}

function safePath(base, filePath) {
  const resolved = path.resolve(base, filePath);
  if (!resolved.startsWith(path.resolve(base))) throw new Error('invalid path');
  return resolved;
}

function sanitizeFilename(name) {
  return name.replace(/[^a-zA-Z0-9._ \-()\[\]]+/g, '_').slice(0, 255);
}

// === API: list servers ===
app.get('/api/servers', ensureAuth, async (req, res) => {
  const user = req.user;
  if (!user || !user.guilds) return res.json([]);

  if (OWNER_ID && user.id === OWNER_ID) {
    try {
      const entries = fs.readdirSync(BASE_MUSIC_DIR, { withFileTypes: true });
      const allGuilds = entries
        .filter(d => d.isDirectory())
        .map(d => {
          const [id, ...rest] = d.name.split(' - ');
          return { id, name: rest.join(' - ') || d.name };
        });
      return res.json(allGuilds);
    } catch {
      return res.json([]);
    }
  }

  const ADMIN_BIT = 0x8n;
  const results = [];
  for (const g of user.guilds) {
    const hasAdmin = (BigInt(g.permissions) & ADMIN_BIT) !== 0n;
    if (!hasAdmin) continue;
    const botIsIn = await botInGuild(g.id);
    if (botIsIn) results.push({ id: g.id, name: g.name });
  }

  res.json(results);
});

// === File listing ===
app.get('/api/files/:serverId', ensureAuth, (req, res) => {
  const serverId = req.params.serverId;
  const dir = resolveServerDir(serverId);
  if (!dir) return res.status(404).json({ error: 'server-directory-not-found' });
  try {
    const items = fs.readdirSync(dir, { withFileTypes: true }).map(d => ({
      name: d.name,
      isDirectory: d.isDirectory(),
    }));
    res.json({ dir, items });
  } catch (e) {
    res.status(500).json({ error: 'read-failed', details: e.message });
  }
});

// === File download ===
app.get('/api/files/:serverId/download', ensureAuth, (req, res) => {
  const serverId = req.params.serverId;
  const file = req.query.file;
  if (!file) return res.status(400).json({ error: 'file-required' });
  const dir = resolveServerDir(serverId);
  if (!dir) return res.status(404).end();
  try {
    const safe = safePath(dir, file);
    res.download(safe);
  } catch (e) {
    res.status(400).json({ error: 'invalid-path' });
  }
});

// === File upload ===
const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;
const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: MAX_UPLOAD_BYTES } });

app.post('/api/files/:serverId/upload', ensureAuth, upload.single('file'), async (req, res) => {
  const serverId = req.params.serverId;
  const dir = resolveServerDir(serverId);
  if (!dir) return res.status(404).json({ error: 'server-directory-not-found' });
  if (!req.file) return res.status(400).json({ error: 'no-file' });

  fs.mkdirSync(dir, { recursive: true });
  const ext = path.extname(req.file.originalname).toLowerCase();
  const ALLOWED_EXT = ['.mp3', '.flac', '.wav', '.m4a', '.ogg'];
  if (!ALLOWED_EXT.includes(ext)) return res.status(400).json({ error: 'invalid-extension' });

  const safeName = sanitizeFilename(req.file.originalname);
  const target = path.join(dir, safeName);
  fs.writeFileSync(target, req.file.buffer);

  // ✅ aktualizacja tylko listy plików, bez ruszania server_id
  if (req.user.id === OWNER_ID && dir.endsWith('com')) {
    console.log('🔄 Upload do /com — aktualizuję listę plików w /play...');
    try {
      const { REST, Routes } = require('discord.js');
      const rest = new REST({ version: '10' }).setToken(BOT_TOKEN);
      const existing = await rest.get(Routes.applicationCommands(DISCORD_CLIENT_ID));

      const COM_DIR = dir;
      const files = fs.readdirSync(COM_DIR)
        .filter(f => /\.(mp3|wav|ogg|m4a|flac)$/i.test(f))
        .slice(0, 25);

      const updated = existing.map(cmd => {
        if (cmd.name === 'play') {
          cmd.options = cmd.options.map(opt => {
            if (opt.name === 'plik') {
              opt.choices = files.map(f => ({ name: f, value: f }));
            }
            return opt;
          });
        }
        return cmd;
      });

      await rest.put(Routes.applicationCommands(DISCORD_CLIENT_ID), { body: updated });
      console.log(`✅ Komendy zaktualizowane po uploadzie (${files.length} plików)`);
    } catch (err) {
      console.error('❌ Błąd przy aktualizacji komend po uploadzie:', err);
    }
  }

  res.json({ ok: true, file: req.file.originalname });
});

// === File delete ===
app.delete('/api/files/:serverId', ensureAuth, async (req, res) => {
  const serverId = req.params.serverId;
  const { file } = req.body;
  const dir = resolveServerDir(serverId);
  if (!dir) return res.status(404).json({ error: 'server-directory-not-found' });

  try {
    const p = safePath(dir, file);
    fs.unlinkSync(p);

    if (req.user.id === OWNER_ID && dir.endsWith('com')) {
      console.log('🔄 Usunięcie z /com — aktualizuję listę plików w /play...');
      try {
        const { REST, Routes } = require('discord.js');
        const rest = new REST({ version: '10' }).setToken(BOT_TOKEN);
        const existing = await rest.get(Routes.applicationCommands(DISCORD_CLIENT_ID));

        const COM_DIR = dir;
        const files = fs.readdirSync(COM_DIR)
          .filter(f => /\.(mp3|wav|ogg|m4a|flac)$/i.test(f))
          .slice(0, 25);

        const updated = existing.map(cmd => {
          if (cmd.name === 'play') {
            cmd.options = cmd.options.map(opt => {
              if (opt.name === 'plik') {
                opt.choices = files.map(f => ({ name: f, value: f }));
              }
              return opt;
            });
          }
          return cmd;
        });

        await rest.put(Routes.applicationCommands(DISCORD_CLIENT_ID), { body: updated });
        console.log(`✅ Komendy zaktualizowane po usunięciu (${files.length} plików)`);
      } catch (err) {
        console.error('❌ Błąd przy aktualizacji komend po usunięciu:', err);
      }
    }

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'delete-failed', details: e.message });
  }
});


// === Health check ===
app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, '0.0.0.0', () => console.log(`🌍 Server listening on port ${PORT}`));
