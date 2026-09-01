#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execSync, spawnSync, spawn } = require('child_process');
const readline = require('readline');
const zlib = require('zlib');

const IS_WIN = process.platform === 'win32';
const RUN_DIR = path.dirname(process.argv[1]);
const DATA_DIR = path.join(RUN_DIR, 'data');
const DEFAULTS_DIR = path.join(DATA_DIR, 'defaults');
const PRESETS_DIR = path.join(RUN_DIR, 'presets');
const UI_DIR = path.join(RUN_DIR, 'ui');

// ANSI colours — purple/magenta theme for Velocity
const W    = '\x1b[0m';
const WH   = '\x1b[97m';
const GR   = '\x1b[90m';
const RD   = '\x1b[91m';
const GN   = '\x1b[92m';
const YL   = '\x1b[93m';
const CY   = '\x1b[96m';
const MG   = '\x1b[95m';       // magenta — primary accent
const PU   = '\x1b[38;5;135m'; // bright purple — secondary accent
const BOLD = '\x1b[1m';
const DIM  = '\x1b[2m';
const ITAL = '\x1b[3m';

const c = (...codes) => (t) => codes.join('') + String(t) + W;

// ── output buffer ──────────────────────────────────────────────────────────
let outBuf = [], outLast = 0;
const OUT_BATCH = 40, OUT_MS = 50;

function outFlush(force = false) {
  if (!outBuf.length) return;
  const now = Date.now();
  if (!force && outBuf.length < OUT_BATCH && (now - outLast) < OUT_MS) return;
  process.stdout.write(outBuf.join('\n') + '\n');
  outBuf = [];
  outLast = now;
}
function p(t = '') { outBuf.push(String(t)); outFlush(); }

// ── clickable refs ─────────────────────────────────────────────────────────
let openableRefs = [];
function resetRefs() { openableRefs = []; }
function addRef(fpath, kind) {
  const isExec = kind === 'jar' || /\.(jar|exe|dll|bat|cmd|ps1)$/i.test(fpath);
  const target = isExec ? path.dirname(fpath) : fpath;
  openableRefs.push({ path: fpath, target, kind, isFolder: isExec });
  return openableRefs.length;
}
function linkRef(fpath, kind) {
  const n = addRef(fpath, kind);
  return c(MG, BOLD)('▶') + ' ' + c(DIM, GR)(`[${n}]`);
}
function openRef(n) {
  if (n < 1 || n > openableRefs.length) return [null, `No such reference: ${n}`];
  const ref = openableRefs[n - 1];
  try {
    if (IS_WIN) spawnSync('explorer', ref.isFolder ? ['/select,', path.normalize(ref.path)] : [ref.target], { detached: true });
    else if (process.platform === 'darwin') spawnSync('open', [ref.target], { detached: true });
    else spawnSync('xdg-open', [ref.target], { detached: true });
    return [ref.target, null];
  } catch(e) { return [null, String(e)]; }
}

// ── commands ───────────────────────────────────────────────────────────────
const COMMANDS = [
  '/admin','/clear','/dashboard','/elevate','/exit','/find',
  '/flash','/ghost','/help','/history','/inspect','/live','/livescan',
  '/max','/open','/path','/preset','/pro','/report','/seeterminal',
  '/source','/stats','/strings','/whitelist','/window',
];

const DATA_FILES = {
  cheat_strings:   'cheat_strings.json',
  client_profiles: 'client_profiles.json',
  scanner:         'scanner.json',   // was habibi.json
};

const DATA_SCHEMA_VERSION = 3;

const ghostState   = { active: false, paths: [], focusPaths: [], strings: [] };
const activePreset = { name: 'default', data: null };
let SCAN_RUNNING = false;
let terminalLog  = [];
let scanCounters = {};
let allFindings  = {};
let scannerStatus = 'idle';  // was habibiStatus

function setScannerStatus(s) { scannerStatus = s; }
function getScannerStatus() { return scannerStatus; }

function scannerWidget() {
  const s = getScannerStatus();
  if (s === 'running') return c(MG)('●') + ' ' + c(MG)('Scanner');
  if (s === 'warn')    return c(YL)('●') + ' ' + c(YL)('Scanner');
  if (s === 'crashed') return c(RD)('●') + ' ' + c(RD)('Scanner');
  return c(GR)('●') + ' ' + c(GR)('Scanner');
}

function resetState() {
  terminalLog  = [];
  scanCounters = { green: 0, yellow: 0, red: 0, total: 0, jars: 0 };
  allFindings  = {
    scanner: [], config_hits: [], log_hits: [], jar_flags: [],
    process_flags: [], dns_flags: [], registry_flags: [], prefetch_flags: [],
    summary: { private_hits: 0, spoof_hits: 0, dns_hits: 0, log_tampering: 0 },
  };
  setScannerStatus('idle');
}

// ── logging ────────────────────────────────────────────────────────────────
function tlog(msg, kind = 'info') {
  const ts = new Date().toISOString().slice(11, 23);
  const icons = {
    info: c(GR)('[') + c(GR)('i') + c(GR)(']'),
    scan: c(GR)('[') + c(MG)('>') + c(GR)(']'),
    ok:   c(GR)('[') + c(GN)('+') + c(GR)(']'),
    warn: c(GR)('[') + c(YL)('!') + c(GR)(']'),
    bad:  c(GR)('[') + c(RD, BOLD)('x') + c(GR)(']'),
  };
  const line = `  ${c(GR)(`[${ts}]`)} ${icons[kind] || icons.info} ${c(WH)(msg)}`;
  terminalLog.push(line);
  if (SCAN_RUNNING) p(line);
}

function statusBar() {
  const g = scanCounters.green || 0, y = scanCounters.yellow || 0;
  const r = scanCounters.red   || 0, t = scanCounters.total  || 0, j = scanCounters.jars || 0;
  return `  ${c(GN)('●')} ${c(WH)(g)}  ${c(YL)('●')} ${c(WH)(y)}  ${c(RD,BOLD)('●')} ${c(WH)(r)}  ${c(GR)('files:')} ${c(WH)(t)}  ${c(GR)('jars:')} ${c(WH)(j)}  │  ${scannerWidget()}`;
}
function drawStatus() {
  outFlush(true);
  process.stdout.write('\r\x1b[K' + statusBar());
}

let lastProgressTime = 0;
function drawProgress(label, done, total, eta = '') {
  const now = Date.now();
  if (done < total && (now - lastProgressTime) < 60) return;
  lastProgressTime = now;
  outFlush(true);
  const bw = 26, pct = Math.min(done / Math.max(total, 1), 1.0);
  const filled = Math.floor(bw * pct);
  const bar = c(MG)('█'.repeat(filled)) + c(GR)('░'.repeat(bw - filled));
  const etaS = eta ? c(GR)(`  ETA ${eta}`) : '';
  process.stdout.write(`\r\x1b[K  ${c(GR)(label.padEnd(18))} ${bar}  ${c(WH)(`${done}/${total}`)}${etaS}  │ ${scannerWidget()}   `);
}

function etaStr(elapsedMs, done, total) {
  if (done === 0) return 'calc...';
  const rate = done / Math.max(elapsedMs / 1000, 0.001);
  const remain = Math.max(0, total - done) / rate;
  return remain < 60 ? `~${Math.floor(remain)}s` : `~${Math.floor(remain/60)}m${Math.floor(remain%60)}s`;
}

// ── crypto / admin ─────────────────────────────────────────────────────────
function sha256File(fpath) {
  try {
    const data = fs.readFileSync(fpath);
    return crypto.createHash('sha256').update(data).digest('hex');
  } catch { return null; }
}

function sha1File(fpath) {
  try {
    const data = fs.readFileSync(fpath);
    return crypto.createHash('sha1').update(data).digest('hex');
  } catch { return null; }
}

// ── Modrinth hash verification ──────────────────────────────────────────────
const _modrinthCache = {};

async function queryModrinth(sha1Hash) {
  if (!sha1Hash) return { pid: null, slug: null, name: null };
  if (_modrinthCache[sha1Hash]) return _modrinthCache[sha1Hash];
  try {
    const https = require('https');
    const get = (url) => new Promise((res, rej) => {
      const req = https.get(url, { headers: { 'User-Agent': 'Velocity-Scanner/3.0' }, timeout: 6000 }, (r2) => {
        let d = ''; r2.on('data', c2 => d += c2); r2.on('end', () => res(d));
      });
      req.on('error', rej); req.on('timeout', () => { req.destroy(); rej(new Error('timeout')); });
    });
    const vData = JSON.parse(await get('https://api.modrinth.com/v2/version_file/' + sha1Hash + '?algorithm=sha1'));
    const pid = vData.project_id;
    if (!pid) { _modrinthCache[sha1Hash] = { pid: null, slug: null, name: null }; return _modrinthCache[sha1Hash]; }
    const pData = JSON.parse(await get('https://api.modrinth.com/v2/project/' + pid));
    const result = { pid, slug: pData.slug || '', name: pData.title || '' };
    _modrinthCache[sha1Hash] = result;
    return result;
  } catch {
    _modrinthCache[sha1Hash] = { pid: null, slug: null, name: null };
    return _modrinthCache[sha1Hash];
  }
}

// Pre-resolve Modrinth hashes for a list of jars before scanning
async function preloadModrinthHashes(jarPaths) {
  const promises = jarPaths.map(async (jp) => {
    const h = sha1File(jp);
    if (h) await queryModrinth(h);
  });
  await Promise.allSettled(promises);
}

function isAdmin() {
  if (!IS_WIN) return process.getuid && process.getuid() === 0;
  try { execSync('net session', { stdio: 'ignore' }); return true; }
  catch { return false; }
}

function openFolderDialog(title = 'Select Folder') {
  if (!IS_WIN) return null;
  try {
    const r = spawnSync('powershell', ['-NoProfile', '-Command',
      `[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')|Out-Null;$f=New-Object System.Windows.Forms.FolderBrowserDialog;$f.Description='${title}';$f.ShowDialog()|Out-Null;$f.SelectedPath`
    ], { encoding: 'utf8', timeout: 60000 });
    const p2 = (r.stdout || '').trim();
    return p2 && fs.existsSync(p2) ? p2 : null;
  } catch { return null; }
}

// ── readline with autocomplete + history ───────────────────────────────────
const commandHistory = [];
let histIdx = 0, savedCurrent = '';

function getHint(text) {
  if (!text || !text.startsWith('/')) return '';
  for (const cmd of COMMANDS) {
    if (cmd.startsWith(text) && cmd !== text) return cmd;
  }
  return '';
}

function readLine(prompt) {
  return new Promise((resolve) => {
    outFlush(true);
    if (!process.stdin.isTTY) {
      process.stdout.write(prompt);
      const rl = readline.createInterface({ input: process.stdin });
      rl.once('line', (line) => { rl.close(); resolve(line); });
      rl.once('close', () => resolve(''));
      return;
    }
    process.stdout.write(prompt);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    let buf = [], pos = 0;
    histIdx = commandHistory.length;
    savedCurrent = '';

    function redraw() {
      const cur = buf.join('');
      const hint = getHint(cur);
      const hr = (hint && pos === buf.length) ? hint.slice(cur.length) : '';
      let line = '\r\x1b[K' + prompt + cur;
      if (hr) line += '\x1b[2m' + hr + '\x1b[0m';
      const back = hr.length + (buf.length - pos);
      if (back > 0) line += `\x1b[${back}D`;
      process.stdout.write(line);
    }

    function done(result) {
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdin.removeListener('data', onData);
      process.stdout.write('\r\x1b[K' + prompt + buf.join('') + '\n');
      if (result.trim()) commandHistory.push(result);
      resolve(result);
    }

    function onData(chunk) {
      const b = chunk[0];
      if (chunk.length === 1) {
        if (b === 0x03) { process.stdout.write('^C\n'); done('__CTRLC__'); return; }
        if (b === 0x0D || b === 0x0A) { done(buf.join('')); return; }
        if (b === 0x08 || b === 0x7F) { if (pos > 0) { buf.splice(pos-1, 1); pos--; redraw(); } return; }
        if (b === 0x09) {
          const hint = getHint(buf.join(''));
          if (hint) { buf = hint.split(''); pos = buf.length; redraw(); }
          return;
        }
        if (b === 0x16) {
          try {
            const cb = execSync('powershell -NoProfile -Command "Get-Clipboard"', { encoding: 'utf8', timeout: 3000 }).trim();
            const clean = cb.replace(/\r\n|\n|\r/g, ' ');
            buf.splice(pos, 0, ...clean.split(''));
            pos += clean.length;
            redraw();
          } catch {}
          return;
        }
        if (b >= 0x20) { buf.splice(pos, 0, String.fromCharCode(b)); pos++; redraw(); return; }
      }
      if (chunk.length >= 3 && chunk[0] === 0x1B && chunk[1] === 0x5B) {
        const code = chunk[2];
        if (code === 0x43) { if (pos < buf.length) { pos++; redraw(); } }
        else if (code === 0x44) { if (pos > 0) { pos--; redraw(); } }
        else if (code === 0x41) {
          if (commandHistory.length) {
            if (histIdx === commandHistory.length) savedCurrent = buf.join('');
            histIdx = Math.max(0, histIdx - 1);
            buf = commandHistory[histIdx].split(''); pos = buf.length; redraw();
          }
        }
        else if (code === 0x42) {
          if (histIdx < commandHistory.length) {
            histIdx++;
            buf = (histIdx === commandHistory.length ? savedCurrent : commandHistory[histIdx]).split('');
            pos = buf.length; redraw();
          }
        }
        else if (code === 0x33 && chunk[3] === 0x7E) { if (pos < buf.length) { buf.splice(pos,1); redraw(); } }
        else if (code === 0x48) { pos = 0; redraw(); }
        else if (code === 0x46) { pos = buf.length; redraw(); }
      }
    }
    process.stdin.on('data', onData);
  });
}

function clear() { process.stdout.write(IS_WIN ? '\x1Bc' : '\x1B[2J\x1B[0f'); }
function divider(w = 74) { p(c(GR)('  ' + '─'.repeat(w))); }

function section(title) {
  const tag = c(GR)('[') + c(MG)('>') + c(GR)('] ') + c(WH, BOLD)(title);
  const pad = Math.max(2, 76 - title.length - 16);
  p('');
  p(tag + ' '.repeat(pad) + scannerWidget());
}

function row(label, val, st, w = 36) {
  const lb = c(WH)(`  ${label.padEnd(w)}`);
  let vb;
  if (st === 'clean') vb = c(GN)(`  ${val}`);
  else if (st === 'warn') vb = c(YL)(`  ${val}`);
  else if (st === 'bad')  vb = c(RD, BOLD)(`  ${val}`);
  else if (st === 'info') vb = c(MG)(`  ${val}`);
  else vb = c(GR)(`  ${val}`);
  p(lb + vb);
}

// ── ASCII logo (from VelocityScan.ps1) ────────────────────────────────────
// Block-art VELOCITY rendered in purple 256-colour gradient
const ASCII_LOGO = [
  '  ██╗   ██╗███████╗██╗      ██████╗  ██████╗██╗████████╗██╗   ██╗',
  '  ██║   ██║██╔════╝██║     ██╔═══██╗██╔════╝██║╚══██╔══╝╚██╗ ██╔╝',
  '  ██║   ██║█████╗  ██║     ██║   ██║██║     ██║   ██║    ╚████╔╝ ',
  '  ╚██╗ ██╔╝██╔══╝  ██║     ██║   ██║██║     ██║   ██║     ╚██╔╝  ',
  '   ╚████╔╝ ███████╗███████╗╚██████╔╝╚██████╗██║   ██║      ██║   ',
  '    ╚═══╝  ╚══════╝╚══════╝ ╚═════╝  ╚═════╝╚═╝   ╚═╝      ╚═╝   ',
];
// Purple gradient: 55→93→129→165→135→99
const LOGO_GRADIENT = [55, 93, 129, 165, 135, 99];

function printLogo() {
  let termWidth = 80;
  try { termWidth = process.stdout.columns || 80; } catch {}
  const width = Math.max(...ASCII_LOGO.map(l => l.length));
  const pad = Math.max(0, Math.floor((termWidth - width) / 2));
  const indent = ' '.repeat(pad);
  ASCII_LOGO.forEach((line, i) => {
    const shade = LOGO_GRADIENT[i];
    p(indent + ITAL + `\x1b[38;5;${shade}m` + line + W + '\x1b[0m');
  });
  p(indent + c(GR)('‾'.repeat(width)));
}

function banner() {
  clear(); p('');
  printLogo(); p('');
  p(c(GR)('[') + c(MG)('>') + c(GR)('] ') + c(WH)('Velocity ready.') + c(GR)('  /help  ·  Tab = autocomplete  ·  Ctrl+C = cancel scan'));
  if (!isAdmin()) p(c(GR)('[') + c(YL)('!') + c(GR)('] ') + c(YL)('Not Administrator — registry + prefetch limited'));
  p(c(GR)('[') + c(MG)('i') + c(GR)('] ') + c(WH)('Preset: ') + c(MG)(activePreset.name) + c(GR)('   ') + scannerWidget());
  p('');
}

// ── launcher paths ─────────────────────────────────────────────────────────
const appdata = process.env.APPDATA || '';
const home    = os.homedir();
const KNOWN_LAUNCHERS = {
  FastClient:    [path.join(appdata, '.fastclient', 'profiles')],
  Vanilla:       [path.join(appdata, '.minecraft')],
  PrismLauncher: [path.join(appdata, 'PrismLauncher')],
  MultiMC:       [path.join(appdata, 'MultiMC')],
  CurseForge:    [path.join(home,    'curseforge', 'minecraft')],
  Technic:       [path.join(appdata, '.technic')],
  FTB:           [path.join(appdata, 'ftblauncher')],
  PolyMC:        [path.join(appdata, 'PolyMC')],
  GDLauncher:    [path.join(appdata, 'gdlauncher_next')],
  Feather:       [path.join(appdata, 'FeatherClient'), path.join(appdata, '.feather')],
  Badlion:       [path.join(appdata, '.badlion')],
  Lunar:         [path.join(appdata, '.lunarclient')],
  ATLauncher:    [path.join(appdata, 'ATLauncher')],
  Modrinth:      [path.join(appdata, 'com.modrinth.theseus')],
  TLauncher:     [path.join(appdata, '.tlauncher')],
  Labymod:       [path.join(appdata, '.labymod4')],
  Salwyrr:       [path.join(appdata, 'Salwyrr')],
};
const MULTI_PROFILE_LAUNCHERS = new Set(['FastClient','PrismLauncher','MultiMC','PolyMC','ATLauncher']);

const DRIVE_WALK_SKIP = new Set([
  'windows','$recycle.bin','system volume information','programdata',
  '$windows.~bt','$windows.~ws','recovery','perflogs',
  'node_modules','.git','.gradle','.m2','target','build',
  '.idea','.vscode','__pycache__','venv','.venv','site-packages','dist','obj',
]);

const CLICKER_NAMES = [
  '198m','198macros','198_macros','zenith','zenithlauncher','zenith_macros',
  'akira_ghost','akiraghost','zoomin_client','zoominclient',
  'sodaclicker','soda_clicker','koidclicker','koid_clicker',
  'wraithclicker','wraith_clicker','rawaccel',
];

const BYPASS_NAMES = [
  'modeleter','model_deleter','antiforensic','anti_forensic',
  'logcleaner','log_cleaner','journalwiper','prefetchcleaner',
];

const CHEAT_DOMAINS = [
  'vape.gg','liquidbounce.net','meteorclient.com','wurst-client.tk',
  'sigma.rip','rusherhack.org','nulled.to','leak.sx','cracked.to',
  'mpgh.net','cyemer.xyz','cyemer.net','cyemer.gg',
  'velaris.xyz','velaris.net','scrimclient.xyz','lucidclient.xyz',
  'argonclient.xyz','spearcore.xyz','xenon.gg',
  'doomsdayclient.com','prestigeclient.vip','198macros.com','dqrkis.xyz',
  'intent.store','rise.today','riseclient.com',
];

// ── default data ───────────────────────────────────────────────────────────
const DEFAULT_DATA = {
  cheat_strings: { default_strings: [
    'com.slither.cyemer','CyemerClient','com.slither','VelarisClient','ArgonClient',
    'LucidClient','ScrimClient','SpearCoreClient','ThunderHack','SigmaClient',
    'WurstClient','MeteorClient','VapeClient','RusherHack','LiquidBounce','net.ccbluex',
    'AutoMace','AutoCrystal','AutoTotemGuard','AutoTotem','KillAura','killaura',
    'TriggerBot','AimAssist','Fakelag','FakeLag','Blink','SpearSwap','MaceSwap',
    'ElytraSwap','Shielddrain','ShieldDrain','AntiKnockback','SelfDestruct','LogCleaner',
    'DirectByteOverwriter','JarUpdater','StringDecoder','Cyemer-Client-Updater',
    'Cyemer-Client-Byte-Overwriter','AutoAnchor','AutoObsidian','AutoShieldBreak',
    'AutoWindCharge','AutoJumpReset','PearlCatch','HoverTotem','KeyPearl','NoFall',
    'BHop','Scaffold','FlyHack','ESP','ShaderESP','HandCham','WTap',
    'ReachExtension','FastPlace','NoBreakDelay','WebBreaker','WindChargeKey',
    'TargetEffect','ObsidianGlow','cyemer/configs','velaris/config','argon/config',
    'module-name','module.isEnabled','ModuleManager','Category.COMBAT',
    'Category.CLIENT','Category.RENDER','BooleanSetting','SliderSetting',
    'ModeSetting','cdn.modrinth.com/data/LQ3K71Q1',
    // extra strings from VelocityScan
    'AutoAnchor','DoubleAnchor','SafeAnchor','AirAnchor','AnchorAction',
    'AutoPot','AutoArmor','ShieldDisabler','ShieldBreaker','AutoDoubleHand',
    'AutoClicker','StunSlam','PopSwitch','AnchorAura','AnchorFill',
    'BedAura','AutoBed','BedBomb','BowAimbot','AutoCrit','CritBypass',
    'ReachHack','ExtendReach','GrimVelocity','GrimDisabler','VelocitySpoof',
    'OffhandTotem','TotemSwitch','HoleFiller','AntiSurround','AntiBurrow',
    'TargetStrafe','AutoGap','AutoPearl','FlyHack','CreativeFlight','BoatFly',
    'PacketFly','AirJump','SpeedHack','BunnyHop','AntiFall','StepHack',
    'FastClimb','AutoStep','HighStep','WaterWalk','LiquidWalk','LavaWalk',
    'NoSlow','NoWeb','NoSoulSand','WallHack','ElytraSpeed','InstantElytra',
    'ScaffoldWalk','FastBridge','BuildHelper','AutoBridge','Nuker','InstantBreak',
    'GhostHand','PlaceAssist','AirPlace','AutoPlace','PlayerESP','MobESP',
    'ItemESP','StorageESP','ChestESP','Tracers','XRayHack','OreESP','NewChunks',
    'DoubleClicker','JitterClick','ButterflyClick','CPSBoost','ChestStealer',
    'InvManager','AutoSprint','AntiAFK','AutoRespawn','FakeLatency','FakePing',
    'SpoofRotation','PositionSpoof','GrimBypass','VulcanBypass','MatrixBypass',
    'PacketMine','PacketWalk','PacketCancel','PacketDupe','SessionStealer',
    'TokenLogger','TokenGrabber','DiscordToken','RemoteAccess','ReverseShell',
    'C2Server','Backdoor','KeyLogger','StashFinder',
    'imgui.binding','JNativeHook','GlobalScreen','NativeKeyListener',
    'client-refmap.json','cheat-refmap.json','phantom-refmap.json',
    'meteordevelopment','cc/novoline','com/alan/clients','club/maxstats',
    'wtf/moonlight','me/zeroeightsix/kami','today/opai',
    'net/minecraft/injection','org/chainlibs/module/impl/modules',
    'xyz/greaj','com/cheatbreaker','doomsdayclient','DoomsdayClient',
    'WalksyOptimizer','LWFH Crystal','vape.gg','vapeclient','VapeLite',
    'intent.store','IntentClient','rise.today','meteor-client',
    'meteorclient','liquidbounce','fdp-client','aristois','impactclient',
    'pandaware','moonClient','futureClient','konas','rusherhack','inertia',
    'catlean','CatleanClient','gypsy','GypsyClient','Prestige','PrestigeClient',
    'XenonClient','GrimClient','dqrkis.xyz','Dqrkis Client',
    'invokeDoAttack','invokeDoItemUse','invokeOnMouseButton',
    'onPushOutOfBlocks','placeInterval','breakInterval','stopOnKill',
    'activateOnRightClick','holdCrystal','fakePunch',
    'JDWP.VirtualMachine.AllModules','LicenseCheckMixin',
    'ClientPlayerInteractionManagerAccessor','obfuscatedAuth',
    'dev.virel','dev.gambleclient','dev.krypton','skid.krypton',
    'org.chainlibs.module.impl.modules.Crystal','org.chainlibs.module.impl.modules.Blatant',
    'imgui.gl3','imgui.glfw',
  ]},
  client_profiles: {
    Cyemer: {
      real_packages: ['com/slither/cyemer/'],
      spoof_mod_ids: ['dynamic_fps','dynamic-fps'],
      config_dirs: ['cyemer','cyemer/configs'],
      config_files: ['cyemer.json'],
      config_path_sig: 'cyemer/configs',
      log_clean_terms: ['cyemer','nanovg'],
      ua_strings: ['Cyemer-Client-Updater/1.0','Cyemer-Client-Byte-Overwriter/1.0'],
      key_classes: ['CyemerClient','Cyemer','ModuleManager','ConfigManager','SelfDestruct','LogCleaner'],
      module_names: ['AimAssist','AutoCrystal','AutoMace','TriggerBot','WTap','Blink','Fakelag'],
      selfdestruct_url: 'cdn.modrinth.com/data/LQ3K71Q1',
    },
    'Cyemer Recode': {
      real_packages: ['com/slither/cyemer/recode/','com/slither/recode/'],
      spoof_mod_ids: ['dynamic_fps','dynamic-fps','lithium'],
      config_dirs: ['cyemer-recode','recode'],
      config_files: ['recode.json'],
      config_path_sig: 'cyemer-recode',
      log_clean_terms: ['cyemer','recode','nanovg'],
      ua_strings: [],
      key_classes: ['RecodeClient','CyemerRecode'],
      module_names: ['AimAssist','AutoCrystal','AutoMace','TriggerBot','Fakelag'],
      selfdestruct_url: '',
    },
    Velaris: {
      real_packages: ['me/velaris/','velaris/client/','com/velaris/'],
      spoof_mod_ids: ['sodium','immediatelyfast','dynamic_fps'],
      config_dirs: ['velaris','.velaris'],
      config_files: ['velaris.json'],
      config_path_sig: 'velaris',
      log_clean_terms: ['velaris'],
      ua_strings: [],
      key_classes: ['VelarisClient','VelarisModule'],
      module_names: ['AimAssist','AutoCrystal','AutoMace','KillAura','Fakelag'],
      selfdestruct_url: '',
    },
    Argon: {
      real_packages: ['me/argon/client/','argon/client/','com/argonhq/'],
      spoof_mod_ids: ['sodium','fabric-api','krypton'],
      config_dirs: ['argon','.argon'],
      config_files: ['argon.json'],
      config_path_sig: 'argon',
      log_clean_terms: ['argon'],
      ua_strings: [],
      key_classes: ['ArgonClient','ArgonModule'],
      module_names: ['KillAura','AimAssist','AutoCrystal'],
      selfdestruct_url: '',
    },
    'Argon B2': {
      real_packages: ['me/argon/b2/','argon/b2/'],
      spoof_mod_ids: ['sodium','krypton'],
      config_dirs: ['argon-b2','.argonb2'],
      config_files: ['argon_b2.json'],
      config_path_sig: 'argon-b2',
      log_clean_terms: ['argon'],
      ua_strings: [],
      key_classes: ['ArgonB2'],
      module_names: ['KillAura','AimAssist','AutoCrystal'],
      selfdestruct_url: '',
    },
    Lucid: {
      real_packages: ['me/lucid/client/','lucid/client/'],
      spoof_mod_ids: ['lithium','sodium-extra'],
      config_dirs: ['lucid','.lucid'],
      config_files: ['lucid.json'],
      config_path_sig: 'lucid',
      log_clean_terms: ['lucid'],
      ua_strings: [],
      key_classes: ['LucidClient'],
      module_names: ['KillAura','AimAssist','AutoCrystal'],
      selfdestruct_url: '',
    },
    'Lucid Argon': {
      real_packages: ['me/lucidargon/','lucidargon/client/'],
      spoof_mod_ids: ['lithium','sodium'],
      config_dirs: ['lucid-argon','.lucid-argon'],
      config_files: ['lucid-argon.json'],
      config_path_sig: 'lucid-argon',
      log_clean_terms: ['lucidargon'],
      ua_strings: [],
      key_classes: ['LucidArgon'],
      module_names: [],
      selfdestruct_url: '',
    },
    Scrim: {
      real_packages: ['me/scrim/','scrim/client/'],
      spoof_mod_ids: ['fabric-api','modmenu'],
      config_dirs: ['scrim','.scrim'],
      config_files: ['scrim.json'],
      config_path_sig: 'scrim',
      log_clean_terms: ['scrim'],
      ua_strings: [],
      key_classes: ['ScrimClient'],
      module_names: [],
      selfdestruct_url: '',
    },
    SpearCore: {
      real_packages: ['me/spearcore/','spearcore/client/'],
      spoof_mod_ids: ['sodium','immediatelyfast'],
      config_dirs: ['spearcore','.spearcore'],
      config_files: ['spearcore.json'],
      config_path_sig: 'spearcore',
      log_clean_terms: ['spearcore'],
      ua_strings: [],
      key_classes: ['SpearCoreClient'],
      module_names: ['AutoMace','SpearSwap'],
      selfdestruct_url: '',
    },
    Xenon: {
      real_packages: ['me/xenon/','xenon/client/'],
      spoof_mod_ids: ['sodium','krypton'],
      config_dirs: ['xenon','.xenon'],
      config_files: ['xenon.json'],
      config_path_sig: 'xenon',
      log_clean_terms: ['xenon'],
      ua_strings: [],
      key_classes: ['XenonClient'],
      module_names: [],
      selfdestruct_url: '',
    },
    Vape: {
      real_packages: ['com/vape/','me/vape/'],
      spoof_mod_ids: [],
      config_dirs: ['vape','.vape'],
      config_files: ['vape.json'],
      config_path_sig: 'vape',
      log_clean_terms: ['vape'],
      ua_strings: [],
      key_classes: ['VapeClient'],
      module_names: ['KillAura','AimAssist'],
      selfdestruct_url: '',
    },
    Wurst: {
      real_packages: ['com/wurst/','net/wurst/'],
      spoof_mod_ids: [],
      config_dirs: ['wurst','.wurst'],
      config_files: ['wurst.json'],
      config_path_sig: 'wurst',
      log_clean_terms: ['wurst'],
      ua_strings: [],
      key_classes: ['WurstClient'],
      module_names: ['KillAura','Fly','Scaffold'],
      selfdestruct_url: '',
    },
    Meteor: {
      real_packages: ['meteordevelopment/meteorclient/'],
      spoof_mod_ids: [],
      config_dirs: ['meteor-client','.meteor'],
      config_files: ['meteor-client.json'],
      config_path_sig: 'meteor-client',
      log_clean_terms: ['meteor'],
      ua_strings: [],
      key_classes: ['MeteorClient'],
      module_names: ['KillAura','AutoCrystal'],
      selfdestruct_url: '',
    },
    RusherHack: {
      real_packages: ['net/rusherhack/','me/rusherhack/'],
      spoof_mod_ids: [],
      config_dirs: ['rusherhack','.rusherhack'],
      config_files: ['rusherhack.json'],
      config_path_sig: 'rusherhack',
      log_clean_terms: ['rusherhack'],
      ua_strings: [],
      key_classes: ['RusherHack'],
      module_names: [],
      selfdestruct_url: '',
    },
    LiquidBounce: {
      real_packages: ['net/ccbluex/liquidbounce/'],
      spoof_mod_ids: [],
      config_dirs: ['liquidbounce','.liquidbounce'],
      config_files: ['liquidbounce.json'],
      config_path_sig: 'liquidbounce',
      log_clean_terms: ['ccbluex','liquidbounce'],
      ua_strings: [],
      key_classes: ['LiquidBounce'],
      module_names: ['KillAura','AutoCrystal','Scaffold'],
      selfdestruct_url: '',
    },
    ThunderHack: {
      real_packages: ['me/thunderhack/','thunderhack/client/'],
      spoof_mod_ids: ['sodium','fabric-api'],
      config_dirs: ['thunderhack','.thunderhack'],
      config_files: ['thunderhack.json'],
      config_path_sig: 'thunderhack',
      log_clean_terms: ['thunderhack'],
      ua_strings: [],
      key_classes: ['ThunderHack','ThunderHackClient'],
      module_names: ['AutoCrystal','AutoMace','KillAura'],
      selfdestruct_url: '',
    },
    Sigma: {
      real_packages: ['me/sigma/','net/sigma/','sigma/client/'],
      spoof_mod_ids: [],
      config_dirs: ['sigma','.sigma'],
      config_files: ['sigma.json'],
      config_path_sig: 'sigma',
      log_clean_terms: ['sigma'],
      ua_strings: [],
      key_classes: ['SigmaClient','SigmaV5'],
      module_names: [],
      selfdestruct_url: '',
    },
    Doomsday: {
      real_packages: ['net/java/'],
      spoof_mod_ids: ['dd','fullbright'],
      config_dirs: [],
      config_files: [],
      config_path_sig: '',
      log_clean_terms: ['doomsday'],
      ua_strings: [],
      key_classes: ['mod_d','BaseMod'],
      module_names: [],
      selfdestruct_url: '',
      doomsday_markers: ['64FV7P4H2NO7Q','addon3.json','addon4.json','mod_d.class','net/java/h','invokePointer','defineClass'],
    },
    Dqrkis: {
      real_packages: ['xyz/dqrkis/','dqrkis/client/'],
      spoof_mod_ids: ['sodium'],
      config_dirs: ['dqrkis','.dqrkis'],
      config_files: ['dqrkis.json'],
      config_path_sig: 'dqrkis',
      log_clean_terms: ['dqrkis'],
      ua_strings: [],
      key_classes: ['DqrkisClient'],
      module_names: ['AutoCrystal','AimAssist'],
      selfdestruct_url: '',
    },
    Prestige: {
      real_packages: ['me/prestige/','prestige/client/'],
      spoof_mod_ids: ['sodium','modmenu'],
      config_dirs: ['prestige','.prestige'],
      config_files: ['prestige.json'],
      config_path_sig: 'prestige',
      log_clean_terms: ['prestige'],
      ua_strings: [],
      key_classes: ['PrestigeClient'],
      module_names: ['AutoCrystal','KillAura','AimAssist'],
      selfdestruct_url: '',
    },
    Gypsy: {
      real_packages: ['me/gypsy/','gypsy/client/'],
      spoof_mod_ids: [],
      config_dirs: ['gypsy','.gypsy'],
      config_files: ['gypsy.json'],
      config_path_sig: 'gypsy',
      log_clean_terms: ['gypsy'],
      ua_strings: [],
      key_classes: ['GypsyClient'],
      module_names: [],
      selfdestruct_url: '',
    },
  },
  scanner: {
    scan_class_limit_standard: 150,
    scan_class_limit_paranoid: 999999,
    confidence_cheat_threshold: 8,
    min_cheat_strings_for_flag: 4,
    known_legit_mod_ids: [
      'sodium','lithium','iris','fabric-api','modmenu','cloth-config',
      'krypton','c2me','feather','carpet','chunky','ias','fabricloader',
      'mixin','immediatelyfast','entity-culling','ferritecore','memoryleakfix',
      'journeymap','jei','rei','jade','waystones','create','botania','optifine',
      'vmp-fabric','vmp','lazydfu','starlight','entityculling','smoothboot-fabric',
      'noisium','threadtweak',
    ],
  },
};

// ── data layer ─────────────────────────────────────────────────────────────
let loadedData = {};

function ensureDataFiles() {
  [DATA_DIR, DEFAULTS_DIR, PRESETS_DIR, UI_DIR].forEach(d => {
    try { fs.mkdirSync(d, { recursive: true }); } catch {}
  });
  const versionPath = path.join(DATA_DIR, '_version.json');
  let onDiskVersion = 0;
  try { onDiskVersion = JSON.parse(fs.readFileSync(versionPath, 'utf8')).version || 0; } catch {}
  const needsMigration = onDiskVersion < DATA_SCHEMA_VERSION;
  for (const [key, fname] of Object.entries(DATA_FILES)) {
    const dpath   = path.join(DATA_DIR, fname);
    const defPath = path.join(DEFAULTS_DIR, fname);
    if (needsMigration || !fs.existsSync(defPath))
      fs.writeFileSync(defPath, JSON.stringify(DEFAULT_DATA[key], null, 2));
    if (needsMigration || !fs.existsSync(dpath))
      fs.writeFileSync(dpath, JSON.stringify(DEFAULT_DATA[key], null, 2));
  }
  if (needsMigration) fs.writeFileSync(versionPath, JSON.stringify({ version: DATA_SCHEMA_VERSION }));
  const fpPath = path.join(DATA_DIR, 'structure_fingerprints.json');
  if (!fs.existsSync(fpPath)) {
    const seed = {};
    for (const [client, profile] of Object.entries(DEFAULT_DATA.client_profiles)) {
      const names = new Set([...(profile.key_classes || []), ...(profile.module_names || [])]);
      if (names.size) seed[client] = [...names].sort();
    }
    fs.writeFileSync(fpPath, JSON.stringify(seed, null, 2));
  }
}

function loadData() {
  ensureDataFiles();
  const out = {};
  for (const [key, fname] of Object.entries(DATA_FILES)) {
    try { out[key] = JSON.parse(fs.readFileSync(path.join(DATA_DIR, fname), 'utf8')); }
    catch { out[key] = DEFAULT_DATA[key]; }
  }
  loadedData = out;
  return out;
}

function getDefaultCheatStrings() { return new Set(loadedData.cheat_strings?.default_strings || []); }
function getClientProfiles()      { return loadedData.client_profiles || {}; }
function getScannerConfig()       { return loadedData.scanner || DEFAULT_DATA.scanner; }
function getKnownLegitModIds()    { return new Set(getScannerConfig().known_legit_mod_ids || []); }
function getAllModuleNames() {
  const names = new Set();
  for (const p of Object.values(getClientProfiles())) (p.module_names || []).forEach(n => names.add(n));
  return names;
}
function getLogCleanTermsMap() {
  const out = {};
  for (const [name, prof] of Object.entries(getClientProfiles()))
    if (prof.log_clean_terms?.length) out[name] = prof.log_clean_terms;
  return out;
}
function getConfigDirsMap() {
  const out = {};
  for (const [name, prof] of Object.entries(getClientProfiles()))
    if (prof.config_dirs?.length) out[name] = prof.config_dirs;
  return out;
}
function getConfigFilesMap() {
  const out = {};
  for (const [name, prof] of Object.entries(getClientProfiles()))
    if (prof.config_files?.length) out[name] = prof.config_files;
  return out;
}

// ── hash store ─────────────────────────────────────────────────────────────
function loadHashStore(name) {
  try { return JSON.parse(fs.readFileSync(path.join(DATA_DIR, name), 'utf8')); }
  catch { return {}; }
}
function saveHashStore(name, data) {
  try { fs.writeFileSync(path.join(DATA_DIR, name), JSON.stringify(data, null, 2)); } catch {}
}
function isWhitelistedHash(sha)    { return sha in loadHashStore('whitelist.json'); }
function recordBadHash(sha, client, jarPath) {
  const store = loadHashStore('known_bad_hashes.json');
  if (!(sha in store)) { store[sha] = { client, first_seen: path.basename(jarPath) }; saveHashStore('known_bad_hashes.json', store); }
}
function addToWhitelist(sha, fpath) {
  const store = loadHashStore('whitelist.json');
  store[sha] = { path: fpath };
  saveHashStore('whitelist.json', store);
}

// ── structure fingerprinting ───────────────────────────────────────────────
function classBasenamesOf(classPaths) {
  return new Set(classPaths.map(cp => path.basename(cp, '.class')));
}
function structureSimilarity(a, b) {
  if (!a.size || !b.size) return 0;
  let inter = 0;
  a.forEach(x => { if (b.has(x)) inter++; });
  return inter / (a.size + b.size - inter);
}
function matchStructure(basenames, threshold = 0.35) {
  if (basenames.size < 3) return [null, 0];
  const store = loadHashStore('structure_fingerprints.json');
  let bestClient = null, bestScore = 0;
  for (const [client, known] of Object.entries(store)) {
    const score = structureSimilarity(basenames, new Set(known));
    if (score > bestScore) { bestClient = client; bestScore = score; }
  }
  return bestScore >= threshold ? [bestClient, bestScore] : [null, 0];
}
function learnStructure(client, basenames) {
  if (!basenames.size) return;
  const store = loadHashStore('structure_fingerprints.json');
  const known = new Set([...(store[client] || []), ...basenames]);
  store[client] = [...known].sort().slice(0, 300);
  saveHashStore('structure_fingerprints.json', store);
}

// ── ZIP / JAR parser ───────────────────────────────────────────────────────
function readZipEntries(jarPath) {
  const buf = fs.readFileSync(jarPath);
  const entries = {};
  let pos = buf.length - 22;
  // search for EOCD signature
  while (pos >= 0 && buf.readUInt32LE(pos) !== 0x06054b50) pos--;
  if (pos < 0) return entries;
  const cdSize   = buf.readUInt32LE(pos + 12);
  const cdOffset = buf.readUInt32LE(pos + 16);
  let cdPos = cdOffset;
  while (cdPos < cdOffset + cdSize) {
    if (buf.readUInt32LE(cdPos) !== 0x02014b50) break;
    const compression = buf.readUInt16LE(cdPos + 10);
    const compSize    = buf.readUInt32LE(cdPos + 20);
    const uncompSize  = buf.readUInt32LE(cdPos + 24);
    const nameLen     = buf.readUInt16LE(cdPos + 28);
    const extraLen    = buf.readUInt16LE(cdPos + 30);
    const commentLen  = buf.readUInt16LE(cdPos + 32);
    const localOffset = buf.readUInt32LE(cdPos + 42);
    const name        = buf.toString('utf8', cdPos + 46, cdPos + 46 + nameLen);
    entries[name]     = { localOffset, compression, compSize, uncompSize };
    cdPos += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function readZipEntry(jarPath, buf, entry) {
  const localBuf = buf || fs.readFileSync(jarPath);
  const { localOffset, compression, compSize } = entry;
  const nameLen  = localBuf.readUInt16LE(localOffset + 26);
  const extraLen = localBuf.readUInt16LE(localOffset + 28);
  const dataStart = localOffset + 30 + nameLen + extraLen;
  const compData  = localBuf.slice(dataStart, dataStart + compSize);
  if (compression === 0) return compData;
  if (compression === 8) return zlib.inflateRawSync(compData);
  return compData;
}

// ── class constant-pool parser ─────────────────────────────────────────────
function extractUtf8Constants(classBytes) {
  const strings = new Set();
  try {
    if (classBytes.length < 10 || classBytes.readUInt32BE(0) !== 0xCAFEBABE) return strings;
    let idx = 8;
    const poolCount = classBytes.readUInt16BE(idx); idx += 2;
    let i = 1;
    while (i < poolCount && idx < classBytes.length) {
      const tag = classBytes[idx++];
      if (tag === 1) {
        const len = classBytes.readUInt16BE(idx); idx += 2;
        const s = classBytes.toString('utf8', idx, idx + len); idx += len;
        if (s.length >= 4) strings.add(s);
        i++;
      } else if ([7,8,16,19,20].includes(tag))        { idx += 2; i++; }
        else if ([9,10,11,12,17,18].includes(tag))     { idx += 4; i++; }
        else if ([3,4].includes(tag))                  { idx += 4; i++; }
        else if ([5,6].includes(tag))                  { idx += 8; i += 2; }
        else if (tag === 15)                           { idx += 3; i++; }
        else break;
    }
  } catch {}
  return strings;
}

function extractPrintableFallback(raw, minLen = 6) {
  const strings = new Set();
  let i = 0;
  while (i < raw.length - minLen) {
    let j = i;
    while (j < raw.length && raw[j] >= 32 && raw[j] < 127) j++;
    if (j - i >= minLen) strings.add(raw.toString('ascii', i, j));
    i = Math.max(j + 1, i + 1);
  }
  return strings;
}

function getClassStrings(rawBytes) {
  const s = extractUtf8Constants(rawBytes);
  if (s.size < 3) { extractPrintableFallback(rawBytes).forEach(x => s.add(x)); }
  return s;
}

// ── config JSON cheat check ────────────────────────────────────────────────
function isCheatConfigJson(data, moduleList) {
  if (typeof data !== 'object' || !data) return [false, 0];
  let cheatStructure = 0, cheatModules = 0;
  for (const [key, val] of Object.entries(data)) {
    if (typeof val === 'object' && val) {
      const keys = new Set(Object.keys(val).map(k => k.toLowerCase()));
      if (keys.has('enabled') && (keys.has('keycode') || keys.has('keybind'))) cheatStructure++;
      if (moduleList.has(key)) cheatModules++;
    }
  }
  return [(cheatStructure >= 2 || cheatModules >= 3), Math.max(cheatStructure, cheatModules)];
}

// ── JAR analyser ───────────────────────────────────────────────────────────
function analyzeJar(jarPath, customStrings, paranoid = false) {
  const r = {
    jarPath, filename: path.basename(jarPath),
    sha256Val: null, sha1Val: null,
    modrinthSlug: null, modrinthName: null, modrinthSpoof: false,
    modId: null, modName: null, isFabric: false,
    fileCount: 0, classCount: 0, pkgTree: {},
    mixinPkgs: [], verdict: 'CLEAN', detectedClient: null,
    cheatStrings: [], clientPackages: [], infectedClasses: [],
    confidence: 0, skipReason: null, spoofEvidence: [],
    selfdestructEv: [], notes: [], classBasenames: new Set(),
    structureMatch: null,
    probability() {
      if (this.verdict === 'CLEAN') return 0;
      let base = 45 + Math.min(this.confidence * 7, 50);
      if (this.cheatStrings.length >= 5) base = Math.min(base + 10, 99);
      if (this.clientPackages.length)    base = Math.min(base + 15, 99);
      if (this.spoofEvidence.length)     base = Math.min(base + 10, 99);
      return base;
    }
  };

  // safe hash — don't crash if file unreadable
  try { r.sha256Val = sha256File(jarPath); } catch {}
  try { r.sha1Val   = sha1File(jarPath); } catch {}

  if (r.sha256Val && isWhitelistedHash(r.sha256Val)) {
    r.verdict = 'CLEAN'; r.skipReason = 'Whitelisted by hash'; return r;
  }
  if (r.sha256Val) {
    const bad = loadHashStore('known_bad_hashes.json');
    if (r.sha256Val in bad) {
      const entry = bad[r.sha256Val];
      r.verdict = 'CHEAT'; r.detectedClient = entry.client; r.confidence = 10;
      r.notes.push(`hash matches previously confirmed ${entry.client} (was named ${entry.first_seen})`);
      return r;
    }
  }

  const activeStrings = getDefaultCheatStrings();
  if (customStrings) customStrings.forEach(s => activeStrings.add(s));
  const profiles    = getClientProfiles();
  const legitIds    = getKnownLegitModIds();
  const hcfg        = getScannerConfig();
  const moduleNames = getAllModuleNames();
  const GENERIC_SEGS = new Set(['me','com','net','org','io','client','impl','mod','internal','core','dev']);

  let buf;
  try { buf = fs.readFileSync(jarPath); }
  catch (e) { r.verdict = 'ERROR'; r.skipReason = String(e).slice(0, 80); return r; }

  let entries;
  try { entries = readZipEntries(jarPath); }
  catch (e) { r.verdict = 'ERROR'; r.skipReason = 'Bad ZIP: ' + String(e).slice(0, 60); return r; }

  const names      = Object.keys(entries);
  r.fileCount      = names.length;
  const classPaths = names.filter(n => n.endsWith('.class'));
  r.classCount     = classPaths.length;
  r.classBasenames = classBasenamesOf(classPaths);

  const [structClient, structScore] = matchStructure(r.classBasenames);
  if (structClient) {
    r.structureMatch = [structClient, structScore];
    r.notes.push(`structure match: ${Math.floor(structScore * 100)}% overlap with ${structClient}`);
    r.confidence = Math.max(r.confidence, structScore >= 0.6 ? 9 : 6);
  }

  if ('fabric.mod.json' in entries) {
    r.isFabric = true;
    try {
      const meta = JSON.parse(readZipEntry(jarPath, buf, entries['fabric.mod.json']).toString('utf8'));
      r.modId   = String(meta.id || '').toLowerCase();
      r.modName = meta.name || '';
    } catch {}
  }

  // ── Modrinth hash cross-reference ──────────────────────────────────────
  // Use pre-cached SHA1 result from preloadModrinthHashes() call
  const _mr = r.sha1Val ? (_modrinthCache[r.sha1Val] || null) : null;
  if (_mr && _mr.slug) {
    r.modrinthSlug = _mr.slug;
    r.modrinthName = _mr.name;
    // Does what Modrinth says match what fabric.mod.json claims?
    if (r.modId && r.modId !== _mr.slug) {
      // Hash belongs to a real mod but this jar claims a different ID — spoofing
      r.modrinthSpoof = true;
      r.spoofEvidence.push(`Modrinth hash=${_mr.slug} (${_mr.name}) but claims mod_id='${r.modId}'`);
      r.confidence = Math.max(r.confidence, 10);
      tlog(`MODRINTH SPOOF  [${r.filename}]  hash=${_mr.slug}  claimed=${r.modId}`, 'bad');
    } else if (!r.spoofEvidence.length && !r.structureMatch && !paranoid) {
      // Hash verified on Modrinth, mod_id matches → legit, skip deep scan
      r.skipReason = `Modrinth verified: ${_mr.name || _mr.slug}`;
      return r;
    }
  }
  // ─────────────────────────────────────────────────────────────────────────

  const clientScores = {};
  for (const [clientName, profile] of Object.entries(profiles)) {
    if (r.modId && (profile.spoof_mod_ids || []).includes(r.modId)) {
      for (const pkg of profile.real_packages || []) {
        if (classPaths.some(cp => cp.startsWith(pkg))) {
          r.spoofEvidence.push(`claims '${r.modId}' but contains ${pkg}`);
          clientScores[clientName] = (clientScores[clientName] || 0) + 100;
          r.confidence = Math.max(r.confidence, 10);
          break;
        }
      }
    }
  }

  if (r.modId && legitIds.has(r.modId) && !r.spoofEvidence.length && !r.structureMatch && !paranoid) {
    r.skipReason = `Known legit: ${r.modId}`; return r;
  }

  for (const [clientName, profile] of Object.entries(profiles)) {
    for (const pkg of profile.real_packages || []) {
      const matching = classPaths.filter(cp => cp.startsWith(pkg));
      if (matching.length) {
        r.clientPackages.push(`${pkg} → ${clientName} (${matching.length} classes)`);
        clientScores[clientName] = (clientScores[clientName] || 0) + 8 + Math.min(matching.length, 20);
        r.confidence = Math.max(r.confidence, 9);
      }
    }
  }

  for (const mixinFile of names.filter(n => n.toLowerCase().includes('mixin') && n.endsWith('.json'))) {
    try {
      const mx  = JSON.parse(readZipEntry(jarPath, buf, entries[mixinFile]).toString('utf8'));
      const pkg = mx.package || '';
      if (pkg) r.mixinPkgs.push(pkg);
      for (const [clientName, profile] of Object.entries(profiles)) {
        for (const realPkg of profile.real_packages || []) {
          const segs = realPkg.replace(/\//g, '.').split('.').filter(s => s && !GENERIC_SEGS.has(s));
          if (segs.some(seg => pkg.toLowerCase().includes(seg.toLowerCase()))) {
            r.clientPackages.push(`mixin:${pkg} → ${clientName}`);
            clientScores[clientName] = (clientScores[clientName] || 0) + 40;
            r.confidence = Math.max(r.confidence, 8);
          }
        }
      }
    } catch {}
  }

  for (const cfgFile of names.filter(n => /\.(json|cfg|txt)$/.test(n) && n.includes('config'))) {
    try {
      const rawCfg = readZipEntry(jarPath, buf, entries[cfgFile]).toString('utf8');
      try {
        const data = JSON.parse(rawCfg);
        for (const [clientName, profile] of Object.entries(profiles)) {
          const sig = profile.config_path_sig || '';
          if (sig && cfgFile.includes(sig)) {
            r.notes.push(`config path: ${cfgFile} → ${clientName}`);
            clientScores[clientName] = (clientScores[clientName] || 0) + 10;
            r.confidence = Math.max(r.confidence, 6);
          }
        }
        const [isCheat, score] = isCheatConfigJson(data, moduleNames);
        if (isCheat) { r.notes.push(`cheat config structure (score ${score})`); r.confidence = Math.max(r.confidence, 5 + score); }
      } catch {}
      for (const sig of activeStrings) {
        if (rawCfg.includes(sig) && !r.cheatStrings.includes(sig)) r.cheatStrings.push(sig);
      }
    } catch {}
  }

  const scanLimit = paranoid ? classPaths.length : Math.min(classPaths.length, hcfg.scan_class_limit_standard || 150);
  for (let ci = 0; ci < scanLimit; ci++) {
    try {
      const raw     = readZipEntry(jarPath, buf, entries[classPaths[ci]]);
      const strings = getClassStrings(raw);
      const hits    = [];
      for (const s of strings) {
        for (const sig of activeStrings) {
          if (s.includes(sig) && s.length < 150 && !hits.includes(sig) && !r.cheatStrings.includes(sig)) {
            hits.push(sig); r.cheatStrings.push(sig); break;
          }
        }
        for (const [clientName, profile] of Object.entries(profiles)) {
          for (const kc of profile.key_classes || []) {
            if (s.trim() === kc) {
              const tag = `class:${kc}`;
              if (!r.cheatStrings.includes(tag)) r.cheatStrings.push(tag);
              clientScores[clientName] = (clientScores[clientName] || 0) + 15;
              r.confidence = Math.max(r.confidence, 8);
            }
          }
          const sdUrl = profile.selfdestruct_url || '';
          if (sdUrl && s.includes(sdUrl)) {
            r.selfdestructEv.push(s.slice(0, 80));
            clientScores[clientName] = (clientScores[clientName] || 0) + 30;
            r.confidence = Math.max(r.confidence, 10);
          }
          for (const ua of profile.ua_strings || []) {
            if (s.includes(ua.split('/')[0])) {
              r.selfdestructEv.push(`UA:${s.slice(0, 60)}`);
              clientScores[clientName] = (clientScores[clientName] || 0) + 25;
              r.confidence = Math.max(r.confidence, 9);
            }
          }
        }
      }
      if (hits.length) r.infectedClasses.push([classPaths[ci], hits.slice(0, 4)]);
    } catch {}
  }

  const ddProfile = profiles.Doomsday;
  if (ddProfile?.doomsday_markers) {
    const ddHits = ddProfile.doomsday_markers.filter(m => names.some(n => n.includes(m))).length;
    if (ddHits >= 3) {
      clientScores.Doomsday = (clientScores.Doomsday || 0) + ddHits * 15;
      r.notes.push(`Doomsday structural markers: ${ddHits} matched`);
      r.confidence = Math.max(r.confidence, 9);
    }
  }

  if (r.structureMatch) {
    const [smClient, smScore] = r.structureMatch;
    clientScores[smClient] = (clientScores[smClient] || 0) + (smScore >= 0.6 ? 20 : 12);
  }

  if (Object.keys(clientScores).length)
    r.detectedClient = Object.entries(clientScores).sort((a,b) => b[1]-a[1])[0][0];

  r.cheatStrings = [...new Set(r.cheatStrings)].slice(0, 50);

  const cheatThresh = hcfg.confidence_cheat_threshold || 8;
  const minStrings  = hcfg.min_cheat_strings_for_flag || 4;

  if      (r.spoofEvidence.length && r.clientPackages.length) { r.verdict = 'CHEAT'; r.confidence = Math.max(r.confidence, 10); }
  else if (r.clientPackages.length)                           { r.verdict = 'CHEAT'; }
  else if (r.selfdestructEv.length)                           { r.verdict = 'CHEAT'; r.confidence = Math.max(r.confidence, 9); }
  else if (r.cheatStrings.length >= 5 && r.confidence >= 6)  { r.verdict = 'CHEAT'; }
  else if (r.cheatStrings.length && r.confidence >= cheatThresh) { r.verdict = 'CHEAT'; }
  else if (r.cheatStrings.length >= minStrings || r.notes.length) { r.verdict = 'SUSPICIOUS'; }
  else r.verdict = 'CLEAN';

  return r;
}

// ── format scan result ─────────────────────────────────────────────────────
function formatScanResult(r) {
  const lines = [];
  if (r.skipReason && r.verdict === 'CLEAN') {
    lines.push(c(GR)(`  ├─ ${r.filename.padEnd(48)}`) + c(GN)('  ✓ legit')); return lines;
  }
  if (r.verdict === 'CLEAN') {
    lines.push(c(GR)(`  ├─ ${r.filename.padEnd(48)}`) + c(GN)('  ✓ clean')); return lines;
  }
  if (r.verdict === 'ERROR') {
    lines.push(c(GR)(`  ├─ ${r.filename.padEnd(48)}`) + c(GR)(`  — ${r.skipReason}`)); return lines;
  }
  const color = r.verdict === 'CHEAT' ? c(RD, BOLD) : c(YL);
  const prob  = r.probability();
  lines.push('');
  lines.push(c(GR)('  ┌─ ') + color(r.filename));
  if (r.modId)          lines.push(c(GR)('  │  ') + c(WH)('Mod ID   ') + c(GR)(r.modId));
  if (r.detectedClient) lines.push(c(GR)('  │  ') + c(WH)('Client   ') + color(r.detectedClient));
  r.spoofEvidence.forEach(ev => lines.push(c(GR)('  │  ') + c(WH)('Spoof    ') + c(RD, BOLD)(ev)));
  r.clientPackages.slice(0,3).forEach(pkg => lines.push(c(GR)('  │  ') + c(WH)('Package  ') + color(pkg)));
  if (r.mixinPkgs.length)     lines.push(c(GR)('  │  ') + c(WH)('Mixins   ') + c(MG)(r.mixinPkgs.slice(0,3).join(', ')));
  if (r.selfdestructEv.length) lines.push(c(GR)('  │  ') + c(WH)('SelfDest ') + c(RD, BOLD)(r.selfdestructEv[0].slice(0, 55)));
  if (r.cheatStrings.length) {
    let cs = r.cheatStrings.slice(0, 8).join(', ');
    if (r.cheatStrings.length > 8) cs += ` (+${r.cheatStrings.length - 8})`;
    lines.push(c(GR)('  │  ') + c(WH)('Strings  ') + color(cs));
  }
  r.notes.slice(0,2).forEach(note => lines.push(c(GR)('  │  ') + c(WH)('Note     ') + c(YL)(note.slice(0, 60))));
  lines.push(c(GR)('  └─ ') + c(WH)('Verdict  ') + color(r.verdict) + c(GR)('  ·  ') + c(WH)(`${prob}% confidence`));
  lines.push('');
  return lines;
}

// ── walk dir ───────────────────────────────────────────────────────────────
function walkDir(dir, skipSet, onFile, onProgress) {
  let count = 0;
  function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!e.name.startsWith('$') && !skipSet.has(e.name.toLowerCase())) walk(full);
      } else {
        count++;
        if (onProgress && count % 500 === 0) onProgress(count);
        onFile(full, e.name);
      }
    }
  }
  walk(dir);
}

function getScanRoots() {
  if (ghostState.active && ghostState.paths.length) return [...ghostState.paths];
  const roots = [];
  for (const [name, paths2] of Object.entries(KNOWN_LAUNCHERS)) {
    for (const p2 of paths2) {
      if (!fs.existsSync(p2)) continue;
      if (MULTI_PROFILE_LAUNCHERS.has(name)) {
        try {
          fs.readdirSync(p2, { withFileTypes: true }).forEach(e => {
            if (e.isDirectory()) roots.push(path.join(p2, e.name));
          });
        } catch {}
      } else {
        roots.push(p2);
      }
      break;
    }
  }
  if (ghostState.focusPaths.length) return [...new Set([...ghostState.focusPaths, ...roots])];
  return [...new Set(roots)];
}

// ── scan phases ────────────────────────────────────────────────────────────
function phase0LogScan(gameRoot, maxDepth = 4) {
  section('PHASE 0 — Log & Modloader Scan');
  divider();
  let clean = true;
  const logTermsMap = getLogCleanTermsMap();
  const logsDir = path.join(gameRoot, 'logs');
  if (fs.existsSync(logsDir)) {
    tlog(`Scanning logs: ${logsDir}`, 'scan');
    for (const logFile of ['latest.log', 'debug.log']) {
      const logPath = path.join(logsDir, logFile);
      if (!fs.existsSync(logPath)) continue;
      try {
        const content = fs.readFileSync(logPath, 'utf8').toLowerCase();
        for (const [clientName, terms] of Object.entries(logTermsMap)) {
          for (const term of terms) {
            if (content.includes(term.toLowerCase())) {
              tlog(`LOG HIT  [${clientName}]  '${term}' in ${logFile}`, 'bad');
              allFindings.log_hits.push({ file: logFile, path: logPath, term, client: clientName });
              allFindings.summary.log_tampering++;
              scanCounters.red++;
              clean = false;
            }
          }
        }
        const stat = fs.statSync(logPath);
        if (Date.now() - stat.mtimeMs < 600000) tlog('Log recently modified — may have been cleaned', 'warn');
      } catch (e) { tlog(`Log read error: ${e}`, 'warn'); }
    }
    const crashDir = path.join(gameRoot, 'crash-reports');
    if (fs.existsSync(crashDir)) {
      try {
        fs.readdirSync(crashDir).slice(-10).forEach(fname => {
          const fpath = path.join(crashDir, fname);
          try {
            const content = fs.readFileSync(fpath, 'utf8').toLowerCase();
            for (const [clientName, terms] of Object.entries(logTermsMap)) {
              for (const term of terms) {
                if (content.includes(term.toLowerCase())) {
                  tlog(`CRASH HIT  [${clientName}]  ${fname}`, 'bad');
                  allFindings.log_hits.push({ file: fname, path: fpath, term, client: clientName, type: 'crash' });
                  allFindings.summary.log_tampering++;
                  scanCounters.red++;
                  clean = false;
                }
              }
            }
          } catch {}
        });
      } catch {}
    }
  } else { tlog('No logs directory found', 'info'); }
  if (clean) { tlog('Logs: clean ✓', 'ok'); scanCounters.green++; }
}

function phase1ConfigScan(gameRoot) {
  section('PHASE 1 — Config Directory Scan');
  divider();
  let clean = true;
  const configRoot = path.join(gameRoot, 'config');
  if (!fs.existsSync(configRoot)) { tlog('No config directory found', 'info'); return; }
  tlog(`Scanning: ${configRoot}`, 'scan');
  const configDirsMap  = getConfigDirsMap();
  const configFilesMap = getConfigFilesMap();
  const moduleNames    = getAllModuleNames();

  for (const [clientName, dirs] of Object.entries(configDirsMap)) {
    for (const d of dirs) {
      const fullDir = path.join(configRoot, d);
      if (fs.existsSync(fullDir)) {
        let contents = [];
        try { contents = fs.readdirSync(fullDir); } catch {}
        tlog(`CONFIG DIR  [${clientName.toUpperCase()}]  ${fullDir}  (${contents.length} files)`, 'bad');
        allFindings.config_hits.push({ client: clientName, type: 'directory', path: fullDir });
        allFindings.summary.private_hits++;
        scanCounters.red++;
        clean = false;
      }
    }
  }

  function walkConfig(dir, depth) {
    if (depth > 4) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    const relDir = path.relative(configRoot, dir).replace(/\\/g, '/');
    const pathClients = new Set();
    for (const [clientName, dirs] of Object.entries(configDirsMap)) {
      for (const d of dirs) {
        const dn = d.replace(/\\/g, '/').replace(/\/$/, '');
        if (relDir === dn || relDir.startsWith(dn + '/')) pathClients.add(clientName);
      }
    }
    for (const e of entries) {
      const fpath = path.join(dir, e.name);
      if (e.isDirectory()) { walkConfig(fpath, depth + 1); continue; }
      scanCounters.total++;
      if (pathClients.size === 1) {
        const clientName = [...pathClients][0];
        tlog(`CONFIG FILE  [${clientName.toUpperCase()}]  ${fpath}`, 'bad');
        allFindings.config_hits.push({ client: clientName, type: 'file', path: fpath });
        allFindings.summary.private_hits++;
        scanCounters.red++;
        clean = false;
      } else if (!pathClients.size) {
        const fname = e.name.toLowerCase();
        for (const [clientName, cfgFiles] of Object.entries(configFilesMap)) {
          if (cfgFiles.map(f => f.toLowerCase()).includes(fname)) {
            tlog(`CONFIG FILE  [${clientName.toUpperCase()}]  ${fpath}`, 'bad');
            allFindings.config_hits.push({ client: clientName, type: 'file', path: fpath });
            allFindings.summary.private_hits++;
            scanCounters.red++;
            clean = false;
          }
        }
      }
    }
  }
  walkConfig(configRoot, 0);
  if (clean) { tlog('Config: clean ✓', 'ok'); scanCounters.green++; }
}

async function phase2Scanner(modsDir, paranoid = false) {
  section('PHASE 2 — Velocity Jar Scanner');
  divider();
  if (!fs.existsSync(modsDir)) { tlog(`Mods directory not found: ${modsDir}`, 'info'); return; }
  let jars;
  try { jars = fs.readdirSync(modsDir).filter(f => f.toLowerCase().endsWith('.jar')); }
  catch { return; }
  if (!jars.length) { tlog('No JARs in mods directory', 'info'); return; }
  // Pre-hash all jars and query Modrinth in parallel before the scan loop
  tlog(`Modrinth hash pre-pass: ${jars.length} JARs...`, 'scan');
  const jarPaths = jars.map(j => path.join(modsDir, j));
  await preloadModrinthHashes(jarPaths);
  tlog(`Scanning ${jars.length} JARs${paranoid ? ' (paranoid)' : ''}`, 'scan');
  setScannerStatus('running');
  const custom = ghostState.active ? ghostState.strings : null;
  const start  = Date.now();
  for (let i = 0; i < jars.length; i++) {
    drawProgress(`Scanning [${i}/${jars.length}]`, i, jars.length, etaStr(Date.now() - start, i + 1, jars.length));
    const jarPath = path.join(modsDir, jars[i]);
    scanCounters.jars++;
    scanCounters.total++;
    try {
      const r = analyzeJar(jarPath, custom ? new Set(custom) : null, paranoid);
      if (r.verdict === 'CHEAT') {
        scanCounters.red++;
        const name = r.detectedClient || 'Unknown';
        if (r.sha256Val) recordBadHash(r.sha256Val, name, jarPath);
        learnStructure(name, r.classBasenames);
        tlog(`FLAGGED  CHEAT  ${c(RD, BOLD)(name)}  ·  ${r.filename}  ·  ${c(YL)(r.probability() + '%')}`, 'bad');
        allFindings.scanner.push({ path: jarPath, verdict: 'CHEAT', client: name, confidence: r.probability(), strings: r.cheatStrings.slice(0,10) });
        allFindings.summary.private_hits++;
        formatScanResult(r).forEach(l => p(l));
      } else if (r.verdict === 'SUSPICIOUS') {
        scanCounters.yellow++;
        tlog(`SUSPICIOUS  ${r.filename}`, 'warn');
        allFindings.scanner.push({ path: jarPath, verdict: 'SUSPICIOUS', strings: r.cheatStrings.slice(0,5) });
      } else { scanCounters.green++; }
    } catch (e) { tlog(`Scan error on ${jars[i]}: ${e}`, 'warn'); setScannerStatus('warn'); }
  }
  process.stdout.write('\r\x1b[K');
  const cheats = allFindings.scanner.filter(x => x.verdict === 'CHEAT').length;
  if (cheats > 0) {
    setScannerStatus('warn');
    tlog(`Scan done · ${jars.length} JARs · ${c(RD,BOLD)(cheats + ' CHEAT(S)')} · ${((Date.now()-start)/1000).toFixed(1)}s`, 'bad');
  } else {
    setScannerStatus('idle');
    tlog(`Scan done · ${jars.length} JARs · clean · ${((Date.now()-start)/1000).toFixed(1)}s`, 'ok');
  }
}

function doDnsScan() {
  tlog('DNS cache scan...', 'scan');
  try {
    const result = spawnSync('ipconfig', ['/displaydns'], { encoding: 'utf8', timeout: 15000 });
    const raw = result.stdout || '';
    for (const line of raw.split('\n')) {
      if (!line.includes('Record Name')) continue;
      const entry = line.split(':')[1]?.trim().toLowerCase().replace(/\.$/, '') || '';
      for (const bad of CHEAT_DOMAINS) {
        if (entry.includes(bad)) {
          tlog(`CHEAT DOMAIN  ${entry}`, 'bad');
          allFindings.dns_flags.push({ entry, matched: bad });
          allFindings.summary.dns_hits++;
          scanCounters.red++;
        }
      }
    }
  } catch (e) { tlog(`DNS failed: ${e}`, 'warn'); }
}

function doProcessScan() {
  tlog('Process scan...', 'scan');
  try {
    const result = spawnSync('tasklist', ['/fo', 'csv', '/nh'], { encoding: 'utf8', timeout: 15000 });
    const lines = (result.stdout || '').split('\n');
    for (const line of lines) {
      const name     = line.split(',')[0]?.replace(/"/g,'').toLowerCase().replace('.exe','') || '';
      const pidMatch = line.match(/"(\d+)"/);
      const pid      = pidMatch ? pidMatch[1] : '?';
      for (const cl of CLICKER_NAMES) {
        if (name.includes(cl)) {
          tlog(`CLICKER  ${name} [PID ${pid}]`, 'bad');
          allFindings.process_flags.push({ pid, name, type: 'clicker' });
          scanCounters.red++;
          break;
        }
      }
      for (const bp of BYPASS_NAMES) {
        if (name.includes(bp)) {
          tlog(`BYPASS TOOL  ${name} [PID ${pid}]`, 'bad');
          allFindings.process_flags.push({ pid, name, type: 'bypass' });
          scanCounters.red++;
          break;
        }
      }
    }
  } catch (e) { tlog(`Process scan failed: ${e}`, 'warn'); }
}

function doRegistryScan() {
  if (!IS_WIN) return;
  tlog('Registry scan...', 'scan');
  const keywords = [...Object.keys(getConfigDirsMap()), ...CLICKER_NAMES, ...BYPASS_NAMES].map(k => k.toLowerCase());
  const runKeys  = [
    'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  ];
  for (const key of runKeys) {
    try {
      const result = spawnSync('reg', ['query', key], { encoding: 'utf8', timeout: 10000 });
      for (const line of (result.stdout || '').split('\n')) {
        const ll = line.toLowerCase();
        for (const kw of keywords) {
          if (ll.includes(kw)) {
            tlog(`REGISTRY  ${line.trim().slice(0, 70)}`, 'bad');
            allFindings.registry_flags.push({ key, value: line.trim() });
            scanCounters.red++;
            break;
          }
        }
      }
    } catch {}
  }
}

function doPrefetchScan() {
  const pfDir = 'C:\\Windows\\Prefetch';
  if (!fs.existsSync(pfDir)) { tlog('Prefetch: need Administrator', 'warn'); return; }
  tlog('Prefetch scan...', 'scan');
  const flags = [...Object.keys(getConfigDirsMap()), ...CLICKER_NAMES, ...BYPASS_NAMES, 'cheatengine','x64dbg','x32dbg'].map(f => f.toLowerCase());
  try {
    for (const fname of fs.readdirSync(pfDir)) {
      if (!fname.endsWith('.pf')) continue;
      const exe  = fname.split('-')[0].toLowerCase();
      const flag = flags.find(f => exe.includes(f));
      if (flag) {
        const fpath = path.join(pfDir, fname);
        const mtime = fs.statSync(fpath).mtime;
        tlog(`PREFETCH  ${exe.toUpperCase()}  last run ${mtime.toISOString().slice(0,19)}`, 'bad');
        allFindings.prefetch_flags.push({ file: fname, last_run: mtime.toISOString() });
        scanCounters.red++;
      }
    }
  } catch (e) { tlog(`Prefetch error: ${e}`, 'warn'); }
}

// ── case files & verdict ────────────────────────────────────────────────────
function buildCaseFiles() {
  const cases = {};
  function getCase(client) {
    if (!cases[client]) cases[client] = { jars: [], configs: [], logs: [], confidence: 0 };
    return cases[client];
  }
  for (const e of allFindings.scanner) {
    const c2 = getCase(e.client || 'Unknown');
    if (e.path && !c2.jars.includes(e.path)) c2.jars.push(e.path);
    c2.confidence = Math.max(c2.confidence, e.confidence || 0);
  }
  for (const e of allFindings.config_hits) {
    if (!e.client) continue;
    const c2 = getCase(e.client);
    if (e.path && !c2.configs.includes(e.path)) c2.configs.push(e.path);
  }
  for (const e of allFindings.log_hits) {
    if (!e.client) continue;
    const c2 = getCase(e.client);
    if (e.path && !c2.logs.includes(e.path)) c2.logs.push(e.path);
  }
  return cases;
}

function renderCaseFiles() {
  const cases = buildCaseFiles();
  if (!Object.keys(cases).length) return;
  p('');
  p(c(GR)('[') + c(MG)('>') + c(GR)('] ') + c(WH, BOLD)('Detected clients — /open <n> to open in explorer'));
  divider();
  for (const [client, cs] of Object.entries(cases).sort((a,b) => b[1].confidence-a[1].confidence)) {
    const confStr = cs.confidence ? `  ${cs.confidence}% confidence` : '';
    p(c(RD, BOLD)(`  ${client}`) + c(GR)(confStr));
    for (const jp of cs.jars) {
      p(`    ${linkRef(jp,'jar')}  ${c(GR)('[jar]')}     ${c(WH)(path.basename(jp))}`);
      p(`         ${c(DIM,GR)(jp)}`);
    }
    for (const cp of cs.configs) {
      p(`    ${linkRef(cp,'config')}  ${c(GR)('[config]')}  ${c(WH)(path.basename(cp))}`);
      p(`         ${c(DIM,GR)(cp)}`);
    }
    for (const lp of cs.logs) {
      p(`    ${linkRef(lp,'log')}  ${c(GR)('[log]')}     ${c(WH)(path.basename(lp))}`);
      p(`         ${c(DIM,GR)(lp)}`);
    }
    p('');
  }
}

function saveReport() {
  try {
    const ts = new Date().toISOString().replace(/[:.]/g,'').slice(0,15).replace('T','_');
    const reportPath = path.join(os.homedir(), 'Desktop', `velocity_report_${ts}.json`);
    fs.writeFileSync(reportPath, JSON.stringify({
      timestamp: ts, preset: activePreset.name,
      scan_counters: scanCounters, findings: allFindings,
    }, null, 2));
    return reportPath;
  } catch { return null; }
}

function printVerdict() {
  renderCaseFiles();
  p(''); divider();
  const { green: g, yellow: y, red: r, total: t, jars: j } = scanCounters;
  row('Files scanned',    t, 'info');
  row('JARs analyzed',    j, 'info');
  row('Clean',            g, 'clean');
  row('Suspicious',       y, 'warn');
  row('Flagged',          r, r > 0 ? 'bad' : 'clean');
  row('Log tampering',    allFindings.summary.log_tampering, allFindings.summary.log_tampering ? 'bad' : 'clean');
  row('DNS hits',         allFindings.summary.dns_hits,      allFindings.summary.dns_hits      ? 'bad' : 'clean');
  divider();
  if (r === 0 && y === 0) p(c(GN, BOLD)('  ✓  CLEAN — no cheat indicators found'));
  else if (r === 0)       p(c(YL, BOLD)(`  ▲  ${y} SUSPICIOUS item(s) — /seeterminal to review`));
  else {
    const names = [...new Set([...allFindings.scanner, ...allFindings.config_hits].map(e=>e.client).filter(Boolean))];
    p(c(RD, BOLD)(`  ✗  FLAGGED — ${r} indicator(s) · ${names.slice(0,4).join(', ')}`));
  }
  divider();
  const rp = saveReport();
  if (rp) p(c(DIM, MG)(`  Report → ${rp}`));
  p('');
}

// ── scan modes ─────────────────────────────────────────────────────────────
async function doFlash(arg = '') {
  SCAN_RUNNING = true; resetRefs();
  const target   = arg.trim().replace(/"/g,'');
  const settings = activePreset.data || {};
  section('FLASH SCAN — logs → config → jars → dns → process');
  divider();
  const mc = target || path.join(appdata, '.minecraft');
  if (!fs.existsSync(mc)) { row('Error', '.minecraft not found', 'warn'); SCAN_RUNNING = false; return; }
  if (target) tlog(`Focused on: ${target}  (this run only)`, 'info');
  phase0LogScan(mc, settings.max_config_depth || 4);
  phase1ConfigScan(mc);
  phase2Scanner(path.join(mc, 'mods'), settings.paranoid_mode || false);
  doDnsScan();
  doProcessScan();
  p(''); drawStatus(); p('');
  printVerdict();
  SCAN_RUNNING = false;
}

async function doPro(arg = '') {
  SCAN_RUNNING = true; resetRefs();
  const target   = arg.trim().replace(/"/g,'');
  const settings = activePreset.data || {};
  section('PRO SCAN — paranoid · every drive · registry · prefetch');
  divider();
  if (!isAdmin()) tlog('Not Administrator — registry/prefetch limited', 'warn');
  const roots = target ? [target] : getScanRoots();
  for (const root of roots) {
    phase0LogScan(root, settings.max_config_depth || 6);
    phase1ConfigScan(root);
    const mods = path.join(root, 'mods');
    if (fs.existsSync(mods)) phase2Scanner(mods, true);
  }
  if (!target) {
    const allJars = [];
    tlog('Building system-wide JAR list...', 'scan');
    let hb = Date.now();
    for (const drive of 'CDEFGH'.split('').map(d => `${d}:\\`)) {
      if (!fs.existsSync(drive)) continue;
      walkDir(drive, DRIVE_WALK_SKIP, (full, fname) => {
        if (fname.toLowerCase().endsWith('.jar')) allJars.push(full);
      }, () => {
        if (Date.now() - hb > 1500) {
          process.stdout.write(`\r\x1b[K  ${c(GR)(`JAR hunt...  ${allJars.length} found so far`)}`);
          hb = Date.now();
        }
      });
    }
    process.stdout.write('\r\x1b[K');
    tlog(`Found ${allJars.length} JARs`, 'ok');
    if (allJars.length) {
      setScannerStatus('running');
      const start = Date.now();
      for (let i = 0; i < allJars.length; i++) {
        drawProgress('System JARs', i, allJars.length, etaStr(Date.now()-start, i+1, allJars.length));
        scanCounters.jars++; scanCounters.total++;
        try {
          const r = analyzeJar(allJars[i], null, true);
          if (r.verdict === 'CHEAT') {
            scanCounters.red++;
            const nm = r.detectedClient || 'Unknown';
            if (r.sha256Val) recordBadHash(r.sha256Val, nm, allJars[i]);
            learnStructure(nm, r.classBasenames);
            tlog(`FLAGGED  CHEAT  ${nm}  ·  ${allJars[i].slice(-60)}`, 'bad');
            allFindings.scanner.push({ path: allJars[i], verdict: 'CHEAT', client: nm, confidence: r.probability() });
            allFindings.summary.private_hits++;
          } else if (r.verdict === 'SUSPICIOUS') { scanCounters.yellow++; }
          else { scanCounters.green++; }
        } catch {}
      }
      process.stdout.write('\r\x1b[K');
      setScannerStatus(scanCounters.red > 0 ? 'warn' : 'idle');
    }
  }
  doRegistryScan();
  doPrefetchScan();
  doDnsScan();
  doProcessScan();
  p(''); drawStatus(); p('');
  printVerdict();
  SCAN_RUNNING = false;
}

async function doMax(arg = '') {
  SCAN_RUNNING = true; resetRefs();
  const target = arg.trim().replace(/"/g,'');
  section('MAX SCAN — every trick in the book');
  divider();
  if (!isAdmin()) tlog('Not Administrator — some features limited', 'warn');
  tlog('MAX 1/10 — Full-depth mode, no scan caps', 'info');
  const roots = target ? [target] : getScanRoots();
  for (const root of roots) {
    phase0LogScan(root, 10);
    phase1ConfigScan(root);
    const mods = path.join(root, 'mods');
    if (fs.existsSync(mods)) phase2Scanner(mods, true);
  }
  tlog('MAX 2/10 — Hash pre-pass (instant renamed-cheat detection)', 'scan');
  const bad     = loadHashStore('known_bad_hashes.json');
  const allJars = [];
  if (!target) {
    tlog('Building system-wide JAR list...', 'scan');
    for (const drive of 'CDEFGH'.split('').map(d => `${d}:\\`)) {
      if (!fs.existsSync(drive)) continue;
      walkDir(drive, DRIVE_WALK_SKIP, (full, fname) => { if (fname.toLowerCase().endsWith('.jar')) allJars.push(full); });
    }
    let hashHits = 0;
    for (const jp of allJars) {
      const h = sha256File(jp);
      if (h && h in bad) { tlog(`HASH HIT  ${bad[h].client}  ·  ${path.basename(jp)}`, 'bad'); scanCounters.red++; hashHits++; }
    }
    if (!hashHits) tlog('  No instant hash hits', 'ok');
  }
  tlog('MAX 3/10 — Recycle Bin sweep', 'scan');
  for (const d of 'CDEFGH'.split('').map(d => `${d}:\\$Recycle.Bin`)) {
    if (!fs.existsSync(d)) continue;
    walkDir(d, new Set(), (full, fname) => {
      if (/\.(jar|json)$/i.test(fname)) {
        tlog(`  Deleted file: ${full}`, 'warn');
        allFindings.config_hits.push({ type:'recycle_bin', path: full });
        scanCounters.yellow++;
      }
    });
  }
  tlog('MAX 4/10 — Downloads/Documents/Videos/Desktop exe scan', 'scan');
  const userDirs = ['Downloads','Documents','Videos','Desktop','Music','Pictures'].map(d => path.join(home, d));
  const looseKw  = [...CLICKER_NAMES, ...BYPASS_NAMES, ...Object.keys(getClientProfiles())].map(k => k.toLowerCase().replace(/[-_]/g,''));
  for (const ud of userDirs) {
    if (!fs.existsSync(ud)) continue;
    try {
      fs.readdirSync(ud).forEach(fname => {
        const stem  = path.parse(fname.toLowerCase()).name.replace(/[-_ ]/g,'');
        const fpath = path.join(ud, fname);
        for (const kw of looseKw) {
          if (kw && stem.includes(kw)) {
            tlog(`  FOUND  '${fname}' in ${path.basename(ud)}`, 'bad');
            allFindings.config_hits.push({ type:'user_dir_tool', path: fpath, match: kw });
            scanCounters.red++;
            break;
          }
        }
      });
    } catch {}
  }
  tlog('MAX 5/10 — Scheduled task persistence check', 'scan');
  try {
    const r = spawnSync('schtasks', ['/query','/fo','CSV'], { encoding:'utf8', timeout:15000 });
    const kws = [...Object.keys(getClientProfiles()), ...CLICKER_NAMES, ...BYPASS_NAMES].map(k=>k.toLowerCase());
    let taskHits = 0;
    for (const line of (r.stdout||'').split('\n')) {
      const ll = line.toLowerCase();
      for (const kw of kws) { if (ll.includes(kw)) { tlog(`  TASK  ${line.trim().slice(0,80)}`, 'bad'); scanCounters.red++; taskHits++; break; } }
    }
    if (!taskHits) tlog('  No suspicious tasks', 'ok');
  } catch {}
  tlog('MAX 6/10 — Startup folder persistence', 'scan');
  const startupDirs = [
    path.join(appdata, 'Microsoft','Windows','Start Menu','Programs','Startup'),
    path.join(process.env.PROGRAMDATA||'', 'Microsoft','Windows','Start Menu','Programs','StartUp'),
  ];
  for (const sd of startupDirs) {
    if (!fs.existsSync(sd)) continue;
    try {
      fs.readdirSync(sd).forEach(fname => {
        const fl = fname.toLowerCase().replace(/[-_]/g,'');
        for (const kw of looseKw) { if (kw && fl.includes(kw)) { tlog(`  STARTUP  ${fname}`, 'bad'); scanCounters.red++; } }
      });
    } catch {}
  }
  tlog('MAX 7/10 — Hosts file tampering check', 'scan');
  try {
    const hosts = fs.readFileSync('C:\\Windows\\System32\\drivers\\etc\\hosts','utf8');
    let hostHits = 0;
    for (const line of hosts.split('\n')) {
      if (!line.trim() || line.trim().startsWith('#')) continue;
      for (const domain of CHEAT_DOMAINS) {
        if (line.toLowerCase().includes(domain)) { tlog(`  HOSTS  ${line.trim().slice(0,70)}`, 'warn'); scanCounters.yellow++; hostHits++; }
      }
    }
    if (!hostHits) tlog('  Hosts file normal', 'ok');
  } catch {}
  tlog('MAX 8/10 — Entropy scan (packed/obfuscated JARs)', 'scan');
  for (const root of roots) {
    const modsDir = path.join(root, 'mods');
    if (!fs.existsSync(modsDir)) continue;
    try {
      fs.readdirSync(modsDir).filter(f=>f.toLowerCase().endsWith('.jar')).forEach(fname => {
        const fpath = path.join(modsDir, fname);
        try {
          const data = fs.readFileSync(fpath).slice(0, 65536);
          const freq = {};
          for (const b of data) freq[b] = (freq[b]||0)+1;
          const entropy = -Object.values(freq).reduce((s,c2) => {
            const p2 = c2/data.length; return s + p2*Math.log2(p2);
          }, 0);
          if (entropy > 7.5) { tlog(`  HIGH ENTROPY  ${fname}  (${entropy.toFixed(2)}/8.0)`, 'warn'); scanCounters.yellow++; }
        } catch {}
      });
    } catch {}
  }
  tlog('MAX 9/10 — Diff against last report', 'scan');
  try {
    const desktop = path.join(home, 'Desktop');
    const reports = fs.readdirSync(desktop).filter(f=>f.startsWith('velocity_report_')&&f.endsWith('.json')).sort();
    if (reports.length > 1) {
      const prev     = JSON.parse(fs.readFileSync(path.join(desktop, reports[reports.length-2]),'utf8'));
      const prevPaths = new Set((prev.findings?.scanner||[]).filter(h=>h.verdict==='CHEAT').map(h=>h.path));
      const curPaths  = new Set(allFindings.scanner.filter(h=>h.verdict==='CHEAT').map(h=>h.path));
      const newOnes   = [...curPaths].filter(p2=>!prevPaths.has(p2));
      if (newOnes.length) newOnes.forEach(np => tlog(`  NEW SINCE LAST SCAN: ${np}`, 'bad'));
      else tlog('  No new detections since last scan', 'ok');
    }
  } catch {}
  tlog('MAX 10/10 — Deep string scan (no class limit)', 'scan');
  const deepJars = target ? [] : [...allJars];
  if (target) walkDir(target, DRIVE_WALK_SKIP, (full, fname) => { if (fname.toLowerCase().endsWith('.jar')) deepJars.push(full); });
  if (deepJars.length) {
    const start = Date.now();
    for (let i = 0; i < deepJars.length; i++) {
      drawProgress('Deep scan', i, deepJars.length, etaStr(Date.now()-start, i+1, deepJars.length));
      try {
        const r = analyzeJar(deepJars[i], null, true);
        if (r.verdict === 'CHEAT') {
          scanCounters.red++;
          const nm = r.detectedClient || 'Unknown';
          if (r.sha256Val) recordBadHash(r.sha256Val, nm, deepJars[i]);
          learnStructure(nm, r.classBasenames);
          tlog(`  DEEP HIT  ${nm}  ·  ${path.basename(deepJars[i])}`, 'bad');
          allFindings.scanner.push({ path: deepJars[i], verdict:'CHEAT', client: nm, confidence: r.probability() });
        } else if (r.verdict === 'SUSPICIOUS') { scanCounters.yellow++; }
        else { scanCounters.green++; }
      } catch {}
    }
    process.stdout.write('\r\x1b[K');
  }
  doRegistryScan(); doPrefetchScan(); doDnsScan(); doProcessScan();
  p(''); drawStatus(); p('');
  printVerdict();
  SCAN_RUNNING = false;
}

// ── individual commands ────────────────────────────────────────────────────
function cmdInspect(arg) {
  p('');
  if (!arg) { p(c(YL)('  Usage: /inspect <jar_path>')); return; }
  let jarPath = arg.trim().replace(/"/g,'');
  if (!fs.existsSync(jarPath)) {
    const mc = path.join(appdata, '.minecraft', 'mods', jarPath);
    if (fs.existsSync(mc)) jarPath = mc;
  }
  if (!fs.existsSync(jarPath)) { p(c(RD)(`  File not found: ${jarPath}`)); return; }
  p(c(MG)(`  Deep scan: ${path.basename(jarPath)}`)); p('');
  const r = analyzeJar(jarPath, null, true);
  formatScanResult(r).forEach(l => p(l));
  if (r.verdict === 'CHEAT' || r.verdict === 'SUSPICIOUS') {
    p(c(GR)('  Package tree:'));
    Object.entries(r.pkgTree).sort((a,b)=>b[1]-a[1]).slice(0,8).forEach(([pkg,cnt]) =>
      p(c(GR)(`    ${pkg.padEnd(48)} ${cnt} classes`)));
  }
  p('');
}

function cmdOpen(arg) {
  p('');
  const n = parseInt(arg);
  if (isNaN(n)) { p(c(YL)(!openableRefs.length ? '  No refs yet — run a scan first' : `  Usage: /open <n>  (1-${openableRefs.length})`)); p(''); return; }
  const [target, err] = openRef(n);
  if (err) p(c(RD)(`  ✗  ${err}`));
  else     p(c(GN)(`  ✓ Opened: ${target}`));
  p('');
}

function cmdPath(args) {
  const tokens = args.split(/\s+/).filter(Boolean);
  p('');
  if (!tokens.length) {
    const chosen = openFolderDialog('Select focus path');
    if (chosen) { ghostState.focusPaths.push(chosen); p(c(GN)(`  ✓ Focus path set: ${chosen}`)); }
    else p(c(YL)('  Cancelled.'));
    p(''); return;
  }
  const sub    = tokens[0].toLowerCase();
  const KNOWN  = new Set(['add','remove','list','clear','focus','explorer']);
  if (!KNOWN.has(sub)) {
    const fpath = args.trim().replace(/"/g,'');
    if (!fs.existsSync(fpath)) { p(c(RD)(`  ✗ Invalid path: ${fpath}`)); p(''); return; }
    if (!ghostState.focusPaths.includes(fpath)) ghostState.focusPaths.push(fpath);
    p(c(GN)(`  ✓ /flash and /pro will focus on: ${fpath}`));
    p(''); return;
  }
  if (sub === 'add' && tokens[1]) {
    const fpath = tokens.slice(1).join(' ').replace(/"/g,'');
    if (!fs.existsSync(fpath)) { p(c(RD)(`  ✗ Not found: ${fpath}`)); p(''); return; }
    if (!ghostState.focusPaths.includes(fpath)) ghostState.focusPaths.push(fpath);
    p(c(GN)(`  ✓ Added: ${fpath}`)); p(''); return;
  }
  if (sub === 'remove') {
    if (tokens[1]) {
      const fpath = tokens.slice(1).join(' ').replace(/"/g,'');
      const idx   = ghostState.focusPaths.indexOf(fpath);
      if (idx >= 0) { ghostState.focusPaths.splice(idx,1); p(c(GN)(`  ✓ Removed: ${fpath}`)); }
      else p(c(YL)(`  Not in list: ${fpath}`));
    } else {
      const n = ghostState.focusPaths.length;
      ghostState.focusPaths.length = 0;
      p(c(GN)(`  ✓ Removed ${n} path(s)`));
    }
    p(''); return;
  }
  if (sub === 'list') {
    p(c(MG, BOLD)('  Focus paths:'));
    (ghostState.focusPaths.length ? ghostState.focusPaths : ['(none)']).forEach(x => p(c(WH)(`    · ${x}`)));
    p(c(MG, BOLD)('  Strings:'));
    (ghostState.strings.length ? ghostState.strings : ['(none)']).forEach(x => p(c(WH)(`    · ${x}`)));
    p(''); return;
  }
  if (sub === 'clear') { ghostState.focusPaths.length = 0; ghostState.strings.length = 0; p(c(GN)('  ✓ Cleared')); p(''); return; }
  p(c(YL)('  /path <path>  |  /path add  |  /path remove  |  /path list  |  /path clear')); p('');
}

function cmdStrings(args) {
  const tokens = args.split(/\s+/).filter(Boolean);
  p('');
  if (!tokens.length) { p(c(YL)('  /strings add <str>  |  list  |  clear')); p(''); return; }
  const sub = tokens[0].toLowerCase();
  if (sub === 'add' && tokens[1]) { ghostState.strings.push(tokens.slice(1).join(' ')); p(c(GN)(`  ✓ Added: ${tokens.slice(1).join(' ')}`)); p(''); return; }
  if (sub === 'list') {
    p(c(MG,BOLD)('  Session strings:'));
    (ghostState.strings.length ? ghostState.strings : ['(none)']).forEach(s => p(c(WH)(`    · ${s}`)));
    p(''); return;
  }
  if (sub === 'clear') { ghostState.strings.length = 0; p(c(GN)('  ✓ Cleared')); p(''); return; }
  p(c(YL)('  /strings add <str>  |  list  |  clear')); p('');
}

function cmdGhost() {
  p('');
  if (ghostState.active) { ghostState.active = false; p(c(YL)('  Ghost mode OFF')); }
  else if (!ghostState.paths.length && !ghostState.strings.length) { p(c(YL)('  Set paths first with /path')); }
  else {
    ghostState.active = true;
    p(c(GN)('  Ghost mode ON'));
    ghostState.paths.forEach(pp   => p(c(GR)(`    path: ${pp}`)));
    ghostState.strings.forEach(s  => p(c(GR)(`    string: ${s}`)));
  }
  p('');
}

function cmdWhitelist(args) {
  const tokens = args.split(/\s+/).filter(Boolean);
  p('');
  if (!tokens.length) {
    const store   = loadHashStore('whitelist.json');
    const entries = Object.entries(store);
    if (!entries.length) p(c(GR)('  Whitelist empty.'));
    else entries.forEach(([sha, entry]) => p(c(WH)(`  ${sha.slice(0,16)}...`) + c(GR)(`  ${entry.path || ''}`)));
    p(''); return;
  }
  if (tokens[0] === 'add' && tokens[1]) {
    const n = parseInt(tokens[1]);
    if (isNaN(n) || n < 1 || n > openableRefs.length) { p(c(RD)(`  ✗ Invalid ref: ${tokens[1]}`)); p(''); return; }
    const fpath = openableRefs[n-1].path;
    const sha   = sha256File(fpath);
    if (!sha) { p(c(RD)('  ✗ Could not hash file')); p(''); return; }
    addToWhitelist(sha, fpath);
    p(c(GN)(`  ✓ Whitelisted: ${fpath}`)); p(''); return;
  }
  if (tokens[0] === 'remove' && tokens[1]) {
    const store   = loadHashStore('whitelist.json');
    const matches = Object.keys(store).filter(h => h.startsWith(tokens[1]));
    if (!matches.length) { p(c(YL)('  No matching hash')); p(''); return; }
    matches.forEach(h => delete store[h]);
    saveHashStore('whitelist.json', store);
    p(c(GN)(`  ✓ Removed ${matches.length} entr(y/ies)`)); p(''); return;
  }
  p(c(YL)('  /whitelist  |  /whitelist add <n>  |  /whitelist remove <hash-prefix>')); p('');
}

function cmdHistory() {
  p(); section('COMMAND HISTORY'); divider();
  if (!commandHistory.length) p(c(GR)('  No commands run yet.'));
  else commandHistory.slice(-30).forEach((cmd, i) => p(c(GR)(`  ${String(i+1).padStart(3)}.  `) + c(WH)(cmd)));
  p('');
}

function cmdStats() {
  p(); section('SCAN STATS'); divider();
  const desktop = path.join(home, 'Desktop');
  let reports = [];
  try { reports = fs.readdirSync(desktop).filter(f=>f.startsWith('velocity_report_')&&f.endsWith('.json')).reverse().slice(0,10); } catch {}
  if (!reports.length) { p(c(GR)('  No saved reports yet.')); p(''); return; }
  for (const fname of reports) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(desktop, fname),'utf8'));
      const red  = data.summary?.private_hits || 0;
      const ts   = fname.replace('velocity_report_','').replace('.json','');
      p(c(WH)(`  ${ts}  `) + (red ? c(RD,BOLD)(`${red} flagged`) : c(GN)('clean')));
    } catch {}
  }
  p('');
}

function cmdElevate() {
  p('');
  if (isAdmin()) { p(c(GN)('  ✓ Already Administrator')); p(''); return; }
  try {
    const script = process.argv[1];
    spawnSync('powershell', ['-NoProfile','-Command',`Start-Process -FilePath "node" -ArgumentList "'${script}'" -Verb runAs`], { detached: true });
    p(c(GN)('  ✓ Relaunching as Administrator'));
  } catch (e) { p(c(RD)(`  ✗  ${e}`)); }
  p('');
}

function cmdReport() {
  p(); section('SAVED REPORTS'); divider();
  const desktop = path.join(home, 'Desktop');
  let reports = [];
  try { reports = fs.readdirSync(desktop).filter(f=>f.startsWith('velocity_report_')&&f.endsWith('.json')).reverse(); } catch {}
  if (!reports.length) { p(c(GR)('  No reports on Desktop.')); p(''); return; }
  reports.slice(0,20).forEach((rp, i) => {
    const mtime = fs.statSync(path.join(desktop, rp)).mtime.toISOString().slice(0,16).replace('T',' ');
    p(c(WH)(`  ${i+1}.  `) + c(MG)(rp) + c(GR)(`  ${mtime}`));
  });
  p('');
}

function cmdSeeterminal() {
  p(); section('LIVE TERMINAL'); divider();
  if (!terminalLog.length) p(c(GR)('  No scan output yet.'));
  else terminalLog.forEach(l => p(l));
  p('');
}

function cmdWindow() {
  p('');
  try {
    spawn('node', [process.argv[1]], { detached: true, stdio: 'ignore', windowsHide: false });
    p(c(GN)('  ✓ New Velocity window opened'));
  } catch (e) { p(c(RD)(`  Failed: ${e}`)); }
  p('');
}

function cmdHelp() {
  p(); section('HELP — commands'); divider();
  const cmds = [
    ['/flash [path]',        'Logs → Config → JARs → DNS → Process (.minecraft only)'],
    ['/flash <path>',        'Same, focused on that path this run only'],
    ['/pro [path]',          'Paranoid · every drive · registry · prefetch'],
    ['/max [path]',          'Everything + 10 exclusive deep passes — no limits'],
    ['/inspect <jar>',       'Deep single-JAR scan'],
    ['/open <n>',            'Open a scan result reference by number'],
    ['/whitelist add <n>',   'Permanently whitelist file by hash (survives renames)'],
    ['/whitelist',           'List whitelisted files'],
    ['/path <path>',         'Focus /flash and /pro on this path'],
    ['/path add <path>',     'Same as /path <path>'],
    ['/path remove [path]',  'Remove focus path'],
    ['/path list',           'List focus paths and session strings'],
    ['/strings add <s>',     'Add custom detection string to session'],
    ['/strings list/clear',  'Manage session strings'],
    ['/ghost',               'Toggle ghost mode'],
    ['/history',             'Show last 30 commands'],
    ['/stats',               'Quick trend from last 10 reports'],
    ['/elevate',             'Relaunch as Administrator'],
    ['/report',              'Browse saved reports'],
    ['/seeterminal',         'Replay scan log'],
    ['/window',              'Open second Velocity window'],
    ['/clear',               'Clear screen'],
    ['/exit',                'Exit'],
  ];
  const mw = Math.max(...cmds.map(([cmd])=>cmd.length)) + 2;
  cmds.forEach(([cmd, desc]) => p(c(MG,BOLD)(`  ${cmd.padEnd(mw)}`) + c(GR)('  ·  ') + c(WH)(desc)));
  p('');
}

// ── REPL ───────────────────────────────────────────────────────────────────
async function repl() {
  loadData();
  activePreset.data = {};
  banner();
  p(c(GR)('  /help for commands  ·  Tab = autocomplete  ·  Ctrl+C = cancel scan'));
  p('');
  while (true) {
    const gt     = ghostState.active ? c(MG)('[ghost] ') : '';
    const prompt = c(GR)('  ') + gt + c(MG,BOLD)('>') + c(GR)(' ');
    let raw;
    try { raw = await readLine(prompt); } catch { break; }
    if (raw === '__CTRLC__') {
      if (SCAN_RUNNING) { SCAN_RUNNING = false; p(''); p(c(YL,BOLD)('  ▲  Scan cancelled')); p(''); }
      else { p(c(GR)('  Ctrl+C — /exit to quit')); p(''); }
      continue;
    }
    raw = raw.trim();
    if (!raw) continue;
    const [command, ...rest] = raw.split(/\s+/);
    const arg = rest.join(' ');
    resetState();
    try {
      switch(command.toLowerCase()) {
        case '/help':        cmdHelp();             break;
        case '/clear':       banner();              break;
        case '/exit':
        case '/quit':        p(c(GR)('  Goodbye.')); p(''); process.exit(0); break;
        case '/flash':       await doFlash(arg);          break;
        case '/pro':         await doPro(arg);            break;
        case '/max':         await doMax(arg);            break;
        case '/inspect':     cmdInspect(arg);       break;
        case '/open':        cmdOpen(arg);          break;
        case '/whitelist':   cmdWhitelist(arg);     break;
        case '/path':        cmdPath(arg);          break;
        case '/strings':     cmdStrings(arg);       break;
        case '/ghost':       cmdGhost();            break;
        case '/history':     cmdHistory();          break;
        case '/stats':       cmdStats();            break;
        case '/elevate':     cmdElevate();          break;
        case '/report':      cmdReport();           break;
        case '/seeterminal': cmdSeeterminal();      break;
        case '/window':      cmdWindow();           break;
        default: p(c(YL)(`  Unknown: ${command}  — /help`)); p('');
      }
    } catch (e) {
      if (e.message === 'SCAN_CANCELLED') { p(''); p(c(YL,BOLD)('  ▲  Scan cancelled')); p(''); }
      else { SCAN_RUNNING = false; p(''); p(c(RD)(`  ✗  Error: ${e.message}`)); p(''); }
    }
  }
}

repl().catch(e => { if (e.code !== 'ERR_USE_AFTER_CLOSE') console.error(e); });
