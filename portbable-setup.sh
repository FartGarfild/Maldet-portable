#!/usr/bin/env bash
#
# Portable Linux Malware Detect Setup
# Распакуйте архив maldet и запустите этот скрипт один раз
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MALDET_DIR="$SCRIPT_DIR/maldetect"

echo "==================================================="
echo "Portable Linux Malware Detect Setup"
echo "==================================================="

# Проверка наличия исходных файлов
if [ ! -d "files" ]; then
    echo "ERROR: 'files' directory not found!"
    echo "Please extract the full maldet archive first."
    exit 1
fi

# Создание портативной структуры
echo "[1/6] Creating directory structure..."
mkdir -p "$MALDET_DIR"/{clean,pub,quarantine,sess,sigs,tmp,logs,internals,cron}
chmod 755 "$MALDET_DIR"
chmod 750 "$MALDET_DIR"/{quarantine,sess,tmp} 2>/dev/null

# Копирование файлов
echo "[2/6] Copying files..."
cp -pR files/* "$MALDET_DIR/" 2>/dev/null
chmod 755 "$MALDET_DIR/maldet"

# Копирование документации
cp -f CHANGELOG COPYING.GPL README "$MALDET_DIR/" 2>/dev/null

# Патчинг основного скрипта maldet
echo "[3/6] Patching maldet script..."
if [ -f "$MALDET_DIR/maldet" ]; then
    cp "$MALDET_DIR/maldet" "$MALDET_DIR/maldet.original"
    
    # Заменяем строку inspath в начале файла
    sed -i.tmp 's|^inspath=.*|inspath="$(cd "$(dirname "$0")" \&\& pwd)"|' "$MALDET_DIR/maldet" 2>/dev/null || \
    sed -i '' 's|^inspath=.*|inspath="$(cd "$(dirname "$0")" \&\& pwd)"|' "$MALDET_DIR/maldet" 2>/dev/null
    
    rm -f "$MALDET_DIR/maldet.tmp" 2>/dev/null
    echo "✓ maldet script patched"
else
    echo "ERROR: maldet script not found!"
    exit 1
fi

# КРИТИЧЕСКИ ВАЖНО: Патчим internals/internals.conf
echo "[4/6] Patching internals/internals.conf..."
if [ -f "$MALDET_DIR/internals/internals.conf" ]; then
    cp "$MALDET_DIR/internals/internals.conf" "$MALDET_DIR/internals/internals.conf.original"
    
    # Создаём полностью новый internals.conf с относительными путями
    # Теперь $inspath будет определён в главном скрипте maldet
    cat > "$MALDET_DIR/internals/internals.conf" << 'INTERNALS_EOF'
#
# Linux Malware Detect v1.6.6
#             (C) 2002-2025, R-fx Networks <proj@r-fx.org>
#             (C) 2025, Ryan MacDonald <ryan@r-fx.org>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
# PORTABLE VERSION - paths are relative to $inspath (defined in main maldet script)
#

# Core paths - $inspath is set in the main maldet script
intcnf="$inspath/internals/internals.conf"
libpath="$inspath/internals"
intfunc="$libpath/functions"

logdir="$inspath/logs"
confpath="$inspath"
cnffile="conf.maldet"
cnf="$confpath/$cnffile"
varlibpath="$inspath"
maldet_log="$logdir/event_log"
maldet_log_truncate="1"

clamscan_log="$logdir/clamscan_log"
datestamp=`date +"%y%m%d-%H%M"`
utime=`date +"%s"`
user=`whoami`
base_domain="cdn.rfxn.com"

if [ "$OSTYPE" == "FreeBSD" ]; then
        md5sum="/sbin/md5 -q"
else
        md5sum=`command -v md5sum 2> /dev/null`
fi

hostid=`command -v hostid 2> /dev/null`
if [ "$hostid" ]; then
        hostid=`$hostid | $md5sum | awk '{print$1}'`
else
        hostid=`uname -a | $md5sum | awk '{print$1}'`
fi
storename_prefix="$hostid.$RANDOM"

od=`command -v od 2> /dev/null`
find=`command -v find 2> /dev/null`
perl=`command -v perl 2> /dev/null`
nice=`command -v nice 2> /dev/null`
cpulimit=`command -v cpulimit 2> /dev/null`
ionice=`command -v ionice 2> /dev/null`
wc=`command -v wc 2> /dev/null`
mail=`command -v mail 2> /dev/null`
sendmail=`command -v sendmail 2> /dev/null`
wget=`command -v wget 2> /dev/null`
curl=`command -v curl 2> /dev/null`
pidof=`command -v pidof 2> /dev/null`
sed=`command -v sed 2> /dev/null`
stat=`command -v stat 2> /dev/null`
logger=`command -v logger 2> /dev/null`
clamscan_extraopts=""
clamdscan_extraopts=""
clamdscan=`command -v clamdscan 2> /dev/null`

ignore_paths="$confpath/ignore_paths"
ignore_sigs="$confpath/ignore_sigs"
ignore_inotify="$confpath/ignore_inotify"
ignore_file_ext="$confpath/ignore_file_ext"
quardir="$varlibpath/quarantine"
sessdir="$varlibpath/sess"
sigdir="$varlibpath/sigs"
cldir="$varlibpath/clean"
tmpdir="$inspath/tmp"
userbasedir="$varlibpath/pub"
hits_history="$sessdir/hits.hist"
quar_history="$sessdir/quarantine.hist"
clean_history="$sessdir/clean.hist"
suspend_history="$sessdir/suspend.hist"
monitor_scanned_history="$sessdir/monitor.scanned.hist"

sig_version_file="$sigdir/maldet.sigs.ver"
if [ -f "$sig_version_file" ]; then
        sig_version=`cat $sig_version_file`
fi
sig_version_url="https://$base_domain/downloads/maldet.sigs.ver"
sig_sigpack_url="https://$base_domain/downloads/maldet-sigpack.tgz"
sig_clpack_url="https://$base_domain/downloads/maldet-cleanv2.tgz"

sig_md5_file="$sigdir/md5v2.dat"
sig_hex_file="$sigdir/hex.dat"
sig_yara_file="$sigdir/rfxn.yara"
sig_cav_hex_file="$sigdir/rfxn.ndb"
sig_cav_md5_file="$sigdir/rfxn.hdb"
sig_user_md5_file="$sigdir/custom.md5.dat"
sig_user_hex_file="$sigdir/custom.hex.dat"

lmd_version_file="$inspath/VERSION"
lmd_version="$ver"
lmd_referer="LMD:$ver:$hostid"
lmd_verprehook_url="https://$base_domain/downloads/maldet.prehook.ver"
lmd_sigprehook_url="https://$base_domain/downloads/maldet.prehook.sig"
lmd_hash_file="$inspath/internals/VERSION.hash"
lmd_hash_url="https://$base_domain/downloads/maldet.current.hash"
lmd_version_url="https://$base_domain/downloads/maldet.current.ver"
lmd_current_tgzbase_url="https://$base_domain/downloads"
lmd_current_tgzfile="maldetect-current.tar.gz"

dig=`command -v dig 2> /dev/null`
nslookup=`command -v nslookup 2> /dev/null`
if [ -f "/var/cpanel/mainip" ]; then
        remote_ip=`cat /var/cpanel/mainip`
elif [ -f "$dig" ]; then
        remote_ip=`$dig +short +time=3 +retry=2 myip.opendns.com @resolver1.opendns.com`
elif [ -f "$nslookup" ]; then
        remote_ip=`$nslookup -sil -querytype=A myip.opendns.com resolver1.opendns.com | awk '/^Address: / { print $2 ; exit }'`
fi
remote_uri_timeout="30"
remote_uri_retries="4"
clamav_paths="/usr/local/cpanel/3rdparty/share/clamav/ /var/lib/clamav/ /var/clamav/ /usr/share/clamav/ /usr/local/share/clamav"
tlog="$libpath/tlog"
inotify=`command -v inotifywait 2> /dev/null`
inotify_log="$inspath/logs/inotify_log"
inotify_user_instances=128
inotify_trim=131072
hex_fifo_path="$varlibpath/internals/hexfifo"
hex_fifo_script="$libpath/hexfifo.pl"
hex_string_script="$libpath/hexstring.pl"
scan_user_access_minuid=100
find_opts="-regextype posix-egrep"
email_template="$libpath/scan.etpl"
email_panel_alert_etpl="$libpath/panel_alert.etpl"
email_subj="maldet alert from $(hostname)"
cron_custom_exec="$confpath/cron/custom.cron"
cron_custom_conf="$confpath/cron/conf.maldet.cron"
compatcnf="$libpath/compat.conf"

if [ "$OSTYPE" == "FreeBSD" ]; then
        sed="$sed -E"
        find_opts=""
fi
INTERNALS_EOF
    
    echo "✓ internals.conf patched with relative paths"
else
    echo "ERROR: internals.conf not found!"
    exit 1
fi

# Создание launcher-скрипта
echo "[5/6] Creating launcher script..."
cat > "$SCRIPT_DIR/maldet" << 'LAUNCHER_EOF'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/maldetect/maldet" "$@"
LAUNCHER_EOF
chmod +x "$SCRIPT_DIR/maldet"

# Создание конфигурации
echo "[6/6] Initializing configuration..."
touch "$MALDET_DIR/logs/event_log"
chmod 640 "$MALDET_DIR/logs/event_log" 2>/dev/null

# Создание файлов истории
touch "$MALDET_DIR/sess/"{hits.hist,quarantine.hist,clean.hist,suspend.hist,monitor.scanned.hist} 2>/dev/null

# Создание README для пользователя
cat > "$SCRIPT_DIR/PORTABLE_README.txt" << 'README_EOF'
PORTABLE LINUX MALWARE DETECT
==============================

Установка завершена!

ИСПОЛЬЗОВАНИЕ:
--------------
1. Запуск из текущей директории:
   ./maldet [options]

2. Запуск напрямую:
   ./maldetect/maldet [options]

3. Добавьте в PATH (опционально):
   export PATH="$(pwd):$PATH"
   maldet [options]

ОСНОВНЫЕ КОМАНДЫ:
-----------------
./maldet -u                    # Обновить сигнатуры
./maldet -a /path/to/scan      # Сканировать директорию
./maldet -l                    # Показать последние сканирования
./maldet -r SCANID             # Показать отчёт сканирования
./maldet -q SCANID             # Поместить найденное в карантин
./maldet --restore FILE        # Восстановить из карантина
./maldet -h                    # Показать справку

ФАЙЛЫ И ДИРЕКТОРИИ:
-------------------
./maldetect/conf.maldet        # Конфигурация
./maldetect/logs/              # Логи
./maldetect/quarantine/        # Карантин
./maldetect/sigs/              # Сигнатуры вредоносов
./maldetect/sess/              # Сессии сканирования

ПРИМЕЧАНИЯ:
-----------
- Для сканирования системных директорий может потребоваться root
- ClamAV интеграция работает если ClamAV установлен в системе
- Автоматические cron-задачи НЕ установлены
- Архив можно переносить между системами
- Оригинальные файлы сохранены с расширением .original

ОБНОВЛЕНИЕ СИГНАТУР:
--------------------
Перед первым использованием ОБЯЗАТЕЛЬНО обновите базы:
./maldet -u

ПЕРЕНОС НА ДРУГУЮ СИСТЕМУ:
---------------------------
tar -czf maldet-portable.tar.gz maldetect-1.6.6/
# На новой системе:
tar -xzf maldet-portable.tar.gz
cd maldetect-1.6.6
./maldet -u
./maldet -a /path/to/scan

README_EOF

echo ""
echo "==================================================="
echo "✓ Portable setup completed!"
echo "==================================================="
echo ""
echo "Location: $MALDET_DIR"
echo "Launcher: $SCRIPT_DIR/maldet"
echo ""

# Тестовый запуск
echo "Testing portable setup..."
if "$SCRIPT_DIR/maldet" -h > /dev/null 2>&1; then
    echo "✓ maldet is working correctly!"
    echo ""
    echo "Quick start:"
    echo "  ./maldet -u              # Update signatures (REQUIRED!)"
    echo "  ./maldet -a /path        # Scan directory"
    echo ""
else
    echo "✗ maldet test failed!"
    echo ""
    echo "Please check manually:"
    echo "  ./maldet -h"
    echo ""
    echo "If errors persist, check:"
    echo "  - maldetect/maldet line ~11 should have relative inspath"
    echo "  - maldetect/internals/internals.conf should use \$inspath variables"
    exit 1
fi

echo "Read PORTABLE_README.txt for full instructions"
echo ""

# Предложение обновить сигнатуры
read -p "Update malware signatures now? (recommended) [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Updating signatures..."
    "$SCRIPT_DIR/maldet" --update 1
    echo ""
fi

echo "Setup complete! Use: ./maldet [options]"
echo ""
