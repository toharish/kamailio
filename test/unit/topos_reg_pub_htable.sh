#!/bin/bash
# topos REGISTER topology hiding with htable storage

. include/common
. include/require.sh

LOG_FILE="${RUN_DIR}/topos_reg_pub_htable.log"
CFG=topos_reg_pub_htable.cfg

if ! (check_kamailio \
		&& check_module "topos" && check_module "topoh" \
		&& check_module "topos_htable" && check_module "htable"); then
	exit 0
fi

cleanup() {
	kill_kamailio 2>/dev/null
	rm -f "$LOG_FILE" "${CFG}.bak"
}
trap cleanup EXIT

$BIN -L "$MOD_DIR" -Y "$RUN_DIR" -P "$PIDFILE" -w . \
	-f "$CFG" -E -e > "$LOG_FILE" 2>&1 &
sleep 2
test -f "$PIDFILE"
