#!/bin/bash
# topos REGISTER/PUBLISH topology hiding with SQLite storage

. include/common
. include/require.sh

SRV=5060
UAS=5070
UAC=5080
DB_FILE="/tmp/topos_reg_pub_test.db"
LOG_FILE="${RUN_DIR}/topos_reg_pub.log"
CFG=topos_reg_pub.cfg

if ! (check_sipp && check_kamailio \
		&& check_module "db_sqlite" && check_module "topos" \
		&& check_module "topoh"); then
	exit 0
fi

cleanup() {
	kill_kamailio 2>/dev/null
	killall -9 sipp 2>/dev/null
	rm -f "$DB_FILE" "$LOG_FILE" "${CFG}.bak"
}
trap cleanup EXIT

setup_db() {
	rm -f "$DB_FILE"
	sqlite3 "$DB_FILE" <<'EOSQL'
CREATE TABLE version (
    id INTEGER PRIMARY KEY NOT NULL,
    table_name VARCHAR(32) NOT NULL,
    table_version INTEGER DEFAULT 0 NOT NULL
);
CREATE TABLE topos_d (
    id INTEGER PRIMARY KEY NOT NULL,
    rectime DATETIME NOT NULL,
    x_context VARCHAR(64) DEFAULT '' NOT NULL,
    s_method VARCHAR(64) DEFAULT '' NOT NULL,
    s_cseq VARCHAR(64) DEFAULT '' NOT NULL,
    a_callid VARCHAR(255) DEFAULT '' NOT NULL,
    a_uuid VARCHAR(255) DEFAULT '' NOT NULL,
    b_uuid VARCHAR(255) DEFAULT '' NOT NULL,
    a_contact VARCHAR(512) DEFAULT '' NOT NULL,
    b_contact VARCHAR(512) DEFAULT '' NOT NULL,
    as_contact VARCHAR(512) DEFAULT '' NOT NULL,
    bs_contact VARCHAR(512) DEFAULT '' NOT NULL,
    a_tag VARCHAR(255) DEFAULT '' NOT NULL,
    b_tag VARCHAR(255) DEFAULT '' NOT NULL,
    a_rr TEXT, b_rr TEXT, s_rr TEXT,
    iflags INTEGER DEFAULT 0 NOT NULL,
    a_uri VARCHAR(255) DEFAULT '' NOT NULL,
    b_uri VARCHAR(255) DEFAULT '' NOT NULL,
    r_uri VARCHAR(255) DEFAULT '' NOT NULL,
    a_srcaddr VARCHAR(128) DEFAULT '' NOT NULL,
    b_srcaddr VARCHAR(128) DEFAULT '' NOT NULL,
    a_socket VARCHAR(128) DEFAULT '' NOT NULL,
    b_socket VARCHAR(128) DEFAULT '' NOT NULL
);
CREATE TABLE topos_t (
    id INTEGER PRIMARY KEY NOT NULL,
    rectime DATETIME NOT NULL,
    x_context VARCHAR(64) DEFAULT '' NOT NULL,
    s_method VARCHAR(64) DEFAULT '' NOT NULL,
    s_cseq VARCHAR(64) DEFAULT '' NOT NULL,
    a_callid VARCHAR(255) DEFAULT '' NOT NULL,
    a_uuid VARCHAR(255) DEFAULT '' NOT NULL,
    b_uuid VARCHAR(255) DEFAULT '' NOT NULL,
    direction INTEGER DEFAULT 0 NOT NULL,
    x_via TEXT,
    x_vbranch VARCHAR(255) DEFAULT '' NOT NULL,
    x_rr TEXT, y_rr TEXT, s_rr TEXT,
    x_uri VARCHAR(255) DEFAULT '' NOT NULL,
    a_contact VARCHAR(512) DEFAULT '' NOT NULL,
    b_contact VARCHAR(512) DEFAULT '' NOT NULL,
    as_contact VARCHAR(512) DEFAULT '' NOT NULL,
    bs_contact VARCHAR(512) DEFAULT '' NOT NULL,
    x_tag VARCHAR(255) DEFAULT '' NOT NULL,
    a_tag VARCHAR(255) DEFAULT '' NOT NULL,
    b_tag VARCHAR(255) DEFAULT '' NOT NULL,
    a_srcaddr VARCHAR(255) DEFAULT '' NOT NULL,
    b_srcaddr VARCHAR(255) DEFAULT '' NOT NULL,
    a_socket VARCHAR(128) DEFAULT '' NOT NULL,
    b_socket VARCHAR(128) DEFAULT '' NOT NULL
);
INSERT INTO version (table_name, table_version) VALUES ('topos_d', 2);
INSERT INTO version (table_name, table_version) VALUES ('topos_t', 2);
EOSQL
}

count_topos_d() {
	sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM topos_d;"
}

start_kamailio() {
	$BIN -L "$MOD_DIR" -Y "$RUN_DIR" -P "$PIDFILE" -w . \
		-f "$CFG" -E -e > "$LOG_FILE" 2>&1 &
	sleep 2
	test -f "$PIDFILE"
}

setup_db
start_kamailio || exit 1

# Verify enable_reg_pub modparam is accepted (kamailio started)
grep -q "enable_reg_pub" "$CFG" || exit 1

sipp -sf topos_reg_pub_uas.xml -i 127.0.0.1 -p "$UAS" -m 1 -timeout 30s -trace_err \
	> "${RUN_DIR}/topos_reg_pub_uas.log" 2>&1 &
UAS_PID=$!
sleep 1

sipp -sf topos_reg_pub_uac.xml -i 127.0.0.1 -p "$UAC" -m 1 -timeout 30s -trace_err \
	127.0.0.1:"$SRV" > "${RUN_DIR}/topos_reg_pub_uac.log" 2>&1 || true
wait "$UAS_PID" 2>/dev/null

# TOPOS must store at least one dialog row for REGISTER
DLG_COUNT=$(count_topos_d)
if [ "$DLG_COUNT" -lt 1 ]; then
	exit 1
fi

# Topology hiding: upstream Contact in 200 should be masked (atpsh prefix from topoh)
if ! grep -q "atpsh-" "${RUN_DIR}/topos_reg_pub_uac.log" \
		"${RUN_DIR}/topos_reg_pub_uac_"*_errors.log 2>/dev/null; then
	# also accept in uac main log body
	if ! grep -q "atpsh-" "${RUN_DIR}/topos_reg_pub_uac.log"; then
		exit 1
	fi
fi

# PUBLISH smoke: storage path accepts PUBLISH when enable_reg_pub=1
killall -9 sipp 2>/dev/null
sipp -sf topos_reg_pub_publish_uas.xml -i 127.0.0.1 -p "$UAS" -m 1 -timeout 15s \
	> /dev/null 2>&1 &
sleep 1
sipp -sf topos_reg_pub_publish_uac.xml -i 127.0.0.1 -p "$UAC" -m 1 -timeout 15s \
	127.0.0.1:"$SRV" > /dev/null 2>&1 || true

BR_COUNT=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM topos_t;")
if [ "$BR_COUNT" -lt 1 ]; then
	exit 1
fi

exit 0
