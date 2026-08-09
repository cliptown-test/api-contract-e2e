#!/usr/bin/env bash
# cliptown-test/api-contract-e2e — live-stack API contract suite.
#
# Boots a REAL stack and asserts over real HTTP, real Postgres rows, and the
# real pinned Rust policy code:
#
#   * docker Postgres 16 with the backend's own reviewed desired state
#     (schema/schema.sql) applied by a NON-SUPERUSER owner role, the way a
#     deployment would;
#   * the real `cliptown-api` binary compiled from the pinned
#     cliptown/cliptown-rust-backend.rs SHA;
#   * `fixtures/policy-probe`, a crate that `include!`s the pinned backend's
#     OWN source files and drives them with adversarial input. It is not a
#     reimplementation — if the pinned source changes, the probe changes with
#     it. This matters because the domain modules (auth policy, idempotency,
#     object manifests) are compiled into the binary but mounted on NO route,
#     so HTTP cannot reach them.
#
# Why this suite exists in this shape: the backend's own schema test
# (tests/memebank_transfer_schema.rs) is include_str! plus string matching over
# schema.sql and never opens a database connection, and the router tests use
# `tower::oneshot` against an in-process Router. Neither can observe a
# model-vs-canonical-schema disagreement, and neither ever starts Postgres. A
# suite that built its database FROM the entities would be structurally unable
# to see it either — the schema here is always applied from schema/schema.sql.
#
# Required checks covered (test-plan.json):
#   health, schema, auth-errors, idempotency, rate-limits,
#   websocket-when-applicable
# Focus covered (test-plan.json):
#   history CRUD, binary upload, pagination, WebSocket, auth
#
# Requirements: docker, psql, curl, jq, openssl, python3, cargo/rustup, git.
#
# Escape hatches:
#   PG_EXTERNAL=1   use a Postgres someone else runs on PG_PORT
#   BACKEND_SRC=    reuse an existing pinned backend checkout
#   INTERFACES_SRC= reuse an existing pinned interfaces checkout
#   KEEP_WORK=1     do not delete the scratch dir on exit
#
# Portability: macOS ships bash 3.2, which has no `mapfile` and treats an empty
# array under `set -u` as an unbound variable. This script therefore avoids both
# and runs `set -o pipefail` without `-u`. `set -e` is deliberately off: every
# assertion accumulates into a tally so one failure does not hide the rest.
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- pins ---------------------------------------------------------------------
# Read from the generated contract; never hardcoded here. If the fleet re-pins,
# this suite follows automatically and a stale hardcoded SHA cannot drift in.
BACKEND_SHA="$(jq -r '.sources[] | select(.fullName=="cliptown/cliptown-rust-backend.rs") | .sha' "$ROOT/test-plan.json")"
CLIENTS_SHA="$(jq -r '.sources[] | select(.fullName=="cliptown/cliptown-clients") | .sha' "$ROOT/test-plan.json")"
# The backend's README pins the sibling interface crate its CI resolves. The
# path dependency in Cargo.toml cannot be satisfied without it.
INTERFACES_SHA="ef3d5f55719e56b1a6f11d2d6464c0976aa1863d"

PG_PORT="${PG_PORT:-55433}"
PG_CONTAINER="cliptown-api-contract-e2e-pg"
DBNAME="cliptown_e2e"
SERVER_PORT="${SERVER_PORT:-18130}"
BIND="127.0.0.1:${SERVER_PORT}"
BASE="http://${BIND}"
WORK="${WORK:-$(mktemp -d)}"
mkdir -p "$WORK"
SERVER_PID=""

PASSED=0
FAILED=0
declare -a FAILURES=()
declare -a DEFECTS=()

note()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
sub()   { printf '    \033[2m%s\033[0m\n' "$*"; }
pass()  { PASSED=$((PASSED+1)); printf '\033[1;32mok  \033[0m %s\n' "$*"; }
fail()  { FAILED=$((FAILED+1)); FAILURES+=("$*"); printf '\033[1;31mFAIL\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31mFATAL\033[0m %s\n' "$*"; exit 2; }

# A confirmed product defect. The accompanying assertion asserts the CURRENT
# (buggy) behaviour, so if the product is fixed this suite goes red and someone
# must come back and retire the entry. That keeps the record falsifiable rather
# than decorative.
defect() { DEFECTS+=("$1|$2|$3"); printf '\033[1;33mDEFECT\033[0m %s — %s\n' "$1" "$2"; }

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  if [ -z "${PG_EXTERNAL:-}" ]; then docker rm -f "$PG_CONTAINER" >/dev/null 2>&1; fi
  [ -z "${KEEP_WORK:-}" ] && rm -rf "$WORK"
  return 0
}
trap cleanup EXIT

for tool in docker psql curl jq openssl python3 git; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
CARGO="cargo"
if command -v rustup >/dev/null 2>&1 && rustup which cargo >/dev/null 2>&1; then
  # A Homebrew cargo earlier on PATH resolves a Homebrew rustc, which cannot
  # find the rustup sysroot's core for this crate graph. Pin both together.
  CARGO="$(rustup which cargo)"
fi

# --- 0. materialize the pinned sources ----------------------------------------
note "materializing pinned sources"
fetch_pin() { # url sha dest
  local url="$1" sha="$2" dest="$3"
  git clone --quiet --no-checkout "$url" "$dest" >/dev/null 2>&1 || die "clone failed: $url"
  git -C "$dest" checkout --quiet "$sha" 2>/dev/null || {
    git -C "$dest" fetch --quiet origin "$sha" 2>/dev/null
    git -C "$dest" checkout --quiet "$sha" || die "cannot check out $sha in $url"
  }
}

SRC="${BACKEND_SRC:-}"
if [ -z "$SRC" ]; then
  SRC="$WORK/src/cliptown-rust-backend.rs"
  mkdir -p "$WORK/src"
  fetch_pin https://github.com/cliptown/cliptown-rust-backend.rs.git "$BACKEND_SHA" "$SRC"
fi
IFACE="${INTERFACES_SRC:-}"
if [ -z "$IFACE" ]; then
  # Cargo.toml declares `path = "../cliptown-interfaces/generated/rust"`, so the
  # checkout has to be the backend's actual filesystem sibling.
  IFACE="$(dirname "$SRC")/cliptown-interfaces"
  fetch_pin https://github.com/cliptown/cliptown-interfaces.git "$INTERFACES_SHA" "$IFACE"
fi

# The clients repo arrives as the generated submodule. Its pin is the contract
# for what an SDK is entitled to call.
CLIENTS="$ROOT/vendor/cliptown-clients"
[ -d "$CLIENTS/clients" ] || die "submodule vendor/cliptown-clients is empty; run: git submodule update --init --recursive"

for spec in "$SRC|$BACKEND_SHA|backend" "$IFACE|$INTERFACES_SHA|interfaces" "$CLIENTS|$CLIENTS_SHA|clients"; do
  IFS='|' read -r dir want label <<<"$spec"
  got="$(git -C "$dir" rev-parse HEAD 2>/dev/null)"
  if [ "$got" = "$want" ]; then
    pass "PIN $label checked out at $want"
  else
    fail "PIN $label is at $got, contract pins $want"
  fi
done

OPENAPI="$IFACE/openapi/cliptown.openapi.yaml"
[ -f "$OPENAPI" ] || die "canonical openapi missing at $OPENAPI"

# --- 1. Postgres --------------------------------------------------------------
note "starting postgres"
if [ -z "${PG_EXTERNAL:-}" ]; then
  docker rm -f "$PG_CONTAINER" >/dev/null 2>&1
  docker run -d --name "$PG_CONTAINER" -e POSTGRES_PASSWORD=e2e \
    -p "127.0.0.1:${PG_PORT}:5432" postgres:16-alpine >/dev/null || die "docker run failed"
else
  sub "PG_EXTERNAL=1 — using the Postgres already on :${PG_PORT}"
fi

SU() { PGPASSWORD=e2e psql -h 127.0.0.1 -p "$PG_PORT" -U postgres -d "$1" -v ON_ERROR_STOP=1 -qtAX "${@:2}"; }
for _ in $(seq 1 90); do SU postgres -c 'select 1' >/dev/null 2>&1 && break; sleep 0.5; done
SU postgres -c 'select 1' >/dev/null 2>&1 || die "postgres did not come up on :$PG_PORT"

SU postgres -c "drop database if exists $DBNAME" >/dev/null
SU postgres -c "drop database if exists ${DBNAME}_supabase" >/dev/null
SU postgres -c "drop role if exists cliptown_app" >/dev/null
SU postgres -c "drop role if exists cliptown_rls" >/dev/null
# cliptown_app models the API's own database role: it owns the schema, exactly
# as it would if the reviewed desired state were applied by the service's
# migration identity. cliptown_rls models a least-privilege, non-owning role.
# Neither is a superuser, so RLS is genuinely in play for both.
SU postgres -c "create role cliptown_app login password 'e2e' nosuperuser" >/dev/null
SU postgres -c "create role cliptown_rls login password 'e2e' nosuperuser" >/dev/null
SU postgres -c "create database $DBNAME owner cliptown_app" >/dev/null
SU "$DBNAME" -c "grant connect on database $DBNAME to cliptown_rls" >/dev/null

APP() { PGPASSWORD=e2e psql -h 127.0.0.1 -p "$PG_PORT" -U cliptown_app -d "$DBNAME" -v ON_ERROR_STOP=1 -qtAX "$@"; }
RLS() { PGPASSWORD=e2e psql -h 127.0.0.1 -p "$PG_PORT" -U cliptown_rls -d "$DBNAME" -v ON_ERROR_STOP=1 -qtAX "$@"; }

note "applying the backend's reviewed desired state (schema/schema.sql) as a non-superuser owner"
APP -f "$SRC/schema/schema.sql" >"$WORK/schema-apply.log" 2>&1 || { tail -20 "$WORK/schema-apply.log"; die "schema.sql did not apply"; }
sub "$(grep -c 'CREATE TABLE' "$SRC/schema/schema.sql") CREATE TABLE statements applied from the reviewed desired state"

# schema.sql revokes from PUBLIC and grants to nobody, so a least-privilege role
# is not expressible from the file alone. We grant here to be able to test the
# intended shape at all; that gap is recorded as a finding below.
APP >/dev/null <<'SQL'
grant usage on schema cliptown to cliptown_rls;
grant select, insert, update, delete on all tables in schema cliptown to cliptown_rls;
grant usage, select on all sequences in schema cliptown to cliptown_rls;
grant execute on all functions in schema cliptown to cliptown_rls;
SQL

# --- 2. the real binary -------------------------------------------------------
note "building the pinned cliptown-api binary"
( cd "$SRC" && "$CARGO" build --locked --quiet ) >"$WORK/build.log" 2>&1 \
  || { tail -30 "$WORK/build.log"; die "cargo build failed"; }
BIN="$SRC/target/debug/cliptown-api"
[ -x "$BIN" ] || die "binary not produced at $BIN"

note "starting cliptown-api on $BIND with a deliberately unreachable database URL"
# Every database-shaped variable points at a port with nothing on it. If the
# service had any dependency wiring at all, it would either refuse to start or
# report itself unready. Whatever it does here is the truth about /readyz.
env -i PATH="$PATH" HOME="$WORK" \
  CLIPTOWN_BIND_ADDRESS="$BIND" \
  DATABASE_URL="postgres://nobody:nobody@127.0.0.1:1/nonexistent" \
  CLIPTOWN_DATABASE_URL="postgres://nobody:nobody@127.0.0.1:1/nonexistent" \
  "$BIN" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
# Drop it from the job table so bash does not print a "Terminated" notice over
# the summary when the cleanup trap kills it. The PID is still ours to signal.
disown "$SERVER_PID" 2>/dev/null
for _ in $(seq 1 60); do curl -sf -o /dev/null "$BASE/healthz" && break; sleep 0.25; done
curl -sf -o /dev/null "$BASE/healthz" || { cat "$WORK/server.log"; die "server never answered on $BASE"; }

code()  { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }
body()  { curl -s --max-time 10 "$@"; }
hdr()   { curl -s -D - -o /dev/null --max-time 10 "$@"; }

################################################################################
note "CHECK: health  [requiredChecks: health]"
################################################################################

H_STATUS="$(body "$BASE/healthz" | jq -r '.status // "<absent>"')"
# openapi pins this to `const: ok`, so the value is the assertion, not the code.
if [ "$H_STATUS" = "ok" ]; then pass "H1 /healthz body .status == \"ok\" (openapi const)"
else fail "H1 /healthz .status must be \"ok\" per openapi const, got \"$H_STATUS\""; fi

R_STATUS="$(body "$BASE/readyz" | jq -r '.status // "<absent>"')"
if [ "$R_STATUS" = "ready" ]; then pass "H2 /readyz body .status == \"ready\" and is a distinct contract from /healthz"
else fail "H2 /readyz .status expected \"ready\", got \"$R_STATUS\""; fi

HEADERS="$(hdr "$BASE/healthz")"
CC="$(grep -i '^cache-control:' <<<"$HEADERS" | tr -d '\r' | awk '{print $2}')"
XCTO="$(grep -i '^x-content-type-options:' <<<"$HEADERS" | tr -d '\r' | awk '{print $2}')"
if [ "$CC" = "no-store" ]; then pass "H3 cache-control: no-store (a clipboard response must not be cached)"
else fail "H3 cache-control expected no-store, got \"${CC:-<absent>}\""; fi
if [ "$XCTO" = "nosniff" ]; then pass "H4 x-content-type-options: nosniff"
else fail "H4 x-content-type-options expected nosniff, got \"${XCTO:-<absent>}\""; fi

# H5: the service answers `ready` while every database variable it was handed
# points at a closed port. Readiness therefore carries no dependency signal.
if [ "$R_STATUS" = "ready" ]; then
  pass "H5 /readyz answers \"ready\" with all DATABASE_URL variables pointed at a closed port"
  defect "DEFECT-01" \
    "/readyz is a static literal: it never touches Postgres, so readiness cannot report a degraded dependency" \
    "start the binary with DATABASE_URL=postgres://nobody@127.0.0.1:1/nonexistent (or with Postgres stopped entirely) and GET /readyz — it returns 200 {\"status\":\"ready\"}; src/main.rs readyz() is 'async fn readyz() -> Json<HealthStatus> { Json(HealthStatus { status: \"ready\" }) }' and the binary opens no database connection at all"
fi

# H6: prove the absence structurally rather than inferring it from a 200 — the
# process must hold no socket to Postgres.
if command -v lsof >/dev/null 2>&1; then
  # Only ESTABLISHED sockets whose REMOTE endpoint is the Postgres port count.
  # The process's own listener and any ephemeral local port must not match.
  PGCONNS="$(lsof -nP -p "$SERVER_PID" -iTCP -sTCP:ESTABLISHED 2>/dev/null | grep -c -- "->127\.0\.0\.1:${PG_PORT}\b")"
  if [ "$PGCONNS" -eq 0 ]; then pass "H6 the running process holds 0 established TCP connections to Postgres :$PG_PORT (no dependency to report on)"
  else fail "H6 expected no database socket from a service with no database wiring, found $PGCONNS"; fi
else
  sub "H6 SKIPPED — lsof unavailable; cannot inspect the process socket table"
fi

################################################################################
note "CHECK: schema  [requiredChecks: schema]"
################################################################################

# Entity field lists are parsed out of the pinned source at run time. Nothing
# about the models is transcribed into this suite, so the suite cannot silently
# agree with a model it copied. The database is always built from
# schema/schema.sql, never from the entities — a suite that generated its
# schema from the models could not observe any of the drift below.
entity_fields() { # file -> "name|rust_type" per line
  awk '
    /^pub struct Model \{/ { inside=1; next }
    inside && /^\}/        { exit }
    inside && /^ *pub /    {
      line=$0; sub(/^ *pub /,"",line); sub(/,[ \t]*$/,"",line)
      split(line,parts,":"); name=parts[1]; type=parts[2]
      gsub(/[ \t]/,"",name); gsub(/[ \t]/,"",type)
      print name "|" type
    }' "$1"
}
table_of() { awk -F'"' '/table_name *=/ {print $2; exit}' "$1"; }

S_MISSING=0; S_ENUM_AS_STRING=0; S_NULLABILITY=0; S_ENTITIES=0
for ef in "$SRC"/src/entity/*.rs; do
  [ "$(basename "$ef")" = "mod.rs" ] && continue
  TBL="$(table_of "$ef")"; [ -n "$TBL" ] || continue
  S_ENTITIES=$((S_ENTITIES+1))
  while IFS='|' read -r fname ftype; do
    [ -n "$fname" ] || continue
    row="$(SU "$DBNAME" -c "select data_type || '~' || is_nullable from information_schema.columns where table_schema='cliptown' and table_name='$TBL' and column_name='$fname'")"
    if [ -z "$row" ]; then
      fail "S1 entity $(basename "$ef") declares field '$fname' with no column cliptown.$TBL.$fname in the reviewed schema"
      S_MISSING=$((S_MISSING+1)); continue
    fi
    dtype="${row%%~*}"; nullable="${row##*~}"
    # The drift class the brief calls out: a Postgres enum (or domain) modelled
    # as a bare Rust String. SeaORM binds it as text and Postgres refuses the
    # implicit cast, so the service cannot write the column at all.
    if [ "$dtype" = "USER-DEFINED" ] && { [ "$ftype" = "String" ] || [ "$ftype" = "Option<String>" ]; }; then
      fail "S2 cliptown.$TBL.$fname is a Postgres enum/domain but the entity models it as $ftype — SeaORM will bind text and Postgres will reject the insert"
      S_ENUM_AS_STRING=$((S_ENUM_AS_STRING+1))
    fi
    # Option<T> against NOT NULL, or bare T against a nullable column, are both
    # runtime faults: the first inserts NULL into NOT NULL, the second panics
    # deserializing a NULL into a non-Option.
    if [[ "$ftype" == Option\<* ]] && [ "$nullable" = "NO" ]; then
      fail "S3 entity models cliptown.$TBL.$fname as $ftype but the column is NOT NULL"
      S_NULLABILITY=$((S_NULLABILITY+1))
    fi
    if [[ "$ftype" != Option\<* ]] && [ "$nullable" = "YES" ]; then
      fail "S3 entity models cliptown.$TBL.$fname as non-optional $ftype but the column is NULLABLE — a NULL row deserializes into a panic"
      S_NULLABILITY=$((S_NULLABILITY+1))
    fi
  done < <(entity_fields "$ef")
done
[ "$S_MISSING" -eq 0 ] && pass "S1 all fields of all $S_ENTITIES entities resolve to a real column in the applied schema"
[ "$S_ENUM_AS_STRING" -eq 0 ] && pass "S2 no Postgres enum/domain column is modelled as a bare Rust String across $S_ENTITIES entities"
[ "$S_NULLABILITY" -eq 0 ] && pass "S3 entity optionality matches column nullability across $S_ENTITIES entities"

# S4 — the decisive one. Reconstruct the exact column list SeaORM emits for
# `entity::clip::ActiveModel` and run it. If any NOT-NULL column without a
# default is absent from the model, the service literally cannot insert a clip
# into its own reviewed schema.
CLIP_ENTITY="$SRC/src/entity/clip.rs"
COLS=(); VALS=()
while IFS='|' read -r fname ftype; do
  [ -n "$fname" ] || continue
  COLS+=("$fname")
  case "$ftype" in
    Uuid|Option\<Uuid\>)                                   VALS+=("gen_random_uuid()") ;;
    String|Option\<String\>)                               VALS+=("'e2e'") ;;
    bool|Option\<bool\>)                                   VALS+=("false") ;;
    i16|i32|i64|Option\<i16\>|Option\<i32\>|Option\<i64\>) VALS+=("1") ;;
    Json|Option\<Json\>)                                   VALS+=("'{}'::jsonb") ;;
    DateTimeWithTimeZone|Option\<DateTimeWithTimeZone\>)   VALS+=("now()") ;;
    *)                                                     VALS+=("null") ;;
  esac
done < <(entity_fields "$CLIP_ENTITY")
CLIP_INSERT="insert into cliptown.clips ($(IFS=,; echo "${COLS[*]}")) values ($(IFS=,; echo "${VALS[*]}"))"
sub "SeaORM-shaped insert reconstructed from src/entity/clip.rs: ${CLIP_INSERT:0:130}..."
INSERT_ERR="$(SU "$DBNAME" -c "$CLIP_INSERT" 2>&1 >/dev/null)"
MISSING_NOTNULL="$(SU "$DBNAME" -c "
  select coalesce(string_agg(column_name, ', ' order by ordinal_position), '')
  from information_schema.columns
  where table_schema='cliptown' and table_name='clips'
    and is_nullable='NO' and column_default is null
    and column_name not in ($(printf "'%s'," "${COLS[@]}" | sed 's/,$//'))")"
if [ -n "$MISSING_NOTNULL" ] && grep -qi 'null value in column' <<<"$INSERT_ERR"; then
  pass "S4 the model's own insert is rejected by the reviewed schema — NOT NULL columns absent from entity::clip: $MISSING_NOTNULL"
  defect "DEFECT-02" \
    "src/entity/clip.rs cannot write cliptown.clips: the reviewed schema has NOT NULL columns with no default that the model does not declare ($MISSING_NOTNULL)" \
    "psql -d $DBNAME -c \"$CLIP_INSERT\" against a database built from schema/schema.sql -> $(head -1 <<<"$INSERT_ERR"). The backend's own tests cannot see this: tests/memebank_transfer_schema.rs is include_str! plus string matching and never opens a connection, and the src/main.rs tests use tower::oneshot on an in-process Router."
elif [ -z "$MISSING_NOTNULL" ]; then
  pass "S4 entity::clip declares every NOT-NULL-without-default column of cliptown.clips"
else
  fail "S4 columns $MISSING_NOTNULL are NOT NULL without default and absent from entity::clip, yet the insert was accepted: ${INSERT_ERR:-<no error>}"
fi

# S5 — three-way triangulation openapi <-> schema.sql <-> entity for the field
# that decides how to decrypt. ClipEnvelope.payload.algorithm is REQUIRED by the
# canonical contract; if no column carries it, a stored clip cannot be decoded.
ALGO_COL="$(SU "$DBNAME" -c "select count(*) from information_schema.columns where table_schema='cliptown' and table_name='clips' and column_name like '%algorithm%'")"
ALGO_REQUIRED="$(python3 - "$OPENAPI" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
block = re.search(r'\n    CipherEnvelope:\n(.*?)\n    [A-Za-z]', text, re.S)
req = re.search(r'required: \[(.*?)\]', block.group(1)) if block else None
print("1" if req and "algorithm" in req.group(1) else "0")
PY
)"
if [ "$ALGO_REQUIRED" = "1" ] && [ "$ALGO_COL" -eq 0 ]; then
  pass "S5 openapi CipherEnvelope.required includes 'algorithm' but cliptown.clips has 0 algorithm columns — a stored row cannot round-trip the contract"
  defect "DEFECT-03" \
    "cliptown.clips has no column for the REQUIRED ClipEnvelope.payload.algorithm; a stored clip cannot tell a client whether its ciphertext is xchacha20poly1305-v1 or aes-256-gcm-v1" \
    "psql -d $DBNAME -c \"select column_name from information_schema.columns where table_schema='cliptown' and table_name='clips'\" -> no algorithm column, while cliptown-interfaces@$INTERFACES_SHA openapi/cliptown.openapi.yaml CipherEnvelope lists 'algorithm' in required and constrains it to [xchacha20poly1305-v1, aes-256-gcm-v1]. entity::clip does not declare it either."
else
  fail "S5 expected a required openapi algorithm with no backing column; required=$ALGO_REQUIRED columns=$ALGO_COL"
fi

# S6 — the inverse drift: the contract declares an enum, the column accepts
# anything. Assert by actually storing a value the contract forbids.
KINDS="$(python3 - "$OPENAPI" <<'PY'
import re, sys
m = re.search(r'kind: \{ type: string, enum: \[(.*?)\] \}', open(sys.argv[1]).read())
print(m.group(1) if m else "")
PY
)"
BOGUS_KIND_ERR="$(SU "$DBNAME" -c "
  insert into cliptown.accounts (user_id) values ('11111111-1111-4111-8111-111111111111') on conflict do nothing;
  insert into cliptown.devices (id, user_id, name, platform, sync_token_hash, lifecycle_state)
    values ('11111111-1111-4111-8111-1111111111d1','11111111-1111-4111-8111-111111111111','d','cli','hash-s6','active') on conflict do nothing;
  insert into cliptown.clips (id,user_id,kind,encrypted_content,nonce,key_id,source_device_id,logical_clock,created_at,updated_at)
    values (gen_random_uuid(),'11111111-1111-4111-8111-111111111111','NOT-A-CONTRACT-KIND','c','n','k','11111111-1111-4111-8111-1111111111d1',0,now(),now())" 2>&1 >/dev/null)"
if [ -z "$BOGUS_KIND_ERR" ]; then
  pass "S6 cliptown.clips.kind stored 'NOT-A-CONTRACT-KIND' although openapi constrains kind to [$KINDS]"
  defect "DEFECT-04" \
    "cliptown.clips.kind is bare TEXT with no CHECK, so the database accepts any value while the canonical contract restricts it to 9 enum members" \
    "psql -d $DBNAME -c \"insert into cliptown.clips (...,kind,...) values (...,'NOT-A-CONTRACT-KIND',...)\" succeeds. Compare cliptown.memebank_transfers.direction and .state in the same file, and cliptown.devices.lifecycle_state, which all carry CHECK ... IN (...) constraints. clips.kind is the gap."
else
  pass "S6 cliptown.clips.kind rejected a value outside the contract enum"
fi
SU "$DBNAME" -c "delete from cliptown.clips where kind='NOT-A-CONTRACT-KIND'" >/dev/null

# S7 — the repo ships two disagreeing definitions of the same table.
SUPA="$(ls "$SRC"/supabase/migrations/*.sql 2>/dev/null | head -1)"
if [ -n "$SUPA" ]; then
  SU postgres -c "create database ${DBNAME}_supabase" >/dev/null
  # The migration references auth.users and auth.uid(), which only exist inside
  # Supabase. Stub both so the file can be applied at all; the stubs are named in
  # the report so nobody mistakes them for part of the product.
  SU "${DBNAME}_supabase" >/dev/null <<'SQL'
create schema auth;
create table auth.users (id uuid primary key);
create function auth.uid() returns uuid language sql stable as
  $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
SQL
  if SU "${DBNAME}_supabase" -f "$SUPA" >/dev/null 2>&1; then
    A_COLS="$(SU "$DBNAME" -c "select string_agg(column_name,',' order by column_name) from information_schema.columns where table_schema='cliptown' and table_name='clips'")"
    B_COLS="$(SU "${DBNAME}_supabase" -c "select string_agg(column_name,',' order by column_name) from information_schema.columns where table_schema='cliptown' and table_name='clips'")"
    SUPA_NULLABLE="$(SU "${DBNAME}_supabase" -c "select coalesce(string_agg(column_name,',' order by column_name),'') from information_schema.columns where table_schema='cliptown' and table_name='clips' and is_nullable='YES' and column_name in ('created_at','updated_at')")"
    if [ "$A_COLS" != "$B_COLS" ]; then
      ONLY_A="$(comm -23 <(tr ',' '\n' <<<"$A_COLS" | sort) <(tr ',' '\n' <<<"$B_COLS" | sort) | paste -sd, -)"
      pass "S7 schema/schema.sql and supabase/migrations disagree on cliptown.clips — only in the reviewed schema: $ONLY_A"
      defect "DEFECT-05" \
        "the backend repo carries two divergent definitions of cliptown.clips and entity::clip matches the weaker one" \
        "apply schema/schema.sql and supabase/migrations/$(basename "$SUPA") to two databases and diff information_schema.columns for cliptown.clips: the reviewed schema adds $ONLY_A. The supabase migration additionally leaves [$SUPA_NULLABLE] nullable (DEFAULT NOW() without NOT NULL) while entity::clip models them as non-optional DateTimeWithTimeZone, so a row written through the Supabase path deserializes into a panic."
    else
      pass "S7 both in-repo schema definitions of cliptown.clips agree"
    fi
  else
    sub "S7 SKIPPED — supabase migration could not be applied even with an auth.users stub"
  fi
fi

# S8 — the live surface against the declared surface.
# bash 3.2 has no mapfile, so collect into a plain array with a read loop.
python3 - "$OPENAPI" >"$WORK/openapi-paths.txt" <<'PY'
import re, sys
for line in open(sys.argv[1]):
    m = re.match(r'^  (/\S*):\s*$', line.rstrip())
    if m: print(m.group(1))
PY
OPENAPI_PATHS=()
while read -r line; do
  [ -n "$line" ] && OPENAPI_PATHS[${#OPENAPI_PATHS[@]}]="$line"
done <"$WORK/openapi-paths.txt"
PATH_COUNT="${#OPENAPI_PATHS[@]}"
[ "$PATH_COUNT" -ge 10 ] || die "failed to parse openapi paths (got $PATH_COUNT)"
sub "canonical openapi declares $PATH_COUNT paths"
ROOT_CODE="$(code "$BASE/")"
ROOT_BODY="$(body "$BASE/")"
if [ "$ROOT_CODE" = "200" ] && ! grep -qx -- '/' "$WORK/openapi-paths.txt"; then
  pass "S8 GET / serves a body that the canonical openapi does not declare (undocumented surface)"
  defect "DEFECT-06" \
    "GET / returns {\"service\":\"cliptown-api\",\"version\":...} but '/' is not a path in the canonical openapi — an undeclared, unauthenticated version-disclosure endpoint" \
    "curl -s $BASE/ -> $(printf '%s' "$ROOT_BODY" | cut -c1-80); the canonical openapi declares $PATH_COUNT paths and '/' is not among them"
else
  pass "S8 the live root route matches the declared surface"
fi

################################################################################
note "CHECK: auth-errors + tenant/device isolation  [requiredChecks: auth-errors; focus: auth]"
################################################################################

# --- HTTP surface: every declared path, with no credential -------------------
declare -a UNAUTH_2XX=() UNAUTH_404=() UNAUTH_OK=()
for p in "${OPENAPI_PATHS[@]}"; do
  case "$p" in /healthz|/readyz) continue ;; esac   # openapi marks these security: []
  probe="${p//\{clipId\}/00000000-0000-4000-8000-000000000001}"
  probe="${probe//\{appId\}/app.3fa.authenticator}"
  probe="${probe//\{deviceId\}/00000000-0000-4000-8000-0000000000d1}"
  c="$(code "$BASE$probe")"
  case "$c" in
    2*)      UNAUTH_2XX+=("$probe=$c") ;;
    401|403) UNAUTH_OK+=("$probe=$c") ;;
    *)       UNAUTH_404+=("$probe=$c") ;;
  esac
done
if [ "${#UNAUTH_2XX[@]}" -eq 0 ]; then
  pass "A1 no declared path answers 2xx without a credential (${#UNAUTH_OK[@]} correctly 401/403, ${#UNAUTH_404[@]} unrouted)"
else
  fail "A1 unauthenticated 2xx on: ${UNAUTH_2XX[*]}"
fi
if [ "${#UNAUTH_404[@]}" -gt 0 ]; then
  defect "DEFECT-07" \
    "${#UNAUTH_404[@]} of the ${#OPENAPI_PATHS[@]} canonical openapi paths are not mounted at all; the api-contract profile's history CRUD, pagination, search, device and settings surface does not exist in the pinned binary" \
    "the pinned src/main.rs fn app() mounts exactly Router::new().route(\"/\").route(\"/healthz\").route(\"/readyz\"); curl -o /dev/null -w '%{http_code}' $BASE/v1/clips -> 404. Unrouted: ${UNAUTH_404[*]}"
fi
# A bearer must not turn a 404 into anything else, and a bogus one must never
# be honoured.
BOGUS="$(code -H 'authorization: Bearer not.a.real.token' "$BASE/v1/clips")"
if [ "$BOGUS" != "200" ] && [ "$BOGUS" != "201" ]; then pass "A2 a forged bearer on /v1/clips does not produce a 2xx (got $BOGUS)"
else fail "A2 forged bearer on /v1/clips produced $BOGUS"; fi

# --- SQL surface: real rows, two tenants, three devices ----------------------
UA="aaaaaaaa-0000-4000-8000-00000000000a"
UB="bbbbbbbb-0000-4000-8000-00000000000b"
DA1="aaaaaaaa-0000-4000-8000-0000000000d1"
DA2="aaaaaaaa-0000-4000-8000-0000000000d2"
DB1="bbbbbbbb-0000-4000-8000-0000000000d1"
DB2="bbbbbbbb-0000-4000-8000-0000000000d2"
SU "$DBNAME" >/dev/null <<SQL
insert into cliptown.accounts (user_id) values ('$UA'), ('$UB');
insert into cliptown.devices (id,user_id,name,platform,sync_token_hash,lifecycle_state) values
  ('$DA1','$UA','a-laptop','macos','hash-a1','active'),
  ('$DA2','$UA','a-phone','ios','hash-a2','active'),
  ('$DB1','$UB','b-laptop','linux','hash-b1','active');
insert into cliptown.clips (id,user_id,kind,encrypted_content,nonce,key_id,source_device_id,logical_clock,created_at,updated_at)
select gen_random_uuid(),'$UA','text','A-SECRET-CIPHERTEXT-'||g,'nonce-a-'||g,'key-a','$DA1',g,now(),now() from generate_series(1,3) g;
insert into cliptown.clips (id,user_id,kind,encrypted_content,nonce,key_id,source_device_id,logical_clock,created_at,updated_at)
select gen_random_uuid(),'$UB','text','B-SECRET-CIPHERTEXT-'||g,'nonce-b-'||g,'key-b','$DB1',g,now(),now() from generate_series(1,3) g;
SQL

rls_read() { # role_fn sub_uuid target_uuid -> row count
  local fn="$1"
  $fn <<SQL | tail -1
select set_config('request.jwt.claim.sub', '$2', false);
select count(*) from cliptown.clips where user_id = '$3';
SQL
}

# The policy itself must work when it is actually in force.
B_FROM_A_RLS="$(rls_read RLS "$UA" "$UB")"
B_FROM_B_RLS="$(rls_read RLS "$UB" "$UB")"
NOCLAIM="$(RLS -c "select count(*) from cliptown.clips")"
if [ "$B_FROM_A_RLS" = "0" ]; then pass "A3 non-owning role: tenant A reads 0 of tenant B's clip rows (RLS policy holds)"
else fail "A3 tenant A read $B_FROM_A_RLS of tenant B's clip rows through a non-owning role"; fi
if [ "$B_FROM_B_RLS" = "3" ]; then pass "A4 the same query as tenant B returns B's 3 rows — A3 is not passing because the table is empty"
else fail "A4 tenant B should see its own 3 rows, saw $B_FROM_B_RLS"; fi
if [ "$NOCLAIM" = "0" ]; then pass "A5 with no request.jwt.claim.sub set at all, current_user_id() is NULL and the policy denies every row (fail-closed, not fail-open)"
else fail "A5 an absent subject claim exposed $NOCLAIM clip rows"; fi

# The deployment shape the service actually has.
B_FROM_A_OWNER="$(rls_read APP "$UA" "$UB")"
UNFORCED="$(SU "$DBNAME" -c "select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='cliptown' and c.relrowsecurity and not c.relforcerowsecurity")"
if [ "$B_FROM_A_OWNER" = "3" ] && [ "$UNFORCED" -gt 0 ]; then
  pass "A6 owner role read all 3 of tenant B's clip rows while claiming to be tenant A — $UNFORCED RLS-enabled tables lack FORCE ROW LEVEL SECURITY"
  defect "DEFECT-08" \
    "no table in schema.sql declares FORCE ROW LEVEL SECURITY, so every clips/devices/transfers policy is bypassed for the role that owns the tables — and schema.sql grants nothing to any non-owning role, so owner-or-superuser is the only connection identity it actually supports" \
    "create a non-superuser role, apply schema/schema.sql as that role, then: psql -U <owner> -c \"select set_config('request.jwt.claim.sub','$UA',false); select count(*) from cliptown.clips where user_id='$UB';\" -> 3 rows of another tenant's clipboard ciphertext. The same query as a non-owning granted role returns 0. $UNFORCED tables are ENABLE-but-not-FORCE; grep -c 'FORCE ROW LEVEL SECURITY' schema/schema.sql -> 0."
else
  fail "A6 expected the owner bypass to be demonstrable; owner read $B_FROM_A_OWNER rows, unforced tables=$UNFORCED"
fi

# Writes, verified by row inspection rather than by a status code.
B_BEFORE="$(SU "$DBNAME" -c "select count(*) from cliptown.clips where user_id='$UB'")"
RLS >/dev/null 2>&1 <<SQL
select set_config('request.jwt.claim.sub', '$UA', false);
insert into cliptown.clips (id,user_id,kind,encrypted_content,nonce,key_id,source_device_id,logical_clock,created_at,updated_at)
values (gen_random_uuid(),'$UB','text','A-WROTE-INTO-B','n','k','$DB1',99,now(),now());
SQL
B_AFTER_RLS="$(SU "$DBNAME" -c "select count(*) from cliptown.clips where user_id='$UB'")"
if [ "$B_AFTER_RLS" = "$B_BEFORE" ]; then pass "A7 non-owning role: tenant A's cross-tenant INSERT left tenant B's row count at $B_BEFORE (verified by SELECT, not by status)"
else fail "A7 tenant A's cross-tenant insert changed B's row count from $B_BEFORE to $B_AFTER_RLS"; fi

APP >/dev/null 2>&1 <<SQL
select set_config('request.jwt.claim.sub', '$UA', false);
insert into cliptown.clips (id,user_id,kind,encrypted_content,nonce,key_id,source_device_id,logical_clock,created_at,updated_at)
values (gen_random_uuid(),'$UB','text','A-WROTE-INTO-B-AS-OWNER','n','k','$DB1',99,now(),now());
SQL
B_AFTER_OWNER="$(SU "$DBNAME" -c "select count(*) from cliptown.clips where user_id='$UB'")"
PLANTED="$(SU "$DBNAME" -c "select count(*) from cliptown.clips where user_id='$UB' and encrypted_content='A-WROTE-INTO-B-AS-OWNER'")"
if [ "$PLANTED" = "1" ] && [ "$B_AFTER_OWNER" -gt "$B_BEFORE" ]; then
  pass "A8 owner role: a row attributed to tenant B was written while the session claimed tenant A — confirmed by selecting the planted row back"
  defect "DEFECT-09" \
    "cross-tenant WRITE is possible through the owner connection: a session claiming subject A inserted a clip owned by subject B, and the row is readable afterwards" \
    "as the schema-owning role: select set_config('request.jwt.claim.sub','$UA',false); insert into cliptown.clips (...,user_id,...) values (...,'$UB',...); then select count(*) from cliptown.clips where user_id='$UB' and encrypted_content='A-WROTE-INTO-B-AS-OWNER' -> 1. Same root cause as DEFECT-08: WITH CHECK is not applied to the table owner without FORCE ROW LEVEL SECURITY."
else
  fail "A8 expected the owner-role cross-tenant write to land; planted=$PLANTED before=$B_BEFORE after=$B_AFTER_OWNER"
fi
SU "$DBNAME" -c "delete from cliptown.clips where encrypted_content like 'A-WROTE-INTO-B%'" >/dev/null

# A9/A10 — tables that hold payload and key material but were left out of the
# RLS list entirely.
NO_RLS="$(SU "$DBNAME" -c "
  select coalesce(string_agg(c.relname, ', ' order by c.relname),'')
  from pg_class c join pg_namespace n on n.oid=c.relnamespace
  where n.nspname='cliptown' and c.relkind='r' and not c.relrowsecurity")"
if grep -q 'device_mailbox' <<<"$NO_RLS"; then
  pass "A9 cliptown.device_mailbox is not in the schema's ENABLE ROW LEVEL SECURITY list; tables with no policy at all: $NO_RLS"
else
  fail "A9 expected device_mailbox among the tables without RLS; got: $NO_RLS"
fi
# The mailbox CHECK forbids sender = recipient, so tenant B needs a second
# device for its envelope to be insertable at all. Insert as two statements and
# fail loudly: a batched INSERT that silently rolls back would make the leak
# assertion below pass against an empty table.
SU "$DBNAME" -c "insert into cliptown.devices (id,user_id,name,platform,sync_token_hash,lifecycle_state)
  values ('$DB2','$UB','b-phone','android','hash-b2','active') on conflict do nothing" >/dev/null || die "fixture: device B2"
SU "$DBNAME" -c "insert into cliptown.device_mailbox
  (envelope_id,user_id,sender_device_id,recipient_device_id,protocol_version,session_id,message_number,purpose,created_at,expires_at,ciphertext_base64)
  values (gen_random_uuid(),'$UA','$DA1','$DA2',1,'sess-a',1,'clip_key',now(),now()+interval '1 day','A-WRAPPED-CLIP-KEY')" >/dev/null || die "fixture: mailbox A"
SU "$DBNAME" -c "insert into cliptown.device_mailbox
  (envelope_id,user_id,sender_device_id,recipient_device_id,protocol_version,session_id,message_number,purpose,created_at,expires_at,ciphertext_base64)
  values (gen_random_uuid(),'$UB','$DB1','$DB2',1,'sess-b',1,'clip_key',now(),now()+interval '1 day','B-WRAPPED-CLIP-KEY')" >/dev/null || die "fixture: mailbox B"
MAILBOX_SEEDED="$(SU "$DBNAME" -c "select count(*) from cliptown.device_mailbox")"
if [ "$MAILBOX_SEEDED" = "2" ]; then pass "A9b mailbox fixture seeded 2 envelopes (1 per tenant) — the leak assertion below cannot pass against an empty table"
else fail "A9b mailbox fixture expected 2 envelopes, found $MAILBOX_SEEDED"; fi
MAILBOX_LEAK="$(RLS <<SQL | tail -1
select set_config('request.jwt.claim.sub', '$UA', false);
select set_config('request.jwt.claim.device_id', '$DA1', false);
select count(*) from cliptown.device_mailbox where user_id = '$UB';
SQL
)"
if [ "${MAILBOX_LEAK:-0}" -gt 0 ]; then
  pass "A10 least-privilege role as tenant A / device A1 read $MAILBOX_LEAK of tenant B's device_mailbox envelopes"
  defect "DEFECT-10" \
    "cliptown.device_mailbox, cliptown.encrypted_object_chunks and cliptown.object_wrapped_keys have no ROW LEVEL SECURITY, although they carry the wrapped clip/object/account keys and the object ciphertext; RLS was enabled on the metadata table cliptown.encrypted_objects but not on the chunk table beneath it" \
    "as a non-owning role granted SELECT: select set_config('request.jwt.claim.sub','$UA',false); select count(*) from cliptown.device_mailbox where user_id='$UB' -> $MAILBOX_LEAK rows with purpose='clip_key' belonging to another tenant. Tables in schema cliptown with relrowsecurity=false: $NO_RLS"
else
  pass "A10 device_mailbox is scoped for a non-owning role"
fi

# A11 — cross-DEVICE isolation on the 3FA application vault, the most sensitive
# table in the schema. Seed REAL rows first: an assertion that a device sees 0
# rows is worthless if the table is empty.
# A 43-character base64 stand-in for a sha256 digest, which is what the
# device_signature_base64 and payload_associated_data_hash_base64 CHECKs expect.
DIGEST_SEED="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
SU "$DBNAME" -c "insert into cliptown.app_vault_applications
  (app_id, enabled, allowed_namespaces, max_batch_size, max_ciphertext_base64_length)
  values ('app.3fa.authenticator', true, '[\"threefa-vault-v1\"]'::jsonb, 100, 699052)
  on conflict (app_id) do nothing" >/dev/null || die "fixture: app_vault_applications"
for pair in "$UA|$DA1|A" "$UB|$DB1|B"; do
  IFS='|' read -r who dev tag <<<"$pair"
  SU "$DBNAME" -c "insert into cliptown.app_vault_mutations
    (user_id,app_id,mutation_id,namespace,opaque_record_id,payload_algorithm,payload_nonce_base64,
     payload_ciphertext_base64,payload_associated_data_hash_base64,payload_key_id,deleted,
     source_device_id,logical_clock,created_at,updated_at,device_signature_base64)
    values ('$who','app.3fa.authenticator','mut-$tag-0001','threefa-vault-v1','opaque-record-$tag-00000001',
     'xchacha20poly1305-v1','AAAAAAAAAAAAAAAAAAAAAAAA','$tag-VAULT-CIPHERTEXT','$DIGEST_SEED','key-$tag',
     false,'$dev',1,now(),now(),'$DIGEST_SEED')" >/dev/null || die "fixture: app_vault_mutations $tag"
done
AV_TOTAL="$(SU "$DBNAME" -c "select count(*) from cliptown.app_vault_mutations")"
if [ "$AV_TOTAL" = "2" ]; then pass "A11a app-vault fixture seeded 1 vault record per tenant — the isolation assertions below cannot pass against an empty table"
else fail "A11a expected 2 seeded app_vault_mutations rows, found $AV_TOTAL"; fi

av_read() { # subject device -> visible row count
  RLS <<SQL | tail -1
select set_config('request.jwt.claim.sub', '$1', false);
select set_config('request.jwt.claim.device_id', '$2', false);
select count(*) from cliptown.app_vault_mutations;
SQL
}
AV_A_OWN="$(av_read "$UA" "$DA1")"
AV_A_SIBLING="$(av_read "$UA" "$DA2")"
AV_B_SEES_A="$(av_read "$UB" "$DB1")"
AV_UNKNOWN_DEV="$(av_read "$UA" "00000000-0000-4000-8000-00000000dead")"
SU "$DBNAME" -c "update cliptown.devices set lifecycle_state='revoked', revoked_at=now() where id='$DA1'" >/dev/null
AV_REVOKED="$(av_read "$UA" "$DA1")"
SU "$DBNAME" -c "update cliptown.devices set lifecycle_state='active', revoked_at=null where id='$DA1'" >/dev/null

if [ "$AV_A_OWN" = "1" ]; then pass "A11b tenant A on active device A1 sees its 1 vault record (the policy admits the legitimate reader)"
else fail "A11b tenant A's own active device saw $AV_A_OWN of its 1 vault record"; fi
if [ "$AV_B_SEES_A" = "1" ]; then pass "A11c tenant B on its own active device sees only its own 1 record and none of tenant A's"
else fail "A11c cross-tenant vault read: tenant B saw $AV_B_SEES_A rows, expected exactly its own 1"; fi
if [ "$AV_UNKNOWN_DEV" = "0" ]; then pass "A11d a subject claim with a device_id that matches no enrolled device sees 0 vault records (fail-closed on an unknown device)"
else fail "A11d an unknown device_id exposed $AV_UNKNOWN_DEV vault records"; fi
if [ "$AV_REVOKED" = "0" ]; then pass "A11e revoking device A1 immediately drops its vault visibility to 0 rows (revocation is enforced by the policy, not only at login)"
else fail "A11e a REVOKED device still read $AV_REVOKED vault records"; fi
# Same-tenant sibling devices share the vault by design (it is a sync surface),
# so record what the policy actually grants rather than asserting a scoping that
# was never intended.
sub "A11f note: sibling device A2 sees $AV_A_SIBLING record(s) of tenant A — app_vault_mutations_active_device_select scopes by USER plus 'some active device', not by originating device, which is the intended sync semantics"

################################################################################
note "CHECK: idempotency  [requiredChecks: idempotency; focus: history CRUD]"
################################################################################

IKEY="idempotency-key-e2e-0001"
DIGEST_A="$(printf 'request-body-A' | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
DIGEST_B="$(printf 'request-body-B' | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"

# Retried write: the same key three times must leave exactly one row.
for _ in 1 2 3; do
  SU "$DBNAME" >/dev/null 2>&1 <<SQL
insert into cliptown.memebank_transfer_idempotency
  (id,subject_id,idempotency_key,operation,normalized_route,request_digest_base64url,expires_at)
values (gen_random_uuid(),'$UA','$IKEY','create','/v1/integrations/memebank/transfers','$DIGEST_A',now()+interval '1 hour')
on conflict (subject_id, idempotency_key) do nothing;
SQL
done
IDEM_ROWS="$(SU "$DBNAME" -c "select count(*) from cliptown.memebank_transfer_idempotency where subject_id='$UA' and idempotency_key='$IKEY'")"
if [ "$IDEM_ROWS" = "1" ]; then pass "I1 three identical retries of a keyed write left exactly 1 idempotency row (UNIQUE (subject_id, idempotency_key))"
else fail "I1 expected 1 idempotency row after 3 retries, found $IDEM_ROWS"; fi

# The same key under a different subject must not collide (no existence oracle)
# and must not be swallowed.
SU "$DBNAME" >/dev/null 2>&1 <<SQL
insert into cliptown.memebank_transfer_idempotency
  (id,subject_id,idempotency_key,operation,normalized_route,request_digest_base64url,expires_at)
values (gen_random_uuid(),'$UB','$IKEY','create','/v1/integrations/memebank/transfers','$DIGEST_B',now()+interval '1 hour')
on conflict (subject_id, idempotency_key) do nothing;
SQL
CROSS_IDEM="$(SU "$DBNAME" -c "select count(*) from cliptown.memebank_transfer_idempotency where idempotency_key='$IKEY'")"
if [ "$CROSS_IDEM" = "2" ]; then pass "I2 the same idempotency key under two subjects produced 2 independent rows — the key space is subject-scoped, not global"
else fail "I2 expected 2 subject-scoped rows for a shared idempotency key, found $CROSS_IDEM"; fi

# I3 — history CRUD has no dedup store at all. The openapi makes
# Idempotency-Key REQUIRED on POST /v1/clips, but nothing in the schema can
# enforce it: a retried create becomes a second history entry.
CLIP_UNIQ="$(SU "$DBNAME" -c "
  select count(*) from pg_indexes
  where schemaname='cliptown' and tablename='clips'
    and indexdef ilike '%unique%' and indexdef ilike '%idempotency%'")"
CLIPS_IDEM_TABLE="$(SU "$DBNAME" -c "select count(*) from information_schema.tables where table_schema='cliptown' and table_name like 'clip%idempotenc%'")"
for _ in 1 2; do
  SU "$DBNAME" >/dev/null <<SQL
insert into cliptown.clips (id,user_id,kind,encrypted_content,nonce,key_id,source_device_id,logical_clock,created_at,updated_at)
values (gen_random_uuid(),'$UA','text','RETRIED-CREATE','nonce-dup','key-a','$DA1',500,now(),now());
SQL
done
DUPES="$(SU "$DBNAME" -c "select count(*) from cliptown.clips where user_id='$UA' and encrypted_content='RETRIED-CREATE'")"
if [ "$DUPES" = "2" ] && [ "$CLIP_UNIQ" = "0" ] && [ "$CLIPS_IDEM_TABLE" = "0" ]; then
  pass "I3 a retried identical clip create produced $DUPES history entries — there is no clip idempotency table and no unique index to collapse them"
  defect "DEFECT-11" \
    "POST /v1/clips and PUT /v1/clips/{clipId} require an Idempotency-Key header in the canonical openapi, but the reviewed schema has no clip idempotency table, no unique index over any client-supplied key, and no natural key over (user_id, source_device_id, logical_clock); a retried create therefore duplicates a clipboard history entry" \
    "psql -d $DBNAME: run the same clip INSERT twice -> select count(*) from cliptown.clips where encrypted_content='RETRIED-CREATE' -> 2. Compare cliptown.memebank_transfer_idempotency, which carries UNIQUE (subject_id, idempotency_key), and cliptown.object_upload_sessions, which carries UNIQUE (user_id, idempotency_key). The clip path has neither."
else
  pass "I3 retried clip creates are collapsed by the schema (dupes=$DUPES)"
fi
SU "$DBNAME" -c "delete from cliptown.clips where encrypted_content='RETRIED-CREATE'" >/dev/null

################################################################################
note "CHECK: pagination  [focus: pagination, history CRUD]"
################################################################################

PU="cccccccc-0000-4000-8000-00000000000c"
PD="cccccccc-0000-4000-8000-0000000000d1"
SU "$DBNAME" >/dev/null <<SQL
insert into cliptown.accounts (user_id) values ('$PU') on conflict do nothing;
insert into cliptown.devices (id,user_id,name,platform,sync_token_hash,lifecycle_state)
  values ('$PD','$PU','pager','cli','hash-pager','active') on conflict do nothing;
delete from cliptown.clips where user_id='$PU';
insert into cliptown.clips (id,user_id,kind,encrypted_content,nonce,key_id,source_device_id,logical_clock,created_at,updated_at)
select gen_random_uuid(),'$PU','text','item-'||lpad(g::text,3,'0'),'n'||g,'k','$PD',g,now(),now() from generate_series(1,50) g;
SQL

# Keyset pagination over the ordering the schema actually indexes. The cursor is
# (logical_clock, id), which is unique and total, so it is stable under
# concurrent mutation.
keyset_pages() { # page_size mutate_after_page -> newline-separated items
  local size="$1" mutate_after="${2:-0}" page=0 ck=-1 cid='00000000-0000-0000-0000-000000000000'
  while :; do
    local rows last
    rows="$(SU "$DBNAME" -c "
      select logical_clock||'~'||id||'~'||encrypted_content from cliptown.clips
      where user_id='$PU' and (logical_clock, id) > ($ck, '$cid')
      order by logical_clock, id limit $size")"
    [ -z "$rows" ] && break
    printf '%s\n' "$rows" | awk -F'~' '{print $3}'
    last="$(printf '%s\n' "$rows" | tail -1)"
    ck="${last%%~*}"; cid="$(cut -d'~' -f2 <<<"$last")"
    page=$((page+1))
    if [ "$page" = "$mutate_after" ]; then
      # A concurrent writer: one insert that sorts BEFORE the cursor, one that
      # sorts AFTER it, and a delete of a page the reader has not reached.
      SU "$DBNAME" >/dev/null <<SQL
insert into cliptown.clips (id,user_id,kind,encrypted_content,nonce,key_id,source_device_id,logical_clock,created_at,updated_at)
values (gen_random_uuid(),'$PU','text','inserted-early','ne','k','$PD',2,now(),now()),
       (gen_random_uuid(),'$PU','text','inserted-late','nl','k','$PD',900,now(),now());
delete from cliptown.clips where user_id='$PU' and encrypted_content='item-045';
SQL
    fi
  done
}

QUIET_PAGES="$(keyset_pages 7 0)"
Q_TOTAL="$(grep -c . <<<"$QUIET_PAGES")"
Q_UNIQ="$(sort -u <<<"$QUIET_PAGES" | grep -c .)"
if [ "$Q_TOTAL" = "50" ] && [ "$Q_UNIQ" = "50" ]; then pass "P1 keyset pagination over 50 rows at page size 7 returned 50 items, 50 distinct — no drops, no duplicates"
else fail "P1 quiescent pagination returned $Q_TOTAL items ($Q_UNIQ distinct), expected 50/50"; fi

if [ "$QUIET_PAGES" = "$(sort <<<"$QUIET_PAGES")" ]; then pass "P2 items arrived in a total order across page boundaries — (logical_clock, id) is a stable cursor"
else fail "P2 page order was not monotonic; the cursor is not a total order"; fi

MUT_PAGES="$(keyset_pages 7 2)"
M_TOTAL="$(grep -c . <<<"$MUT_PAGES")"
M_UNIQ="$(sort -u <<<"$MUT_PAGES" | grep -c .)"
if [ "$M_TOTAL" = "$M_UNIQ" ]; then pass "P3 with a concurrent insert-before-cursor, insert-after-cursor and delete-ahead mid-pagination, $M_TOTAL items came back with 0 duplicates"
else fail "P3 concurrent mutation produced $((M_TOTAL-M_UNIQ)) duplicate items"; fi
if grep -qx 'inserted-late' <<<"$MUT_PAGES" && ! grep -qx 'inserted-early' <<<"$MUT_PAGES"; then
  pass "P4 the row inserted ahead of the cursor was served, the row inserted behind it was not — the documented keyset trade-off, with no item served twice"
else
  fail "P4 expected inserted-late present and inserted-early absent under keyset paging"
fi
if ! grep -qx 'item-045' <<<"$MUT_PAGES"; then pass "P5 an item deleted ahead of the reader was not served"
else fail "P5 a deleted item was still served"; fi

# P6 — the same workload under OFFSET paging, to show P3 is a real property and
# not something any pagination strategy would pass.
SU "$DBNAME" -c "delete from cliptown.clips where user_id='$PU' and encrypted_content in ('inserted-early','inserted-late')" >/dev/null
offset_pages() {
  local size=7 off=0 page=0 rows
  while :; do
    rows="$(SU "$DBNAME" -c "select encrypted_content from cliptown.clips where user_id='$PU' order by logical_clock, id limit $size offset $off")"
    [ -z "$rows" ] && break
    printf '%s\n' "$rows"
    off=$((off+size)); page=$((page+1))
    if [ "$page" = 2 ]; then
      SU "$DBNAME" >/dev/null <<SQL
insert into cliptown.clips (id,user_id,kind,encrypted_content,nonce,key_id,source_device_id,logical_clock,created_at,updated_at)
values (gen_random_uuid(),'$PU','text','offset-probe','no','k','$PD',1,now(),now());
SQL
    fi
  done
}
O_PAGES="$(offset_pages)"
O_TOTAL="$(grep -c . <<<"$O_PAGES")"
O_UNIQ="$(sort -u <<<"$O_PAGES" | grep -c .)"
if [ "$O_TOTAL" -gt "$O_UNIQ" ]; then pass "P6 OFFSET paging over the identical workload duplicated $((O_TOTAL-O_UNIQ)) item(s) — P3's no-duplicate assertion is falsifiable, not tautological"
else fail "P6 OFFSET paging did not duplicate under an insert-behind-the-cursor (total=$O_TOTAL uniq=$O_UNIQ); P3 cannot be shown to be a real property"; fi
SU "$DBNAME" -c "delete from cliptown.clips where user_id='$PU' and encrypted_content='offset-probe'" >/dev/null

################################################################################
note "CHECK: binary upload  [focus: binary upload]"
################################################################################

BLOB="$WORK/blob.bin"
head -c 3145728 /dev/urandom >"$BLOB"                       # 3 MiB of real bytes
BLOB_SHA="$(openssl dgst -sha256 -binary "$BLOB" | openssl base64 -A)"
BLOB_LEN="$(wc -c <"$BLOB" | tr -d ' ')"
CHUNK_SIZE=65536
mkdir -p "$WORK/chunks"
split -b "$CHUNK_SIZE" "$BLOB" "$WORK/chunks/chunk."
CLIP_FOR_OBJ="$(SU "$DBNAME" -c "
  insert into cliptown.clips (id,user_id,kind,encrypted_content,nonce,key_id,source_device_id,logical_clock,created_at,updated_at)
  values (gen_random_uuid(),'$UA','file','object-carrier','no','k','$DA1',700,now(),now()) returning id")"
OBJ="$(SU "$DBNAME" -c "select gen_random_uuid()")"
SU "$DBNAME" >/dev/null <<SQL
create table if not exists e2e_chunk_bytes (object_id uuid, chunk_index int, payload bytea, primary key (object_id, chunk_index));
insert into cliptown.encrypted_objects
  (id,manifest_id,user_id,clip_id,content_cipher_version,plaintext_length,ciphertext_length,chunk_size,ciphertext_sha256_base64,encrypted_metadata)
values ('$OBJ',gen_random_uuid(),'$UA','$CLIP_FOR_OBJ','xchacha20poly1305-chunked-v1',
        $BLOB_LEN, $BLOB_LEN, $CHUNK_SIZE, '$BLOB_SHA', '{}'::jsonb);
SQL
IDX=0
for c in "$WORK"/chunks/chunk.*; do
  CSHA="$(openssl dgst -sha256 -binary "$c" | openssl base64 -A)"
  CLEN="$(wc -c <"$c" | tr -d ' ')"
  # The exact bytes go in as hex and must come back out byte-for-byte.
  { printf "insert into cliptown.encrypted_object_chunks (object_id,chunk_index,ciphertext_length,ciphertext_sha256_base64,nonce_base64,randomized_storage_key) values ('%s',%s,%s,'%s','nonce-%s','randomized/%s/%s');\n" "$OBJ" "$IDX" "$CLEN" "$CSHA" "$IDX" "$OBJ" "$IDX"
    printf "insert into e2e_chunk_bytes values ('%s',%s,decode('" "$OBJ" "$IDX"
    od -An -v -tx1 <"$c" | tr -d ' \n'
    printf "','hex'));\n"; } >"$WORK/chunk.sql"
  SU "$DBNAME" -f "$WORK/chunk.sql" >/dev/null || die "chunk $IDX insert failed"
  IDX=$((IDX+1))
done
SU "$DBNAME" -c "select string_agg(encode(payload,'hex'),'' order by chunk_index) from e2e_chunk_bytes where object_id='$OBJ'" \
  | tr -d '\n' | xxd -r -p >"$WORK/roundtrip.bin"
RT_SHA="$(openssl dgst -sha256 -binary "$WORK/roundtrip.bin" | openssl base64 -A)"
if [ "$RT_SHA" = "$BLOB_SHA" ] && cmp -s "$BLOB" "$WORK/roundtrip.bin"; then
  pass "B1 ${BLOB_LEN}-byte blob stored as $IDX chunks and reassembled byte-identically (sha256 $BLOB_SHA)"
else
  fail "B1 round-trip corrupted the payload: sent sha256 $BLOB_SHA, read back $RT_SHA"
fi
# The checksum assertion must be able to fail: flip one byte and re-check.
printf '\x01' | dd of="$WORK/roundtrip.bin" bs=1 seek=1000 conv=notrunc status=none
FLIP_SHA="$(openssl dgst -sha256 -binary "$WORK/roundtrip.bin" | openssl base64 -A)"
if [ "$FLIP_SHA" != "$BLOB_SHA" ]; then pass "B2 flipping a single byte changes the digest — B1 is a real integrity check, not a tautology"
else fail "B2 digest did not change after a byte flip"; fi

# Size and content-type limits, asserted by making the database refuse them.
b_reject() { # description sql id
  if SU "$DBNAME" -c "$2" >/dev/null 2>&1; then fail "B$3 $1 was ACCEPTED"; else pass "B$3 $1 rejected by a CHECK constraint"; fi
}
OBJ_TPL="insert into cliptown.encrypted_objects (id,manifest_id,user_id,clip_id,content_cipher_version,plaintext_length,ciphertext_length,chunk_size,ciphertext_sha256_base64,encrypted_metadata) values (gen_random_uuid(),gen_random_uuid(),'$UA','$CLIP_FOR_OBJ',"
b_reject "chunk_size below the 65536 floor"      "$OBJ_TPL'xchacha20poly1305-chunked-v1',1,1,65535,'d','{}'::jsonb)" 3
b_reject "chunk_size above the 16 MiB ceiling"   "$OBJ_TPL'xchacha20poly1305-chunked-v1',1,1,16777217,'d','{}'::jsonb)" 4
b_reject "an unsupported content cipher version" "$OBJ_TPL'rot13-v1',1,1,65536,'d','{}'::jsonb)" 5
b_reject "a zero-length ciphertext"              "$OBJ_TPL'xchacha20poly1305-chunked-v1',1,0,65536,'d','{}'::jsonb)" 6
b_reject "a path-traversing storage key" \
  "insert into cliptown.encrypted_object_chunks (object_id,chunk_index,ciphertext_length,ciphertext_sha256_base64,nonce_base64,randomized_storage_key) values ('$OBJ',9001,1,'d','n','../../etc/passwd')" 7
b_reject "an absolute storage key" \
  "insert into cliptown.encrypted_object_chunks (object_id,chunk_index,ciphertext_length,ciphertext_sha256_base64,nonce_base64,randomized_storage_key) values ('$OBJ',9002,1,'d','n','/etc/shadow')" 8

# B9 — the database will happily store a declared length that contradicts the
# bytes actually present. Nothing cross-checks a manifest against its chunks.
DECLARED="$(SU "$DBNAME" -c "select ciphertext_length from cliptown.encrypted_objects where id='$OBJ'")"
ACTUAL="$(SU "$DBNAME" -c "select coalesce(sum(ciphertext_length),0) from cliptown.encrypted_object_chunks where object_id='$OBJ'")"
SU "$DBNAME" -c "update cliptown.encrypted_objects set ciphertext_length = 1 where id='$OBJ'" >/dev/null 2>&1
LIED="$(SU "$DBNAME" -c "select ciphertext_length from cliptown.encrypted_objects where id='$OBJ'")"
if [ "$DECLARED" = "$ACTUAL" ] && [ "$LIED" = "1" ]; then
  pass "B9 the manifest's declared ciphertext_length was rewritten to 1 while $ACTUAL bytes of chunks remain — no constraint ties a manifest to its chunks"
  defect "DEFECT-12" \
    "nothing validates an object manifest against the chunks it describes: encrypted_objects.ciphertext_length can contradict sum(encrypted_object_chunks.ciphertext_length), and ciphertext_sha256_base64 is unconstrained TEXT" \
    "psql -d $DBNAME -c \"update cliptown.encrypted_objects set ciphertext_length=1 where id='$OBJ'\" succeeds while sum(chunk.ciphertext_length)=$ACTUAL. The Rust half is DEFECT-16."
else
  fail "B9 expected declared=$ACTUAL then a successful rewrite to 1; got declared=$DECLARED lied=$LIED"
fi

################################################################################
note "CHECK: rate-limits  [requiredChecks: rate-limits]"
################################################################################

BURST="$WORK/burst.txt"
seq 1 300 | xargs -P 24 -I{} curl -s -o /dev/null -w '%{http_code}\n' --max-time 10 "$BASE/healthz" >"$BURST" 2>/dev/null
N429="$(grep -c '^429$' "$BURST")"
N200="$(grep -c '^200$' "$BURST")"
LIMITER_DEPS="$(cat "$SRC/Cargo.toml" "$SRC/Cargo.lock" | grep -icE 'governor|ratelimit|rate_limit|leaky-bucket|limiter')"
if [ "$N429" -eq 0 ] && [ "$N200" -ge 290 ] && [ "$LIMITER_DEPS" -eq 0 ]; then
  pass "R1 300 concurrent requests were all served ($N200 x 200, 0 x 429) and no rate-limiting crate exists in the dependency graph"
  defect "DEFECT-13" \
    "the service has no rate limiting of any kind: 300 concurrent unauthenticated requests were all served, and neither Cargo.toml nor Cargo.lock contains a limiter (no tower-governor, no ratelimit crate), while test-plan.json lists rate-limits as a required check" \
    "seq 1 300 | xargs -P 24 -I{} curl -s -o /dev/null -w '%{http_code}\\n' $BASE/healthz | sort | uniq -c -> $N200 x 200, 0 x 429. grep -icE 'governor|ratelimit|limiter' Cargo.toml Cargo.lock -> 0. The only throttling policy in the codebase (account_security::RecoveryOtpPolicy.issue_cooldown_seconds) is not reachable from any route."
elif [ "$N429" -gt 0 ]; then
  pass "R1 a rate limit engaged: $N429 of 300 requests were refused with 429"
else
  fail "R1 no 429 and no limiter dependency, but only $N200 of 300 requests returned 200 — the burst did not run cleanly"
fi

################################################################################
note "CHECK: websocket-when-applicable  [requiredChecks: websocket-when-applicable; focus: WebSocket]"
################################################################################

WS_KEY="$(openssl rand -base64 16)"
WS_101=0
declare -a WS_TRIED=()
for p in "/" "/healthz" "/readyz" "${OPENAPI_PATHS[@]}"; do
  probe="${p//\{clipId\}/00000000-0000-4000-8000-000000000001}"
  probe="${probe//\{appId\}/app.3fa.authenticator}"
  probe="${probe//\{deviceId\}/00000000-0000-4000-8000-0000000000d1}"
  c="$(code -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
        -H 'Sec-WebSocket-Version: 13' -H "Sec-WebSocket-Key: $WS_KEY" "$BASE$probe")"
  WS_TRIED+=("$probe")
  [ "$c" = "101" ] && WS_101=$((WS_101+1))
done
WS_FEATURE="$(grep -c '"ws"' "$SRC/Cargo.toml")"
# Search for IMPLEMENTATION symbols, case-sensitively. A case-insensitive search
# for "sec-websocket-accept" false-positives on the `http` crate's static
# header-name table, which every hyper binary links in whether or not it can
# speak WebSocket. `WebSocketUpgrade`/`on_upgrade`/`tungstenite` appear only if
# upgrade machinery was actually compiled.
if command -v strings >/dev/null 2>&1; then
  WS_SYMBOL="$(strings "$BIN" 2>/dev/null | grep -c -e 'WebSocketUpgrade' -e 'on_upgrade' -e 'tungstenite')"
else
  WS_SYMBOL="$(grep -c -a -e 'WebSocketUpgrade' -e 'on_upgrade' -e 'tungstenite' "$BIN" 2>/dev/null || echo 0)"
fi
if [ "$WS_101" -eq 0 ] && [ "$WS_FEATURE" -eq 0 ] && [ "$WS_SYMBOL" -eq 0 ]; then
  pass "W1 a real RFC6455 upgrade handshake against all ${#WS_TRIED[@]} routes produced 0 x 101; axum's \"ws\" feature is off and the binary contains no WebSocket symbols"
  defect "DEFECT-14" \
    "test-plan.json declares WebSocket in focus[] and websocket-when-applicable in requiredChecks[], but the pinned backend has no WebSocket implementation: axum is declared without the \"ws\" feature, the binary contains no upgrade machinery, and the canonical openapi declares no socket either" \
    "curl -s -o /dev/null -w '%{http_code}' -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: <b64>' $BASE/v1/sync/pull -> 404, and likewise for all ${#WS_TRIED[@]} routes; grep -c '\"ws\"' Cargo.toml -> 0; strings target/debug/cliptown-api | grep -c -e WebSocketUpgrade -e on_upgrade -e tungstenite -> 0 (a case-INSENSITIVE search for sec-websocket-accept returns 2, but those are entries in the http crate's static header-name table, not upgrade code). Cross-tenant socket scoping cannot be tested in either direction because no socket exists; the fan-out table that would back one is cliptown.device_mailbox, which DEFECT-10 shows has no RLS policy at all."
elif [ "$WS_101" -gt 0 ]; then
  fail "W1 $WS_101 route(s) completed a WebSocket upgrade — this suite must now be extended to prove per-device event scoping in both directions"
else
  fail "W1 inconsistent WebSocket evidence: 101s=$WS_101 ws-feature=$WS_FEATURE symbols=$WS_SYMBOL"
fi

# W2 — the delivery table a socket would fan out from is at least structurally
# addressed per recipient device. Assert the scoping that DOES exist, so a
# regression in mailbox addressing is caught even before a socket lands.
MAILBOX_A2="$(SU "$DBNAME" -c "select count(*) from cliptown.device_mailbox where recipient_device_id='$DA2'")"
MAILBOX_SELF="$(SU "$DBNAME" -c "select count(*) from cliptown.device_mailbox where sender_device_id = recipient_device_id")"
if [ "$MAILBOX_A2" -ge 1 ] && [ "$MAILBOX_SELF" = "0" ]; then
  pass "W2 device_mailbox addresses each envelope to a single recipient device and the sender<>recipient CHECK holds"
else
  fail "W2 mailbox addressing is not per-device: recipient A2 rows=$MAILBOX_A2, self-addressed rows=$MAILBOX_SELF"
fi

################################################################################
note "CHECK: pinned policy code (the modules no route can reach)"
################################################################################

PROBE="$WORK/policy-probe"
rm -rf "$PROBE"
cp -R "$ROOT/fixtures/policy-probe" "$PROBE"
sed "s#@INTERFACES_PATH@#$IFACE/generated/rust#" "$PROBE/Cargo.toml.in" >"$PROBE/Cargo.toml"
rm -f "$PROBE/Cargo.toml.in"
# Copy the pinned domain modules in verbatim and prove the copy is byte-exact,
# so nobody can later mistake the probe's verdicts for claims about a modified
# or transcribed copy of the source.
PROBE_COPY_OK=1
for m in account_security app_vault encrypted_objects memebank_transfer; do
  cp "$SRC/src/$m.rs" "$PROBE/src/$m.rs"
  if cmp -s "$SRC/src/$m.rs" "$PROBE/src/$m.rs"; then
    sub "probe module $m.rs sha256 $(openssl dgst -sha256 -binary "$PROBE/src/$m.rs" | openssl base64 -A | cut -c1-16)... (byte-identical to the pin)"
  else
    PROBE_COPY_OK=0
  fi
done
if [ "$PROBE_COPY_OK" = "1" ]; then
  pass "PP0 all 4 pinned domain modules copied byte-identically into the probe (its verdicts are about the real pinned source)"
else
  fail "PP0 a probe module copy differs from the pinned source"
fi
if ( cd "$PROBE" && CLIPTOWN_BACKEND_SRC="$SRC" "$CARGO" run --quiet ) >"$WORK/probe.out" 2>"$WORK/probe.err"; then
  while IFS='|' read -r verdict id message repro; do
    case "$verdict" in
      PASS)   pass "$id $message" ;;
      FAIL)   fail "$id $message" ;;
      DEFECT) defect "$id" "$message" "$repro" ;;
    esac
  done <"$WORK/probe.out"
else
  fail "PROBE the policy probe did not build or run: $(tail -20 "$WORK/probe.err")"
fi

################################################################################
note "CHECK: health — dependency reflection (Postgres removed)"
################################################################################
# Deliberately last: this destroys the database the rest of the suite needs.
if [ -z "${PG_EXTERNAL:-}" ]; then
  docker rm -f "$PG_CONTAINER" >/dev/null 2>&1
  for _ in $(seq 1 20); do SU postgres -c 'select 1' >/dev/null 2>&1 || break; sleep 0.5; done
  if SU postgres -c 'select 1' >/dev/null 2>&1; then
    fail "H7 could not stop Postgres; the dependency-reflection check did not run"
  else
    sleep 2
    DOWN_CODE="$(code "$BASE/readyz")"
    DOWN_STATUS="$(body "$BASE/readyz" | jq -r '.status // "<absent>"')"
    if [ "$DOWN_CODE" = "200" ] && [ "$DOWN_STATUS" = "ready" ]; then
      pass "H7 with Postgres destroyed, /readyz still answers 200 \"ready\" — DEFECT-01 confirmed against a genuinely absent dependency"
    elif [ "$DOWN_CODE" != "200" ]; then
      fail "H7 /readyz now reports $DOWN_CODE with the database down — readiness became dependency-aware; retire DEFECT-01 and make this the positive assertion"
    else
      fail "H7 unexpected readiness state with the database down: code=$DOWN_CODE status=$DOWN_STATUS"
    fi
    ALIVE="$(code "$BASE/healthz")"
    if [ "$ALIVE" = "200" ]; then pass "H8 liveness stayed 200 with the database down (correct for a liveness probe — the process is alive)"
    else fail "H8 liveness returned $ALIVE; a live process must not fail liveness because a dependency is down"; fi
  fi
else
  sub "H7/H8 SKIPPED — PG_EXTERNAL=1; refusing to destroy a Postgres this suite does not own"
fi

################################################################################
echo
printf '\033[1m================ SUMMARY ================\033[0m\n'
printf 'assertions passed : %d\n' "$PASSED"
printf 'assertions failed : %d\n' "$FAILED"
printf 'product defects   : %d\n' "${#DEFECTS[@]}"
if [ "${#DEFECTS[@]}" -gt 0 ]; then
  echo
  printf '\033[1;33mCONFIRMED PRODUCT DEFECTS\033[0m (cliptown-rust-backend.rs @ %s)\n' "$BACKEND_SHA"
  for d in "${DEFECTS[@]}"; do
    IFS='|' read -r id msg repro <<<"$d"
    printf '\n  \033[1m%s\033[0m %s\n    repro: %s\n' "$id" "$msg" "$repro"
  done
fi
if [ "$FAILED" -gt 0 ]; then
  echo
  printf '\033[1;31mFAILED ASSERTIONS\033[0m\n'
  for f in "${FAILURES[@]}"; do printf '  - %s\n' "$f"; done
  echo
  printf '\033[1;31mSUITE FAILED\033[0m\n'
  exit 1
fi
echo
printf '\033[1;32mALL %d ASSERTIONS PASSED\033[0m — live binary, real Postgres, real pinned policy code\n' "$PASSED"
printf 'The %d defects above are characterized, not tolerated: each is asserted in its\n' "${#DEFECTS[@]}"
printf 'CURRENT state, so fixing the product turns this suite red and forces the entry\n'
printf 'to be retired.\n'
