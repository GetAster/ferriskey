#!/usr/bin/env bash
# Builds every test binary of the workspace in one cargo invocation, then runs
# them concurrently with their ignored (database-backed) tests included. Each
# run boots its own Postgres schema, so runs share no state; the tests inside
# one run keep sharing their fixture, as they do under `cargo test`.
#
# Integration tests live in one `it` binary per crate (one module per former
# binary). That binary is expanded into one process run per top-level module,
# preserving the pre-merge topology: each module still gets its own process
# and its own schema, and libtest still runs the module's tests in parallel
# threads.
set -euo pipefail

jobs="${TEST_JOBS:-$(getconf _NPROCESSORS_ONLN)}"
logs="$(mktemp -d)"
export logs

# Ignored for a reason other than needing Postgres: they assert an open
# finding, or have rotted while CI never ran them. Remove an entry once fixed.
skip=(
  sso_08_parallel_refreshes_keep_the_session_alive
  sso_11_host_header_does_not_change_the_issuer
  creates_client_with_realm_default_scopes_assigned
)
export SKIP_ARGS="${skip[*]/#/--skip }"

cargo test --workspace --exclude ferriskey-client --lib --bins --tests --locked --no-run \
  --message-format=json-render-diagnostics \
  | jq -r 'select(.reason == "compiler-artifact" and .executable != null)
           | select(.profile.test or (.target.kind | index("test")))
           | [.target.name, .executable, .manifest_path] | @tsv' \
  > "$logs/binaries.tsv"

# One run line per (label, exe, manifest-dir, libtest-filter) tuple. An `it`
# binary is expanded to one run per top-level module; the filter "module::"
# selects exactly that module's tests.
expand() {
  local name="$1" exe="$2" dir pkg filter
  dir="$(dirname "$3")"
  case "$name" in
    oidc_bdd)
      # `harness = false`: parses its own arguments and rejects libtest flags.
      printf '%s\t%s\t%s\t%s\n' "oidc_bdd" "$exe" "$dir" ""
      ;;
    it)
      pkg="$(basename "$dir")"
      { "$exe" --list; "$exe" --list --ignored; } 2>/dev/null \
        | sed -n 's/^\(.*\): test$/\1/p' \
        | awk -F'::' '{ if (NF == 1) print $1; else print $1 "::" }' \
        | sort -u \
        | while IFS= read -r filter; do
            [ -n "$filter" ] || continue
            printf '%s\t%s\t%s\t%s\n' "$pkg/it/$filter" "$exe" "$dir" "$filter"
          done
      ;;
    *)
      printf '%s\t%s\t%s\t%s\n' "$name" "$exe" "$dir" ""
      ;;
  esac
}
export -f expand

while IFS=$'\t' read -r name exe manifest; do
  expand "$name" "$exe" "$manifest"
done < "$logs/binaries.tsv" > "$logs/runs.tsv"

run() {
  local label="$1" exe="$2" dir="$3" filter="$4" log
  log="$logs/$(echo "$label" | tr '/:' '__').log"
  # shellcheck disable=SC2206
  local args=(--include-ignored $SKIP_ARGS)
  case "$label" in
    oidc_bdd) args=() ;;
    # Shares one realm whose CORS origin cache is keyed by realm name alone,
    # so its tests race when run concurrently.
    *web_origin_test*) args+=(--test-threads=1) ;;
  esac

  local start=$SECONDS
  if [ -n "$filter" ]; then
    (cd "$dir" && CARGO_MANIFEST_DIR="$dir" "$exe" ${args[@]+"${args[@]}"} "$filter") >"$log" 2>&1
  else
    (cd "$dir" && CARGO_MANIFEST_DIR="$dir" "$exe" ${args[@]+"${args[@]}"}) >"$log" 2>&1
  fi
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "ok   $label ($((SECONDS - start))s) $(grep -h '^test result:' "$log" | tail -1)"
  else
    echo "FAIL $label ($((SECONDS - start))s)"
    echo "$log" >>"$logs/failed"
  fi
}
export -f run

xargs -n 4 -P "$jobs" bash -c 'run "$@"' _ <"$logs/runs.tsv"

if [[ -s "$logs/failed" ]]; then
  while read -r log; do
    echo "::group::$(basename "$log")"
    cat "$log"
    echo "::endgroup::"
  done <"$logs/failed"
  exit 1
fi
