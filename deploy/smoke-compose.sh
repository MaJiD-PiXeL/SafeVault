#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || ( $# -eq 2 && $2 != --recovery ) ]]; then
    echo 'Usage: bash deploy/smoke-compose.sh /path/to/caddy-root.crt [--recovery]' >&2
    exit 2
fi

host=safevault.localhost
origin="https://$host"
username=composesmoke
password=SafeVault-CI-account-only-4823
state=$(mktemp -d)
trap 'rm -f -- "$state/cookies" "$state/index" "$state/index.headers" "$state/worker" "$state/vaults.headers"; rmdir -- "$state"' EXIT
cookies="$state/cookies"
fixture="$(dirname -- "${BASH_SOURCE[0]}")/../frontend/tests/fixtures/encryption-v1.json"
curl_https=(curl --silent --show-error --fail --max-time 10 --noproxy '*'
    --resolve "$host:443:127.0.0.1" --cacert "$1"
    --cookie "$cookies" --cookie-jar "$cookies")

echo 'Checking HTTPS and web assets'
"${curl_https[@]}" --retry 5 --retry-connrefused --dump-header "$state/index.headers" \
    --output "$state/index" "$origin/"
grep -q 'SafeVault' "$state/index"
grep -qi '^content-security-policy: .*wasm-unsafe-eval' "$state/index.headers"
"${curl_https[@]}" --output "$state/worker" "$origin/offline-shell.js"
grep -q 'safevault-offline-shell-' "$state/worker"

echo 'Checking liveness and database readiness'
"${curl_https[@]}" "$origin/api/health/" | jq -e '.status == "healthy"' > /dev/null
"${curl_https[@]}" "$origin/api/ready/" | jq -e '.status == "ready"' > /dev/null

echo 'Checking CSRF, registration and secure cookies'
token=$("${curl_https[@]}" "$origin/api/auth/session/" |
    jq -er 'select(.user == null) | .csrfToken | select(test("^[a-zA-Z0-9]{64}$"))')
token=$("${curl_https[@]}" "$origin/api/auth/register/" \
    --header "Origin: $origin" --header "X-CSRFToken: $token" \
    --header 'Content-Type: application/json' \
    --data "$(jq -cn --arg username "$username" --arg password "$password" '{$username, $password}')" |
    jq -er --arg username "$username" 'select(.user.username == $username) | .csrfToken | select(test("^[a-zA-Z0-9]{64}$"))')
awk '$1 ~ /^#HttpOnly_/ && $4 == "TRUE" { secure[$6] = 1 }
     END { exit !(secure["velnar_session"] && secure["velnar_csrf"]) }' "$cookies"

"${curl_https[@]}" --dump-header "$state/vaults.headers" "$origin/api/vaults/" |
    jq -e '.vaults == []' > /dev/null
grep -qi '^cache-control: .*no-store' "$state/vaults.headers"

echo 'Checking encrypted entry storage and paginated reads'
json_write=(--header "Origin: $origin" --header "X-CSRFToken: $token" --header 'Content-Type: application/json')
vault=$(jq -c '.vault' "$fixture")
vault_id=$(jq -r '.id' <<< "$vault")
"${curl_https[@]}" "${json_write[@]}" --data "$vault" "$origin/api/vaults/" |
    jq -e --arg id "$vault_id" '.id == $id' > /dev/null

entry=$(jq -c '.entry | {id, nonce, ciphertext}' "$fixture")
entries_url="$origin/api/vaults/$vault_id/entries/"
"${curl_https[@]}" "${json_write[@]}" --data "$entry" "$entries_url" |
    jq -e --argjson entry "$entry" '{id, nonce, ciphertext} == $entry and .revision == 1' > /dev/null
"${curl_https[@]}" "$entries_url?state=all&offset=0" |
    jq -e --argjson entry "$entry" \
        '.count == 1 and .next_offset == null and (.results[0] | {id, nonce, ciphertext}) == $entry' > /dev/null

if [[ ${2:-} == --recovery ]]; then
    email=recovery@example.test
    new_password=SafeVault-CI-replacement-only-7138
    recovery_url="$origin/api/auth/recovery"

    recovery_link() {
        local action=$1 link attempt
        for (( attempt = 0; attempt < 45; attempt++ )); do
            if link=$(curl --silent --fail --max-time 2 --noproxy '*' 'http://127.0.0.1:8025/api/v1/message/latest' |
                jq -cer --arg email "$email" --arg prefix "$origin/#account-action=$action&username=$username&token=" '
                    select(.Username == "smoke" and [.To[].Address] == [$email]) |
                    .Text | split("\n")[] | sub("\r$"; "") | select(startswith($prefix)) |
                    ltrimstr($prefix) | select(test("^[a-z0-9]+-[a-f0-9]+$"))'); then
                printf '%s\n' "$link"
                return 0
            fi
            sleep 2
        done
        echo "The $action email did not arrive in the local SMTP capture service." >&2
        return 1
    }

    echo 'Checking authenticated SMTP delivery of the verification link'
    "${curl_https[@]}" "${json_write[@]}" "$recovery_url/email/" \
        --data "$(jq -cn --arg email "$email" --arg password "$password" '{$email, $password}')"
    link=$(recovery_link verify)
    "${curl_https[@]}" "${json_write[@]}" "$recovery_url/verify/" \
        --data "$(jq -cn --arg username "$username" --arg token "$link" '{$username, $token}')"
    "${curl_https[@]}" "$recovery_url/email/" | jq -e --arg email "$email" '.email == $email and .verified' > /dev/null

    echo 'Checking queued password reset, session revocation and vault preservation'
    "${curl_https[@]}" "${json_write[@]}" "$recovery_url/request/" \
        --data "$(jq -cn --arg username "$username" '{$username}')" | jq -e '.accepted == true' > /dev/null
    link=$(recovery_link reset)
    "${curl_https[@]}" "${json_write[@]}" "$recovery_url/reset/" \
        --data "$(jq -cn --arg username "$username" --arg token "$link" --arg password "$new_password" '{$username, $token, $password}')"

    token=$("${curl_https[@]}" "$origin/api/auth/session/" | jq -er 'select(.user == null) | .csrfToken')
    login_headers=(--header "Origin: $origin" --header "X-CSRFToken: $token" --header 'Content-Type: application/json')
    old_login_status=$("${curl_https[@]}" --no-fail --output /dev/null --write-out '%{http_code}' \
        "${login_headers[@]}" "$origin/api/auth/login/" \
        --data "$(jq -cn --arg username "$username" --arg password "$password" '{$username, $password}')")
    test "$old_login_status" = 400
    token=$("${curl_https[@]}" "${login_headers[@]}" "$origin/api/auth/login/" \
        --data "$(jq -cn --arg username "$username" --arg password "$new_password" '{$username, $password}')" |
        jq -er --arg username "$username" 'select(.user.username == $username) | .csrfToken')
    "${curl_https[@]}" "$entries_url?state=all&offset=0" |
        jq -e --argjson entry "$entry" '.count == 1 and (.results[0] | {id, nonce, ciphertext}) == $entry' > /dev/null
fi

"${curl_https[@]}" --request POST --header "Origin: $origin" --header "X-CSRFToken: $token" \
    "$origin/api/auth/logout/" | jq -e 'has("user") and .user == null' > /dev/null
