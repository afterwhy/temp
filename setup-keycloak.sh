#!/bin/bash

# ======== CONFIG =========
KC_URL="http://localhost:8080"
REALM="myrealm"
ADMIN_USER="admin"
ADMIN_PASS="admin"
REAL_CLIENT="real-client"
CLIENTS=("client-1" "client-2")
ROLES=("role-1" "role-2" "role-3" "role-4")
# =========================

# Random password generator
random_password() {
  tr -dc A-Za-z0-9 </dev/urandom | head -c 12
}

# Get admin token
get_admin_token() {
  curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" -d "client_id=admin-cli" \
    -d "username=$ADMIN_USER" -d "password=$ADMIN_PASS" \
  | jq -r .access_token
}

TOKEN=$(get_admin_token)

# Get client UUID by clientId
get_client_id() {
  local search_client_id="$1"
  local clients_json

  # Get all clients (JSON array)
  clients_json=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "$KC_URL/admin/realms/$REALM/clients")

  # Strip leading [ and trailing ] from array, replace },{ with }§{ to split
  echo "$clients_json" \
    | sed -E 's/^\[//' \
    | sed -E 's/\]$//' \
    | sed 's/},{/}§{/g' \
    | tr '§' '\n' \
    | while read -r obj; do
        # Extract clientId from object
        local cid=$(echo "$obj" | grep -o '"clientId":"[^"]*"' | cut -d':' -f2 | tr -d '"')
        if [[ "$cid" == "$search_client_id" ]]; then
          # Extract id from object
          echo "$obj" | grep -o '"id":"[^"]*"' | head -n1 | cut -d':' -f2 | tr -d '"'
          return 0
        fi
      done

  return 1  # not found
}

# Create client with random secret
create_client() {
  local client_id=$1
  local secret=$(random_password)

  curl -s -o /dev/null -X POST "$KC_URL/admin/realms/$REALM/clients" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{
      \"clientId\": \"$client_id\",
      \"enabled\": true,
      \"protocol\": \"openid-connect\",
      \"publicClient\": false,
      \"secret\": \"$secret\"
    }"
  echo "$client_id secret: $secret"
}

# Create roles in real-client
create_role() {
  local client_uuid=$(get_client_id "$REAL_CLIENT")
  local role_name=$1

  curl -s -o /dev/null -X POST "$KC_URL/admin/realms/$REALM/clients/$client_uuid/roles" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"name\": \"$role_name\"}"
}

# Create user
create_user() {
  local username=$1
  local password=$2

  curl -s -o /dev/null -X POST "$KC_URL/admin/realms/$REALM/users" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{
      \"username\": \"$username\",
      \"enabled\": true,
      \"credentials\": [
        {
          \"type\": \"password\",
          \"value\": \"$password\",
          \"temporary\": false
        }
      ]
    }"
}

# Get user ID
get_user_id() {
  local username=$1
  curl -s -H "Authorization: Bearer $TOKEN" \
    "$KC_URL/admin/realms/$REALM/users?username=$username" | jq -r '.[0].id'
}

# Assign role from real-client to user
assign_role_to_user() {
  local username=$1
  local role_name=$2
  local user_id=$(get_user_id "$username")
  local client_uuid=$(get_client_id "$REAL_CLIENT")

  local role_json=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "$KC_URL/admin/realms/$REALM/clients/$client_uuid/roles/$role_name")

  curl -s -o /dev/null -X POST "$KC_URL/admin/realms/$REALM/users/$user_id/role-mappings/clients/$client_uuid" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "[$role_json]"
}

# Add protocol mapper to pull real-client roles into token
add_role_mapper_to_client() {
  local client_id=$1
  local client_uuid=$(get_client_id "$client_id")

  curl -s -o /dev/null -X POST "$KC_URL/admin/realms/$REALM/clients/$client_uuid/protocol-mappers/models" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{
      \"name\": \"real-client-role-mapper\",
      \"protocol\": \"openid-connect\",
      \"protocolMapper\": \"oidc-usermodel-client-role-mapper\",
      \"config\": {
        \"clientId\": \"$REAL_CLIENT\",
        \"claim.name\": \"resource_access.$REAL_CLIENT.roles\",
        \"jsonType.label\": \"String\",
        \"access.token.claim\": \"true\",
        \"id.token.claim\": \"true\",
        \"userinfo.token.claim\": \"true\"
      }
    }"
}

# ----------------------------
# EXECUTION
# ----------------------------

echo "[*] Creating role-defining client: $REAL_CLIENT"
create_client "$REAL_CLIENT"

for client in "${CLIENTS[@]}"; do
  echo "[*] Creating token client: $client"
  create_client "$client"
  echo "    Adding protocol mapper to expose $REAL_CLIENT roles"
  add_role_mapper_to_client "$client"
done

echo "[*] Creating roles in $REAL_CLIENT"
for role in "${ROLES[@]}"; do
  create_role "$role"
done

# Users and role mapping
declare -A USER_ROLE_MAP=(
  [user-1]="role-1"
  [user-2]="role-2"
  [user-3]="role-3"
  [user-4]="role-4"
)

echo "[*] Creating users and assigning roles"
for user in "${!USER_ROLE_MAP[@]}"; do
  pw=$(random_password)
  echo "  - $user (password: $pw, role: ${USER_ROLE_MAP[$user]})"
  create_user "$user" "$pw"
  assign_role_to_user "$user" "${USER_ROLE_MAP[$user]}"
done

echo "[✔] All done!"
