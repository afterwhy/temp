#!/bin/bash

# ========== CONFIG ==========
KC_URL="http://localhost:8080"
REALM="myrealm"
ADMIN_USER="admin"
ADMIN_PASS="admin"
NEW_USERS=("client-1-user-1" "client-1-user-2" "client-2-user-1" "client-2-user-2")
ROLES=("role-1" "role-2")
CLIENTS=("client-1" "client-2")
REAL_CLIENT_ID="real-client"
# ============================

# Random password generator
random_password() {
  tr -dc A-Za-z0-9 </dev/urandom | head -c 16
}

# Get admin token
get_admin_token() {
  curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    -d "username=$ADMIN_USER" \
    -d "password=$ADMIN_PASS" | jq -r .access_token
}

TOKEN=$(get_admin_token)

# Helper to get client UUID by clientId
get_client_id() {
  local client_id=$1
  curl -s -H "Authorization: Bearer $TOKEN" \
    "$KC_URL/admin/realms/$REALM/clients?clientId=$client_id" | jq -r '.[0].id'
}

# Create client
create_client() {
  local client_id=$1
  local secret=$(random_password)

  curl -s -o /dev/null -w "%{http_code}" -X POST "$KC_URL/admin/realms/$REALM/clients" \
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

# Create role under real-client
create_client_role() {
  local client_id=$1
  local role_name=$2
  local client_uuid=$(get_client_id "$client_id")

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
  curl -s -H "Authorization: Bearer $TOKEN" "$KC_URL/admin/realms/$REALM/users?username=$username" | jq -r '.[0].id'
}

# Assign role from real-client to user
assign_role_to_user() {
  local username=$1
  local role_name=$2
  local user_id=$(get_user_id "$username")
  local client_uuid=$(get_client_id "$REAL_CLIENT_ID")

  local role_json=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "$KC_URL/admin/realms/$REALM/clients/$client_uuid/roles/$role_name")

  curl -s -o /dev/null -X POST "$KC_URL/admin/realms/$REALM/users/$user_id/role-mappings/clients/$client_uuid" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "[$role_json]"
}

# Add protocol mapper to external clients
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
        \"clientId\": \"$REAL_CLIENT_ID\",
        \"claim.name\": \"resource_access.$REAL_CLIENT_ID.roles\",
        \"jsonType.label\": \"String\",
        \"access.token.claim\": \"true\",
        \"id.token.claim\": \"true\",
        \"userinfo.token.claim\": \"true\"
      }
    }"
}

# -------------------------
# EXECUTION
# -------------------------

echo "[*] Creating real-client..."
create_client "$REAL_CLIENT_ID"

for role in "${ROLES[@]}"; do
  echo "[*] Creating role '$role' under real-client"
  create_client_role "$REAL_CLIENT_ID" "$role"
done

for client in "${CLIENTS[@]}"; do
  echo "[*] Creating client '$client'..."
  create_client "$client"

  echo "[*] Adding role mapper to '$client' to pull roles from real-client..."
  add_role_mapper_to_client "$client"
done

for user in "${NEW_USERS[@]}"; do
  pass=$(random_password)
  echo "[*] Creating user '$user' with password: $pass"
  create_user "$user" "$pass"

  for role in "${ROLES[@]}"; do
    assign_role_to_user "$user" "$role"
  done
done

echo "[✔] Setup complete."
