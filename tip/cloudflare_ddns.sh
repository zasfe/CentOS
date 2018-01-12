#/usr/bin/env sh

# DYNAMIC DNS WITH CLOUDFLARE - ROHAN JAIN
# https://www.rohanjain.in/cloudflare-ddns/
# thank. 

# Modified(2018-01-12). identifier(domain), zone_identifier find api call..


# Get the Zone ID from: https://www.cloudflare.com/a/overview/<your-domain>
DNS_ZONE=<your-dns-zone>

# Get these from: https://www.cloudflare.com/a/account/my-account
AUTH_EMAIL=<cloudflare-auth-email>
AUTH_KEY=<cloudflare-auth-key>

# Desired domain name
DOMAIN_NAME="<subdomain>.<your-domain>"

# Get previous IP address
_PREV_IP_FILE="/tmp/public-ip.txt"
_PREV_IP=$(cat $_PREV_IP_FILE &> /dev/null)

# Install `dig` via `dnsutils` for faster IP lookup.
command -v dig &> /dev/null && {
    _IP=$(dig +short myip.opendns.com @resolver1.opendns.com)
} || {
    _IP=$(curl --silent https://api.ipify.org)
} || {
    exit 1
}

# If new/previous IPs match, no need for an update.
if [ "$_IP" = "$_PREV_IP" ]; then
    exit 0
fi

ZONE_IDENTIFIER=$(curl --silent -X GET "https://api.cloudflare.com/client/v4/zones" \
    -H "X-Auth-Email: $AUTH_EMAIL" \
    -H "X-Auth-Key:  $AUTH_KEY" \
    -H "Content-Type: application/json" \
    -d "name=$DNS_ZONE" | awk -F\" '{print$6}')

#echo "ZONE_IDENTIFIER=${ZONE_IDENTIFIER}"

if [ "${ZONE_IDENTIFIER}" = "" ]; then
    echo "Domain name Not find"
    exit 1
fi

HOST_IDENTIFIER=$(curl "https://api.cloudflare.com/client/v4/zones/${ZONE_IDENTIFIER}/dns_records" \
    --silent -X GET \
    -H "X-Auth-Email: $AUTH_EMAIL" \
    -H "X-Auth-Key: $AUTH_KEY" \
    -H "Content-Type: application/json" \
    -d "name=${DOMAIN_NAME}"  | sed -e 's/{/{\n/g' | grep "\"${DOMAIN_NAME}\"" | awk -F\" '{print$4}')

_UPDATE=$(cat <<EOF
{ "type": "A",
  "name": "$DOMAIN_NAME",
  "content": "$_IP",
  "ttl": 120,
  "proxied": false }
EOF
)

# If host not exist create, exist update.
if [ "${ZONE_IDENTIFIER}" = "" ]; then

# host create.
curl -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_IDENTIFIER}/dns_records" \
     --silent \
     -H "X-Auth-Email: $AUTH_EMAIL" \
     -H "X-Auth-Key: $AUTH_KEY" \
     -H "Content-Type: application/json" \
     -d "$_UPDATE" > /home/zasfe/tmp/cloudflare-ddns-update.json && \
     echo $_IP > $_PREV_IP_FILE
else

# host update.
curl -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_IDENTIFIER}/dns_records/${ZONE_IDENTIFIER}" \
     --silent \
     -H "X-Auth-Email: $AUTH_EMAIL" \
     -H "X-Auth-Key: $AUTH_KEY" \
     -H "Content-Type: application/json" \
     -d "$_UPDATE" > /home/zasfe/tmp/cloudflare-ddns-update.json && \
     echo $_IP > $_PREV_IP_FILE
fi

