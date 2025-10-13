#!/bin/bash

CERT_PATH="/certs/krbcert.pem"
EXPIRATION_THRESHOLD=30
LIFESPAN_IN_DAYS=1095   # 3 years
KRB5_CONFIG_SERVER=${KRB5_CONFIG_SERVER:-kadmin_api}

echo $KRB5_CONFIG_SERVER

generate_certificate() {
    openssl req -nodes -new -x509 \
        -days $LIFESPAN_IN_DAYS \
        -keyout /certs/krbkey.pem \
        -out /certs/krbcert.pem \
        -addext "subjectAltName=DNS:$KRB5_CONFIG_SERVER" \
        -subj "/C=RU/ST=Moscow/L=Moscow/O=Global Security/OU=Multifactor/CN=$KRB5_CONFIG_SERVER" > /dev/null 2>&1
}

if [[ ! -f "$CERT_PATH" ]]; then
  echo "Certificate not found. Generating a new certificate..."
  generate_certificate
  exit 0
fi

end_date=$(openssl x509 -enddate -noout -in "$CERT_PATH" | cut -d= -f2)
end_date_epoch=$(date -d "$end_date" +%s)
current_date_epoch=$(date +%s)
days_left=$(( (end_date_epoch - current_date_epoch) / 86400 ))

if [[ $days_left -le $EXPIRATION_THRESHOLD ]]; then
  echo "Certificate expires in $days_left days or has already expired. Generating a new certificate..."
  generate_certificate
  exit 0
fi

echo "Certificate is valid for another $days_left days."
