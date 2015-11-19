#!/bin/sh

# edit urlfiles as your configuration
urlfiles="/etc/httpd/tls"/*.url


nextmonth=$(( 30*24*3600 + $(date +%s) ))
todaystr="$(date +%Y%m%d)"
curl_cmd="$(which curl 2>/dev/null)"
wget_cmd="$(which wget 2>/dev/null)"
ftp_cmd="$(which ftp 2>/dev/null)"

for urlfile in ${urlfiles}; do
  url="$(cat ${urlfile})"
  if [ -z "${url}" ]; then
    # invalid url file
    continue
  fi

  crtfile="${urlfile%.url}.crt"
  crttoday="${urlfile%.url}-${todaystr}.crt"
  if [ -f "${crtfile}" ] && \
     openssl verify -attime "${nextmonth}" "${crtfile}" > /dev/null; then
    # valid, nothing to do
    continue
  fi

  # certificate will expire in 30 days, renew it
  if [ -n "${url}" ]; then
    # fetch new certificate
    if [ -n "${curl_cmd}" ]; then
      "${curl_cmd}" --silent --fail "${url}" | \
                    openssl x509 -inform DER -outform PEM -out "${crttoday}"
    elif [ -n "${wget_cmd}" ]; then
      "${wget_cmd}" --quiet -O - "${url}" | \
                    openssl x509 -inform DER -outform PEM -out "${crttoday}"
    elif [ -n "${ftp_cmd}" ]; then
      # BSD ftp, supporting https
      "${ftp_cmd}" -V -o - "${url}" | \
                   openssl x509 -inform DER -outform PEM -out "${crttoday}"
    else
      false
    fi

    if [ "0" = "$?" -a  -f "${crttoday}" ]; then
      # fetching certificate succeeded, update symlink
      ln -s -f "$(basename ${crttoday})" "${crtfile}"
      echo "Certifiate renewed :"
      echo -n "  ${crtfile}, "
      openssl x509 -noout -enddate -in "${crtfile}"
    else
      echo "Failed to renew certifiate : ${urlfile}"
    fi
  fi
done

