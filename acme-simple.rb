#!/usr/bin/env ruby
# coding: utf-8
#
# Copyright (c) 2015, Hanabusa Masahiro All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1.  Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#
# 2.  Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
# 3.  The name of the author may not be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
# EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISE OF THE POSSIBILITY OF SUCH DAMAGE.
#
# ( BSD license without advertising clause )
#
# ============================================================================


require 'net/https'
require 'uri'
require 'openssl'
require 'base64'
require 'json'
require 'optparse'
require 'readline'

# default server : Let's encrypt beta
ACME_URL_DEFAULT='https://acme-v01.api.letsencrypt.org/directory'
# this script directory
SCRIPT_DIR = File.expand_path(File.dirname(__FILE__))


#
# RFC 4648 "URL and Filename safe Base64 encode", without padding
#
def base64url(bin)
  Base64.urlsafe_encode64(bin).delete('=')
end


#
# Create JWS string (RFC 7515, JSON Web Signature)
# Flattened JSON serialization, RSA key with SHA256 signature
#
def jws_rs256(jsonpayload, nonce, rsa)

  # JWS header
  jwk = { 'kty'=>'RSA',
          'n'=>base64url(rsa.n.to_s(2)),
          'e'=>base64url(rsa.e.to_s(2)) }
  header = {'alg' => 'RS256', 'jwk'=>jwk}
  header['nonce'] = nonce if nonce

  # base64 encode
  encodedheader  = base64url(header.to_json)
  encodedpayload = base64url(jsonpayload.to_json)
  
  # Sign encoded string
  signature = rsa.sign('sha256', encodedheader+'.'+encodedpayload)

  {
    'protected' => encodedheader,
    'payload'   => encodedpayload,
    'signature' => base64url(signature)
  }.to_json
end


#
# Send HTTP GET
# => Response,JSON
def http_get(urlstr)
  url = URI.parse(urlstr)

  http = Net::HTTP::Proxy(:ENV).new(url.host, url.port)
  http.use_ssl = ( 'https' == url.scheme )
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER

  http.start {
    req = Net::HTTP::Get.new(url.request_uri)
    res = http.request(req)

    if res.content_type =~ /application\/.*json/ then
      [ res, JSON.parse(res.body) ]
    else
      [ res, {} ]
    end
  }
end


#
# Send HTTP POST JWS
# => Response,JSON
def http_post(urlstr, jsonpayload, rsa)
  url = URI.parse(urlstr)

  http = Net::HTTP::Proxy(:ENV).new(url.host, url.port)
  http.use_ssl = ( 'https' == url.scheme )
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER

  http.start {
    # first, fetch nonce value
    req = Net::HTTP::Head.new(url.request_uri)
    res = http.request(req)
    nonce = res['Replay-Nonce']

    # send POST request with nonce
    req = Net::HTTP::Post.new(url.request_uri)
    req.content_type = 'application/jwt'
    req.body = jws_rs256(jsonpayload, nonce, rsa)
    res = http.request(req)

    if res.content_type =~ /application\/.*json/ then
      [ res, JSON.parse(res.body) ]
    else
      [ res, {} ]
    end
  }
end


#
# Get server names from CSR
# => ['servername1', 'servername2', ... ]
# 
def servernames_from_csr(csr)
  server_names = []

  # get common name
  cn = csr.subject.to_a.find{ |key,val,type| key=='CN' }
  server_names << cn[1] 

  # try finding SubjectAltName
  extreq = csr.attributes.find { |attr| attr.oid == 'extReq' }
  return server_names unless extreq

  asnext = extreq.value
  return server_names unless asnext.value.is_a?(Array)

  asnext.value.each do |asnseq1|
    next unless asnseq1.is_a?(OpenSSL::ASN1::Sequence)
    next unless asnseq1.value.is_a?(Array)

    asnseq1.value.each do |asnseq2|
      next unless asnseq2.is_a?(OpenSSL::ASN1::Sequence)
      next unless asnseq2.value.is_a?(Array)

      ary = asnseq2.value.map{ |asn|
        asn.value if asn.is_a?(OpenSSL::ASN1::Primitive)
      }
      ext = nil
      case ary.size
      when 2
        # extension oid , extension value
        ext = OpenSSL::X509::Extension.new(ary[0], ary[1])
      when 3
        # extension oid , critical, extension value
        ext = OpenSSL::X509::Extension.new(ary[0], ary[2], ary[1])
      end

      if ext && ext.oid == 'subjectAltName' then
        # subjectAltName extension found
        ext.value.split(',').each do |san|
          # san = "DNS:host.example.com" etc.
          san.strip!
          type,host = san.split(':')
          if type == 'DNS' then
            server_names << host.strip
          end
        end
      end
    end
  end
  server_names.uniq
end 


#
# ACME register request
# => registration URL
def acme_new_register(url, email, tel, rsa, rsaname)
  contact = []
  contact << "mailto:#{email}" if email
  contact << "tel:#{tel}"      if tel

  # create ACME register request
  reg = { 'resource' => 'new-reg' }
  reg['contact'] = contact if 0<contact.size

  # send request 
  res,result = http_post(url, reg, rsa)

  case res
  when Net::HTTPCreated
    # 201 Created, registration succeeded
    print "ACME registration succeeded, id=>#{result['id']}\n"
    print res['Location'], "\n"
    p result

    # save id in file
    begin
      open("#{rsaname}.id", 'w') do |f|
        f.print({ 'location' => res['Location'], 
                  'links'    => res.get_fields('Link'),
                  'body'     => result } .to_json)
      end
    rescue => e
      p e
    end
  when Net::HTTPConflict
    # 409 Conflict, already registred
    if contact.empty? then
      # Without contact information, Location header fetching purpose
      return res['Location']
    end
    p result
    abort "RSA key is already registered."
  else
    p result
    abort "ACME registration failed with #{res.code}"
  end

end


#
# ACME show/update registration
# => {:location, :tos}
def acme_update_register(url, email, tel, agreement, rsa)
  contact = []
  contact << "mailto:#{email}" if email
  contact << "tel:#{tel}"      if tel

  # create ACME register request
  reg = { 'resource' => 'reg' }
  reg['contact']   = contact   if 0<contact.size
  reg['agreement'] = agreement if agreement

  # send request 
  res,result = http_post(url, reg, rsa)
  case res
  when Net::HTTPAccepted
    # 202 Accepted, 'reg' request accepted
    p result
  else
    p result
    abort "ACME registration failed with #{res.code}"
  end

  # get Location, Link headers
  links = { :location => res['Location'] }
  res.get_fields('Link').each do |link|
    case link
    when /<([^>]*)>.*terms-of-service/
      links[:tos] = $1
    when /<([^>]*)>.*recover/
      links[:recover] = $1
    end
  end

  links
end


#
# ACME simpleHttp challenge
#
def acme_simplehttp(url, use_tls, server_name, token, script, rsa)
  challenge = {
    'type'  => 'simpleHttp',
    'token' => token,
    'tls'   => use_tls
  }
  
  # create challenge file
  tokenfile = "/tmp/#{File.basename(token)}"
  open(tokenfile, 'w') do |f|
    f.write( jws_rs256(challenge, nil, rsa) )
  end

  # run simpleHttp script (default, some echo and wait key press only.)
  scriptresult = system(script, server_name, token, tokenfile)

  # remove token file
  begin
    File.unlink(tokenfile)
  rescue => e
    # ignore unlink failure (custom script may move token file)
  end

  if ! scriptresult then
    abort "Validation script #{script} failed.\n"
  end
  
  # send challenge
  challenge['resource'] = 'challenge'
  res,result = http_post(url, challenge, rsa)
  case res
  when Net::HTTPOK, Net::HTTPAccepted
    # challenge accepted
    print "Wait for validation process."
  else
    p result
    abort "ACME challenge failed with #{res.code}"
  end

  # wait for validation
  status = nil
  expire = nil
  for tm in (0...30).step(2)
    res,result = http_get(url)
    case res
    when Net::HTTPOK, Net::HTTPAccepted
      status = result['status']
      expire = result['expires']
      if status == 'valid' || status == 'invalid' then
        # completed
        break
      else
        # validation under progress
        print '.'
        sleep(2)
        next
      end
    else
      p result
      abort "ACME challenge failed with #{res.code}"
    end
  end
  print "\n\n"
 
  if status == 'valid' then
    print "#{server_name} is authorized until #{expire}.\n\n"
  else
    p result
    abort "Identifier authorization failed(#{status}) for #{server_name}."
  end 
end


#
# ACME New authorization request
# (support simpleHttp only)
#
def acme_newauth(url, use_tls, server_name, script, rsa)

  print "Try identifier authorization for #{server_name} ..."

  newauth = {
    'resource' => 'new-authz',
    'identifier' => { 'type' => 'dns', 'value' => server_name }
  }

  # send request 
  res,result = http_post(url, newauth, rsa)
  case res
  when Net::HTTPCreated
    # 201 Created, receive challenge token
    print "ACME challenge received.\n"
    p result

    # find simpleHttp challenge
    challenge = result['challenges'].find { |c| c['type'] == 'simpleHttp' }
    if challenge then
      # simpleHttp found.
      nexturl = challenge['uri']
      token   =challenge['token']
      return acme_simplehttp(nexturl, use_tls, server_name, token, script, rsa)
    else
      abort "ACME server does not permit simpleHttp challenge."
    end
  else
    p result
    abort "ACME identifier authorization failed with #{res.code}"
  end
end


#
# ACME certificate issuance request
#
def acme_newcertificate(url, csr, csrname, rsa)
  newcert = {
    'resource' => 'new-cert',
    'csr' => base64url(csr.to_der)
  }

  # send request 
  res,result = http_post(url, newcert, rsa)
  case res
  when Net::HTTPCreated
    # 201 Created, get certificate download URL from Location header
    crturl = res['Location']
    print "New certificate request succeeded.\n"
    print "Download your certificate from #{crturl}\n\n" 

    begin
      # save download URL
      open("#{csrname}.url", 'w') do |f|
        f.puts(crturl)
      end
    rescue => e
      p e
    end
    return crturl
  else
    p result
    abort "ACME certificate issuance request failed with #{res.code}"
  end
end


#
# ACME revoke certificate request
#
def acme_revokecertificate(url, crt, rsa)
  revoke = {
    'resource' => 'revoke-cert',
    'certificate' => base64url(crt.to_der)
  }

  # send request 
  res,result = http_post(url, revoke, rsa)
  case res
  when Net::HTTPOK
    print "Certificate is revoked\n"

  else
    p result
    abort "ACME revoke certificate request failed with #{res.code}"
  end
end


# ================================================================
#  Here is program entry point


# initialize commandline options
acme_url = ACME_URL_DEFAULT
opmode  = nil
rsa      = nil
rsaname  = nil
csrfile  = nil
csrname  = nil
email    = nil
tel      = nil
use_tls  = true
agree    = false
script   = File.join(SCRIPT_DIR, 'acme-validation.sh')


# parse commandline option
opt = OptionParser.new(nil, 20)

helpmsg = <<END_OF_BANNER
ACME simple offline client
  New account registration
    acme-offline -m new -e you@example.com -t +81345678901 -k private.pem
  Show account
    acme-offline -m show -k private.pem
  Update account, agree term of service
    acme-offline -m update -g -k private.pem
  Request certificate
      acme-offline -m auth -c server.csr [-p] [-s custom_script] -k private.pem

END_OF_BANNER
opt.banner = helpmsg + opt.banner



opt.on('-m MODE', 'new|show|update|auth|revoke')    { |v| opmode = v.upcase }
opt.on('-k ACCOUNT_RSA', 'ACME account RSA private key.'){ |rsafile|
  rsa = OpenSSL::PKey::RSA.new( File.read(rsafile) )
  rsaname = rsafile.sub(/[.][^.]*$/, '')
}
opt.on('-e EMAIL', 'Your contact email address.')   { |v| email = v }
opt.on('-t TEL', 'Your contact telephone number.')  { |v| tel = v }
opt.on('-g', 'Agree term of service.')              { |v| agree = true }
opt.on('-c SERVER_CSR|CRT', \
       'Server CSR(when auth) or CRT(when revoke).'){ |v|
  csrfile = v
  csrname = csrfile.sub(/[.][^.]*$/, '')
}
opt.on('-s SCRIPT', 'Custom script to process simpleHttp validation.'){ |v|
  script = v
}
opt.on('-p', 'Use plain HTTP, not HTTPS under simpleHttp validation.'){ |v|
  use_tls = false
}
opt.on('-a ACME_URL', 'Set ACME server URL.') { |v| acme_url = v }
opt.parse!(ARGV)

# check commandline
if ! rsa.is_a?(OpenSSL::PKey::RSA) then
  abort "RSA private key must be specified with -k option.\n\n" \
      + "See #{File.basename($0)} -h\n"
end


# Get ACME directory (command - URL mapping)
res, acme_directory = http_get(acme_url)
if ! res.is_a?(Net::HTTPOK ) then
  # not responding
  abort "ACME server #{acme_url} is not responding"
end


# check directory
newreg_url  = acme_directory['new-reg']
abort "Register URL is not found." unless newreg_url
newauth_url = acme_directory['new-authz']
abort "Identifier authorization URL is not found." unless newauth_url
newcert_url = acme_directory['new-cert']
abort "Certificate Issuance URL is not found." unless newcert_url
revoke_url = acme_directory['revoke-cert']
abort "Revoke certificate URL is not found." unless revoke_url


case opmode
when 'NEW'
  # Register new account with contact information
  if email || tel then
    acme_new_register(newreg_url, email, tel, rsa, rsaname)
  else
    abort "When new registration, contact information (email, tel) are needed."
  end

when 'SHOW'
  # Show registration, 'new-reg' to get location & 'reg' to get registered info
  reg_url = acme_new_register(newreg_url, nil, nil, rsa, rsaname)
  links = acme_update_register(reg_url, nil, nil, nil, rsa)
  p links
  print "Read term of service at #{links[:tos]}\n" if links[:tos]

when 'UPDATE'
  # Update registration, get registered info
  reg_url = acme_new_register(newreg_url, nil, nil, rsa, rsaname)
  links = acme_update_register(reg_url, nil, nil, nil, rsa)

  # then update registration
  tosurl = agree ? links[:tos] : nil
  acme_update_register(reg_url, email, tel, tosurl, rsa)  

when 'AUTH'
  # New authorization & issue mode
  csr = OpenSSL::X509::Request.new( File.read(csrfile) )
  # check CSR
  if csr then
    server_names = servernames_from_csr(csr)
    server_names.each do |server_name|
      if server_name.include?('*') then
        abort "Wildcard names are not supported yet. (#{server_name})"
      end
    end
  end

  if csr && server_names && 0<server_names.size then
    server_names.each do |server_name|
      acme_newauth(newauth_url, use_tls, server_name, script, rsa)
    end

    # Request certificate
    crturl = acme_newcertificate(newcert_url, csr, csrname, rsa)

    if crturl then
      # succeeded.
      print "================================================================\n"
      print "\n"
      print "Congratulations, certificate issuance succeeded.\n"
      print "You can download your certificate at\n  #{crturl}\n\n"
      print "Run following command on your web server:\n"
      print "  curl #{crturl} | \\\n"
      print "       openssl x509 -inform DER -outform PEM -out #{csrname}.crt\n"
      print "or\n"
      print "  wget -O - #{crturl} \\\n"
      print "       openssl x509 -inform DER -outform PEM -out #{csrname}.crt\n"
      print "\n"
      print "================================================================\n"
    end
  else
    abort "To request certificate, you must specify valid CSR."
  end

when 'REVOKE'
  # revoke certificate mode
  crt = OpenSSL::X509::Certificate.new( File.read(csrfile) ) if csrfile
  acme_revokecertificate(revoke_url, crt, rsa)
  
else
  abort "-m MODE must be specified.\n\nSee #{File.basename($0)} -h\n"

end
