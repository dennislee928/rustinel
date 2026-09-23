 winget install FireDaemon.OpenSSL

  # Auto-detect OpenSSL executable path
$openssl = if (Get-Command openssl -ErrorAction SilentlyContinue) {
     "openssl"
 } elseif (Test-Path "C:\Program Files\Git\usr\bin\openssl.exe") {
     "C:\Program Files\Git\usr\bin\openssl.exe"
 } else {
     throw "OpenSSL was not found. Please install it first."
 }

 # 1. Generate key and cert
 & $openssl req -x509 -newkey rsa:2048 -nodes -days 365 `
   -keyout temp_key.pem `
   -out temp_cert.pem `
   -subj "/C=US/ST=State/L=City/O=Organization/OU=Dev/CN=localhost"

 # 2. Combine into PEM bundle
 Get-Content temp_cert.pem, temp_key.pem | Set-Content -Encoding utf8 bundle.pem

 # 3. Clean up temporary files
 Remove-Item temp_cert.pem, temp_key.pem

Test-Path bundle.pem

Get-Content bundle.pem

& "C:\Program Files\Git\usr\bin\openssl.exe" x509 -in bundle.pem -modulus -noout
& "C:\Program Files\Git\usr\bin\openssl.exe" rsa -in bundle.pem -modulus -noout