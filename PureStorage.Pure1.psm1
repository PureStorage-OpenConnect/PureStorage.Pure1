function New-PureOneCertificate {
    <#
    .SYNOPSIS
      Creates a new certificate for use in authentication with Pure1.
    .DESCRIPTION
      Creates a properly formatted RSA 256 certificate
    .INPUTS
      Certificate store (optional)
    .OUTPUTS
      Returns the certificate
    .EXAMPLE
      PS C:\ New-PureOneCertificate

      Creates a properly formatted self-signed certificate for Pure1 authentication. Defaults to certificate store of cert:\currentuser\my
    .EXAMPLE
      PS C:\ New-PureOneCertificate -certificateStore cert:\localmachine\my

      Creates a properly formatted self-signed certificate for Pure1 authentication. Uses the specifed certificate store. Non-default stores usually require running as administrator. Windows only.
    .EXAMPLE
      PS /home/pureuser> $password = Read-Host -AsSecureString
      PS /home/pureuser> New-PureOneCertificate -RsaPassword $password

      Creates a properly formatted private and public key pair for Pure1 authentication. Uses the working directory. Linux or MacOS only.

    .EXAMPLE
      PS /home/pureuser> $password = Read-Host -AsSecureString  
      PS /home/pureuser> New-PureOneCertificate -RsaPassword $password -PrivateKeyFileDirectory "/home/pureuser"

      Creates a properly formatted private and public key pair for Pure1 authentication and stores it in specified directory. Linux or MacOS only.
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='Certificate')]
    Param(
            [Parameter(Position=0,ParameterSetName='Certificate')]
            [String]$CertificateStore = "cert:\currentuser\my",

            [Parameter(Position=1,ParameterSetName='RSAPair',mandatory=$True)]
            [SecureString]$RsaPassword,
            
            [Parameter(Position=2,ParameterSetName='RSAPair')]
            [Switch]$Overwrite,

            [Parameter(Position=3,ParameterSetName='RSAPair')]
            [String]$PrivateKeyFileDirectory
    )
    if ([string]::IsNullOrEmpty($PrivateKeyFileDirectory))
    {
      $keyPath = (Get-Location).Path
    }
    else {
      if ((Test-Path -Path $PrivateKeyFileDirectory) -eq $false)
      {
        throw "Entered path $($PrivateKeyFileDirectory) is not valid. Please enter a valid directory. For example, /home/user"
      }
      else {
        $keyPath = $PrivateKeyFileDirectory
      }
    }
    $checkPath = Test-Path "$($keyPath)/PureOnePrivate.pem"
    if (($checkPath -eq $true) -and ($Overwrite -eq $false))
    {
      throw "A pre-existing Pure1 Private Key exists at $($keyPath)/PureOnePrivate.pem. Overwriting this key will require a new application ID to be generated for the new key in Pure1. Either re-run with the -overwrite switch, or specify a different directory in the -keypath parameter, or skip this cmdlet and pass in the path of your custom key location to New-PureOneConnection."
    }
    if ($IsWindows -eq $false)
    {
      if ($RsaPassword.Length -eq 0)
      {
        $RsaPassword = Read-Host -Prompt "Please enter a password to be used for the private key" -AsSecureString
      }
      $DecryptedRsaPassword = ConvertFrom-SecureString $RsaPassword -AsPlainText 
      if (($DecryptedRsaPassword.length -lt 4) -or ($DecryptedRsaPassword.length -gt 1022))
      {
        throw "The entered private key password must be more than 4 characters and less than 1023 characters."
      }
      openssl genrsa -aes256 -passout pass:$DecryptedRsaPassword -out $keypath/PureOnePrivate.pem 2048 2>/dev/null
      openssl rsa -in $keypath/PureOnePrivate.pem -outform PEM -pubout -out $keypath/PureOnePublic.pem -passin pass:$DecryptedRsaPassword 2>/dev/null
      $keyPaths = [ordered]@{
        PrivateKey = "$($keyPath)/PureOnePrivate.pem"
        PublicKey = "$($keyPath)/PureOnePublic.pem"
      }
      return $keyPaths
    }
    if (($null -eq $isWindows) -or ($isWindows -eq $true))
    {
      if (([System.Environment]::OSVersion.Version).Major -eq 6)
      {
          #For Windows 2012 support--less specific but the default certificate still works.
          $CertObj = New-SelfSignedCertificate -certstorelocation $certificateStore -DnsName PureOneCert
      }
      else 
      {
          $policies = [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport,[System.Security.Cryptography.CngExportPolicies]::AllowExport
          $CertObj = New-SelfSignedCertificate -certstorelocation $certificateStore -HashAlgorithm "SHA256" -KeyLength 2048 -KeyAlgorithm RSA -KeyUsage DigitalSignature  -KeyExportPolicy $policies -Subject "PureOneCert" -ErrorAction Stop   
      }
      $cert = Get-ChildItem -Path $CertObj.PSPath
      return $cert
    }
}
function Get-PureOnePublicKey {
    <#
    .SYNOPSIS
      Retrives and formats a PEM based Public Key from a Windows-based certificate
    .DESCRIPTION
      Pulls out the public key and formats it in INT 64 PEM encoding for use in Pure1
    .INPUTS
      Certificate
    .OUTPUTS
      Returns the PEM based public key
    .EXAMPLE
      PS C:\ $cert = New-PureOneCertificate
      PS C:\ $cert | Get-PureOnePublicKey

      Returns the PEM formatted Public Key of the certificate passed in via piping so that it can be entered in Pure1.
    .EXAMPLE
      PS C:\ $cert = New-PureOneCertificate
      PS C:\ Get-PureOnePublicKey -certificate $cert

      Returns the PEM formatted Public Key of the certificate passed in so that it can be entered in Pure1.
    .EXAMPLE
      PS /home/pureuser> $password = Read-Host -AsSecureString
      PS /home/pureuser> $keys = New-PureOneCertificate -RsaPassword $password
      PS /home/pureuser> Get-PureOnePublicKey -PrivateKeyFileLocation $keys.PrivateKey -RsaPassword $password

      Returns the PEM formatted Public Key of the default Pure1 private key file passed in so that it can be entered in Pure1.
    .EXAMPLE
      PS /home/pureuser> $password = Read-Host -AsSecureString  
      PS /home/pureuser> Get-PureOnePublicKey -PrivateKeyFileLocation /home/pureuser/PureOnePrivateKey.pem -RsaPassword $password

      Returns the PEM formatted Public Key of a private key file passed in so that it can be entered in Pure1.
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Position=0,ValueFromPipeline=$True,mandatory=$True,ParameterSetName='Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,

        [Parameter(Position=1,ParameterSetName='RSAPair',mandatory=$True)]
        [String]$PrivateKeyFileLocation,

        [Parameter(Position=2,ParameterSetName='RSAPair',mandatory=$True)]
        [securestring]$RsaPassword
    )
    if ($null -eq $certificate)
    {
      $checkPath = Test-Path $PrivateKeyFileLocation
      if ($checkPath -eq $false)
      {
        throw "File not found at $($PrivateKeyFileLocation). Check path and try again."
      }
      $DecryptedRsaPassword = ConvertFrom-SecureString $RsaPassword -AsPlainText
      openssl rsa -in $($PrivateKeyFileLocation) -outform PEM -pubout -out ./PureOnePublicTemp.pem -passin pass:$DecryptedRsaPassword  2>/dev/null
      $checkPath = Test-Path ./PureOnePublicTemp.pem
      if ($checkPath -eq $false)
      {
        throw "Public key could not be generated. Confirm password and/or permission access to private key"
      }
      $publicKey = Get-Content ./PureOnePublicTemp.pem
      Remove-Item -Path ./PureOnePublicTemp.pem
      Return $publicKey
    }
    else {
     $certRaw = ([System.Convert]::ToBase64String($certificate.PublicKey.EncodedKeyValue.RawData)).tostring()
      return ("-----BEGIN PUBLIC KEY-----`n" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" + $certRaw + "`n-----END PUBLIC KEY-----")
    }
}
function New-PureOneJwt {
    <#
    .SYNOPSIS
      Takes in a Pure1 Application ID and certificate to create a JSON Web Token.
    .DESCRIPTION
      Takes in a Pure1 Application ID and certificate to create a JSON Web Token that is valid for by default 30 days, but is extended if a custom expiration is passed in. Can also take in a private key in lieu of the full cert. Will reject if the private key is not properly formatted.
    .INPUTS
      Pure1 Application ID, an expiration, and a certificate or a private key.
    .OUTPUTS
      Returns the JSON Web Token as a string.
    .EXAMPLE
        PS C:\ $cert = New-PureOneCertificate
        PS C:\ New-PureOneJwt -certificate $cert -pureAppID pure1:apikey:v4u3ZXXXXXXXXC6o

        Returns a JSON Web Token that can be used to create a Pure1 REST session. A JWT generated with no specificed expiration is valid for 30 days.
    .EXAMPLE
        PS C:\ $cert = New-PureOneCertificate
        PS C:\ New-PureOneJwt -certificate $cert -pureAppID pure1:apikey:v4u3ZXXXXXXXXC6o -expiration ((get-date).addDays(2))

        Returns a JSON Web Token that can be used to create a Pure1 REST session. An expiration is set for two days from now, so this JWT will be valid to create new REST sessions for 48 hours.
    .EXAMPLE
      PS /home/pureuser> $password = Read-Host -AsSecureString  
      PS /home/pureuser> New-PureOneJwt -PrivateKeyFileLocation /home/pureuser/PureOnePrivate.pem -RsaPassword $password -PureAppID pure1:apikey:TACAwKsXL7kLa96q

      Creates a JSON web token for external use for the specified private key and the associated Pure1 API key.
    .EXAMPLE
      PS /home/pureuser> $password = Read-Host -AsSecureString  
      PS /home/pureuser> New-PureOneJwt -PrivateKeyFileLocation /home/pureuser/PureOnePrivate.pem -RsaPassword $password -PureAppID pure1:apikey:TACAwKsXL7kLa96q

      Creates a JSON web token for external use for the specified private key and the associated Pure1 API key. An expiration is set for two days from now, so this JWT will be valid to create new REST sessions for 48 hours.
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding()]
    Param(
            [Parameter(Position=0,ValueFromPipeline=$True,ParameterSetName='Windows')]
            [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,

            [Parameter(Position=1,mandatory=$True)]
            [string]$PureAppID,
            
            [Parameter(Position=2,ValueFromPipeline=$True,ParameterSetName='Windows')]
            [System.Security.Cryptography.RSA]$PrivateKey,

            [Parameter(Position=3,ValueFromPipeline=$True)]
            [System.DateTime]$Expiration,

            [Parameter(Position=4,ParameterSetName='Unix',mandatory=$True)]
            [string]$PrivateKeyFileLocation,

            [Parameter(Position=5,ParameterSetName='Unix',mandatory=$True)]
            [securestring]$RsaPassword
    )
    if (($null -eq $isWindows) -or ($isWindows -eq $true))
    {
      if (($null -eq $privateKey) -and ($null -eq $certificate))
      {
          throw "You must pass in a x509 certificate or a RSA Private Key"
      }
      #checking for certificate accuracy
      if ($null -ne $certificate)
      {
          if ($certificate.HasPrivateKey -ne $true)
          {
              throw "There is no private key associated with this certificate. Please regenerate certificate with a private key."
          }
          if ($null -ne $certificate.PrivateKey)
          {
              $privateKey = $certificate.PrivateKey
          }
          else {
              try {
                  $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
              }
              catch {
                  throw "Could not obtain the private key from the certificate. Please re-run this cmdlet from a PowerShell session started with administrative rights or ensure you have Read Only or higher rights to the certificate."
              }
          }
      }
      #checking for correct private key type. Must be SHA-256, 2048 bit.
      if ($null -ne $privateKey)
      {
          if ($privateKey.KeySize -ne 2048)
          {
              throw "The key must be 2048 bit. It is currently $($privateKey.KeySize)"
          }
          if ($privateKey.SignatureAlgorithm -ne "RSA")
          {
              throw "This key is not an RSA-based key."
          }
      }
    }
    $pureHeader = '{"alg":"RS256","typ":"JWT"}'
    $curTime = (Get-Date).ToUniversalTime()
    $curTime = [Math]::Floor([decimal](Get-Date($curTime) -UFormat "%s"))
    if ($null -eq $expiration)
    {
        $expTime = $curTime  + 2592000
    }
    else {
        $expTime = $expiration.ToUniversalTime()
        $expTime = [Math]::Floor([decimal](Get-Date($expTime) -UFormat "%s"))
    }
    $payloadJson = '{"iss":"' + $pureAppID + '","iat":' + $curTime + ',"exp":' + $expTime + '}'
    $encodedHeader = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pureHeader)) -replace '\+','-' -replace '/','_' -replace '='
    $encodedPayload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson)) -replace '\+','-' -replace '/','_' -replace '='
    $toSign = $encodedHeader + '.' + $encodedPayload
    if ($IsWindows -eq $false) {
        if ($RsaPassword.Length -eq 0)
        {
          $RsaPassword = Read-Host -Prompt "Please enter a password to be used for the private key" -AsSecureString
        }
        $DecryptedRsaPassword = ConvertFrom-SecureString $RsaPassword -AsPlainText
        set-content -value $tosign -Path ./PureOneHeader.txt -NoNewline
        Start-Process -FilePath ./openssl -ArgumentList "dgst -binary -sha256 -sign $($PrivateKeyFileLocation) -passin pass:$($DecryptedRsaPassword) -out ./PureOneSignedHeader.txt ./PureOneHeader.txt"
        $signature = openssl base64 -in ./PureOneSignedHeader.txt
        if ($null -eq $signature)
        {
          #sometimes this needs retried, honestly not sure why.
          $signature = openssl base64 -in ./PureOneSignedHeader.txt
        }
        $signature = $signature -replace '\+','-' -replace '/','_' -replace '='
        Remove-Item -Path ./PureOneSignedHeader.txt
        Remove-Item -Path ./PureOneHeader.txt
    }
    else {
      $toSignEncoded = [System.Text.Encoding]::UTF8.GetBytes($toSign)
      $signature = [Convert]::ToBase64String($privateKey.SignData($toSignEncoded,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) -replace '\+','-' -replace '/','_' -replace '='
    }
    $jwt = $toSign + '.' + $signature 
    return $jwt.Replace(" ", "")
}
function New-PureOneConnection {
    <#
    .SYNOPSIS
      Takes in a Pure1 Application ID and certificate to create a 10 hour access token.
    .DESCRIPTION
      Takes in a Pure1 Application ID and certificate to create a 10 hour access token. Can also take in a private key in lieu of the full cert. Will reject if the private key is not properly formatted.
    .INPUTS
      Pure1 Application ID, a certificate or a private key.
    .OUTPUTS
      Does not return anything--it stores the Pure1 REST access token in a global variable called $Global:PureOneConnections. Valid for 10 hours.
    .EXAMPLE
      PS C:\ $cert = New-PureOneCertificate
      PS C:\ $cert | New-PureOneConnection -pureAppID pure1:apikey:PZogg67LcjImYTiI

      Create a Pure1 REST connection using a passed in certificate and the specified Pure1 App ID
    .EXAMPLE
      PS C:\ $cert = New-PureOneCertificate
      PS C:\ $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
      PS C:\ $privateKey | New-PureOneConnection -pureAppID pure1:apikey:PZogg67LcjImYTiI

      Create a Pure1 REST connection using a passed in private key and the specified Pure1 App ID
    .EXAMPLE
      PS /home/pureuser> $password = Read-Host -AsSecureString  
      PS /home/pureuser> New-PureOneConnection -PrivateKeyFileLocation /home/pureuser/PureOnePrivate.pem -RsaPassword $password -PureAppID pure1:apikey:TACAwKsXL7kLa96q

      Creates a Pure1 REST connection for use with additional Pure1 cmdlets.
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='Certificate')]
    Param(
            [Parameter(Position=0,ValueFromPipeline=$True,mandatory=$True,ParameterSetName='Certificate')]
            [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,

            [Parameter(Position=1,mandatory=$True)]
            [string]$PureAppID,
            
            [Parameter(Position=2,ValueFromPipeline=$True,mandatory=$True,ParameterSetName='PrivateKey')]
            [System.Security.Cryptography.RSA]$PrivateKey,

            [Parameter(Position=3)]
            [switch]$ReturnOrg,

            [Parameter(Position=4,ParameterSetName='Unix',mandatory=$True)]
            [string]$PrivateKeyFileLocation,

            [Parameter(Position=5,ParameterSetName='Unix',mandatory=$True)]
            [securestring]$RsaPassword
    )
    if ([string]::IsNullOrEmpty($PrivateKeyFileLocation))
    {
      if ($null -eq $certificate)
      {
          $jwt = New-PureOneJwt -privateKey $privateKey -pureAppID $pureAppID -expiration ((Get-Date).AddSeconds(60))
      }
      else {
          $jwt = New-PureOneJwt -certificate $certificate -pureAppID $pureAppID -expiration ((Get-Date).AddSeconds(60)) 
      }
    }
    else {
      $jwt = New-PureOneJwt -PrivateKeyFileLocation $PrivateKeyFileLocation -RsaPassword $RsaPassword -pureAppID $pureAppID -expiration ((Get-Date).AddSeconds(60))
    }
    $apiendpoint = "https://api.pure1.purestorage.com/oauth2/1.0/token"
    $AuthAction = @{
        grant_type = "urn:ietf:params:oauth:grant-type:token-exchange"
        subject_token = $jwt
        subject_token_type = "urn:ietf:params:oauth:token-type:jwt"
        }
    $pureOnetoken = Invoke-RestMethod -Method Post -Uri $apiendpoint -ContentType "application/x-www-form-urlencoded" -Body $AuthAction
    write-debug $pureOnetoken
    $orgInfo = Resolve-JWTtoken -token $pureOnetoken
    $date = get-date "1/1/1970"
    $date = $date.AddSeconds($orgInfo.exp).ToLocalTime()
    if (($null -eq $isWindows) -or ($isWindows -eq $true))
    {
      $newOrg = New-Object -TypeName WindowsPureOneOrganization -ArgumentList $orgInfo.org,$pureOnetoken.access_token,$PureAppID,$orgInfo.max_role,$date,$certificate -ErrorAction Stop
    }
    else {
      $newOrg = $newOrg = New-Object -TypeName UnixPureOneOrganization -ArgumentList $orgInfo.org,$pureOnetoken.access_token,$PureAppID,$orgInfo.max_role,$date,$RsaPassword,$PrivateKeyFileLocation -ErrorAction Stop
    }
    if ($Global:PureOneConnections.Count -eq 0)
    {
      $Global:PureOneConnections += $newOrg
      $Global:PureOneConnections[0].SetDefault($true)
    }
    else 
    {
      foreach ($connection in $Global:PureOneConnections) 
      {
        if ($connection.PureOneOrgID -eq $newOrg.PureOneOrgID)
          {
            if ($connection.updateLock -eq $false)
            {
              throw "The Pure1 Organization with ID $($connection.PureOneOrgID) is already connected."
            }
            else {
              $pureOneUpdate = $True
              break
            }
          }
        }
      if ($pureOneUpdate -ne $true)
      {
        $Global:PureOneConnections += $newOrg
      }
    }
    if ($returnOrg -eq $true)
    {
      return $newOrg
    }
}
function New-PureOneOperation {
  <#
  .SYNOPSIS
    Allows you to run a Pure1 REST operation that has not yet been built into this module.
  .DESCRIPTION
    Runs a REST operation to Pure1
  .INPUTS
    A filter/query, an resource, a REST body, and optionally an access token.
  .OUTPUTS
    Returns Pure1 REST response.
  .EXAMPLE
    PS C:\ $cert = New-PureOneCertificate
    PS C:\ $cert | New-PureOneConnection -pureAppID pure1:apikey:PZogg67LcjImYTiI
    PS C:\ New-PureOneOperation -resourceType volumes -restOperationType GET

    Create a Pure1 REST connection and requests all volumes
  .EXAMPLE
    PS C:\ $cert = New-PureOneCertificate
    PS C:\ $cert | New-PureOneConnection -pureAppID pure1:apikey:PZogg67LcjImYTiI
    PS C:\ New-PureOneOperation -resourceType arrays -restOperationType GET

    Create a Pure1 REST connection and requests all arrays
  .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support

  *******Disclaimer:******************************************************
  This scripts are offered "as is" with no warranty.  While this 
  scripts is tested and working in my environment, it is recommended that you test 
  this script in a test lab before using in a production environment. Everyone can 
  use the scripts/commands provided here without any written permission but I
  will not be liable for any damage or loss to the system.
  ************************************************************************
  #>

  [CmdletBinding()]
  Param(
      [Parameter(Position=0,mandatory=$True)]
      [string]$ResourceType,

      [Parameter(Position=1)]
      [string]$QueryFilter,

      [Parameter(Position=2)]
      [string]$JsonBody,

      [Parameter(Position=3,mandatory=$True)]
      [ValidateSet('POST','GET','DELETE','PUT')]
      [string]$RestOperationType,

      [Parameter(Position=4)]
      [string]$PureOneToken
  )
  $pureOneHeader = Set-PureOneHeader -pureOneToken $pureOneToken -ErrorAction Stop
  Write-Debug $pureOneHeader.authorization
  $apiendpoint = "https://api.pure1.purestorage.com/api/$($global:pureOneRestVersion)/" + $resourceType + $queryFilter
  Write-Debug $apiendpoint
  $ErrorActionPreference = "Stop"
  if ($jsonBody -ne "")
  {
      $pureResponse = Invoke-RestMethod -Method $restOperationType -Uri $apiendpoint -ContentType "application/json" -Headers $pureOneHeader  -Body $jsonBody -ErrorAction Stop
      $pureObjects = $pureResponse.items
  }
  else 
  {
    $pureResponse = Invoke-RestMethod -Method $restOperationType -Uri $apiendpoint -ContentType "application/json" -Headers $pureOneHeader -ErrorAction Stop
    Write-Debug $pureResponse
    $pureObjects = $pureResponse.items
    while ($null -ne $pureResponse.continuation_token) 
    {
        $continuationToken = $pureResponse.continuation_token
        if ($queryFilter -eq "")
        {
            $apiendpoint = $apiendpoint + "?"
        }
        try {            
          $pureResponse = Invoke-RestMethod -Method $restOperationType -Uri ($apiendpoint + "&continuation_token=`'$($continuationToken)`'") -ContentType "application/json" -Headers $pureOneHeader -ErrorAction Stop
          write-debug $pureResponse
          $pureObjects += $pureResponse.items
        }
        catch {
          write-debug $_
          if ($_.Exception -like "*The remote server returned an error: (504) Gateway Timeout.*")
          {
            Write-Warning -Message "The remote server returned an error: (504) Gateway Timeout. Pausing briefly and re-trying."
            start-sleep 5
          }
          elseif ((convertfrom-json -inputobject $_.ErrorDetails.Message).Message -eq "API org rate limit exceeded")
          {
            Write-Warning -Message "Pure1 API rate limit exceeded. Sleeping briefly to reset counter."
            start-sleep 5
          }
          continue
        } 
    }  
  }   
  $ErrorActionPreference = "Continue"
  return $pureObjects
}
function Get-PureOneArray {
    <#
    .SYNOPSIS
      Returns all Pure Storage arrays listed in your Pure1 account.
    .DESCRIPTION
      Returns all Pure Storage arrays listed in your Pure1 account. Allows for some filters.
    .INPUTS
      None required. Optional inputs are array type, array name, and Pure1 access token.
    .OUTPUTS
      Returns the Pure Storage array information in Pure1.
    .EXAMPLE
      PS C:\ Get-PureOneArray

      Returns all arrays in all connected Pure1 organizations
    .EXAMPLE
      PS C:\ Get-PureOneArray -arrayProduct FlashBlade

      Returns all FlashBlades in all connected Pure1 organizations
    .EXAMPLE
      PS C:\ Get-PureOneArray -arrayId ef9d6965-7e16-4d46-9425-d2fea48a8fe5

      Returns array with specified ID
    .EXAMPLE
      PS C:\ Get-PureOneArray -arrayName sn1-m20r2-c05-36

      Returns array with specified name
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='OrgProduct')]
    Param(
            [Parameter(Position=0,ParameterSetName='Name',mandatory=$True)]
            [string]$ArrayName,

            [Parameter(Position=1,ParameterSetName='Product',mandatory=$True)]
            [ValidateSet('Purity//FA','Purity//FB','FlashArray','FlashBlade')]
            [string]$ArrayProduct,
            
            [Parameter(Position=2,ParameterSetName='ID',mandatory=$True)]
            [string]$ArrayId,

            [Parameter(Position=3)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization[]]$PureOneOrganization
    )
      if ($arrayProduct -ne "")
      {
          switch ($arrayProduct) {
              "FlashArray" {$arrayProduct = 'Purity//FA'; break}
              "FlashBlade" {$arrayProduct = 'Purity//FB'; break}
            }
      }
      if ($arrayName -ne "")
      {
          $restQuery = "?names=`'$($arrayName)`'"
      }
      if ($arrayProduct -ne "")
      {
          $restQuery = "?filter=os=`'$($arrayProduct)`'"
      }
      if ($arrayId -ne "")
      {
          $restQuery = "?ids=`'$($arrayId)`'"
      }
      $tokens = @()
      if ([string]::IsNullOrWhiteSpace($pureOneToken))
      {
        $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
      }
      else{
        $tokens += $pureOneToken
      }
      $pureArrays = @()
      foreach ($token in $tokens) {
        $pureArrays += New-PureOneOperation -resourceType arrays -queryFilter $restQuery -pureOneToken $token -restOperationType GET -ErrorAction SilentlyContinue
      }
      if (($pureArrays | Measure-Object).Count -eq 0)
      {
        throw "No matching arrays were found on entered Pure1 organization(s)."
      }
      return $pureArrays    
}
function Get-PureOneArrayTag {
    <#
    .SYNOPSIS
      Gets a tag for a given array or arrays in Pure1
    .DESCRIPTION
      Gets a tag for a given array or arrays in Pure1
    .INPUTS
      Array name(s) or ID(s) and optionally a tag key name and/or an access token.
    .OUTPUTS
      Returns the Pure Storage array(s) key/value tag information in Pure1.
    .EXAMPLE
      PS C:\ Get-PureOneArrayTag 

      Returns all tags
    .EXAMPLE
      PS C:\ Get-PureOneArrayTag -tagKey owner 

      Returns all tags with the key of "owner"
    .EXAMPLE
      PS C:\ Get-PureOneArrayTag -arrayNames flasharray-m50-2

      Returns all matching tags on array with specified name
    .EXAMPLE
      PS C:\ Get-PureOneArrayTag -tagKey owner -arrayIds aad42743-611e-45ac-8b93-a869c4728a1d

      Returns matching tags with key of "owner" on array with specified ID
    .EXAMPLE
      PS C:\ Get-PureOneArrayTag -tagKey owner -arrayIds aad42743-611e-45ac-8b93-a869c4728a1d,e8998e19-aa08-45db-8bd0-4ea9171277a3

      Returns matching tags with key of "owner" on the arrays with specified IDs
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='TagKey')]
    Param(
            [Parameter(Position=0,ParameterSetName='ArrayNames')]
            [string[]]$ArrayNames,
         
            [Parameter(Position=1,ParameterSetName='ArrayIDs')]
            [string[]]$ArrayIds,

            [Parameter(Position=2,ParameterSetName='ArrayIDs')]
            [Parameter(Position=2,ParameterSetName='ArrayNames')]
            [Parameter(Position=2,ParameterSetName='TagKey')]
            [string]$TagKey,

            [Parameter(Position=3)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization[]]$PureOneOrganization
    )
      if ($arrayNames.count -gt 0)
      {
          $objectQuery = "resource_names="
          for ($i=0;$i -lt $arrayNames.count; $i++)
          {
              if ($i-eq 0)
              {
                  $objectQuery = $objectQuery + "`'$($arrayNames[$i])`'"
              }
              else {
                  $objectQuery = $objectQuery + ",`'$($arrayNames[$i])`'"
              }
          }
      }
      if ($arrayIds.Count -gt 0)
      {
          $objectQuery = "resource_ids="
          for ($i=0;$i -lt $arrayIds.count; $i++)
          {
              if ($i-eq 0)
              {
                  $objectQuery = $objectQuery + "`'$($arrayIds[$i])`'"
              }
              else {
                  $objectQuery = $objectQuery + ",`'$($arrayIds[$i])`'"
              }
          }
      }
      if ($tagKey -ne "")
      {
          $keyQuery = "?keys=`'$($tagKey)`'"
          if (($arrayNames.count -gt 0) -or ($arrayIds.count -gt 0))
          {
              $keyQuery = $keyQuery + "&"
          }
      }
      else
      {    
          $keyQuery = "?"
      }
      $tokens = @()
      if ([string]::IsNullOrWhiteSpace($pureOneToken))
      {
        $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
      }
      else{
        $tokens += $pureOneToken
      }
      $pureArrayTags = @()
      foreach ($token in $tokens) {
        $pureArrayTags += New-PureOneOperation -resourceType "arrays/tags" -queryFilter "$($keyQuery)$($objectQuery)" -pureOneToken $token -restOperationType GET -ErrorAction SilentlyContinue
      }
      return $pureArrayTags    
}
function Set-PureOneArrayTag {
    <#
    .SYNOPSIS
      Sets/updates a tag for a given array or arrays in Pure1
    .DESCRIPTION
      Sets/updates a tag for a given array or arrays in Pure1
    .INPUTS
      Array name(s) or ID(s) and a tag key name/value and/or optionally an access token.
    .OUTPUTS
      Returns the Pure Storage array(s) key/value tag information in Pure1.
    .EXAMPLE
      PS C:\ Set-PureOneArrayTag -tagKey owner -tagValue cody -arrayNames flasharray-m50-2

      Creates/updates tag on array with specified name
    .EXAMPLE
      PS C:\ Set-PureOneArrayTag -tagKey owner -tagValue cody -arrayNames flasharray-m50-2,flasharray-m50-1

      Creates/updates tag on specified arrays
    .EXAMPLE
      PS C:\ Set-PureOneArrayTag -tagKey owner -arrayIds aad42743-611e-45ac-8b93-a869c4728a1d

      Creates/updates tag on array with specified ID
    .EXAMPLE
      PS C:\ Set-PureOneArrayTag -tagKey owner -arrayIds aad42743-611e-45ac-8b93-a869c4728a1d,e8998e19-aa08-45db-8bd0-4ea9171277a3

      Creates/updates tag on the arrays with specified IDs
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='ArrayNames')]
    Param(
            [Parameter(Position=0,mandatory=$True,ParameterSetName='ArrayNames')]
            [string[]]$ArrayNames,
         
            [Parameter(Position=1,mandatory=$True,ParameterSetName='ArrayIDs')]
            [string[]]$ArrayIds,

            [Parameter(Position=2,mandatory=$True,ParameterSetName='ArrayIDs')]
            [Parameter(Position=2,mandatory=$True,ParameterSetName='ArrayNames')]
            [string]$TagKey,

            [Parameter(Position=3,mandatory=$True,ParameterSetName='ArrayIDs')]
            [Parameter(Position=3,mandatory=$True,ParameterSetName='ArrayNames')]
            [string]$TagValue,

            [Parameter(Position=4)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization[]]$PureOneOrganization

    )
    if ($arrayNames.count -gt 0)
    {
        $objectQuery = "?resource_names="
        for ($i=0;$i -lt $arrayNames.count; $i++)
        {
            if ($i-eq 0)
            {
                $objectQuery = $objectQuery + "`'$($arrayNames[$i])`'"
            }
            else {
                $objectQuery = $objectQuery + ",`'$($arrayNames[$i])`'"
            }
        }
    }
    if ($arrayIds.Count -gt 0)
    {
        $objectQuery = "?resource_ids="
        for ($i=0;$i -lt $arrayIds.count; $i++)
        {
            if ($i-eq 0)
            {
                $objectQuery = $objectQuery + "`'$($arrayIds[$i])`'"
            }
            else {
                $objectQuery = $objectQuery + ",`'$($arrayIds[$i])`'"
            }
        }
    }
    $newTag = @{
        key = ${tagKey}
        value = ${tagValue}
    }
    $newTagJson = $newTag |ConvertTo-Json
    $newTagJson = "[" + $newTagJson + "]"
    $tokens = @()
    if ([string]::IsNullOrWhiteSpace($pureOneToken))
    {
      $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
    }
    else{
      $tokens += $pureOneToken
    }
    $pureArrayTags = @()
    foreach ($token in $tokens) {
      $pureArrayTags += New-PureOneOperation -resourceType "arrays/tags/batch" -queryFilter $objectQuery -pureOneToken $token -restOperationType PUT -jsonBody $newTagJson -ErrorAction SilentlyContinue
    }
    if (($pureArrayTags | Measure-Object).Count -eq 0)
    {
      throw "Tag not created. No matching arrays were found on entered Pure1 organization(s)."
    } 
    return $pureArrayTags        
}
function Remove-PureOneArrayTag {
    <#
    .SYNOPSIS
      Removes one or more tags for a given array or arrays in Pure1
    .DESCRIPTION
      Removes one or more tags for a given array or arrays in Pure1
    .INPUTS
      Array name(s) or ID(s) and one or more tag key names and/or optionally an access token. If you do not enter a key name, all tags for the input arrays will be removed.
    .OUTPUTS
      Returns nothing.
    .EXAMPLE
      PS C:\ Remove-PureOneArrayTag -tagKey owner -arrayNames flasharray-m50-2

      Removes all matching tags on array with specified name
    .EXAMPLE
      PS C:\ Remove-PureOneArrayTag -tagKey owner -arrayIds aad42743-611e-45ac-8b93-a869c4728a1d

      Removes matching tags with key of "owner" on array with specified ID
    .EXAMPLE
      PS C:\ Remove-PureOneArrayTag -tagKey owner -arrayIds aad42743-611e-45ac-8b93-a869c4728a1d,e8998e19-aa08-45db-8bd0-4ea9171277a3

      Removes matching tags with key of "owner" on the arrays with specified IDs
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='ArrayNames')]
    Param(
            [Parameter(Position=0,mandatory=$True,ParameterSetName='ArrayNames')]
            [string[]]$ArrayNames,
         
            [Parameter(Position=1,mandatory=$True,ParameterSetName='ArrayIDs')]
            [string[]]$ArrayIds,

            [Parameter(Position=2,mandatory=$True,ParameterSetName='ArrayIDs')]
            [Parameter(Position=2,mandatory=$True,ParameterSetName='ArrayNames')]
            [string[]]$TagKeys,

            [Parameter(Position=3)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization[]]$PureOneOrganization
    )
    if ($arrayNames.count -gt 0)
    {
        $objectQuery = "?resource_names="
        for ($i=0;$i -lt $arrayNames.count; $i++)
        {
            if ($i-eq 0)
            {
                $objectQuery = $objectQuery + "`'$($arrayNames[$i])`'"
            }
            else {
                $objectQuery = $objectQuery + ",`'$($arrayNames[$i])`'"
            }
        }
    }

    if ($arrayIds.Count -gt 0)
    {
        $objectQuery = "?resource_ids="
        for ($i=0;$i -lt $arrayIds.count; $i++)
        {
            if ($i-eq 0)
            {
                $objectQuery = $objectQuery + "`'$($arrayIds[$i])`'"
            }
            else {
                $objectQuery = $objectQuery + ",`'$($arrayIds[$i])`'"
            }
        }
    }
    if ($tagKeys.Count -gt 0)
    {
        $objectQuery = $objectQuery + "&keys="
        for ($i=0;$i -lt $tagKeys.count; $i++)
        {
            if ($i -eq 0)
            {
                $objectQuery = $objectQuery + "`'$($tagKeys[$i])`'"
            }
            else {
                $objectQuery = $objectQuery + ",`'$($tagKeys[$i])`'"
            }
        }
    }
    $tokens = @()
    if ([string]::IsNullOrWhiteSpace($pureOneToken))
    {
      $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
    }
    else{
      $tokens += $pureOneToken
    }
    $pureArrayTags = @()
    foreach ($token in $tokens) {
      $pureArrayTags += New-PureOneOperation -resourceType "arrays/tags" -queryFilter $objectQuery -pureOneToken $token -restOperationType DELETE -ErrorAction SilentlyContinue
    }
    if (($pureArrayTags | Measure-Object).Count -eq 0)
    {
      throw "No matching arrays were found on entered Pure1 organization(s)."
    }
    return $pureArrayTags   
}
function Get-PureOneArrayNetworking {
    <#
    .SYNOPSIS
      Returns the networking information for a given array in Pure1
    .DESCRIPTION
      Returns the the networking information for a given array in Pure1
    .INPUTS
      Array name or ID and optionally access token.
    .OUTPUTS
      Returns the Pure Storage array network information in all connected Pure1 organizations
    .EXAMPLE
      PS C:\ Get-PureOneArrayNetworking -arrayName sn1-m20-c08-17 

      Returns the networking information for all network interfaces
    .EXAMPLE
      PS C:\ Get-PureOneArrayNetworking -arrayName sn1-m20-c08-17 -virtualIP

      Returns the networking information for virtual IP interfaces
    .EXAMPLE
      PS C:\ Get-PureOneArrayNetworking -arrayName sn1-m20-c08-17 -service iscsi

      Returns the networking information for iscsi interfaces
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='ArrayName')]
    Param(
            [Parameter(Position=0,mandatory=$True,ParameterSetName='ArrayName')]
            [string]$ArrayName,
         
            [Parameter(Position=1,mandatory=$True,ParameterSetName='ArrayID')]
            [string]$ArrayId,

            [Parameter(Position=2,ParameterSetName='ArrayID')]
            [Parameter(Position=2,ParameterSetName='ArrayName')]
            [Switch]$VirtualIP,

            [Parameter(Position=3,ParameterSetName='ArrayID')]
            [Parameter(Position=3,ParameterSetName='ArrayName')]
            [string]$Service,

            [Parameter(Position=4)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization[]]$PureOneOrganization
    )
      if (($virtualIP -eq $true) -and (($service -ne "management") -and ($service -ne "") ))
      {
          throw "Virtual IPs are only management-based services, so you cannot request virtual IPs with $($service) as the service"
      }
      $objectQuery = "?"
      if ($virtualIP -eq $true)
      {
          $objectQuery = $objectQuery + "names=`'vir1`',`'vir0`'&"
      }
      if ($arrayName -ne "")
      {
          #URL encoding the square brackets as some network do not pass them properly
          $objectQuery = $objectQuery + "filter=" + ([System.Web.HttpUtility]::Urlencode("arrays[any].name")) + "=`'$($arrayName)`'"
      }
      if ($arrayId -ne "")
      {
          $objectQuery = $objectQuery + "filter=" + ([System.Web.HttpUtility]::Urlencode("arrays[any].name")) + "=`'$($arrayId)`'"
      }
      if ($service -ne "")
      {
          $objectQuery = $objectQuery + ([System.Web.HttpUtility]::Urlencode(" and services[any]")) + "=`'$($service)`'"
      }
      $tokens = @()
      if ([string]::IsNullOrWhiteSpace($pureOneToken))
      {
        $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
      }
      else{
        $tokens += $pureOneToken
      }
      $pureArrayNetwork = @()
      foreach ($token in $tokens) {
        $pureArrayNetwork += New-PureOneOperation -resourceType "network-interfaces" -queryFilter $objectQuery -pureOneToken $token -restOperationType GET  -ErrorAction SilentlyContinue
      }
      if (($pureArrayNetwork | Measure-Object).Count -eq 0)
      {
        throw "No networking information found. The specificied service: [$($service)] might not exist on this array or it might be misspelled"
      }
      return $pureArrayNetwork
}
function Get-PureOneMetricDetail {
    <#
    .SYNOPSIS
      Returns the available metrics in Pure1 
    .DESCRIPTION
      Returns the available metrics in Pure1 and their specifics
    .INPUTS
      Resource type or metric name and/or access token.
    .OUTPUTS
      Returns the Pure Storage metric details
    .EXAMPLE
      PS C:\ Get-PureOneMetricDetail

      Returns the details for all available metrics
    .EXAMPLE
      PS C:\ Get-PureOneMetricDetail -resourceType volumes

      Returns the details for all available volume-based metrics
    .EXAMPLE
      PS C:\ Get-PureOneMetricDetail -metricName pod_write_qos_rate_limit_time_us

      Returns the details for the metric named pod_write_qos_rate_limit_time_us
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='ResourceType')]
    Param(
            [Parameter(Position=0,ParameterSetName='MetricName')]
            [string]$MetricName,
         
            [Parameter(Position=1,ParameterSetName='ResourceType')]
            [string]$ResourceType,

            [Parameter(Position=2)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization]$PureOneOrganization
    )
        $objectQuery = "?"
        if ($resourceType -ne "")
        {
            $objectQuery = $objectQuery + "resource_types=`'$($resourceType)`'&"
        }
        if ($metricName -ne "")
        {
            $objectQuery = $objectQuery +"names=`'$($metricName)`'"
        }
        $tokens = @()
        if ([string]::IsNullOrWhiteSpace($pureOneToken))
        {
          $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
        }
        else{
          $tokens += $pureOneToken
        }
        $pureOneMetrics = @()
        $pureOneMetrics += New-PureOneOperation -resourceType "metrics" -queryFilter $objectQuery -pureOneToken $tokens[0] -restOperationType GET -ErrorAction SilentlyContinue
        return $pureOneMetrics  
}
function Get-PureOneMetric {
    <#
    .SYNOPSIS
      Returns the metrics for a given array in Pure1
    .DESCRIPTION
      Returns the metrics for a given array in Pure1, either an average or a maximum of a given time period. Default behavior is to return the average.
    .INPUTS
      Required: resource name or ID and metric name. Optional: timeframe, granularity, and aggregation type (if none entered defaults will be used based on metric entered). Also optionally an access token.
    .OUTPUTS
      Returns the Pure Storage array information in Pure1.
    .EXAMPLE
      PS C:\ Get-PureOneMetric -metricName array_read_iops -objectName sn1-x70-c05-33

      Returns all data points available for the specified metric on the target object (in this case read IOPs for the array)
    .EXAMPLE
      PS C:\ Get-PureOneMetric -metricName array_read_iops -objectName sn1-x70-c05-33 -maximum

      Returns all maximum data points (no average taken, the highest value instead is used) available for the specified metric on the target object (in this case read IOPs for the array)
    .EXAMPLE
      PS C:\ Get-PureOneMetric -metricName array_read_iops -objectName sn1-x70-c05-33 -startTime (get-date).AddDays(-10)

      Returns all data points for the last 10 days for the specified metric on the target object (in this case read IOPs for the array)
    .EXAMPLE
      PS C:\ Get-PureOneMetric -metricName array_read_iops -objectName sn1-x70-c05-33 -startTime (get-date).AddDays(-7) -endTime (get-date).AddDays(-6) 

      Returns all data points for the the one day a week prior for the specified metric on the target object (in this case read IOPs for the array)
    .EXAMPLE
      PS C:\ Get-PureOneMetric -metricName array_read_iops -objectName sn1-x70-c05-33 -startTime (get-date).AddDays(-7) -endTime (get-date).AddDays(-6) -granularity 3600000 -maximum

      Returns the highest valued data point per hour (every 3,600,000 milliseconds) for the the one day a week prior for the specified metric on the target object (in this case read IOPs for the array)
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>
    [CmdletBinding(DefaultParameterSetName='ObjectNameAvg')]
    Param(
            [Parameter(Position=0,mandatory=$True,ParameterSetName='ObjectNameAvg')]
            [Parameter(Position=0,mandatory=$True,ParameterSetName='ObjectNameMax')]
            [string]$ObjectName,
        
            [Parameter(Position=1,mandatory=$True,ParameterSetName='ObjectIDAvg')]
            [Parameter(Position=1,mandatory=$True,ParameterSetName='ObjectIDMax')]
            [string]$ObjectId,

            [Parameter(Position=2,ParameterSetName='ObjectIDAvg')]
            [Parameter(Position=2,ParameterSetName='ObjectNameAvg')]
            [switch]$Average,

            [Parameter(Position=3,ParameterSetName='ObjectIDMax')]
            [Parameter(Position=3,ParameterSetName='ObjectNameMax')]
            [switch]$Maximum,

            [Parameter(Position=4,mandatory=$True)]
            [string]$MetricName,

            [Parameter(Position=5)]
            [System.DateTime]$StartTime,

            [Parameter(Position=6)]
            [System.DateTime]$EndTime,

            [Parameter(Position=7)]
            [Int64]$Granularity,

            [Parameter(Position=8)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization[]]$PureOneOrganization
    )
      if (($average -eq $false) -and ($maximum -eq $false)) 
      {
          #defaulting to average if neither option is entered
          $average = $true
      }
      #get metric rules
      $metricDetails = Get-PureOneMetricDetail -metricName $metricName
      #set granularity if not set
      if ($granularity -eq 0)
      {
          $granularity = $metricDetails.availabilities.resolution
      }

      #set end time to start time minus retention for that stat (if not entered) and convert to epoch time
      if ($null -eq $endTime)
      {
          $endTime = Get-Date
          $endTime = $endTime.ToUniversalTime()
      }
      else {
          $endTime = $endTime.ToUniversalTime()
      }
      [datetime]$epoch = '1970-01-01 00:00:00'
      $endEpoch = (New-TimeSpan -Start $epoch -End $endTime).TotalMilliSeconds
      $endEpoch = [math]::Round($endEpoch)

      #set start time to current time (if not entered) and convert to epoch time
      if ($null -eq $startTime)
      {
          $startTime = $epoch.AddMilliseconds($metricDetails._as_of - $metricDetails.availabilities.retention)
      }
      else {
          $startTime = $startTime.ToUniversalTime()
      }
      $startEpoch = (New-TimeSpan -Start $epoch -End $startTime).TotalMilliSeconds
      $startEpoch = [math]::Round($startEpoch)

      #building query
      if ($average -eq $true)
      {
          $objectQuery = "?aggregation='avg'&end_time=$($endEpoch)&names=`'$($metricName)`'&resolution=$($granularity)&start_time=$($startEpoch)&"
      }
      else {
          $objectQuery = "?aggregation='max'&end_time=$($endEpoch)&names=`'$($metricName)`'&resolution=$($granularity)&start_time=$($startEpoch)&"
      }
      if ($objectName -ne "")
      {
          $objectQuery = $objectQuery + "resource_names=`'$($objectName)`'"
      }
      else {
          $objectQuery = $objectQuery + "ids=`'$($objectId)`'"
      }
      $tokens = @()
      if ([string]::IsNullOrWhiteSpace($pureOneToken))
      {
        $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
      }
      else{
        $tokens += $pureOneToken
      }
      $pureOneMetrics = @()
      foreach ($token in $tokens) {
        $pureOneMetrics += New-PureOneOperation -resourceType "metrics/history" -queryFilter $objectQuery -pureOneToken $token -restOperationType GET -ErrorAction SilentlyContinue
      }
      if (($pureOneMetrics | Measure-Object).Count -eq 0)
      {
        throw "No matching arrays were found on entered Pure1 organization(s)."
      }
      return $pureOneMetrics  
}
function Get-PureOneVolume {
    <#
    .SYNOPSIS
      Returns all Pure Storage volumes listed in your Pure1 account.
    .DESCRIPTION
      Returns all Pure Storage volumes listed in your Pure1 account. Allows for some filters.
    .INPUTS
      None required. Optional inputs are array type, array name, and Pure1 access token.
    .OUTPUTS
      Returns the Pure Storage array information in Pure1.
    .EXAMPLE
      PS C:\ Get-PureOneVolume 

      Get all volumes on all FlashArrays in all connected Pure1 organizations.
    .EXAMPLE
      PS C:\ Get-PureOneVolume -arrayName sn1-x70-b05-33

      Get all volumes on specified FlashArray.
    .EXAMPLE
      PS C:\ Get-PureOneVolume -volumeName myVolume-01

      Get all volumes with the specified name. If the same name exists on two more more arrays, all objects will be returned.
    .EXAMPLE
      PS C:\ Get-PureOneVolume -volumeName myVolume-01 -arrayName sn1-x70-b05-33

      Get the volume with the specified name if it exists on that array.
    .EXAMPLE
      PS C:\ Get-PureOneVolume -volumeSerial 1037B35FD0EF40A500C65559

      Get the volume with the specified serial number.
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='ArrayNameVolName')]
    Param(
            [Parameter(Position=0,ParameterSetName='ArrayNameVolName')]
            [Parameter(Position=0,ParameterSetName='ArrayNameVolSerial')]
            [string]$ArrayName,
            
            [Parameter(Position=1,ParameterSetName='ArrayIDVolName')]
            [Parameter(Position=1,mandatory=$True,ParameterSetName='ArrayIDVolSerial')]
            [string]$ArrayId,

            [Parameter(Position=2,ParameterSetName='ArrayIDVolName')]
            [Parameter(Position=2,ParameterSetName='ArrayNameVolName')]
            [string]$VolumeName,

            [Parameter(Position=3,ParameterSetName='ArrayIDVolSerial')]
            [Parameter(Position=3,ParameterSetName='ArrayNameVolSerial')]
            [string]$VolumeSerial,

            [Parameter(Position=4)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization[]]$PureOneOrganization
    )
      if ($null -ne $global:pureOneRateLimit)
      {
        if ($Global:pureOneRateLimit -in 1..1000)
        {
          $objectQuery = "?limit=$($global:pureOneRateLimit)&"
        }
        else {
          throw "Pure1 Rate limit set to invalid amount. Must be between 1-1000. Currently set to $($global:pureOneRateLimit)"
        }
      }
      else {
        $objectQuery = "?"
      }
      if ($volumeName -ne "")
      {
          $restQuery = $restQuery + "names=`'$($volumeName)`'"
          if (($arrayName -ne "") -or ($arrayId -ne ""))
          {
              $objectQuery = $objectQuery + "&"
          }
      }
      elseif ($volumeSerial -ne "")
      {
          $volumeSerial = $volumeSerial.ToUpper()
          $objectQuery = $objectQuery +"filter=serial=`'$($volumeSerial)`'"
          if ($arrayName -ne "")
          {
              $objectQuery = $objectQuery + ([System.Web.HttpUtility]::Urlencode(" and arrays[any].name")) + "=`'$($arrayName)`'"
          }
          if ($arrayId -ne "")
          {
              $objectQuery = $objectQuery + ([System.Web.HttpUtility]::Urlencode(" and arrays[any].id")) + "=`'$($arrayId)`'"
          }
      }
      if ($volumeSerial -eq "")
      {
          if ($arrayName -ne "")
          {
              $objectQuery = $objectQuery + "filter=" + ([System.Web.HttpUtility]::Urlencode("arrays[any].name")) + "=`'$($arrayName)`'"
          }
          if ($arrayId -ne "")
          {
              $objectQuery = $objectQuery + "filter=" + ([System.Web.HttpUtility]::Urlencode("arrays[any].id")) + "=`'$($arrayId)`'"
          }
      }
      $tokens = @()
      if ([string]::IsNullOrWhiteSpace($pureOneToken))
      {
        $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
      }
      else{
        $tokens += $pureOneToken
      }
      $pureVolumes = @()
      foreach ($token in $tokens) {
        $pureVolumes += New-PureOneOperation -resourceType "volumes" -queryFilter $objectQuery -pureOneToken $token -restOperationType GET -ErrorAction SilentlyContinue
      }
      if (($pureVolumes | Measure-Object).Count -eq 0)
      {
        throw "No matching volumes were found on entered Pure1 organization(s)."
      }
      return $pureVolumes
}
function Get-PureOnePod {
    <#
    .SYNOPSIS
      Returns all Pure Storage pods listed in your Pure1 account.
    .DESCRIPTION
      Returns all Pure Storage pods listed in your Pure1 account. Allows for some filters.
    .INPUTS
      None required. Optional inputs are pod name, array name or ID, and Pure1 access token.
    .OUTPUTS
      Returns the Pure Storage pod information in all connected Pure1 organizations.
    .EXAMPLE
      PS C:\ Get-PureOnePod

      Returns all pods on all FlashArrays in all connected Pure1 organizations
    .EXAMPLE
      PS C:\ Get-PureOnePod -arrayId 2dcf29ad-6aca-4913-b62e-a15875c6635f

      Returns all pods on FlashArray with specified ID
    .EXAMPLE
      PS C:\ Get-PureOnePod -podName newpod 

      Returns all pods with the specified name
    .EXAMPLE
      PS C:\ Get-PureOnePod -podName newpod -arrayName sn1-m20-c12-25

      Returns the pod with the specified name on the specified FlashArray
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='Pod')]
    Param(
            [Parameter(Position=0,ParameterSetName='ArrayName')]
            [Parameter(Position=0,ParameterSetName='Pod')]
            [string]$ArrayName,
            
            [Parameter(Position=1,ParameterSetName='ArrayId')]
            [Parameter(Position=1,ParameterSetName='Pod')]
            [string]$ArrayId,

            [Parameter(Position=2,ParameterSetName='Pod')]
            [string]$PodName,

            [Parameter(Position=3)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization[]]$PureOneOrganization
    )
        $objectQuery = "?"
        if ($podName -ne "")
        {
            $objectQuery = $objectQuery + "names=`'$($podName)`'"
            if (($arrayName -ne "") -or ($arrayId -ne ""))
            {
                $objectQuery = $objectQuery + "&"
            }
        }
        if ($arrayName -ne "")
        {
            $objectQuery = $objectQuery + "filter=" + ([System.Web.HttpUtility]::Urlencode("arrays[any].name")) + "=`'$($arrayName)`'"
        }
        if ($arrayId -ne "")
        {
            $objectQuery = $objectQuery + "filter=" + ([System.Web.HttpUtility]::Urlencode("arrays[any].id")) + "=`'$($arrayId)`'"
        }
        $tokens = @()
        if ([string]::IsNullOrWhiteSpace($pureOneToken))
        {
          $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
        }
        else{
          $tokens += $pureOneToken
        }
        $purePods = @()
        foreach ($token in $tokens) {
          $purePods += New-PureOneOperation -resourceType "pods" -queryFilter $objectQuery -pureOneToken $token -restOperationType GET-ErrorAction SilentlyContinue
        }
        if (($purePods | Measure-Object).Count -eq 0)
        {
          throw "No matching pods were found on entered Pure1 organization(s)."
        }
        return $purePods
}
function Get-PureOneVolumeSnapshot {
    <#
    .SYNOPSIS
      Returns all Pure Storage volume snapshots listed in all connected Pure1 organizations.
    .DESCRIPTION
      Returns all Pure Storage volume snapshots listed in all connected Pure1 organizations. Allows for some filters.
    .INPUTS
      None required. Optional inputs are array type, array name, volume name, snapshot name or snapshot serial, or Pure1 access token.
    .OUTPUTS
      Returns the Pure Storage array information in all connected Pure1 organizations.
    .EXAMPLE
      PS C:\ Get-PureOneVolumeSnapshot

      Returns all snapshots on all FlashArrays
    .EXAMPLE
      PS C:\ Get-PureOneVolumeSnapshot -arrayName flasharray-m50-2

      Returns all snapshots on the specified array
    .EXAMPLE
      PS C:\ Get-PureOneVolumeSnapshot -snapshotName db-001.test

      Returns the snapshots with the specified name
    .EXAMPLE
      PS C:\ Get-PureOneVolumeSnapshot -volumeName sql00-Backup02

      Returns all snapshots for the specified volume 
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='SnapshotName')]
    Param(
            [Parameter(Position=0,ParameterSetName='ArrayName')]
            [string]$ArrayName,
            
            [Parameter(Position=1,ParameterSetName='ArrayID')]
            [string]$ArrayId,

            [Parameter(Position=2,ParameterSetName='SnapshotName')]
            [string]$SnapshotName,

            [Parameter(Position=3,ParameterSetName='SnapshotSerial')]
            [string]$SnapshotSerial,

            [Parameter(Position=4,ParameterSetName='VolumeName')]
            [string]$VolumeName,

            [Parameter(Position=5)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization[]]$PureOneOrganization
    )
    if ($null -ne $global:pureOneRateLimit)
    {
      if ($Global:pureOneRateLimit -in 1..1000)
      {
        $objectQuery = "?limit=$($global:pureOneRateLimit)&"
      }
      else {
        throw "Pure1 Rate limit set to invalid amount. Must be between 1-1000. Currently set to $($global:pureOneRateLimit)"
      }
    }
    else {
      $objectQuery = "?limit=200"
    }
      if ($snapshotName -ne "")
      {
          $objectQuery = $objectQuery + "&names=`'$($snapshotName)`'"
      }
      elseif ($snapshotSerial -ne "")
      {
          $snapshotSerial = $snapshotSerial.ToUpper()
          $objectQuery = $objectQuery +"&filter=serial=`'$($snapshotSerial)`'"
          if ($arrayName -ne "")
          {
              $objectQuery = $objectQuery + ([System.Web.HttpUtility]::Urlencode(" and arrays[any].name")) + "=`'$($arrayName)`'"
          }
          if ($arrayId -ne "")
          {
              $objectQuery = $objectQuery + ([System.Web.HttpUtility]::Urlencode(" and arrays[any].id")) + "=`'$($arrayId)`'"
          }
      }
      if ($snapshotSerial -eq "")
      {
          if ($arrayName -ne "")
          {
              $objectQuery = $objectQuery + "&filter=" + ([System.Web.HttpUtility]::Urlencode("arrays[any].name")) + "=`'$($arrayName)`'"
          }
          if ($arrayId -ne "")
          {
              $objectQuery = $objectQuery + "&filter=" + ([System.Web.HttpUtility]::Urlencode("arrays[any].id")) + "=`'$($arrayId)`'"
          }
      }
      if ($volumeName -ne "")
      {
          $objectQuery = $objectQuery + "&filter=" + ([System.Web.HttpUtility]::Urlencode("source.name")) + "=`'$($volumeName)`'"
      }
      $tokens = @()
      if ([string]::IsNullOrWhiteSpace($pureOneToken))
      {
        $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
      }
      else{
        $tokens += $pureOneToken
      }
      $pureSnaps = @()
      foreach ($token in $tokens) {
        $pureSnaps += New-PureOneOperation -resourceType "volume-snapshots" -queryFilter $objectQuery -pureOneToken $token -restOperationType GET -ErrorAction SilentlyContinue
      }
      if (($pureSnaps | Measure-Object).Count -eq 0)
      {
        throw "No matching snapshots were found on entered Pure1 organization(s)."
      }
      return $pureSnaps
}
function Get-PureOneFileSystem {
    <#
    .SYNOPSIS
      Returns all Pure Storage file systems listed in all connected Pure1 organizations.
    .DESCRIPTION
      Returns all Pure Storage file systems  listed in all connected Pure1 organizations. Allows for some filters.
    .INPUTS
      None required. Optional inputs are array type, array name, file system name, or Pure1 access token.
    .OUTPUTS
      Returns the Pure Storage array information in all connected Pure1 organizations.
    .EXAMPLE
      PS C:\ Get-PureOneFileSystem
      
      Return all FlashBlade file systems (NFS, SMB, S3)
    .EXAMPLE
      PS C:\ Get-PureOneFileSystem
      
      Return all FlashBlade file systems (NFS, SMB, S3)
    .EXAMPLE
      PS C:\ Get-PureOneFileSystem -fsName fs20
      
      Return the specified FlashBlade file system (NFS, SMB, S3)
    .EXAMPLE
      PS C:\ Get-PureOneFileSystem -arrayName sn1-fb-c02-33
      
      Return all FlashBlade file systems on specified array (NFS, SMB, S3)
    .EXAMPLE
      PS C:\ Get-PureOneFileSystem -arrayId 0e30e967-d749-4e03-9d32-701eeff14376
      
      Return all FlashBlade file systems on specified array(NFS, SMB, S3)
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I

    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='FileSystem')]
    Param(
            [Parameter(Position=0,ParameterSetName='ArrayName')]
            [string]$ArrayName,
            
            [Parameter(Position=1,ParameterSetName='ArrayID')]
            [string]$ArrayId,

            [Parameter(Position=2,ParameterSetName='FileSystem')]
            [string]$FsName,

            [Parameter(Position=3)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization[]]$PureOneOrganization
    )
    $objectQuery = "?"
    if ($fsName -ne "")
    {
        $restQuery = $restQuery + "names=`'$($fsName)`'"
        if (($arrayName -ne "") -or ($arrayId -ne ""))
        {
            $objectQuery = $objectQuery + "&"
        }
    }
    if ($arrayName -ne "")
    {
        $objectQuery = $objectQuery + "filter=" + ([System.Web.HttpUtility]::Urlencode("arrays[any].name")) + "=`'$($arrayName)`'"
    }
    if ($arrayId -ne "")
    {
        $objectQuery = $objectQuery + "filter=" + ([System.Web.HttpUtility]::Urlencode("arrays[any].id")) + "=`'$($arrayId)`'"
    }
    $tokens = @()
    if ([string]::IsNullOrWhiteSpace($pureOneToken))
    {
      $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
    }
    else{
      $tokens += $pureOneToken
    }
    $pureFilesystems = @()
    foreach ($token in $tokens) {
      $pureFilesystems += New-PureOneOperation -resourceType "file-systems" -queryFilter $objectQuery -pureOneToken $token -restOperationType GET -ErrorAction SilentlyContinue
    }
    if (($pureFilesystems | Measure-Object).Count -eq 0)
    {
      throw "No matching arrays were found on entered Pure1 organization(s)."
    }
    return $pureFilesystems
}
function Get-PureOneFileSystemSnapshot {
    <#
    .SYNOPSIS
      Returns all Pure Storage file system snapshots listed in all connected Pure1 organizations.
    .DESCRIPTION
      Returns all Pure Storage file system snapshots listed in all connected Pure1 organizations. Allows for some filters.
    .INPUTS
      None required. Optional inputs are array name, file system name, snapshot name, or Pure1 access token.
    .OUTPUTS
      Returns the Pure Storage file system(s) information in all connected Pure1 organizations.
    .EXAMPLE
      PS C:\ Get-PureOneFileSystemSnapshot

      Returns all file system snapshots on all FlashBlades
    .EXAMPLE
      PS C:\ Get-PureOneFileSystemSnapshot -arrayName sn1-fb-c02-33

      Returns all file system snapshots on specified FlashBlade
    .EXAMPLE
      PS C:\ Get-PureOneFileSystemSnapshot -snapshotName nbu-msdp-metadata.2020_04_30_00_00

      Returns the specified file system snapshot
    .EXAMPLE
      PS C:\ Get-PureOneFileSystemSnapshot -fsName nbu-msdp-metadata

      Returns all snapshots for the specified file system 
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>

    [CmdletBinding(DefaultParameterSetName='FileSystemName')]
    Param(
            [Parameter(Position=0,ParameterSetName='ArrayName')]
            [string]$ArrayName,
            
            [Parameter(Position=1,ParameterSetName='ArrayID')]
            [string]$ArrayId,

            [Parameter(Position=2,ParameterSetName='SnapshotName')]
            [string]$SnapshotName,

            [Parameter(Position=3,ParameterSetName='FileSystemName')]
            [string]$FsName,

            [Parameter(Position=4)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization[]]$PureOneOrganization
    )
    $objectQuery = "?"
    if ($snapshotName -ne "")
    {
        $objectQuery = $objectQuery + "names=`'$($snapshotName)`'"
        if (($arrayName -ne "") -or ($arrayId -ne ""))
        {
            $objectQuery = $objectQuery + "&"
        }
    }
    if ($arrayName -ne "")
    {
        $objectQuery = $objectQuery + "filter=" + ([System.Web.HttpUtility]::Urlencode("arrays[any].name")) + "=`'$($arrayName)`'"
    }
    if ($arrayId -ne "")
    {
        $objectQuery = $objectQuery + "filter=" + ([System.Web.HttpUtility]::Urlencode("arrays[any].id")) + "=`'$($arrayId)`'"
    }
    if ($fsName -ne "")
    {
        $objectQuery = $objectQuery + "filter=" + ([System.Web.HttpUtility]::Urlencode("source.name")) + "=`'$($fsName)`'"
    }
    $tokens = @()
    if ([string]::IsNullOrWhiteSpace($pureOneToken))
    {
      $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
    }
    else{
      $tokens += $pureOneToken
    }
    $purefsSnapshots = @()
    foreach ($token in $tokens) {
      $purefsSnapshots += New-PureOneOperation -resourceType "file-system-snapshots" -queryFilter $objectQuery -pureOneToken $token -restOperationType GET -ErrorAction SilentlyContinue
    }
    if (($purefsSnapshots | Measure-Object).Count -eq 0)
    {
      throw "No matching file system snapshots were found on entered Pure1 organization(s)."
    }
    return $purefsSnapshots
}
function Get-PureOneArrayLoadMeter {
    <#
    .SYNOPSIS
      Returns the busy meter for a given array in all connected Pure1 organizations
    .DESCRIPTION
      Returns the busy meter for a given array (or arrays) in all connected Pure1 organizations, either an average or a maximum of a given time period. Default behavior is to return the average.
    .INPUTS
      Required: resource names or IDs--must be an array. Optional: timeframe, granularity, and aggregation type (if none entered defaults will be used based on metric entered). Also optionally an access token.
    .OUTPUTS
      Returns the Pure Storage busy meter metric information in all connected Pure1 organizations.
    .EXAMPLE
      PS C:\ Get-PureOneArrayBusyMeter -objectName flasharray-m50-1

      Returns the busy meter at default resolution for all available time, for the specified array.
    .EXAMPLE
      PS C:\ Get-PureOneArrayBusyMeter -objectName flasharray-m50-1 -startTime (get-date).AddDays(-10)

      Returns the busy meter at default resolution for the past ten days, for the specified array.
    .EXAMPLE
      PS C:\ Get-PureOneArrayBusyMeter -objectName flasharray-m50-1 -startTime (get-date).AddDays(-2) -endTime (get-date).AddDays(-1)

      Returns the busy meter at default resolution for one day ending 24 hours ago, for the specified array.
    .EXAMPLE
      PS C:\ Get-PureOneArrayBusyMeter -objectName flasharray-m50-1 -startTime (get-date).AddDays(-1) -startTime (get-date).AddDays(-1) -granularity 86400000 -maximum

      Returns one value for the previous 24 hours, representing the maximum busyness value for the specified array in that window.
    .NOTES
      Version:        1.1
      Author:         Cody Hosterman https://codyhosterman.com
      Creation Date:  08/29/2020
      Purpose/Change: Core support
  
    *******Disclaimer:******************************************************
    This scripts are offered "as is" with no warranty.  While this 
    scripts is tested and working in my environment, it is recommended that you test 
    this script in a test lab before using in a production environment. Everyone can 
    use the scripts/commands provided here without any written permission but I
    will not be liable for any damage or loss to the system.
    ************************************************************************
    #>
    [CmdletBinding(DefaultParameterSetName='objectName')]
    Param(
            [Parameter(Position=0,mandatory=$True,ParameterSetName='objectName')]
            [Parameter(Position=0,mandatory=$True,ParameterSetName='objectNameAVG')]
            [Parameter(Position=0,mandatory=$True,ParameterSetName='objectNameMAX')]
            [string[]]$ObjectName,
         
            [Parameter(Position=1,mandatory=$True,ParameterSetName='objectID')]
            [Parameter(Position=1,mandatory=$True,ParameterSetName='objectIDAVG')]
            [Parameter(Position=1,mandatory=$True,ParameterSetName='objectIDMAX')]
            [string[]]$ObjectId,

            [Parameter(Position=2,mandatory=$True,ParameterSetName='objectNameAVG')]
            [Parameter(Position=2,mandatory=$True,ParameterSetName='objectIDAVG')]
            [switch]$Average,

            [Parameter(Position=2,mandatory=$True,ParameterSetName='objectNameMAX')]
            [Parameter(Position=2,mandatory=$True,ParameterSetName='objectIDMAX')]
            [switch]$Maximum,

            [Parameter(Position=5)]
            [System.DateTime]$StartTime,

            [Parameter(Position=6)]
            [System.DateTime]$EndTime,

            [Parameter(Position=7)]
            [Int64]$Granularity,

            [Parameter(Position=8)]
            [string]$PureOneToken,

            [Parameter(Position=4)]
            [PureOneOrganization[]]$PureOneOrganization
    )
      $metricName = "array_total_load"
      if (($average -eq $false) -and ($maximum -eq $false)) 
      {
          #defaulting to average if neither option is entered
          $average = $true
      }
      if (($null -ne $startTime) -and ($null -ne $endTime))
      {
        if ($startTime -ge $endTime)
        {
          throw "The specified start time $($startTime) cannot be the same or later than the specified end time $($endTime)"
        }
      }
      #get metric rules
      $metricDetails = Get-PureOneMetricDetail -metricName $metricName
      #set granularity if not set
      if ($granularity -eq 0)
      {
          $granularity = $metricDetails.availabilities.resolution
      }

      #set end time to start time minus retention for that stat (if not entered) and convert to epoch time
      if ($endTime -eq $null)
      {
          $endTime = Get-Date
          $endTime = $endTime.ToUniversalTime()
      }
      else {
          $endTime = $endTime.ToUniversalTime()
      }
      [datetime]$epoch = '1970-01-01 00:00:00'
      $endEpoch = (New-TimeSpan -Start $epoch -End $endTime).TotalMilliSeconds
      $endEpoch = [math]::Round($endEpoch)

      #set start time to current time (if not entered) and convert to epoch time
      if ($startTime -eq $null)
      {
          $startTime = $epoch.AddMilliseconds($metricDetails._as_of - $metricDetails.availabilities.retention)
      }
      else {
          $startTime = $startTime.ToUniversalTime()
      }
      $startEpoch = (New-TimeSpan -Start $epoch -End $startTime).TotalMilliSeconds
      $startEpoch = [math]::Round($startEpoch)

      #building query
      if ($average -eq $true)
      {
          $objectQuery = "?aggregation='avg'&end_time=$($endEpoch)&names=`'$($metricName)`'&resolution=$($granularity)&start_time=$($startEpoch)&"
      }
      else {
          $objectQuery = "?aggregation='max'&end_time=$($endEpoch)&names=`'$($metricName)`'&resolution=$($granularity)&start_time=$($startEpoch)&"
      }
      if ($objectName -ne "")
      {
          if ($objectName.count -gt 1)
          {
              foreach ($arrayName in $objectName)
              {
                  $pureArrays = $pureArrays + "`'$($arrayName)`'"
                  if ($arrayName -ne ($objectName |Select-Object -Last 1))
                  {
                      $pureArrays = $pureArrays + ","
                  }
              }
              $objectQuery = $objectQuery + "resource_names=" + $pureArrays
          }
          else {
              $objectQuery = $objectQuery + "resource_names=`'$($objectName)`'"
          }
      }
      else {
          if ($objectId.count -gt 1)
          {
              foreach ($arrayName in $objectId)
              {
                  $pureArrays = $pureArrays + "`'$($arrayName)`'"
                  if ($arrayName -ne ($objectId |Select-Object -Last 1))
                  {
                      $pureArrays = $pureArrays + ","
                  }
              }
              $objectQuery = $objectQuery + "resource_ids=" + $pureArrays
          }
          else {
              $objectQuery = $objectQuery + "resource_ids=`'$($objectId)`'"
          }
      }
    $tokens = @()
    if ([string]::IsNullOrWhiteSpace($pureOneToken))
    {
      $tokens += Get-PureOneToken -pureOneOrganization $pureOneOrganization
    }
    else{
      $tokens += $pureOneToken
    }
    $loadMeters = @()
    foreach ($token in $tokens) {
      $loadMeters += New-PureOneOperation -resourceType "metrics/history" -queryFilter $objectQuery -pureOneToken $token -restOperationType GET  -ErrorAction SilentlyContinue
    }
    if (($loadMeters | Measure-Object).Count -eq 0)
    {
      throw "No matching arrays were found on entered Pure1 organization(s)."
    }
    return $loadMeters
}

#internal functions
function Resolve-JWTtoken {
  [cmdletbinding()]
  param([Parameter(Mandatory=$true)][string]$token)
  $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
  while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
  $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
  $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
  $tokobj = $tokenArray | ConvertFrom-Json
  return $tokobj
}
function Set-PureOneHeader {
  [CmdletBinding()]
  Param(
          [Parameter(Position=0)]
          [string]$pureOneToken
  )
    if (($null -eq $Global:PureOneConnections) -and ([string]::IsNullOrWhiteSpace($pureOneToken)))
    {
        throw "No access token found in the global variable or passed in. Run the cmdlet New-PureOneRestConnection to authenticate."
    }
    if (![string]::IsNullOrWhiteSpace($pureOneToken)) {
        $pureOneHeader = @{authorization="Bearer $($pureOnetoken)"}
    }
    else {
        $foundDefaultOrg = $Global:PureOneConnections |Where-Object {$_.DefaultOrg -eq $true}
        $pureOneHeader = @{authorization="Bearer $($foundDefaultOrg.pureOneToken)"} 
    }
    return $pureOneHeader
}
function Get-PureOneToken{
  [CmdletBinding()]
  Param(
        [Parameter(Position=0)]
        [PureOneOrganization[]]$pureOneOrganization,

        [Parameter(Position=1)]
        [switch]$defaultOrg
  )
  if ($pureOneOrganization.Count -eq 0)
  {
      if ($defaultOrg -eq $true)
      {
        $foundDefaultOrg = $null
        $foundDefaultOrg = $Global:PureOneConnections |Where-Object {$_.DefaultOrg -eq $true}
        if ($null -eq $foundDefaultOrg)
        {
          throw "No default Pure1 Connection found. Please authenticate with New-PureOneConnection or set a connection with the .SetDefault(`$true) operation"
        }
        else {
          return $Global:foundDefaultOrg.PureOneToken
        }
      }
      else {
        return $Global:PureOneConnections.PureOneToken
      }
  }
  else {
    return $pureOneOrganization.PureOneToken
  }
}
#custom classes
class PureOneOrganization
{
  [int] $PureOneOrgID 
  [string] $Role
  [datetime] $SessionExpiration
  [string] $PureOneAppID
  [string] $PureOneToken
  [bool]$DefaultOrg = $false
  hidden [bool]$updateLock = $false
    # Constructor
    
    SetDefault ([bool]$DefaultOrg)
    {
      if ($DefaultOrg -eq $true)
      {
        $count = 0
        foreach ($connection in $Global:PureOneConnections) 
        {
          if (($connection.DefaultOrg -eq $true) -and ($connection.PureOneOrgID -ne $this.PureOneOrgID))
          {
            throw "Cannot set this connection as default, connection for Pure1 organization $($connection.PureOneOrgID) is already default. Unset it via: `$Global:PureOneConnections[$($count)].SetDefault(`$false)."
          }
          $count++
        }
      }
      $this.DefaultOrg = $DefaultOrg
    }
}
class UnixPureOneOrganization : PureOneOrganization {
  [securestring]$RsaPassword 
  [String]$PrivateKeyFileLocation
  UnixPureOneOrganization ([int] $PureOneOrgID, [string] $pureOneToken, [string] $PureOneAppID, [string] $role,[datetime] $SessionExpiration,[securestring]$RsaPassword, [String]$PrivateKeyFileLocation)
  {
      $this.PureOneOrgID = $PureOneOrgID
      $this.PureOneAppID = $PureOneAppID
      $this.SessionExpiration = $SessionExpiration
      $this.Role = $role
      $this.PureOneToken = $pureOnetoken
      $this.RsaPassword = $RsaPassword
      $this.PrivateKeyFileLocation = $PrivateKeyFileLocation
  }
  RefreshConnection ()
  {
    $this.updateLock = $true
    $org = New-PureOneConnection -pureAppID $this.PureOneAppID -PrivateKeyFileLocation $this.PrivateKeyFileLocation -RsaPassword $this.RsaPassword -returnOrg
    $this.SessionExpiration = $org.SessionExpiration
    $this.PureOneToken = $org.pureOnetoken
    $this.updateLock = $false
    return 
  }
}
class WindowsPureOneOrganization : PureOneOrganization {
  [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate
  # Constructor
  WindowsPureOneOrganization ([int] $PureOneOrgID, [string] $pureOneToken, [string] $PureOneAppID, [string] $role,[datetime] $SessionExpiration, [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate)
  {
      $this.PureOneOrgID = $PureOneOrgID
      $this.PureOneAppID = $PureOneAppID
      $this.SessionExpiration = $SessionExpiration
      $this.Role = $role
      $this.PureOneToken = $pureOnetoken
      $this.Certificate = $certificate
  }
  RefreshConnection ()
  {
    $this.updateLock = $true
    $org = New-PureOneConnection -pureAppID $this.PureOneAppID -certificate $this.Certificate -returnOrg
    $this.SessionExpiration = $org.SessionExpiration
    $this.PureOneToken = $org.pureOnetoken
    $this.updateLock = $false
    return 
  }
}
#Global variables
$global:pureOneRateLimit = $null
$global:pureOneRestVersion = "1.latest"
$Global:PureOneConnections = @()

New-Alias -Name Get-PureOneArrayBusyMeter -Value Get-PureOneArrayLoadMeter
New-Alias -Name New-PureOneRestConnection -Value New-PureOneConnection
New-Alias -Name New-PureOneRestOperation -Value New-PureOneOperation