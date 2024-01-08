[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $Domain = 'viarapidas.com',
    [Parameter()]
    [string]
    $Server
)

function Test-MSOLMXEntry {
    param (
        $Name,
        $Environment,
        $server
    )
    [CmdletBinding]
    $resolveDnsNameSplat = @{
        Name        = $Name
        ErrorAction = 'SilentlyContinue'
        Type        = 'MX'
    }
    if ($server) { $resolveDnsNameSplat.add("Server", $server) }
    $Result = Resolve-DnsName @resolveDnsNameSplat | Where-Object NameExchange | Sort-Object Preference
    $Results = ($Result | Measure-Object).Count

    switch ($Environment) {
        'DODCON' { $nameExchange = "$($Name.replace('.','-')).mail.protection.office365.us" }
        'DOD' { $nameExchange = "$($Name.replace('.','-')).mail.protection.outlook.com" }
        Default { $nameExchange = "$($Name.replace('.','-')).mail.protection.outlook.com" }
    }
    
    if ($Results -gt 0) {
        if ($result[0].nameExchange -eq $NameExchange) {
            write-host "MX: [$NameExchange] for type: [MX] is correct" -ForegroundColor Green 
        }
        else {
            write-host "MX: [$($Result[0].nameExchange)] for type: [MX] does not equal expected result: [$NameExchange]" -ForegroundColor Red 
        }
    }
    If ($Results -gt 1) {
        Write-Host "WARNING: Extra MX records found" -ForegroundColor Yellow
        foreach ($item in $Result) {
            write-host "    $($item.NameExchange)" -ForegroundColor Yellow
        }
    }
}

function Test-MSOLDKIMEntry {
    param (
        $Selector,
        $Domain,
        $Server
    )
    [CmdletBinding]

    $name = "$Selector._domainkey.$domain"
    $resolveDnsNameSplat = @{
        Name        = $Name
        ErrorAction = 'SilentlyContinue'
        Type        = 'CNAME'
    }
    if ($Server) { $resolveDnsNameSplat.Add('Server', $Server) }
    $Selector = Resolve-DnsName @resolveDnsNameSplat 

    $Selectors = ($Selector | Measure-Object).Count

    If ($Selectors -eq 1) {

        Write-Host "CNAME: [$Name] record exists"
        $Type = 'TXT'
        $Result = Resolve-DnsName -Type $Type -Name $Selector.NameHost -ErrorAction SilentlyContinue

        $Results = ($result | Measure-Object).Count
    
        if ($Results -gt 0) {
            if ($Results -eq 1) {
                $Strings = $result[0].Strings
                if ($Strings[0] -notlike 'v=DKIM1*') {
                    Write-Host "DKIM: [$($Selector.NameHost)] is malformed" -ForegroundColor Red
                    write-host $result[1].Strings
                }
                else {
                    write-host "DKIM: [$($Selector.NameHost)] for type: [$type] is configured" -ForegroundColor Green
                }
            }
            else {
                Write-Host "DKIM: [$($Selector.NameHost)] is malformed" -ForegroundColor Red
            }
        }
        else {
            write-host "DKIM: [$($Selector.NameHost)] does not exist" -ForegroundColor Red
        }
    }
    else {
        Write-Host "DKIM: [$name] CNAME record is missing"
    }
    $Result
}

function Test-MSOLDnsEntry {
    param (
        $Type,
        $Name,
        $Server
    )
    [CmdletBinding]
    $resolveDnsNameSplat = @{
        Name        = $Name
        ErrorAction = 'SilentlyContinue'
        Type        = $Type
    }
    if ($Server) { $resolveDnsNameSplat.add("Server", $Server) }
    $Result = Resolve-DnsName @resolveDnsNameSplat

    $Results = ($result | Measure-Object).Count
    
    if ($Results -gt 0) {
        
        if ($Result[0].Name -ne $Name -or $result[0].Type -ne $Type) {
            write-host "$($Type): [$Name] does not equal result: [$($Result[0].name)] with type [$($Result[0].Type)]" -ForegroundColor Red
        }
        else {
            write-host "$($Type): [$Name] exists" -ForegroundColor Green
        }
        
    }
    else {
        write-host "$($Type): [$Name] does not exist" -ForegroundColor Red
        
    }
    $Result

}

function Test-IntuneRecords {
    param (
        $Domain,
        $Environment,
        $Server
    )
    [CmdletBinding]

    $Type = 'CNAME'
    
    $resolveDnsNameSplat = @{
        Name        = "enterpriseregistration.$domain"
        ErrorAction = 'SilentlyContinue'
        Type        = $Type
    }
    if ($Server) { $resolveDnsNameSplat.add("Server", $Server) }
    $EnterpriseRegistration = Resolve-DnsName @resolveDnsNameSplat -Verbose

    $resolveDnsNameSplat = @{
        Name        = "enterpriseenrollment.$domain"
        ErrorAction = 'SilentlyContinue'
        Type        = $Type
    }
    if ($Server) { $resolveDnsNameSplat.add("Server", $Server) }
    $EnterpriseEnrollment = Resolve-DnsName @resolveDnsNameSplat -Verbose

    $Results = ($EnterpriseRegistration | Measure-Object).Count
    
    $Name = 'enterpriseregistration.windows.net'
    #$Name = $resolveDnsNameSplat.name
    if ($Results -gt 0) {
        if ($EnterpriseRegistration[0].NameHost -ne $Name -or $EnterpriseRegistration[0].Type -ne $Type) {
            write-host "$($Type): [$Name] does not equal result: [$($EnterpriseRegistration[0].NameHost)] with type [$($EnterpriseRegistration[0].Type)]" -ForegroundColor Red
        }
        else {
            write-host "$($Type): [$Name] exists" -ForegroundColor Green
        }
        
    }
    else {
        write-host "$($Type): [$Name] does not exist" -ForegroundColor Red
        
    }

    switch ($Environment) {
        'DODCON' { $Name = 'enterpriseenrollment-s.manage.microsoft.us' }
        'DOD' { $Name = 'enterpriseenrollment-s.manage.microsoft.us' }
        Default { $Name = 'enterpriseenrollment.manage.microsoft.com' }
    }
    if ($Environment) {} else {}
    if ($Results -gt 0) {
        if ($EnterpriseEnrollment[0].NameHost -ne $Name -or $EnterpriseEnrollment[0].Type -ne $Type) {
            write-host "$($Type): [$Name] does not equal result: [$($EnterpriseEnrollment[0].NameHost)] with type [$($EnterpriseEnrollment[0].Type)]" -ForegroundColor Red
        }
        else {
            write-host "$($Type): [$Name] exists" -ForegroundColor Green
        }
        
    }
    else {
        write-host "$($Type): [$Name] does not exist" -ForegroundColor Red
        
    }

    $Result
    #>
}

function Test-MSOLSIPEntries {
    param (
        $Domain,
        $Environment,
        $Server
    )
    [CmdletBinding]

    $Name = "_sipfederationtls._tcp.$domain"
    $Type = 'SRV'
    $Port = 5061
    switch ($Environment) {
        'DODCON' { $Answer = 'sipfed.online.gov.skypeforbusiness.us' }
        'DOD' { $Answer = 'sipfed.online.dod.skypeforbusiness.us' }
        Default { $Answer = 'sipfed.online.lync.com' }
    }
    
    $resolveDnsNameSplat = @{
        Name        = $Name
        ErrorAction = 'SilentlyContinue'
        Type        = $Type
        DnsOnly     = $true
    }
    if ($Server) { $resolveDnsNameSplat.add("Server", $Server) }
    $Result = Resolve-DnsName @resolveDnsNameSplat

    $Results = ($Result | Measure-Object).Count

    if ($Results -eq 0) {
        write-host "$($Type): [$Name] does not exist" -ForegroundColor Red
    }
    else {
        if ($Result.NameTarget -ne $Answer -or $Result.Port -ne $Port) {
            write-host "$($Type): [$($Result.NameTarget)] does not equal result: [$Answer] with port [$($Result.Port)]" -ForegroundColor Red
        }
        else {
            write-host "$($Type): [$Name] exists" -ForegroundColor Green
        }
        
    }

    $Name = "_sip._tls.$domain"
    $Type = 'SRV'
    $Port = 443
    switch ($Environment) {
        'DODCON' { $Answer = 'sipdir.online.gov.skypeforbusiness.us' }
        'DOD' { $Answer = 'sipdir.online.dod.skypeforbusiness.us' }
        Default { $Answer = 'sipdir.online.lync.com' }
    }
    $resolveDnsNameSplat = @{
        Name        = $Name
        ErrorAction = 'SilentlyContinue'
        Type        = $Type
        DnsOnly     = $true
    }
    if ($Server) { $resolveDnsNameSplat.add("Server", $Server) }
    $Result = Resolve-DnsName @resolveDnsNameSplat
  
    #   $Result = Resolve-DnsName -Type $Type -Name $Name -DnsOnly -ErrorAction SilentlyContinue #sipdir.online.lync.com 443
    $Results = ($Result | Measure-Object).Count

    if ($Results -eq 0) {
        write-host "$($Type): [$Name] does not exist" -ForegroundColor Red
    }
    else {
        if ($Result.NameTarget -ne $Answer -or $Result.Port -ne $Port) {
            write-host "$($Type): [$($Result.NameTarget)] does not equal result: [$Answer] with port [$($Result.Port)]" -ForegroundColor Red
        }
        else {
            write-host "$($Type): [$Name] exists" -ForegroundColor Green
        }
        
    }

    $Name = "sip.$domain"
    $Type = 'CNAME'
    switch ($Environment) {
        'DODCON' { $Answer = 'sipdir.online.gov.skypeforbusiness.us' }
        'DOD' { $Answer = 'sipdir.online.dod.skypeforbusiness.us' }
        Default { $Answer = 'sipdir.online.lync.com' }
    }
    $resolveDnsNameSplat = @{
        Name        = $Name
        ErrorAction = 'SilentlyContinue'
        Type        = $Type
        DnsOnly     = $true
    }
    if ($Server) { $resolveDnsNameSplat.add("Server", $Server) }
    $Result = Resolve-DnsName @resolveDnsNameSplat
   
    #    $Result = Resolve-DnsName -Type $Type -Name $Name -DnsOnly -ErrorAction SilentlyContinue #sipdir.online.lync.com
    $Results = ($Result | Measure-Object).Count

    if ($Results -eq 0) {
        write-host "$($Type): [$Name] does not exist" -ForegroundColor Red
    }
    else {
        if ($Result.NameHost -ne $Answer) {
            write-host "$($Type): [$($Result.NameHost)] does not equal result: [$($Result.name)] " -ForegroundColor Red
        }
        else {
            write-host "$($Type): [$Name] exists" -ForegroundColor Green
        }
        
    }
    
    $Name = "lyncdiscover.$domain"
    $Type = 'CNAME'
    switch ($Environment) {
        'DODCON' { $Answer = 'webdir.online.gov.skypeforbusiness.us' }
        'DOD' { $Answer = 'webdir.online.dod.skypeforbusiness.us' }
        Default { $Answer = 'webdir.online.lync.com' }
    }
    $resolveDnsNameSplat = @{
        Name        = $Name
        ErrorAction = 'SilentlyContinue'
        Type        = $Type
        DnsOnly     = $true
    }
    if ($Server) { $resolveDnsNameSplat.add("Server", $Server) }
    $Result = Resolve-DnsName @resolveDnsNameSplat

    #   $Result = Resolve-DnsName -Type $Type -Name $Name -DnsOnly -ErrorAction SilentlyContinue 
    $Results = ($Result | Measure-Object).Count

    if ($Results -eq 0) {
        write-host "$($Type): [$Name] does not exist" -ForegroundColor Red
    }
    else {
        if ($Result.NameHost -ne $Answer) {
            write-host "$($Type): [$($Result.NameHost)] does not equal result: [$($Result.name)] " -ForegroundColor Red
        }
        else {
            write-host "$($Type): [$Name] exists" -ForegroundColor Green
        }
        
    }

    $Result

}
function Test-AutodiscoverEntry {
    param (
        $Domain,
        $environment,
        $Server
    )
    [CmdletBinding]
    $Name = "autodiscover.$domain"
    $Type = 'CNAME'
    
    switch ($environment) {
        'DODCON' { $Answer = 'autodiscover.office365.us' }
        'DOD' { $Answer = 'autodiscover.outlook.com' }
        Default { $Answer = 'autodiscover.outlook.com' }
    }
    $resolveDnsNameSplat = @{
        Name        = $Name
        ErrorAction = 'SilentlyContinue'
        Type        = $Type
        DnsOnly = $true
    }
    if($Server){$resolveDnsNameSplat.add("Server",$Server)}
    $Result = Resolve-DnsName @resolveDnsNameSplat

    #$Result = Resolve-DnsName -Type $Type -Name $Name -DnsOnly -ErrorAction SilentlyContinue #sipfed.online.lync.com 5061

    $Results = ($Result | Measure-Object).Count

    if ($Results -eq 0) {
        write-host "$($Type): [$Name] does not exist" -ForegroundColor Red
    }
    else {
        if ($Result.NameHost -ne $Answer ) {
            write-host "$($Type): [$($Result.NameHost)] does not equal result: [$Answer]" -ForegroundColor Red
        }
        else {
            write-host "$($Type): [$Name] exists" -ForegroundColor Green
        }
        
    }
}

function Test-MSOLDMARCEntry {
    param (
        $domain,
        $Server
    )
    [CmdletBinding]
    $Type = 'TXT'
    $Name = "_dmarc.$domain"
    $resolveDnsNameSplat = @{
        Name        = $Name
        ErrorAction = 'SilentlyContinue'
        Type        = $Type
        DnsOnly = $true
    }
    if($Server){$resolveDnsNameSplat.add("Server",$Server)}
    $dmarc = Resolve-DnsName @resolveDnsNameSplat

    #$dmarc = Resolve-DnsName -Type $Type -Name $Name -ErrorAction SilentlyContinue

    $Results = ($dmarc | Measure-Object).Count

    #Write-Host $Result.Name
    #write-host $Results
    
    if ($Results -eq 1) {
        $records = $dmarc.Strings.split(';').trim()
        if ($records[0] -ne 'v=DMARC1') {
            Write-Host "DMARC: [$Name] is malformed"
        }
        else {
            write-host "DMARC: [$name] is correct" -ForegroundColor Green
        }
    }
    else {
        write-host "DMARC: [$Name] does not exist" -ForegroundColor Red
    }
}

function Test-AIPEntry {
    param (
        $domain,
        $Server
    )
    [CmdletBinding]
    $Type = 'SRV'
    $Name = "_rmsredir._http._tcp.$domain"
    $AIP = Resolve-DnsName -Type $Type -Name $Name -ErrorAction SilentlyContinue

    $Results = ($AIP | Measure-Object).Count

    #Write-Host $Result.Name
    #write-host $Results
    
    if ($Results -eq 1) {
        $records = $AIP.Strings.split(';').trim()
        if ($records[0] -ne 'v=DMARC1') {
            Write-Host "AIP: [$Name] is malformed"
        }
        else {
            write-host "AIP: [$name] is correct" -ForegroundColor Green
        }
    }
    else {
        write-host "AIP: [$Name] does not exist" -ForegroundColor Red
    }
}

function Test-MSOLSPFRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $domain,
        $Server
    )

    $resolveDnsNameSplat = @{
        Name = "$domain"
        Type = 'TXT'
    }
    if ($Server) { $resolveDnsNameSplat.add("Server", $Server) }
    $spf = Resolve-DnsName @resolveDnsNameSplat | Where-Object Strings -like '*v=spf1*'

    $Results = ($spf | Measure-Object).Count

    #Write-Host $Result.Name
    #write-host $Results
    
    if ($Results -ne 0) {
        $records = $spf.Strings.split(' ').trim()
        if ($records[0] -notlike 'v=spf1*' -or $Results -gt 1) {
            Write-Host "SPF: [$Domain] is malformed $($records[0])"
        }
        else {
            write-host "SPF: [$Domain] is correct" -ForegroundColor Green
        }
    }
    else {
        write-host "SPF: [$Domain] does not exist" -ForegroundColor Red
    }
}

$Cloud = .\get-cloudtype.ps1 -TenantName $Domain

Write-Host "This is a $($Cloud.tenant_region_sub_scope) tenant"
$testMSOLDnsEntrySplat = @{
    Name = $Domain
    Type = 'SOA'
}
if ($Server) { $testMSOLDnsEntrySplat.add('Server', $Server) }
$DomainSOA = Test-MSOLDnsEntry @testMSOLDnsEntrySplat -ErrorAction SilentlyContinue
#$DomainTXT = Test-MSOLDnsEntry -Type TXT -name $Domain -ErrorAction SilentlyContinue

#Teams
$testMSOLSIPEntriesSplat = @{
    Environment = $Cloud.tenant_region_sub_scope_raw
    Domain      = $domain
}
if ($Server) { $testMSOLSIPEntriesSplat.add('Server', $Server) }
$Sip = Test-MSOLSIPEntries @testMSOLSIPEntriesSplat -ErrorAction SilentlyContinue 

#Intune https://learn.microsoft.com/en-us/mem/intune/enrollment/windows-enrollment-create-cname
$testIntuneRecordsSplat = @{
    Environment = $Cloud.tenant_region_sub_scope_raw
    Domain      = $domain
}
if ($Server) { $testIntuneRecordsSplat.add('Server', $Server) }
$Intune = Test-IntuneRecords @testIntuneRecordsSplat -ErrorAction SilentlyContinue

#Email
$testAutodiscoverEntrySplat = @{
    environment = $Cloud.tenant_region_sub_scope_raw
    Domain      = $domain
}
if ($Server) { $testAutodiscoverEntrySplat.add('Server', $Server) }
$AutoDiscover = Test-AutodiscoverEntry @testAutodiscoverEntrySplat -ErrorAction SilentlyContinue

$testMSOLMXEntrySplat = @{
    Environment = $Cloud.tenant_region_sub_scope_raw
    Name        = $Domain
}
if ($Server) { $testMSOLMXEntrySplat.add('Server', $Server) }
$DomainMX = Test-MSOLMXEntry @testMSOLMXEntrySplat -ErrorAction SilentlyContinue 

$testMSOLSPFRecordSplat = @{
    domain = $Domain
}
if ($Server) { $testMSOLSPFRecordSplat.add('Server', $Server) }
$domainSPF = Test-MSOLSPFRecord @testMSOLSPFRecordSplat

$testMSOLDMARCEntrySplat = @{
    domain = $domain
}
if ($Server) { $testMSOLDMARCEntrySplat.add('Server', $Server) }
$Dmarc = Test-MSOLDMARCEntry @testMSOLDMARCEntrySplat -ErrorAction SilentlyContinue

$testMSOLDKIMEntrySplat = @{
    Selector = "selector1"
    Domain   = $domain
}
if ($Server) { $testMSOLDKIMEntrySplat.add('Server', $Server) }
$Selector1 = Test-MSOLDKIMEntry @testMSOLDKIMEntrySplat -ErrorAction SilentlyContinue

$testMSOLDKIMEntrySplat = @{
    Selector = "selector2"
    Domain   = $domain
}
if ($Server) { $testMSOLDKIMEntrySplat.add('Server', $Server) }
$Selector2 = Test-MSOLDKIMEntry @testMSOLDKIMEntrySplat -ErrorAction SilentlyContinue

#Microsoft Information Protection
$testMSOLDnsEntrySplat = @{
    Name = "_rmsredir._http._tcp.$domain"
    Type = 'SRV'
}
if ($Server) { $testMSOLDnsEntrySplat.add('Server', $Server) }
$rmredir = Test-MSOLDnsEntry @testMSOLDnsEntrySplat

#Remote Desktop
$testMSOLDnsEntrySplat = @{
    Name = "_msradc.$domain"
    Type = 'TXT'
}
if ($Server) { $testMSOLDnsEntrySplat.add('Server', $Server) }
$wvd = Test-MSOLDnsEntry @testMSOLDnsEntrySplat


#$SipSRV = Test-MSOLDnsEntry -Type SRV -name "_sip._tls.$domain" -ErrorAction SilentlyContinue
#$Sip = Test-MSOLDnsEntry -Type CNAME -name "sip.$domain" -ErrorAction SilentlyContinue
#$Lyncdiscover = Test-MSOLDnsEntry -Type CNAME -name "lyncdiscover.$domain" -ErrorAction SilentlyContinue
#$DomainSOA | Select-Object Name, Type, PrimaryServer, NameExchange,IP4Address
#$DomainMX | Select-Object Name, Type, PrimaryServer, NameExchange,IP4Address
#$Selector1

#If ($DomainMX.NameExchange -ne '') {}
<#
$SipFederationTLS
$SipSRV
$AutoDiscover
$Sip
$Lyncdiscover
$DomainMX
$DomainSOA
$DomainTXT
$EnterpriseRegistration
$EnterpriseEnrollment
$Dmarc
$Selector1
$Selector2


if ($SipFederationTLS.Name -ne "_sipfederationtls._tcp.$domain") { write-host "Name does not equal expected result " }
if ($SipSRV.Name -ne "_sipfederationtls._tcp.$domain") { write-host "Name does not equal expected result " }
if ($AutoDiscover.Name -ne "_sipfederationtls._tcp.$domain") { write-host "Name does not equal expected result " }
if ($Sip.Name -ne "_sipfederationtls._tcp.$domain") { write-host "Name does not equal expected result " }
if ($Lyncdiscover.Name -ne "_sipfederationtls._tcp.$domain") { write-host "Name does not equal expected result " }
if ($DomainMX.Name -ne "_sipfederationtls._tcp.$domain") { write-host "Name does not equal expected result " }
if ($DomainSOA.Name -ne "_sipfederationtls._tcp.$domain") { write-host "Name does not equal expected result " }
if ($DomainTXT.Name -ne "_sipfederationtls._tcp.$domain") { write-host "Name does not equal expected result " }
if ($EnterpriseRegistration.Name -ne "_sipfederationtls._tcp.$domain") { write-host "Name does not equal expected result " }
if ($EnterpriseEnrollment.Name -ne "_sipfederationtls._tcp.$domain") { write-host "Name does not equal expected result " }
if ($Dmarc.Name -ne "_sipfederationtls._tcp.$domain") {
    write-host "Name does not equal expected result "
}
if ($Selector1.Name -ne "_sipfederationtls._tcp.$domain") { write-host "Name does not equal expected result " }
if ($Selector2.Name -ne "_sipfederationtls._tcp.$domain") { write-host "Name does not equal expected result " }
#>