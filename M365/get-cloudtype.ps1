[CmdletBinding()]
param (
    [string]$TenantGUID, 
    [string]$TenantName 
)

#$Cloud https://www.cloudregions.io/azure/regions
$regions = @{
    NA    = 'North America'
    USG   = 'Fairfax'
    USGOV = 'Arlinton'
    WW    = 'World Wide'
    DE    = 'Black Forest'
    EU    = 'Europe'
}

$SubRegions = @{
    DOD    = 'IL5 - DOD'
    DODCON = 'IL4 - GCCH'
    GCC    = 'GCC'
}

if ($TenantName) {
    $Uri = "https://login.windows.net/$TenantName/.well-known/openid-configuration" 
}
else {
    $Uri = "https://login.microsoftonline.com/$TenantGUID/.well-known/openid-configuration" 
}

try {

    $Cloud = Invoke-RestMethod -uri $Uri -ErrorAction Stop

    [PSCustomObject]@{
        tenant_name                 = $TenantName
        tenantID                    = $cloud.token_endpoint.Split('/')[3]
        tenant_region_scope         = $regions[$Cloud.tenant_region_scope]
        tenant_region_scope_raw     = $Cloud.tenant_region_scope
        tenant_region_sub_scope     = if ($Cloud.tenant_region_sub_scope) { $SubRegions[$Cloud.tenant_region_sub_scope] } else { 'Commercial' }
        tenant_region_sub_scope_raw = $Cloud.tenant_region_sub_scope
        cloud_instance_name         = $Cloud.cloud_instance_name 
    }
}
catch {
    [PSCustomObject]@{
        tenant_name                 = $TenantName
        tenantID                    = $TenantGUID
        tenant_region_scope         = 'Not Found'
        tenant_region_scope_raw     = ''
        tenant_region_sub_scope     = 'Not Found'
        tenant_region_sub_scope_raw = ''
        cloud_instance_name         = 'Not Found'
    }
}


