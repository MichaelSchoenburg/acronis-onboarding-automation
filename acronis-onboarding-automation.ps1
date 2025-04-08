<#
.SYNOPSIS
    Acronis Onboarding

.DESCRIPTION
    This PowerShell script is intended to be used in a RMM solution (e. g. Solarwinds N-able RMM or Riversuit Riverbird).

.INPUTS
    No parameters. Variables are supposed to be set by the rmm solution this script is used in.

.OUTPUTS
    None

.LINK
    https://github.com/MichaelSchoenburg/AcronisOnboarding

.LINK
    https://developer.acronis.com/doc/account-management/v2/reference/index.html#docs/summary/summary

.LINK
    https://www.acronis.com/en-us/blog/posts/how-to-personalize-unattended-acronis-agent-installation-on-windows/

.NOTES
    Author: Michael Schönburg
    Version: v1.0
    
    This projects code loosely follows the PowerShell Practice and Style guide, as well as Microsofts PowerShell scripting performance considerations.
    Style guide: https://poshcode.gitbook.io/powershell-practice-and-style/
    Performance Considerations: https://docs.microsoft.com/en-us/powershell/scripting/dev-cross-plat/performance/script-authoring-considerations?view=powershell-7.1
#>

#region FUNCTIONS
<# 
    Declare Functions
#>

function Write-ConsoleLog {
    <#
        .SYNOPSIS
        Logs an event to the console.
        
        .DESCRIPTION
        Writes text to the console with the current date (US format) in front of it.
        
        .PARAMETER Text
        Event/text to be outputted to the console.
        
        .EXAMPLE
        Write-ConsoleLog -Text 'Subscript XYZ called.'
        
        Long form

        .EXAMPLE
        Log 'Subscript XYZ called.
        
        Short form
    #>

    [alias('Log')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
        Position = 0)]
        [string]
        $Text
    )

    # Save current VerbosePreference
    $VerbosePreferenceBefore = $VerbosePreference

    # Enable verbose output
    $VerbosePreference = 'Continue'

    # Write verbose output
    Write-Output "$( Get-Date -Format 'MM/dd/yyyy HH:mm:ss' ) - $( $Script:Section ): $( $Text )"

    # Restore current VerbosePreference
    $VerbosePreference = $VerbosePreferenceBefore
}

function Get-Token {
    <#
        .SYNOPSIS
        Returns an API token.
        
        .DESCRIPTION
        Authorize this API client (PowerShell) against the Acronis Account Management API receiving a token. The token is then used to authenticate further API calls.
        
        .PARAMETER Url
        URL for your Acronis portal.
        
        .PARAMETER ApiClientId
        Client ID for the Acronis Account Management API. This can be generated the Acronis management portal.

        .PARAMETER ApiClientSecret
        Client secret for the Acronis Account Management API. This too can be generated in the Acronis management portal.

        .EXAMPLE
        Get-Token -Url 'https://portal.ajani.info' -ApiClientId '02baa9be-f1a2-4524-a8cb-0cd75c9acb61' -ApiClientSecret 'mzrop4shdxil3ud4lvvdcn5l4acqtafufi4juudqabfhxga756pm'

        .OUTPUTS
        Outputs an array (System.Object) with two variables. First the access token. Secondly the scope.

        .NOTES
        If you want to use this script for all your clients, you can generate an API client from you partner account which has access to all you clients tenants. 
        Check the related link for a guid from the manufacturer on how the Acronis Account Management API works and where you can create your API Client ID and secret.

        .LINK
        https://www.acronis.com/en-us/blog/posts/how-to-automate-acronis-agent-installations/
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Url,

        [Parameter(Mandatory)]
        [string]
        [ValidatePattern('^[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+$')]
        $ApiClientId,

        [Parameter(Mandatory)]
        [string]
        [ValidateLength(52,52)]
        $ApiClientSecret
    )

    # Manually construct Basic Authentication Header
    $pair = "${ApiClientId}:${ApiClientSecret}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"
    $headers = @{ "Authorization" = $basicAuthValue }

    # Use param to tell type of credentials we request
    $postParams = @{ grant_type = "client_credentials" }

    # Add the request content type to the headers
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $headers.Add("User-Agent", "ACP 3.0/Acronis Cyber Platform PowerShell Examples")
    $token = Invoke-RestMethod -Method Post -Uri "${Url}/idp/token" -Headers $headers -Body $postParams

    # Return access token
    return $token
}

#endregion FUNCTIONS
#region INITIALIZATION
<# 
    Libraries, Modules, ...
#>

# Nothing to initialize this time...

#endregion INITIALIZATION
#region DECLARATIONS
<#
    Declare local variables and global variables
#>

# The following variables should be set through your rmm solution. 
# Here some examples of possible declarations with explanations for each variable.
# Tip: PowerShell variables are not case sensitive.

<# 

$CustomerTenantName = "Test-Tenant"
$BaseUrl = 'https://portal.centerbackup.one/'
$Url = 'https://portal.centerbackup.one/api/2' # The full URL for your Acronis tenant (plugging Ajani right here)
$ApiClientId = '02baa9be-f1a2-4624-a95b-0cx75c9acb61' # API client ID
$ApiClientSecret = 'mzrop4shdxil3ud4lvvwdn5l6acqtauufi4juudqabfhxga756pm' # API client secret

#>

#endregion DECLARATIONS
#region EXECUTION
<# 
    Script entry point
#>

try {
    $Successful = $false

    <# 
        Get installation token from API
    #>

    $Script:Section = 'API'

    # Issue token to access API
    Log "Issuing API access token..."
    $ApiToken = Get-Token -Url $Url -ApiClientId $ApiClientId -ApiClientSecret $ApiClientSecret
    $ApiAccessToken = $ApiToken.access_token

    # Manually construct Bearer
    Log "Constructing bearer..."
    $bearerAuthValue = "Bearer $ApiAccessToken"
    $headers = @{ "Authorization" = $bearerAuthValue }

    # The request contains body with JSON
    Log "Constructing headers..."
    $headers.Add("Content-Type", "application/json")
    $headers.Add("User-Agent", "ACP 3.0/Acronis Cyber Platform PowerShell Examples")

    # Get own tenant ID
    Log "Reading own tenant ID..."
    $apiClientInfo = Invoke-RestMethod -Uri "$($Url)/clients/$($ApiClientId)" -Headers $headers
    $tenantId = $apiClientInfo.tenant_id

    # Get customer tenant ID
    Log "Reading customer tenant ID..."
    $pagingParams = @{tenant = $tenantId; text = $customerTenantName}
    $searchResult = Invoke-RestMethod -Uri "$($Url)/search" -Headers $headers -Body $pagingParams

    if ($searchResult.items.Count -eq 0) {
        Log "No acronis tenant of the kind 'customer' with the name '$($customerTenantName)' was found. Aborting script!"
        Exit 1
    }

    $customerTenant = $searchResult.items.Where{($_.obj_type -eq 'tenant') -and ($_.kind -eq 'customer')}
    $customerTenantId = $customerTenant.id

    Log "Found tenant '$($customerTenant.name)' at path '$($customerTenant.path)' with ID '$($customerTenantId)'."

    # Get services
    $servicesGeneral = (Invoke-RestMethod -Uri "$($Url)/applications" -Headers $headers).items

    # Get active services for tenant
    $servicesForTenant = (Invoke-RestMethod -Uri "$($Url)/tenants/$($customerTenantId)/applications" -Headers $headers).items
    $servicesGeneral.Where({ $_.id -in $servicesForTenant }) | Select-Object Name, Id

    # Define which services to set
    $ServicesToSet = @(
        "6e6d758d-8e74-3ae3-ac84-50eb0dff12eb" # Cyber Protection
    )

    # Set services
    foreach ($s in $ServicesToSet) {
        Invoke-RestMethod -Method Post -Uri "$($Url)/applications/$($s)/bindings/tenants/$($customerTenantId)" -Headers $headers
    }
    
    <# 
        Managing offering items and quotas 
    #>

    # Get offering items
    $offeringItems = (Invoke-RestMethod -Method Get -Uri "$($Url)/tenants/$($customerTenantId)/offering_items" -Headers $headers).items
    
    # Activate offering item "local_storage"
    for ($i = 0; $i -lt $offeringItems.Count; $i++) {
        Log "$($offeringItems[$i].name) - $($offeringItems[$i].status)"
        if ($offeringItems[$i].name -eq "local_storage") {
            $offeringItems[$i].status = "1"
        }
    }

    $json = @{
        'offering_items' = $offeringItems
    }
    $json = $json | ConvertTo-Json

    $result = Invoke-RestMethod -Method Put -Uri "$($Url)/tenants/$($customerTenantId)/offering_items" -Headers $headers -Body $json
} catch {
    Log "Exception Message: $($PSItem.Exception.Message)"
    Log "Inner Exception Message: $($PSItem.Exception.InnerException)"
    $PSItem.InvocationInfo | Format-List *
} finally {
    if ($Successful) {
        Log "`$Successful is set to true. Exiting with exit code 0."
        Exit 0
    } else {
        Log "`$Successful isn't set to true. Exiting with exit code 1."
        Exit 1
    }
}

#endregion EXECUTION
