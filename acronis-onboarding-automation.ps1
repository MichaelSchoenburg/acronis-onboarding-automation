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
    https://developer.acronis.com/doc/outbound/apis/index.html

.LINK
    https://github.com/acronis/acronis-cyber-platform-powershell-examples/

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
    Libraries, Modules, 
#>

# Nothing to initialize this time

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
    Log "Issuing API access token"
    $ApiToken = Get-Token -Url $Url -ApiClientId $ApiClientId -ApiClientSecret $ApiClientSecret
    $ApiAccessToken = $ApiToken.access_token

    # Manually construct Bearer
    Log "Constructing bearer"
    $bearerAuthValue = "Bearer $ApiAccessToken"
    $headers = @{ "Authorization" = $bearerAuthValue }

    # The request contains body with JSON
    Log "Constructing headers"
    $headers.Add("Content-Type", "application/json")
    $headers.Add("User-Agent", "Acronis Onboarding Automation PowerShell Script")

    # Get own tenant ID
    Log "Reading own tenant ID"
    $apiClientInfo = Invoke-RestMethod -Uri "$($Url)/clients/$($ApiClientId)" -Headers $headers
    $tenantId = $apiClientInfo.tenant_id

    # Create customer tenant
    $customerTenatName          = 'Test-Tenant'                 # The tenant name.
    $types                      = 'billing', 'management'       # Types of the contact. May be one of the following values: legal, primary, billing, technical, management.
    $country                    = 'DE'                          # Organization’s country.
    $state                      = 'Nordrhein-Westfalen'         # Organization’s state.
    $zipcode                    = '53842'                       # Organization’s zip code.
    $city                       = 'Troisdorf'                   # Organization’s city.
    $address1                   = 'Heidegraben 4a'              # Address line 1.
    $address2                   = ''                            # Address line 2.
    $representativeFirstname    = 'Stephan'                     # The first name of the organization’s representative.
    $representativeLastname     = 'Engels'                      # The last name of the organization’s representative.
    $representativeTitle        = 'Geschäftsführer'             # A job title of the organization’s representative.
    $industry                   = 'IT-Dienstleistung'           # The name of the industry that identifies the primary business activities of the organization.
    $organizationSize           = '1-10'                        # Total number of employees in the organization. May be one of the following values: 1-10, 11-100, 101-500, 501-1000, 5000+. # Somehow doesn't work
    $website                    = 'https://www.itc-engels.de'   # A URL of the organization’s website.
    $eMailAddress               = 'support@itc-engels.de'       # An email address that will be used for account activation and service notifications.
    $phone                      = '+49 2246 92600 - 0'          # Organization’s phone number.

    $json = @{
        name                =  $customerTenatName   # The tenant name.
        kind                = 'customer'            # The tenant type. The value can be partner, folder, customer, or unit. Set to unit for personal tenants.
        parent_id           = $tenantId             # The UUID of a tenant where this tenant is created.
        language            = 'de'                  # The default language of notifications, reports, and the software that is used within the tenant. For the list of supported values, see Supported language codes.
        version             = 1                     # The revision number of the tenant. Each update of the tenant increases this number.
        contact = @{
            types               = $types
            country             = $country
            state               = $state
            zipcode             = $zipcode
            city                = $city
            address1            = $address1
            address2            = $address2
            firstname           = $representativeFirstname
            lastname            = $representativeLastname
            title               = $representativeTitle
            industry            = $industry
            organization_site   = $organizationSize
            website             = $website
            email               = $eMailAddress
            phone               = $phone
        } # The legal contact information of the organization.
        contacts = $null # An array of user contact objects that were created in the tenant. Only returned in GET /tenants endpoint. # Somehow never works...
    }
    $tenant = $json | ConvertTo-Json

    $response = Invoke-RestMethod -Method Post -Uri "$($Url)/tenants" -Headers $headers -Body $tenant
    
    $customerTenantId = $response.id

    <#

    # Tenant auslesen
    $tenantId = 'c290e1c6-ce36-4066-8fc5-8ada52f0a19f'
    $myTenant = Invoke-RestMethod -Uri "$($Url)/tenants/$($tenantId)" -Headers $headers

    # Mehrere Tenants auslesen
    $array = 'c2a0e1c6-ce36-4066-8dc5-9ada52f0a19f', 'a7af0d7f-a59c-454f-8df9-606f2d436726'
    $tenantIds = $array -join ','
    $pagingParams = @{uuids = $tenantIds}
    $searchResult = Invoke-RestMethod -Uri "$($Url)/tenants" -Headers $headers -Body $pagingParams
    $searchResult.items | Out-GridView

    # Einzelnen Tenant modifizieren
    $json = @{
        version = $myTenant.version
        contact = @{
            types = $types
            country = $country
            state = $state
            zipcode = $zipcode
            city = $city
            address1 = $address1
            address2 = $address2
            firstname = $representativeFirstname
            lastname = $representativeLastname
            title = $representativeTitle
            industry = $industry
            organization_site = $organizationSize
            website = $website
            email = $eMailAddress
            phone = $phone
        }
        contacts = $null # Somehow doesn't work
    }
    $tenant = $json | ConvertTo-Json
    $response = Invoke-RestMethod -Method Put -Uri "$($Url)/tenants/c2a0e1c6-ce39-4046-8fd5-8adb52f0b18f" -Headers $headers -Body $tenant

    # Search tenant
    Log "Reading customer tenant ID"
    $pagingParams = @{tenant = $tenantId; text = $customerTenantName}
    $searchResult = Invoke-RestMethod -Uri "$($Url)/search" -Headers $headers -Body $pagingParams

    if ($searchResult.items.Count -eq 0) {
        Log "No acronis tenant of the kind 'customer' with the name '$($customerTenantName)' was found. Aborting script!"
        Exit 1
    }

    $customerTenant = $searchResult.items.Where{($_.obj_type -eq 'tenant') -and ($_.kind -eq 'customer')}
    $customerTenantId = $customerTenant.id

    Log "Found tenant '$($customerTenant.name)' at path '$($customerTenant.path)' with ID '$($customerTenantId)'."

    #>

    # Get services
    $servicesGeneral = (Invoke-RestMethod -Uri "$($Url)/applications" -Headers $headers).items

    # Get active services for tenant
    $servicesForTenant = (Invoke-RestMethod -Uri "$($Url)/tenants/$($customerTenantId)/applications" -Headers $headers).items
    $servicesGeneral.Where({ $_.id -in $servicesForTenant }) | Select-Object Name, Id

    # Define which services to set
    $Service_CyberProtectionId = "6e6d758d-8e74-3ae3-ac84-50eb0dff12eb"
    $ServicesToSet = @(
        $Service_CyberProtection
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

    $response = Invoke-RestMethod -Method Put -Uri "$($Url)/tenants/$($customerTenantId)/offering_items" -Headers $headers -Body $json

    <# 

    # Set billing mode -- Doesn't work...
    $json = @{
        'value' = 'per_device'
    }
    $json = $json | ConvertTo-Json
    Invoke-RestMethod -Method Put -Uri "$($Url)/applications/$($Service_CyberProtectionId)/settings/tenants/$($customerTenantId)/licensing_mode" -Headers $headers -Body $json

    # Alle für den Tenant verfügbaren Settings auslesen
    $response = Invoke-RestMethod -Method Get -Uri "$($Url)/applications/$($Service_CyberProtectionId)/settings/tenants/$($customerTenantId)" -Headers $headers

    #>
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
