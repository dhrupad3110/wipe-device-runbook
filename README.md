powershell
CopyEdit
param (
    [string]$userPrincipalName
)

# Define Variables
$tenantId = "<Your_Tenant_ID>"
$clientId = "<Your_Client_ID>"
$clientSecret = "<Your_Client_Secret>"

# Get Access Token
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$body = @{
    client_id     = $clientId
    scope        = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type   = "client_credentials"
}

$response = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body
$accessToken = $response.access_token

# Get User ID
$userUrl = "https://graph.microsoft.com/v1.0/users/$userPrincipalName"
$userResponse = Invoke-RestMethod -Method Get -Uri $userUrl -Headers @{Authorization = "Bearer $accessToken"}
$userId = $userResponse.id

# Get Devices
$devicesUrl = "https://graph.microsoft.com/v1.0/users/$userId/managedDevices"
$devicesResponse = Invoke-RestMethod -Method Get -Uri $devicesUrl -Headers @{Authorization = "Bearer $accessToken"}

if ($devicesResponse.value.Count -eq 0) {
    Write-Host "No devices found for user $userPrincipalName"
    exit
}

# Wipe Each Device
foreach ($device in $devicesResponse.value) {
    $deviceId = $device.id
    $wipeUrl = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/$deviceId/wipe"
    
    $wipeBody = @{
        keepEnrollmentData = $false
        keepUserData = $false
    } | ConvertTo-Json -Depth 2

    Invoke-RestMethod -Method Post -Uri $wipeUrl -Headers @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    } -Body $wipeBody

    Write-Host "Wipe command sent for device: $($device.deviceName)"
}

Write-Host "Wipe process completed for all devices associated with $userPrincipalName"
