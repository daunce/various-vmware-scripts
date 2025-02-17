<#
.SYNOPSIS
    This script connects to multiple ESXi hosts, either enables/disables SSH, displays or updates network and NTP information, and outputs the results in a formatted table.

.DESCRIPTION
    The script reads a list of ESXi hosts from a CSV file, connects to each host using provided credentials, retrieves network and NTP information, and outputs the results in a formatted table. It also includes error handling for connection failures.

.PARAMETER -ssh enable / -ssh disable
    Toggle to either enable/disable SSH on ESXi hosts

.PARAMETER -CsvPath .\vcf-hosts-lab01-mgmt.csv
    The path to the CSV file containing the list of ESXi hosts

.PARAMETER -update
    Toggle to update the ESXi hosts based on the values in the csv

.EXAMPLE
    .\check-vcf-hosts.ps1 -ssh enable

    .\check-vcf-hosts.ps1 -CsvPath .\vcf-hosts-lab01-mgmt.csv -update

    .\check-vcf-hosts.ps1 -ssh disable

.NOTES
    Outputs log file ESXi_Update_Log_<date>_<time>.log
    Ensure you have the required PowerCLI modules installed and imported.
    The CSV file should have the following format with headers:

    IP,Hostname,DomainName,NTPServers,DNServers,SubnetMask
    10.11.11.101, lab01-m01-esx01, vmw.one, ntp.vmw.one, 10.10.10.4, 255.255.255.0
    10.11.11.102, lab01-m01-esx02, vmw.one, ntp.vmw.one, 10.10.10.4, 255.255.255.0
#>



# Main script logic
param (
    [string]$CsvPath = "vcf-hosts-lab01-mgmt",
    [switch]$Update,
    [string]$ssh
)

# Define the path to the log file
$logFile = "ESXi_Update_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Function to log messages to a file (renamed from Log-Message)
function Write-LogMessage {
    param (
        [string]$Message,
        [string]$Type = "INFO"
    )
    $logEntry = "[{0}] {1}: {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Type, $Message
    $logEntry | Out-File -Append -FilePath $logFile
}

# Function to handle errors (renamed from Handle-Error)
function Resolve-Error {
    param (
        [string]$Message,
        [string]$HostIP
    )
    Write-LogMessage -Message "Error on host ${HostIP}: ${Message}" -Type "ERROR"
}

# Function to connect to ESXi host
function Connect-ESXiHost {
    param (
        [string]$HostIP,
        [PSCredential]$Credential
    )
    try {
        $esxiConnection = Connect-VIServer -Server $HostIP -Credential $Credential -ErrorAction Stop
        return $esxiConnection
    } catch {
        Resolve-Error -Message $_.Exception.Message -HostIP $HostIP
        return $null
    }
}

# Function to gather host details
function Get-HostDetails {
    param (
        [string]$HostIP,
        [PSCredential]$Credential
    )
    $esxiConnection = Connect-ESXiHost -HostIP $HostIP -Credential $Credential
    if ($esxiConnection -ne $null) {
        try {
            $esxiHost = Get-VMHost -Server $esxiConnection
            $esxiHostNetwork = Get-VMHostNetwork -VMHost $esxiHost
            $ntpPolicy = Get-VMHostNtpServer -VMHost $esxiHost
            $ntpService = Get-VMHostService -VMHost $esxiHost | Where-Object { $_.Key -eq 'ntpd' }

            # Use your preferred PSCustomObject structure
            $hostDetails = [PSCustomObject]@{
                IP            = $HostIP
                Hostname      = ($esxiHostNetwork).hostname
                DomainName    = ($esxiHostNetwork).DomainName
                DnsServers    = ($esxiHostNetwork).DnsAddress -join ", "
                NtpServers    = $ntpPolicy -join ", "
                NtpRunning    = $ntpService.Running
                MgmtIP        = ($esxiHost | Get-VMHostNetworkAdapter | where-object {$_.Name -eq "vmk0"}).IP
                SubnetMask    = ($esxiHost | Get-VMHostNetworkAdapter | where-object {$_.Name -eq "vmk0"}).SubnetMask
                Gateway       = ($esxiHostNetwork).Gateway
                VLAN          = ($esxiHost | Get-VirtualPortGroup | Where-Object {$_.Name -eq "Management Network"}).VlanId
                SshStatus     = ($esxiHost | Get-VMHostService | Where-Object Key -EQ "TSM-SSH").Running
            }

            Write-LogMessage -Message "Retrieved details for host $HostIP"
            return $hostDetails
        } catch {
            Resolve-Error -Message $_.Exception.Message -HostIP $HostIP
        } finally {
            Disconnect-VIServer -Server $esxiConnection -Confirm:$false
        }
    }
}

# Function to enable / disable ssh

function Set-Ssh {
    param (
        [PSCustomObject]$CsvData,
        [PSCredential]$Credential,
        $SshEnable
    )
    $HostIP = $CsvData.IP
    $esxiConnection = Connect-ESXiHost -HostIP $HostIP -Credential $Credential
    if ($esxiConnection -ne $null) {
        try {
            if ($SshEnable -eq $true) {
                Get-VMHost $HostIP | Get-VMHostService | Where-Object Key -EQ "TSM-SSH" |  Start-VMHostService -Confirm:$False | Out-Null
            } elseif ($SshEnable -eq $false) {
                Get-VMHost $HostIP | Get-VMHostService | Where-Object Key -EQ "TSM-SSH" |  Stop-VMHostService -Confirm:$False | Out-Null
            }
        } catch {
            Resolve-Error -Message $_.Exception.Message -HostIP $HostIP
        } finally {
            Disconnect-VIServer -Server $esxiConnection -Confirm:$false
        }
    }

}

# Function to update host details
function Update-HostDetails {
    param (
        [PSCustomObject]$CsvData,
        [PSCredential]$Credential
    )
    $HostIP = $CsvData.IP
    $esxiConnection = Connect-ESXiHost -HostIP $HostIP -Credential $Credential
    if ($esxiConnection -ne $null) {
        try {
            $esxiHost = Get-VMHost -Server $esxiConnection
            $esxiHostNetwork = Get-VMHostNetwork -VMHost $esxiHost

            # Collect current settings for comparison
            $currentNTP = (Get-VMHostNtpServer -VMHost $esxiHost) -join " "
            $currentDNS = ($esxiHostNetwork).DnsAddress -join " "
            # $currentDNS = ($esxiHost | Get-VMHostNetwork).DnsAddress -join " "
            $updated = $false

            # Update NTP servers
            $currentNTPService = Get-VmHostService | Where-Object {$_.key -eq "ntpd"} 

            if ($currentNTPService.Policy -ne "on") {
                $currentNTPService | Set-VMHostService -policy "on" | Out-Null
            }

            if ($CsvData.NTPServers -ne $currentNTP) {
                if ($currentNTP -ne "") {
                    Remove-VMHostNtpServer -NtpServer (Get-VMHostNtpServer -VMHost $esxiHost) -Confirm:$false
                }
                $currentNTPService | Stop-VMHostService -Confirm:$false | Out-Null
                Add-VMHostNtpServer -VMHost $esxiHost -NtpServer $CsvData.NTPServers.Split(" ")
                $currentNTPService | Start-VMHostService -Confirm:$false | Out-Null
                Write-LogMessage -Message "Updated NTP servers for host ${HostIP}. From: ${currentNTP} To: $($CsvData.NTPServers)" -Type "UPDATE"
                $updated = $true
            }

            if ($currentNTPService.Running -eq $false){
                $currentNTPService | Start-VMHostService -Confirm:$false | Out-Null
            }


            # Update DNS servers
            if ($CsvData.DNServers -ne $currentDNS) {
                $esxiHostNetwork | Set-VMHostNetwork -DnsAddress $CsvData.DNServers.Split(" ")
                # $esxiHost | Get-VMHostNetwork | Set-VMHostNetwork -DnsAddress $CsvData.DNServers.Split(" ")
                Write-LogMessage -Message "Updated DNS servers for host ${HostIP}. From: ${currentDNS} To: $($CsvData.DNServers)" -Type "UPDATE"
                $updated = $true
            }

            # Update hostname
            $currentHostName = ($esxiHostNetwork).HostName
            if ($CsvData.Hostname -ne $currentHostName){
                $esxiHostNetwork | Set-VMHostNetwork -HostName $CsvData.Hostname | Out-Null
                Write-LogMessage -Message "Updated Hostname for host ${HostIP}. From: ${currentHostName} To: $($CsvData.Hostname)" -Type "UPDATE"
                $updated = $true
            }

            # Update domain name
            $currentDomainName = ($esxiHostNetwork).DomainName
            if ($CsvData.DomainName -ne $currentDomainName){
                $esxiHostNetwork | Set-VMHostNetwork -DomainName $CsvData.DomainName | Out-Null
                Write-LogMessage -Message "Updated Domain name for host ${HostIP}. From: ${currentDomainName} To: $($CsvData.DomainName)" -Type "UPDATE"
                $updated = $true
            }


            if (-not $updated) {
                Write-LogMessage -Message "No updates made for host ${HostIP}"
            }

        } catch {
            Resolve-Error -Message $_.Exception.Message -HostIP $HostIP
        } finally {
            Disconnect-VIServer -Server $esxiConnection -Confirm:$false
        }
    }
}

# Get secure credentials from the user
$credential = Get-Credential

# Debug
$stopwatch = [system.diagnostics.stopwatch]::StartNew()



# Import CSV and process each host
$hostsData = Import-Csv -Path $CsvPath

# Create a collection to hold all results
$results = @()

foreach ($esxiHost in $hostsData) {
    $HostIP = $esxiHost.IP

    if ($ssh -eq "enable") {
        Set-Ssh -CsvData $esxiHost -Credential $credential -SshEnable $true
    } elseif ($Ssh -eq "disable") {
        Set-Ssh -CsvData $esxiHost -Credential $credential -SshEnable $false
    } else {
        if ($Update.IsPresent) {
            Update-HostDetails -CsvData $esxiHost -Credential $credential
        } 
        $hostDetails = Get-HostDetails -HostIP $HostIP -Credential $credential
        if ($hostDetails) {
            $results += $hostDetails
        }
    }
}

# Format and display the results
$results | Format-Table -Property IP, Hostname, DomainName, DnsServers, NtpServers, NtpRunning, MgmtIP, SubnetMask, Gateway, VLAN, SshStatus -AutoSize

# Write the results to the log file
$results | Export-Csv -Path $logFile -NoTypeInformation

Write-LogMessage -Message "Script completed."
Write-Host "Paramaters: `nUpdate: $($Update.IsPresent)`nSSH enable: $ssh"

# Testing only
# $stopwatch.Elapsed
