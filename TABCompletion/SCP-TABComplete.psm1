<#
What is this?
This is a PowerShell module providing TAB completion for the native scp command

How to use this file alone?
- Put the path to scp and ssh executable to your path variable (SSH and SCP NEED TO BE EXECUTABLE FROM ANY LOCATION)
- Run $env:PSModulePath in PowerShell
- Place this file in one of the module locations in a sub folder named SCP-TABComplete
- Run import-module SCP-TABComplete (to get this permanently, add the line to your $profile)
- Now you should have tab completion for scp parameters (enter scp <TAB> or scp <Ctrl+Space>)

How to use this file in the bundle?
- Put the path to scp and ssh executable to your path variable (SSH and SCP NEED TO BE EXECUTABLE FROM ANY LOCATION)
- Run $env:PSModulePath in PowerShell
- Place this file and the file TABCompletion.psm1 in one of the module locations in a sub folder named TABCompletion
- Run import-module TABCompletion (to get this permanently, add the line to your $profile)
- Now you should have tab completion for scp parameters (enter scp <TAB> or scp <Ctrl+Space>)

Where do I get the latest version?
https://github.com/dodmi/PowerShell-Addons/TABCompletion/tree/master/

When was this file updated?
2024-11-08
#>

<#
    .DESCRIPTION
    Returns all hosts defined in the config file,
    ignoring hostnames that describe multiple hosts or
    exclude hosts
    .PARAMETER configFile
    The config file to look in
#>
function Get-SSHConfigHosts {
    param (
        [String][Parameter(Mandatory=$true)] $configFile
    )
    $configHosts = @()
    if (Test-Path -PathType Leaf $configFile) {
        $fileContent = Get-Content $configFile
        foreach ($line in $fileContent) {
            if ($line -match '^Host\s+(.*)$') {
                $hosts = ($matches[1] | Select-String -allMatches '([^\s]+)').matches
                for ($i=0; $i -lt $hosts.length; $i++) {
                    if ($hosts[$i].Value -notmatch '[\*|\?|/|!]') { $configHosts += $hosts[$i].Value }
                }
            }
        }
    }
    return $configHosts
}

<#
    .DESCRIPTION
    Returns all hosts contained in the known_hosts file
    .PARAMETER hostFile
    The known_hosts file to look in
#>
function Get-SSHKnownHosts {
    param (
        [String][Parameter(Mandatory=$true)] $hostFile
    )
    $knownHosts = @()
    if (Test-Path -PathType Leaf $hostFile) {
        $fileContent = Get-Content ($env:userprofile + "\.ssh\known_hosts")
        foreach ($line in $fileContent) {
            if ($line -match '^([^\s,]*).*') { $knownHosts += $matches[1] }
        }
    }
    return $knownHosts
}

<#
    .DESCRIPTION
    Returns a sorted, unique list of all known SSH hosts
#>
function Get-SSHHosts {
    $AllHosts = @()

    $AllHosts += Get-SSHKnownHosts -hostFile (Join-Path $env:userProfile "\.ssh\known_hosts")
    $AllHosts += Get-SSHKnownHosts -hostFile (Join-Path $env:userProfile "\.ssh\known_hosts2")
    $AllHosts += Get-SSHKnownHosts -hostFile (Join-Path $env:allUsersProfile "\ssh\ssh_known_hosts")
    $AllHosts += Get-SSHKnownHosts -hostFile (Join-Path $env:allUsersProfile "\ssh\ssh_known_hosts2")

    $AllHosts += Get-SSHConfigHosts -configFile (Join-Path $env:userProfile "\.ssh\config")
    $AllHosts += Get-SSHConfigHosts -configFile (Join-Path $env:allUsersProfile "\ssh\ssh_config")

    return ($AllHosts  | Sort-Object -CaseSensitive -Unique)
}

<#
    .DESCRIPTION
    Creates a result element from a string or a hash set containing an additional description
    .PARAMETER Param
    The parameter to create the completion reult for (e.g. -p)
    .PARAMETER ShortDesc
    A short description to display in lists (e.g. -p (Print))
    .PARAMETER LongDesc
    A long description to display as hint (e.g. Print the file)
#>
function Create-CompletionResult {
    param(
        [ValidateNotNullOrEmpty()][String] $Param,
        [ValidateNotNullOrEmpty()][String] $ShortDesc,
        [ValidateNotNullOrEmpty()][String] $LongDesc
    )

    $res = [System.Management.Automation.CompletionResult]::new($Param, $ShortDesc, 'ParameterValue', $LongDesc)

    return $res
}

<#
    .DESCRIPTION
    Returns a list of file and folder names to complete
    .PARAMETER wordToComplete
    The text to filter the results for
#>
function Complete-Files {
    param ([String] $wordToComplete)
    $currentPath = Get-Location | Select -ExpandProperty Path
    $result = @()
    $proposals = Get-ChildItem -Force "$wordToComplete*" | Select -ExpandProperty Fullname | % {$_.Replace($currentPath,".")}
    foreach ($p in $proposals) {
        if ((Test-Path $p -PathType Container) -and -not (Test-Path $p -PathType Leaf)) { $p += "\" }
        if ($p.Contains(" ") -and -not ($p.StartsWith('"') -or $p.StartsWith("'"))) { $p = "'$p'" }
        if ($p.Contains("$") -and -not ($p.StartsWith('"') -or $p.StartsWith("'"))) { $p = "'$p'" }
        $result += $p
    }

	if (($result.count -eq 0) -and ($wordToComplete -like "")) { $result += ".\" }
    return $result
}

<#
    .DESCRIPTION
    Gets the element to the left of the cursor
    .PARAMETER cmdAst
    The command structure as provided in Register-ArgumentCompleter
    .PARAMETER curPos
    The cursor position as provided in Register-ArgumentCompleter
#>
function Get-LeftCommandLineElement {
    param(
        [System.Management.Automation.Language.CommandAst] $cmdAst,
        [int] $curPos
    )

    for ($i = $cmdAst.CommandElements.Count - 1; $i -ge 0; $i--) {
        $aktCmdPart = $cmdAst.CommandElements[$i].Extent
        $result = ""
        if (($i -gt 0) -and ($aktCmdPart.StartOffset -le $curPos) -and
            (($aktCmdPart.EndOffset -ge $curPos) -or
             ($cmdAst.CommandElements[-1].Extent.EndOffset -lt $curPos))) {
            if ($cmdAst.CommandElements[-1].Extent.EndOffset -lt $curPos) {
                $result = $cmdAst.CommandElements[-1].Extent.Text
            } else {
                $result = $cmdAst.CommandElements[$i-1].Extent.Text
            }
            break
        }
    }
    return $result
}

<#
    .DESCRIPTION
    Finally implements the completion logic and registers the SCP command completor
#>
function Add-SCPTabCompletion {
    # Command to complete
	$script:cmd = @("scp","scp.exe")

    # Logic to compare input and present results
    $script:completionScriptBlock = {
        param($wordToComplete, $commandAst, $cursorPosition)

        # Parameter list
        $simpleParams = @(
            @{"Param"="-3"; "ShortDesc"="-3 (copy through localhost)"; "LongDesc"="Copies files between two remote hosts through localhost"},
            @{"Param"="-4"; "ShortDesc"="-4 (IPv4 mode)"; "LongDesc"="Force IPv4 connection"},
            @{"Param"="-6"; "ShortDesc"="-6 (IPv6 mode)"; "LongDesc"="Force IPv6 connection"},
            @{"Param"="-A"; "ShortDesc"="-A (agent)"; "LongDesc"="Forward using connection agent"},
            @{"Param"="-B"; "ShortDesc"="-B (batch mode)"; "LongDesc"="Use batch mode, don't ask for passwords"},
            @{"Param"="-C"; "ShortDesc"="-C (compression)"; "LongDesc"="Enable data compression"},
            @{"Param"="-c"; "ShortDesc"="-c (<ciphers>)"; "LongDesc"="Specify comma separated list of allowed ciphers"},
            @{"Param"="-D"; "ShortDesc"="-D (local SFTP)"; "LongDesc"="Connect directly to a local SFTP server"},
            @{"Param"="-F"; "ShortDesc"="-F (config <file>)"; "LongDesc"="Specify config file to use"},
            @{"Param"="-i"; "ShortDesc"="-i (id <file>)"; "LongDesc"="Specify id file to use"},
            @{"Param"="-J"; "ShortDesc"="-J (jump <addr>)"; "LongDesc"="Specify jump host, used to connect to target"},
            @{"Param"="-l"; "ShortDesc"="-l (<limit>)"; "LongDesc"="Limit bandwith in Kbit/s"},
            @{"Param"="-O"; "ShortDesc"="-O (legacy mode)"; "LongDesc"="Use the legacy scp protocol"},
            @{"Param"="-o"; "ShortDesc"="-o (SSH <option>)"; "LongDesc"="Specify an option to use like in the config file, may be used multiple times"},
            @{"Param"="-P"; "ShortDesc"="-P (<port>)"; "LongDesc"="Specify port to connect to"},
            @{"Param"="-p"; "ShortDesc"="-p (preserve)"; "LongDesc"="Preserve file timestamps and mode bits"},
            @{"Param"="-q"; "ShortDesc"="-q (quiet)"; "LongDesc"="Quiet mode"},
            @{"Param"="-R"; "ShortDesc"="-R (from remote)"; "LongDesc"="Using scp on the remote origin to copy to the remote target"},
            @{"Param"="-S"; "ShortDesc"="-S (ssh <file>)"; "LongDesc"="Specify an alternate SSH (compatible) executable"},
            @{"Param"="-T"; "ShortDesc"="-T (no name checks)"; "LongDesc"="Disable filename checking"},
            @{"Param"="-v"; "ShortDesc"="-v (verbose)"; "LongDesc"="Print debug messages"},
            @{"Param"="-X"; "ShortDesc"="-X (SFTP <option>)"; "LongDesc"="Specify an option to pass to SFTP, may be used multiple times"}
        )

        # Prepare known target hosts
        $hosts = @()
        foreach ($h in (Get-SSHHosts)) {
            $hosts += @{"Param"=$h; "ShortDesc"=$h; "LongDesc"="Connect to target system $h"}
        }

        $sshOptions = "AddressFamily=", "BatchMode=", "BindAddress=", "BindInterface=", "CanonicalDomains=", "CanonicalizeFallbackLocal=", "CanonicalizeHostname=", "CanonicalizeMaxDots=", "CanonicalizePermittedCNAMEs=", "CASignatureAlgorithms=", "CertificateFile=", "CheckHostIP=", "Ciphers=", "Compression=", "ConnectionAttempts=", "ConnectTimeout=", "ControlMaster=", "ControlPath=", "ControlPersist=", "GlobalKnownHostsFile=", "GSSAPIAuthentication=", "GSSAPIDelegateCredentials=", "HashKnownHosts=", "Host=", "HostbasedAcceptedAlgorithms=", "HostbasedAuthentication=", "HostKeyAlgorithms=", "HostKeyAlias=", "Hostname=", "IdentitiesOnly=", "IdentityAgent=", "IdentityFile=", "IPQoS=", "KbdInteractiveAuthentication=", "KbdInteractiveDevices=", "KexAlgorithms=", "KnownHostsCommand=", "LogLevel=", "MACs=", "NoHostAuthenticationForLocalhost=", "NumberOfPasswordPrompts=", "PasswordAuthentication=", "PKCS11Provider=", "Port=", "PreferredAuthentications=", "ProxyCommand=", "ProxyJump=", "PubkeyAcceptedAlgorithms=", "PubkeyAuthentication=", "RekeyLimit=", "RequiredRSASize=", "SendEnv=", "ServerAliveInterval=", "ServerAliveCountMax=", "SetEnv=", "StrictHostKeyChecking=", "TCPKeepAlive=", "UpdateHostKeys=", "User=", "UserKnownHostsFile=", "VerifyHostKeyDNS="
        $sftpOptions = "nrequests=", "buffer="

        switch -RegEx -CaseSensitive (Get-LeftCommandLineElement -cmdAst $commandAst -curPos $cursorPosition) {
            "-F|-i|-S" {
                $allResults = Complete-Files $wordToComplete
                break
            }
            "-J" {
                $allResults = @()
                $allResults += $hosts | ? { $_.Param -like "$wordToComplete*" } | % { Create-CompletionResult @_ }
                break
            }
            "-o" {
                $allResults = $sshOptions | ? { $_ -like "$wordToComplete*" }
                break
            }
            "-c" {
                $allResults = ssh -Q cipher | ? { $_ -like "$wordToComplete*" }
                break
            }
            "-X" {
                $allResults = $sftpOptions | ? { $_ -like "$wordToComplete*" }
                break
            }
            default {
                $allResults = @()
                $allResults += $hosts | ? { $_.Param -like "$wordToComplete*" } | % { Create-CompletionResult @_ }
                $allResults += $simpleParams | ? { $_.Param -like "$wordToComplete*" } | % { Create-CompletionResult @_ }
                break
            }
        }

        return $allResults
    }

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        # Register completion for native commands
        # (this is broken in PowerShell 5.1 and below for parameters starting with - or --)
        $script:cmd | % { Register-ArgumentCompleter -Native -CommandName $_ -ScriptBlock $script:completionScriptBlock }
    } else {
        # Overwrite TabExpansion function for PowerShell 5.1 and below
        # (this works fine, but command completion is only supported at the end of the line)
        if (Test-Path "Function:\TabExpansion") {
            $script:FuncBackupName = "TabExpansion." + (get-date).Ticks
            Rename-Item "Function:\TabExpansion" "global:$($script:FuncBackupName)"
        }

        function global:TabExpansion {
            param(
                [String] $line,
                [String] $lastWord
            )

            $commandLine = [regex]::Split($line, '[|;]')[-1].TrimStart()
            $ast=[System.Management.Automation.Language.Parser]::ParseInput($commandLine, [ref]$null, [ref]$null)
            $commandAst=$ast.Find({$args[0] -is [System.Management.Automation.Language.CommandAst]}, $false)

            if ($commandAst.GetCommandName() -in $script:cmd) {
                Invoke-Command -ScriptBlock $script:completionScriptBlock -ArgumentList @($lastWord,$commandAst,$commandLine.length)
            } else {
                if ($script:FuncBackupName) { & $script:FuncBackupName -line $line -lastWord $lastWord }
            }
        }
    }
}

if ((Get-Command scp -CommandType Application -EA SilentlyContinue) -and (Get-Command ssh -CommandType Application -EA SilentlyContinue)) {
	Add-SCPTabCompletion
} else {
	Write-Error "SCP or SSH was not found in your environment! Put it too path..."
}

# Expose no functions
Export-ModuleMember -Function ""
