<#
What is this?
This is a PowerShell module providing TAB completion for the native ssh command

How to use this file alone?
- Put the path to ssh executable to your path variable (SSH NEEDS TO BE EXECUTABLE FROM ANY LOCATION)
- Run $env:PSModulePath in PowerShell
- Place this file in one of the module locations in a sub folder named SSH-TABComplete
- Run import-module SSH-TABComplete (to get this permanently, add the line to your $profile)
- Now you should have tab completion for ssh parameters (enter ssh <TAB> or ssh <Ctrl+Space>)

How to use this file in the bundle?
- Put the path to ssh executable to your path variable (SSH NEEDS TO BE EXECUTABLE FROM ANY LOCATION)
- Run $env:PSModulePath in PowerShell
- Place this file and the file TABCompletion.psm1 in one of the module locations in a sub folder named TABCompletion
- Run import-module TABCompletion (to get this permanently, add the line to your $profile)
- Now you should have tab completion for ssh parameters (enter ssh <TAB> or ssh <Ctrl+Space>)

Where do I get the latest version?
https://github.com/dodmi/PowerShell-Addons/TABCompletion/tree/master/

When was this file updated?
2021-05-22
#>

<#
    .DESCRIPTION
    Returns all hosts defined in the config file,
    ignoring hostnames that describe multiple hosts or
    exclude hosts
#>
function Get-SSHConfigHosts {
    $fileContent = Get-Content ($env:userprofile + "\.ssh\config")
    $configHosts = @()
    foreach ($line in $fileContent) {
        if ($line -match '^Host\s+(.*)$') {
			$hosts = ($matches[1] | Select-String -allMatches '([^\s]+)').matches
			for ($i=0; $i -lt $hosts.length; $i++) {
				if ($hosts[$i].Value -notmatch '[\*|\?|/|!]') { $configHosts += $hosts[$i].Value }
            }
        }
    }
    return $configHosts
}

<#
    .DESCRIPTION
    Returns all hosts contained in the known_hosts file
#>
function Get-SSHKnownHosts {
    $fileContent = Get-Content ($env:userprofile + "\.ssh\known_hosts")
    $knownHosts = @()
    foreach ($line in $fileContent) {
        if ($line -match '^([^\s,]*).*') { $knownHosts += $matches[1] }
    }
    return $knownHosts
}

<#
    .DESCRIPTION
    Returns a sorted, unique list of all known SSH hosts
#>
function Get-SSHHosts {
    $AllHosts = @()
    $AllHosts += Get-SSHConfigHosts
    foreach ($h in Get-SSHKnownHosts) {
        if ($h -notin $AllHosts) { $Allhosts += $h }
    }
    return ($AllHosts  | Sort-Object -CaseSensitive -Unique)
}

<#
    .DESCRIPTION
    Returns the active local IPs
#>
function Get-ActiveIPs {
    $assignedIPs = @()
    foreach ($ip in $(Get-NetIPAddress | ? {($_.AddressState -like "Preferred") -and ($_.IPAddress -notmatch "(127.0.0.1|::1)")} | Select -ExpandProperty IPAddress)) {
        $assignedIPs += $ip
    }
    return $assignedIPs
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
    Finally implements the completion logic and registers the SSH command completor
#>
function Add-SSHTabCompletion {
    # Command to complete
	$script:cmd = @("ssh","ssh.exe")

    # Logic to compare input and present results
    $script:completionScriptBlock = {
        param($wordToComplete, $commandAst, $cursorPosition)

        # Parameter list
        $simpleParams = @(
            @{"Param"="-4"; "ShortDesc"="-4 (IPv4 mode)"; "LongDesc"="Force IPv4 connection"},
            @{"Param"="-6"; "ShortDesc"="-6 (IPv6 mode)"; "LongDesc"="Force IPv6 connection"},
            @{"Param"="-A"; "ShortDesc"="-A (agent)"; "LongDesc"="Forward using connection agent"},
            @{"Param"="-a"; "ShortDesc"="-a (no agent)"; "LongDesc"="Disables agent forwarding"},
            @{"Param"="-B"; "ShortDesc"="-B (bind <if>)"; "LongDesc"="Specify interface to bind to"},
            @{"Param"="-b"; "ShortDesc"="-b (bind <addr>)"; "LongDesc"="Specify address to bind to"},
            @{"Param"="-C"; "ShortDesc"="-C (compression)"; "LongDesc"="Enable data compression"},
            @{"Param"="-c"; "ShortDesc"="-c (<ciphers>)"; "LongDesc"="Specify comma separated list of allowed ciphers"},
            @{"Param"="-D"; "ShortDesc"="-D (dyn fwd <port>)"; "LongDesc"="Specify [bindAddress:]port to dynamically forward connections, made to this port"},
            @{"Param"="-E"; "ShortDesc"="-E (log <file>)"; "LongDesc"="Specify log file to use"},
            @{"Param"="-e"; "ShortDesc"="-e (esc <char>)"; "LongDesc"="Specify the escape char to use"},
            @{"Param"="-F"; "ShortDesc"="-F (config <file>)"; "LongDesc"="Specify config file to use"},
            @{"Param"="-f"; "ShortDesc"="-f (fall to bg)"; "LongDesc"="Fall to background before command execution"},
            @{"Param"="-G"; "ShortDesc"="-G (print config)"; "LongDesc"="Print configuration"},
            @{"Param"="-g"; "ShortDesc"="-g (fwd ports)"; "LongDesc"="Allow local port forwarding"},
            @{"Param"="-I"; "ShortDesc"="-I (PKCS#11 <lib>)"; "LongDesc"="Specify PKCS#11 lib to use"},
            @{"Param"="-i"; "ShortDesc"="-i (id <file>)"; "LongDesc"="Specify id file to use"},
            @{"Param"="-J"; "ShortDesc"="-J (jump <addr>)"; "LongDesc"="Specify jump host, used to connect to target"},
            @{"Param"="-K"; "ShortDesc"="-K (GSSAPI)"; "LongDesc"="Enable GSSAPI authentication"},
            @{"Param"="-k"; "ShortDesc"="-k (no GSSAPI)"; "LongDesc"="Disable GSSAPI authentication"},
            @{"Param"="-L"; "ShortDesc"="-L (fwd conn <p:h:p>)"; "LongDesc"="Specify [bindAddress:]port:host:port to forward from local port to host:port"},
            @{"Param"="-l"; "ShortDesc"="-l (login <user>)"; "LongDesc"="Specify login name"},
            @{"Param"="-M"; "ShortDesc"="-M (master)"; "LongDesc"="Master mode for connection sharing"},
            @{"Param"="-m"; "ShortDesc"="-m (MAC <algos>)"; "LongDesc"="Specify comma separated list of MAC algorithms"},
            @{"Param"="-N"; "ShortDesc"="-N (no rem cmd)"; "LongDesc"="No execution of remote commands"},
            @{"Param"="-n"; "ShortDesc"="-n (redirect null)"; "LongDesc"="Redirect stdIn from /dev/null"},
            @{"Param"="-O"; "ShortDesc"="-O (ctrl <cmd>)"; "LongDesc"="Specify command to control an active connection master process"},
            @{"Param"="-o"; "ShortDesc"="-o (<options>)"; "LongDesc"="Specify options to use like in the config file"},
            @{"Param"="-p"; "ShortDesc"="-p (<port>)"; "LongDesc"="Specify port to connect to"},
            @{"Param"="-q"; "ShortDesc"="-q (quiet)"; "LongDesc"="Quiet mode"},
            @{"Param"="-Q"; "ShortDesc"="-Q (query <option>)"; "LongDesc"="Specify option to query available values"},
            @{"Param"="-R"; "ShortDesc"="-R (rev fwd conn <p:h:p>)"; "LongDesc"="Specify [bindAddress:]port:host:port to forward from host:port to local port"},
            @{"Param"="-S"; "ShortDesc"="-S (ctl <socket>)"; "LongDesc"="Specify a socket for connection sharing"},
            @{"Param"="-s"; "ShortDesc"="-s (subsystem)"; "LongDesc"="Use a subsystem on the remote machine"},
            @{"Param"="-T"; "ShortDesc"="-T (no term)"; "LongDesc"="Disable pseudo terminal"},
            @{"Param"="-t"; "ShortDesc"="-t (term)"; "LongDesc"="Force pseudo terminal"},
            @{"Param"="-V"; "ShortDesc"="-V (version)"; "LongDesc"="Display version"},
            @{"Param"="-v"; "ShortDesc"="-v (verbose)"; "LongDesc"="Print debug messages"},
            @{"Param"="-W"; "ShortDesc"="-W (fwd in/out <h:p>)"; "LongDesc"="Specify host:port to forward stdIn and stdOut to"},
            @{"Param"="-w"; "ShortDesc"="-w (<tun> fwd)"; "LongDesc"="Specify localTun[:remoteTun] to forward through localTun device"},
            @{"Param"="-X"; "ShortDesc"="-X (X11 fwd)"; "LongDesc"="Enable X11 forwarding"},
            @{"Param"="-x"; "ShortDesc"="-x (no X11 fwd)"; "LongDesc"="Disable X11 forwarding"},
            @{"Param"="-Y"; "ShortDesc"="-Y (trusted X11 fwd)"; "LongDesc"="Enable trusted X11 forwarding"},
            @{"Param"="-y"; "ShortDesc"="-y (use syslog)"; "LongDesc"="Write errors to syslog instead of stdErr"}
        )

        # Query options (for -Q)
        $queryOptions = "cipher", "cipher_auth", "help", "mac", "kex", "kex-gss", "key", "key-cert", "key-plain", "key-sig", "protocol-version", "sig"

        # Prepare known target hosts
        $hosts = @()
        foreach ($h in (Get-SSHHosts)) {
            $hosts += @{"Param"=$h; "ShortDesc"=$h; "LongDesc"="Connect to target system $h"}
        }

        switch -RegEx -CaseSensitive (Get-LeftCommandLineElement -cmdAst $commandAst -curPos $cursorPosition) {
            "-b" {
                $allResults = Get-ActiveIPs | ? { $_ -like "$wordToComplete*" }
                break
            }
            "-Q" {
                $allResults = $queryOptions | ? { $_ -like "$wordToComplete*" }
                break
            }
            "-E|-F|-i" {
                $allResults = Complete-Files $wordToComplete
                break
            }
            "-J|-W" {
                $allResults = @()
                $allResults += $hosts | ? { $_.Param -like "$wordToComplete*" } | % { Create-CompletionResult @_ }
                break
            }
            "-c" {
                $allResults = ssh -Q cipher | ? { $_ -like "$wordToComplete*" }
                break
            }
            "-m" {
                $allResults = ssh -Q mac | ? { $_ -like "$wordToComplete*" }
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

if (Get-Command ssh -CommandType Application -EA SilentlyContinue) {
	Add-SSHTabCompletion
} else {
	Write-Error "SSH was not found in your environment! Put it too path..."
}

# Expose no functions
Export-ModuleMember -Function ""
