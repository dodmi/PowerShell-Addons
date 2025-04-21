<#
What is this?
This is a PowerShell module providing TAB completion for the native openssl command

Are there any requirements?
- PowerShell obviously
- OpenSSL 1.1.*, 3.0.* - 3.4.* or 3.5

How to use this file alone?
- Put the path to openssl executable to your path variable (OPENSSL NEEDS TO BE EXECUTABLE FROM ANY LOCATION)
- Run $env:PSModulePath in PowerShell
- Place this file in one of the module locations in a sub folder named OpenSSL-TABComplete
- Run import-module OpenSSL-TABComplete (to get this permanently, add the line to your $profile)
- Now you should have tab completion for openssl parameters (enter openssl <TAB> or openssl <Ctrl+Space>)

How to use this file in the bundle?
- Put the path to openssl executable to your path variable (OPENSSL NEEDS TO BE EXECUTABLE FROM ANY LOCATION)
- Run $env:PSModulePath in PowerShell
- Place this file and the file TABCompletion.psm1 in one of the module locations in a sub folder named TABCompletion
- Run import-module TABCompletion (to get this permanently, add the line to your $profile)
- Now you should have tab completion for openssl parameters (enter openssl <TAB> or openssl <Ctrl+Space>)

Where do I get the latest version?
https://github.com/dodmi/PowerShell-Addons/TABCompletion/tree/master/

When was this file updated?
2025-04-21
#>

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
    Gets the OpenSSL mode (first argument)
    .PARAMETER cmdAst
    The command structure as provided in Register-ArgumentCompleter
#>
function Get-OpenSSLMode {
    param(
        [System.Management.Automation.Language.CommandAst] $cmdAst
    )

	if ($cmdAst.CommandElements.Count -le 1) {
		$result = ""
	} else {
		$result = $cmdAst.CommandElements[1].Extent.Text
	}
    return $result
}

<#
	.DESCRIPTION
	Provides an option list, that was retrieved from openssl list -1 -options <mode>
	.PARAMETER Mode
	The OpenSSL mode to get the options for
#>
function Get-OpenSSLOptions {
	param( [String] $Mode )
	$options = openssl list -1 -options $Mode
	for ($i=0; $i -lt $options.count; $i++) {
		if ($options[$i].indexOf(" ") -gt 0) {
			$options[$i] = $($options[$i].split(" "))[0]
		}
		$options[$i] = "-" + $options[$i]
	}
	return $options
}

$script:optionHelpTable = @{}

<#
	.DESCRIPTION
	Returns a short help for the provided option
	.PARAMETER Option
	The option, for which the help is needed
#>
function Get-OpenSSLOptionHelp {
	param(
		[String] $Option,
		[String] $Mode
	)
	$helpStr = "$Mode $Option"
	if (-not $script:optionHelpTable.containsKey($Mode)) {
		$helpStrings = openssl $Mode -help 2>&1
		$helpTable = [HashTable]::New(0, [StringComparer]::Ordinal)
		foreach ($line in $helpStrings)
		{
			if ($line -match "^\s(-\S+)\s(\S+)\s+(.+)$")
			{
				$helpTable.add($Matches[1], "<"+$Matches[2]+"> | "+$Matches[3])
			}
			if ($line -match "^\s(-\S+)\s\s+(.+)$")
			{
				$helpTable.add($Matches[1], $Matches[2])
			}
		}
		$script:optionHelpTable.add($Mode, $helpTable)
	}
	if ($script:optionHelpTable.$Mode.containsKey($Option))
	{
		$helpStr = $script:optionHelpTable.$Mode.$Option
	}
	if ($Option -like "-help") { $helpStr = "Displays all available options with a short description" }
	return $helpStr
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
    Returns a list of folder names to complete
    .PARAMETER wordToComplete
    The text to filter the results for
#>
function Complete-Dirs {
    param ([String] $wordToComplete)
    $currentPath = Get-Location | Select -ExpandProperty Path
    $result = @()
    $proposals = Get-ChildItem -Force -Directory "$wordToComplete*" | Select -ExpandProperty Fullname | % {$_.Replace($currentPath,".")}
    foreach ($p in $proposals) {
        $p += "\"
        if ($p.Contains(" ") -and -not ($p.StartsWith('"') -or $p.StartsWith("'"))) { $p = "'$p'" }
        if ($p.Contains("$") -and -not ($p.StartsWith('"') -or $p.StartsWith("'"))) { $p = "'$p'" }
        $result += $p
    }

	if (($result.count -eq 0) -and ($wordToComplete -like "")) { $result += ".\" }
    return $result
}

<#
    .DESCRIPTION
    Finally defines and registers the OpenSSL command completor
#>
function Add-OpenSSLTabCompletion {

    # Command to complete
	$script:cmd = @("openssl","openssl.exe")

    # Logic to compare input and present results
    $script:completionScriptBlock = {
        param($wordToComplete, $commandAst, $cursorPosition)

        # Parameter list (supported modes in OpenSSL 1.1)
        $modes = @(
			@{"Param"="asn1parse"; "ShortDesc"="asn1parse"; "LongDesc"="Parse an ASN.1 sequence"},
			@{"Param"="ca"; "ShortDesc"="ca"; "LongDesc"="Certificate Authority Management"},
			@{"Param"="ciphers"; "ShortDesc"="ciphers"; "LongDesc"="Cipher Suite Description Determination"},
			@{"Param"="cms"; "ShortDesc"="cms"; "LongDesc"="Cryptographic Message Syntax utility"},
			@{"Param"="crl"; "ShortDesc"="crl"; "LongDesc"="Certificate Revocation List Management"},
			@{"Param"="crl2pkcs7"; "ShortDesc"="crl2pkcs7"; "LongDesc"="CRL to PKCS#7 Conversion"},
			@{"Param"="dgst"; "ShortDesc"="dgst"; "LongDesc"="Message Digest Calculation"},
			@{"Param"="dhparam"; "ShortDesc"="dhparam"; "LongDesc"="Generation and Management of Diffie-Hellman Parameters"},
			@{"Param"="dsa"; "ShortDesc"="dsa"; "LongDesc"="DSA Data Management"},
			@{"Param"="dsaparam"; "ShortDesc"="dsaparam"; "LongDesc"="DSA Parameter Generation and Management"},
			@{"Param"="ec"; "ShortDesc"="ec"; "LongDesc"="EC (Elliptic curve) key processing"},
			@{"Param"="ecparam"; "ShortDesc"="ecparam"; "LongDesc"="EC parameter manipulation and generation"},
			@{"Param"="enc"; "ShortDesc"="enc"; "LongDesc"="Encoding with Ciphers"},
			@{"Param"="engine"; "ShortDesc"="engine"; "LongDesc"="Engine (loadable module) information and manipulation"},
			@{"Param"="errstr"; "ShortDesc"="errstr"; "LongDesc"="Error Number to Error String Conversion"},
			@{"Param"="gendsa"; "ShortDesc"="gendsa"; "LongDesc"="Generation of DSA Private Key from Parameters"},
			@{"Param"="genpkey"; "ShortDesc"="genpkey"; "LongDesc"="Generation of Private Key or Parameters"},
			@{"Param"="genrsa"; "ShortDesc"="genrsa"; "LongDesc"="Generation of RSA Private Key"},
			@{"Param"="help"; "ShortDesc"="help"; "LongDesc"="Display Help"},
			@{"Param"="list"; "ShortDesc"="list"; "LongDesc"="List functions and options"},
			@{"Param"="nseq"; "ShortDesc"="nseq"; "LongDesc"="Create or examine a Netscape certificate sequence"},
			@{"Param"="ocsp"; "ShortDesc"="ocsp"; "LongDesc"="Online Certificate Status Protocol utility"},
			@{"Param"="passwd"; "ShortDesc"="passwd"; "LongDesc"="Generation of hashed passwords"},
			@{"Param"="pkcs12"; "ShortDesc"="pkcs12"; "LongDesc"="PKCS#12 Data Management"},
			@{"Param"="pkcs7"; "ShortDesc"="pkcs7"; "LongDesc"="PKCS#7 Data Management"},
			@{"Param"="pkcs8"; "ShortDesc"="pkcs8"; "LongDesc"="PKCS#8 Data Management"},
			@{"Param"="pkey"; "ShortDesc"="pkey"; "LongDesc"="Public and private key management"},
			@{"Param"="pkeyparam"; "ShortDesc"="pkeyparam"; "LongDesc"="Public key algorithm parameter management"},
			@{"Param"="pkeyutl"; "ShortDesc"="pkeyutl"; "LongDesc"="Public key algorithm cryptographic operation utility"},
			@{"Param"="prime"; "ShortDesc"="prime"; "LongDesc"="Compute prime numbers"},
			@{"Param"="rand"; "ShortDesc"="rand"; "LongDesc"="Generate pseudo-random bytes"},
			@{"Param"="rehash"; "ShortDesc"="rehash"; "LongDesc"="Create symbolic links to certificate and CRL files named by the hash values"},
			@{"Param"="req"; "ShortDesc"="req"; "LongDesc"="PKCS#10 X.509 Certificate Signing Request Management"},
			@{"Param"="rsa"; "ShortDesc"="rsa"; "LongDesc"="RSA key management"},
			@{"Param"="rsautl"; "ShortDesc"="rsautl"; "LongDesc"="RSA utility for signing, verification, encryption, and decryption"},
			@{"Param"="s_client"; "ShortDesc"="s_client"; "LongDesc"="Generic SSL/TLS client"},
			@{"Param"="s_server"; "ShortDesc"="s_server"; "LongDesc"="Generic SSL/TLS server"},
			@{"Param"="s_time"; "ShortDesc"="s_time"; "LongDesc"="SSL Connection Timer"},
			@{"Param"="sess_id"; "ShortDesc"="sess_id"; "LongDesc"="SSL Session Data Management"},
			@{"Param"="smime"; "ShortDesc"="smime"; "LongDesc"="S/MIME mail processing"},
			@{"Param"="speed"; "ShortDesc"="speed"; "LongDesc"="Algorithm Speed Measurement"},
			@{"Param"="spkac"; "ShortDesc"="spkac"; "LongDesc"="SPKAC printing and generating utility"},
			@{"Param"="srp"; "ShortDesc"="srp"; "LongDesc"="Maintain SRP password file"},
			@{"Param"="storeutl"; "ShortDesc"="storeutl"; "LongDesc"="Utility to list and display certificates, keys, CRLs, etc"},
			@{"Param"="ts"; "ShortDesc"="ts"; "LongDesc"="Time Stamping Authority tool"},
			@{"Param"="verify"; "ShortDesc"="verify"; "LongDesc"="X.509 Certificate Verification"},
			@{"Param"="version"; "ShortDesc"="version"; "LongDesc"="OpenSSL Version Information"},
			@{"Param"="x509"; "ShortDesc"="x509"; "LongDesc"="X.509 Certificate Data Management"}
		)

		$defaultModeList = "^asn1parse$|^ca$|^ciphers$|^cms$|^crl$|^crl2pkcs7$|^dgst$|^dhparam$|^dsa$|^dsaparam$|^ec$|^ecparam$|^enc$|^engine$|^errstr$|^gendsa$|^genpkey$|^genrsa$|^list$|^nseq$|^ocsp$|^passwd$|^pkcs12$|^pkcs7$|^pkcs8$|^pkey$|^pkeyparam$|^pkeyutl$|^prime$|^rand$|^rehash$|^req$|^rsa$|^rsautl$|^s_client$|^s_server$|^s_time$|^sess_id$|^smime$|^speed$|^spkac$|^srp$|^storeutl$|^ts$|^verify$|^version$|^x509$"

		if ($script:OpenSSLVersion -in ("3.x","3.5")) {
			$newModes = @(
				@{"Param"="cmp"; "ShortDesc"="cmp"; "LongDesc"="Certificate Management Protocol (CMP, RFC 4210) application"},
				@{"Param"="fipsinstall"; "ShortDesc"="fipsinstall"; "LongDesc"="Perform FIPS configuration installation"},
				@{"Param"="info"; "ShortDesc"="info"; "LongDesc"="Print OpenSSL built-in information"},
				@{"Param"="kdf"; "ShortDesc"="kdf"; "LongDesc"="Perform Key Derivation Function operations"},
				@{"Param"="mac"; "ShortDesc"="mac"; "LongDesc"="Perform Message Authentication Code operations"}
			)

			$modes += $newModes
			$defaultModeList += "|^cmp$|^fipsinstall$|^info$|^kdf$|^mac$"
		}

		if ($script:OpenSSLVersion -like "3.5") {
			$newModes = @(
				@{"Param"="skeyutl"; "ShortDesc"="skeyutl"; "LongDesc"="Opaque symmetric keys routines"}
			)

			$modes += $newModes
			$defaultModeList += "|^skeyutl$"
		}

		$mode = Get-OpenSSLMode $commandAst
        switch -RegEx ($mode) {
			$defaultModeList {
				switch -RegEx (Get-LeftCommandLineElement $commandAst $cursorPosition) {
					"^-CAform$" {
						$allResults = "PEM","DER"
						$allResults = $allResults | ? { $_ -like "$wordToComplete*" } | Sort-Object
					}
					"^-CAkeyform$" {
						$allResults = "PEM","DER","ENGINE"
						$allResults = $allResults | ? { $_ -like "$wordToComplete*" } | Sort-Object
					}
					"^-inform$" {
						$allResults = "PEM","DER"
						switch -RegEx ($mode) {
							"^smime$|^cms$" { $allResults += "SMIME" }
							"^dsa$" { $allResults += "PVK" }
						}
						$allResults = $allResults | ? { $_ -like "$wordToComplete*" } | Sort-Object
					}
					"^-keyform$" {
						$allResults = "PEM","DER","ENGINE"
						$allResults = $allResults | ? { $_ -like "$wordToComplete*" } | Sort-Object
					}
					"^-outform$" {
						$allResults = "PEM","DER"
						switch -RegEx ($mode) {
							"^smime$|^cms$" { $allResults += "SMIME" }
							"^dsa$|^rsa$" { $allResults += "PVK" }
							"^sess_id$" { $allResults += "NSS" }
						}
						$allResults = $allResults | ? { $_ -like "$wordToComplete*" } | Sort-Object
					}
					"^-rctform$" {
						$allResults = "PEM","DER"
						$allResults = $allResults | ? { $_ -like "$wordToComplete*" } | Sort-Object
					}
					"^-maxfraglen$" {
						$allResults = "512","1024","2048","4096"
						$allResults = $allResults | ? { $_ -like "$wordToComplete*" } | Sort-Object
					}
					"^-purpose$" {
						switch -RegEx ($mode) {
							"^verify$" {
								$allResults = "sslclient", "sslserver", "nssslserver", "smimesign", "smimeencrypt", "crlsign", "any", "ocsphelper", "timestampsign"
								$allResults = $allResults | ? { $_ -like "$wordToComplete*" } | Sort-Object
							}
							default {
								$allResults = Get-OpenSSLOptions -Mode $mode | ? { $_ -like "$wordToComplete*" } | % { Create-CompletionResult -Param $_ -ShortDesc $_ -LongDesc (Get-OpenSSLOptionHelp -Option $_ -Mode $mode) }
							}
						}
					}
					"^-verify_name$" {
						switch -RegEx ($mode) {
							"^verify$" {
								$allResults = "default", "pkcs7", "smime_sign", "ssl_client", "ssl_server"
								$allResults = $allResults | ? { $_ -like "$wordToComplete*" } | Sort-Object
							}
							default {
								$allResults = Get-OpenSSLOptions -Mode $mode | ? { $_ -like "$wordToComplete*" } | % { Create-CompletionResult -Param $_ -ShortDesc $_ -LongDesc (Get-OpenSSLOptionHelp -Option $_ -Mode $mode) }
							}
						}
					}
					"^-CA$|^-cafile$|^-CAfile$|^-CAkey$|^-CAserial$|^-cert_chain$|^-cert2$|^-certfile$|^-certsout$|^-chain$|^-chainCAfile$|^-config$|^-content$|^-CRL$|^-CRLfile$|^-ctlogfile$|^-data$|^-dcert$|^-dcert_chain$|^-dhparam$|^-dkey$|^-extfile$|^-force_pubkey$|^-genconf$|^-gendelta$|^-in$|^-index$|^-inkey$|^-key2$|^-keyfile$|^-keylogfile$|^-kfile$|^-keyout$|^-msgfile$|^-oid$|^-out$|^-paramfile$|^-peerkey$|^-prverify$|^-psk_session$|^-queryfile$|^-rand$|^-recip$|^-reqin$|^-reqout$|^-requestCAfile$|^-respin$|^-respout$|^-revoke$|^-rkey$|^-rother$|^-rsigner$|^-sess_in$|^-sess_out$|^-sigfile$|^-sign_other$|^-signer$|^-signkey$|^-srpvfile$|^-ss_cert$|^-ssl_config$|^-status_file$|^-trusted$|^-untrusted$|^-VAfile$|^-verify_other$|^-verify_receipt$|^-verifyCAfile$|^-writerand$|^-xcert$|^-xchain$|^-xkey$" {
						$allResults = Complete-Files $wordToComplete
					}
					"^-CApath$|^-chainCApath$|^-outdir$|^-verifyCApath$" {
						$allResults = Complete-Dirs $wordToComplete
					}
					"^-cert$" {
						switch -RegEx ($mode) {
							"^ca$|^ocsp$|^s_client$|^s_server$|^s_time$" {
								$allResults = Complete-Files $wordToComplete
							}
							default {
								$allResults = Get-OpenSSLOptions -Mode $mode | ? { $_ -like "$wordToComplete*" } | % { Create-CompletionResult -Param $_ -ShortDesc $_ -LongDesc (Get-OpenSSLOptionHelp -Option $_ -Mode $mode) }
							}
						}
					}
					"^-early_data$" {
						switch -RegEx ($mode) {
							"^s_client$" {
								$allResults = Complete-Files $wordToComplete
							}
							default {
								$allResults = Get-OpenSSLOptions -Mode $mode | ? { $_ -like "$wordToComplete*" } | % { Create-CompletionResult -Param $_ -ShortDesc $_ -LongDesc (Get-OpenSSLOptionHelp -Option $_ -Mode $mode) }
							}
						}
					}
					"^-sign$" {
						switch -RegEx ($mode) {
							"^dgst$" {
								$allResults = Complete-Files $wordToComplete
							}
							default {
								$allResults = Get-OpenSSLOptions -Mode $mode | ? { $_ -like "$wordToComplete*" } | % { Create-CompletionResult -Param $_ -ShortDesc $_ -LongDesc (Get-OpenSSLOptionHelp -Option $_ -Mode $mode) }
							}
						}
					}
					"^-verify$" {
						switch -RegEx ($mode) {
							"^dgst$" {
								$allResults = Complete-Files $wordToComplete
							}
							default {
								$allResults = Get-OpenSSLOptions -Mode $mode | ? { $_ -like "$wordToComplete*" } | % { Create-CompletionResult -Param $_ -ShortDesc $_ -LongDesc (Get-OpenSSLOptionHelp -Option $_ -Mode $mode) }
							}
						}
					}
					"^-issuer$" {
						switch -RegEx ($mode) {
							"^ocsp$" {
								$allResults = Complete-Files $wordToComplete
							}
							default {
								$allResults = Get-OpenSSLOptions -Mode $mode | ? { $_ -like "$wordToComplete*" } | % { Create-CompletionResult -Param $_ -ShortDesc $_ -LongDesc (Get-OpenSSLOptionHelp -Option $_ -Mode $mode) }
							}
						}
					}
					"^-key$" {
						switch -RegEx ($mode) {
							"^ca$" {
								$allResults = Get-OpenSSLOptions -Mode $mode | ? { $_ -like "$wordToComplete*" } | % { Create-CompletionResult -Param $_ -ShortDesc $_ -LongDesc (Get-OpenSSLOptionHelp -Option $_ -Mode $mode) }
							}
							default {
								$allResults = Complete-Files $wordToComplete
							}
						}
					}
					"^-spkac$" {
						switch -RegEx ($mode) {
							"^ca$" {
								$allResults = Complete-Files $wordToComplete
							}
							default {
								$allResults = Get-OpenSSLOptions -Mode $mode | ? { $_ -like "$wordToComplete*" } | % { Create-CompletionResult -Param $_ -ShortDesc $_ -LongDesc (Get-OpenSSLOptionHelp -Option $_ -Mode $mode) }
							}
						}
					}
					"^-md$" {
						$allResults = @()
						$digests = openssl list -1 -digest-algorithms
						for ($i=0; $i -lt $digests.count; $i++) {
							if ($digests[$i].indexOf(" ") -gt 0) {
								$digests[$i] = ($digests[$i].split(" "))[2]
							}
						}
						$allResults = $digests | ? { $_ -like "$wordToComplete*" } | Sort-Object -Unique
					}
					default {
						$allResults = Get-OpenSSLOptions -Mode $mode | ? { $_ -like "$wordToComplete*" } | % { Create-CompletionResult -Param $_ -ShortDesc $_ -LongDesc (Get-OpenSSLOptionHelp -Option $_ -Mode $mode) }
					}
				}
			}
			"^help$" {
				$allResults = $modes | ? { $_.Param -like "$wordToComplete*" } | % { Create-CompletionResult @_ }
			}
            default {
                $allResults = $modes | ? { $_.Param -like "$wordToComplete*" } | % { Create-CompletionResult @_ }
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

if (Get-Command openssl -CommandType Application -EA SilentlyContinue) {
	$openSSLVersionString = openssl version 2>&1
	switch -wildcard ($openSSLVersionString) {
		"OpenSSL 1.1.*" {
			$script:OpenSSLVersion = "1.1"
			break
		}
		"OpenSSL 3.0.*" {
			$script:OpenSSLVersion = "3.x"
			break
		}
		"OpenSSL 3.1.*" {
			$script:OpenSSLVersion = "3.x"
			break
		}
		"OpenSSL 3.2.*" {
			$script:OpenSSLVersion = "3.x"
			break
		}
		"OpenSSL 3.3.*" {
			$script:OpenSSLVersion = "3.x"
			break
		}
		"OpenSSL 3.4.*" {
			$script:OpenSSLVersion = "3.x"
			break
		}
		"OpenSSL 3.5.*" {
			$script:OpenSSLVersion = "3.5"
			break
		}
		default {
			Write-Error "Could not determine OpenSSL version or version is not 1.1, 3.0 - 3.4 or 3.5: $openSSLVersionString"
			return
		}
	}
	Add-OpenSSLTabCompletion
} else {
	Write-Error "OpenSSL was not found in your environment! Put it too path..."
}

# Expose no functions
Export-ModuleMember -Function ""
