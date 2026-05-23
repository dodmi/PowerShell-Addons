<#
 .SYNOPSIS
	Loader for TAB completion modules
 .DESCRIPTION
	Loader Module for any *-TABComplete.psm1 module in the same directory
	This is a simple loader, which loads any module with the name format *-TABComplete.psm1 in the module's directory
	So, it's possible to load all TAB-Completion additions by the command "Import-Module TABCompletion"
 .NOTES
	Date: 2026-05-23
#>

<#
 .SYNOPSIS
	Import all completion modules in the folder
 .DESCRIPTION
	Import all modules in the same folder as TABCompletion.psm1
#>
function Import-CompletionModule {
	[OutputType([String[]])]
	param()

	$srcPath = Get-Module -ListAvailable TABCompletion | Select -ExpandProperty Path
	if ($srcPath) {
		$srcPath = Split-Path -Parent $srcPath
		Write-Output "Pfad: $srcPath"
		Get-ChildItem -Path $srcPath -Filter "*-TABComplete.psm1" | % { Import-Module $_.FullName }
	}
}

Import-CompletionModule

Export-ModuleMember -Function ""
