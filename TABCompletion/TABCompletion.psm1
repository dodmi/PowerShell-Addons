<#
	Loader Module for any *-TABComplete.psm1 module in the same directory
	This is a simple loader, which loads any module with the name format *-TABComplete.psm1 in the module's directory
	So, it's possible to load all TAB-Completion additions by the command "Import-Module TABCompletion"
#>

function Import-Completions {
	$srcPath = Get-Module -ListAvailable TABCompletion
	if ($srcPath) {
		$srcPath = Split-Path $srcPath[0].Path
		Write-Output "Pfad: $srcPath"
		Get-ChildItem -Path $srcPath -Filter "*-TABComplete.psm1" | % {Import-Module $_.FullName}
	}
}

Import-Completions

Export-ModuleMember -Function ""