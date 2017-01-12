Get-ChildItem $PSScriptRoot -Recurse -Exclude 'Lib', 'Tests' -File -Include *.ps1 |
    ForEach-Object { . $_.FullName }