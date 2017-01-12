@{
RootModule = 'CatalogTools.psm1'

ModuleVersion = '0.1.0.0'

GUID = '8c68d3af-334f-48b7-a98f-e276b4309c03'

Author = 'Matthew Graeber'

Copyright = 'BSD 3-Clause'

Description = 'CatalogTools is a module to assist in parsing and managing catalog files.'

PowerShellVersion = '3.0'

RequiredAssemblies = @('Lib\BouncyCastle.Crypto.dll')

# Functions to export from this module
FunctionsToExport = @(
    'Get-CatalogFile'
)

PrivateData = @{

    PSData = @{
        Tags = @('security', 'DFIR', 'defense')

        LicenseUri = 'https://github.com/mattifestation/CatalogTools/blob/master/LICENSE'

        ProjectUri = 'https://github.com/mattifestation/CatalogTools'

        ReleaseNotes = @'
0.1.0
-----
Initial release.

Enhancements:
* Added Get-CatalogFile
'@
    }

}

}
