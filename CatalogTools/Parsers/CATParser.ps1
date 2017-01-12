function Get-CatalogFile {
<#
.SYNOPSIS

Catalog (.cat) file parser.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.DESCRIPTION

Get-CatalogFile parses catalog files without relying upon built-in Win32 APIs.

.PARAMETER Path

Specifies the path to one or more catalog files.

.EXAMPLE

Get-ChildItem 'C:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}' | Get-CatalogFile

.EXAMPLE

Get-ChildItem C:\ -Recurse -Include *.cat | Get-CatalogFile

.EXAMPLE

Get-CatalogFile -Path oem1.cat

.INPUTS

System.IO.FileInfo

Accepts file output from Get-ChildItem or Get-Item. Get-CatalogFile only parses files with the .cat extension.

.OUTPUTS

CatalogTools.ParsedCatalog

Outputs a custom object coinsisting of parsed catalog file data - timestamp, header, members, and signature.
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path
    )

    PROCESS {
        foreach ($FilePath in $Path) {
            $FullPath = Resolve-Path -Path $FilePath

            $FileInfo = Get-Item -Path $FullPath

            if ($FileInfo.Extension -ne '.cat') {
                Write-Error "$FullPath does not have the .cat extension."
                continue
            }

            $FileStream = [IO.File]::OpenRead($FullPath)

            if (-not $FileStream) { continue }

            $ASN1InputStream = New-Object -TypeName Org.BouncyCastle.Asn1.Asn1InputStream -ArgumentList $FileStream

            $ASN1Object = $ASN1InputStream.ReadObject()

            if (-not $ASN1Object) {
                Write-Error "$FullPath is not ASN.1 encoded data."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue 
            }

            if (($ASN1Object.Count -lt 2)) {
                Write-Error "$($FullPath): ASN.1 encoded data does not hold enough information to hold PKCS#7 ASN.1 SignedData (1.2.840.113549.1.7.2)."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            if (-not ($ASN1Object[0] -is [Org.BouncyCastle.Asn1.DerObjectIdentifier])) {
                Write-Error "$($FullPath): ASN.1 encoded data is not PKCS#7 ASN.1 SignedData (1.2.840.113549.1.7.2). It must contain an OID datatype."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            if ($ASN1Object[0].Id -ne '1.2.840.113549.1.7.2') {
                Write-Error "$($FullPath): ASN.1 encoded data is not PKCS#7 ASN.1 SignedData. Its OID must be 1.2.840.113549.1.7.2."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            if (-not ($ASN1Object[1] -is [Org.BouncyCastle.Asn1.DerTaggedObject])) {
                Write-Error "$($FullPath): ASN.1 encoded data is not PKCS#7 ASN.1 SignedData (1.2.840.113549.1.7.2). It must contain a context-specific tag."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            if (($ASN1Object[1].TagNo -ne 0) -or ($ASN1Object[1].IsEmpty())) {
                Write-Error "$($FullPath): ASN.1 encoded data is not PKCS#7 ASN.1 SignedData (1.2.840.113549.1.7.2). It must contain a non-empty context-specific tag ([0])."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            $SignedDataObject = $ASN1Object[1].GetObject()

            if ((-not $SignedDataObject) -or (-not ($SignedDataObject -is [Org.BouncyCastle.Asn1.DerSequence])) -or ($SignedDataObject.Count -lt 4)) {
                Write-Error "$($FullPath): Embedded PKCS#7 ASN.1 SignedData data type must be a SEQUENCE consisting of at least 4 elements."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            # PKCS#7 ASN.1 SignedData is defined in RFC2315

            if (-not ($SignedDataObject[0] -is [Org.BouncyCastle.Asn1.DerInteger])) {
                Write-Error "$($FullPath): No PKCS#7 ASN.1 SignedData Version field present."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            if ($SignedDataObject[0].PositiveValue -ne 1) {
                Write-Error "$($FullPath): PKCS#7 ASN.1 SignedData must have a Version of 1. Returned version: $($SignedDataObject[0].PositiveValue)."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            # Unless I care at a later time about the signer message digest algorithm, only validate that this required field is present.
            # At this time, I only care about catalog information in the ContentInfo property.
            if (-not ($SignedDataObject[1] -is [Org.BouncyCastle.Asn1.DerSet])) {
                Write-Error "$($FullPath): DigestAlgorithmIdentifiers PKCS#7 ASN.1 SignedData field is not present."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            if (-not ($SignedDataObject[2] -is [Org.BouncyCastle.Asn1.DerSequence]) -or ($SignedDataObject[2].Count -ne 2)) {
                Write-Error "$($FullPath): ContentInfo PKCS#7 ASN.1 SignedData field must be of type SEQUENCE with two elements."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            if (-not ($SignedDataObject[2][0] -is [Org.BouncyCastle.Asn1.DerObjectIdentifier])) {
                Write-Error "$($FullPath): ContentInfo PKCS#7 ASN.1 SignedData does not have an embedded OBJECT IDENTIFIER."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            # A CTL is a list of hashes of certificates or a list of file names.
            # https://msdn.microsoft.com/en-us/library/windows/desktop/ms721572(v=vs.85).aspx#_security_certificate_trust_list_gly
            if ($SignedDataObject[2][0].Id -ne '1.3.6.1.4.1.311.10.1') {
                Write-Error "$($FullPath): ContentInfo PKCS#7 ASN.1 SignedData is not of type PKCS #7 ContentType Object Identifier for Certificate Trust List (CTL) (1.3.6.1.4.1.311.10.1). OID continueed: $($SignedDataObject[2][0].Id)."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            if (-not ($SignedDataObject[2][1] -is [Org.BouncyCastle.Asn1.DerTaggedObject]) -or ($SignedDataObject[2][1].TagNo -ne 0) -or ($SignedDataObject[2][1].IsEmpty()) -or (-not $SignedDataObject[2][1].IsExplicit())) {
                Write-Error "$($FullPath): ContentInfo PKCS#7 ASN.1 SignedData does not have an embedded non-empty, explicit context-specific tag."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            $CatalogRootObject = $SignedDataObject[2][1].GetObject()

            # Start parsing/validating the catalog file header.
            if (-not ($CatalogRootObject -is [Org.BouncyCastle.Asn1.DerSequence]) -and ($CatalogRootObject.Count -lt 5)) {
                Write-Error "$($FullPath): Certificate Trust List data must have at least 5 elements for a szOID_CATALOG_LIST type."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            if (-not ($CatalogRootObject[0] -is [Org.BouncyCastle.Asn1.DerSequence]) -or ($CatalogRootObject[0].Count -lt 1) -or ($CatalogRootObject[0].Id -ne '1.3.6.1.4.1.311.12.1.1')) {
                Write-Error "$($FullPath): Certificate Trust List does not have embedded data of type szOID_CATALOG_LIST (1.3.6.1.4.1.311.12.1.1)."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            if (-not ($CatalogRootObject[1] -is [Org.BouncyCastle.Asn1.DerOctetString])) {
                Write-Error "$($FullPath): Catalog list does not contain a list identifier."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            $ListIdentifier = ($CatalogRootObject[1].GetOctets() | ForEach-Object { "{0:X2}" -f $_ }) -join ''

            if (-not ($CatalogRootObject[2] -is [Org.BouncyCastle.Asn1.DerUtcTime])) {
                Write-Error "$($FullPath): Catalog list does not contain a timestamp."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            $Timestamp = $CatalogRootObject[2].ToDateTime()

            $CatalogVersion = $null

            switch ($CatalogRootObject[3][0].Id) {
                '1.3.6.1.4.1.311.12.1.2' { $CatalogVersion = 1 }
                '1.3.6.1.4.1.311.12.1.3' { $CatalogVersion = 2 }
                default {
                    Write-Error "$($FullPath): Undefined catalog version OID. OID returned: $($CatalogRootObject[3][0].Id)"
                    $ASN1InputStream.Close()
                    $FileStream.Close()
                    continue
                }
            }

            $HeaderAttributeObjects = $null

            # Parse header attributes if they exist.
            if ($CatalogRootObject.Count -eq 6) {
                if (-not ($CatalogRootObject[5] -is [Org.BouncyCastle.Asn1.DerTaggedObject]) -or ($CatalogRootObject[5].TagNo -ne 0) -or ($CatalogRootObject[5].IsEmpty())) {
                    Write-Error "$($FullPath): Catalog header attributes are of an incorrect type."
                    $ASN1InputStream.Close()
                    $FileStream.Close()
                    continue
                }

                $HeaderAttributes = $CatalogRootObject[5].GetObject()

                if (-not ($HeaderAttributes -is [Org.BouncyCastle.Asn1.DerSequence]) -or ($HeaderAttributes.Count -lt 1)) {
                    Write-Error "$($FullPath): Catalog header attributes are of an incorrect type."
                    $ASN1InputStream.Close()
                    $FileStream.Close()
                    continue
                }

                $HeaderAttributeObjects = New-Object -TypeName PSObject[]($HeaderAttributes.Count)

                for ($i = 0; $i -lt $HeaderAttributes.Count; $i++) {
                    if (-not ($HeaderAttributes[$i] -is [Org.BouncyCastle.Asn1.DerSequence]) -or ($HeaderAttributes[$i].Count -ne 2)) {
                        Write-Error "$($FullPath): Catalog header attribute is of an incorrect type."
                        $ASN1InputStream.Close()
                        $FileStream.Close()
                        continue
                    }

                    $OID = $HeaderAttributes[$i][0].Id

                    if ($OID -ne '1.3.6.1.4.1.311.12.2.1') {
                        Write-Warning "$($FullPath): Incorrect catalog header attribute object identifier. OID returned: $OID"
                    }

                    $HeaderAttrProperties = [Org.BouncyCastle.Asn1.Asn1Object]::FromByteArray($HeaderAttributes[$i][1].GetOctets())

                    $AttributeName = $HeaderAttrProperties[0].ToString()
                    # Depending on how things may be encoded,
                    # I might not be able to get away with Unicode encoding everything.
                    $AttributeValue = [Text.Encoding]::Unicode.GetString($HeaderAttrProperties[2].GetOctets())

                    $HeaderAttributeObjects[$i] = [PSCustomObject] @{
                        PSTypeName = 'CatalogTools.ParsedCatalog.NameValuePair'
                        Name = $AttributeName
                        Value = $AttributeValue
                    }
                }
            }

            # Used for parser debugging. This should never be the case from my observations.
            if ($CatalogRootObject.Count -gt 6) {
                Write-Warning "$($FullPath): Catalog list has more than 6 entries."
            }

            # Start parsing the individual members of the catalog file
            if (-not ($CatalogRootObject[4] -is [Org.BouncyCastle.Asn1.DerSequence])) {
                Write-Error "$($FullPath): Catalog list does not contain a sequence of members."
                $ASN1InputStream.Close()
                $FileStream.Close()
                continue
            }

            $MemberSequence = $CatalogRootObject[4]

            $CatalogMembers = New-Object -TypeName 'System.Collections.Generic.List[System.Management.Automation.PSObject]'

            # At this point, I've decided to lay off extensive ASN.1 validation since I'm confident that
            # I'm dealing with a legitimate catalog file. The chances for a malformed file format are
            # signficantly reduced at this point.
            foreach ($Member in $MemberSequence) {
                $TagName = $null

                switch ($CatalogVersion) {
                    1 { $TagName = [Text.Encoding]::Unicode.GetString($Member[0].GetOctets()) }
                    2 { $TagName = ($Member[0].GetOctets() | ForEach-Object { "{0:X2}" -f $_ }) -join '' }
                }

                $NameValuePairs = New-Object -TypeName 'System.Collections.Generic.List[System.Management.Automation.PSObject]'
                $MemberInfo = New-Object -TypeName 'System.Collections.Generic.List[System.Management.Automation.PSObject]'
                $HashInfo = New-Object -TypeName 'System.Collections.Generic.List[System.Management.Automation.PSObject]'

                foreach ($MemberAttribute in $Member[1]) {
                    $MemberAttrType = $MemberAttribute[0].Id

                    switch ($MemberAttrType) {
                        '1.3.6.1.4.1.311.12.2.1' { # CAT_NAMEVALUE_OBJID
                            $AttributeName = $MemberAttribute[1][0][0]
                            # Depending on how things may be encoded,
                            # I might not be able to get away with Unicode encoding everything.
                            $AttributeValue = [Text.Encoding]::Unicode.GetString($MemberAttribute[1][0][2].GetOctets())

                            $Object = [PSCustomObject] @{
                                PSTypeName = 'CatalogTools.ParsedCatalog.NameValuePair'
                                Name = $AttributeName
                                Value = $AttributeValue
                            }

                            $NameValuePairs.Add($Object)
                        }

                        '1.3.6.1.4.1.311.12.2.2' { # CAT_MEMBERINFO_OBJID
                            $SubjectGuid = $MemberAttribute[1][0][0].ToString()
                            $CertificateVersion = $MemberAttribute[1][0][1].Value.IntValue

                            $Object = [PSCustomObject] @{
                                PSTypeName = 'CatalogTools.ParsedCatalog.MemberCertificateGuid'
                                SubjectGuid = $SubjectGuid
                                CertificateVersion = $CertificateVersion
                            }
                            
                            $MemberInfo.Add($Object)
                        }

                        '1.3.6.1.4.1.311.12.2.3' { # CAT_MEMBERINFO2_OBJID
                            # I have yet to see this populated with actual data
                            # In the mean time, I will throw a warning if it is populated.

                            <#
                            typedef struct _CAT_MEMBERINFO2
                            {
                                GUID            SubjectGuid;
                                DWORD           dwCertVersion;

                            } CAT_MEMBERINFO2, *PCAT_MEMBERINFO2;
                            #>

                            if ($MemberAttribute[1].GetObject().GetOctets()) {
                                Write-Warning "$($FullPath): CAT_MEMBERINFO2 struct populated. Inspect the data here and parse accordingly."
                            }
                        }

                        '1.3.6.1.4.1.311.2.1.4' { # Authenticode - SPC_INDIRECT_DATA_OBJID
                            $HashAlgorithm = $null
                            $HashOid = $MemberAttribute[1][0][1][0][0].Id

                            switch ($HashOid) {
                                '2.16.840.1.101.3.4.2.1' { $HashAlgorithm = 'SHA256' }
                                '1.3.14.3.2.26' { $HashAlgorithm = 'SHA1' }
                                default { Write-Warning "$($FullPath): Unimplemented algorithm OID: $HashOid" }
                            }

                            $Hash = ($MemberAttribute[1][0][1][1].GetOctets() | ForEach-Object { "{0:X2}" -f $_ }) -join ''
                            
                            $AttributeTypeValueData = $MemberAttribute[1][0][0]
                            $AttributeTypeValueDataOid = $MemberAttribute[1][0][0][0].Id

                            switch ($AttributeTypeValueDataOid) {
                                '1.3.6.1.4.1.311.2.1.15' { # SPC_PE_IMAGE_DATA_OBJID - i.e. most likely, just page hashes
                                    $ImageData = $AttributeTypeValueData[1][1].GetObject()

                                    $PageHashBytes = $null
                                    $TagGuid = $null
                                    $EnhancedHash = $null

                                    if ($ImageData.TagNo -eq 2) {
                                        $PageHashAttr = $ImageData.GetObject().GetObject()

                                        if ($PageHashAttr) {
                                            $PageHashAttrBytes = $PageHashAttr.GetOctets()

                                            if ($PageHashAttrBytes) {
                                                $ObsoletePageHashTag = [Text.Encoding]::ASCII.GetString(($PageHashAttr.GetOctets() | Where-Object { $_ }))
                                    
                                                if ($ObsoletePageHashTag -ne '<<<Obsolete>>>') {
                                                    Write-Warning "$($FullPath): Unsupported page hash type!"
                                                }
                                            }
                                        }
                                    } else {
                                        $TagGuid = [Guid] $AttributeTypeValueData[1][1].GetObject().GetObject()[0].GetOctets()

                                        $PageHashData = [Org.BouncyCastle.Asn1.Asn1Object]::FromByteArray($AttributeTypeValueData[1][1].GetObject().GetObject()[1].GetOctets())
                                        $PageHashVersionOid = $PageHashData[0][0].Id

                                        switch ($PageHashVersionOid) {
                                            '1.3.6.1.4.1.311.2.3.1' { # SPC_PE_IMAGE_PAGE_HASHES_V1_OBJID
                                                $PageHashVersion = 1
                                            }

                                            '1.3.6.1.4.1.311.2.3.2' { # SPC_PE_IMAGE_PAGE_HASHES_V2_OBJID
                                                $PageHashVersion = 2
                                            }

                                            default {
                                                $PageHashVersion = $null
                                                Write-Warning "$($FullPath): Unsupported SPC_PE_IMAGE_PAGE_HASHES type: $PageHashVersionOid"
                                            }
                                        }

                                        [Byte[]] $PageHashBytes = $PageHashData[0][1].GetOctets()
                                    }
                                }

                                '1.3.6.1.4.1.311.2.1.25' { # SPC_GLUE_RDN_OBJID or SPC_CAB_DATA_OBJID
                                    # I've only ever seen this as '<<<Obsolete>>>'
                                    $GlueObject = $AttributeTypeValueData[1].GetObject().GetObject()
                                    $GlueTag = $null

                                    # This type may be present but it will probably be null.
                                    if ($GlueObject) {
                                        $GlueObjectBytes = $GlueObject.GetOctets()

                                        if ($GlueObjectBytes) {
                                            $GlueTag = [Text.Encoding]::ASCII.GetString(($GlueObject.GetOctets() | Where-Object { $_ }))
                                    
                                            if ($GlueTag -ne '<<<Obsolete>>>') {
                                                Write-Warning "$($FullPath): Unsupported `"glue tag`" data (1.3.6.1.4.1.311.2.1.25): $GlueTag. Try parsing SPC_CAB_DATA_OBJID data."
                                            }
                                        }
                                    }
                                }

                                '1.3.6.1.4.1.311.2.1.28' { # SPC_LINK_OBJID
                                    $TagGuid = [Guid] $AttributeTypeValueData[1].GetObject()[0].GetOctets()
                                    $EnhancedHash = ($AttributeTypeValueData[1].GetObject()[1].GetOctets() | ForEach-Object { "{0:X2}" -f $_ }) -join ''
                                }

                                default {
                                    Write-Warning "$($FullPath): Unsupported SPC_INDIRECT_DATA_CONTENT type OID: $AttributeTypeValueDataOid. $FullPath"
                                }
                            }

                            $Object = [PSCustomObject] @{
                                PSTypeName = 'CatalogTools.ParsedCatalog.MemberHashInformation'
                                Algorithm = $HashAlgorithm
                                FileHash = $Hash
                                Guid = $TagGuid
                                PageHashVersion = $PageHashVersion
                                PageHashData = $PageHashBytes
                                EnhancedHash = $EnhancedHash
                            }

                            $HashInfo.Add($Object)
                        }

                        default {
                            Write-Warning "$($FullPath): Unsupported list member attribute type: $MemberAttrType"
                        }
                    }
                }

                $Object = [PSCustomObject] @{
                    Tag = $TagName
                    HashInfo = if ($HashInfo.Count) { $HashInfo } else { $null }
                    NameValuePairs = if ($NameValuePairs.Count) { $NameValuePairs } else { $null }
                }

                $CatalogMembers.Add($Object)
            }

            $ParsedCatalog = [PSCustomObject] @{
                PSTypeName = 'CatalogTools.ParsedCatalog'
                FilePath = $FullPath
                ListIdentifier = $ListIdentifier
                CatalogVersion = $CatalogVersion
                EffectiveDate = $Timestamp
                HeaderAttributes = $HeaderAttributeObjects
                CatalogMembers = $CatalogMembers
                Signer = (Get-AuthenticodeSignature -FilePath $FullPath)
            }

            $ParsedCatalog

            $ASN1InputStream.Close()
            $FileStream.Close()
        }
    }
}

Export-ModuleMember -Function 'Get-CatalogFile'