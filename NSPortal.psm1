
#-----------------------------------------------------------[Functions]------------------------------------------------------------

function ConvertFrom-RijndaelString{
<#
.SYNOPSIS
    Decrypt IPMan Passwords
.DESCRIPTION
    Pass Password hash from IPMan DB to Cmdlet and will return plain text. Rijndale is the original name for AES. 
.PARAMETER EncryptedString
    Pass encrypted string from IPMan password table.  
.PARAMETER Passphrase
    Input the passphrase to decrypt
.PARAMETER Salt
    Input key Salt value
.PARAMETER Init
    Input initialization vector (IV)
.NOTES
    Version:        1.0
    Author:         disposablecat
    Purpose/Change: Initial script development
.EXAMPLE
    ConvertFrom-RijndaelString -EncryptedString 'ysytY5Y3KFqb+gayGbsUYw==' -Passphrase 'k388JJ3j@kK*kdk33K' -Salt 'g@(sk~' -Init '$%JEM&*&OP^LLVQ$'
    Return decrypted string
#>
    [CmdletBinding()]
    [OutputType([string])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $EncryptedString,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $Passphrase,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $Salt,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $Init
    )

    Process
    {
        Try
        {
            [Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null;
            #Convert it to Base64
	        if($EncryptedString -is [string]){
		        $EncryptedString = [Convert]::FromBase64String($EncryptedString)
   	        }

            #Creating COM object for RijndaelManaged.
	        $RijndaelManaged = new-Object System.Security.Cryptography.RijndaelManaged
            #Set RijndaelManaged mode to 1.
            $RijndaelManaged.Mode = 1
	        #Convert the Salt to ASCII Bytes
	        $Salt = [Text.Encoding]::ASCII.GetBytes($Salt)
	        #Create the Encryption Key using the passphrase, Salt and SHA1 algorithm at 256 bits (256/8)
	        $RijndaelManaged.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $Passphrase, $Salt, "SHA1", 3).GetBytes(32)
	        #Encoding provided Init and setting Intersecting Vector
            $RijndaelManaged.IV = [Text.Encoding]::ASCII.GetBytes($Init)[0..15]
	        #Create a new Decryptor
	        $Decryptor = $RijndaelManaged.CreateDecryptor()
	        #Create a New memory stream with the encrypted value.
	        $MemoryStream = new-Object IO.MemoryStream @(,$EncryptedString)
	        #Read the new memory stream and read it in the cryptology stream
	        $CryptoStream = new-Object Security.Cryptography.CryptoStream $MemoryStream,$Decryptor,"Read"
	        #Creating streamreader using cryptostream.
	        $StreamReader = new-Object IO.StreamReader $CryptoStream
            #Setting Return variable by reading streamreader.
            $Return = $StreamReader.ReadToEnd()
            return $Return
            #Close StreamReader
	        $StreamReader.Close()
	        #Close CryptoStream
	        $CryptoStream.Close()
	        #Close MemoryStream
	        $MemoryStream.Close()
	        #Clear RijndaelManaged Cryptology IV and Key
	        $RijndaelManaged.Clear()
        }
        Catch
        {
            #Catch any error.
            Write-Verbose “Exception Caught: $($_.Exception.Message)”
        }

    }
}

function Export-DecryptedPwdCsv{
<#
.SYNOPSIS
    Input IPMan Pwd Csv and export decrypted Csv
.DESCRIPTION
    Input IPMan Pwd Csv and export decrypted Csv. For migrating off of old IPMan tool. 
.PARAMETER InputPath
    Input CSV path
.PARAMETER OutputPath
    Output Csv path
.PARAMETER Passphrase
    Input the passphrase to decrypt
.PARAMETER Salt
    Input key Salt value
.PARAMETER Init
    Input initialization vector (IV)   
.NOTES
    Version:        1.0
    Author:         disposablecat
    Purpose/Change: Initial script development
.EXAMPLE
    Export-DecryptedPwdCsv -InputPath ".\InputCsv.csv" -Outputpath ".\OutputCsv.csv"
    Take input IPMan password table export, decrypts all encrypted strings and outputs a csv in plaintext. 
#>
    [CmdletBinding()]
    [OutputType([string])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern('.csv$')]
        [string]$InputPath,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern('.csv$')]
        [string]$OutputPath,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $Passphrase,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $Salt,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $Init
    )

    Begin
    {

        $Nodes = New-Object System.Collections.Generic.List[System.Object]
        #Base object for changes
        $ChangeObjectBase = New-Object PSObject; 
        $ChangeObjectBase | Add-Member -type Noteproperty -Name ID -Value $Null
        $ChangeObjectBase | Add-Member -type Noteproperty -Name Name -Value $Null
        $ChangeObjectBase | Add-Member -type Noteproperty -Name TelnetReadOnly -Value $Null
        $ChangeObjectBase | Add-Member -type Noteproperty -Name TelnetEnable -Value $Null
        $ChangeObjectBase | Add-Member -type Noteproperty -Name SNMPReadOnly -Value $Null
        $ChangeObjectBase | Add-Member -type Noteproperty -Name SNMPWrite -Value $Null
        $ChangeObjectBase | Add-Member -type Noteproperty -Name SNMP_RW_RO -Value $Null
        $ChangeObjectBase | Add-Member -type Noteproperty -Name IPAddress -Value $Null
        
    }
    Process
    {
        Try
        {
            Write-Verbose "$(Get-Date -Format "yyyy-MM-dd:HH:mm:ss:ff") - Verifying if File can be read."
            if(Test-Path -Path $InputPath)
            {
                Write-Verbose "$(Get-Date -Format "yyyy-MM-dd:HH:mm:ss:ff") - $($InputPath) exists."
            }
            else
            {
                throw "Cannot read $($InputPath)."
            }
            Write-Verbose "$(Get-Date -Format "yyyy-MM-dd:HH:mm:ss:ff") - $($InputPath) imported."
            $InCsvOb = Import-Csv $InputPath
            Write-Verbose "$(Get-Date -Format "yyyy-MM-dd:HH:mm:ss:ff") - Iterating through imported csv object and creating new list of objects."
            ForEach ($Ob in $InCsvOb)
            {
                $ChangeObject = $ChangeObjectBase | Select *
                $ChangeObject.ID = $Ob.EQ_ID
                $ChangeObject.Name = $Ob.EQ_Name
                $ChangeObject.TelnetReadOnly = ConvertFrom-RijndaelString -EncryptedString $Ob.ps_TelnetReadOnly -Passphrase $Passphrase -Salt $Salt -Init $Init
                $ChangeObject.TelnetEnable = ConvertFrom-RijndaelString -EncryptedString $Ob.ps_TelnetEnable -Passphrase $Passphrase -Salt $Salt -Init $Init
                $ChangeObject.SNMPReadOnly = ConvertFrom-RijndaelString -EncryptedString $Ob.ps_SNMPReadOnly -Passphrase $Passphrase -Salt $Salt -Init $Init
                $ChangeObject.SNMPWrite = ConvertFrom-RijndaelString -EncryptedString $Ob.ps_SNMPWrite -Passphrase $Passphrase -Salt $Salt -Init $Init
                $ChangeObject.SNMP_RW_RO = ConvertFrom-RijndaelString -EncryptedString $Ob.ps_SNMP_RW_RO -Passphrase $Passphrase -Salt $Salt -Init $Init
                $ChangeObject.IPAddress = $Ob.inIPAddress
                $Nodes.Add($ChangeObject)
            }
            Write-Verbose "$(Get-Date -Format "yyyy-MM-dd:HH:mm:ss:ff") - Iteration done."
            Write-Verbose "$(Get-Date -Format "yyyy-MM-dd:HH:mm:ss:ff") - Exporting list of objects to csv."
            $Nodes | Select * | Export-Csv -Path $OutputPath -NoTypeInformation
            Write-Verbose "$(Get-Date -Format "yyyy-MM-dd:HH:mm:ss:ff") - $($OutputPath) created."

        }
        Catch
        {
            #Catch any error.
            Write-Verbose “Exception Caught: $($_.Exception.Message)”
        }
    }
}
