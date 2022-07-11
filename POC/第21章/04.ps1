$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="samAccountType=805306368"
## $Searcher.filter="name=Jeff_Admin"        ## 指定要查询的用户名
## $Searcher.filter="name=Domain admins"     ## 管理员组**
$Result = $Searcher.FindAll()
**Foreach($obj in $Result)
{
  Foreach($prop in $obj.Properties)
  {
    $prop
    ## $prop.member                           # 组成员
    ## $prop.memberof                         # 所属组
  }
  Write-Host "------------------------"
}
