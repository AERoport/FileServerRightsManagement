#$ErrorActionPreference='Stop'

function formACL($theSID, $fileSystemRights)
    {
    #Write-Host "-function formACL(theSID=$theSID, fileSystemRights=$fileSystemRights)"
     # Чтение
    $accessControlType = [System.Security.AccessControl.AccessControlType]"Allow" # 'Deny'
    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit" # "None' 'ContainerInherit,ObjectInherit'
    $propagationFlags = [System.Security.AccessControl.PropagationFlags]"None" #'None' 'NoPropagateInherit,InheritOnly'
     

    $rule =$null
    
    try {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($theSID, $fileSystemRights, $inheritanceFlags, $propagationFlags, $accessControlType) -ErrorAction Stop
        }
    catch 
        {
        Write-Host " ERRROR"-BackgroundColor DarkRed
        throw $_
        }
    #$rule | Out-Host
    return $rule
 }

function shortFSRights($theString){
return $theString.ToString().Replace(' ', '').Replace('WriteExtendedAttributes','WrExAtr').Replace('WriteAttributes', 'WrAtr').Replace('ReadAndExecute', 'R&E').Replace('Synchronize','Sync')
}


function formGroupName([System.String] $p, [System.Security.AccessControl.FileSystemAccessRule] $rule)
{
    #Write-Host "-function formGroupName([System.String] p=$p, rule=$rule)"
    $FileSystemRights = $rule.FileSystemRights.ToString().Replace(' ', '')
    $inheritanceFlags = $rule.inheritanceFlags.ToString().Replace(' ', '')
    $propagationFlags = $rule.PropagationFlags.ToString().Replace(' ', '')

    $p = $p.Replace(':', '').Replace('\', '^').Replace(',', '_')
    $FileSystemRights = $FileSystemRights.Replace(',', '^')
    $inheritanceFlags = $inheritanceFlags.Replace(',', '^').Replace('ContainerInherit','CI').Replace('ObjectInherit','OI')
    $propagationFlags = $propagationFlags.Replace(',', '^').Replace('NoPropagateInherit','NPI').Replace('InheritOnly','IO')
    $p = '#{' + $p  + '}{' + $FileSystemRights +'}{'+$inheritanceFlags+'}{'+$propagationFlags+'}'
    return $p
}

function formGroupDescription( [System.String] $thePath, $aa)
{
    #Write-Host "-function formGroupDescription( [System.String] thePath=$thePath, aa=$aa)"
    $MAX_DESCRIPTION_LENGTH = 48
    $rightsName = shortFSRights -theString $aa
    $maxPathLength = $MAX_DESCRIPTION_LENGTH-10
    if ($thePath.Length -gt $maxPathLength)
        { $thePath=$thePath.Substring(0,$maxPathLength)}
    $res =  "ФР "+$thePath+" Д-"+$rightsName
    if ($res.Length -gt $MAX_DESCRIPTION_LENGTH)
        {$res = $res.Substring(0,$MAX_DESCRIPTION_LENGTH)}
    return $res
}

function createLocalGroup([System.String] $p, $rule)
{
    
    #Write-Host "-function createLocalGroup([System.String] p=$p, AccType=$AccType)"
    $groupName = formGroupName -p $p -rule $rule

    $groupDescription = formGroupDescription -thePath $p -aa $rule.FileSystemRights
    Write-Host "Creating group: $groupName | groupDescription = $groupDescription"
    #Write-Host $groupDescription.Length
    $group=$null
    try 
    {
        $group = New-LocalGroup -Name $groupName -Description $groupDescription -ErrorAction Stop
    }
    catch [Microsoft.PowerShell.Commands.GroupExistsException]
    {
        Write-Host "!! Warning !! Group Already Exists: $groupName" -ForegroundColor Yellow
        $group = Get-LocalGroup -Name $groupName -ErrorAction Stop
        #Write-Host '..finded group ='$group
    }

    catch 
    {
        Write-Host "ERROR : $group" -ForegroundColor Red -BackgroundColor DarkGreen
        throw $_
    }
    #Write-Host "group=$group"
    return $group
}

function getACL($thePath)
{
    #Write-Host "-function getACL( thePath=$thePath)" 
    try 
    { 
        $acl = Get-Acl -Path $thePath -ErrorAction Stop
    }
    catch [System.Management.Automation.ItemNotFoundException]
    {
        Write-Host $_.Exception -BackgroundColor DarkYellow | fl
        throw $PSItem
    }
    catch
    {
        Write-Host "!!!!!"  -BackgroundColor DarkYellow
        #Write-Host $_.Exception
        throw $_
    }
    return $acl
}


function grantAccessForPath($thePath, $rule)
{
    #Write-Host "-function grantAccessForPath(thePath=$thePath, rule=$rule)"
    $acl = getACL -thePath $thePath
    
    try
        {
        $acl.AddAccessRule($rule)
        Set-Acl -Path $thePath -AclObject $acl -ErrorAction Stop
        }
    catch
        { 
        Write-Host "!!ERROR!!"  -BackgroundColor DarkYellow
        throw $_
        }
    Write-Host "Adding $rule to $thePath SUCCESS "
}

function formGroup($thePath, $rule)
    {
    #Write-Host "-function formGroup(thePath=$thePath, rule=$rule)"
    $group = createLocalGroup -p $thePath -rule $rule

    $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule($group.SID, $rule.FileSystemRights, $rule.inheritanceFlags, $rule.PropagationFlags, $rule.AccessControlType) -ErrorAction Stop
    #$newRule | Out-Host
    grantAccessForPath -thePath $thePath -rule $NewRule
    return $group
    }


function getNTAccountFromSID($UserSID) {
    $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserSID)
    $objName = $objSID.Translate( [System.Security.Principal.NTAccount])
    return $objName.Value
}



#Check $theGroup is Local Group or not
function isLocalGroup($theGroup)
{
    try
        {$temp = Get-LocalGroup($theGroup) -ErrorAction Stop }
    catch
        {return $false}
    return $true
}

#Copy members from one local group to another
function copyMembers($groupFrom, $groupTo)
{
    #Write-Host "function copyMembers(groupFrom=$groupFrom, groupTo=$groupTo)"
    $members = Get-LocalGroupMember -Group $groupFrom 
    Write-Host "----copyMembers($groupFrom, $groupTo) ------ " -ForegroundColor Green
    ForEach($member in $members)
    {
        Write-Host "Adding $member into $groupTo"
        try
        {
            Add-LocalGroupMember -Group $groupTo -Member $member -ErrorAction Stop
        }
        catch [Microsoft.PowerShell.Commands.MemberExistsException]
        {
            Write-Host "$member is already member of $groupTo" -ForegroundColor Yellow
            #throw $_
        }
        catch
        {
            Write-Host $_    -ForegroundColor Yellow
            #throw $_
        }
    } #foreach 
    Write-Host "----- CM ------ " -ForegroundColor Green
}

function MoveRights($thePath)
    {
    #------------------------------
    Write-Host "### thePath=$thePath" -ForegroundColor Magenta
    $acl = getACL -thePath $thePath
    $oldSDDL = $acl.Sddl.Clone()

    # Getting not-inherited Rights
    # 3-d argument is [System.Security.Principal.SecurityIdentifier]   or [System.Security.Principal.NTAccount]
    $AccessRules= $acl.GetAccessRules($true, $false,[System.Security.Principal.SecurityIdentifier])  

    Write-Host "----BEGIN FOREACH ------ " -ForegroundColor Green
    ForEach ($ar in $AccessRules)
        {
        $theObjName = getNTAccountFromSID($ar.IdentityReference)
        Write-Host ''
        Write-Host "-- $theObjName -- " -ForegroundColor Blue
        $ar | Out-Host 
    
        #$group1 = formGroup -thePath $thePath -rule $ar
        $group1 = createLocalGroup -p $thePath -rule $ar
        $theGroupName = getNTAccountFromSID($group1.SID) 
        if ($theGroupName.Equals($theObjName)) 
            {
            Write-Host "!!! Warning !!! Adding into itself impossible" -ForegroundColor Yellow
            }
        else 
            {
            try
                {
                $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule($group1.SID, $ar.FileSystemRights, $ar.inheritanceFlags, $ar.PropagationFlags, $ar.AccessControlType) -ErrorAction Stop           
                $acl.AddAccessRule($newRule)
                if (isLocalGroup -theGroup $ar.IdentityReference)
                    {
                    Write-Host "$theObjName is localGroup"
                    $groupFrom = Get-LocalGroup -SID $ar.IdentityReference
                    copyMembers -groupFrom $groupFrom -groupTo $group1
                    }
                else 
                    {
                    Write-Host "Adding $theObjName into $theGroupName"
                    Add-LocalGroupMember -Group $group1 -Member $theObjName -ErrorAction Stop
                    }
                Write-Host "Purging .. $theObjName"
                $acl.PurgeAccessRules($ar.IdentityReference)
                }
            catch [Microsoft.PowerShell.Commands.MemberExistsException]
                {
                Write-Host "$theObjName Already Member of $theGroupName" -ForegroundColor Yellow
                #throw $_
                }
            catch
                {
                Write-Host $_    -ForegroundColor Yellow
                #throw $_
                }
            } #else
     
      
        Write-Host "------------- " -ForegroundColor Blue
        #break
        } #foreach 
    Write-Host "-----FE------ " -ForegroundColor Green

    if ($oldSDDL.Equals($acl.Sddl))
        {
        Write-Host "SDDL not changed, so ACL will not saved"  -ForegroundColor Cyan
        }
    else 
        {
        Write-Host "Saving ACL..  please wait. Start at" (Get-Date).ToString() 
        Set-Acl -Path $thePath -AclObject $acl -ErrorAction Stop
        Write-Host "Done" (Get-Date).ToString()
        }

    
}

