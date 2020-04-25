[System.String]$thePath ="D:\TEST"


Write-Host "---- START ----" (Get-Date).ToString() 
Write-Host " Подгрузка бибилиотеки MakeGroupsAndRights.ps1"
. .\MakeGroupsAndRights.ps1
#Import-Module -Name MakeGroupsAndRights.ps1


MoveRights -thePath $thePath

$dirs = Get-ChildItem -Path $thePath -Attributes Directory -Depth 0
ForEach ($dir in $dirs)
        {
           #MoveRights -thePath $dir.FullName
           $dir.FullName
        }

Write-Host "------END----------" (Get-Date).ToString() 
