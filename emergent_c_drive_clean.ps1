# 清除使用者與系統 Temp 資料夾
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

# 觸發 Windows 內建的深層儲存清掃
cleanmgr /sagerun:1

#

Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { -not $_.PSIsContainer -and $_.Length -gt 1GB } | 
    Sort-Object Length -Descending | 
    Select-Object @{Name="Size(GB)";Expression={[math]::round($_.Length/1GB,2)}}, FullName -First 20 | 
    Format-Table -AutoSize

#
powercfg -h off

#

# 1. 清理舊版 Windows Update 備份檔 (WinSxS Component Store)
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase

# 2. 清理資源回收桶
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

# 3. 清理 Windows Update 下載暫存包
Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
Start-Service -Name wuauserv

##
# 建立腳本存放目錄
New-Item -ItemType Directory -Path "C:\Scripts" -Force | Out-Null

# 寫入邏輯：剩餘空間小於 30GB 才執行清理
@'
$drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
$freeGB = [math]::round($drive.FreeSpace / 1GB, 2)

if ($freeGB -lt 30) {
    Write-Output "$(Get-Date): C 碟剩餘 $freeGB GB，低於 30GB 門檻，開始自動清理..."
    
    # 清理使用者與系統 Temp
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    
    # 清空資源回收桶
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue

    # 清理 Windows Update 暫存
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv
}
'@ | Set-Content -Path "C:\Scripts\AutoCleanC.ps1" -Encoding UTF8

##

$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Scripts\AutoCleanC.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 9:00AM
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "AutoCleanC_Drive" -Action $action -Trigger $trigger -Principal $principal -Force