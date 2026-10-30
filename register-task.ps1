<#
  注册"证书到期前 15 天自动续期并部署到阿里云 ALB"的 Windows 计划任务。

  两条通道，任一成功即可：
    1. Register-ScheduledTask（CIM）—— 首选
    2. schtasks /Create /XML（RPC）—— CIM 报 0x80004005 时的后备

  用法（双击 register-task.bat）：
      默认     每天 03:30 运行，只处理 *.hnjs888.com
      管理员   右键以管理员身份运行，参数加 /system，注销后也能执行

  参数：
      -At           每天触发时间，默认 03:30
      -Domain       要托管的证书域名（CN），默认 *.hnjs888.com
      -RunAsSystem  以 SYSTEM 账户运行（需管理员权限）
#>
param(
    [string]$TaskName = "LetsEncrypt-Renew",
    [string]$At = "03:30",
    [string]$Domain = "*.hnjs888.com",
    [switch]$RunAsSystem
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$bat = Join-Path $root "renew.bat"

if (-not (Test-Path $bat)) {
    throw "找不到 renew.bat：$bat"
}

$argLine = '/c "' + $bat + '" --domain "' + $Domain + '"'
$desc = "Let's Encrypt 自动续期：剩余 <=15 天时签发新证书并部署到阿里云 ALB。日志 data\logs\renew-YYYYMMDD.log"

$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($elevated) { Write-Host ("当前身份：" + $me + "（管理员）") } else { Write-Host ("当前身份：" + $me + "（普通用户）") }
Write-Host ""

$done = $false
$channel = ""

# ---------------------------------------------------------------- 通道一：CIM
try {
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $argLine -WorkingDirectory $root
    $trigger = New-ScheduledTaskTrigger -Daily -At $At
    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Hours 1)

    if ($RunAsSystem) {
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Settings $settings -Principal $principal -Description $desc -Force | Out-Null
    }
    else {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Settings $settings -Description $desc -Force | Out-Null
    }
    $done = $true
    $channel = "Register-ScheduledTask（CIM）"
}
catch {
    Write-Host ("CIM 通道失败：" + $_.Exception.Message) -ForegroundColor DarkYellow
    Write-Host "改用 schtasks /XML 重新尝试..." -ForegroundColor DarkYellow
    Write-Host ""
}

# ------------------------------------------------------------ 通道二：XML 文件
if (-not $done) {
    $start = (Get-Date).Date.Add(([datetime]$At).TimeOfDay)

    if ($RunAsSystem) {
        $principalXml = '<UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel>'
    }
    else {
        $principalXml = '<UserId>' + $me + '</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel>'
    }

    $escArgs = $argLine.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
    $escRoot = $root.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
    $escDesc = $desc.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")

    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>$escDesc</Description>
    <URI>\$TaskName</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>$($start.ToString("yyyy-MM-ddTHH:mm:ss"))</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      $principalXml
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>$escArgs</Arguments>
      <WorkingDirectory>$escRoot</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

    $xmlPath = Join-Path $env:TEMP ($TaskName + ".xml")
    $xml | Out-File -FilePath $xmlPath -Encoding Unicode -Force

    $exe = Join-Path $env:SystemRoot "System32\schtasks.exe"
    & $exe /Create /TN $TaskName /XML $xmlPath /F
    if ($LASTEXITCODE -eq 0) {
        $done = $true
        $channel = "schtasks /XML（RPC）"
    }
    else {
        Write-Host ""
        Write-Host ("XML 通道也失败了（退出码 " + $LASTEXITCODE + "）。") -ForegroundColor Red
        Write-Host ("XML 已保留在：" + $xmlPath) -ForegroundColor DarkGray
    }
}

# -------------------------------------------------------------------- 结果
if (-not $done) {
    Write-Host ""
    Write-Host "注册失败。两条通道都没成功，通常是账户权限或组策略限制。" -ForegroundColor Red
    Write-Host "请右键 register-task.bat，选择“以管理员身份运行”再试一次。" -ForegroundColor Yellow
    exit 1
}

$info = Get-ScheduledTask -TaskName $TaskName
$next = (Get-ScheduledTaskInfo -TaskName $TaskName).NextRunTime

Write-Host ""
Write-Host "已注册计划任务" -ForegroundColor Green
Write-Host ("  通道     " + $channel)
Write-Host ("  名称     " + $TaskName)
Write-Host ("  身份     " + $info.Principal.UserId)
Write-Host ("  触发     每天 " + $At)
Write-Host ("  下次运行 " + $next)
Write-Host ("  状态     " + $info.State)
Write-Host ""
Write-Host ("实际执行 cmd.exe " + $argLine)
Write-Host ""
Write-Host "立即试跑一次并看结果："
Write-Host ("  Start-ScheduledTask -TaskName " + $TaskName)
Write-Host ("  Get-Content `"$root\data\logs\renew-" + (Get-Date -Format yyyyMMdd) + ".log`" -Tail 20")
Write-Host ""
Write-Host ("删除任务：Unregister-ScheduledTask -TaskName " + $TaskName + " -Confirm:`$false") -ForegroundColor DarkGray
