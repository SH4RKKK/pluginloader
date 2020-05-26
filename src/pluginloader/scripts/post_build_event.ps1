function Get-BaseDir {
  param(
    [Parameter(Mandatory=$true)] [string]$SubKey,
    [Parameter(Mandatory=$false)] [string]$Combine
  )

  $localMachine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32)
  try {
    $key = $localMachine.OpenSubKey($SubKey)
    try {
        return [System.IO.Path]::Combine([string]$key.GetValue('BaseDir'), $Combine)
    } catch {
    } finally {
      if ( $key -ne $null ) {
        $key.Dispose()
      }
    }
  } catch {
  } finally {
    if ( $localMachine -ne $null ) {
      $localMachine.Dispose()
    }
  }
  return $null
}

function Get-InstallLocation {
  param(
    [Parameter(Mandatory=$true)] [string]$ProductCode,
    [Parameter(Mandatory=$false)] [string]$Combine
  )

  $localMachine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32)
  try {
    $key = $localMachine.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode")
    try {
        return [System.IO.Path]::Combine([string]$key.GetValue('InstallLocation'), $Combine)
    } catch {
    } finally {
      if ( $key -ne $null ) {
        $key.Dispose()
      }
    }
  } catch {
  } finally {
    if ( $localMachine -ne $null ) {
      $localMachine.Dispose()
    }
  }
  return $null
}

if ( !$env:CI -or [System.IO.File]::Exists("$env:MSBuildProjectDir\scripts\postbuild.no") ) {
  if ( ![System.IO.File]::Exists("$env:MSBuildProjectDir\scripts\postbuild.yes") ) {
    Add-Type -AssemblyName 'System.Windows.Forms'
    switch ( [System.Windows.Forms.MessageBox]::Show(`
      "Would you like to automatically copy $env:MSBuildTargetFileName to your BNS folder(s) after compilation? You may need to copy it once manually and adjust its ACL.`nYou won't be asked about this again.",`
      "$env:MSBuildTargetPath",`
      [System.Windows.Forms.MessageBoxButtons]::YesNo,`
      [System.Windows.Forms.MessageBoxIcon]::Question) ) {
      {[System.Windows.Forms.DialogResult]::Yes} { '' > "$env:MSBuildProjectDir\scripts\postbuild.yes"; break }
      {[System.Windows.Forms.DialogResult]::No} { '' > "$env:MSBuildProjectDir\scripts\postbuild.no" }
      default { exit }
    }
  }
  $BnSBaseDir = Get-BaseDir -SubKey 'SOFTWARE\NCWest\BnS'
  if ( ![System.IO.Directory]::Exists($BnSBaseDir) ) {
    $BnSBaseDir = Get-InstallLocation -ProductCode '{9C7ADD9B-0F54-4526-87E8-E739FBB91FD4}'
  }
  $TWBNS22BaseDir = Get-BaseDir -SubKey 'SOFTWARE\NCTaiwan\TWBNS22'
  if ( ![System.IO.Directory]::Exists($TWBNS22BaseDir) ) {
    $TWBNS22BaseDir = Get-InstallLocation -ProductCode '{37EEA701-C7E3-4DC9-BCFB-39C89A6998AD}'
  }
  foreach ( $BaseDir in @($BnSBaseDir, $TWBNS22BaseDir) ) {
    if ( [System.IO.Directory]::Exists($BaseDir) ) {
      switch ( $env:MSBuildPlatformTarget ) {
        'x86' { Copy-Item "$env:MSBuildTargetPath" -Destination "$BaseDir\bin\" -Force; break }
        'x64' { Copy-Item "$env:MSBuildTargetPath" -Destination "$BaseDir\bin64\" -Force; break }
      }
    }
  }

  $BNSRBaseDir = Get-BaseDir -SubKey 'SOFTWARE\plaync\BNSR_LIVE' -Combine 'BNSR'
  if ( !$BNSRBaseDir -or ![System.IO.Directory]::Exists($BNSRBaseDir) ) {
    $BNSRBaseDir = Get-InstallLocation -ProductCode '{97789F8F-D694-46FC-B5C7-2C59EEEBE7A1}' -Combine 'BNSR'
  }
  if ( [System.IO.Directory]::Exists($BNSRBaseDir) -and $env:MSBuildPlatformTarget -eq 'x64' ) {
    Copy-Item "$env:MSBuildTargetPath" -Destination "$BNSRBaseDir\Binaries\Win64\" -Force
  }
}
