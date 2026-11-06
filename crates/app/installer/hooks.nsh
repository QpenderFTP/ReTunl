; ReTunl: extra steps for the Tauri NSIS installer (included by its installer.nsi).

!macro NSIS_HOOK_POSTINSTALL
  ; a running copy closed by the installer may have left the Windows proxy on
  ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --clear-proxy'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; the cleanup runs after the app is closed and its files are removed, so keep a copy
  ${If} $UpdateMode <> 1
    InitPluginsDir
    CopyFiles /SILENT "$INSTDIR\${MAINBINARYNAME}.exe" "$PLUGINSDIR\retunl-cleanup.exe"
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
    ; turn off our system proxy, remove autostart (Run key and the elevated task)
    ${If} ${FileExists} "$PLUGINSDIR\retunl-cleanup.exe"
      ExecWait '"$PLUGINSDIR\retunl-cleanup.exe" --cleanup'
      Delete "$PLUGINSDIR\retunl-cleanup.exe"
    ${EndIf}
    ; the "delete app data" box: servers, rules and settings, downloaded cores
    ${If} $DeleteAppDataCheckboxState = 1
      SetShellVarContext current
      RmDir /r "$APPDATA\ReTunl"
      RmDir /r "$LOCALAPPDATA\ReTunl"
    ${EndIf}
  ${EndIf}
!macroend
