; VortexSSH Windows installer (NSIS 3, Unicode).
;
; Build on Linux with a native makensis:
;   NSISDIR=<nsis-data> makensis installer\windows\vortexssh.nsi
; or on Windows with the standard makensis.exe.
; The binaries are expected under target\x86_64-pc-windows-gnu\release (a
; Linux cross-build) or target\release (native); adjust BINDIR below.

Unicode true
Target amd64-unicode
SetCompressor /SOLID lzma

!define APPNAME "VortexSSH"
!define APPVERSION "0.1.0"
!define PUBLISHER "VortexSSH"
!define BINDIR "..\..\target\x86_64-pc-windows-gnu\release"

Name "${APPNAME} ${APPVERSION}"
OutFile "vortexssh-setup-${APPVERSION}.exe"
InstallDir "$PROGRAMFILES64\VortexSSH"
InstallDirRegKey HKCU "Software\VortexSSH" "InstallDir"
RequestExecutionLevel admin

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "StrFunc.nsh"
${Using:StrFunc} UnStrRep

!define MUI_ICON "..\..\assets\icon.ico"
!define MUI_UNICON "..\..\assets\icon.ico"

!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "VortexSSH" SecMain
  SectionIn RO
  SetOutPath "$INSTDIR"
  File "${BINDIR}\vortexssh.exe"
  File "${BINDIR}\vortexssh-tui.exe"
  File "${BINDIR}\vortexssh-gui.exe"
  File "..\..\assets\icon.ico"

  WriteRegStr HKCU "Software\VortexSSH" "InstallDir" "$INSTDIR"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  CreateDirectory "$SMPROGRAMS\VortexSSH"
  CreateShortcut "$SMPROGRAMS\VortexSSH\VortexSSH.lnk" "$INSTDIR\vortexssh-gui.exe" "" "$INSTDIR\icon.ico" 0
  CreateShortcut "$SMPROGRAMS\VortexSSH\VortexSSH (Terminal).lnk" "$INSTDIR\vortexssh-tui.exe" "" "$INSTDIR\icon.ico" 0
  CreateShortcut "$SMPROGRAMS\VortexSSH\VortexSSH (CLI).lnk" "$INSTDIR\vortexssh.exe" "" "$INSTDIR\icon.ico" 0
  CreateShortcut "$SMPROGRAMS\VortexSSH\Uninstall.lnk" "$INSTDIR\uninstall.exe"

  SetRegView 64
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VortexSSH" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VortexSSH" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VortexSSH" "DisplayVersion" "${APPVERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VortexSSH" "Publisher" "${PUBLISHER}"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VortexSSH" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VortexSSH" "NoRepair" 1
SectionEnd

Section "Add to PATH" SecPath
  ReadRegStr $0 HKCU "Environment" "Path"
  ${If} $0 == ""
    WriteRegExpandStr HKCU "Environment" "Path" "$INSTDIR"
  ${Else}
    WriteRegExpandStr HKCU "Environment" "Path" "$0;$INSTDIR"
  ${EndIf}
  System::Call 'user32::SendMessageW(p 0xFFFF, i 0x1A, p 0, w "Environment")'
SectionEnd

Section "Desktop shortcut" SecDesktop
  CreateShortcut "$DESKTOP\VortexSSH.lnk" "$INSTDIR\vortexssh-gui.exe" "" "$INSTDIR\icon.ico" 0
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "The VortexSSH executables."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPath} "Add VortexSSH to your user PATH."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Create a desktop shortcut."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  Delete "$INSTDIR\vortexssh.exe"
  Delete "$INSTDIR\vortexssh-tui.exe"
  Delete "$INSTDIR\vortexssh-gui.exe"
  Delete "$INSTDIR\icon.ico"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$SMPROGRAMS\VortexSSH\VortexSSH.lnk"
  Delete "$SMPROGRAMS\VortexSSH\VortexSSH (Terminal).lnk"
  Delete "$SMPROGRAMS\VortexSSH\VortexSSH (CLI).lnk"
  Delete "$SMPROGRAMS\VortexSSH\Uninstall.lnk"
  RMDir "$SMPROGRAMS\VortexSSH"
  Delete "$DESKTOP\VortexSSH.lnk"

  ReadRegStr $0 HKCU "Environment" "Path"
  ${If} $0 != ""
    ${UnStrRep} $0 "$0" "$INSTDIR;" ""
    ${UnStrRep} $0 "$0" ";$INSTDIR" ""
    ${UnStrRep} $0 "$0" "$INSTDIR" ""
    ${If} $0 == ""
      DeleteRegValue HKCU "Environment" "Path"
    ${Else}
      WriteRegExpandStr HKCU "Environment" "Path" "$0"
    ${EndIf}
  ${EndIf}

  SetRegView 64
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VortexSSH"
  DeleteRegKey HKCU "Software\VortexSSH"
SectionEnd
