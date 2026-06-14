!include "MUI2.nsh"

Name "GhostLink"
OutFile "GhostLink_Setup_v3.1.0.exe"
InstallDir "$PROGRAMFILES\GhostLink"
RequestExecutionLevel admin

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"
  File /r "dist\GHOSTLINK\*.*"
  
  ;   Tell NSIS to install shortcuts for ALL users
  SetShellVarContext all
  
  CreateShortCut "$DESKTOP\GhostLink.lnk" "$INSTDIR\GHOSTLINK.exe"
  CreateDirectory "$SMPROGRAMS\GhostLink"
  CreateShortCut "$SMPROGRAMS\GhostLink\GhostLink.lnk" "$INSTDIR\GHOSTLINK.exe"
  CreateShortCut "$SMPROGRAMS\GhostLink\Uninstall.lnk" "$INSTDIR\uninstall.exe"
  
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\GHOSTLINK" "DisplayName" "GhostLink v3.1.0"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\GHOSTLINK" "UninstallString" "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  Delete "$INSTDIR\*.*"
  RMDir "$INSTDIR"
  Delete "$DESKTOP\GhostLink.lnk"
  RMDir /r "$SMPROGRAMS\GhostLink"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\GHOSTLINK"
SectionEnd
