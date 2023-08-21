Run the `.bat` to send the copied URL to the server. If an URL is provided as an argument, the provided URL will be sent instead.

If you want to pin the `.bat` to the Taskbar, create a shortcut for `C:\Windows\System32\cmd.exe /c "C:\path\to\mpv-url-opener.bat"`, as a plain `.bat` shortcut file can't be pinned to the Taskbar.

Sadly, unlike on Linux / KDE Plasma, drag'n'dropping a URL from a browser onto the shortcut pinned on the Taskbar doesn't work on Windows, the URL is not being passed as the first argument to the script and, in fact, the script does not even get run.

The purpose of the `.bat` file is to bypass the PowerShell security error preventing the `.ps1` file from being run directly:

```powershell
PS C:\Users\nurupo\AppData\Local\_programs\mpv-url-opener> .\mpv-url-opener.ps1
.\mpv-url-opener.ps1 : File
C:\Users\nurupo\AppData\Local\_programs\mpv-url-opener\mpv-url-opener.ps1 cannot be loaded because
running scripts is disabled on this system. For more information, see about_Execution_Policies at
https:/go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:1
+ .\mpv-url-opener.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) [], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess
```
