@echo off

 REM File: uninstall.bat
 REM Author: Jeff Odegard
 REM Purpose: Windows / XAMPP Uninstallation Script
 REM Created: Oct 3, 2018

 REM Copyright 2018: Cyber Perspective, All rights reserved
 REM Released under the Apache v2.0 License

 REM See license.txt for details
 
 REM Change Log:
 REM - Oct 3, 2018 - File created
 
echo.
echo This will completely uninstall Sagacity and XAMPP and delete 
echo the findings database and all result files in www/tmp.  
echo.
echo This cannot be undone.
echo.
set /p uninstall="Are you sure? (y/N) "

set result=0
if "%uninstall%"=="Y" (set result=1)
if "%uninstall%"=="y" (set result=1)
if "%uninstall%"=="Yes" (set result=1)
if "%uninstall%"=="yes" (set result=1)
if "%uninstall%"=="YES" (set result=1)

if "%result%"=="1" (
	cd C:\
	echo - Stopping Apache and MySQL services.
	sc stop Apache2.4
	sc stop mysql
	echo - Deleting the MySQL service.
	sc delete mysql
	echo - Deleting the Sagacity www folder.
	del /F /S /Q C:\xampp\www 1>nul
	rmdir /S /Q C:\xampp\www
	echo - Uninstalling XAMPP
	C:\xampp\uninstall.exe --mode unattended
)

echo.
echo Thank you for trying Sagacity.  If you have any questions or comments, please contact us at https://www.cyberperspectives.com/contact_us
echo.

if "%result%"=="1" (
	set /p foo="Uninstall complete.  Press enter to continue."
) else (
	set /p foo="Whew, that was a close one! Uninstall aborted.  Press enter to continue."
)

