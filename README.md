![Logo][logo]

Thank you for looking into Sagacity, a standalone web application designed to ingest, manage, and report on vulnerability assessment and STIG compliance data.  If you find it useful, please consider helping us make it better.

For usage instructions, please read the [user guide][guide] located on your Sagacity host

We are constantly trying to improve Sagacity. Please email any bugs or feature ideas to [developers@cyberperspectives.com](developers@cyberperspectives.com) subject Sagacity Bug, or you can enter an issue on the [GitHub project](https://github.com/cyberperspectives/sagacity/issues)

## Table of Contents

### [System Requirements](#system-requirements)
- Windows
- Linux

### [Software Requirements](#software-requirements)

### [Service Configuration](#service-configuration)

### [Windows Installation](#windows-installation)
- [XAMPP Installation](#xampp-installation)
- [XAMPP Configuration](#xampp-configuration)
- [Setup Repository](#setup-windows-repository)
- [Install Sagacity](#install-windows-sagacity)

### [Linux Installation](#linux-installation)
- [Setup Repository](#setup-linux-repository)
- [Install Sagacity](#install-linux-sagacity)

### [Database Initialization](#database-initialization) (Windows and Linux)

### [Complete](#complete)

### [Troubleshooting](#troubleshooting)
- Windows
    - XAMPP Apache Won't Start
- Linux

### System Requirements

Sagacity requires a relatively beefy system to do all the things that are necessary.  Sagacity operates very well on Linux distributions.  These are our recommendations.

#### Windows

- Processor: 2.0 Ghz+ (recommend Intel i5+ / Ryzen 1500)
- Memory: 8 GB
- Hard Drive: 50 GB free (SSD recommended)

#### Linux

- Processor: 2.0 Ghz+ (recommend Intel i5+ / Ryzen 1500)
- Memory: 4 GB
- Hard Drive: 50 GB free (SSD recommended)

### Software Requirements

Sagacity has the following software requirements. The versions listed are the minimum required for operation. For PHP, we recommend the closest version you can get to the one listed, further versions may deprecate features before we have the chance to update the code.

- PHP 7.2+
- MySQL 5.7+ or MariaDB 10+
- Apache 2.4+

Sagacity accomplishes a lot of data intensive tasks as such we recommend 1GB of memory for PHP (set in php.ini by the memory_limit directive). Other required settings are checked later in the install process. Any errors will need to be corrected before you can proceed.

### Service Configuration

We have included hardened configuration files for Apache, MySQL/MariaDB, and PHP in the /conf directory. On Windows, these files get copied to the XAMPP directories automatically. Existing files are renamed to .old. On Linux, no changes are made because of the distributed nature of Linux distributions' configs. Some use several files for Apache and PHP (e.g. 1 for CLI and 1 for Apache). This makes it difficult and potentially confusing to copy the configs, thus they are not.

### Windows Installation

The following software will need to be downloaded from the vendors (links provided).  The versions listed indicated the test version of the software, but these versions do not necessarily need to be used,  just so long as there are no compatibility or accrediation issues.  To perform most of these steps you will need administrative access to the client you are working on.  During the installation, if you are prompted to allow firewall access, then you will need to allow for "Domain/Private networks".

- XAMPP v7.2.4
    - http://www.apachefriends.org/en/index.html
    - Apache v2.4.33
    - MariaDB v10.1.31
    - PHP v7.2.4
- MySQL Workbench v6.3.10 (highly recommended)
    - http://dev.mysql.com/downloads/tools/workbench/
    - Requires .NET Framework 4.5 and MSVC++ 2015 Redistributable.  The links are on the page under prerequisites.  Note: These may already be installed in Windows 10.
- TortoiseGIT v2.6.0
    - https://tortoisegit.org/
- If you want to use the OpenVAS plugin database, you will need a way to extract the nasl_plugins package. We recommend either [7zip](https://www.7-zip.org/) or [Cygwin](https://www.cygwin.com/) for this, or extracting the files on a separate Unix system before loading them into the database.

#### XAMPP Installation

- Select "OK" on the UAC dialog
- When installing XAMPP, ensure that ONLY Apache, MySQL/MariaDB, and PHP are selected.  All other options are unncessary.
- Accept the default installation directory (C:\xampp)
- Uncheck "Learn more about BitNami for XAMPP"
- Click next two more times to complete the installation
- You may be prompted that the Windows Firewall has blocked the process.  Allow the communication for each of them on private networks.
- We recommend that you add the PHP (C:\xampp\php) and MySQL (C:\xampp\mysql\bin) paths to your ENV PATH variable to simplify commands you will need to run.  Right-click on "Computer", select "Properties", "Advanced System Settings", "Environment Variables".  Be sure to change the path for all users.

#### XAMPP Configuration

- To test the installation, open a browser and browse to http://localhost this will show the XAMPP management page.  Apache is working.
- If Apache does not start, see the [Troubleshooting] section at the end of this document to see common known issues.
- Open the XAMPP Control Center and stop the Apache and MySQL/MariaDB services
- Close the XAMPP Control Center
- Right-click on the XAMPP tray icon and click "Quit"
- Open a Windows Explorer window
- Browse to "C:\xampp" and create a directory called "www"

#### Setup Windows Repository

- Install TortoiseGit, and accept the default options

#### Install Windows Sagacity

- Browse to "C:\xampp\www"
- If installing on Windows 10, right-click on the www folder, select "Properties" and make sure that the folder is not set to Read Only.  If it is:
    - Uncheck the "Read Only" box and click "Apply"
    - Make sure that the "Apply changes to this folder, subfolder and files" box is selected
    - Click OK
- Right-click on "install.bat" and select "Run as Administrator"
- Enter admin credentials, if prompted
- This script will copy hardened config files for Apache, MySQL/MariaDB, and PHP to the appropriate directories (after renaming existing files to .old) and create the system services for Apache and MySQL/MariaDB
- Upon script completion, it will ask you if you want to continue the setup process by opening your default browser to the setup page.

** NOTE: Sagacity is designed to operate with the Apache and MySQL/MariaDB services listening on localhost (127.0.0.1) ONLY.  If you change the configuration to listen on the network, your vulunerability information will be available to anyone on the network! **

** NOTE: If you choose not to install the services, you will have to open the XAMPP Control Center to start your services from there after each time you reboot **

- Open the XAMPP Control Center and verify the Apache and MySQL/MariaDB services are running (if you installed the system services).  If they are not running, then start them.
- Visit [http://localhost].  This will take you to a wizard for setting up your Sagacity installation.  The page will first verify that you have everything installed and enabled before it allows you to continue the setup process.  Just follow any requirements it sets up before continuing.
    - Database
        - Enter the information listed on the page and select if you want to preload CPE, CVE, and STIG data (add'l settings are available by clicking on "Adv Web Settings").  Once you click "Next", Sagacity will get the install process running.  It will download the necessary files and get them loaded to the database.  You can do these separately if you like by following Appendix B.1 in the [User Guide]
    - Company: Enter information here that will get updated in the eChecklist files upon exporting
    - Options: These are personal options for how Sagacity will operate
- Delete the C:\xampp\htdocs folder.  It contains default XAMPP web sites and applicaation that may or may not be secure.

Congratulations!  You can now proceed to the [Database Initialization](#database-initialization), below to finish installing Sagacity

### Linux Installation

Sagacity has been tested on Ubuntu 14.04 LTS and CentOS 7.4, but should be able to run on most major Linux distributions, including RedHat/CentOS, SuSE, and Debian.  These instructions are based on CentOS 7.4, so your specifics might vary a little.

** Because Sagacity creates, copies, moves, and reads files, you may run into issues if SELinux is enabled and enforcing.  We recommend either putting it into "permissive" mode or excluding the web root from it's enforcement. **

Install the packages listed below from the distribution repository or one you trust. _To perform most of these steps, you will need root access to the client you are working on_

- PHP 7.2
    - MySQLi
    - OpenSSL
    - ZipArchive
- Apache 2+
- MySQL Server 5.7+
- Git

** NOTE:  As stated in the intro section, there are hardened configuration files available in the "conf" directory.  If you wish to use them you will have to update them for use on your specific Linux distribution because they were made for a XAMPP Windows install **

#### Setup Linux Repository

To download the code base you can either "checkout" the code base to your local install, then copy it to your server, or "checkout" the code base directly to the document root of the web server (e.g. /var/www/html).

If you choose the former, 

### Install Linux Sagacity

The first step is to open a terminal window, change directory to the document root path (/var/www/html).  You must make sure that the document root, subdirectories, and files are readable and the directories are writable by the web user.

Since the hardened configurations are not copied on Linux you will need to update the system php.ini file to include the following (this is also displayed on the next step):

- request_order is set to "GPCS" or "GPC"
- include_path includes path to the web root, classes, and inc folders
    - ./:/var/www/html:/var/www/html/classes:/var/www/html/inc
- memory_limit 1G
- upload\_max\_filesize & post\_max\_size should match and be a little bigger than the largest file you expect to have to upload (100M is a good starting point)

Visit htt://localhost/.  This will take you to a setup wizard that will verify that all required modules and settings are as needed, then it takes you through a multi-step process to finish the setup.

- Database
    - Enter the information listed on the page and select if you want to preload CPE, CVE, and STIG data (add'l setting sare available by click"Adv Web Settings").  Once you click "Next", Sagacity will get the install process running.  It will download the necessary files and get them loaded to the database.  You can do these separately if you like by following Appendix B.1 in the [User Guide]
- Company: Enter information here that will get updated in the eChecklist files upon exporting
- Options: These are personal options for how Sagacity will operate

** NOTE: As you step through the process, the script will be updating the Sagacity configuration file, populating the database with schemas, tables, routines, and baseline data.  You should see occasion popup's telling you where it is in the process.  If you do not see anything take a look at the log files **

Congratulations! You can now proceed to the [Database Initialization](#database-initialization), below to finish installing Sagacity.

### Database Initialization

If you checked the checkboxes on the Database page of the setup process, you just need to wait until that completes (approx 20-60 mins) before you can begin using Sagacity as it has to load all reference content.  You can script updating the reference material as often as you like using your preferred scripting engine and cron tool.  Just follow the steps in the [User Guide]

** NOTE: The standard file naming convention for Unclassified STIG library compilation files is `U_SRG-STIG_Library_{year}_{month}.zip` where {year} is a 4-digit year and {month} = 01, 04, 07, or 10.  If there are issues loading the STIG data, visit DISA's IASE website http://iase.disa.mil/stigs/compilations/Pages/index.aspx to verify that the current file is in that format.  If anything different (e.g. `U_SRG-STIG_Library_2018_01_v2.zip`, copy that URL and add the -u="{url}" parameter to the `update_db.php` script (BEFORE all the -- parameters) **

** NOTE: If you have a Nessus&reg; (Nessus Professional&trade; or SecurityCenter&trade;) license, Sagacity will search the default folder paths and include those files when ingesting the OpenVAS library **

** NOTE: If you have acccess to the FOUO STIG content, you can manually download the zip compilation file and put it in the {document_root}/tmp folder also BEFORE running the script.  The script will automatically extract the .zip file and include those when parsing. **

You will need to open a terminal/command prompt, navigate to the "exec" folder in the document root and then run the following command to download and update your database:
    `php update_db.php --cpe --nvd --stig`
    
You can also run this script anytime to update your database to the latest content or establish a cron job/scheduled task to automate recurring updates.  CPE, CVE, and OpenVAS content is updated as needed.  The STIG compilation zip file is update quarterly (Jan, Apr, Jul, & Oct).  You can also download any individual STIG xml files and copy them to {tmp}/stigs/xml, then run the follow command to import them:
    `php update_db.php --stig --po`
    
For offline database updates, run the following on an _online_ system:
    `php update_db.php --cpe --nvd --stig --do`
    
The `--do` parameter tells the script to only download the files.  This will put them in the tmp directory, then you can copy the downloaded files to your offline systems tmp folder and run the command again (changing `--do` to `--po`) to import the data.
    `php update_db.php --cpe --nvd --stig --po`
    
The files can also be downloaded directly from the sources:

- [https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml](https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml)
- [https://nvd.nist.gov/vuln/data-feeds](https://nvd.nist.gov/vuln/data-feeds) (download the JSON ZIP files)
- [http://iase.disa.mil/stigs/compilations/Pages/index.aspx](http://iase.disa.mil/stigs/compilations/Pages/index.aspx) (Download the FOUO [CAC required] or non-FOUO STIG library)
- Copy the files to the tmp folder on the Sagacity host and run the `--po` command show above

### Complete

You are now ready to visit http://localhost to start managing your security assessments with Sagacity

1. Go to the Management tab and add a System, Site, and ST&amp;E
1. Go to the Results tab, select your ST&amp;E, and start adding scan results.  The hosts from the scan files will be displayed on the ST&amp;E Operations tab
1. For more information, see the [Sagacity User Guide](http://localhost/help.php?topic=all)

### Troubleshooting

The following sections include solutions to some common intallation issues encountered when getting Sagacity up and running

#### Windows
- ##### XAMPP Apache Won't Start
The most common problem with XAMPP is that Apache will not start after XAMPP is install.  This is usually because Windows is using the port(s) that Apache wants, 80 and 443.  To find what web ports are listening on the system:

1. In a command prompt, use `netstat -an | more` to see what ports are in use on the system.  Specfically, check for 80, 443, and 8080.

In Windows 10, the World Wide Web Publishing Service runs by default on port 80.  There are two solutions for this: disable the service or move Sagacity to another port:

1. Open Computer Management --> Services and Applications --> Services
1. Scroll down to the World Wide Web Publishing Service.  Right-click and Stop.
1. Right-click again and select Properties. Change the Startup Type to Manual or Disabled.
1. Try to start Apache again

To move Sagacity to another port:

1. Open C:\xampp\apache\conf\httpd.conf in a text editor
1. Find the uncommented listen line: `Listen 80`. Change it to: `Listen 127.0.0.1:8080` or another unused port.  ** NOTE: For security purposes, Sagacity needs to be configured to listen on `127.0.0.1` ONLY! The Sagacity app does not have the security features (yet) to be exposed to the network.
1. Save the httpd.conf file and try to start Apache
1. Please note that you will have to append the new port to your URLs when using Sagacity: [http://localhost:8080/setup.php](http://localhost:8080/setup.php)

If you have VMWare installed, the vmware-hostd service runs on port 443.  Since VMWare requires this service, disable SSL in Apache.  Because Sagacity is a localhost-only tool, this should not affect system security.

1. Open C:\xampp\apache\conf\http.conf in a text editor
1. Find the line "`Include conf/extra/httpd-ssl.conf`" (around line 539), and comment it out: `# Include conf/extra/httpd-ssl.conf`
1. Save the httpd.conf file and try to start Apache

#### Linux

The most common problem on Linux systems is permissions. After downloading Sagacity and before running anything, make sure the permissions are set such that Sagacity can write to the {document_root} directory and all subdirectories.  Permissions need to be as follows for the Apache user

Directories: rwx
Files: rw

If you run into any issues, you can run the following commands to get it working (from the parent directory of the document root):

`sudo chown apache:apache {document root}`

`sudo find {document root} -type d -exec chmod 755 '{}' \;`

`sudo find {document root} -type f -exec chmod 644 '{}' \;`

Also, if you manually run scripts, you may need to run in a sudo context so that the Apache user owns the files `sudo -u apache {script}`

[logo]: https://i1.wp.com/www.cyberperspectives.com/wp-content/uploads/2017/02/Sagacity-Logo.png?resize=600%2C188
[guide]: http://localhost/help.php?topic=all
[User Guide](http://localhost/help.php?topic=all#B.1)