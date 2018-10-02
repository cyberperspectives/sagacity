Common Platform Enumeration for PHP
--------------------------------------

*CPE* (this code) is a MIT licensed PHP package, implementing the
CPE standards.


About the CPE standard
----------------------

Common Platform Enumeration (CPE) is a standardized method of describing
and identifying classes of applications, operating systems, and hardware
devices present among an enterprise's computing assets.

For more information, please visit the official website of CPE,
developed by [MITRE](http://cpe.mitre.org/) and maintained by [NIST](http://nvd.nist.gov/cpe.cfm).


Features
--------

- CPE rich comparison.
- CPE Language parsing and evaluation.
- MIT Licensed.

Getting Started
--------
- Clone repository

```bash
$ git clone https://github.com/pacificsec/cpe.git
$ cd cpe
```
- Create a new PHP file to run tests

```php
<?php
require('autoload.php');

use PacificSec\CPE\Matching\CPENameMatcher;
use PacificSec\CPE\Naming\CPENameUnbinder;
use PacificSec\CPE\Naming\CPENameBinder;

CPENameMatcher::test();
CPENameUnbinder::test();
CPENameBinder::test();
```

```php
<?php
require('autoload.php');

use PacificSec\CPE\Naming\CPENameUnbinder;

$cpenu = new CPENameUnbinder();
$wfn = $cpenu->unbindURI("cpe:/a:microsoft:internet_explorer%01%01%01%01:?:beta");
var_dump($wfn);
$wfn = $cpenu->unbindURI("cpe:/a:microsoft:internet_explorer:8.%2a:sp%3f");
var_dump($wfn);
$wfn = $cpenu->unbindURI("cpe:/a:microsoft:internet_explorer:8.%02:sp%01");
var_dump($wfn);
$wfn = $cpenu->unbindURI("cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~");
var_dump($wfn);
$wfn = $cpenu->unbindFS("cpe:2.3:a:micr\\?osoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*");
var_dump($wfn);
```