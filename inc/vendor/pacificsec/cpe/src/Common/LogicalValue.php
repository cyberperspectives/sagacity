<?php
namespace PacificSec\CPE\Common;

use \Exception;

/**
 * This class represents a Logical Value. It is based on Java version
 * implemented by JKRAUNELIS <jkraunelis@mitre.org>.
 *
 * @see <a href="http://cpe.mitre.org">cpe.mitre.org</a> for more information.
 * @author Antonio Franco
 * @email antonio.franco@pacificsec.com
 */
class LogicalValue {

    private $any = false;
    private $na = false;

    // Object must be constructed with the string "ANY" or "NA".
    public function __construct($type) {
        if ($type == "ANY") {
            $this->any = true;
        } else if ($type == "NA") {
            $this->na = true;
        } else {
            throw new Exception("LogicalValue must be ANY or NA");
        }
    }

    public function isANY(){
        return $this->any;
    }

    public function isNA(){
        return $this->na;
    }

    public function __toString(){
        if ($this->any){
            return "ANY";
        }
        return "NA";
    }
}