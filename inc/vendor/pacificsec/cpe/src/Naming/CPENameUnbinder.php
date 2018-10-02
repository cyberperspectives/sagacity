<?php
namespace PacificSec\CPE\Naming;

use PacificSec\CPE\Common\WellFormedName;
use PacificSec\CPE\Common\Utilities;
use PacificSec\CPE\Common\LogicalValue;
use \Exception;

/**
 * The CPENameUnBinder class is a simple implementation
 * of the CPE Name unbinding algorithm, as specified in the
 * CPE Naming Standard version 2.3. It is based on Java version
 * implemented by Joshua Kraunelis <jkraunelis@mitre.org>.
 *
 * @see <a href="http://cpe.mitre.org">cpe.mitre.org</a> for more information.
 * @author Antonio Franco
 * @email antonio.franco@pacificsec.com
 */
class CPENameUnbinder {

    /**
     * Top level function used to unbind a URI to a WFN.
     * @param $uri string representing the URI to be unbound.
     * @return WellFormedName representing the unbound URI.
     * @throws Exception representing parsing errors.
     */
    public function unbindURI($uri) {
        // Validate the URI
        Utilities::validateURI($uri);
        // Initialize the empty WFN.
        $result = new WellFormedName();

        for ($i = 0; $i != 8; $i++) {
            // get the i'th component of uri
            $v = $this->getCompURI($uri, $i);
            switch ($i) {
                case 1:
                    $result->set("part", $this->decode($v));
                    break;
                case 2:
                    $result->set("vendor", $this->decode($v));
                    break;
                case 3:
                    $result->set("product", $this->decode($v));
                    break;
                case 4:
                    $result->set("version", $this->decode($v));
                    break;
                case 5:
                    $result->set("update", $this->decode($v));
                    break;
                case 6:
                    // Special handling for edition component.
                    // Unpack edition if needed.
                    if ($v == "" || $v == "-"
                        || substr($v, 0, 1) != "~") {
                            // Just a logical value or a non-packed value.
                            // So unbind to legacy edition, leaving other
                            // extended attributes unspecified.
                            $result->set("edition", $this->decode($v));
                        } else {
                            // We have five values packed together here.
                            $this->unpack($v, $result);
                        }
                        break;
                case 7:
                    $result->set("language", $this->decode($v));
                    break;
            }
        }
        return $result;
    }

    /**
     * Top level function to unbind a formatted string to WFN.
     * @param string $fs Formatted string to unbind
     * @return WellFormedName
     * @throws Exception representing parsing error
     */
    public function unbindFS($fs) {
        // Validate the formatted string
        Utilities::validateFS($fs);
        // Initialize empty WFN
        $result = new WellFormedName();
        // The cpe scheme is the 0th component, the cpe version is the 1st.
        // So we start parsing at the 2nd component.
        for ($a = 2; $a != 13; $a++) {
            // Get the a'th string field.
            $v = $this->getCompFS($fs, $a);
            // Unbind the string.
            $v = $this->unbindValueFS($v);
            // Set the value of the corresponding attribute.
            switch ($a) {
                case 2:
                    $result->set("part", $v);
                    break;
                case 3:
                    $result->set("vendor", $v);
                    break;
                case 4:
                    $result->set("product", $v);
                    break;
                case 5:
                    $result->set("version", $v);
                    break;
                case 6:
                    $result->set("update", $v);
                    break;
                case 7:
                    $result->set("edition", $v);
                    break;
                case 8:
                    $result->set("language", $v);
                    break;
                case 9:
                    $result->set("sw_edition", $v);
                    break;
                case 10:
                    $result->set("target_sw", $v);
                    break;
                case 11:
                    $result->set("target_hw", $v);
                    break;
                case 12:
                    $result->set("other", $v);
                    break;
            }
        }
        return $result;
    }

    /**
     * Returns the i'th field of the formatted string.  The colon is the field
     * delimiter unless prefixed by a backslash.
     * @param string $fs formatted string to retrieve from
     * @param int $i index of field to retrieve from fs.
     * @return int value of index of formatted string
     */
    private function getCompFS($fs, $i) {
        if ($i == 0) {
            // return the substring from index 0 to the first occurence of an
            // unescaped colon
            $colon_idx = Utilities::getUnescapedColonIndex($fs);
            // If no colon is found, we are at the end of the formatted string,
            // so just return what's left.
            if ($colon_idx == 0) {
                return $fs;
            }
            return substr($fs, 0, $colon_idx);
        } else {
            $substrStart = Utilities::getUnescapedColonIndex($fs) + 1;
            $substrLength = strlen($fs) - $substrStart;
            return $this->getCompFS(substr($fs, $substrStart, $substrLength), $i - 1);
        }
    }

    /**
     * Takes a string value and returns the appropriate logical value if string
     * is the bound form of a logical value.  If string is some general value
     * string, add quoting of non-alphanumerics as needed.
     * @param string $s value to be unbound
     * @return string logical value or quoted string
     * @throws Exception representing parsing errors
     */
    private function unbindValueFS($s) {
        if ($s == "*") {
            return new LogicalValue("ANY");
        }
        if ($s == "-") {
            return new LogicalValue("NA");
        }
        return $this->addQuoting($s);
    }

    /**
     * Inspect each character in a string, copying quoted characters, with
     * their escaping, into the result.  Look for unquoted non alphanumerics
     * and if not "*" or "?", add escaping.
     * @param $s
     * @return
     * @throws Exception representing parsing errors.
     */
    private function addQuoting($s) {
        $result = "";
        $idx = 0;
        $embedded = false;
        while ($idx < strlen($s)) {
            $c = substr($s, $idx, 1);
            if (Utilities::isAlphanum($c)) {
                // Alphanumeric characters pass untouched.
                $result .= $c;
                $idx = $idx + 1;
                $embedded = true;
                continue;
            }
            if ($c == "\\") {
                // Anything quoted in the bound string stays quoted in the
                // unbound string.
                $result .= substr($s, $idx, 2);
                $idx = $idx + 2;
                $embedded = true;
                continue;
            }
            if ($c == "*") {
                // An unquoted asterisk must appear at the beginning or the end
                // of the string.
                if ($idx == 0 || $idx == strlen($s) - 1) {
                    $result .= $c;
                    $idx = $idx + 1;
                    $embedded = true;
                    continue;
                } else {
                    throw new Exception("Error! cannot have unquoted * embedded in formatted string.", 0);
                }
            }
            if ($c == "?") {
                // An unquoted question mark must appear at the beginning or
                // end of the string, or in a leading or trailing sequence.
                if ( // ? legal at beginning or end
                    (($idx == 0) || ($idx == (strlen($s) - 1)))
                    // embedded is false, so must be preceded by ?
                    || (!$embedded && (substr($s, $idx - 1, 1) == "?"))
                    // embedded is true, so must be followed by ?
                    || ($embedded && (substr($s, $idx + 1, 1) == "?"))) {
                        $result .= $c;
                        $idx = $idx + 1;
                        $embedded = false;
                        continue;
                    } else {
                        throw new Exception("Error! cannot have unquoted ? embedded in formatted string.", 0);
                    }
            }
            // All other characters must be quoted.
            $result .= "\\" . $c;
            $idx = $idx + 1;
            $embedded = true;
        }
        return $result;
    }

    /**
     * Return the i'th component of the URI.
     * @param $uri string representation of URI to retrieve components from.
     * @param int $i Index of component to return.
     * @return mixed If i = 0, returns the URI scheme. Otherwise, returns the i'th
     * component of uri.
     */
    private function getCompURI($uri, $i) {
        if ($i == 0) {
            return substr($uri, $i, strpos($uri, "/"));
        }
        $sa = explode(":", $uri);
        // If requested component exceeds the number
        // of components in URI, return blank
        if ($i >= sizeof($sa)) {
            return "";
        }
        if ($i === 1) {
            return substr($sa[$i], 1, strlen($sa[$i])-1);
        }
        return $sa[$i];
    }

    /**
     * Scans a string and returns a copy with all percent-encoded characters
     * decoded.  This function is the inverse of pctEncode() defined in the
     * CPENameBinder class.  Only legal percent-encoded forms are decoded.
     * Others raise a ParseException.
     * @param $s string to be decoded
     * @return string decoded string
     * @throws Exception representing parsing errors
     * @see CPENameBinder#pctEncode
     */
    private function decode($s) {
        if ($s == "") {
            return new LogicalValue("ANY");
        }
        if ($s == "-") {
            return new LogicalValue("NA");
        }
        // Start the scanning loop.
        // Normalize: convert all uppercase letters to lowercase first.
        $s = strtolower($s);
        $result = "";
        $idx = 0;
        $embedded = false;
        while ($idx < strlen($s)) {
            // Get the idx'th character of s.
            $c = substr($s, $idx, 1);
            // Deal with dot, hyphen, and tilde: decode with quoting.
            if ($c == "." || $c == "-" || $c == "~") {
                $result .= "\\" . $c;
                $idx = $idx + 1;
                // a non-%01 encountered.
                $embedded = true;
                continue;
            }
            if ($c != "%") {
                $result .= $c;
                $idx = $idx + 1;
                // a non-%01 encountered.
                $embedded = true;
                continue;
            }
            // We get here if we have a substring starting w/ '%'.
            $form = substr($s, $idx, 3);
            if ($form == "%01") {
                if (($idx == 0)
                    || ($idx == strlen($s) - 3)
                    || (!$embedded && substr($s, $idx - 3, 2) == "%01")
                    || ($embedded && (strlen($s) >= $idx + 6))
                    && (substr($s, $idx + 3, 3) == "%01")) {
                        $result .= "?";
                        $idx = $idx + 3;
                        continue;
                    } else {
                        throw new Exception("Error decoding string", 0);
                    }
            } else if ($form == "%02") {
                if (($idx == 0) || ($idx == (strlen($s) - 3))) {
                    $result .= "*";
                } else {
                    throw new Exception("Error decoding string", 0);
                }
            } else if ($form == "%21") {
                $result .= "\\!";
            } else if ($form == "%22") {
                $result .= "\\\"";
            } else if ($form == "%23") {
                $result .= "\\#";
            } else if ($form == "%24") {
                $result .= "\\$";
            } else if ($form == "%25") {
                $result .= "\\%";
            } else if ($form == "%26") {
                $result .= "\\&";
            } else if ($form == "%27") {
                $result .= "\\'";
            } else if ($form == "%28") {
                $result .= "\\(";
            } else if ($form == "%29") {
                $result .= "\\)";
            } else if ($form == "%2a") {
                $result .= "\\*";
            } else if ($form == "%2b") {
                $result .= "\\+";
            } else if ($form == "%2c") {
                $result .= "\\,";
            } else if ($form == "%2f") {
                $result .= "\\/";
            } else if ($form == "%3a") {
                $result .= "\\:";
            } else if ($form == "%3b") {
                $result .= "\\;";
            } else if ($form == "%3c") {
                $result .= "\\<";
            } else if ($form == "%3d") {
                $result .= "\\=";
            } else if ($form == "%3e") {
                $result .= "\\>";
            } else if ($form == "%3f") {
                $result .= "\\?";
            } else if ($form == "%40") {
                $result .= "\\@";
            } else if ($form == "%5b") {
                $result .= "\\[";
            } else if ($form == "%5c") {
                $result .= "\\\\";
            } else if ($form == "%5d") {
                $result .= "\\]";
            } else if ($form == "%5e") {
                $result .= "\\^";
            } else if ($form == "%60") {
                $result .= "\\`";
            } else if ($form == "%7b") {
                $result .= "\\{";
            } else if ($form == "%7c") {
                $result .= "\\|";
            } else if ($form == "%7d") {
                $result .= "\\}";
            } else if ($form == "%7e") {
                $result .= "\\~";
            } else {
                throw new Exception("Unknown form: " . $form, 0);
            }
            $idx = $idx + 3;
            $embedded = true;
        }
        return $result;
    }

    /**
     * Unpacks the elements in s and sets the attributes in the given
     * WellFormedName accordingly.
     * @param string $s packed string
     * @param $wfn WellFormedName
     * @return WellFormedName The augmented WellFormedName.
     */
    private function unpack($s, WellFormedName $wfn) {
        // Parse out the five elements.
        $start = 1;
        $ed = ""; $sw_edition = ""; $t_sw = ""; $t_hw = ""; $oth = "";
        $end = strpos($s, "~", $start);
        if ($start == $end) {
            $ed = "";
        } else {
            $ed = substr($s, $start, $end-$start);
        }
        $start = $end + 1;
        $end = strpos($s, "~", $start);
        if ($start == $end) {
            $sw_edition = "";
        } else {
            $sw_edition = substr($s, $start, $end-$start);
        }
        $start = $end + 1;
        $end = strpos($s, "~", $start);
        if ($start == $end) {
            $t_sw = "";
        } else {
            $t_sw = substr($s, $start, $end-$start);
        }
        $start = $end + 1;
        $end = strpos($s, "~", $start);
        if ($start == $end) {
            $t_hw = "";
        } else {
            $t_hw = substr($s, $start, $end-$start);
        }
        $start = $end + 1;
        if ($start >= strlen($s)) {
            $oth = "";
        } else {
            $oth = substr($s, $start, strlen($s) - 1 - $start);
        }
        // Set each component in the WFN.
        try {
            $wfn->set("edition", $this->decode($ed));
            $wfn->set("sw_edition", $this->decode($sw_edition));
            $wfn->set("target_sw", $this->decode($t_sw));
            $wfn->set("target_hw", $this->decode($t_hw));
            $wfn->set("other", $this->decode($oth));
        } catch (Exception $e) {
            echo $e->getMessage() . "\n";
        }
        return $wfn;
    }

    /*
     * Static method to demonstrate this class.
     */
    public static function test() {
        // A few examples.
        echo "Testing CPENamingUnbind...<br>\n";
        $cpenu = new CPENameUnbinder();
        $wfn = $cpenu->unbindURI("cpe:/a:microsoft:internet_explorer%01%01%01%01:?:beta");
        echo $wfn . "<br>\n";
        $wfn = $cpenu->unbindURI("cpe:/a:microsoft:internet_explorer:8.%2a:sp%3f");
        echo $wfn . "<br>\n";
        $wfn = $cpenu->unbindURI("cpe:/a:microsoft:internet_explorer:8.%02:sp%01");
        echo $wfn . "<br>\n";
        $wfn = $cpenu->unbindURI("cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~");
        echo $wfn . "<br>\n";
        echo $cpenu->unbindFS("cpe:2.3:a:micr\\?osoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*") . "<br>\n";
    }
}