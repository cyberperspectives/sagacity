<?php
namespace PacificSec\CPE\Naming;

use PacificSec\CPE\Common\WellFormedName;
use PacificSec\CPE\Common\Utilities;
use PacificSec\CPE\Common\LogicalValue;

/**
 * The CPENameBinder class is a simple implementation
 * of the CPE Name binding algorithm, as specified in the
 * CPE Naming Standard version 2.3.
 * It is based on Java version
 * implemented by Joshua Kraunelis <jkraunelis@mitre.org>.
 *
 * @see <a href="http://cpe.mitre.org">cpe.mitre.org</a> for more information.
 * @author Antonio Franco
 * @email antonio.franco@pacificsec.com
 */
class CPENameBinder
{

    /**
     * Binds a {@link WellFormedName} object to a URI.
     *
     * @param $w WellFormedName
     *            to be bound to URI
     * @return string URI binding of WFN
     */
    public function bindToURI(WellFormedName $w)
    {

        // Initialize the output with the CPE v2.2 URI prefix.
        $uri = "cpe:/";

        // Define the attributes that correspond to the seven components in a v2.2. CPE.
        $attributes = array(
            "part",
            "vendor",
            "product",
            "version",
            "update",
            "edition",
            "language"
        );

        // Iterate over the well formed name
        foreach ($attributes as $a) {
            $v = "";
            if ($a == "edition") {
                // Call the pack() helper function to compute the proper
                // binding for the edition element.
                $ed = $this->bindValueForURI($w->get("edition"));
                $sw_ed = $this->bindValueForURI($w->get("sw_edition"));
                $t_sw = $this->bindValueForURI($w->get("target_sw"));
                $t_hw = $this->bindValueForURI($w->get("target_hw"));
                $oth = $this->bindValueForURI($w->get("other"));
                $v = $this->pack($ed, $sw_ed, $t_sw, $t_hw, $oth);
            } else {
                // Get the value for a in w, then bind to a string
                // for inclusion in the URI.
                $v = $this->bindValueForURI($w->get($a));
            }
            // Append v to the URI then add a colon.
            $uri = $uri . $v . ":";
        }
        // Return the URI string, with trailing colons trimmed.
        return $this->trim($uri);
    }

    /**
     * Top-level function used to bind WFN w to formatted string.
     *
     * @param $w WellFormedName
     *            to bind
     * @return string Formatted String
     */
    public function bindToFS(WellFormedName $w)
    {
        // Initialize the output with the CPE v2.3 string prefix.
        $fs = "cpe:2.3:";
        foreach (array(
            "part",
            "vendor",
            "product",
            "version",
            "update",
            "edition",
            "language",
            "sw_edition",
            "target_sw",
            "target_hw",
            "other"
        ) as $a) {
            $v = $this->bindValueForFS($w->get($a));
            $fs = $fs . $v;
            // add a colon except at the very end
            if (strpos($a, "other") === false) {
                $fs = $fs . ":";
            }
        }
        return $fs;
    }

    /**
     * Convert the value v to its proper string representation for insertion to
     * formatted string.
     *
     * @param mixed $v
     *            value to convert
     * @return mixed Formatted value
     */
    private function bindValueForFS($v)
    {
        if ($v instanceof LogicalValue) {
            $l = $v;
            // The value NA binds to a blank.
            if ($l->isANY()) {
                return "*";
            }
            // The value NA binds to a single hyphen.
            if ($l->isNA()) {
                return "-";
            }
        }
        return $this->processQuotedChars($v);
    }

    /**
     * Inspect each character in string s.
     * Certain nonalpha characters pass
     * thru without escaping into the result, but most retain escaping.
     *
     * @param
     *            $s
     * @return
     */
    private function processQuotedChars($s)
    {
        $result = "";
        $idx = 0;
        while ($idx < strlen($s)) {
            $c = substr($s, $idx, 1);
            if ($c != "\\") {
                // unquoted characters pass thru unharmed.
                $result .= $c;
            } else {
                // escaped characters are examined.
                $nextchr = substr($s, $idx + 1, 1);
                // the period, hyphen and underscore pass unharmed.
                if ($nextchr == "." || $nextchr == "-" || $nextchr == "_") {
                    $result .= $nextchr;
                    $idx = $idx + 2;
                    continue;
                } else {
                    // all others retain escaping.
                    $result .= "\\" . $nextchr;
                    $idx = $idx + 2;
                    continue;
                }
            }
            $idx = $idx + 1;
        }
        return $result;
    }

    /**
     * Converts a string to the proper string for including in
     * a CPE v2.2-conformant URI.
     * The logical value ANY binds
     * to the blank in the 2.2-conformant URI.
     *
     * @param $s string
     *            to be converted
     * @return string converted string
     */
    private function bindValueForURI($s)
    {
        if ($s instanceof LogicalValue) {
            $l = $s;
            // The value NA binds to a blank.
            if ($l->isANY()) {
                return "";
            }
            // The value NA binds to a single hyphen.
            if ($l->isNA()) {
                return "-";
            }
        }

        // If we get here, we're dealing with a string value.
        return $this->transformForURI($s);
    }

    /**
     * Scans an input string and performs the following transformations:
     * - Pass alphanumeric characters thru untouched
     * - Percent-encode quoted non-alphanumerics as needed
     * - Unquoted special characters are mapped to their special forms
     *
     * @param $s string
     *            to be transformed
     * @return string transformed string
     */
    private function transformForURI($s)
    {
        $result = "";
        $idx = 0;

        while ($idx < strlen($s)) {
            // Get the idx'th character of s.
            $thischar = substr($s, $idx, 1);
            // Alphanumerics (incl. underscore) pass untouched.
            if (Utilities::isAlphanum($thischar)) {
                $result .= $thischar;
                $idx = $idx + 1;
                continue;
            }
            // Check for escape character.
            if ($thischar == "\\") {
                $idx = $idx + 1;
                $nxtchar = substr($s, $idx, 1);
                $result .= $this->pctEncode($nxtchar);
                $idx = $idx + 1;
                continue;
            }
            // Bind the unquoted '?' special character to "%01".
            if ($thischar == "?") {
                $result .= "%01";
            }
            // Bind the unquoted '*' special character to "%02".
            if ($thischar == "*") {
                $result .= "%02";
            }
            $idx = $idx + 1;
        }
        return $result;
    }

    /**
     * Returns the appropriate percent-encoding of character c.
     * Certain characters are returned without encoding.
     *
     * @param string $c the
     *            single character string to be encoded
     * @return string the percent encoded string
     */
    private function pctEncode($c)
    {
        switch ($c) {
            case '!':
                return "%21";
            case "\"":
                return "%22";
            case "#":
                return "%23";
            case "$":
                return "%24";
            case "%":
                return "%25";
            case "&":
                return "%26";
            case "'":
                return "%27";
            case "(":
                return "%28";
            case ")":
                return "%29";
            case "*":
                return "%2a";
            case "+":
                return "%2b";
            case ",":
                return "%2c";
            case "/":
                return "%2f";
            case ":":
                return "%3a";
            case ";":
                return "%3b";
            case "<":
                return "%3c";
            case "=":
                return "%3d";
            case ">":
                return "%3e";
            case "?":
                return "%3f";
            case "@":
                return "%40";
            case "[":
                return "%5b";
            case "\\":
                return "%5c";
            case "]":
                return "%5d";
            case "^":
                return "%5e";
            case "`":
                return "%60";
            case "{":
                return "%7b";
            case "|":
                return "%7c";
            case "}":
                return "%7d";
            case "~":
                return "%7e";
            default:
                return $c;
        }
    }

    /**
     * Packs the values of the five arguments into the single
     * edition component.
     * If all the values are blank, the
     * function returns a blank.
     *
     * @param string $ed edition
     *            string
     * @param string $sw_ed software
     *            edition string
     * @param string $t_sw target
     *            software string
     * @param string $t_hw target
     *            hardware string
     * @param string $oth other
     *            edition information string
     * @return string the packed string, or blank
     */
    private function pack($ed, $sw_ed, $t_sw, $t_hw, $oth)
    {
        if ($sw_ed == "" && $t_sw == "" && $t_hw == "" && $oth == "") {
            // All the extended attributes are blank, so don't do
            // any packing, just return ed.
            return $ed;
        }
        // Otherwise, pack the five values into a single string
        // prefixed and internally delimited with the tilde.
        return "~" . $ed . "~" . $sw_ed . "~" . $t_sw . "~" . $t_hw . "~" . $oth;
    }

    /**
     * Removes trailing colons from the URI.
     *
     * @param string $s the
     *            string to be trimmed
     * @return string the trimmed string
     */
    private function trim($s)
    {
        $s1 = strrev($s);
        $idx = 0;
        for ($i = 0; $i != strlen($s1); $i ++) {
            if (substr($s1, $i, 1) == ":") {
                $idx = $idx + 1;
            } else {
                break;
            }
        }
        // Return the substring after all trailing colons,
        // reversed back to its original character order.
        return strrev(substr($s1, $idx, strlen($s1) - $idx));
    }

    /*
     * Static method to demonstrate this class.
     */
    public static function test()
    {
        // A few examples.
        echo "Testing CPENamingBind...<br>\n";
        $wfn = new WellFormedName("a", "microsoft", "internet_explorer", "8\\.0\\.6001", "beta", new LogicalValue("ANY"), "sp2", null, null, null, null);
        $wfn2 = new WellFormedName();

        $wfn2->set("part", "a");
        $wfn2->set("vendor", "foo\\\$bar");
        $wfn2->set("product", "insight");
        $wfn2->set("version", "7\\.4\\.0\\.1570");
        $wfn2->set("target_sw", "win2003");
        $wfn2->set("update", new LogicalValue("NA"));
        $wfn2->set("sw_edition", "online");
        $wfn2->set("target_hw", "x64");
        $cpenb = new CPENameBinder();

        echo $cpenb->bindToURI($wfn) . "<br>\n";
        echo $cpenb->bindToFS($wfn2) . "<br>\n";
    }
}