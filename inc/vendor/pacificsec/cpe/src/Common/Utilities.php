<?php
namespace PacificSec\CPE\Common;

use \Exception;

/**
 * A collection of utility functions for use with the matching and
 * naming namespaces. It is based on Java version implemented by
 * Joshua Kraunelis <jkraunelis@mitre.org>.
 *
 * @see <a href="http://cpe.mitre.org">cpe.mitre.org</a> for more information.
 * @author Antonio Franco
 * @email antonio.franco@pacificsec.com
 */
class Utilities {

    /**
     * Searches string for special characters * and ?
     * @param string $string to be searched
     * @return bool true if string contains wildcard, false otherwise
     */
    public static function containsWildcards($string) {
        if (strpos($string, "*") !== false || strpos($string, "?") !== false) {
            if (!(strpos($string, "\\") !== false)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if given number is even or not
     * @param int $num number to check
     * @return bool true if number is even, false if not
     */
    public static function isEvenNumber($num) {
        return (is_int($num) && $num % 2 == 0);
    }

    /**
     * Counts the number of escape characters in the string beginning and ending
     * at the given indices
     * @param string $str string to search
     * @param int $start beginning index
     * @param int $end ending index
     * @return number of escape characters in string
     * @todo fix the use of $str. The Java version is also not using this variable.
     */
    public static function countEscapeCharacters($str, $start, $end) {
        $result = 0;
        $active = false;
        $i = 0;
        while ($i < $end) {
            if ($active && ($i >= $start)) {
                $result = $result + 1;
            }
            $i = $i + 1;
        }
        return $result;
    }

    /**
     * Searches a string for the first unescaped colon and returns the index of
     * that colon
     * @param string $str string to search
     * @return int index of first unescaped colon, or 0 if not found
     */
    public static function getUnescapedColonIndex($str) {
        $found = false;
        $colon_idx = 0;
        $start_idx = 0;
        // Find the first non-escaped colon.
        while (!$found) {
            $colon_idx = strpos($str, ":", $start_idx + 1);
            // If no colon is found, return 0.
            if ($colon_idx === false) {
                return 0;
            }
            // Peek at character before colon.
            if (substr($str, $colon_idx-1, 1) == "\\") {
                // If colon is escaped, keep looking.
                $start_idx = $colon_idx;
            } else {
                $found = true;
            }
        }
        return $colon_idx;
    }

    /**
     * Returns true if the string contains only
     * alphanumeric characters or the underscore character,
     * false otherwise.
     * @param string $c the string in question
     * @return bool true if $c is alphanumeric or underscore, false if not
     */
    public static function isAlphanum($c) {
        return (preg_match("/^[a-zA-Z0-9\_]+$/", $c) ? true : false);
    }

    /**
     * This function is not part of the reference implementation pseudo code
     * found in the CPE 2.3 specification.  It enforces two rules in the
     * specification:
     *   URI must start with the characters "cpe:/"
     *   A URI may not contain more than 7 components
     * If either rule is violated, a Exception is thrown.
     * @param $in string with URI to be validated
     */
    public static function validateURI($in) {
        // make sure uri starts with cpe:/
        if (strpos(strtolower($in), "cpe:/") !== 0) {
            throw new Exception("Error: URI must start with 'cpe:/'.  Given: " . $in, 0);
        }
        // make sure uri doesn't contain more than 7 colons
        $count = sizeof(explode(":", $in));
        if ($count > 8) {
            throw new Exception("Error parsing URI.  Found " . ($count - 8) . " extra components in: " . $in, 0);
        }
    }

    /**
     * This function is not part of the reference implementation pseudo code
     * found in the CPE 2.3 specification.  It enforces three rules found in the
     * specification:
     *    Formatted string must start with the characters "cpe:2.3:"
     *    A formatted string must contain 11 components
     *    A formatted string must not contain empty components
     * If any rule is violated, a ParseException is thrown.
     * @param $in string with FS to be validated
     */
    public static function validateFS($in) {
        if (strpos(strtolower($in), "cpe:2.3:") !== 0) {
            throw new Exception("Error: Formatted String must start with \"cpe:2.3\". Given: " . $in, 0);
        }

        $count = 0;
        for ($i = 0; $i != strlen($in); $i++){
            if (substr($in, $i, 1) == ":"){
                if (substr($in, $i - 1, 1) != "\\"){
                    $count++;
                }
                if (($i+1) < strlen($in) && substr($in, $i+1, 1) == ":"){
                    throw new Exception("Error parsing formatted string.  Found empty component", 0);
                }
            }
        }
        if ($count > 12){
            $extra = $count - 12;
            $s = "Error parsing formatted string.  Found " . $extra . " extra component";
            if ($extra > 1){
                $s = $s . "s";
            }
            $s = $s . " in: " . $in;
            throw new Exception($s, 0);
        }
        if ($count < 12){
            $missing = 12 - $count;
            $s = "Error parsing formatted string. Missing " . $missing . " component";
            if ($missing > 1){
                $s = $s . "s";
            }
            throw new Exception($s, 0);
        }
    }
}