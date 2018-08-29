<?php
namespace PacificSec\CPE\Matching;

use PacificSec\CPE\Common\WellFormedName;
use PacificSec\CPE\Common\Utilities;
use PacificSec\CPE\Common\LogicalValue;
use PacificSec\CPE\Naming\CPENameBinder;
use PacificSec\CPE\Naming\CPENameUnbinder;

/**
 * The CPENameMatcher is an implementation of the CPE Matching algorithm,
 * as specified in the CPE Matching Standard version 2.3. It is based on
 * Java version implemented by Joshua Kraunelis <jkraunelis@mitre.org>.
 *
 * @see <a href="http://cpe.mitre.org">cpe.mitre.org</a> for more information.
 * @author Antonio Franco
 * @email antonio.franco@pacificsec.com
 */
class CPENameMatcher {

    /**
     * Tests two Well Formed Names for disjointness.
     * @param $source WellFormedName Source WFN
     * @param $target WellFormedName Target WFN
     * @return true if the names are disjoint, false otherwise
     */
    public function isDisjoint(WellFormedName $source, WellFormedName $target) {
        // if any pairwise comparison is disjoint, the names are disjoint.
        $resultList = $this->compareWFNs($source, $target);
        foreach ($resultList as $result){
            if ($result == Relation::DISJOINT)
                return true;
        }
        return false;
    }

    /**
     * Tests two Well Formed Names for equality.
     * @param $source WellFormedName Source WFN
     * @param $target WellFormedName Target WFN
     * @return true if the names are equal, false otherwise
     */
    public function isEqual(WellFormedName $source, WellFormedName $target) {
        // if every pairwise comparison is equal, the names are equal.
        $resultList = $this->compareWFNs($source, $target);
        foreach ($resultList as $result){
            if ($result != Relation::EQUAL){
                return false;
            }
        }
        return true;
    }

    /**
     * Tests if the target Well Formed Name is a subset of the source Well Formed
     * Name.
     * @param $source WellFormedName Source WFN
     * @param $target WellFormedName Target WFN
     * @return true if the target is a subset of the source, false otherwise
     */
    public function isSubset(WellFormedName $source, WellFormedName $target) {
        // if any comparison is anything other than subset or equal, then target is
        // not a subset of source.
        $resultList = $this->compareWFNs($source, $target);
        foreach ($resultList as $result){
            if ($result != Relation::SUBSET && $result != Relation::EQUAL) {
                return false;
            }
        }
        return true;
    }

    /**
     * Tests if the target Well Formed name is a superset of the source Well Formed
     * Name.
     * @param $source WellFormedName Source WFN
     * @param $target WellFormedName Target WFN
     * @return true if the target is a superset of the source, false otherwise
     */
    public function isSuperset(WellFormedName $source, WellFormedName $target) {
        // if any comparison is anything other than superset or equal, then target is not
        // a superset of source.
        $resultList = $this->compareWFNs($source, $target);
        foreach ($resultList as $result){
            if ($result != Relation::SUPERSET && $result != Relation::EQUAL) {
                return false;
            }
        }
        return true;
    }

    /**
     * Compares each attribute value pair in two Well Formed Names.
     * @param $source WellFormedName Source WFN
     * @param $target WellFormedName Target WFN
     * @return array A array mapping attribute string to attribute value Relation
     */
    public function compareWFNs(WellFormedName $source, WellFormedName $target) {
        $result = array();
        $result["part"] = $this->compare($source->get("part"), $target->get("part"));
        $result["vendor"] = $this->compare($source->get("vendor"), $target->get("vendor"));
        $result["product"] = $this->compare($source->get("product"), $target->get("product"));
        $result["version"] = $this->compare($source->get("version"), $target->get("version"));
        $result["update"] = $this->compare($source->get("update"), $target->get("update"));
        $result["edition"] = $this->compare($source->get("edition"), $target->get("edition"));
        $result["language"] = $this->compare($source->get("language"), $target->get("language"));
        $result["sw_edition"] = $this->compare($source->get("sw_edition"), $target->get("sw_edition"));
        $result["target_sw"] = $this->compare($source->get("target_sw"), $target->get("target_sw"));
        $result["target_hw"] = $this->compare($source->get("target_hw"), $target->get("target_hw"));
        $result["other"] = $this->compare($source->get("other"), $target->get("other"));
        return $result;
    }

    /**
     * Compares an attribute value pair.
     * @param string  $source Source attribute value.
     * @param string $target Target attribute value.
     * @return int The relation between the two attribute values.
     */
    private function compare($source, $target) {
        // matching is case insensitive, convert strings to lowercase.
        if ($this->isString($source)) {
            $source = strtolower($source);
        }
        if ($this->isString($target)) {
            $target = strtolower($target);
        }

        // Unquoted wildcard characters yield an undefined result.
        if ($this->isString($target) && Utilities::containsWildcards($target)) {
            return Relation::UNDEFINED;
        }
        // If source and target values are equal, then result is equal.
        if ($source == $target) {
            return Relation::EQUAL;
        }

        // Check to see if source or target are Logical Values.
        $lvSource = null;
        $lvTarget = null;
        if ($source instanceof LogicalValue) {
            $lvSource = $source;
        }
        if ($target instanceof LogicalValue) {
            $lvTarget = $target;
        }
        if ($lvSource != null && $lvTarget != null) {
            // If Logical Values are equal, result is equal.
            if ($lvSource->isANY() == $lvTarget->isANY() || $lvSource->isNA() == $lvTarget->isNA()) {
                return Relation::EQUAL;
            }
        }
        // If source value is ANY, result is a superset.
        if ($lvSource != null) {
            if ($lvSource->isANY()) {
                return Relation::SUPERSET;
            }
        }
        // If target value is ANY, result is a subset.
        if ($lvTarget != null) {
            if ($lvTarget->isANY()) {
                return Relation::SUBSET;
            }
        }
        // If source or target is NA, result is disjoint.
        if ($lvSource != null) {
            if ($lvSource->isNA()) {
                return Relation::DISJOINT;
            }
        }
        if ($lvTarget != null) {
            if ($lvTarget->isNA()) {
                return Relation::DISJOINT;
            }
        }
        // only Strings will get to this point, not LogicalValues
        return $this->compareStrings($source, $target);
    }

    /**
     * Compares a source string to a target string, and addresses the condition
     * in which the source string includes unquoted special characters. It
     * performs a simple regular expression  match, with the assumption that
     * (as required) unquoted special characters appear only at the beginning
     * and/or the end of the source string. It also properly differentiates
     * between unquoted and quoted special characters.
     *
     * @param $source string Source attribute value.
     * @param $target string Target attribute value.
     * @return Relation between source and target Strings.
     */
    private function compareStrings($source, $target) {
        $start = 0;
        $end = strlen($source);
        $begins = 0;
        $ends = 0;
        $index = 0; $leftover = 0; $escapes = 0;

        if (substr($source, 0, 1) == "*") {
            $start = 1;
            $begins = -1;
        } else {
            while (($start < strlen($source)) && (substr($source, $start, 1) == "?")) {
                $start = $start + 1;
                $begins = $begins + 1;
            }
        }
        if ((substr($source, $end - 1, 1) == "*") && ($this->isEvenWildcards($source, $end - 1))) { //TODO
            $end = $end - 1;
            $ends = -1;
        } else {
            while (($end > 0) && substr($source, $end - 1, 1) == "?" && ($this->isEvenWildcards($source, $end - 1))) { //TODO
                $end = $end - 1;
                $ends = $ends + 1;
            }
        }

        $source = substr($source, $start, $end-$start);
        $index = -1;
        $leftover = strlen($target);
        while ($leftover > 0) {
            $index = strpos($target, $source, $index + 1);
            if ($index === false) {
                break;
            }
            $escapes = Utilities::countEscapeCharacters($target, 0, $index);
            if (($index > 0) && ($begins != -1) && ($begins < ($index - $escapes))) {
                break;
            }
            $escapes = Utilities::countEscapeCharacters($target, $index + 1, strlen($target));
            $leftover = strlen($target) - $index - $escapes - strlen($source);
            if (($leftover > 0) && (($ends != -1) && ($leftover > $ends))) {
                continue;
            }
            return Relation::SUPERSET;
        }
        return Relation::DISJOINT;
    }

    /**
     * Searches a string for the backslash character
     * @param $str string to search in
     * @param int $idx end index
     * @return true if the number of backslash characters is even, false if odd
     */
    private function isEvenWildcards($str, $idx) {
        $result = 0;
        while (($idx > 0) && (strpos($str, "\\", $idx - 1)) !== false) {
            $idx = $idx - 1;
            $result = $result + 1;
        }
        return Utilities::isEvenNumber($result);
    }

    /**
     * Tests if an Object is an instance of the String class
     * @param mixed $arg the var to test
     * @return bool true if arg is a string, false if not
     */
    private function isString($arg) {
        return is_string($arg);
    }

    /*
     * Static method to demonstrate this class.
     */
    public static function test() {
        // Examples.
        $wfn = new WellFormedName("a", "microsoft", "internet_explorer", "8\\.0\\.6001", "beta", new LogicalValue("ANY"), "sp2", null, null, null, null);
        $wfn2 = new WellFormedName("a", "microsoft", "internet_explorer", new LogicalValue("ANY"), new LogicalValue("ANY"), new LogicalValue("ANY"), new LogicalValue("ANY"), new LogicalValue("ANY"), new LogicalValue("ANY"), new LogicalValue("ANY"), new LogicalValue("ANY"));
        $cpenm = new CPENameMatcher();
        $cpenu = new CPENameUnbinder();
        $cpenb = new CPENameBinder();
        $wfn = $cpenu->unbindURI($cpenb->bindToURI($wfn));
        $wfn2 = $cpenu->unbindFS($cpenb->bindToFS($wfn2));
        var_dump($cpenm->isDisjoint($wfn, $wfn2)); // false
        var_dump($cpenm->isEqual($wfn, $wfn2)); // false
        var_dump($cpenm->isSubset($wfn, $wfn2)); // true, $wfn2 is a subset of wfn
        var_dump($cpenm->isSuperset($wfn, $wfn2)); // false
        $wfn = $cpenu->unbindFS("cpe:2.3:a:adobe:*:9.*:*:PalmOS:*:*:*:*:*");
        $wfn2 = $cpenu->unbindURI("cpe:/a::Reader:9.3.2:-:-");
        var_dump($cpenm->isDisjoint($wfn, $wfn2)); // true, $wfn2 and wfn are disjoint
        var_dump($cpenm->isEqual($wfn, $wfn2)); // false
        var_dump($cpenm->isSubset($wfn, $wfn2)); // false
        var_dump($cpenm->isSuperset($wfn, $wfn2)); // false
    }
}