<?php
namespace PacificSec\CPE\Common;

use \Exception;

/**
 * The WellFormedName class represents a Well Formed Name, as defined
 * in the CPE Specification version 2.3. It is based on Java version
 * implemented by jkraunelis <jkraunelis@mitre.org>.
 *
 * @see <a href="http://cpe.mitre.org">cpe.mitre.org</a> for details.
 * @author Antonio Franco
 * @email antonio.franco@pacificsec.com
 */
class WellFormedName {

    // Underlying wfn representation.
    private $wfn = null;
    // All permissible WFN attributes as defined by specification.
    private $attributes = array("part", "vendor", "product", "version",
        "update", "edition", "language", "sw_edition", "target_sw",
        "target_hw", "other");

    /**
     * Constructs a new WellFormedName object, setting each component to the
     * given parameter value.  If a parameter is null, the component is set to
     * the default value "ANY".
     * @param $part string representing the part component
     * @param $vendor string representing the vendor component
     * @param $product string representing the product component
     * @param $version string representing the version component
     * @param $update string representing the update component
     * @param $edition string representing the edition component
     * @param $language string representing the language component
     * @param $sw_edition string representing the sw_edition component
     * @param $target_sw string representing the target_sw component
     * @param $target_hw string representing the target_hw component
     * @param $other string representing the other component
     */
    public function __construct($part = null, $vendor = null, $product = null, $version = null,
        $update = null, $edition = null, $language = null, $sw_edition = null, $target_sw = null,
        $target_hw = null, $other = null) {

            $this->wfn = array();

            // Constructs a new WellFormedName object, with all components set to the default value "ANY".
            if ($part === null && $vendor === null && $product === null && $version === null &&
                $update === null && $edition === null && $language === null && $sw_edition === null && $target_sw === null &&
                $target_hw === null && $other === null){
                    foreach ($this->attributes as $a){
                        if ($a != "part"){
                            $this->set($a, new LogicalValue("ANY"));
                        }
                    }
                    return;
            }

            $this->set("part", $part);
            $this->set("vendor", $vendor);
            $this->set("product", $product);
            $this->set("version", $version);
            $this->set("update", $update);
            $this->set("edition", $edition);
            $this->set("language", $language);
            $this->set("sw_edition", $sw_edition);
            $this->set("target_sw", $target_sw);
            $this->set("target_hw", $target_hw);
            $this->set("other", $other);
    }

    /**
     * @param $attribute string representing the component value to get
     * @return string the string value of the given component, or default value "ANY"
     * if the component does not exist
     */
    public function get($attribute){
        if (array_key_exists($attribute, $this->wfn))
            return $this->wfn[$attribute];
            else
                return new LogicalValue("ANY");
    }

    /**
     * Sets the given attribute to value, if the attribute is in the list of
     * permissible components
     * @param $attribute string representing the component to set
     * @param $value object or string representing the value of the given component
     */
    public final function set($attribute, $value){
        // Iterate over permissible attributes.
        foreach ($this->attributes as $a){
            // If the argument is a valid attribute, set that attribute's value.
            if ($attribute == $a) {
                // check to see if we're setting a LogicalValue ANY or NA
                if ($value instanceof LogicalValue){
                    // don't allow logical values in part component
                    if ($attribute == "part"){
                        var_dump($value); echo "<br>\n";
                        var_dump($a); echo "<br>\n";
                        var_dump($attribute); echo "<br>\n";
                        throw new Exception("Error! part component cannot be a logical value");
                    }
                    // put the Object in the ht and break
                    $this->wfn[$attribute] = $value;
                    break;
                }
                if ($value == null || $value == ""){
                    // if value is null or blank, set attribute to default logical ANY
                    $this->wfn[$attribute] = new LogicalValue("ANY");
                    break;
                }
                $svalue = $value;
                // Reg exs
                // check for printable characters - no control characters
                if (!preg_match("/^[[:print:]]*$/", $svalue)){
                    throw new Exception("Error! encountered non printable character in: " . $svalue, 0);
                }
                // svalue has whitespace
                if (preg_match("/^.*\\s+.*$/", $svalue)){
                    throw new Exception("Error! component cannot contain whitespace: " . $svalue, 0);
                }
                // svalue has more than one unquoted star
                if (preg_match("/^\\*{2,}.*$/", $svalue) || preg_match("/^.*\\*{2,}$/", $svalue)){
                    throw new Exception("Error! component cannot contain more than one * in sequence: " . $svalue, 0);
                }
                // svalue has unquoted punctuation embedded
                if (preg_match("/^.*(?<!\\\\)[\\!\\\"\\#\\$\\%\\&\\'\\(\\)\\+\\,\\.\\/\\:\\;\\<\\=\\>\\@\\[\\]\\^\\`\\{\\|\\}\\~\\-].*$/", $svalue)) {
                    throw new Exception("Error! component cannot contain unquoted punctuation: " . $svalue, 0);
                }
                // svalue has an unquoted *
                if (preg_match("/^.+(?<!\\\\)[\\*].+$/", $svalue)) {
                    throw new Exception("Error! component cannot contain embedded *: " . $svalue, 0);
                }
                // svalue has embedded unquoted ?
                // this will catch a single unquoted ?, so make sure we deal with that
                if (strpos($svalue, "?") !== false) {
                    if ($svalue == "?") {
                        // single ? is valid
                        $this->wfn[$attribute] = $svalue;
                        break;
                    }
                    // remove leading and trailing ?s
                    $v = $svalue;
                    while (strpos($v, "?") === 0) {
                        // remove all leading ?'s
                        $v = substr($v, 1);
                    }
                    $v = strrev($v);
                    while (strpos($v, "?") === 0) {
                        // remove all trailing ?'s (string has been reversed)
                        $v = substr($v, 1);
                    }
                    // back to normal
                    $v = strrev($v);
                    // after leading and trailing ?s are removed, check if value
                    // contains unquoted ?s
                    if (preg_match("/^.+(?<!\\\\)[\\?].+$/", $v)) {
                        throw new Exception("Error! component cannot contain embedded ?: " . $svalue, 0);
                    }
                }

                // single asterisk is not allowed
                if ($svalue == "*") {
                    throw new Exception("Error! component cannot be a single *: " . $svalue, 0);
                }
                // quoted hyphen not allowed by itself
                if ($svalue == "-") {
                    throw new Exception("Error! component cannot be quoted hyphen: " . $svalue, 0);
                }
                // part must be a, o, or h
                if ($attribute == "part") {
                    if ($svalue != "a" && $svalue != "o" && $svalue != "h") {
                        throw new Exception("Error! part component must be one of the following: 'a', 'o', 'h': " . $svalue, 0);
                    }
                }
                // should be good to go
                $this->wfn[$attribute] = $svalue;
                break;
            }
        }
    }

    /**
     *
     * @return string representation of the WellFormedName
     */
    public function __toString() {
        $str = "wfn:[";
        foreach ($this->attributes as $attr) {
            $str = $str . $attr;
            $str = $str . "=";

            $o = $this->wfn[$attr];
            if ($o instanceof LogicalValue) {
                $str = $str . $o;
                $str = $str . ", ";
            } else {
                $str = $str . "\"";
                $str = $str . $o;
                $str = $str . "\", ";
            }
        }
        $str = substr($str, 0, strlen($str)-1);
        $str = substr($str, 0, strlen($str)-1);
        $str = $str . "]";

        return $str;
    }

}