<?php

/**
 * File: validation.inc
 * Author: Ryan Prather
 * Purpose: This class will contain all the validation routines that are necessary for the program
 * Created: Oct 14, 2013
 *
 * Portions Copyright 2016-2017: Cyber Perspectives, LLC, All rights reserved
 * Released under the Apache v2.0 License
 *
 * Portions Copyright (c) 2012-2015, Salient Federal Solutions
 * Portions Copyright (c) 2008-2011, Science Applications International Corporation (SAIC)
 * Released under Modified BSD License
 *
 * See license.txt for details
 *
 * Change Log:
 *  - Oct 14, 2013 - File created
 *  - Jun 5, 2017 - Removed unnecessary elements and added validation for IPv4 addresses
 */

/**
 *
 * @author Ryan Prather
 *
 */
class validation {

  /**
   * Constant regular expression to validate MySQL formated dates
   *
   * @var string
   */
  const DATE_FORMAT = "/Y\-m\-d/";

  /**
   * Constant regular expression to validate MySQL formatted time
   *
   * @var string
   */
  const TIME_FORMAT = "/H\:i\:s/";

  /**
   * Constant regular expression to validate MySQL formatted DateTime
   *
   * @var string
   */
  const DATETIME_FORMAT = "/Y\-m\-d H\:i\:s/";

  /**
   * Constant regular expression to validate US phone numbers
   *
   * @var string
   */
  const PHONE_FORMAT = "/\(?\d{3}\)?[\ \-]\d{3}\-\d{4}/";

  /**
   *
   * @param string $string
   *    The string to evaluate
   * @param int $min [optional]
   *    The minimum length of string allowed
   * @param int $max [optional]
   *    The maximum length of string allowed
   *
   * @return boolean
   *    Returns TRUE if a valid string (and within min and max length), otherwise FALSE
   */
  public static function valid_string($string, $min = null, $max = null) {
    if (!is_string($string)) {
      return false;
    }

    if (!is_null($min) && strlen($string) < $min) {
      return false;
    }

    if (!is_null($max) && strlen($string) > $max) {
      return false;
    }

    return true;
  }

  /**
   * Function to validate an integer
   *
   * @param int $int
   *    The integer to evaluate
   * @param int $min [optional]
   *    The minimum value allowed
   * @param int $max [optional]
   *    The maximum value allowed
   *
   * @return boolean
   *    Returns TRUE if a valid integer (and within min and max if passed), otherwise FALSE
   */
  public static function valid_int($int, $min = null, $max = null) {
    if (!is_int($int)) {
      return false;
    }
    if ($min > 0 && $int < $min) {
      return false;
    }
    if ($max > 0 && $int > $max) {
      return false;
    }
    return true;
  }

  /**
   * Function to validate a date/time/datetime value
   *
   * @param DateTime|string $date
   *    The date to evaluate (can be a DateTime object or string that the DateTime class can parse without special instructions)
   * @param DateTime $min [optional]
   *    The minimum date allowed
   * @param DateTime $max [optional]
   *    The maximum date allowed
   *
   * @return boolean
   *    Returns TRUE if it is a valid date and within optional min and max values
   */
  public static function valid_date($date, $min = null, $max = null) {
    try {
      $dt = new DateTime($date);
    }
    catch (Exception $ex) {
      return false;
    }

    if (!is_null($min) && is_a($min, 'DateTime') && $dt < $min) {
      return false;
    }

    if (!is_null($max) && is_a($max, 'DateTime') && $dt > $max) {
      return false;
    }

    return true;
  }

  /**
   * Function to validate a floating point number
   *
   * @param float $float
   *    The value to evaluate
   * @param float $min [optional]
   *    The minimum value for the float
   * @param float $max [optional]
   *    The maximum value for the float
   *
   * @return boolean
   *    Returns TRUE if it is a valid float value (within min and max if passed)
   */
  public static function valid_float($float, $min = null, $max = null) {
    if (!is_float($float)) {
      return false;
    }
    if ($min > 0.0 && $float < $min) {
      return false;
    }
    if ($max > 0.0 && $float > $max) {
      return false;
    }
    return true;
  }

  /**
   * Function to validate an email address
   *
   * @param string $email
   *    Email address to evaluate
   *
   * @return boolean
   *    Returns TRUE if valid email address, otherwise FALSE
   */
  public static function valid_email($email) {
    $atIndex = strrpos($email, "@");
    if (is_bool($atIndex) && !$atIndex) {
      return false;
    }
    else {
      $domain = substr($email, $atIndex + 1);
      $local = substr($email, 0, $atIndex);
      $localLen = strlen($local);
      $domainLen = strlen($domain);
      if ($localLen < 1 || $localLen > 64) {
        // local part length exceeded
        return false;
      }
      else if ($domainLen < 1 || $domainLen > 255) {
        // domain part length exceeded
        return false;
      }
      else if ($local[0] == '.' || $local[$localLen - 1] == '.') {
        // local part starts or ends with '.'
        return false;
      }
      else if (preg_match('/\\.\\./', $local)) {
        // local part has two consecutive dots
        return false;
      }
      else if (!preg_match('/^[A-Za-z0-9\\-\\.]+$/', $domain)) {
        // character not valid in domain part
        return false;
      }
      else if (preg_match('/\\.\\./', $domain)) {
        // domain part has two consecutive dots
        return false;
      }
      else if (!preg_match('/^(\\\\.|[A-Za-z0-9!#%&`_=\\/$\'*+?^{}|~.-])+$/', str_replace("\\\\", "", $local))) {
        // character not valid in local part unless
        // local part is quoted
        if (!preg_match('/^"(\\\\"|[^"])+"$/', str_replace("\\\\", "", $local))) {
          return false;
        }
      }

      if (!(checkdnsrr($domain, "MX") || checkdnsrr($domain, "A"))) {
        // domain not found in DNS
        return false;
      }
    }

    return true;
  }

  /**
   * Function to validate a North American phone number
   *
   * @param string $phone
   *    The phone number to evaluate
   *
   * @return boolean
   *    Return TRUE if it is a valid US/CA phone number
   */
  public static function valid_phone($phone) {
    if (!preg_match(self::PHONE_FORMAT, $phone)) {
      return false;
    }

    return true;
  }

  /**
   * Function to make sure that an IP is valid
   *
   * @param string $ip
   *    The IPv4 address to evaluate
   *
   * @return boolean
   *    Returns TRUE if it is a valid IPv4 address, otherwise FALSE
   */
  public static function valid_ip($ip) {
    if (!preg_match("/((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))|(^\s*((?=.{1,255}$)(?=.*[A-Za-z].*)[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?)*)\s*$)/", $ip)) {
      return false;
    }

    return true;
  }

}
