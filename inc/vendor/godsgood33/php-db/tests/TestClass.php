<?php

class TestClass
{

    var $var;

    public function _escape()
    {
        return str_replace([
            "\n",
            "\r",
            "\\",
            "'",
            '"'
        ], [
            "\\n",
            "\\r",
            "\\\\",
            "\'",
            '\"'
        ], $this->var);
    }
}