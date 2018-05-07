<?php
namespace PacificSec\CPE\Matching;

/**
 * Class for relational values. It is based on Java version implemented by
 * Joshua Kraunelis <jkraunelis@mitre.org>.
 * 
 * @author Antonio Franco
 * @email antonio.franco@pacificsec.com
 */
class Relation {
	const DISJOINT = 1;
	const SUBSET = 2;
	const SUPERSET = 3;
	const EQUAL = 4;
	const UNDEFINED = 5;
}