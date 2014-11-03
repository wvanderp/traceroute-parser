<?php
	include("../parser.php");
	$file = file_get_contents("tracerout.txt");
	var_dump(parse($file));
?>
