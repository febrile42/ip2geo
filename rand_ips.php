<html>
<head></head>
<body><?php
for ($i=0; $i < 10000; $i++) { 
	$randip = long2ip(rand(0, "4294967295"));
	echo $randip . " ";
}

?>
</body>
</html>