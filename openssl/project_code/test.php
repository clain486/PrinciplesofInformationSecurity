<?php
	$con=new mysqli("127.0.0.1","test","12345");
	if(!$con){
		die('cound not connect: ' . mysql_error());
	}
	else{
		$con->query("SET NAMES 'utf8'");
		$con->select_db("scores");
		$result=$con->query("SELECT * FROM scorename");
		
		while($row=$result->fetch_assoc()){
			echo $row['name'] . " " . $row['score'];
			echo "<br />";
		}
	}
	mysql_close($con);
?>