<?php
	$con=new mysqli("127.0.0.1","test","12345"); 
	if(!$con){
		die("error:" . mysql_error());
	}
	else{
		$con->query("SET NAMES 'utf8'");
		$con->select_db("scores");
		$user=$_GET['user'];
		$pass=$_GET['pass'];
  		$sql='select * from scorename where name=' . "'$user' and score=" . "'$pass';";
		$res=mysqli_query($con,$sql);
		$row=mysqli_num_rows($res);
		if($row!=0){
			echo "<h1>sucessfully login welcome &nbsp{$user}</h1>";
		}
		else{
			echo "username or password is wrong";
		}
	}
	mysql_close($con);
?>