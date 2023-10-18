<?php
$p = @$_GET['p'];
ob_start();
$pagesize = 2048;
?>
<!doctype html>
<html>
<head>
<title>Virtual Network Lab</title>
<?php
if ($p=='photo') {
?>
<style type="text/css">
img { border-radius:10px; }
</style>
<?php
}
?>
</head>
<body>
<h1>Virtual Network Lab</h1>

<?php
switch ($p) {
	case 'photo':
?>
<h2>Check out these photos.</h2>
<?php
		$album = array(
			'4602'=>'Arizona-Sonora Desert Museum, Tucson, AZ',
			'4887'=>'South Kaibab Trail, Grand Canyon, AZ',
			'4498'=>'Don Hummel Park, Tucson, AZ',
			'5919'=>'Venice Beach, Venice, CA',
			'5491'=>'Palace of Fine Arts, San Francisco, CA',
		);
		uksort($album,function($x,$y){return mt_rand(-1,1);});
		foreach ($album as $photo=>$info) {
			printf('<p><img src="%s.jpg" alt=""/><br/>%s</p>'."\n",$photo,$info);
		}
?>
<p>All photos taken by <a href="http://www.cs.arizona.edu/people/shijunxiao/">Junxiao Shi</a>. Distributed under Creative Commons BY-NC 3.0 license.</p>
<?php
		break;
	case 'music': ?>
<h2>Enjoy the music.</h2>
<p>Stephen Foster - Beautiful Dreamer</p>
<div><audio src="beautiful-dreamer.mp3" controls="controls" autoplay="autoplay"/></div>
<p>This music is in public domain. You can <a href="beautiful-dreamer.mp3">download MP3 file</a>.</p>
<?php
		break;
	case 'upload':
		$file = $_FILES['u'];
		if (!$file || $file['size']<1) printf("<h2>No file uploaded.</h2>\n");
		else printf("<h2>I got your file.</h2>\n<p>%s, %d bytes, SHA1 hash is %s.<br/>The content is saved to /dev/null.</p>\n",htmlspecialchars($file['type']),$file['size'],sha1_file($file['tmp_name']));
		break;
	default: ?>
<h2>You made it.</h2>
<p>This page (2KB) is served from VNL host <?php echo $_SERVER['SERVER_ADDR'].':'.$_SERVER['SERVER_PORT']; ?> in your topology.<br/>
You are requesting from <?php echo $_SERVER['REMOTE_ADDR'].':'.$_SERVER['REMOTE_PORT']; ?> at <?php echo date('Y-m-d H:i:s',$_SERVER['REQUEST_TIME']); ?>.</p>

<h2>What to do next?</h2>
<ul>
<li>browse a <a href="?p=photo">photo album</a> (0.4MB)</li>
<li>access a FTP site <kbd>ftp -p <?php echo $_SERVER['SERVER_ADDR']; ?> 16221</kbd> (PASV mode only)</li>
<li>listen to <a href="?p=music">music</a> (3.6MB)</li>
<li>play with a UDP service <kbd>nc -u -p 16207 <?php echo $_SERVER['SERVER_ADDR']; ?> 16207</kbd> (type one or more numbers separated by space, press ENTER, and you'll get the sum)</li>
<li>upload a file <form action="?p=upload" style="display:inline;" method="post" enctype="multipart/form-data"><span><input type="file" name="u"/><input type="submit" value="UPLOAD"/> (4MB max)</span></form></li>
<li>download a file <kbd>wget http://<?php echo $_SERVER['SERVER_ADDR'].':'.$_SERVER['SERVER_PORT']; ?>/64MB.bin -O/dev/null</kbd> (also available: 1MB.bin 2MB.bin 4MB.bin 8MB.bin 16MB.bin 32MB.bin)</li>
</ul>
<?php
		break;
}
?>
</body>
</html>
<?php
$b = ob_get_clean();
$b .= '<!--'.str_repeat('*',$pagesize-7-strlen($b)).'-->';
header('Content-Length: '.strlen($b));
echo $b;
?>
