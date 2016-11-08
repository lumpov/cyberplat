<?php

$sec = file_get_contents('../test/secret.key');
$pub = file_get_contents('../test/pubkeys.key');
$passwd = '1111111111';

$res = ipriv_sign("Hello world", $sec, $passwd);
print "Sign: $res[0]\n";
if (!$res[0]) {
    print("\nresult:\n$res[1]\n");
	$res = ipriv_verify($res[1], $pub, 17033);
	print "\n";
	print "Verify: $res[0]\n";
	if (!$res[0])
    	print("\nresult:\n$res[1]\n");
}
print "-----------------------\n";


$res = ipriv_encrypt("Hello, world!", $pub, 17033);
print "Encrypt: $res[0]\n";
if ($res[0] > 0) {
    print("\nresult:$res[1]\n");
	$res = ipriv_decrypt($res[1], $sec, $passwd);
	print "\n";
	print "Decrypt: $res[0]\n";
	if ($res[0] > 0)
	    print("\nresult:$res[1]\n");
}
print "-----------------------\n";


$res = ipriv_sign2("Hello world", $sec, $passwd);
print "Sign2: $res[0]\n";
if (!$res[0]) {
    print("\nresult:\n$res[1]\n");
	print "\n";
	$res = ipriv_verify2("Hello world", $res[1], $pub, 17033);
	print "Verify2: $res[0]\n";
}
print "-----------------------\n";

?>
