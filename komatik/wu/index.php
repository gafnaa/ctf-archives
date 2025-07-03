<?php
include('secret.php');
?>
<?php
if(isset($_POST['money']) && !empty($_POST['money']))
{
    $money=$_POST['money'];
    if(ctype_digit($money))
    {
        if((int)($money+0x1337)===0)
        {
            die('<center>Money is just a number! flag > all. Here your flag: <br><font size=5 color=red><strong>'.$flag.'</strong></font></center>');
        }
        else
        {
            die("<strong><center>Sadly, We don't have enough money to give at this time :(</center></strong>");
        }
    }
    else
    {
        die('<strong><center>2k vinoy monkey?</center></strong>');
    }
}
if(isset($_GET['is_debug']) && !empty($_GET['is_debug']) && $_GET['is_debug']==="1")
{
    show_source(__FILE__);
}
?>
<!-- From tsu with l0v3: ?is_debug=1 -->