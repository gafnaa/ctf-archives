# POST Practice

This website requires authentication, via POST. However, it seems as if someone has defaced our site. Maybe there is still some way to authenticate? http://165.227.106.113/post.php

## Solution

found source code on the website

```html
<h1>This site takes POST data that you have not submitted!</h1>
<!-- username: admin | password: 71urlkufpsdnlkadsf -->
```
we have to send post to that website.

```sh
$ curl -X POST http://165.227.106.113/post.php -d "username=admin&password=71urlkufpsdnlkadsf"
<h1>flag{p0st_d4t4_4ll_d4y}</h1>
```

## Flag
    CTFlearn{p0st_d4t4_4ll_d4y}
