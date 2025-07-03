# Hidden Path

Legends speak of the infamous Kamara-Heto, a black-hat hacker of old who rose to fame as they brought entire countries to their knees. Opinions are divided over whether the fabled figure truly existed, but the success of the team surely lies in the hope that they did, for the location of the lost vault is only known to be held on what remains of the NSA's data centres. You have extracted the source code of a system check-up endpoint - can you find a way in? And was Kamara-Heto ever there?

## Solution

Open the link and we can see the web

![hidenpath](/hackthebox/tryout/assets/hidenpath.PNG)

We see a simple web application that appears to be a server status checking system

Look up on source code to gaining information.
then, we get this leak..

```js
app.post('/server_status', async (req, res) => {
    const { choice,ㅤ} = req.body;
    const integerChoice = +choice;
    
    if (isNaN(integerChoice)) {
        return res.status(400).send('Invalid choice: must be a number');
    }

    const commands = [
        'free -m',
        'uptime',
        'iostat',
        'mpstat',
        'netstat',
        'ps aux',ㅤ
    ];

    if (integerChoice < 0 || integerChoice >= commands.length) {
        return res.status(400).send('Invalid choice: out of bounds');
    }
```

There is a hidden character in the line `const {choice, } = req.body:` This same symbol also appears in the `command` list, which indicates which commands we are allowed to run on the server.

We can pass a *some-command* value to that character variable, and it will end up in the list of allowed commands.

In my Burp Repeater, I tried several requests with different values, and after some trials, I got this response:

![hidep](/hackthebox/tryout/assets/hidep.PNG)

We can pass another parameter with name of `ㅤ`, value of our new command, and execute it with choice=6. RCE is officially found! Now it's just a matter of exposing the flag

![hide](/hackthebox/tryout/assets/hide.PNG)

## Flag
    HTB{1nvi5IBl3_cH4r4cT3rS_n0t_sO_v1SIbL3_d562b60ae1f777d5da6d87fd5f789af4}