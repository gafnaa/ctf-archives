# Critical Flight

Your team has assigned you to a mission to investigate the production files of Printed Circuit Boards for irregularities. This is in response to the deployment of nonfunctional DIY drones that keep falling out of the sky. The team had used a slightly modified version of an open-source flight controller in order to save time, but it appears that someone had sabotaged the design before production. Can you help identify any suspicious alterations made to the boards?

## Solution

Given many "gerber" files. 
View those using https://www.pcbway.com/project/OnlineGerberViewer.html

Archive those files in .zip and upload it

![gerber1](/hackthebox/tryout/assets/gerber1_fyylg2dnm.PNG)

Try to unview some layers to see clearly for each part. Then, I found part of the flag by only view "copper" in "bottom"

![gerber2](/hackthebox/tryout/assets/gerber2_o1geikpcx.PNG)

Do same thing as before, to find the other part of the flag.
Then, I found last part of flag by only view "copper" in "inner"

![gerber3](/hackthebox/tryout/assets/gerber3_w2qqh0enr.PNG)

Then, merge it and submit the flag

## Flag
    HTB{533_7h3_1nn32_w02k1n95_0f_313c720n1c5#$@}


 