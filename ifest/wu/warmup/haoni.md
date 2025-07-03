# haoni

## Desc

## Solution

Diberikan file `main`

Hasil ketika di run
```
> ./main
Enter the flag:
```

ok, sekarang coba buka file tersebut pake Ghidra/IDA buat decompile programnya.

Setelah didecompile didapatkan 2 fungsi buat generate flagnya:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4[112]; // [rsp+0h] [rbp-70h] BYREF

  printf("Enter the flag: ");
  __isoc99_scanf("%99s", v4);
  if ( (unsigned int)sub_401166(v4) )
    puts("Correct! Here's your flag!");
  else
    puts("Wrong flag. Try again.");
  return 0LL;
}
```

```c
__int64 __fastcall sub_401166(const char *a1)
{
  _DWORD v2[7]; // [rsp+10h] [rbp-20h]
  int i; // [rsp+2Ch] [rbp-4h]

  if ( strlen(a1) != 14 )
    return 0LL;
  if ( strncmp(a1, "IFEST13{", 8uLL) )
    return 0LL;
  v2[0] = 102;
  v2[1] = 96;
  v2[2] = 98;
  v2[3] = 106;
  v2[4] = 99;
  v2[5] = 112;
  for ( i = 8; i <= 13; ++i )
  {
    if ( (i ^ a1[i]) != v2[i - 8] )
      return 0LL;
  }
  return 1LL;
}
```

Program tersebut meminta pengguna untuk memasukkan flag dan akan memverifikasi apakah flag yang dimasukkan benar dengan memanggil fungsi `sub_401166`.

Syarat dari `sub_401166`:
- Panjang string harus 14 karakter.
- Awal string harus "IFEST13{" (8 karakter pertama).
- Karakter ke-9 sampai ke-14 (a1[8] sampai a1[13]) harus memenuhi:
  `(i ^ a1[i]) == v2[i - 8]`

Nilai `v2` :
```c
v2[0] = 102; // i = 8
v2[1] = 96;  // i = 9
v2[2] = 98;  // i = 10
v2[3] = 106; // i = 11
v2[4] = 99;  // i = 12
v2[5] = 112; // i = 13
```

Untuk setiap i, kita gunakan:
```c
a1[i] = i ^ v2[i - 8]
```

Mari kita hitung:
```
i = 8: a1[8] = 8 ^ 102 = 110 = 'n'
i = 9: a1[9] = 9 ^ 96 = 105 = 'i'
i = 10: a1[10] = 10 ^ 98 = 104 = 'h'
i = 11: a1[11] = 11 ^ 106 = 97 = 'a'
i = 12: a1[12] = 12 ^ 99 = 111 = 'o'
i = 13: a1[13] = 13 ^ 112 = 125 = '}'
```

Tinggal gabungin dan kita dapet flagnya!

## Flag
    IFEST13{nihao}
