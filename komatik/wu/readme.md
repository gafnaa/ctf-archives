---
title: "Liga Komatik 2025 - Writeup"
description: ""
pubDate: 2025-07-13 21:00
slug: "ligakomatik-wu"
---

## team : Satpam Digital

- [Web](#web)
- [Rev](#rev)
- [Foren](#foren)
- [Pwn](#pwn)

## Web

### Pay me 2 win

<img width="434" height="352" alt="image" src="https://github.com/user-attachments/assets/6d405bb0-b64c-462f-94f3-79ffe7ef385d" />

Buka link yang tersedia, dan ditemukan potongan source code (index.php) berikut

<img width="571" height="219" alt="image" src="https://github.com/user-attachments/assets/990fdc00-7135-4831-8eb7-3382cecccb0f" />

Terdapat hint yang diberikan di bagian komentar, mengikuti petunjuk pada komentar, kita
mengunjungi alamat berikut:
http://ctf.asgama.online:40003/?is_debug=1
Setelah dibuka lalu di scroll ke bawah, ditemukan potongan suatu source code PHP berikut:

<img width="606" height="372" alt="image" src="https://github.com/user-attachments/assets/c7b3cc5c-118e-4455-8189-f8879af6bfe7" />

Dari potongan kode di atas, kita bisa menyimpulkan:

- Input money dikirim melalui metode POST.
- Nilai money harus merupakan digit numerik (ctype_digit).
- Kemudian, nilai tersebut dijumlahkan dengan 0x1337 (atau 4919 dalam desimal), dan
  dibandingkan apakah hasilnya === 0.
- Jika kondisi ini terpenuhi, maka flag akan ditampilkan.

Namun, karena ctype_digit() hanya menerima angka positif tanpa tanda minus, kita tidak bisa
langsung mengirim nilai -0x1337 untuk membuat hasil akhir menjadi nol. Solusi untuk ini adalah
mengirim nilai overflow yang jika ditambahkan dengan 0x1337 menghasilkan nol saat dikonversi
ke tipe int.
Untuk mengakali pengecekan ctype_digit, kita manfaatkan integer overflow. Nilai money yang
kita kirim adalah:
18446744073709546697
Nilai ini merupakan hasil dari:

<img width="601" height="33" alt="image" src="https://github.com/user-attachments/assets/adc0e849-cec7-41c3-8105-5c1fc2e25107" />

Ketika nilai ini dikonversi ke int dalam konteks 64-bit integer overflow, hasil akhirnya adalah
-0x1337, sehingga:

```py
(int)($money+0x1337)===0
```

Kemudian, untuk memudahkan proses exploitasi, kita menggunakan burpsuite untuk mengubah
request value.

<img width="505" height="780" alt="image" src="https://github.com/user-attachments/assets/5b44d62d-3398-40e1-a53a-d84971fcb156" />

### Flag

```
LK25{w0w_ez_0v3rfl0w}
```

## Rev

### Baby rev

<img width="402" height="309" alt="image" src="https://github.com/user-attachments/assets/13f193e3-cb16-4fd8-93c5-73b6a8b71160" />

Unduh file baby_rev tersebut.
Lakukan command file untuk mendapatkan informasi mengenai ekstensi file
Artinya, file ini merupakan file executable 64-bit Linux (ELF 64-bit).
Langkah cepat pertama dalam reverse engineering adalah mencoba melihat string literal di dalam
binary tersebut, yaitu dengan command berikut:

<img width="609" height="56" alt="image" src="https://github.com/user-attachments/assets/73e334c2-83c7-4852-a3ad-3edacf782235" />

### Flag

```
LK25{just_0p3n_th1s_1n_n0t3p4d}
```

### No symbols

<img width="413" height="340" alt="image" src="https://github.com/user-attachments/assets/9365d2ae-936d-461d-8558-8fb6a8a743ff" />

Kita diberikan sebuah file binary (no_symbols) yang meminta input:

<img width="612" height="67" alt="image" src="https://github.com/user-attachments/assets/69cb9170-c933-43ed-af14-f6f1b071a22b" />

Tujuannya adalah menemukan flag yang benar.
Setelah membuka file ini di disassembler, kami menemukan fungsi seperti ini:

<img width="370" height="81" alt="image" src="https://github.com/user-attachments/assets/a9c9c826-b803-4112-9f25-6b04bcd01447" />

Artinya:

- Program membaca 51 karakter input dari user ke dalam array v13.
- Tiap karakter akan di-XOR dengan 0x14 (heksadesimal untuk 20 desimal).
- Hasil XOR dibandingkan dengan array v12, yang sudah ditentukan di awal program.
- Jika semua cocok, maka input dianggap sebagai flag yang benar.

Untuk mencari flag yang benar, kita cukup membalik operasi XOR yang digunakan dalam
program.

Di dalam file binary tersebut terdapat sebuah fungsi yang berisi array konstanta (disebut v12
dalam pseudocode hasil disassembly). Program akan membaca 51 karakter dari input pengguna,
kemudian melakukan operasi XOR setiap karakter dengan 0x14 (heksadesimal untuk 20 desimal),
lalu hasilnya dibandingkan dengan elemen-elemen di array tersebut.

<img width="610" height="401" alt="image" src="https://github.com/user-attachments/assets/56ac9a26-59a3-4caa-bc56-5a26479b63cc" />

Kemudian, kita menggunakan script berikut untuk membantu

<img width="283" height="131" alt="image" src="https://github.com/user-attachments/assets/e269c9cd-1bb1-420f-bd11-17e8c129159b" />

Penjelasan dari kode tersebut:
● v12 adalah array yang ada di dalam binary yang digunakan untuk membandingkan input.
● Di dalam program, input user di-XOR dengan 0x14, lalu dibandingkan dengan elemen di
v12.
● Untuk mendapatkan input yang benar (flag), kita cukup membalik proses itu: karakter =
elemen ^ 0x14.
● Script ini mengembalikan flag yang tepat setelah proses XOR dibalik.
Terakhir, tinggal jalankan program tersebut untuk mendapatkan flag

### Flag

```
LK25{remov1ng_symb0l_table5_is_4_comm0n_rev_tr1ck}
```

### XOR

<img width="361" height="275" alt="image" src="https://github.com/user-attachments/assets/d2005a0a-18d4-4280-b1d7-e9af5a00ebde" />

Kita diberikan sebuah file binary (xor) yang meminta input

<img width="542" height="108" alt="image" src="https://github.com/user-attachments/assets/014bea7c-4e17-4ff1-9a70-e9575223b669" />

Kemudian, kita membuka program tersebut menggunakan Ghidra untuk melakukan proses
dekompilasi. Didapatkan fungsi berikut:

<img width="490" height="398" alt="image" src="https://github.com/user-attachments/assets/7a6d4bb2-73ef-4f7f-acfc-4474497a4128" />
<img width="551" height="575" alt="image" src="https://github.com/user-attachments/assets/db5435d3-d0ff-499a-a3c9-3f151aa0186e" />

Analisis program:

- Terdapat sebuah string panjang berisi karakter acak:
  "asdghkashdfclkamsdfjalxsdkjfxhcaksvjnalsckuqpoiewt"
- Program memilih beberapa karakter dari string tersebut dengan pola tertentu, lalu
  menyimpannya ke dalam variabel local_148. Karakter-karakter ini nantinya akan
  digunakan sebagai hasil pembanding akhir.
- Password yang dimasukkan pengguna akan di-XOR satu per satu dengan nilai dari array
  local_e8. Hasilnya kemudian disimpan di variabel local_108.
- Program akan membandingkan local_108 (hasil XOR dari input) dengan local_148. Jika
  sama, berarti password benar.

Karena kita tahu hasil akhirnya (local_148) dan kunci XOR-nya (local_e8), maka kita bisa
membalik prosesnya. Berikut program yang kita buat untuk membantu.

<img width="556" height="214" alt="image" src="https://github.com/user-attachments/assets/e5ef9157-6f37-4d00-a2cb-7d12a5994220" />

Dalam program ini, program meminta user memasukkan password sepanjang 50 karakter.
Password tersebut akan di-XOR satu per satu dengan array kunci (local_e8) dan hasilnya
dibandingkan dengan string acuan (local_148) yang dibentuk dari string local_168. Jika hasil
XOR cocok, maka password benar dan ditampilkan flagnya.

<img width="554" height="58" alt="image" src="https://github.com/user-attachments/assets/bf6e0152-9c04-419b-ab26-bd38e49969fb" />

### Flag

```
LK25{remov1ng_symb0l_table5_is_4_comm0n_rev_tr1ck}
```

## Foren

### run_me.png

<img width="400" height="331" alt="image" src="https://github.com/user-attachments/assets/ff046516-a630-4b61-b9eb-3763013379f3" />

Pada challenge ini, kita diberikan sebuah program Python yang menyimpan data biner ke dalam
sebuah gambar PNG

<img width="529" height="167" alt="image" src="https://github.com/user-attachments/assets/822849ee-366c-4a0b-97f6-f90b7b6d01ad" />

Program ini mengonversi isi file main menjadi sebuah gambar dengan cara mengemas setiap 3
byte sebagai satu warna pixel. Gambar yang dihasilkan menyimpan semua informasi dari file asli
dalam bentuk visual. Teknik ini memungkinkan file biner disembunyikan atau ditransmisikan
melalui file gambar.

<img width="349" height="177" alt="image" src="https://github.com/user-attachments/assets/05f12bf9-7c41-4f29-87e6-cca409219271" />

Setelah kita tahu bahwa program pertama menyimpan isi file main ke dalam gambar hidden.png
dengan cara mengubah setiap 3 byte menjadi satu warna pixel (RGB), maka langkah berikutnya
adalah mengembalikan data tersebut ke bentuk semula. Program kedua atau program solver
digunakan untuk tujuan ini. Program tersebut akan membuka gambar hidden.png, lalu membaca
setiap pixel satu per satu. Nilai warna merah, hijau, dan biru dari setiap pixel dikumpulkan kembali menjadi urutan byte. Seluruh byte tersebut kemudian disatukan dan disimpan dalam file baru bernama extracted_main, yang merupakan hasil rekonstruksi dari file main sebelum dikonversi ke gambar.

Penjelasan program:

- Membuka gambar hidden.png menggunakan library Pillow (PIL) untuk dibaca pixel-nya.
- Mengambil ukuran gambar (lebar dan tinggi) untuk menentukan seberapa banyak pixel
  yang harus dibaca.
- Melakukan iterasi terhadap setiap pixel dari kiri ke kanan, atas ke bawah.
- Membaca nilai RGB dari setiap pixel dan menggabungkan ketiganya sebagai tiga byte
  data.
- Mengumpulkan semua byte ke dalam satu bytearray, sehingga membentuk kembali data
  asli yang sebelumnya dikonversi.
- Menyimpan hasil ekstraksi ke dalam file extracted_main dalam mode biner (wb), sebagai
  hasil rekonstruksi file asli.

Terakhir, tinggal cek isi file extracted_main untuk melihat flagnya

### Flag

```
LK25{i_think_the_output_is_kinda_cool}
```

## Pwn

### redirection

<img width="390" height="322" alt="image" src="https://github.com/user-attachments/assets/f6290939-e008-430a-9efe-f89b7a93057d" />

Kita diberikan link untuk connect ke server:
Kita juga diberikan sebuah file binary (redirection) yang merupakan source code dari chall ini.
Kemudian, kita membuka program tersebut menggunakan IDA untuk melakukan proses
dekompilasi dan analisis alur program.

<img width="536" height="97" alt="image" src="https://github.com/user-attachments/assets/6bc5f569-8055-4446-8c29-992cdc091b9d" />
<img width="360" height="263" alt="image" src="https://github.com/user-attachments/assets/d54b3811-77f4-4f1a-9d75-d2d88bd67c02" />

Penjelasan file:

- Fungsi main() memanggil vulnerable() dengan parameter:
  <img width="269" height="27" alt="image" src="https://github.com/user-attachments/assets/d54ff819-2844-4a4f-b57a-b90c4374fd77" />

- Fungsi vulnerable() melakukan hal-hal berikut
- Membaca file flag.txt
- Menyimpan isinya ke dalam buffer flag yang ada di .bss
- Meminta input user dengan scanf("%s", v1) di buffer berukuran 32 byte
- Buffer v1 dialokasikan di stack sebesar 32 byte → rawan buffer overflow
- Binary tidak menggunakan PIE, jadi alamat flag bisa diprediksi

Dengan informasi ini, kita tahu bahwa kita bisa melakukan buffer overflow untuk menimpa return
address dan menjalankan ROP chain agar memanggil puts(flag) dan mencetak flag ke layar.

<img width="475" height="303" alt="image" src="https://github.com/user-attachments/assets/bdd67c2d-58ed-433a-9587-9788402f2784" />

Penjelasan Program:

- Kita menggunakan pwntools untuk meng-handle koneksi dan pengiriman payload.
- Payload dibuat dengan overflow sebanyak 40 byte (b"A"\*40) untuk mencapai return
  address.
- pop rdi; ret digunakan untuk mengatur argumen pertama fungsi puts(), yaitu alamat
  buffer flag.
- Lalu kita panggil puts@plt dengan argumen flag.
- Tambahan ret (0x40101a) digunakan untuk stack alignment jika dibutuhkan oleh sistem
  tertentu (misal glibc modern).

Dengan menggunakan teknik buffer overflow dan ROP sederhana ini, kita berhasil mendapatkan
flag dari binary yang diberikan.

### Flag

```
LK25{flow_redirection_is_similar_to_ret2win}
```
