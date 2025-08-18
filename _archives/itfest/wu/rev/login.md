# login


## Solusi

Tantangan ini adalah sebuah binary Linux 64-bit yang meminta kredensial berupa username dan password. Analisis pada fungsi main menunjukkan bahwa input dari pengguna akan dilewatkan ke dua fungsi verifikasi: verify_username dan verify_password. Jika kedua fungsi mengembalikan nilai true, program akan memberikan pesan sukses.

Kunci dari tantangan ini terletak pada dua fungsi transformasi: transform_user_char dan transform_pass_char.

transform_user_char(char, index): Fungsi ini mengubah setiap karakter dari username berdasarkan posisinya (indeks).

Jika indeks genap, karakter di-XOR dengan 5.

Jika indeks ganjil, karakter ditambah dengan 10.

transform_pass_char(char, index): Fungsi ini mengubah setiap karakter dari password berdasarkan sisa bagi (%) dari indeksnya dengan 4.

Jika index % 4 == 0, karakter ditambah 10.

Jika index % 4 == 1, karakter dikali 2.

Jika index % 4 == 2, karakter di-XOR dengan 7.

Jika index % 4 == 3, karakter ditambah 20.

Hasil dari transformasi ini kemudian dibandingkan dengan data yang sudah ada di dalam memori program, yaitu secret_data untuk username dan pass_matrix untuk password. Untuk menyelesaikan tantangan ini, kita harus membalik logika transformasi tersebut.

Mencari Data Rahasia dengan GDB
Karena secret_data dan pass_matrix tidak terlihat langsung di dalam kode, kita perlu mencarinya di memori saat program berjalan menggunakan debugger seperti GDB.

Mencari secret_data:

Kita memasang breakpoint pada fungsi verify_username (b verify_username).

Menjalankan program (run) dan memasukkan username dengan panjang 8 karakter (misal: aaaaaaaa).

Setelah program berhenti, kita melihat kode assembly dengan perintah disas. Di sana kita menemukan alamat secret_data dimuat ke dalam register.

0x...: lea 0x2ddb(%rip),%rax  # 0x555555558060 <secret_data>

Dengan alamat 0x555555558060, kita memeriksa isinya. Karena data disimpan sebagai integer (4-byte), kita menggunakan perintah x/8w 0x555555558060 untuk melihat 8 integer di dalamnya.

0x555555558060 <secret_data>: 0x4c 0x5e 0x43 0x4f 0x56 0x5e 0x37 0x3f

Mencari pass_matrix:

Prosesnya sama, kita memasang breakpoint di verify_password (b verify_password).

Melanjutkan eksekusi (continue) dan memasukkan password dengan panjang 40 karakter.

Perintah disas menunjukkan alamat dari pass_matrix.

0x...: lea 0x2d77(%rip),%rax  # 0x555555558080 <pass_matrix>

Kita memeriksa 40 integer di alamat 0x555555558080 dengan perintah x/40w 0x555555558080 dan mendapatkan semua nilainya.

Skrip Solver dan Flag Final
Setelah mendapatkan kedua set data tersebut, kita membuat skrip Python untuk membalikkan logika transformasi dan merekonstruksi kredensial yang benar.

### Data yang diekstrak dari GDB
secret_data = [
    0x4c, 0x5e, 0x43, 0x4f, 0x56, 0x5e, 0x37, 0x3f
]
pass_matrix = [
    0x2e, 0x84, 0x4e, 0x43, 0x48, 0x00, 0x43, 0x43,
    0x4e, 0x3e, 0x28, 0x4a, 0x49, 0x84, 0x30, 0x17,
    0x4e, 0x5e, 0x4e, 0x14, 0x4f, 0x84, 0x28, 0x39,
    0x4d, 0x6a, 0x45, 0x52, 0x0e, 0x7a, 0x32, 0x43,
    0x4a, 0x62, 0x02, 0x19, 0x51, 0x7e, 0x45, 0x48
]

### Fungsi untuk membalikkan transformasi username
def reverse_transform_user_char(char_code, index):
    if (index & 1) != 0: return char_code - 10
    else: return char_code ^ 5

### Fungsi untuk membalikkan transformasi password
def reverse_transform_pass_char(char_code, index):
    mod = index % 4
    original_val = 0
    if mod == 0: original_val = char_code - 10
    elif mod == 1: original_val = char_code // 2
    elif mod == 2: original_val = char_code ^ 7
    elif mod == 3: original_val = char_code - 20
    return original_val + 48

### Rekonstruksi username dan password
username = "".join([chr(reverse_transform_user_char(c, i)) for i, c in enumerate(secret_data)])
password = "".join([chr(reverse_transform_pass_char(c, i)) for i, c in enumerate(pass_matrix)])

print(f"Username: {username}")
print(f"Password: {password}")

Setelah menjalankan skrip di atas, kita mendapatkan kredensial yang benar:

Username: ITFEST25

Password: Try_n0t_tO_forg3t_y0ur_Usern4me_pa55word

Dengan menggabungkan keduanya, kita mendapatkan flag final.

## Flag
    ITFEST25{Try_n0t_tO_forg3t_y0ur_Usern4me_pa55word}
