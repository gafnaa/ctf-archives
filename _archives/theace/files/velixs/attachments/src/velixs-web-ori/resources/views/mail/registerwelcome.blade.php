<!doctype html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">

<head>
    <title></title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>

<body>
    <div style="border: 1px dashed #ccc; padding: 20px; font-family: monospace;">
        <h1 style="font-size: 24px; margin-bottom: 20px;">😺 Selamat datang {{ $data->name }}</h1>
        <p style="font-size: 16px; margin-bottom: 20px;">Selamat bergabung di <a href="https://velixs.com">velixs.com</a>. akun anda sudah terdaftar silahkan melakukan login.</p>
        <br>
        <table width="95%" border="0" cellpadding="3" cellspacing="0">
            <tbody>
            <tr>
              <td width="14%">Email</td>
              <td width="1%">:</td>
              <td width="85%"><strong>{{ $data->email }}</strong></td>
            </tr>
            <tr>
              <td width="14%">Username</td>
              <td width="1%">:</td>
              <td width="85%"><strong>{{ $data->username }}</strong></td>
            </tr>
            <tr>
              <td>Password</td>
              <td>:</td>
              <td><strong>{{ $data->password }}</strong></td>
            </tr>
            <tr>
              <td>&nbsp;</td>
              <td>&nbsp;</td>
              <td valign="top"><em>Segera ganti password demi keamanan!</em></td>
            </tr>
            <tr>
              <td>&nbsp;</td>
              <td>&nbsp;</td>
              <td valign="bottom">Akun baru akan di hapus jika tidak login dalam 24 jam dari tanggal pendaftaran.</td>
            </tr>
          </tbody>
        </table>
        <br><br>
        <p style="font-size: 14px; margin-bottom: 0;">Jika Anda merasa ada hal yang dapat dibantu, silahkan hubungi kami melalui <a href="{{ route('contact') }}">Contact</a>.</p>
        <hr style="border: none; border-top: 1px dashed #ccc; margin-top: 20px; margin-bottom: 20px;">
        <p style="font-size: 12px;">&copy; 2022 - {{ now('Y') }} <a style="text-decoration:none; text-transform:none;" href="{{ route('main') }}">velixs.com</a></p>
    </div>
</body>

</html>
