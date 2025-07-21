<!doctype html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">

<head>
    <title></title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>

<body>
    <div style="border: 1px dashed #ccc; padding: 20px; font-family: monospace; text-align: center;">
        <h1 style="font-size: 24px; margin-bottom: 20px;">😹 Forgot Password</h1>
        <p style="font-size: 16px; margin-bottom: 20px;">It seems that you’ve forgotten your password.</p>
        <br>
        <a href="{{ $data->url }}" style="text-decoration:none; text-transform:none; padding: 5px 10px 5px 10px; border: 1px dashed;">Change Password!</a>
        <br><br>
        <p style="font-size: 14px; margin-bottom: 0;">If you did not make this request, just ignore this email. Otherwise please click the button above to reset your password.</p>
        <hr style="border: none; border-top: 1px dashed #ccc; margin-top: 20px; margin-bottom: 20px;">
        <p style="font-size: 12px;">&copy; 2022 - {{ now()->format('Y') }} <a style="text-decoration:none; text-transform:none;" href="https://velixs.com">velixs.com</a></p>
    </div>
</body>

</html>
