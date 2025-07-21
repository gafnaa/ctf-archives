@extends('layouts.admin.main')

@section('title', 'Edit Users')

@section('content')
<form id="form-update-profile" action="{!! route('admin.users.update',$user->id) !!}" enctype="multipart/form-data">
    @csrf
    <div class="card mb-3">
        <div class="card-body p-2">
            <div class="d-flex justify-content-end">
                <button class="btn btn-label-primary me-2 d-flex justify-content-center justify-items-center" name="button_submit" value="update" type="submit">
                    <svg xmlns="http://www.w3.org/2000/svg" class="me-2" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                        <path d="M7 18a4.6 4.4 0 0 1 0 -9a5 4.5 0 0 1 11 2h1a3.5 3.5 0 0 1 0 7h-1"></path>
                        <path d="M9 15l3 -3l3 3"></path>
                        <path d="M12 12l0 9"></path>
                    </svg>Update
                </button>
                <button class="btn btn-primary" name="button_submit" value="update and exit" type="submit">
                    <svg xmlns="http://www.w3.org/2000/svg" class="me-2" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                        <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                        <path d="M17 11h1c1.38 0 3 1.274 3 3c0 1.657 -1.5 3 -3 3l-6 0v-10c3 0 4.5 1.5 5 4z"></path>
                        <path d="M9 8l0 9"></path>
                        <path d="M6 17l0 -7"></path>
                        <path d="M3 16l0 -2"></path>
                    </svg>Update &amp; Exit
                </button>
            </div>
        </div>
    </div>
    <div class="row">
        <div class="col-12 col-xl-4 col-lg-4">
            <div class="card mb-4">
                <div class="card-body">
                    <div class="user-avatar-section">
                        <div class="d-flex align-items-center flex-column">
                            <img id="preview-avatar" class="img-fluid mb-3 pt-1 mt-4" src="{!! $user->_avatar() !!}" height="100" width="100" alt="User avatar" style="border-radius: 50%">
                        </div>
                    </div>
                    <div class="info-container">
                        <div class="d-flex justify-content-center gap-2">
                            <label class="btn btn-label-primary suspend-user waves-effect" for="account-upload">
                                <input id="account-upload" name="avatar" accept="image/*" type="file" tabindex="-1" style="display: none;">
                                Change Avatar
                            </label>
                        </div>
                        <ul class="list-unstyled mb-4 mt-3">
                            <li class="d-flex align-items-center mb-3">
                              <i class="ti ti-wallet"></i><span class="fw-bold mx-2">Saldo:</span> <span><small>Rp</small> {{ number_format($user->saldo, 2, ',', '.') }}</span>
                            </li>
                            <li class="d-flex align-items-center mb-3">
                              <i class="ti ti-flame"></i><span class="fw-bold mx-2">Apikey:</span> <span>{{ $user->api_key ?? '-' }}</span>
                            </li>
                            <li class="d-flex align-items-center mb-3">
                              <i class="ti ti-hash"></i><span class="fw-bold mx-2">License:</span> <span>{{ $user->_count_license() }}</span>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-12 col-xl-8 col-lg-8">
            <div class="card mb-3">
                <div class="card-header border-bottom py-3 pb-0">
                    <h4 class="card-title">Personal Info</h4>
                </div>
                <div class="card-body pt-3">
                    <div class="row">
                        <div class="col-12 col-xl-6 col-lg-6 mb-1">
                            <label class="form-label" for="accountFirstName">Name</label>
                            <input type="text" class="form-control" name="name" placeholder="Enter your name" value="{{ $user->name }}">
                        </div>
                        <div class="col-12 col-xl-6 col-lg-6 mb-1">
                            <label class="form-label" for="accountLastName">Username</label>
                            <input type="text" class="form-control" name="username" value="{{ $user->username }}">
                        </div>
                        <div class="col-12 col-xl-6 col-lg-6 mb-1">
                            <label class="form-label" for="accountLastName">Email</label>
                            <input type="email" class="form-control" name="email" value="{{ $user->email }}">
                        </div>
                        <div class="col-12 col-xl-6 col-lg-6 mb-1">
                            <label class="form-label" for="accountLastName">Whatsapp</label>
                            <input type="text" class="form-control" name="whatsapp" value="{{ $user->whatsapp }}" placeholder="62xxx">
                        </div>
                        <div class="col-12 col-xl-6 col-lg-6 mb-1">
                            <label class="form-label" for="accountLastName">Saldo</label>
                            <input type="text" class="form-control" name="saldo" value="{{ $user->saldo }}">
                        </div>
                        <div class="col-12 col-xl-6 col-lg-6 mb-1">
                            <label class="form-label" for="accountLastName">Role</label>
                            <select class="form-select" name="role" required="">
                                <option {{ $user->role=='admin' ? 'selected' :'' }} value="admin">Admin</option>
                                <option {{ $user->role=='user' ? 'selected' :'' }} value="user">User</option>
                            </select>
                        </div>
                        <div class="col-12 mb-1">
                            <label class="form-label" for="accountLastName">About</label>
                            <textarea name="about" rows="5" class="form-control">{{ $user->about }}</textarea>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card mb-3">
                <div class="card-header border-bottom py-3 pb-0">
                    <h4 class="card-title">Security</h4>
                </div>
                <div class="card-body pt-3">
                    <div class="row">
                        <p>Don't fill it if you don't want to change the password.</p>
                        <div class="col-12 col-sm-6 mb-1">
                            <label class="form-label" for="account-new-password">New Password</label>
                            <div class="input-group form-password-toggle input-group-merge">
                                <input type="text" name="new_password" class="form-control" placeholder="Enter new password" autocomplete="new-password">
                                <div class="input-group-text cursor-pointer">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-eye"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                                </div>
                            </div>
                        </div>
                        <div class="col-12 col-sm-6 mb-1">
                            <label class="form-label" for="account-retype-new-password">Retype New Password</label>
                            <div class="input-group form-password-toggle input-group-merge">
                                <input type="text" class="form-control" name="confirm-new-password" placeholder="Confirm your new password" autocomplete="new-password">
                                <div class="input-group-text cursor-pointer"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-eye"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>


            <div class="card">
                <div class="card-header border-bottom py-3 pb-0">
                    <h4 class="card-title text-danger">Suspend</h4>
                </div>
                <div class="card-body mt-3">
                    <textarea name="suspended" rows="5" class="form-control" placeholder="ex. You were banned for breaking the rules ">{{ $user->suspended }}</textarea>
                    <small>The message content will activate suspend for this account</small>
                </div>
            </div>
        </div>
    </div>
</form>
@endsection

@push('js')
    <script>
        // submit on submit
        let button_submit = '';
        $('button[name=button_submit]').click(function() {
            button_submit = $(this).val();
        });
        $('#form-update-profile').submit(function(e) {
            e.preventDefault();
            var data = new FormData(this);
            Swal.fire({
                html: '<div class="d-flex justify-content-center"><div class="sk-bounce sk-primary"><div class="sk-bounce-dot"></div><div class="sk-bounce-dot"></div></div></div><br>Loading...',
                allowOutsideClick: false,
                buttonsStyling: false,
                showConfirmButton: false,
            });
            $('button[name=button_submit]').attr('disabled', true);
            $.ajax({
                url: $(this).attr('action'),
                type: 'POST',
                data: data,
                cache: false,
                contentType: false,
                processData: false,
                success: function(data) {
                    Swal.fire({
                        icon: 'success',
                        text: data.message,
                        customClass: {
                            confirmButton: 'btn btn-primary'
                        },
                        timer: 1500
                    });
                    setTimeout(() => {
                        if (button_submit == 'update and exit') {
                            window.location.href = "{!! route('admin.users.index') !!}";
                        }
                    }, 1500);
                    $('button[name=button_submit]').attr('disabled', false);
                    $('#form-update-profile input[name=new_password]').val('');
                    $('#form-update-profile input[name=confirm-new-password]').val('');
                    $('#form-update-profile input[name=avatar]').val('');
                },
                error: function(data) {
                    $('button[name=button_submit]').attr('disabled', false);
                    Swal.fire({
                        icon: 'error',
                        text: data.responseJSON.message ?? 'Something went wrong!',
                        customClass: {
                            confirmButton: 'btn btn-primary'
                        },
                        timer: 1500
                    });
                }
            });
        });


        $("input[name=avatar]").change(function() {
            if (this.files && this.files[0]) {
                var reader = new FileReader();
                reader.onload = function(e) {
                    $('#preview-avatar').attr('src', e.target.result);
                }
                reader.readAsDataURL(this.files[0]);
            }
        });

    </script>
@endpush
