@extends('layouts.admin.main')

@section('title', 'Setting Plan')

@section('content')
<form id="submit" action="{!! route('admin.users.plan', $user->id) !!}">
    @csrf
    <div class="d-flex justify-content-end">
        <button class="btn btn-primary" name="button_submit" type="submit">
            <svg xmlns="http://www.w3.org/2000/svg" class="me-2" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                <path d="M17 11h1c1.38 0 3 1.274 3 3c0 1.657 -1.5 3 -3 3l-6 0v-10c3 0 4.5 1.5 5 4z"></path>
                <path d="M9 8l0 9"></path>
                <path d="M6 17l0 -7"></path>
                <path d="M3 16l0 -2"></path>
            </svg>Update
        </button>
    </div>
    <hr>
    <div class="card">
        <div class="card-body">
            <div class="mb-3">
                <label class="form-label">Change Plan</label>
                <select name="plan_new" class="form-select">
                    @foreach ($plans as $plan)
                        <option value="{{ $plan['id'] }}">{{ \Str::upper($plan['plan']) }}</option>
                    @endforeach
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label">Expired In Day</label>
                <input name="expired_new" class="form-control" type="number" value="0">
            </div>
            <hr>
            <div class="card" id="listinclude-container">
                <h6 class="card-header">
                    <div>Current Plan</div>
                </h6>
                <div class="table-responsive text-nowrap">
                    <table class="table">
                        <tbody class="table-border-bottom-0 table-body">
                            <tr>
                                <td>Plan</td>
                                <td style="text-transform: uppercase">{{ $current->plan }}</td>
                            </tr>
                            <tr>
                                <td>Request / Day</td>
                                <td>{{ $current->max_request }}</td>
                            </tr>
                            <tr>
                                <td>Remining Request</td>
                                <td>{{ $current->current_request }}</td>
                            </tr>
                            <tr>
                                <td>Expired at</td>
                                <td>{{ $current->expired }}</td>
                            </tr>
                        </tbody>
                    </table>
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
        $('#submit').submit(function(e) {
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
                        location.reload();
                    }, 1500);
                },
                error: function(data) {
                    $('button[name=button_submit]').attr('disabled', false);
                    Swal.fire({
                        icon: 'error',
                        text: data.responseJSON.message ?? 'Something went wrong!',
                        customClass: {
                            confirmButton: 'btn btn-primary'
                        },
                        timer: 2000
                    });
                }
            });
        });
    </script>
@endpush
