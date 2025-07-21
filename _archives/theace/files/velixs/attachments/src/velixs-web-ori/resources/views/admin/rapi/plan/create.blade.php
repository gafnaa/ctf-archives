@extends('layouts.admin.main')

@section('title', 'Create Plan')

@section('content')
<form id="submit" action="{!! route('admin.plan.create') !!}">
    @csrf
    <div class="d-flex justify-content-end">
        <button class="btn btn-label-primary me-2 d-flex justify-content-center justify-items-center" name="button_submit" value="save" type="submit">
            <svg xmlns="http://www.w3.org/2000/svg" class="me-2" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                <path d="M7 18a4.6 4.4 0 0 1 0 -9a5 4.5 0 0 1 11 2h1a3.5 3.5 0 0 1 0 7h-1"></path>
                <path d="M9 15l3 -3l3 3"></path>
                <path d="M12 12l0 9"></path>
            </svg>Save
        </button>
        <button class="btn btn-primary" name="button_submit" value="save and edit" type="submit">
            <svg xmlns="http://www.w3.org/2000/svg" class="me-2" width="20" height="20" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path stroke="none" d="M0 0h24v24H0z" fill="none"></path>
                <path d="M17 11h1c1.38 0 3 1.274 3 3c0 1.657 -1.5 3 -3 3l-6 0v-10c3 0 4.5 1.5 5 4z"></path>
                <path d="M9 8l0 9"></path>
                <path d="M6 17l0 -7"></path>
                <path d="M3 16l0 -2"></path>
            </svg>Save & Edit
        </button>
    </div>
    <hr>
    <div class="card">
        <div class="card-body">
            <div class="mb-3">
                <label class="form-label">Plan Name</label>
                <input type="text" name="plan" placeholder="Free" class="form-control" required>
            </div>
            <div class="row">
                <div class="col-12 col-lg-6 col-md-6">
                    <div class="mb-3">
                        <label class="form-label">Price</label>
                        <input type="text" name="price" placeholder="string: 10.000" class="form-control" required>
                    </div>
                </div>
                <div class="col-12 col-lg-6 col-md-6">
                    <div class="mb-3">
                        <label class="form-label">Request / Days</label>
                        <input type="number" name="max_request" placeholder="10" class="form-control" required>
                    </div>
                </div>
            </div>
            <hr>
            <h6>Pricing Display Page</h6>
            <div class="row">
                <div class="col-12 col-lg-6 col-md-6">
                    <div class="mb-3">
                        <label class="form-label">Button Text</label>
                        <input type="text" name="button_title" placeholder="Whatsapp" class="form-control" required>
                    </div>
                </div>
                <div class="col-12 col-lg-6 col-md-6">
                    <div class="mb-3">
                        <label class="form-label">Button Url</label>
                        <input type="text" name="button_url" placeholder="//wa.me" class="form-control" required>
                    </div>
                </div>
            </div>

            <div class="card" id="listinclude-container">
                <h6 class="card-header d-flex justify-content-between">
                    <div>What's included</div>
                    <div>
                        <button type="button" class="btn btn-primary btn-add">add new</button>
                    </div>
                </h6>
                <div class="table-responsive text-nowrap">
                    <table class="table">
                        <thead class="table-light">
                            <tr>
                                <th>Text</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody class="table-border-bottom-0 table-body">
                            <tr>
                                <td>
                                    <input type="text" class="form-control" name="listinclude[]" required>
                                </td>
                                <td>
                                    <button type="button" class="btn-danger btn btn-delete">Delete</button>
                                </td>
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
                        if (button_submit == 'save') {
                            window.location.href = "{{ route('admin.plan.index') }}";
                        } else {
                            window.location.href = data.redirect_edit;
                        }
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

        document.addEventListener("DOMContentLoaded", function() {
            const listinclude = document.querySelector("#listinclude-container");
            listinclude.querySelector(".btn-add").addEventListener("click", function() {
                const tr = document.createElement("tr");
                tr.innerHTML = `<td><input type="text" class="form-control" name="listinclude[]" required></td><td><button type="button" class="btn-danger btn btn-delete">Delete</button></td>`
                listinclude.querySelector(".table-body").appendChild(tr);
                tr.querySelector(".btn-delete").addEventListener("click", function() {
                    tr.remove();
                });
            })

            listinclude.querySelectorAll(".btn-delete").forEach((btn) => {
                btn.addEventListener("click", function() {
                    this.closest("tr").remove();
                })
            })
        })
    </script>
@endpush
