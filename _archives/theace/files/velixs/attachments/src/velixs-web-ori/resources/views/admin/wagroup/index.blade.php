@extends('layouts.admin.main')

@section('title', 'Manage License')

@section('content')
<div class="card">
    <div class="card-datatable table-responsive pt-0">
      <table class="ilsya-datatables table">
        <thead>
          <tr>
            <th></th>
            <th></th>
            <th>id</th>
            <th>whatsapp</th>
            <th>link</th>
            <th>status</th>
          </tr>
        </thead>
      </table>
    </div>
  </div>
@endsection

@push('js')
    <script src="{!! asset('assets/dash') !!}/vendor/libs/select2/select2.js"></script>
    <script src="{!! asset('assets/dash') !!}/vendor/libs/bootstrap-select/bootstrap-select.js"></script>
    <script src="{!! asset('assets/dash') !!}/js/forms-selects.js"></script>
    <script src="{!! asset('assets/dash') !!}/vendor/libs/datatables-bs5/datatables-bootstrap5.js"></script>
    <script src="{!! asset('assets/dash/ilsya.tables.js?v=1') !!}"></script>
    <script>
        $(function () {
            const table = new itables({
                table: '.ilsya-datatables',
                ajax: '{!! route('admin.wagroup.json') !!}',
                url_delete: '{!! route('admin.wagroup.destroy') !!}',
                columns: [
                    { data: '' },
                    { data: 'id' },
                    { data: 'id' },
                    { data: 'whatsapp' },
                    { data: 'whatsapp_url' },
                    { data: 'status' }
                ],
                header: 'List Whatsapp Group',
                buttons: [
                    {
                        text: '<i class="ti ti-trash me-sm-1" style="margin-top: -3px;"></i> <span class="d-none d-sm-inline-block">Delete</span>',
                        className: 'itable-btn-delete btn btn-label-danger me-2'
                    },
                    {
                        text: '<i class="ti ti-repeat me-sm-1" style="margin-top: -3px;"></i> <span class="d-none d-sm-inline-block">Sync</span>',
                        className: 'itable-btn-sync btn btn-label-primary me-2'
                    },
                ]
            });

            $(document).on('click', '.itable-btn-sync', (e)=>{
                e.preventDefault();
                Swal.fire({
                    html: '<div class="d-flex justify-content-center"><div class="sk-bounce sk-primary"><div class="sk-bounce-dot"></div><div class="sk-bounce-dot"></div></div></div><br>Loading...',
                    allowOutsideClick: false,
                    buttonsStyling: false,
                    showConfirmButton: false,
                });
                $.ajax({
                    url: '{!! route('admin.wagroup.sync') !!}',
                    type: 'GET',
                    headers: {
                        'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content'),
                    },
                    success: function(res){
                        Swal.fire({
                            icon: 'success',
                            text: res.message ?? 'Sync successfully!',
                            customClass: {
                                confirmButton: 'btn btn-primary'
                            },
                            timer: 1500
                        });
                        table.ajax.reload();
                    },
                    error: function(data){
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
            })

            //__btn_switch_status
            $(document).on('click','.__btn_switch_status',function(e){
                e.preventDefault();
                const id = $(this).data('id');
                const status = $(this).data('status');
                Swal.fire({
                    html: '<div class="d-flex justify-content-center"><div class="sk-bounce sk-primary"><div class="sk-bounce-dot"></div><div class="sk-bounce-dot"></div></div></div><br>Loading...',
                    allowOutsideClick: false,
                    buttonsStyling: false,
                    showConfirmButton: false,
                });
                $.ajax({
                    url: '{!! route('admin.wagroup.toggle.status') !!}',
                    type: 'POST',
                    headers: {
                        'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content'),
                    },
                    data: {
                        id: id,
                        status: status
                    },
                    success: function(res){
                        Swal.fire({
                            icon: 'success',
                            text: res.message ?? 'Status updated successfully!',
                            customClass: {
                                confirmButton: 'btn btn-primary'
                            },
                            timer: 1500
                        });
                        table.ajax.reload();
                    },
                    error: function(data){
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
        });
    </script>
@endpush

@push('css')
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/datatables-bs5/datatables.bootstrap5.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/datatables-responsive-bs5/responsive.bootstrap5.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/datatables-checkboxes-jquery/datatables.checkboxes.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/datatables-buttons-bs5/buttons.bootstrap5.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/flatpickr/flatpickr.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/datatables-rowgroup-bs5/rowgroup.bootstrap5.css" />

    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/select2/select2.css" />
    <link rel="stylesheet" href="{!! asset('assets/dash') !!}/vendor/libs/bootstrap-select/bootstrap-select.css" />
@endpush
