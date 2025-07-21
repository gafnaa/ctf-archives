@extends('layouts.admin.main')

@section('title', 'Referral '.$display_title)

@section('content')
<div class="card">
    <div class="card-datatable table-responsive pt-0">
      <table class="ilsya-datatables table">
        <thead>
          <tr>
            <th></th>
            <th></th>
            <th>id</th>
            <th>Amount</th>
            <th>method</th>
            <th>to</th>
            <th>status</th>
            <th>message</th>
            <th>Owner</th>
            <th>Date</th>
          </tr>
        </thead>
      </table>
    </div>
  </div>

<div class="modal fade" id="modalstatus" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered" role="document">
    <div class="modal-content">
        <div class="modal-header">
            <h5 class="modal-title" id="modalCenterTitle">Update Status</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <form id="form-update-status" action="{{ route('admin.ref.update.status.ajax') }}" method="post">
            @csrf
            <input type="hidden" name="id" required>
            <div class="modal-body">
                <div class="row">
                    <div class="col-12 mb-3">
                        <label class="form-label">Status</label>
                        <select class="form-control" name="status" required id="select-status">
                        </select>
                    </div>
                    <div class="col-12 mb-3">
                        <label class="form-label">Message</label>
                        <textarea class="form-control" rows="6" name="message_status" required id="message_status"></textarea>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-label-secondary" data-bs-dismiss="modal">
                    Close
                </button>
                <button type="submit" id="btn-update" class="btn btn-primary">Save changes</button>
            </div>
        </form>
    </div>
    </div>
</div>
@endsection

@push('js')
    <script src="{!! asset('assets/dash') !!}/vendor/libs/select2/select2.js"></script>
    <script src="{!! asset('assets/dash') !!}/vendor/libs/bootstrap-select/bootstrap-select.js"></script>
    <script src="{!! asset('assets/dash') !!}/js/forms-selects.js"></script>
    <script src="{!! asset('assets/dash') !!}/vendor/libs/datatables-bs5/datatables-bootstrap5.js"></script>
    <script src="{!! asset('assets/dash/ilsya.tables.js?v=12') !!}"></script>
    <script>
        $(function () {
            $(document).on('click', ".btn-edit-status", function(e){
                const modal = $('#modalstatus');
                modal.find("#btn-update").html("Loading...");
                modal.find("#btn-update").attr("disabled", true);
                e.preventDefault();
                $.ajax({
                    url: '{{ route('admin.ref.edit.status.ajax','') }}/'+$(this).data('id'),
                    method: 'get',
                    dataType: 'json',
                    success: function (res) {
                        modal.find("#btn-update").html("Save changes");
                        modal.find("#btn-update").attr("disabled", false);
                        modal.find("input[name='id']").val(res.data.id);
                        $("#select-status").empty();
                        $("#select-status").append(`<option ${res.data.status == 'approved' ? 'selected' : ''} value='approved'>approved</option>`);
                        $("#select-status").append(`<option ${res.data.status == 'pending' ? 'selected' : ''} value='pending'>pending</option>`);
                        $("#select-status").append(`<option ${res.data.status == 'rejected' ? 'selected' : ''} value='rejected'>rejected</option>`);
                    },
                    error: function (data) {
                        modal.find("#btn-update").html("Save changes");
                        modal.find("#btn-update").attr("disabled", false);
                        Swal.fire({
                            icon: 'error',
                            text: data.responseJSON.message ?? 'Something went wrong!',
                            showConfirmButton: false,
                            timer: 1500
                        });
                    }
                })
            })

            $(document).on('change', '#select-status', function(e){
                const modal = $('#modalstatus');
                if ($(this).val() == 'approved') {
                    modal.find("#message_status").val('Approved');
                }else if ($(this).val() == 'pending') {
                    modal.find("#message_status").val('Being processed');
                }else {
                    modal.find("#message_status").val('Rejected');
                }
            })

            $(document).on('submit', '#form-update-status', function(e){
                e.preventDefault();
                const modal = $('#modalstatus');
                modal.find("#btn-update").html("Loading...");
                modal.find("#btn-update").attr("disabled", true);
                $.ajax({
                    url: $(this).attr('action'),
                    method: 'post',
                    data: $(this).serialize(),
                    dataType: 'json',
                    success: function (res) {
                        modal.find("#btn-update").html("Save changes");
                        modal.find("#btn-update").attr("disabled", false);
                        modal.find("input[name='id']").val('');
                        $("#select-status").empty();
                        modal.modal('hide');
                        $('.ilsya-datatables').DataTable().ajax.reload();
                        Swal.fire({
                            icon: 'success',
                            text: res.message ?? 'Status updated successfully!',
                            showConfirmButton: false,
                            timer: 1500
                        })
                    },
                    error: function (data) {
                        modal.find("#btn-update").html("Save changes");
                        modal.find("#btn-update").attr("disabled", false);
                        Swal.fire({
                            icon: 'error',
                            text: data.responseJSON.message ?? 'Something went wrong!',
                            showConfirmButton: false,
                            timer: 1500
                        });
                    }
                })
            })

            const table = new itables({
                table: '.ilsya-datatables',
                ajax: '{!! route('admin.ref.json',["type" => $type, "user" => $user]) !!}',
                url_delete: '{!! route('admin.ref.destroy') !!}',
                columns: [
                    { data: '' },
                    { data: 'id' },
                    { data: 'id' },
                    { data: 'amount' },
                    { data: 'method' },
                    { data: 'to' },
                    { data: 'status' },
                    { data: 'message_status' },
                    { data: 'owner' },
                    { data: 'created_at' },
                ],
                header: 'List {{ $display_title }}',
                buttons: [
                    {
                        text: '<i class="ti ti-trash me-sm-1" style="margin-top: -3px;"></i> <span class="d-none d-sm-inline-block">Delete</span>',
                        className: 'itable-btn-delete btn btn-label-danger me-2'
                    }
                ]
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
