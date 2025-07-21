@extends('layouts.admin.main')

@section('title', 'Manage Blog Tags')

@section('content')
<div class="card">
    <div class="card-datatable table-responsive pt-0">
      <table class="ilsya-datatables table">
        <thead>
          <tr>
            <th></th>
            <th></th>
            <th>id</th>
            <th>Name</th>
            <th>Slug</th>
            <th></th>
          </tr>
        </thead>
      </table>
    </div>
  </div>


<div class="modal fade" id="modal-edit" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="modalCenterTitle">Edit Tags</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form action="{!! route('admin.blog.tags.update') !!}" method="post" id="form-update">
                @csrf
                <input type="hidden" name="id">
                <div class="modal-body isloading">
                    <div class="d-flex justify-content-center">
                        <div class="sk-plane sk-primary"></div>
                    </div>
                </div>
                <div class="modal-body content" style="display: none">
                    <div class="row g-2">
                        <div class="col-12 col-xl-6 col-lg-6 mb-0">
                            <label for="emailWithTitle" class="form-label">Name</label>
                            <input type="text" name="title" class="form-control" placeholder="Ilsya" />
                        </div>
                        <div class="col-12 col-xl-6 col-lg-6 mb-0">
                            <label for="dobWithTitle" class="form-label">Slug</label>
                            <input type="text" class="form-control" name="slug" placeholder="ilsya" />
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-label-secondary" data-bs-dismiss="modal">
                        Close
                    </button>
                    <button type="submit" class="btn btn-primary">Update</button>
                </div>
            </form>
        </div>
    </div>
</div>
<div class="modal fade" id="modal-add" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="modalCenterTitle">New Tags</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <form action="{!! route('admin.blog.tags.create') !!}" method="post" id="form-create">
                @csrf
                <div class="modal-body">
                    <div class="row g-2">
                        <div class="col-12 col-xl-6 col-lg-6 mb-0">
                            <label for="emailWithTitle" class="form-label">Name</label>
                            <input type="text" name="title" class="form-control" placeholder="Ilsya" />
                        </div>
                        <div class="col-12 col-xl-6 col-lg-6 mb-0">
                            <label for="dobWithTitle" class="form-label">Slug</label>
                            <input type="text" class="form-control" name="slug" placeholder="ilsya" />
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-label-secondary" data-bs-dismiss="modal">
                        Close
                    </button>
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
    </div>
</div>
@endsection

@push('js')
    <script src="{!! asset('assets/dash') !!}/vendor/libs/datatables-bs5/datatables-bootstrap5.js"></script>
    <script src="{!! asset('assets/dash/ilsya.tables.js?v=1') !!}"></script>
    <script>
        $(function () {
            const table = new itables({
                table: '.ilsya-datatables',
                ajax: '{!! route('admin.blog.tags.json') !!}',
                url_delete: '{!! route('admin.blog.tags.destroy') !!}',
                columns: [
                    { data: '' },
                    { data: 'id' },
                    { data: 'id' },
                    { data: 'title' },
                    { data: 'slug' },
                    { data: '' }
                ],
                header: 'List Tags',
                customDefs: [
                    {
                        targets: -1,
                        title: 'Actions',
                        orderable: false,
                        searchable: false,
                        render: function (data, type, full, meta) {
                            return ('<a href="javascript:void(0)" data-id="'+full.id+'" class="btn btn-sm btn-icon item-edit itable-btn-edit"><i class="text-primary ti ti-pencil"></i></a>');
                        }
                    }
                ],
                buttons: [
                    {
                        text: '<i class="ti ti-trash me-sm-1" style="margin-top: -3px;"></i> <span class="d-none d-sm-inline-block">Delete</span>',
                        className: 'itable-btn-delete btn btn-label-danger me-2'
                    },
                    {
                        text: '<i class="ti ti-plus me-sm-1"></i> <span class="d-none d-sm-inline-block">Add New</span>',
                        className: 'btn btn-primary me-2 btn-add',
                        attr: {
                            'data-bs-toggle': 'modal',
                            'data-bs-target': '#modal-add'
                        }
                    },
                ]
            });
        });

        $(document).on('click', '.itable-btn-edit', function() {
            var id = $(this).data('id');
            $('#modal-edit').modal('show');
            $("#modal-edit .content").hide();
            $("#modal-edit .isloading").show();
            $.ajax({
                type: "GET",
                url: '{!! route('admin.blog.tags.edit','') !!}/'+id,
                success: function(data){
                    $("#modal-edit .isloading").hide();
                    $("#modal-edit .content").show();
                    $("#modal-edit input[name='title']").val(data.data.title);
                    $("#modal-edit input[name='slug']").val(data.data.slug);
                    $("#modal-edit input[name='id']").val(data.data.id);
                },
                error: function(data){
                    Swal.fire({
                        icon: 'error',
                        text: data.responseJSON.message ?? 'Something went wrong!',
                        showConfirmButton: false,
                        timer: 1500
                    });
                }
            });
        });

        $("#form-create").submit(function(e) {
            e.preventDefault();
            var form = $(this);
            var url = form.attr('action');
            var data = form.serialize();
            form.find('button[type="submit"]').attr('disabled', true);
            $.ajax({
                type: "POST",
                url: url,
                data: data,
                success: function(data){
                    Swal.fire({
                        icon: 'success',
                        text: data.message,
                        showConfirmButton: false,
                        timer: 1500
                    });
                    $('#modal-add').modal('hide');
                    $('.ilsya-datatables').DataTable().ajax.reload();
                    form.find('button[type="submit"]').attr('disabled', false);
                    form.find('input[name="title"]').val('');
                    form.find('input[name="slug"]').val('');
                },
                error: function(data){
                    Swal.fire({
                        icon: 'error',
                        text: data.responseJSON.message ?? 'Something went wrong!',
                        showConfirmButton: false,
                        timer: 1500
                    });
                    form.find('button[type="submit"]').attr('disabled', false);
                }
            });
        });

        $("#form-update").submit(function(e) {
            e.preventDefault();
            var form = $(this);
            var url = form.attr('action');
            var data = form.serialize();
            form.find('button[type="submit"]').attr('disabled', true);
            $.ajax({
                type: "POST",
                url: url,
                data: data,
                success: function(data){
                    Swal.fire({
                        icon: 'success',
                        text: data.message,
                        showConfirmButton: false,
                        timer: 1500
                    });
                    $('#modal-edit').modal('hide');
                    $('.ilsya-datatables').DataTable().ajax.reload();
                    form.find('button[type="submit"]').attr('disabled', false);
                    form.find('input[name="title"]').val('');
                    form.find('input[name="slug"]').val('');
                },
                error: function(data){
                    Swal.fire({
                        icon: 'error',
                        text: data.responseJSON.message ?? 'Something went wrong!',
                        showConfirmButton: false,
                        timer: 1500
                    });
                    form.find('button[type="submit"]').attr('disabled', false);
                }
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
@endpush
