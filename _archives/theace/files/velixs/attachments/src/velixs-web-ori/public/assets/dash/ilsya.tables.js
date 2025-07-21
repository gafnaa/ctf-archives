// SCRIPT BY ILSYA @ 2023
// WEBSITE: https://velixs.com
// GITHUB: https://github.com/ilsyaa

class itables {
    constructor(ilsya){
        this.table = $(ilsya.table);
        this.table_result = null;
        this.url = ilsya.ajax ?? null;
        this.columns = ilsya.columns ?? [];
        this.header = ilsya.header ?? '-';
        this.detail_title = ilsya.detail_title ?? null;
        this.buttons = ilsya.buttons ?? [
            {
                text: '<i class="ti ti-trash me-sm-1" style="margin-top: -3px;"></i> <span class="d-none d-sm-inline-block">Delete</span>',
                className: 'itable-btn-delete btn btn-label-danger me-2'
            },
            {
                text: '<i class="ti ti-plus me-sm-1"></i> <span class="d-none d-sm-inline-block">Add New</span>',
                className: 'itable-btn-create btn btn-primary'
            }
        ];
        this.customDefs = ilsya.customDefs ?? [];
        this.url_delete = ilsya.url_delete ?? null;
        this.responsive = ilsya.responsive ?? true;
        this.scrollX = ilsya.scrollX ?? false;
        return this.init();
    }
    init(){
        if (this.table.length) {
            var columnDefs = [
                {
                    // For Responsive
                    className: 'control',
                    orderable: false,
                    searchable: false,
                    responsivePriority: 2,
                    targets: 0,
                    render: function () {
                        return '';
                    }
                },
                {
                    // For Checkboxes
                    targets: 1,
                    orderable: false,
                    searchable: false,
                    responsivePriority: 3,
                    checkboxes: true,
                    render: function (data, type, full, meta) {
                        return '<input type="checkbox" class="dt-checkboxes itable-checkboxs form-check-input" data-id="' + full.id + '" />';
                    },
                    checkboxes: {
                        selectAllRender: '<input type="checkbox" class="form-check-input itable-checkbox-all" />'
                    }
                },
                {
                    targets: 2,
                    searchable: false,
                    visible: false
                },
                {
                    responsivePriority: 1,
                    targets: 3
                },
            ];

            if (this.customDefs.length) {
                columnDefs = columnDefs.concat(this.customDefs);
            }

            if (this.responsive) {
                this.responsive = {
                    details: {
                        display: $.fn.dataTable.Responsive.display.modal({
                            header: function (row) {
                                var data = row.data();
                                return this.detail_title ? 'Details of ' + data[this.detail_title] : 'Details';
                            }
                        }),
                        type: 'column',
                        renderer: function (api, rowIdx, columns) {
                            var data = $.map(columns, function (col, i) {
                                return col.title !== '' // ? Do not show row in modal popup if title is blank (for check box)
                                    ? '<tr data-dt-row="' +
                                    col.rowIndex +
                                    '" data-dt-column="' +
                                    col.columnIndex +
                                    '">' +
                                    '<td>' +
                                    col.title +
                                    ':' +
                                    '</td> ' +
                                    '<td>' +
                                    col.data +
                                    '</td>' +
                                    '</tr>'
                                    : '';
                            }).join('');

                            return data ? $('<table class="table"/><tbody />').append(data) : false;
                        }
                    }
                }
            }

            this.table_result = this.table.DataTable({
                ajax: this.url,
                columns: this.columns,
                processing: true,
                serverSide: true,
                columnDefs: columnDefs,
                // order: [[2, 'desc']],
                dom: '<"card-header flex-column flex-md-row"<"head-label text-center"><"dt-action-buttons text-end pt-3 pt-md-0"B>><"row"<"col-sm-12 col-md-6"l><"col-sm-12 col-md-6 d-flex justify-content-center justify-content-md-end"f>>t<"row"<"col-sm-12 col-md-6"i><"col-sm-12 col-md-6"p>>',
                displayLength: 10,
                lengthMenu: [10, 25, 50, 75, 100],
                buttons: this.buttons,
                responsive: this.responsive,
                scrollX: this.scrollX
            });
            $('div.head-label').html('<h5 class="card-title mb-0">' + this.header + '</h5>');

            this.delete(this.table_result);
            return this.table_result;
        }
    }


    delete(table){
        var route_delete = this.url_delete;
        $('.itable-btn-delete').on('click', function(){
            if (!route_delete) {
                return Swal.fire({
                    icon: 'error',
                    text: 'Url delete not found.',
                    customClass: {
                        confirmButton: 'btn btn-success'
                    },
                    timer: 1500
                });
            }
            var id = [];
            $('.itable-checkboxs:checked').each(function(){
                id.push($(this).data('id'));
            });
            if (id.length === 0) {
                return Swal.fire({
                    icon: 'info',
                    text: 'Please select data to delete.',
                    customClass: {
                        confirmButton: 'btn btn-success'
                    },
                    timer: 1500
                });
            }
            Swal.fire({
                text: "Are you sure you want to delete selected data?",
                icon: 'warning',
                showCancelButton: true,
                confirmButtonText: 'Yes, delete it!',
                customClass: {
                    confirmButton: 'btn btn-primary me-3',
                    cancelButton: 'btn btn-label-secondary'
                },
                buttonsStyling: false
            }).then(function (result) {
                if (result.value) {
                    Swal.fire({
                        html: '<div class="d-flex justify-content-center"><div class="sk-bounce sk-primary"><div class="sk-bounce-dot"></div><div class="sk-bounce-dot"></div></div></div><br>Loading...',
                        allowOutsideClick: false,
                        buttonsStyling: false,
                        showConfirmButton: false,
                    });
                    $.ajax({
                        url: route_delete,
                        type: 'POST',
                        headers: {
                            'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content'),
                        },
                        data: { ids: id },
                        success: function (data) {
                            table.ajax.reload();
                            Swal.fire({
                                icon: 'success',
                                text: data.message ?? 'Data has been deleted.',
                                customClass: {
                                    confirmButton: 'btn btn-success'
                                },
                                timer: 1500
                            });
                        },
                        error: function (data) {
                            // console.log(data);
                            Swal.fire({
                                icon: 'error',
                                text: data.responseJSON.message ?? 'Data failed to delete.',
                                customClass: {
                                    confirmButton: 'btn btn-success'
                                },
                                timer: 1500
                            });
                        }
                    });
                }
            });
        });
    }
}
