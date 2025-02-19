<?php init_head(); ?>

<style>
    .table>tbody>tr>td,
    .table>tfoot>tr>td {
        color:rgb(0, 0, 0);
    }
</style>
<div id="wrapper">
    <div class="content">
        <div class="row">
            <div class="col-md-12" id="small-table">
                <div class="panel_s">
                    <div class="panel-body">
                        <div class="col-md-12">
                            <div class="row">
                                <div class="col-md-2">
                                    <?php echo render_select('warehouse_id', $warehouses, array('warehouse_id', array('warehouse_code', 'warehouse_name')), 'warehouse_name'); ?>
                                </div>
                                <div class="col-md-2">
                                    <?php echo render_select('group_id', $commodity_groups, array('id', 'name'), 'Block'); ?>
                                </div>

                                <div class="col-md-1" style="margin-top: 22px;">
                                    <a href="#" onclick="get_data_booking_chart_report(); return false;" class="btn btn-info button-pdf-margin-top"><?php echo _l('_filter'); ?></a>
                                </div>
                            </div>

                        </div>

                        <hr class="hr-panel-heading" />
                        <div class="col-md-12" id="report">
                            <div class="panel panel-info col-md-12 panel-padding">
                                <div class="panel-body" id="booking_chart_report">
                                </div>
                            </div>
                        </div>

                    </div>
                </div>
            </div>
        </div>
    </div>

</div>

<?php init_tail(); ?>
<script>
    function get_data_booking_chart_report() {
        "use strict";
        var formData = new FormData();
        formData.append("csrf_token_name", $('input[name="csrf_token_name"]').val());
        formData.append("warehouse_id", $('select[name="warehouse_id"]').val());
        formData.append("group_id", $('select[name="group_id"]').val());
        $.ajax({
            url: admin_url + 'warehouse/get_booking_chart_report_view',
            method: 'post',
            data: formData,
            contentType: false,
            processData: false
        }).done(function(response) {
            var response = JSON.parse(response);
            $('#booking_chart_report').html('');
            $('#booking_chart_report').append(response.value);
        });
    }
</script>

</body>

</html>