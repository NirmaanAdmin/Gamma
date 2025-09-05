<?php defined('BASEPATH') or exit('No direct script access allowed'); ?>
<?php init_head(); ?>
<div id="wrapper" class="customer_profile">
   <div class="content">
      <div class="row">
         <div class="col-md-12">
            <?php if (isset($client) && $client->registration_confirmed == 0 && is_admin()) { ?>
               <div class="alert alert-warning">
                  <?php echo _l('customer_requires_registration_confirmation'); ?>
                  <br />
                  <a href="<?php echo admin_url('purchase/confirm_registration/' . $client->userid); ?>"><?php echo _l('confirm_registration'); ?></a>
               </div>
            <?php } ?>

            <?php if (isset($client) && (!has_permission('purchase_customers', '', 'view') && is_vendor_admin($client->userid))) { ?>
               <div class="alert alert-info">
                  <?php echo _l('customer_admin_login_as_client_message', get_staff_full_name(get_staff_user_id())); ?>
               </div>
            <?php } ?>
         </div>
         <?php if ($group == 'profile') { ?>
            <div class="btn-bottom-toolbar btn-toolbar-container-out text-right">
               <button class="btn btn-info only-save customer-form-submiter">
                  <?php echo _l('submit'); ?>
               </button>

            </div>
         <?php } ?>
         <?php if (isset($client)) { ?>
            <div class="col-md-3">
               <div class="panel_s mbot5">
                  <div class="panel-body padding-10">
                     <h4 class="bold">
                        #<?php echo pur_html_entity_decode($client->userid . ' ' . $title); ?>


                     </h4>
                  </div>
               </div>
               <?php $this->load->view('customers/tabs'); ?>
            </div>
         <?php } ?>
         <div class="col-md-<?php if (isset($client)) {
                                 echo 9;
                              } else {
                                 echo 12;
                              } ?>">
            <div class="panel_s">
               <div class="panel-body">
                  <?php if (isset($client)) { ?>
                     <?php echo form_hidden('isedit'); ?>
                     <?php echo form_hidden('userid', $client->userid); ?>
                     <div class="clearfix"></div>
                  <?php } ?>
                  <div>
                     <div class="tab-content">
                        <?php $this->load->view((isset($tabs) ? $tabs['view'] : 'customers/groups/profile')); ?>
                     </div>
                  </div>
               </div>
            </div>
         </div>
      </div>
      <?php if ($group == 'profile') { ?>
         <div class="btn-bottom-pusher"></div>
      <?php } ?>
   </div>
</div>
<?php init_tail(); ?>

<?php require 'modules/purchase/assets/js/customer_js.php'; ?>

</body>

</html>
<script>
   $('select[name="block_id"]').on('change', function() {

      var data_select = {};

      data_select.group_id = $('select[name="block_id"]').val();


      $.post(admin_url + 'warehouse/get_subgroup_fill_data', data_select).done(function(response) {
         response = JSON.parse(response);
         $("select[name='floor_id']").html('');

         $("select[name='floor_id']").append(response.subgroup);
         $("select[name='floor_id']").selectpicker('refresh');

         if (sub_group_value != '') {

            $("select[name='floor_id']").val(sub_group_value).change();
            sub_group_value = '';
         }



      });

   });

   $('select[name="property_id"]').on('change', function() {
      $("select[name='block_id']").val('').change();
      $("select[name='floor_id']").val('').change();
      $("select[name='flat_id']").val('').change();
   });

   $(document).ready(function() {
      // Check if floor_id has a value on page load
      var floor_id = $("select[name='floor_id']").val();

      if (floor_id && floor_id != '') {
         $('select[name="floor_id"]').trigger('change');
      }
   });
   $('select[name="floor_id"]').on('change', function() {
      var block_id = $("select[name='block_id']").val();
      var property_id = $("select[name='property_id']").val();
      var floor_id = $("select[name='floor_id']").val();
      var flat_id_hidden = $('#flat_id_hidden').val();
      if (floor_id != '') {

         var data_select = {};
         data_select.block_id = block_id;
         data_select.property_id = property_id;
         data_select.floor_id = floor_id;
         data_select.flat_id_hidden = flat_id_hidden;
         $.post(admin_url + 'warehouse/get_flat_fill_data', data_select).done(function(response) {
            response = JSON.parse(response);
            $("select[name='flat_id']").html('');
            $("select[name='flat_id']").append(response.flats);
            $("select[name='flat_id']").selectpicker('refresh');
         });
      }

   });
   $(document).ready(function() {
      $('#add_new_customer').on('click', function() {
         var html = `
            <div class="col-md-12 customer-field" style="margin:10px 0px; padding:0px !important;position:relative;">
                <input type="text" name="company2" class="form-control" id="company2" placeholder="Customer Name">
               <span>
                    <i class="fa fa-times pull-right text-danger remove_customer" title="Remove" style="cursor:pointer;position:absolute;top:-4px;right:-4px;"></i>
                </span>
            </div>
            
        `;
         $('#extra_customers').append(html);
         $('#add_new_customer').addClass('hide');
      });

      // Remove on click
      $(document).on('click', '.remove_customer', function() {
         $('#company2').val('');
         $(this).closest('.customer-field').remove();

         $('#add_new_customer').removeClass('hide');
      });

      $('#add_new_pan_card').on('click', function() {
         var html = `
            <div class="col-md-12 customer-field" style="margin:10px 0px; padding:0px !important;position:relative;">
                <input type="text" name="pan_card_2" class="form-control" id="pan_card" placeholder="Pan Card">
               <span>
                    <i class="fa fa-times pull-right text-danger remove_pan_card" title="Remove" style="cursor:pointer;position:absolute;top:-4px;right:-4px;"></i>
                </span>
            </div>
            
        `;
         $('#extra_pan_card').append(html);
         $('#add_new_pan_card').addClass('hide');
      });

      // Remove on click
      $(document).on('click', '.remove_pan_card', function() {
         $('#pan_card_2').val('');
         $(this).closest('.customer-field').remove();

         $('#add_new_pan_card').removeClass('hide');
      });


      $('#add_new_adhar_card').on('click', function() {
         var html = `
            <div class="col-md-12 customer-field" style="margin:10px 0px; padding:0px !important;position:relative;">
                <input type="text" name="adhar_card_2" class="form-control" id="adhar_card" placeholder="Adhar Card">
               <span>
                    <i class="fa fa-times pull-right text-danger remove_adhar_card" title="Remove" style="cursor:pointer;position:absolute;top:-4px;right:-4px;"></i>
               </span>
            </div>

        `;
         $('#extra_adhar_card').append(html);
         $('#add_new_adhar_card').addClass('hide');
      });

      // Remove on click
      $(document).on('click', '.remove_adhar_card', function() {
         $('#adhar_card_2').val('');
         $(this).closest('.customer-field').remove();

         $('#add_new_adhar_card').removeClass('hide');
      });


      $('#add_new_election_card').on('click', function() {
         var html = `
            <div class="col-md-12 customer-field" style="margin:10px 0px; padding:0px !important;position:relative;">
                <input type="text" name="election_card_2" class="form-control" id="election_card" placeholder="Election Card">
               <span>
                    <i class="fa fa-times pull-right text-danger remove_election_card" title="Remove" style="cursor:pointer;position:absolute;top:-4px;right:-4px;"></i>
               </span>
            </div>

        `;
         $('#extra_election_card').append(html);
         $('#add_new_election_card').addClass('hide');
      });

      // Remove on click
      $(document).on('click', '.remove_election_card', function() {
         $('#election_card_2').val('');
         $(this).closest('.customer-field').remove();

         $('#add_new_election_card').removeClass('hide');
      });

   });
</script>