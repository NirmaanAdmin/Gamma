<?php defined('BASEPATH') or exit('No direct script access allowed'); ?>
<h4 class="mtop5"><?php echo _l('Booking Form'); ?></h4>
<hr />
<div class="row">
   <?php echo form_hidden('userid', (isset($client) ? $client->userid : '')); ?>
   <?php echo form_open($this->uri->uri_string(), array('class' => 'vendor-form', 'autocomplete' => 'off')); ?>
   <div class="additional"></div>
   <div class="col-md-12">
      <div class="horizontal-scrollable-tabs">
         <div class="scroller arrow-left"><i class="fa fa-angle-left"></i></div>
         <div class="scroller arrow-right"><i class="fa fa-angle-right"></i></div>
         <div class="horizontal-tabs">
            <ul class="nav nav-tabs profile-tabs row customer-profile-tabs nav-tabs-horizontal" role="tablist">
               <li role="presentation" class="<?php if (!$this->input->get('tab')) {
                                                   echo 'active';
                                                }; ?>">
                  <a href="#contact_info" aria-controls="contact_info" role="tab" data-toggle="tab">
                     <?php echo _l('Customer Detail'); ?>
                  </a>
               </li>
               <?php
               $customer_custom_fields = false;
               if (total_rows(db_prefix() . 'customfields', array('fieldto' => 'vendors', 'active' => 1)) > 0) {
                  $customer_custom_fields = true;
               ?>
                  <li role="presentation" class="<?php if ($this->input->get('tab') == 'custom_fields') {
                                                      echo 'active';
                                                   }; ?>">
                     <a href="#custom_fields" aria-controls="custom_fields" role="tab" data-toggle="tab">
                        <?php echo _l('custom_fields'); ?>
                     </a>
                  </li>
               <?php } ?>
               <!-- <li role="presentation">
                  <a href="#billing_and_shipping" aria-controls="billing_and_shipping" role="tab" data-toggle="tab">
                     <?php echo _l('billing_shipping'); ?>
                  </a>
               </li> -->

               <!-- <li role="presentation">
                  <a href="#return_policies" aria-controls="return_policies" role="tab" data-toggle="tab">
                     <?php echo _l('pur_return_policies'); ?>
                  </a>
               </li> -->

               <!-- <?php if (isset($client)) { ?>
                  <li role="presentation">
                     <a href="#vendor_admins" aria-controls="vendor_admins" role="tab" data-toggle="tab">
                        <?php echo _l('vendor_admins'); ?>
                     </a>
                  </li>

               <?php } ?> -->
            </ul>
         </div>
      </div>
      <div class="tab-content">

         <?php if ($customer_custom_fields) { ?>
            <div role="tabpanel" class="tab-pane <?php if ($this->input->get('tab') == 'custom_fields') {
                                                      echo ' active';
                                                   }; ?>" id="custom_fields">
               <?php $rel_id = (isset($client) ? $client->userid : false); ?>
               <?php echo render_custom_fields('vendors', $rel_id); ?>
            </div>
         <?php } ?>
         <div role="tabpanel" class="tab-pane<?php if (!$this->input->get('tab')) {
                                                echo ' active';
                                             }; ?>" id="contact_info">
            <div class="row">
               <div class="col-md-12<?php if (isset($client) && (!is_empty_customer_company($client->userid) && total_rows(db_prefix() . 'contacts', array('userid' => $client->userid, 'is_primary' => 1)) > 0)) {
                                       echo '';
                                    } else {
                                       echo ' hide';
                                    } ?>" id="client-show-primary-contact-wrapper">
                  <!-- <div class="checkbox checkbox-info mbot20 no-mtop">
                     <input type="checkbox" name="show_primary_contact" <?php if (isset($client) && $client->show_primary_contact == 1) {
                                                                           echo ' checked';
                                                                        } ?> value="1" id="show_primary_contact">
                     <label for="show_primary_contact"><?php echo _l('show_primary_contact', _l('invoices') . ', ' . _l('estimates') . ', ' . _l('payments') . ', ' . _l('credit_notes')); ?></label>
                  </div> -->
               </div>
               <div class="col-md-6">
                  <?php $vendor_code = (isset($client) ? $client->vendor_code : $next_number);
                  echo render_input('vendor_code', 'Customer Code', $vendor_code, 'text', array('readonly' => true)); ?>
                  <?php $value = (isset($client) ? $client->company : ''); ?>
                  <?php $attrs = (isset($client) ? array() : array('autofocus' => true)); ?>
                  <?php echo render_input('company', 'Customer Name', $value, 'text', $attrs); ?>
                  <div id="company_exists_info" class="hide"></div>
                  <?php hooks()->do_action('after_pur_customer_profile_company_field', $client ?? null); ?>
                  <div class="row">
                     <div class="col-md-6">
                        <?php $value = (isset($client) ? $client->phonenumber : ''); ?>
                        <?php echo render_input('phonenumber', 'client_phonenumber', $value); ?>
                     </div>
                     <div class="col-md-6">
                        <?php $value = (isset($client) ? $client->pan_card : ''); ?>
                        <?php echo render_input('pan_card', 'Pan Card', $value); ?>
                     </div>
                     <div class="col-md-6">
                        <?php $value = (isset($client) ? $client->adhar_card : ''); ?>
                        <?php echo render_input('adhar_card', 'Adhar Card', $value); ?>
                     </div>
                     <div class="col-md-6">
                        <?php $value = (isset($client) ? $client->election_card : ''); ?>
                        <?php echo render_input('election_card', 'Election Card', $value); ?>
                     </div>

                     <div class="col-md-6">
                        <?php echo render_select('property_id', $warehouses, array('warehouse_code', 'warehouse_name'), 'Property Name') ?>
                     </div>

                     <div class="col-md-6">
                        <?php echo render_select('block_id', $commodity_groups, array('id', 'name'), 'Block Name') ?>
                     </div>
                     <div class="col-md-6">
                        <?php echo render_select('floor_id', $sub_groups, array('id', 'sub_group_name'), 'Floor Name') ?>
                     </div>

                     <div class="col-md-6">
                        <?php echo render_select('flat_id', [], [], 'Flat Name') ?>
                     </div>


                  </div>
                  <?php if (get_option('disable_language') == 0) { ?>
                     <div class="form-group select-placeholder">
                        <label for="default_language" class="control-label"><?php echo _l('localization_default_language'); ?>
                        </label>
                        <select name="default_language" id="default_language" class="form-control selectpicker" data-none-selected-text="<?php echo _l('dropdown_non_selected_tex'); ?>">
                           <option value=""><?php echo _l('system_default_string'); ?></option>
                           <?php foreach ($this->app->get_available_languages() as $availableLanguage) {
                              $selected = '';
                              if (isset($client)) {
                                 if ($client->default_language == $availableLanguage) {
                                    $selected = 'selected';
                                 }
                              }
                           ?>
                              <option value="<?php echo pur_html_entity_decode($availableLanguage); ?>" <?php echo pur_html_entity_decode($selected); ?>><?php echo ucfirst($availableLanguage); ?></option>
                           <?php } ?>
                        </select>
                     </div>
                  <?php } ?>
               </div>
               <div class="col-md-6">
                  <div class="row">
                     <div class="col-md-6">
                        <?php $value = (isset($client) ? $client->tokan_amount : ''); ?>
                        <?php echo render_input('tokan_amount', 'Token Amount(₹)', $value, 'number'); ?>
                     </div>
                     <div class="col-md-6">
                        <?php $value = (isset($client) ? $client->final_amount : ''); ?>
                        <?php echo render_input('final_amount', 'Final Amount(₹)', $value, 'number'); ?>
                     </div>
                  </div>
                  <?php $value = (isset($client) ? $client->address : ''); ?>
                  <?php echo render_textarea('address', 'client_address', $value); ?>

                  <?php $bank_detail = (isset($client) ? $client->bank_detail : ''); ?>
                  <?php echo render_textarea('bank_detail', 'bank_detail', $bank_detail); ?>
                  <?php $payment_terms = (isset($client) ? $client->payment_terms : ''); ?>
                  <?php echo render_textarea('payment_terms', 'payment_terms', $payment_terms); ?>
               </div>
            </div>
         </div>




      </div>
   </div>
   <?php echo form_close(); ?>
</div>
<?php if (isset($client)) { ?>
   <?php if (has_permission('purchase_vendors', '', 'create') || has_permission('purchase_vendors', '', 'edit')) { ?>
      <div class="modal fade" id="customer_admins_assign" tabindex="-1" role="dialog">
         <div class="modal-dialog">
            <?php echo form_open(admin_url('purchase/assign_vendor_admins/' . $client->userid)); ?>
            <div class="modal-content">
               <div class="modal-header">
                  <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                  <h4 class="modal-title"><?php echo _l('assign_admin'); ?></h4>
               </div>
               <div class="modal-body">
                  <?php
                  $selected = array();
                  foreach ($customer_admins as $c_admin) {
                     array_push($selected, $c_admin['staff_id']);
                  }
                  echo render_select('customer_admins[]', $staff, array('staffid', array('firstname', 'lastname')), '', $selected, array('multiple' => true), array(), '', '', false); ?>
               </div>
               <div class="modal-footer">
                  <button type="button" class="btn btn-default" data-dismiss="modal"><?php echo _l('close'); ?></button>
                  <button type="submit" class="btn btn-info"><?php echo _l('submit'); ?></button>
               </div>
            </div>
            <!-- /.modal-content -->
            <?php echo form_close(); ?>
         </div>
         <!-- /.modal-dialog -->
      </div>
      <!-- /.modal -->
   <?php } ?>
<?php } ?>


<script>
   $('select[name="group_id"]').on('change', function() {

      var data_select = {}

      ;
      data_select.group_id = $('select[name="group_id"]').val();


      $.post(admin_url + 'warehouse/get_subgroup_fill_data', data_select).done(function(response) {
         response = JSON.parse(response);
         $("select[name='sub_group']").html('');

         $("select[name='sub_group']").append(response.subgroup);
         $("select[name='sub_group']").selectpicker('refresh');

         if (sub_group_value != '') {

            $("select[name='sub_group']").val(sub_group_value).change();
            sub_group_value = '';
         }



      });

   });
</script>