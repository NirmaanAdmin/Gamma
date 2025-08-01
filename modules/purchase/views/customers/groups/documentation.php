<?php defined('BASEPATH') or exit('No direct script access allowed'); ?>
<h4 class="mtop5"><?php echo _l('documentation'); ?></h4>
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
                  <a href="#sale_agreement" aria-controls="sale_agreement" role="tab" data-toggle="tab">
                     <?php echo _l('Sale Agreement'); ?>
                  </a>
               </li>
               <!-- <?php
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
               <?php } ?> -->
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
               <?php
               // echo render_custom_fields('vendors', $rel_id);
               form_hidden('sale_agreement', true);
               ?>
            </div>
         <?php } ?>

         <div role="tabpanel" class="tab-pane<?php if (!$this->input->get('tab')) {
                                                echo ' active';
                                             }; ?>" id="sale_agreement">
            <a href="<?php echo admin_url('purchase/sale_agreements/'.$client->userid); ?>" class="btn btn-info new-contact mbot25 pull-right"><?php echo _l('New Agreement'); ?></a>

            <table class="table dt-table">
               <thead>
                  <tr>
                     <th>#</th>
                     <th><?php echo _l('Agreement Name'); ?></th>
                     <th><?php echo _l('Agreement Date'); ?></th>
                     <th class="text-right"><?php echo _l('options'); ?></th>
                  </tr>
               </thead>
               <tbody>
                  <?php if (isset($sale_agreements) && count($sale_agreements) > 0) { $sr = 1; ?>
                     <?php foreach ($sale_agreements as $agreement) { ?>
                        <tr>
                           <td><?php echo $sr++; ?></td>
                           <td><?php echo pur_html_entity_decode($agreement['agreement_name']); ?></td>
                           <td data-order="<?php echo pur_html_entity_decode($agreement['create_at']); ?>"><?php echo date('d M, Y', strtotime($agreement['create_at'])); ?></td>
                           <td class="text-right">
                              <div class="btn-group">
                                 <a href="<?php echo admin_url('purchase/edit_sale_agreements/' . $agreement['id']); ?>" class="btn btn-default btn-icon"><i class="fa fa-pencil-square"></i></a>
                                 <a href="<?php echo admin_url('purchase/delete_sale_agreement/' . $agreement['id']); ?>" class="btn btn-danger _delete btn-icon"><i class="fa fa-remove"></i></a>
                              </div>
                           </td>
                        </tr>
                     <?php } ?>
                  <?php } ?>
               </tbody>
            </table>


         </div>
         <?php if (isset($client)) { ?>
            <div role="tabpanel" class="tab-pane" id="vendor_admins">
               <?php if (has_permission('purchase_vendors', '', 'create') || has_permission('purchase_vendors', '', 'edit')) { ?>
                  <a href="#" data-toggle="modal" data-target="#customer_admins_assign" class="btn btn-info mbot30"><?php echo _l('assign_admin'); ?></a>
               <?php } ?>
               <table class="table dt-table">
                  <thead>
                     <tr>
                        <th><?php echo _l('staff_member'); ?></th>
                        <th><?php echo _l('customer_admin_date_assigned'); ?></th>
                        <?php if (has_permission('purchase_vendors', '', 'create') || has_permission('purchase_vendors', '', 'edit')) { ?>
                           <th><?php echo _l('options'); ?></th>
                        <?php } ?>
                     </tr>
                  </thead>
                  <tbody>
                     <?php foreach ($customer_admins as $c_admin) { ?>
                        <tr>
                           <td><a href="<?php echo admin_url('profile/' . $c_admin['staff_id']); ?>">
                                 <?php echo staff_profile_image($c_admin['staff_id'], array(
                                    'staff-profile-image-small',
                                    'mright5'
                                 ));
                                 echo get_staff_full_name($c_admin['staff_id']); ?></a>
                           </td>
                           <td data-order="<?php echo pur_html_entity_decode($c_admin['date_assigned']); ?>"><?php echo _dt($c_admin['date_assigned']); ?></td>
                           <?php if (has_permission('purchase_vendors', '', 'create') || has_permission('purchase_vendors', '', 'edit')) { ?>
                              <td>
                                 <a href="<?php echo admin_url('purchase/delete_vendor_admin/' . $client->userid . '/' . $c_admin['staff_id']); ?>" class="btn btn-danger _delete btn-icon"><i class="fa fa-remove"></i></a>
                              </td>
                           <?php } ?>
                        </tr>
                     <?php } ?>
                  </tbody>
               </table>
            </div>
         <?php } ?>
         <div role="tabpanel" class="tab-pane" id="billing_and_shipping">
            <div class="row">
               <div class="col-md-12">
                  <div class="row">
                     <div class="col-md-6">
                        <h4 class="no-mtop"><?php echo _l('billing_address'); ?> <a href="#" class="pull-right billing-same-as-customer"><small class="font-medium-xs"><?php echo _l('customer_billing_same_as_profile'); ?></small></a></h4>
                        <hr />
                        <?php $value = (isset($client) ? $client->billing_street : ''); ?>
                        <?php echo render_textarea('billing_street', 'billing_street', $value); ?>
                        <?php $value = (isset($client) ? $client->billing_city : ''); ?>
                        <?php echo render_input('billing_city', 'billing_city', $value); ?>
                        <?php $value = (isset($client) ? $client->billing_state : ''); ?>
                        <?php echo render_input('billing_state', 'billing_state', $value); ?>
                        <?php $value = (isset($client) ? $client->billing_zip : ''); ?>
                        <?php echo render_input('billing_zip', 'billing_zip', $value); ?>
                        <?php $selected = (isset($client) ? $client->billing_country : ''); ?>
                        <?php echo render_select('billing_country', $countries, array('country_id', array('short_name')), 'billing_country', $selected, array('data-none-selected-text' => _l('dropdown_non_selected_tex'))); ?>
                     </div>
                     <div class="col-md-6">
                        <h4 class="no-mtop">
                           <i class="fa fa-question-circle" data-toggle="tooltip" data-title="<?php echo _l('customer_shipping_address_notice'); ?>"></i>
                           <?php echo _l('shipping_address'); ?> <a href="#" class="pull-right customer-copy-billing-address"><small class="font-medium-xs"><?php echo _l('customer_billing_copy'); ?></small></a>
                        </h4>
                        <hr />
                        <?php $value = (isset($client) ? $client->shipping_street : ''); ?>
                        <?php echo render_textarea('shipping_street', 'shipping_street', $value); ?>
                        <?php $value = (isset($client) ? $client->shipping_city : ''); ?>
                        <?php echo render_input('shipping_city', 'shipping_city', $value); ?>
                        <?php $value = (isset($client) ? $client->shipping_state : ''); ?>
                        <?php echo render_input('shipping_state', 'shipping_state', $value); ?>
                        <?php $value = (isset($client) ? $client->shipping_zip : ''); ?>
                        <?php echo render_input('shipping_zip', 'shipping_zip', $value); ?>
                        <?php $selected = (isset($client) ? $client->shipping_country : ''); ?>
                        <?php echo render_select('shipping_country', $countries, array('country_id', array('short_name')), 'shipping_country', $selected, array('data-none-selected-text' => _l('dropdown_non_selected_tex'))); ?>
                     </div>
                     <?php if (
                        isset($client) &&
                        (total_rows(db_prefix() . 'invoices', array('clientid' => $client->userid)) > 0 || total_rows(db_prefix() . 'estimates', array('clientid' => $client->userid)) > 0 || total_rows(db_prefix() . 'creditnotes', array('clientid' => $client->userid)) > 0)
                     ) { ?>
                        <div class="col-md-12">
                           <div class="alert alert-warning">
                              <div class="checkbox checkbox-default">
                                 <input type="checkbox" name="update_all_other_transactions" id="update_all_other_transactions">
                                 <label for="update_all_other_transactions">
                                    <?php echo _l('customer_update_address_info_on_invoices'); ?><br />
                                 </label>
                              </div>
                              <b><?php echo _l('customer_update_address_info_on_invoices_help'); ?></b>
                              <div class="checkbox checkbox-default">
                                 <input type="checkbox" name="update_credit_notes" id="update_credit_notes">
                                 <label for="update_credit_notes">
                                    <?php echo _l('customer_profile_update_credit_notes'); ?><br />
                                 </label>
                              </div>
                           </div>
                        </div>
                     <?php } ?>
                  </div>
               </div>
            </div>
         </div>

         <div role="tabpanel" class="tab-pane" id="return_policies">
            <div class="row">
               <div class="col-md-6">
                  <?php $return_within_day = (isset($client->return_within_day) &&  $client->return_within_day != null) ? $client->return_within_day : get_option('pur_return_request_within_x_day');
                  echo render_input('return_within_day', 'pur_return_request_within_x_day', $return_within_day, 'number', ['min' => 1]); ?>
               </div>
               <div class="col-md-6">
                  <?php $return_order_fee = (isset($client) ? $client->return_order_fee : '');
                  echo render_input('return_order_fee', 'pur_fee_for_return_order', $return_order_fee, 'number'); ?>
               </div>
               <div class="col-md-12">
                  <?php $return_policies = (isset($client) ? $client->return_policies : '');
                  echo render_textarea('return_policies', 'pur_return_policies_information', $return_policies, array(), array()); ?>
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