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
               <li role="presentation">
                  <a href="#cost_certificate" aria-controls="cost_certificate" role="tab" data-toggle="tab">
                     <?php echo _l('Cost Certificate'); ?>
                  </a>
               </li>
            </ul>
         </div>
      </div>
      <div class="tab-content">


         <div role="tabpanel" class="tab-pane<?php if (!$this->input->get('tab')) {
                                                echo ' active';
                                             }; ?>" id="sale_agreement">
            <a href="<?php echo admin_url('purchase/sale_agreements/' . $client->userid); ?>" class="btn btn-info new-contact mbot25 pull-right"><?php echo _l('New Agreement'); ?></a>

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
                  <?php if (isset($sale_agreements) && count($sale_agreements) > 0) {
                     $sr = 1; ?>
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

         <div role="tabpanel" class="tab-pane" id="cost_certificate">
            <a href="<?php echo admin_url('purchase/cost_certificates/' . $client->userid); ?>" class="btn btn-info new-contact mbot25 pull-right"><?php echo _l('New Certificate'); ?></a>

            <table class="table dt-table">
               <thead>
                  <tr>
                     <th>#</th>
                     <th><?php echo _l('Certificate Name'); ?></th>
                     <th><?php echo _l('Certificate Date'); ?></th>
                     <th class="text-right"><?php echo _l('options'); ?></th>
                  </tr>
               </thead>
               <tbody>
                  <?php if (isset($cost_certificates) && count($cost_certificates) > 0) {
                     $sr = 1; ?>
                     <?php foreach ($cost_certificates as $certificate) { ?>
                        <tr>
                           <td><?php echo $sr++; ?></td>
                           <td><?php echo $certificate['cost_certificate_name']; ?></td>
                           <td data-order="<?php echo pur_html_entity_decode($certificate['create_at']); ?>"><?php echo date('d M, Y', strtotime($certificate['create_at'])); ?></td>
                           <td class="text-right">
                              <div class="btn-group">
                                 <a href="<?php echo admin_url('purchase/edit_cost_certificates/' . $certificate['id']); ?>" class="btn btn-default btn-icon"><i class="fa fa-pencil-square"></i></a>
                                 <a href="<?php echo admin_url('purchase/delete_cost_certificates/' . $certificate['id']); ?>" class="btn btn-danger _delete btn-icon"><i class="fa fa-remove"></i></a>
                              </div>
                           </td>
                        </tr>
                     <?php } ?>
                  <?php } ?>
               </tbody>
            </table>
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