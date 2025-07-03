<?php

defined('BASEPATH') or exit('No direct script access allowed');

$organization_info = '';
$organization_info = '<div style="color:#424242;">';
$organization_info .= format_organization_info();
$organization_info .= '</div><br/><br/>';
$pdf->writeHTML($organization_info, true, false, false, false, '');

$formbasicinfo = '';
$formbasicinfo .= '<table width="100%" bgcolor="#fff" cellspacing="0" cellpadding="5" border="1">';
$formbasicinfo .= '<tbody>';
$formbasicinfo .= '
<tr style="font-size:20px;" colspan="4">
    <td align="center"><b>DAILY PROGRESS REPORT</b></td>
</tr>
<tr style="font-size:13px;">
    <td width="20%;" align="left"><b>' . _l('form_settings_subject') . '</b></td>
    <td width="40%;" align="left">' . $form_data->subject . '</td>
    <td width="20%;" align="left"><b>' . _l('form_settings_assign_to') . '</b></td>
    <td width="20%;" align="left">' . get_staff_full_name($form_data->assigned) . '</td>
</tr>
<tr style="font-size:13px;">
    <td width="20%;" align="left"><b>' . _l('project') . '</b></td>
    <td width="40%;" align="left">' . get_project_name_by_id($form_data->project_id) . '</td>
    <td width="20%;" align="left"><b>Due Date</b></td>
    <td width="20%;" align="left">' . date('d M, Y', strtotime($form_data->duedate)) . '</td>
</tr>
<tr style="font-size:13px;">
    <td width="20%;" align="left"><b>' . _l('department') . '</b></td>
    <td width="40%;" align="left">' . get_staff_department_name($form_data->department) . '</td>
    <td width="20%;" align="left"><b>Priority</b></td>
    <td width="20%;" align="left">' . get_priority_name($form_data->priority) . '</td>
</tr>
<tr style="font-size:13px;">
    <td width="20%;" align="left"><b>DPR Date</b></td>
    <td width="40%;" align="left">' . date('d M, Y', strtotime($form_data->date)) . '</td>
    <td width="20%;" align="left"><b>Client</b></td>
    <td width="20%;" align="left">' . get_company_name($form_basic_info->client_id) . '</td>
</tr>
<tr style="font-size:13px;">
    <td width="20%;" align="left"><b>Consultant</b></td>
    <td width="40%;" align="left">' . $form_basic_info->consultant . '</td>
    <td width="20%;" align="left"><b>PMC</b></td>
    <td width="20%;" align="left">' . $form_basic_info->pmc . '</td>
</tr>
<tr style="font-size:13px;">
    <td width="20%;" align="left"><b>Weather</b></td>
    <td width="10%;" align="left">' . $form_basic_info->weather . '</td>
    <td width="20%;" align="left"><b>Work Stop?</b></td>
    <td width="10%;" align="left">' . $form_basic_info->work_stop . '</td>
    <td width="20%;" align="left"><b>Contractor</b></td>
    <td width="20%;" align="left">' . $form_basic_info->contractor . '</td>
</tr>
';
$formbasicinfo .= '</tbody>';
$formbasicinfo .= '</table>';

$pdf->writeHTML($formbasicinfo, true, false, false, false, '');

$formrowsinfo = '';
$formrowsinfo .= '<table width="100%" bgcolor="#fff" cellspacing="0" cellpadding="5" border="1" style="word-break: break-word;">';
$formrowsinfo .= '<thead>';  // Changed from tbody to thead for header rows
$formrowsinfo .= '
<tr style="font-size:20px;">
    <td colspan="11" align="center"><b>ACTIVITY WITH LOCATION & OUTPUT</b></td>
</tr>
<tr style="font-size:11px;">
    <td rowspan="2" width="11%;" align="center"><b>Location</b></td>
    <td rowspan="2" width="11%;" align="center"><b>Agency</b></td>
    <td rowspan="2" width="10%;" align="center"><b>Type</b></td>
    <td rowspan="2" width="16%;" align="center"><b>Remarks</b></td> 
    <td colspan="2" width="20%;" align="center"><b>Work Progress</b></td>
    <td colspan="3" width="19%;" align="center"><b>Type Of Manpower</b></td>
    <td rowspan="2" width="8%;" align="center"><b>Machinery</b></td>
    <td rowspan="2" width="5%;" align="center"><b>Total</b></td> 
</tr>
<tr style="font-size:11px;">
    <td width="10%;" align="center"><b>Work Execute (smt/Rmt/Cmt)</b></td>
    <td width="10%;" align="center"><b>Material Consumption</b></td>
    <td width="6%;" align="center"><b>Skilled</b></td>
    <td width="8%;" align="center"><b>Unskilled</b></td>
    <td width="5%;" align="center"><b>Total</b></td>
</tr>
';
$formrowsinfo .= '</thead>';

$formrowsinfo .= '<tbody>';  // Start tbody for data rows
if (!empty($form_rows_info)) {
    foreach ($form_rows_info as $key => $value) {
        $formrowsinfo .= '
            <tr style="font-size:11px;">
                <td align="left" width="11%;">' . $value['location'] . '</td>
                <td align="left" width="11%;">' . get_vendor_company_name($value['agency']) . '</td>
                <td align="left" width="10%;">' . get_progress_report_type_name($value['type']) . '</td>
                <td align="left" width="16%;">' . $value['sub_type'] . '</td> 
                <td align="left" width="10%;">' . $value['work_execute'] . '</td>
                <td align="left" width="10%;">' . $value['material_consumption'] . '</td>
                <td align="center" width="6%;">' . $value['male'] . '</td>
                <td align="center" width="8%;">' . $value['female'] . '</td>
                <td align="center" width="5%;">' . $value['total'] . '</td>
                <td align="left" width="8%;">' . get_progress_report_machinary_name($value['machinery']) . '</td>
                <td align="center" width="5%;">' . $value['total_machinery'] . '</td> 
            </tr>';
    }
}
$formrowsinfo .= '</tbody>';
$formrowsinfo .= '</table>';



$pdf->SetAutoPageBreak(true, 20);
$pdf->writeHTML($formrowsinfo, true, false, false, false, '');

// Add a page break before the note
if ($form_data->message != '') {
    $pdf->AddPage(); // Add a new page

    $noteContent = '<h2>Note:</h2>';
    $noteContent .= '<p>' . $form_data->message . '</p>';

    $pdf->writeHTML($noteContent, true, false, false, false, '');
}
