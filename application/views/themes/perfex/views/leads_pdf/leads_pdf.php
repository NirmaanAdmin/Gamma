<?php defined('BASEPATH') or exit('No direct script access allowed');

$formrowsinfo = '';

$formrowsinfo .= '<table width="100%" bgcolor="#fff" cellspacing="0" cellpadding="5" border="1" style="word-break: break-word;">';

/* ===========================
   TABLE HEADER
=========================== */

$formrowsinfo .= '<thead>';

$formrowsinfo .= '
<tr style="font-size:16px;">
    <td colspan="10" align="center"><b>Leads Data</b></td>
</tr>

<tr style="font-size:11px;">
    <td width="4%;" align="center"><b>#</b></td>
    <td width="14%;" align="center"><b>Name</b></td>
    <td width="10%;" align="center"><b>Phone</b></td>
    <td width="10%;" align="center"><b>Alt Phone</b></td>
    <td width="14%;" align="center"><b>Project</b></td>
    <td width="10%;" align="center"><b>Status</b></td>
    <td width="10%;" align="center"><b>Source</b></td>
    <td width="12%;" align="center"><b>Assigned</b></td>
    <td width="10%;" align="center"><b>Lead Value</b></td>
    <td width="10%;" align="center"><b>Date Added</b></td>
</tr>
';

$formrowsinfo .= '</thead>';

/* ===========================
   TABLE BODY
=========================== */

$formrowsinfo .= '<tbody>';

if (!empty($lead_data)) {

    $i = 1;

    foreach ($lead_data as $row) {

        $assigned = trim(
            ($row['assigned_firstname'] ?? '') . ' ' .
            ($row['assigned_lastname'] ?? '')
        );

        $projects = !empty($row['projects'])
            ? get_projects($row['projects'])
            : '';

        $formrowsinfo .= '
        <tr style="font-size:10px;">
            <td width="4%;" align="center">'.$i++.'</td>
            <td width="14%;" align="left">'.$row['name'].'</td>
            <td width="10%;" align="left">'.$row['phonenumber'].'</td>
            <td width="10%;" align="left">'.$row['alt_phonenumber'].'</td>
            <td width="14%;" align="left">'.$projects.'</td>
            <td width="10%;" align="left">'.$row['status_name'].'</td>
            <td width="10%;" align="left">'.$row['source_name'].'</td>
            <td width="12%;" align="left">'.$assigned.'</td>
            <td width="10%;" align="right">'.$row['lead_value'].'</td>
            <td width="10%;" align="center">'.$row['dateadded'].'</td>
        </tr>
        ';
    }

} else {

    $formrowsinfo .= '
    <tr>
        <td colspan="10" align="center">No Data Found</td>
    </tr>
    ';
}

$formrowsinfo .= '</tbody>';
$formrowsinfo .= '</table>';

/* ===========================
   PDF OUTPUT
=========================== */

$pdf->writeHTML($formrowsinfo, true, false, false, false, '');
