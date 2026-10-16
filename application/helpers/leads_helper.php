<?php

defined('BASEPATH') or exit('No direct script access allowed');

hooks()->add_action('app_admin_head', 'leads_app_admin_head_data');

function leads_app_admin_head_data()
{
?>
    <script>
        var leadUniqueValidationFields = <?php echo json_decode(json_encode(get_option('lead_unique_validation'))); ?>;
        var leadAttachmentsDropzone;
    </script>
<?php
}

/**
 * Check if the user is lead creator
 * @since  Version 1.0.4
 * @param  mixed  $leadid leadid
 * @param  mixed  $staff_id staff id (Optional)
 * @return boolean
 */

function is_lead_creator($lead_id, $staff_id = '')
{
    if (!is_numeric($staff_id)) {
        $staff_id = get_staff_user_id();
    }

    return total_rows(db_prefix() . 'leads', [
        'addedfrom' => $staff_id,
        'id'        => $lead_id,
    ]) > 0;
}

/**
 * Lead consent URL
 * @param  mixed $id lead id
 * @return string
 */
function lead_consent_url($id)
{
    return site_url('consent/l/' . get_lead_hash($id));
}

/**
 * Lead public form URL
 * @param  mixed $id lead id
 * @return string
 */
function leads_public_url($id)
{
    return site_url('forms/l/' . get_lead_hash($id));
}

/**
 * Get and generate lead hash if don't exists.
 * @param  mixed $id  lead id
 * @return string
 */
function get_lead_hash($id)
{
    $CI   = &get_instance();
    $hash = '';

    $CI->db->select('hash');
    $CI->db->where('id', $id);
    $lead = $CI->db->get(db_prefix() . 'leads')->row();
    if ($lead) {
        $hash = $lead->hash;
        if (empty($hash)) {
            $hash = app_generate_hash() . '-' . app_generate_hash();
            $CI->db->where('id', $id);
            $CI->db->update(db_prefix() . 'leads', ['hash' => $hash]);
        }
    }

    return $hash;
}

/**
 * Get leads summary
 * @return array
 */
function get_leads_summary()
{
    $CI = &get_instance();
    if (!class_exists('leads_model')) {
        $CI->load->model('leads_model');
    }
    $statuses = $CI->leads_model->get_status();

    $totalStatuses         = count($statuses);
    $has_permission_view   = staff_can('view',  'leads');
    $sql                   = '';
    $whereNoViewPermission = '(addedfrom = ' . get_staff_user_id() . ' OR assigned=' . get_staff_user_id() . ' OR is_public = 1)';

    $statuses[] = [
        'lost'  => true,
        'name'  => _l('lost_leads'),
        'color' => '#fc2d42',
    ];

    /*    $statuses[] = [
        'junk'  => true,
        'name'  => _l('junk_leads'),
        'color' => '',
    ];*/

    foreach ($statuses as $status) {
        $sql .= ' SELECT COUNT(*) as total';
        $sql .= ',SUM(lead_value) as value';
        $sql .= ' FROM ' . db_prefix() . 'leads';

        if (isset($status['lost'])) {
            $sql .= ' WHERE lost=1';
        } elseif (isset($status['junk'])) {
            $sql .= ' WHERE junk=1';
        } else {
            $sql .= ' WHERE status=' . $status['id'];
        }
        if (!$has_permission_view) {
            $sql .= ' AND ' . $whereNoViewPermission;
        }
        $sql .= ' UNION ALL ';
        $sql = trim($sql);
    }

    $result = [];

    // Remove the last UNION ALL
    $sql    = substr($sql, 0, -10);
    $result = $CI->db->query($sql)->result();

    if (!$has_permission_view) {
        $CI->db->where($whereNoViewPermission);
    }

    $total_leads = $CI->db->count_all_results(db_prefix() . 'leads');

    foreach ($statuses as $key => $status) {
        if (isset($status['lost']) || isset($status['junk'])) {
            $statuses[$key]['percent'] = ($total_leads > 0 ? number_format(($result[$key]->total * 100) / $total_leads, 2) : 0);
        }

        $statuses[$key]['total'] = $result[$key]->total;
        $statuses[$key]['value'] = $result[$key]->value;
    }

    return $statuses;
}

/**
 * Render lead status select field with ability to create inline statuses with + sign
 * @param  array  $statuses         current statuses
 * @param  string  $selected        selected status
 * @param  string  $lang_key        the label of the select
 * @param  string  $name            the name of the select
 * @param  array   $select_attrs    additional select attributes
 * @param  boolean $exclude_default whether to exclude default Client status
 * @return string
 */
function render_leads_status_select($statuses, $selected = '', $lang_key = '', $name = 'status', $select_attrs = [], $exclude_default = false)
{
    foreach ($statuses as $key => $status) {
        if ($status['isdefault'] == 1) {
            if ($exclude_default == false) {
                $statuses[$key]['option_attributes'] = ['data-subtext' => _l('leads_converted_to_client')];
            } else {
                unset($statuses[$key]);
            }

            break;
        }
    }

    if (is_admin() || get_option('staff_members_create_inline_lead_status') == '1') {
        return render_select_with_input_group($name, $statuses, ['id', 'name'], $lang_key, $selected, '<div class="input-group-btn"><a href="#" class="btn btn-default" onclick="new_lead_status_inline();return false;" class="inline-field-new"><i class="fa fa-plus"></i></a></div>', $select_attrs);
    }

    return render_select($name, $statuses, ['id', 'name'], $lang_key, $selected, $select_attrs);
}

/**
 * Render lead source select field with ability to create inline source with + sign
 * @param  array   $sources         current sourcees
 * @param  string  $selected        selected source
 * @param  string  $lang_key        the label of the select
 * @param  string  $name            the name of the select
 * @param  array   $select_attrs    additional select attributes
 * @return string
 */
function render_leads_source_select($sources, $selected = '', $lang_key = '', $name = 'source', $select_attrs = [])
{
    if (is_admin() || get_option('staff_members_create_inline_lead_source') == '1') {
        echo render_select_with_input_group($name, $sources, ['id', 'name'], $lang_key, $selected, '<div class="input-group-btn"><a href="#" class="btn btn-default" onclick="new_lead_source_inline();return false;" class="inline-field-new"><i class="fa fa-plus"></i></a></div>', $select_attrs);
    } else {
        echo render_select($name, $sources, ['id', 'name'], $lang_key, $selected, $select_attrs);
    }
}

/**
 * Load lead language
 * Used in public GDPR form
 * @param  string $lead_id
 * @return string return loaded language
 */
function load_lead_language($lead_id)
{
    $CI = &get_instance();
    $CI->db->where('id', $lead_id);
    $lead = $CI->db->get(db_prefix() . 'leads')->row();

    // Lead not found or default language already loaded
    if (!$lead || empty($lead->default_language)) {
        return false;
    }

    $language = $lead->default_language;

    if (!file_exists(APPPATH . 'language/' . $language)) {
        return false;
    }

    $CI->lang->is_loaded = [];
    $CI->lang->language  = [];

    $CI->lang->load($language . '_lang', $language);
    load_custom_lang_file($language);
    $CI->lang->set_last_loaded_language($language);

    return true;
}

function get_interested_in($id = null)
{
    $CI = &get_instance();
    $CI->db->where('status', 1);

    // If an ID is provided, get the specific record
    if ($id !== null) {
        $CI->db->where('id', $id);
        $record = $CI->db->get(db_prefix() . 'leads_interested')->row();

        // Return the 'name' property if the record exists, otherwise return null
        return $record ? $record->name : null;
    } else {
        // No ID provided, return all matching records as an array
        $records = $CI->db->get(db_prefix() . 'leads_interested')->result_array();
        return $records;
    }
}

function get_facing_preference($id = null)
{
    $CI = &get_instance();
    $CI->db->where('status', 1);

    // If an ID is provided, get the specific record
    if ($id !== null) {
        $CI->db->where('id', $id);
        $record = $CI->db->get(db_prefix() . 'leads_facing_preference')->row();

        // Return the 'name' property if the record exists, otherwise return null
        return $record ? $record->name : null;
    } else {
        // No ID provided, return all matching records as an array
        $records = $CI->db->get(db_prefix() . 'leads_facing_preference')->result_array();
        return $records;
    }
}
function get_projects($id = null)
{
    $CI = &get_instance();


    // If an ID is provided, get the specific record
    if ($id !== null) {
        $CI->db->where('id', $id);
        $record = $CI->db->get(db_prefix() . 'projects')->row();

        // Return the 'name' property if the record exists, otherwise return null
        return $record ? $record->name : null;
    } else {
        // No ID provided, return all matching records as an array
        $records = $CI->db->get(db_prefix() . 'projects')->result_array();
        return $records;
    }
}

function get_assgined_projects($staff_id)
{
    $CI = &get_instance();
    $CI->db->select('project_id');
    $CI->db->where('staff_id', $staff_id);
    $CI->db->from(db_prefix() . 'project_members');

    return $CI->db->get()->result_array();
}

function get_leads_status_name_by_id($id)
{
    if (!empty($id)) {
        $CI = &get_instance();
        $CI->db->select('name');
        $CI->db->from(db_prefix() . 'leads_status');
        $CI->db->where('id', $id);
        $result = $CI->db->get()->row();
        if (!empty($result)) {
            return $result->name;
        }
    }
    return '';
}

function get_leads_source_name_by_id($id)
{
    if (!empty($id)) {
        $CI = &get_instance();
        $CI->db->select('name');
        $CI->db->from(db_prefix() . 'leads_sources');
        $CI->db->where('id', $id);
        $result = $CI->db->get()->row();
        if (!empty($result)) {
            return $result->name;
        }
    }
    return '';
}

function add_lead_activity_log($id, $is_create = true)
{
    $CI = &get_instance();
    if (!empty($id)) {
        $CI->db->where('id', $id);
        $lead = $CI->db->get(db_prefix() . 'leads')->row();
        if (!empty($lead)) {
            $is_create_value = $is_create ? 'created' : 'deleted';
            $description = "Lead <b>" . $lead->name . "</b> has been " . $is_create_value . ".";
            $CI->db->insert(db_prefix() . 'module_activity_log', [
                'module_name' => 'lead',
                'rel_id' => $id,
                'description' => $description,
                'date' => date('Y-m-d H:i:s'),
                'staffid' => get_staff_user_id()
            ]);
        }
    }
    return true;
}

function update_all_lead_fields_activity_log($id, $new_data)
{
    $CI = &get_instance();
    $CI->load->model('staff_model');
    if (empty($id)) {
        return false;
    }
    $lead = $CI->db->where('id', $id)
        ->get(db_prefix() . 'leads')
        ->row();
    if (!$lead) {
        return false;
    }
    $old_data = (array)$lead;
    $normalize = function ($value) {
        $value = trim((string)$value);
        if (in_array(strtolower($value), ['null', 'none', 'nil', 'n/a', '-', '--'])) {
            return '';
        }
        if ($value === '0000-00-00') {
            return '';
        }
        if (is_numeric($value)) {
            $num = (float)$value;
            return ($num == 0.0) ? '' : $num;
        }
        return strtolower($value);
    };
    $norm_old = array_map($normalize, $old_data);
    $norm_new = array_map($normalize, $new_data);
    $changes = array_diff_assoc($norm_new, $norm_old);
    if (empty($changes)) {
        return true;
    }
    $field_map = [
        'status' => _l('lead_add_edit_status'),
        'source' => _l('lead_add_edit_source'),
        'assigned' => _l('lead_add_edit_assigned'),
        'name' => _l('lead_add_edit_name'),
        'projects' => _l('Projects'),
        'phonenumber' => _l('lead_add_edit_phonenumber'),
        'alt_phonenumber' => _l('Alt PhoneNumber'),
        'lead_value' => _l('lead_value'),
        'email' => _l('lead_add_edit_email'),
        'broker' => _l('Broker Name'),
        'firm' => _l('Firm Name'),
        'contact_details' => _l('Broker Contact Details'),
        'call_time' => _l('Call Time'),
    ];
    foreach ($changes as $field => $dummy) {
        if (!isset($field_map[$field])) {
            continue;
        }
        $old_value = $old_data[$field] ?? '';
        $new_value = $new_data[$field] ?? '';
        if ($field === 'status') {
            $old_value = !empty($old_value) ? get_leads_status_name_by_id($old_value) : '';
            $new_value = !empty($new_value) ? get_leads_status_name_by_id($new_value) : '';
        }
        if ($field === 'source') {
            $old_value = !empty($old_value) ? get_leads_source_name_by_id($old_value) : '';
            $new_value = !empty($new_value) ? get_leads_source_name_by_id($new_value) : '';
        }
        if ($field === 'assigned') {
            $staff_list = $CI->staff_model->get('', ['active' => 1]);
            $opts = array_combine(
                array_column($staff_list, 'staffid'),
                array_map(fn($a) => $a['firstname'] . ' ' . $a['lastname'], $staff_list)
            );
            $old_value = $opts[$old_value] ?? '';
            $new_value = $opts[$new_value] ?? '';
        }
        update_lead_activity_log($id, $field_map[$field], $old_value, $new_value);
    }
    return true;
}

function update_lead_activity_log($id, $field, $old_value, $new_value)
{
    $CI = &get_instance();
    if (!empty($id)) {
        $CI->db->where('id', $id);
        $lead = $CI->db->get(db_prefix() . 'leads')->row();
        if (!empty($lead)) {
            $old_value = !empty($old_value) ? $old_value : 'None';
            $new_value = !empty($new_value) ? $new_value : 'None';
            $description = "" . $field . " field is updated from <b>" . $old_value . "</b> to <b>" . $new_value . "</b> in Lead <b>" . $lead->name . "</b>.";
            $CI->db->insert(db_prefix() . 'module_activity_log', [
                'module_name' => 'lead',
                'rel_id' => $lead->id,
                'description' => $description,
                'date' => date('Y-m-d H:i:s'),
                'staffid' => get_staff_user_id()
            ]);
        }
    }
    return true;
}