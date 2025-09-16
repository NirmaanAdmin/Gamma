<?php

defined('BASEPATH') or exit('No direct script access allowed');

include_once(APPPATH . 'libraries/pdf/App_pdf.php');

class Sale_deed_pdf extends App_pdf
{
    protected $sale_deed;

    public function __construct($sale_deed)
    {
        $sale_deed                = hooks()->apply_filters('request_html_pdf_data', $sale_deed);
        $GLOBALS['Sale_deed_pdf'] = $sale_deed;

        parent::__construct();

        $this->sale_deed = $sale_deed;

        $this->SetTitle(_l('sale_deed'));
        # Don't remove these lines - important for the PDF layout
        $this->sale_deed = $this->fix_editor_html($this->sale_deed);
    }

    public function prepare()
    {
        $this->set_view_vars('sale_deed', $this->sale_deed);

        return $this->build();
    }

    protected function type()
    {
        return 'sale_deed';
    }

    protected function file_path()
    {
        $customPath = APPPATH . 'views/themes/' . active_clients_theme() . '/views/my_requestpdf.php';
        $actualPath = APP_MODULES_PATH . '/purchase/views/customers/sale_deedpdf.php';

        if (file_exists($customPath)) {
            $actualPath = $customPath;
        }

        return $actualPath;
    }
}