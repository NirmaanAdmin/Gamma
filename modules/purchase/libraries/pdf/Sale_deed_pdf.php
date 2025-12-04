<?php

defined('BASEPATH') or exit('No direct script access allowed');

include_once(APPPATH . 'libraries/pdf/App_pdf.php');

class Sale_deed_pdf extends App_pdf
{
    protected $sale_deed;

    public function __construct($sale_deed)
    {
        $sale_deed = hooks()->apply_filters('request_html_pdf_data', $sale_deed);
        $GLOBALS['Sale_deed_pdf'] = $sale_deed;

        parent::__construct();

        $this->sale_deed = $sale_deed;

        // Custom legal size (8.5 x 14 inches)
        $custom_layout = [215.9, 355.6];
        $this->SetPageFormat($custom_layout, 'P');

        // Enable header
        $this->setPrintHeader(true);

        // Key fix: Set header margin to the height of your header + padding
        $this->setHeaderMargin(38); // 30 (header height) + 8 (padding)

        // Set margins - top should be >= header margin
        $this->SetMargins(15, 38, 15);

        $this->SetAutoPageBreak(true, 20);
        $this->SetTitle(_l('sale_deed'));
        $this->sale_deed = $this->fix_editor_html($this->sale_deed);

        // Manually add first page with correct positioning
        $this->AddPage();

        // Force starting position below header for first page
        $this->SetY(38);
    }


    public function prepare()
    {
        // Don't auto-add page here since we added it in constructor
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
    // -----------------------------------------------------------------------------
    // CUSTOM HEADER
    // -----------------------------------------------------------------------------
    public function Header()
    {
        // Top Line
        $this->SetLineStyle(['width' => 0.4]);
        $this->Line(10, 12, $this->getPageWidth() - 10, 12);

        $this->SetFont('helvetica', 'B', 12);
        $this->SetXY(0, 15);
        $this->Cell(0, 6, "“ KAUTILYA ONE-54 ”", 0, 1, 'C');

        $this->SetFont('helvetica', '', 10);
        $this->SetXY(0, 22);
        $this->Cell(0, 6, "RERA No. PR/GJ/AHMEDABAD/AHMEDABAD CITY/AUDA/MAA10980/291122", 0, 1, 'C');

        $this->Line(10, 30, $this->getPageWidth() - 10, 30);

        $this->SetY(40);
    }
}
