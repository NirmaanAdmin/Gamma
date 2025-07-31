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
               <?php echo render_custom_fields('vendors', $rel_id); ?>
            </div>
         <?php } ?>
         <div role="tabpanel" class="tab-pane<?php if (!$this->input->get('tab')) {
                                                echo ' active';
                                             }; ?>" id="sale_agreement">
            <form action="<?php echo admin_url('your_controller/save_agreement'); ?>" method="POST">
                  <p>AGREEMENT FOR SALE</p>
                  <p>(Without Possession)</p><br>
                  <p>THIS AGREEMENT FOR SALE is made and executed at Ahmedabad on this <input type="text" name="field_1" class="form-control input-sm" style="display:inline-block; width:auto;" /> day of <input type="text" name="field_2" class="form-control input-sm" style="display:inline-block; width:auto;" />, 2023.</p><br>
                  <p>BETWEEN</p><br>
                  <p> kautilya Developers PAN : AATFK 6344 G</p><br>
                  <p>A Partnership Firm, having its Registered office at : 16, Dena Bank Society, Near Kiran Park, Nava Vadaj, Ahmedabad - 380013 & having site office at, "Kautilya One-54", located at Opp. Swaminarayan Temple, B/h. Omkar Lotus, Chandkheda, Ahmedabad.</p><br>
                  <p>Hereinafter referred to as the “ Vendor ” and/or “ Developer ” (which expression shall, unless it be repugnant to the context or the meaning thereof, be deemed to mean and include its present and future partner, executors, administrators, legal representatives and permitted assigns etc.) of the FIRST PART;</p><br>
                  <p>AND</p><br>
                  <p>(1) SNEHLATA MATHUR</p>
                  <p><input type="text" name="field_3" class="form-control input-sm" style="display:inline-block; width:auto;" /> <input type="text" name="field_4" class="form-control input-sm" style="display:inline-block; width:auto;" /></p>
                  <p>(2) MATHUR MANOJ KUMAR</p>
                  <p><input type="text" name="field_5" class="form-control input-sm" style="display:inline-block; width:auto;" /> <input type="text" name="field_6" class="form-control input-sm" style="display:inline-block; width:auto;" /></p>
                  <p>Both Adult Residing at –</p><br><br><br><br>
                  <p>Hereinafter referred to as the “PURCHASER” (Which expression shall unless repugnant to the context and meaning thereof shall mean and include his / her / their / its heirs, legal representatives, executors, successors and assigns) of the SECOND PART.</p><br>
                  <p>The Vendor and Purchaser are hereinafter individually referred to as the ‘Party’ and collectively referred to as the ‘Parties’.</p><br>
                  <p>WHEREAS-</p><br>
                  <p>(A) The developer is seized and possessed of or otherwise well sufficiently entitled to all that piece and parcel of land bearing
                     1) Final Plot No. 321, admeasuring 3400 sq.mtrs. of Town Planning Scheme No. 76 / B (Chandkheda), allotted in lieu of Survey No. 875/3 admeasuring 5666 sq.mtrs. & 2) Final Plot No. 322, admeasuring 2125 sq.mtrs. of Town Planning Scheme No. 76 / B (Chandkheda), allotted in lieu of Survey No. 875/4 admeasuring 3541 sq.mtrs. situated within the village limits of Chandkheda, Taluka - Sabarmati in the Registration Sub - District of Ahmedabad - 2 (Vadaj) of District Ahmedabad (For the sake of convenience hereinafter referred to as the “Said Land”).</p><br>
                  <p>(B) The Non-Agricultural Permission for Residencial & Commercial purpose of the “Said Land” was granted by the Hon' District Collecter, Ahmedabad under 1) Order No. CB / NA / Ahmedabad / CHANDKHEDA / 875 / 3 / 1009284 / 2019 on 03-06-2019 for Survey No. 875 / 3 of Mouje Chandkheda and entry to that effect was mutated in the revenue record by mutation entry No. 13606 dated : 15-06-2019, which were certified by the competent authority on 29-07-2019 & 2) Order No. CB / LAND-1 / NA / SR - 956 / 2018 / FMPS NO - 323282 on 29-10-218 for Survey No. 875 / 4 of Mouje Chandkheda and entry to that effect was mutated in the revenue record by mutation entry No. 13372 dated :
                     15-12-2018, which were certified by the competent authority on 28-01-2019</p><br>
                  <p>(C) The Vendor has purchased the Said land Paiki 1) Survey No. 875 / 3 from Daksh enterprise, a partnership firm by sale deed registered in the office of the Sub-Registrar of Assurances of Ahmedabad - 2 (Vadaj) under Serial No. 5406, dated : 04-04-2022 and entry to that effect was mutated in the revenue record by mutation entry No. 14858, Dated : 12-04-2022, Which was certified by the competent authority on 13-05-2022 & 2) Survey No. 875 / 4 from Jayantibhai Prahladbhai Nayak, Dilipkumar alias Bipinkumar Prahladbhai Nayak, Rajendrakumar Prahladbhai Nayak, Kailasben D/o. Prahladbhai Nayak W/o. Kundanlal Nayak, Sudhaben D/o. Prahladbhai Nayak Wd/o. Maheshbhai Nayak, Nitinkumar Nandubhai Nayak, Bhavnaben D/o. Nandubhai Nayak W/o. Nileshbhai Nayak, Rinaben D/o. Nandubhai Nayak W/o. Jitendrakumar Sisodiya, Jyotiben D/o. Nandubhai Nayak W/o. Jayendrakumar Nayak, Ranjanben Wd/o. Nandubhai Prahladbhai Nayak, Ajaykumar Mahendrakumar Nayak, Amarkumar Mahendrakumar Nayak, Dipakkumar Mahendrakumar Nayak, Ashaben D/o. Mahendrakumar Nayak W/o. Krunalkumar Nayak & Pratimaben Wd/o. Mahendrakumar Prahladbhai Nayak by sale deed registered in the office of the Sub-Registrar of Assurances of Ahmedabad - 2 (Vadaj) under Serial No. 20546, dated : 22-11-2018. In said deed of sale Sankalp Infrastructure, a partnership firm remain there presence as confirming party and entry to that effect was mutated in the revenue record by mutation entry No. 13355, Dated : 01-12-2018, Which was certified by the competent authority on 03-01-2019.</p><br>
                  <p>(D) Ahmedabad Municipal Corporation granted permission for construction on said land by following Commencement Letter <input type="text" name="field_7" class="form-control input-sm" style="display:inline-block; width:auto;" /> issued on 28th July, 2022 and granted Development Permission.</p><br>
                  <p>Block No. Case No. (Rajachitthi No.)</p>
                  <p>A + B BHNTI / WZ / 210522 / CGDCRV / A6107 / R0 / M1</p>
                  <p>(Rajachitthi No. 06627 / 210522 / A6107 / R0 / M1)</p><br>
                  <p>C BHNTS / WZ / 210522 / CGDCRV / A6108 / R0 / M1</p>
                  <p>(Rajachitthi No. 06628 / 210522 / A6108 / R0 / M1)</p><br>
                  <p>D BHNTS / WZ / 210522 / CGDCRV / A6109 / R0 / M1</p>
                  <p>(Rajachitthi No. 06629 / 210522 / A6109 / R0 / M1)</p><br>
                  <p>(E) The “Said Developer” has floated scheme of Residential & Commercial units known as “ KAUTILYA ONE-54 ” (hereinafter referred to as the “Said Scheme”) on the “Said Land”.</p><br>
                  <p>(F) The said scheme has been registered under the Real Estate (Regulation and Development) Act, 2016 and under the rules of the Gujarat Real Estate (Regulation and Development) (General) Rules, 2017 under Rera Project Registration Referance No.
                     PR / GJ / Ahmedabad / ahmedabad CITY / AUDA / MAA10980 / 291122.</p><br>
                  <p>(G) The Vendor has initiated the construction as per the approved plan and Development permission.</p><br>
                  <p>(H) The Party of the Second Part has visited the said scheme and has shown his / her / their / its willingness to purchase Flat No. <input type="text" name="field_8" class="form-control input-sm" style="display:inline-block; width:auto;" /> in Wing “ <input type="text" name="field_9" class="form-control input-sm" style="display:inline-block; width:auto;" /> ” having Carpet Area (“Carpet Area” means the net usable floor area of an Property, excluding the area covered by the external walls, areas under services shafts, exclusive balcony or verandah area and exclusive open terrace area but includes the area covered by the internal partition walls of the Property) admeasuring about 80.60 sq.mtrs. (i.e. <input type="text" name="field_10" class="form-control input-sm" style="display:inline-block; width:auto;" /> sq.mtrs. Built up area) situated on <input type="text" name="field_11" class="form-control input-sm" style="display:inline-block; width:auto;" /> Floor of the said Scheme along with (i) Wash Area admeasuring 2.42 sq.mtrs.. (ii) Balcony admeasuring about 3.21 sq.mtrs.. in the scheme known as “ KAUTILYA ONE-54 ” together with undivided share in the said land admeasuring about 34.17 Sq.Mtrs. (for the sake of convenience hereinafter referred to as the “Said Property”) from the “Said Developer” at lump sum consideration amount of the said property is fixed for Rs.<input type="text" name="field_12" class="form-control input-sm" style="display:inline-block; width:auto;" />/- Rupees <input type="text" name="field_13" class="form-control input-sm" style="display:inline-block; width:auto;" /> <input type="text" name="field_14" class="form-control input-sm" style="display:inline-block; width:auto;" /> Only.</p><br>
                  <p>(I) The said entire consideration amount is included of the carpet area of the Unit, Wash Area & Balcony.</p><br>
                  <p>(J) The Vendor has provided the copies of Approved Lay-Out Plan, Key-Plan, Building Plan, Elevation Plan, Section Plan etc., N.A. permission, Sale Deed, 7/12 Extracts, all Mutation Entries No. 6, necessary orders/permissions, Loan Papers, Receipts of the Land Revenue, Title Clearance Certificate / Search Report etc. to the Party of the Second Part and after getting it verified through the Advocate / Solicitor / Legal Expert and after being satisfied with the same the Party of the Second Part has agreed to purchase the Said Property from the Vendor.</p><br>
                  <p>(K) The Vendor has given all the information about quality of the materials and goods used in the said scheme to the purchaser, which the Purchaser has got verified through their experts of the respective fields and the Purchaser is fully satisfied with same.</p><br>
                  <p>(L) The Vendor will obey all the terms and conditions, restriction laid down by the competent authority for passing the plan of the said scheme and will construct the said scheme accordingly. The vendor will be responsible for completing the construction of the said scheme and obtain B.U.Permission / Completion Certificate from the competent authority.</p><br>
                  <p>(M) The Parties herein hereby agrees to obey the following terms and conditions mentioned in this Agreement for Sale and also agrees to obey the Rules and Regulations / Laws enacted and framed from time to time by the Government.</p><br>
                  <p>NOW IT IS HEREBY AGREED BETWEEN THE PARTIES HERETO AS FOLLOWS :</p><br>
                  <p>(1) The “Said Developer” has agreed to sell to the party of the Second Part and the Party of the Second Part has agreed to purchase the “Said Property” (more particularly described in the schedule hereunder written) from the “Said Developer” at or for the entire negotiated lump sum consideration as mentioned hereinabove.</p><br>
                  <p>(2) The Party of the Second Part has paid the following amount of the entire negotiated lump sum consideration towards the Booking Amount / Earnest Money to the Said Developer as per the details mentioned below :</p><br><br><br><br>
                  <p>The Said Developer hereby acknowledges the receipt of the same and admits that the said amount shall be adjusted against the total consideration at the time of execution of Sale Deed.</p>
                  <p>The total consideration in respect of the Said Property shall be payable by the Party of the Second Part as per the payment schedule mentioned below :-</p><br>
                  <p>(i) Amount of 30% of the total consideration to be paid to the Vendor after the execution of Agreement.</p><br>
                  <p>(ii) Amount of 45% of the total consideration to be paid to the Vendor on completion of the Plinth of the building or wing in which the said Property is located.</p><br>
                  <p>(iii) Amount of 70% of the total consideration to be paid to the Vendor on completion of the slabs including podiums and stilts of the building or wing in which the said Property is located.</p><br>
                  <p>(iv) Amount of 75% of the total consideration to be paid to the Vendor on completion of the walls, internal plaster, floorings doors and windows of the said Property.</p><br>
                  <p>(v) Amount of 80% of the total consideration to be paid to the Vendor on completion of the Sanitary fittings, stair cases, lift wells, lobbies up to the floor level of the said Property.</p><br>
                  <p>(vi) Amount of 85% of the total consideration to be paid to the Vendor on completion of the external plumbing and external plaster, elevation, terraces with waterproofing of the building or wing in which the said Property is located.</p><br>
                  <p>(vii) Amount of 95% of the total consideration to be paid to the Vendor on completion of the lifts, water pumps, electrical fittings, electro, mechanical and environment requirements, entrance lobby/s, plinth protection, paving of areas appertain and all other requirements as may be prescribed in the Agreement of sale of the building or wing in which the said Property is located.</p><br>
                  <p>(viii) Balance Amount against and at the time of handing over of the possession of the Property to the Purchaser on or after receipt of B.U.Permission / completion certificate.</p><br>
                  <p>(3) The total consideration price as stated above excludes Taxes (consisting of tax paid or payable by the Vendor by way of Goods and Service Tax, and Cess or any other similar taxes which may be levied, in connection with the construction of and carrying out the project payable by the Vendor) up to the date of handing over the possession of the Said Property, which shall be separately / payable by the Purchaser in the manner as may be decided by the Vendor.</p><br>
                  <p>(4) The total consideration price is escalation-free, save and except escalations/increases, due to increase on account of development charges payable to the competent authority and/or any other increase in charges which may be levied or imposed by the competent authority Local Bodies / Government from time to time. The Vendor undertakes and agrees that while raising a demand on the Purchaser for increase in development charges, cost, or levies imposed by the competent authorities, etc., the Vendor shall enclose the said notification / order / rule / regulation published / issued in that behalf to that effect along with the demand letter being issued to the Purchaser, Which shall only be applicable on subsequent payments.</p><br>
                  <p>(5) REPRESENTATION AND WARRANTIES OF THE VENDOR:</p>
                  <p>(i) The Vendor has clear and marketable title with respect to the said land; as declared in the title report and has the requisite rights to carry out development upon the said land and also has actual, physical and legal possession of the said land for the implementation of the said scheme;</p><br>
                  <p>(ii) The Vendor has lawful rights and requisite approvals from the competent Authorities to carry out development of the said scheme and shall obtain requisite approvals from time to time to complete the development of the project;</p><br>
                  <p>(iii) There are no encumbrances upon the Project Land or the Project except those disclosed in the Title Report;</p><br>
                  <p>(iv) There are no litigations pending before any Court of law with respect to the said land or said scheme except those disclosed in the title report;</p><br>
                  <p>(v) All approvals, licenses and permits issued by the competent authorities with respect to the said scheme, said land and said building / wing are valid and subsisting and have been obtained by following due process of law. Further, all approvals, licenses and permits to be issued by the competent authorities with respect to the Project, project land and said building / wing shall be obtained by following due process of law and the Vendor has been and shall, at all times, remain to be in compliance with all applicable laws in relation to the Project, project land, Building / wing and common areas;</p><br>
                  <p>(vi) The Vendor has the right to enter into this Agreement and has not committed or omitted to perform any act or thing, whereby the right, title and interest of the Purchaser created herein, may prejudicially be affected;</p><br>
                  <p>(vii) The Vendor has not entered into any agreement for sale and/or development agreement or any other agreement/ arrangement with any person or party with respect to the said land, including the said scheme and the said property which will, in any manner, affect the rights of Purchaser under this Agreement;</p><br>
                  <p>(viii) The Vendor declares that the Vendor is not restricted in any manner whatsoever from selling the said property to the purchaser in the manner contemplated in this Agreement;</p><br>
                  <p>(6) The vendor will have to complete the construction of the said scheme as per the approved plan till 31-12-2026 and will have to obtain B.U.Permission / completion certificate.</p><br>
                  <p>(7) The Purchaser will not store in the said property any goods which are of hazardous, combustible or dangerous nature or are so heavy as to damage the construction or structure of the building in which the said property is situated or storing of which goods is objected to by the concerned local or other authority and shall take care while carrying heavy packages which may damage or likely to damage the staircases, common passages or any other structure of the building in which the said property is situated, including entrances of the building in which the said property is situated and in case any damage is caused to the building in which the Said Property is situated or the Said Property on account of negligence or default of the Purchaser in this behalf, the Purchaser shall be liable for the consequences of this breach.</p><br>
                  <p>(8) All and every cost, charges and expenses shall be borne and paid by the ALLOTTEE to the PROMOTER additionally. Such payment shall be made by the ALLOTTEE to the PROMOTER as and when demanded by the PROMOTER failing which, the ALLOTTEE shall be liable to pay interest at the rate SBI Marginal Cost of funds based Lending Rate (M.C.L.R.) + 2 % agreed hereunder for the delayed period on the outstanding amount till payment is made to the PROMOTER. Further, in any event, such outstanding amounts with interest thereon shall be paid by the ALLOTTEE to the PROMOTER before the execution and registration of the Deed of Conveyance by the PROMOTER in favour of the ALLOTTEE. At the same time PROMOTER fails to complete construction work and handingover possession within stipulated time period PROMOTER is liable to pay interest at the rate SBI Marginal Cost of funds based Lending Rate (MCLR) + 2 % to Allottee.</p><br>
                  <p>(9) Without prejudice to the right of Vendor to charge interest in terms of clause mentioned hereinabove, on the Purchaser committing default in payment on due date of any amount due and payable by the Purchaser to the Vendor under this Agreement (including his / her / their / its proportionate share of taxes levied by concerned local authority and other outgoings) and on the Purchaser committing three defaults of payment of installments, the Vendor shall at its own option, may terminate this Agreement. Provided that, Vendor shall give notice of fifteen days in writing to the Purchaser, by Registered Post AD at the address provided by the Purchaser or mail at the e-mail address provided by the Purchaser, or its intention to terminate this Agreement and of the specific breach or breaches of terms and conditions in respect of which it is intended to terminate the Agreement. If the Purchaser fails to rectify the breach or breaches mentioned by the Vendor within the period of notice then at the end of such notice period, Vendor shall be entitled to terminate this Agreement ex-parte.</p><br>
                  <p>(10) Provided further that upon termination of this Agreement as aforesaid, the Vendor shall refund to the Purchaser (subject to adjustment and recovery of any agreed liquidated damages or any other amount which may be payable to Vendor) within a period of thirty days of the termination, the installments of sale consideration of the said property which may till then have been paid by the Purchaser to the Vendor.</p><br>
                  <p>(11) The Vendor shall give possession of the property to the purchaser on or before 31-12-2026. If the Vendor fails or neglects to give possession of the Property to the Purchaser on account of reasons beyond the control the vendor and of its agents by the aforesaid date then the Vendor shall be liable on demand to refund to the Purchaser the amounts already received in respect of the Property with interest at the same rate as may be mentioned in the clause above herein above from the date the Vendor received the sum till the date the amounts and interest thereon is repaid.</p><br>
                  <p>Provided that the Vendor shall be entitled to reasonable extension of time for giving delivery of said property on the aforesaid date, if the completion of building in which the said property is to be situated is delayed on account of-</p>
                  <p>(i) War, civil commotion or act of God;</p>
                  <p>(ii) Any notice, order, rule, notification of the Government and/or other public or competent authority/court.</p><br>
                  <p>(12) The Vendor, upon obtaining the occupancy certificate from the competent authority and the payment made by the Purchaser as per the agreement shall offer in writing the possession of the said property, to the Purchaser in terms of this Agreement to be taken within 3 (three) months from the date of issue of such notice and the Vendor shall give possession of the said property to the Purchaser. The Vendor agrees and undertakes to indemnify the Purchaser in case of failure of fulfillment of any of the provisions, formalities, documentation on part of the Vendor. The Purchaser agree(s) to pay the maintenance charges as determined by the Vendor or association of Purchasers, as the case may be. The Vendor on its behalf shall offer the possession to the Purchaser in writing within 7 days of receiving the occupancy certificate of the Project.</p><br>
                  <p>The Purchaser shall take possession of the said property within 15 days of the written notice from the Vendor to the Purchaser intimating that the said property is ready for use and occupancy and if the purchaser fails to take the possession within 15 days of the written notice then the purchaser agrees to pay his / her / their / its proportionate maintenance expenses, security deposit in connection with the electricity, water connection in the said property and also to pay the escalation, if any .</p><br>
                  <p>(13) If within a period of five years from the date of handing over the Said Property to the Purchaser, the Purchaser brings to the notice of the Vendor any structural defect in the Said Property or the building in which the Said Property are situated or any defects on account of workmanship, quality or provision of service, then, whenever possible such defects shall be rectified by the Vendor at its own cost and in case it is not possible to rectify such defects, then the Purchaser shall be entitled to receive from the Vendor, compensation for such defect in the manner as provided under the Act.</p><br>
                  <p>Provided that the Vendor shall not be liable in respect of any structural defect or defects on account of workmanship, quality or provision of service which cannot be attributable to the Vendor or beyond the control of the Vendor.</p><br>
                  <p>(14) The Vendor shall confirm the final carpet area that has been allotted to the Purchaser after the construction of the Building is complete and the Building Use Permission / occupancy certificate is granted by the competent authority, by furnishing details of the changes, if any, in the carpet area, subject to a variation cap of three percent. The total price payable for the carpet area shall be recalculated upon condeveloperation by the Vendor. If there is any reduction in the carpet area within the defined limit then Vendor shall refund the excess money paid by Purchaser If there is any increase in the carpet area allotted to Purchaser, the Vendor shall demand additional amount from the Purchaser as per the next milestone of the Payment Plan. All these monetary adjustments shall be made at the same rate per square meter as agreed in above clause of this Agreement.</p><br>
                  <p>(15) The Vendor assures and declares unto the Purchaser that the said property was purchased out of the funds of Vendor and hence except the Vendor nobody else is having right, title, share, claim and interest and prior to the conveyance of the said Property, the Vendor has not sold, transferred, assigned, mortgaged or gifted the said property or any part thereof to anybody else and that there is no any order passed by any court of law restraining the Vendor from being sale, transfer, assign, mortgage of the said property to anybody else and that there are no legal proceedings standing or held on the said property by any court or authority nor any such order is issued or served by any court or authority and that the said property is not under any acquisition, requisition or reservation and that our titles to the said property are absolutely clear, marketable and saleable.</p><br>
                  <p>(16) The Promoter hereby declares that the Floor Space Index available as on date in respect of the project land is 6630 square meters only and Promoter has planned to utilize Floor Space Index of 14917.5 square meters by availing of TDR or FSI available on payment of premiums or FSI available as incentive FSI by implementing various scheme as mentioned in the Development Control Regulation or based on expectation of increased FSI which may be available in future on modification to Development Control Regulations, which are applicable to the said Project. The Promoter has disclosed the Floor Space Index of 14583.92 square meters as proposed to be utilized by him on the project land in the said Project and Allottee has agreed to purchase the said Apartment based on the proposed construction and sale of apartments to be carried out by the Promoter by utilizing the proposed FSI and on the understanding that the declared proposed FSI shall belong to Promoter only.</p><br>
                  <p>(17) In the event of sale not being completed due to any willful delay or default on the part of the Vendor, the Party of the Second Part shall have right to require specific performance by the Vendor of this agreement.</p><br>
                  <p>(18) The Purchaser will have to compulsorily become the member and obey the rules and regulations of the maintenance body to be formed in future. The purchaser will have to pay the amount of maintenance deposit, without any objection, to be collected by the maintenance body, in future.</p><br>
                  <p>(19) The Purchaser has clearly understood and agreed that the Unit-Holders of Unit No. A-101, A-102, A-103, A-104, B-101, B-102, B-103, B-104, C-101, C-102, C-103, C-104, D-101, D-102, D-103 & D-104 have got ingress and outgress to the terrace. None of the other Unit-holders of the said scheme have any right on this terrace. Another extra terrace will be common for all Unit-Holders. Unit-Holders of above mentioned unit nos. are not entitled to make any kind of temporary or permanent shade, structure or construction on said terrace. Further the purchaser has clearly understood and agreed that the unit holder of ground floor Flat No. A-001 & B-001 shall have exclusive use rights with respect to open back side margin space located adjoining to their wash yards. The Purchaser agrees and confirms the said condition and in future the Prospective Purchaser will not make any dispute or demand for the said permanent arrangement. The Unit-Holder shall allow the First Party / Maintenance Society to use the terrace for any utilities repairs and he / she / they is / are not entitled to raise any objection for the same.</p><br>
                  <p>(20) The purchaser cannot give the said property on lease, sub-lease, rent, leave and license or in any manner for his/her/their/its personal benefit till the total sale consideration of the said property is completed.</p><br>
                  <p>(21) The Purchaser cannot transfer the said property to anybody on the basis of this Agreement for Sale.</p><br>
                  <p>(22) The Purchaser/s are not entitled to make any change in interior/exterior elevation, exterior colour scheme of the said scheme. The Purchaser/s shall not be entitled to make any change/alteration in internal / external structure of the Said Property.</p><br>
                  <p>(23) The Purchaser/s is required to keep the ‘Said Property’, walls and partition walls, sewers, drains, pipes and appurtenances thereto belonging to, in good and tenantable repair and conditions and in particular so as to support, shelter and protect the parts of the building other than their property.</p><br>
                  <p>(24) The Purchaser shall have to maintain at their cost, the ‘Said Property’ in good condition, state and order, in which it is delivered to them and shall abide by all byelaws, rules and regulations of the government, electricity charges, local bodies and other authorities.</p><br>
                  <p>(25) The Purchaser shall have to pay / contribute proportionate amount to service society / association formed for the maintenance of said “ KAUTILYA ONE-54 ” Scheme.</p><br>
                  <p>(26) The Party of the Second Part will have access rights to all common amenities and common areas provided by the Party of the First Part. The Party of the Second Part will also not claim individual ownership rights in the undivided share in land.</p><br>
                  <p>(27) The Party of the Second Part shall have absolute right, interest, in the “Said Property” only after the date of final Sale Deed and after the possession of property, which shall be given at the time of execution of Sale Deed till such date the Party of Second Part shall not have any such claim or right to “Said Property”. he / she / they / it shall not claim any right, title, interest in any other common property of the Said Scheme.</p><br>
                  <p>(28) If any provision of this Agreement shall be determined to be void or unenforceable under the Act or the Rules and Regulations made there under or under other applicable laws, such provisions of the Agreement shall be deemed amended or deleted in so far as reasonably inconsistent with the purpose of this Agreement and to the extent necessary to conform to Act or the Rules and Regulations made there under or the applicable law, as the case may be, and the remaining provisions of this Agreement shall remain valid and enforceable as applicable at the time of execution of this Agreement.</p><br>
                  <p>(29) This Agreement for sale is to be read and understood as per the provisions made under the Real Estate (Regulation and Development) Act, 2016 and under the rules of the Gujarat Real Estate (Regulation and Development) (General) Rules, 2017.</p><br>
                  <p>(30) Any dispute between parties shall be settled amicably. In case of failure to settled the dispute amicably, which shall be referred to the RERA authority as per the provisions of the Real Estate (Regulation and Development) Act, 2016, Rules and Regulations, thereunder.</p><br>
                  <p>(31) That the rights and obligations of the parties under or arising out of this Agreement shall be construed and enforced in accordance with the laws of India for the time being in force and the Ahmedabad courts will have the jurisdiction for this Agreement.</p><br>
                  <p>(32) That all notices to be served on the Purchaser and the Vendor as contemplated by this Agreement shall be deemed to have been duly served if sent to the Purchaser or the Vendor by Registered Post A.D and notified Email ID/Under Certificate of Posting at their respective addresses specified below:</p>
                  <p>Details of Purchaser : as per this agreement.</p>
                  <p>Details of Vendor : as per this agreement.</p>
                  <p>It shall be the duty of the Purchaser and the Vendor to inform each other of any change in address subsequent to the execution of this Agreement in the above address by Registered Post failing which all communications and letters posted at the above address shall be deemed to have been received by the Vendor or the Purchaser, as the case may be.</p><br>
                  <p>(33) The out of pocket expenses, costs, and charges of and incidental to this agreement and the conveyance to be executed hereafter or for any writing declaration indemnity etc. such as stamp duty, registration fee, GST and all other taxes and also fees of Advocate / Solicitor for obtaining Title Clearance Certificate of the said property shall be borne by the party of the SECOND PART Only.</p><br>
                  <p>SCHEDULE ABOVE REFERRED TO</p>
                  <p>(Description of the said Immovable Vendor)</p>
                  <p>All That piece & parcel of Immovable property bearing Flat No. <input type="text" name="field_15" class="form-control input-sm" style="display:inline-block; width:auto;" /> in Wing “ <input type="text" name="field_16" class="form-control input-sm" style="display:inline-block; width:auto;" /> ” having total Carpet Area admeasuring about <input type="text" name="field_17" class="form-control input-sm" style="display:inline-block; width:auto;" /> sq.mtrs. situated on <input type="text" name="field_18" class="form-control input-sm" style="display:inline-block; width:auto;" /> Floor of the said Scheme along with (i) Wash Area admeasuring 2.42 sq.mtrs.. (ii) Balcony admeasuring about 3.21 sq.mtrs.. in the scheme known as “ KAUTILYA ONE-54 ” together with undivided share in the said land admeasuring about <input type="text" name="field_19" class="form-control input-sm" style="display:inline-block; width:auto;" /> Sq.Mtrs. bearing A) Final Plot No. 321, admeasuring 3400 sq.mtrs. of Town Planning Scheme No. 76 / B (Chandkheda), allotted in lieu of Survey No. 875/3 admeasuring 5666 sq.mtrs. & B) Final Plot No. 322, admeasuring 2125 sq.mtrs. of Town Planning Scheme No. 76 / B (Chandkheda), allotted in lieu of Survey No. 875/4 admeasuring 3541 sq.mtrs. situated within the village limits of Chandkheda, Taluka - Sabarmati in the Registration Sub - District of Ahmedabad - 2 (Vadaj) of District Ahmedabad.</p><br><br>
                  <p>DETAILS OF THE FOUR CORNERS OF THE SAID FLAT PROPERTY</p><br>
                  <p>East: 40 FT T.P Road</p>
                  <p>West : Flat No - A/404</p>
                  <p>North: Flat No - A/402</p>
                  <p>South: Block B</p><br><br>
                  <p>IN WITNESS WHEREOF the “Said Developer” hereto through its authorized Partner has hereunto executed this Agreement on the Day Month and year herein above written.</p><br>
                  <p>SIGNED AND DELIVERED BY THE</p>
                  <p>PARTY OF THE FIRST PART :-</p><br>
                  <p> kautilya Developers</p>
                  <p>A Partnership Firm</p>
                  <p>through its authorise signatory</p>
                  <p>Kiran Rasiklal Kamdar</p><br>
                  <p><input type="text" name="field_20" class="form-control input-sm" style="display:inline-block; width:auto;" /></p><br>
                  <p>In the presence of following</p>
                  <p>two Witness :-</p><br>
                  <p>1. <input type="text" name="field_21" class="form-control input-sm" style="display:inline-block; width:auto;" /></p><br>
                  <p>2.<input type="text" name="field_22" class="form-control input-sm" style="display:inline-block; width:auto;" /></p><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>
                  <p>SCHEDULE</p>
                  <p>AS PER SECTION 32(A) OF THE REGISTRATION ACT</p><br>
                  <p>Signature, Photograph and Thumb Impression of First Part:-</p><br><br><br><br><br><br><br>
                  <p><input type="text" name="field_23" class="form-control input-sm" style="display:inline-block; width:auto;" /> <input type="text" name="field_24" class="form-control input-sm" style="display:inline-block; width:auto;" /></p><br>
                  <p> kautilya Developers - A Partnership Firm through its authorise signatory Kiran Rasiklal Kamdar</p><br>
                  <p>Signature, Photograph and Thumb Impression of Second Part:-</p><br><br><br><br><br><br>
                  <p><input type="text" name="field_25" class="form-control input-sm" style="display:inline-block; width:auto;" /> <input type="text" name="field_26" class="form-control input-sm" style="display:inline-block; width:auto;" /></p><br><br><br><br><br>
                  <p><input type="text" name="field_27" class="form-control input-sm" style="display:inline-block; width:auto;" /> <input type="text" name="field_28" class="form-control input-sm" style="display:inline-block; width:auto;" /></p><br>
               <button type="submit" class="btn btn-primary">Save Agreement</button>
            </form>
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