<?php
// update_check_in_out.php

date_default_timezone_set('Asia/Kolkata');


// —— DB CONFIG ——
$host     = "localhost";
$username = "u318220648_kautilyadb";
$password = "Nirmaan@1234";
$database = "u318220648_kautilyadb";

// connect
$conn = new mysqli($host, $username, $password, $database);

if ($conn->connect_error) {
    die("Connection failed");
}

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

// begin transaction
$conn->begin_transaction();

try {

    $today_date  = date('Y-m-d');
    $today_start = $today_date . ' 00:00:00';
    $today_end   = $today_date . ' 23:59:59';


    // SQL
    $sql = "UPDATE `tblforms` 
            SET `locked` = 1 
            WHERE `date` BETWEEN ? AND ?";

    $stmt = $conn->prepare($sql);

    $stmt->bind_param("ss", $today_start, $today_end);

    $stmt->execute();

    $affected = $stmt->affected_rows;

    $stmt->close();

    $conn->commit();

} catch (Exception $e) {

    $conn->rollback();
}

$conn->close();

