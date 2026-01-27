<?php
// update_check_in_out.php

date_default_timezone_set('Asia/Kolkata');

function writeLog($message)
{
    $logFile = __DIR__ . '/cron_activity.log';
    $time = date('Y-m-d H:i:s');
    file_put_contents($logFile, "[$time] $message" . PHP_EOL, FILE_APPEND);
}

writeLog("========== CRON STARTED ==========");

// —— DB CONFIG ——
$host     = "localhost";
$username = "u318220648_kautilyadb";
$password = "Nirmaan@1234";
$database = "u318220648_kautilyadb";

// connect
$conn = new mysqli($host, $username, $password, $database);

if ($conn->connect_error) {
    writeLog("DB Connection Failed: " . $conn->connect_error);
    die("Connection failed");
}

writeLog("Database connected successfully");

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

// begin transaction
$conn->begin_transaction();
writeLog("Transaction started");

try {

    $today_date  = date('Y-m-d');
    $today_start = $today_date . ' 00:00:00';
    $today_end   = $today_date . ' 23:59:59';

    writeLog("Today Range: $today_start to $today_end");

    // SQL
    $sql = "UPDATE `tblforms` 
            SET `locked` = 1 
            WHERE `date` BETWEEN ? AND ?";

    $stmt = $conn->prepare($sql);
    writeLog("SQL Prepared");

    $stmt->bind_param("ss", $today_start, $today_end);
    writeLog("Parameters bound");

    $stmt->execute();
    writeLog("Query executed");

    $affected = $stmt->affected_rows;
    writeLog("Rows Updated: $affected");

    $stmt->close();
    writeLog("Statement closed");

    $conn->commit();
    writeLog("Transaction committed");

} catch (Exception $e) {

    $conn->rollback();
    writeLog("Transaction rolled back");

    writeLog("ERROR: " . $e->getMessage());
}

$conn->close();
writeLog("Database connection closed");

writeLog("=========== CRON ENDED ===========");
