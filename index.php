<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Analyzer - Website Statistics</title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <!-- Flatpickr for date picker -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
    <style>
        body {
            padding-top: 20px;
            background-color: #f8f9fa;
        }
        .navbar {
            margin-bottom: 20px;
        }
        .card {
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .stats-container {
            margin-top: 20px;
        }
        #loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        .chart-container {
            height: 400px;
            margin-bottom: 30px;
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .toggle-btn {
            background: none;
            border: none;
            color: #6c757d;
            cursor: pointer;
            transition: transform 0.3s;
        }
        .toggle-btn:hover {
            color: #495057;
        }
        .toggle-btn.collapsed {
            transform: rotate(180deg);
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fas fa-chart-line me-2"></i>Log Analyzer
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link active" href="#"><i class="fas fa-home me-1"></i> Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#"><i class="fas fa-info-circle me-1"></i> About</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container">
        <div class="row">
            <!-- Upload Logs Card -->
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-header bg-light">
                        <h4><i class="fas fa-upload me-2"></i>Upload Logs</h4>
                    </div>
                    <div class="card-body">
                        <?php
                        // Initialize session for CSRF protection if not already started
                        if (session_status() == PHP_SESSION_NONE) {
                            session_start();
                        }
                        
                        // Generate CSRF token if it doesn't exist
                        if (!isset($_SESSION['csrf_token'])) {
                            $_SESSION['csrf_token'] = bin2hex(mt_rand());
                        }
                        
                        // Process log file upload
                        $uploadMessage = '';
                        $uploadMessageType = '';
                        
                        if (isset($_FILES['logfile']) && $_FILES['logfile']['error'] == 0) {
                            // Verify CSRF token
                            if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
                                $uploadMessage = 'Error: Invalid form submission. Please try again.';
                                $uploadMessageType = 'danger';
                            } else {
                            // Define allowed file types and size limit
                            $allowedTypes = ['text/plain', 'application/octet-stream', 'text/x-log', 'text/csv'];
                            $maxSize = 10 * 1024 * 1024; // 10MB
                            
                            // Get file info
                            $fileInfo = finfo_open(FILEINFO_MIME_TYPE);
                            $fileType = finfo_file($fileInfo, $_FILES['logfile']['tmp_name']);
                            finfo_close($fileInfo);
                            
                            // Validate file type and size
                            if (!in_array($fileType, $allowedTypes)) {
                                $uploadMessage = 'Error: Invalid file type (' . $fileType . '). Only log files are allowed.';
                                $uploadMessageType = 'danger';
                            } elseif ($_FILES['logfile']['size'] > $maxSize) {
                                $uploadMessage = 'Error: File size exceeds the limit (10MB).';
                                $uploadMessageType = 'danger';
                            } else {
                                // Create uploads directory if it doesn't exist
                                $uploadDir = 'access_logs/uploads/';
                                if (!file_exists($uploadDir)) {
                                    mkdir($uploadDir, 0755, true);
                                }
                                
                                // Generate a secure filename using uniqid (more compatible than random_bytes)
                                $filename = 'upload_' . date('Y-m-d_H-i-s') . '_' . uniqid(mt_rand(), true) . '.log';
                                $destination = $uploadDir . $filename;
                                
                                // Move the uploaded file
                                if (move_uploaded_file($_FILES['logfile']['tmp_name'], $destination)) {
                                    $uploadMessage = 'Log file uploaded successfully! File type detected: ' . $fileType . '. You can now search through it.';
                                    $uploadMessageType = 'success';
                                } else {
                                    $uploadMessage = 'Error: Failed to upload file. Please try again.';
                                    $uploadMessageType = 'danger';
                                }
                            }
                        }
                        }
                        
                        // Display upload message if any
                        if (!empty($uploadMessage)) {
                            echo '<div class="alert alert-' . $uploadMessageType . ' mb-3">' . $uploadMessage . '</div>';
                        }
                        ?>
                        <form method="POST" enctype="multipart/form-data" id="uploadForm">
                            <!-- CSRF Token -->
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            
                            <div class="mb-3">
                                <label for="logfile" class="form-label">Select Log File</label>
                                <input type="file" class="form-control" id="logfile" name="logfile" accept=".log,text/plain" required>
                                <div class="form-text">Max file size: 10MB. Only log files (.log) are accepted.</div>
                            </div>
                            <div class="alert alert-info mb-3">
                                <i class="fas fa-info-circle me-1"></i> <strong>Note:</strong> Uploaded log files are moved to the access_logs folder and will be available for analysis alongside existing logs.
                            </div>
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-upload me-1"></i> Upload Log File
                            </button>
                        </form>
                        <hr>
                        <div class="mt-3">
                            <h6><i class="fas fa-shield-alt me-1"></i> Security Measures:</h6>
                            <ul class="small text-muted">
                                <li>File type validation</li>
                                <li>Size limit enforcement</li>
                                <li>Secure file naming</li>
                                <li>Isolated storage location</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Search Logs Card -->
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-header bg-light">
                        <h4><i class="fas fa-search me-2"></i>Search Logs</h4>
                    </div>
                    <div class="card-body">
                        <form method="POST" id="searchForm">
                            <div class="mb-3">
                                <label for="date" class="form-label">Date and Time</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-calendar"></i></span>
                                    <input type="text" id="date" name="date" class="form-control" 
                                        placeholder="dd/Mmm/yyyy:hh:mm" 
                                        value="<?php echo (isset($_POST['date'])) ? htmlspecialchars($_POST['date']) : ''; ?>" />
                                </div>
                                <div class="form-text">Format: dd/Mmm/yyyy:hh:mm (e.g., 17/Apr/2025:00:00)</div>
                            </div>
                            <div class="mb-3">
                                <label for="filter" class="form-label">Additional Filter (Optional)</label>
                                <div class="input-group">
                                    <span class="input-group-text"><i class="fas fa-filter"></i></span>
                                    <input type="text" id="filter" name="filter" class="form-control" 
                                        placeholder="IP, URL, or User Agent" 
                                        value="<?php echo (isset($_POST['filter'])) ? htmlspecialchars($_POST['filter']) : ''; ?>" />
                                </div>
                            </div>
                            <div class="d-grid gap-2 d-md-flex">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-search me-1"></i> Search
                                </button>
                                <button type="button" id="exportBtn" class="btn btn-success" <?php echo !isset($_POST['date']) ? 'disabled' : ''; ?>>
                                    <i class="fas fa-download me-1"></i> Export CSV
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Main Card for Results -->
        
        <!-- Loading indicator -->
        <div id="loading">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2">Processing logs, please wait...</p>
        </div>
    <?php
    // Set longer execution time for processing large log files
    ini_set('max_execution_time', 300);
    
    // Process the form submission
    if(isset($_POST['date'])) :
        // Sanitize inputs
        $date = htmlspecialchars($_POST['date']);
        $additionalFilter = isset($_POST['filter']) ? htmlspecialchars($_POST['filter']) : '';
        
        // Define tracking categories
        $stats = array(
            'Amazon CloudFront' => 0,
            'www.google.com' => 0,
            'AhrefsBot' => 0,
            'bingbot' => 0,
            'Pingdom.com' => 0,
            'mj12bot.com' => 0,
            '/freegeoip/json/' => 0,
            'Microsoft Office' => 0,
            'static/' => 0,
            'megaindex.com' => 0,
            'ELB-HealthChecker' => 0,
            'Bytespider' => 0,
            'qa.com' => 0,
            'NodePing' => 0,
            'SiteAuditBot' => 0,
            'amazonbot' => 0,
            '64.39.98.' => 0,
            'YandexBot' => 0,
            'AwarioBot' => 0,
            'MojeekBot' => 0,
            '13.74.98.' => 0,
            '13.74.98.244' => 0,
            '13.74.98.172' => 0,
            '139.87.113.' => 0,
            '185.223.249.' => 0,
            '45.134.225.250'=> 0,
            'Trident' => 0
        );
        
        // Initialize counters and arrays
        $total = 0;
        $statusCodes = [];
        $ipAddresses = [];
        $userAgents = [];
        $requestUrls = [];
        $matchedLines = [];
        $pageSize = 100; // Number of log entries per page
        $currentPage = isset($_GET['page']) ? (int)$_GET['page'] : 1;
        
        try {
            // Get all log files from main directory and uploads directory
            $logfiles = [];
            
            // Get files from main access_logs directory
            $mainLogFiles = array_diff(scandir('access_logs'), array('..', '.', 'uploads'));
            foreach ($mainLogFiles as $file) {
                $logfiles[] = ['path' => 'access_logs/', 'name' => $file];
            }
            
            // Get files from uploads directory if it exists
            $uploadsDir = 'access_logs/uploads/';
            if (file_exists($uploadsDir) && is_dir($uploadsDir)) {
                $uploadedFiles = array_diff(scandir($uploadsDir), array('..', '.'));
                foreach ($uploadedFiles as $file) {
                    $logfiles[] = ['path' => $uploadsDir, 'name' => $file];
                }
            }
            
            // Process each log file
            foreach ($logfiles as $fileInfo) {
                $filePath = $fileInfo['path'] . $fileInfo['name'];
                
                if (!file_exists($filePath) || is_dir($filePath)) {
                    continue;
                }
                
                $file = fopen($filePath, 'r');
                if (!$file) {
                    continue;
                }
                
                // Pre-compile regular expressions for better performance
                $ipRegex = '/^(\S+)/';
                $statusCodeRegex = '/" (\d{3}) /';
                $urlRegex = '/"([A-Z]+) ([^"]+) HTTP/';
                $userAgentRegex = '/"([^"]+)"$/';
                $botRegex = '/(bot|spider|crawl)/i';
                $mobileRegex = '/(mobile|android|iphone|ipad|ios)/i';
                
                // Process the file in larger chunks for better performance
                $buffer = '';
                $chunkSize = 8192; // 8KB chunks
                
                while (!feof($file)) {
                    $buffer .= fread($file, $chunkSize);
                    
                    // Process complete lines
                    $lines = explode("\n", $buffer);
                    // Keep the last potentially incomplete line in the buffer
                    $buffer = array_pop($lines);
                    
                    foreach ($lines as $lineItem) {
                        // Skip empty lines
                        if (empty(trim($lineItem))) {
                            continue;
                        }
                        
                        // Quick check for date before doing more expensive operations
                        if (strpos($lineItem, $date) === false) {
                            continue;
                        }
                        
                        // Check additional filter if provided
                        if (!empty($additionalFilter) && strpos($lineItem, $additionalFilter) === false) {
                            continue;
                        }
                        
                        // Count by referrer/source - use array_key_exists for better performance
                        foreach ($stats as $referer => $count) {
                            if (strpos($lineItem, $referer) !== false) {
                                $stats[$referer]++;
                                break;
                            }
                        }
                        
                        // Extract additional information for analysis
                        // IP Address
                        if (preg_match($ipRegex, $lineItem, $matches)) {
                            $ip = $matches[1];
                            isset($ipAddresses[$ip]) ? $ipAddresses[$ip]++ : $ipAddresses[$ip] = 1;
                        }
                        
                        // HTTP Status Code
                        if (preg_match($statusCodeRegex, $lineItem, $matches)) {
                            $statusCode = $matches[1];
                            isset($statusCodes[$statusCode]) ? $statusCodes[$statusCode]++ : $statusCodes[$statusCode] = 1;
                        }
                        
                        // Request URL
                        if (preg_match($urlRegex, $lineItem, $matches)) {
                            $url = $matches[2];
                            $urlPath = parse_url($url, PHP_URL_PATH);
                            isset($requestUrls[$urlPath]) ? $requestUrls[$urlPath]++ : $requestUrls[$urlPath] = 1;
                        }
                        
                        // User Agent
                        if (preg_match($userAgentRegex, $lineItem, $matches)) {
                            $userAgent = $matches[1];
                            // Store full user agent and a longer preview (100 chars instead of 50)
                            $shortUA = substr($userAgent, 0, 100) . (strlen($userAgent) > 100 ? '...' : '');
                            $userAgentKey = md5($userAgent); // Use hash as key to avoid length issues
                            
                            if (isset($userAgents[$userAgentKey])) {
                                $userAgents[$userAgentKey]['count']++;
                            } else {
                                // Determine user agent type once
                                $type = 'desktop'; // Default
                                if (preg_match($botRegex, $userAgent)) {
                                    $type = 'bot';
                                } elseif (preg_match($mobileRegex, $userAgent)) {
                                    $type = 'mobile';
                                }
                                
                                $userAgents[$userAgentKey] = [
                                    'full' => $userAgent,
                                    'short' => $shortUA,
                                    'count' => 1,
                                    'type' => $type
                                ];
                            }
                        }
                        
                        // Store the matched line for display
                        $matchedLines[] = $lineItem;
                        
                        $total++;
                    }
                }
                
                // Process any remaining content in the buffer
                if (!empty(trim($buffer))) {
                    $lineItem = $buffer;
                    
                    // Apply the same processing as above for the last line
                    if (strpos($lineItem, $date) !== false && 
                        (empty($additionalFilter) || strpos($lineItem, $additionalFilter) !== false)) {
                        
                        // Process the last line (same code as above)
                        foreach ($stats as $referer => $count) {
                            if (strpos($lineItem, $referer) !== false) {
                                $stats[$referer]++;
                                break;
                            }
                        }
                        
                        if (preg_match($ipRegex, $lineItem, $matches)) {
                            $ip = $matches[1];
                            isset($ipAddresses[$ip]) ? $ipAddresses[$ip]++ : $ipAddresses[$ip] = 1;
                        }
                        
                        if (preg_match($statusCodeRegex, $lineItem, $matches)) {
                            $statusCode = $matches[1];
                            isset($statusCodes[$statusCode]) ? $statusCodes[$statusCode]++ : $statusCodes[$statusCode] = 1;
                        }
                        
                        if (preg_match($urlRegex, $lineItem, $matches)) {
                            $url = $matches[2];
                            $urlPath = parse_url($url, PHP_URL_PATH);
                            isset($requestUrls[$urlPath]) ? $requestUrls[$urlPath]++ : $requestUrls[$urlPath] = 1;
                        }
                        
                        if (preg_match($userAgentRegex, $lineItem, $matches)) {
                            $userAgent = $matches[1];
                            $shortUA = substr($userAgent, 0, 100) . (strlen($userAgent) > 100 ? '...' : '');
                            $userAgentKey = md5($userAgent);
                            
                            if (isset($userAgents[$userAgentKey])) {
                                $userAgents[$userAgentKey]['count']++;
                            } else {
                                $type = 'desktop';
                                if (preg_match($botRegex, $userAgent)) {
                                    $type = 'bot';
                                } elseif (preg_match($mobileRegex, $userAgent)) {
                                    $type = 'mobile';
                                }
                                
                                $userAgents[$userAgentKey] = [
                                    'full' => $userAgent,
                                    'short' => $shortUA,
                                    'count' => 1,
                                    'type' => $type
                                ];
                            }
                        }
                        
                        $matchedLines[] = $lineItem;
                        $total++;
                    }
                }
                fclose($file);
            }
            
            // Sort data for better presentation
            arsort($stats);
            arsort($ipAddresses);
            arsort($statusCodes);
            arsort($requestUrls);
            
            // Sort user agents by count
            uasort($userAgents, function($a, $b) {
                if ($a['count'] == $b['count']) return 0;
                return ($a['count'] > $b['count']) ? -1 : 1;
            });
            
            // Limit arrays to top entries for display
            $topIPs = array_slice($ipAddresses, 0, 10);
            $topURLs = array_slice($requestUrls, 0, 10);
            $topUserAgents = array_slice($userAgents, 0, 10);
            
            // Calculate pagination
            $totalPages = ceil(count($matchedLines) / $pageSize);
            $currentPage = max(1, min($currentPage, $totalPages));
            $offset = ($currentPage - 1) * $pageSize;
            $paginatedLines = array_slice($matchedLines, $offset, $pageSize);
            
        } catch (Exception $e) {
            echo '<div class="alert alert-danger">Error processing logs: ' . htmlspecialchars($e->getMessage()) . '</div>';
        }
        ?>
        
        <!-- Results Section -->
        <div class="stats-container">
            <?php if ($total > 0): ?>
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    Found <strong><?php echo $total; ?></strong> log entries matching your criteria.
                    <?php if (!empty($additionalFilter)): ?>
                        Additional filter: <strong><?php echo htmlspecialchars($additionalFilter); ?></strong>
                    <?php endif; ?>
                </div>
                
                <!-- Summary Cards -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card text-white bg-primary">
                            <div class="card-body">
                                <h5 class="card-title">Total Hits</h5>
                                <p class="card-text display-4"><?php echo $total; ?></p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-white bg-success">
                            <div class="card-body">
                                <h5 class="card-title">Successful Requests</h5>
                                <p class="card-text display-4"><?php echo isset($statusCodes['200']) ? $statusCodes['200'] : 0; ?></p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-white bg-warning">
                            <div class="card-body">
                                <h5 class="card-title">Unique IPs</h5>
                                <p class="card-text display-4"><?php echo count($ipAddresses); ?></p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-white bg-info">
                            <div class="card-body">
                                <h5 class="card-title">Unique URLs</h5>
                                <p class="card-text display-4"><?php echo count($requestUrls); ?></p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Charts Section -->
                <div class="row mb-4">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-light">
                                <h5><i class="fas fa-chart-pie me-2"></i>Traffic Sources</h5>
                                <button type="button" class="toggle-btn" data-bs-toggle="collapse" data-bs-target="#trafficSourcesChart" aria-expanded="true" aria-controls="trafficSourcesChart">
                                    <i class="fas fa-chevron-up"></i>
                                </button>
                            </div>
                            <div class="collapse show" id="trafficSourcesChart">
                                <div class="card-body">
                                    <div class="chart-container" id="sourcesChart">
                                        <!-- Chart will be rendered here by JavaScript -->
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-light">
                                <h5><i class="fas fa-chart-bar me-2"></i>Status Codes</h5>
                                <button type="button" class="toggle-btn" data-bs-toggle="collapse" data-bs-target="#statusCodesChart" aria-expanded="true" aria-controls="statusCodesChart">
                                    <i class="fas fa-chevron-up"></i>
                                </button>
                            </div>
                            <div class="collapse show" id="statusCodesChart">
                                <div class="card-body">
                                    <div class="chart-container" id="statusChart">
                                        <!-- Chart will be rendered here by JavaScript -->
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Detailed Statistics -->
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-light">
                                <h5><i class="fas fa-globe me-2"></i>Traffic Sources</h5>
                                <button type="button" class="toggle-btn" data-bs-toggle="collapse" data-bs-target="#trafficSourcesTable" aria-expanded="true" aria-controls="trafficSourcesTable">
                                    <i class="fas fa-chevron-up"></i>
                                </button>
                            </div>
                            <div class="collapse show" id="trafficSourcesTable">
                                <div class="card-body">
                                    <table class="table table-striped table-hover">
                                        <thead class="table-light">
                                            <tr>
                                                <th>Source</th>
                                                <th class="text-end">Hit Count</th>
                                                <th class="text-end">Percentage</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($stats as $referer => $count): 
                                                if ($count > 0): 
                                                    $percentage = ($count / $total) * 100;
                                            ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($referer); ?></td>
                                                <td class="text-end"><?php echo $count; ?></td>
                                                <td class="text-end"><?php echo number_format($percentage, 1); ?>%</td>
                                            </tr>
                                            <?php 
                                                endif;
                                            endforeach; 
                                            ?>
                                        </tbody>
                                        <tfoot class="table-light">
                                            <tr>
                                                <th>Identified Sources</th>
                                                <th class="text-end"><?php echo array_sum($stats); ?></th>
                                                <th class="text-end"><?php echo number_format((array_sum($stats) / $total) * 100, 1); ?>%</th>
                                            </tr>
                                            <tr>
                                                <th>Other Sources</th>
                                                <th class="text-end"><?php echo $total - array_sum($stats); ?></th>
                                                <th class="text-end"><?php echo number_format((($total - array_sum($stats)) / $total) * 100, 1); ?>%</th>
                                            </tr>
                                        </tfoot>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-light">
                                <h5><i class="fas fa-server me-2"></i>Top IP Addresses</h5>
                                <button type="button" class="toggle-btn" data-bs-toggle="collapse" data-bs-target="#topIPsTable" aria-expanded="true" aria-controls="topIPsTable">
                                    <i class="fas fa-chevron-up"></i>
                                </button>
                            </div>
                            <div class="collapse show" id="topIPsTable">
                                <div class="card-body">
                                    <table class="table table-striped table-hover">
                                        <thead class="table-light">
                                            <tr>
                                                <th>IP Address</th>
                                                <th class="text-end">Hit Count</th>
                                                <th class="text-end">Percentage</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($topIPs as $ip => $count): 
                                                $percentage = ($count / $total) * 100;
                                            ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($ip); ?></td>
                                                <td class="text-end"><?php echo $count; ?></td>
                                                <td class="text-end"><?php echo number_format($percentage, 1); ?>%</td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mt-4">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-light">
                                <h5><i class="fas fa-link me-2"></i>Top URLs</h5>
                                <button type="button" class="toggle-btn" data-bs-toggle="collapse" data-bs-target="#topURLsTable" aria-expanded="true" aria-controls="topURLsTable">
                                    <i class="fas fa-chevron-up"></i>
                                </button>
                            </div>
                            <div class="collapse show" id="topURLsTable">
                                <div class="card-body">
                                    <table class="table table-striped table-hover">
                                        <thead class="table-light">
                                            <tr>
                                                <th>URL Path</th>
                                                <th class="text-end">Hit Count</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($topURLs as $url => $count): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($url); ?></td>
                                                <td class="text-end"><?php echo $count; ?></td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-light">
                                <h5><i class="fas fa-desktop me-2"></i>Top User Agents</h5>
                                <button type="button" class="toggle-btn" data-bs-toggle="collapse" data-bs-target="#topUserAgentsTable" aria-expanded="true" aria-controls="topUserAgentsTable">
                                    <i class="fas fa-chevron-up"></i>
                                </button>
                            </div>
                            <div class="collapse show" id="topUserAgentsTable">
                                <div class="card-body">
                                    <!-- User Agent Type Legend -->
                                    <div class="mb-3 p-2 bg-light rounded">
                                        <h6 class="mb-2"><i class="fas fa-info-circle me-1"></i> User Agent Types:</h6>
                                        <div class="d-flex flex-wrap gap-3">
                                            <div>
                                                <span class="badge bg-success me-1"><i class="fas fa-desktop me-1"></i> Desktop</span>
                                                <small>Standard desktop browsers</small>
                                            </div>
                                            <div>
                                                <span class="badge bg-primary me-1"><i class="fas fa-mobile-alt me-1"></i> Mobile</span>
                                                <small>Mobile devices and tablets</small>
                                            </div>
                                            <div>
                                                <span class="badge bg-secondary me-1"><i class="fas fa-robot me-1"></i> Bot</span>
                                                <small>Search engines and crawlers</small>
                                            </div>
                                        </div>
                                    </div>
                                    <table class="table table-striped table-hover">
                                        <thead class="table-light">
                                            <tr>
                                                <th>User Agent</th>
                                                <th class="text-end">Hit Count</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($topUserAgents as $agentData): ?>
                                            <tr>
                                                <td>
                                                    <?php 
                                                    // Add icon based on user agent type
                                                    $icon = '';
                                                    $typeClass = '';
                                                    switch ($agentData['type']) {
                                                        case 'bot':
                                                            $icon = '<i class="fas fa-robot me-2 text-secondary"></i>';
                                                            $typeClass = 'text-secondary';
                                                            break;
                                                        case 'mobile':
                                                            $icon = '<i class="fas fa-mobile-alt me-2 text-primary"></i>';
                                                            $typeClass = 'text-primary';
                                                            break;
                                                        case 'desktop':
                                                            $icon = '<i class="fas fa-desktop me-2 text-success"></i>';
                                                            $typeClass = 'text-success';
                                                            break;
                                                    }
                                                    echo $icon;
                                                    ?>
                                                    <span class="<?php echo $typeClass; ?>">
                                                        <?php echo htmlspecialchars($agentData['short']); ?>
                                                    </span>
                                                </td>
                                                <td class="text-end"><?php echo $agentData['count']; ?></td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                    <div class="mt-3 text-end">
                                        <a href="#userAgentFullView" class="btn btn-outline-primary btn-sm" data-bs-toggle="collapse" role="button" aria-expanded="false" aria-controls="userAgentFullView">
                                            <i class="fas fa-list-alt me-1"></i> View All User Agents in Full
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Full User Agent View with Pagination -->
                <div class="collapse mt-4" id="userAgentFullView">
                    <div class="card">
                        <div class="card-header bg-light">
                            <h5><i class="fas fa-user-agent me-2"></i>Full User Agent Report</h5>
                            <button type="button" class="toggle-btn" data-bs-toggle="collapse" data-bs-target="#userAgentFullViewContent" aria-expanded="true" aria-controls="userAgentFullViewContent">
                                <i class="fas fa-chevron-up"></i>
                            </button>
                        </div>
                        <div class="collapse show" id="userAgentFullViewContent">
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-striped table-hover table-sm">
                                        <thead class="table-light">
                                            <tr>
                                                <th>#</th>
                                                <th>Type</th>
                                                <th>User Agent</th>
                                                <th class="text-end">Count</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php 
                                            // Pagination for full user agent view
                                            $uaPageSize = 50; // Number of user agents per page
                                            $uaCurrentPage = isset($_GET['ua_page']) ? (int)$_GET['ua_page'] : 1;
                                            $uaTotalPages = ceil(count($userAgents) / $uaPageSize);
                                            $uaCurrentPage = max(1, min($uaCurrentPage, $uaTotalPages));
                                            $uaOffset = ($uaCurrentPage - 1) * $uaPageSize;
                                            $paginatedUserAgents = array_slice($userAgents, $uaOffset, $uaPageSize, true);
                                            
                                            $uaEntryNumber = $uaOffset + 1;
                                            foreach ($paginatedUserAgents as $uaKey => $agentData): 
                                                // Determine User Agent type icon
                                                $uaIcon = '';
                                                $uaTypeText = '';
                                                $uaTypeClass = '';
                                                
                                                switch ($agentData['type']) {
                                                    case 'bot':
                                                        $uaIcon = '<i class="fas fa-robot me-2"></i>';
                                                        $uaTypeText = 'Bot';
                                                        $uaTypeClass = 'badge bg-secondary';
                                                        break;
                                                    case 'mobile':
                                                        $uaIcon = '<i class="fas fa-mobile-alt me-2"></i>';
                                                        $uaTypeText = 'Mobile';
                                                        $uaTypeClass = 'badge bg-primary';
                                                        break;
                                                    case 'desktop':
                                                        $uaIcon = '<i class="fas fa-desktop me-2"></i>';
                                                        $uaTypeText = 'Desktop';
                                                        $uaTypeClass = 'badge bg-success';
                                                        break;
                                                }
                                            ?>
                                            <tr>
                                                <td><?php echo $uaEntryNumber++; ?></td>
                                                <td><span class="<?php echo $uaTypeClass; ?>"><?php echo $uaIcon . $uaTypeText; ?></span></td>
                                                <td><code class="small"><?php echo htmlspecialchars($agentData['full']); ?></code></td>
                                                <td class="text-end"><?php echo $agentData['count']; ?></td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                                
                                <!-- Pagination for User Agent Full View -->
                                <?php if ($uaTotalPages > 1): ?>
                                <nav aria-label="User agent pagination">
                                    <ul class="pagination justify-content-center">
                                        <li class="page-item <?php echo ($uaCurrentPage <= 1) ? 'disabled' : ''; ?>">
                                            <a class="page-link" href="?ua_page=<?php echo $uaCurrentPage - 1; ?>&date=<?php echo urlencode($date); ?>&filter=<?php echo urlencode($additionalFilter); ?>&page=<?php echo $currentPage; ?>">Previous</a>
                                        </li>
                                        
                                        <?php
                                        $uaStartPage = max(1, $uaCurrentPage - 2);
                                        $uaEndPage = min($uaTotalPages, $uaStartPage + 4);
                                        
                                        if ($uaStartPage > 1) {
                                            echo '<li class="page-item"><a class="page-link" href="?ua_page=1&date=' . urlencode($date) . '&filter=' . urlencode($additionalFilter) . '&page=' . $currentPage . '">1</a></li>';
                                            if ($uaStartPage > 2) {
                                                echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                                            }
                                        }
                                        
                                        for ($i = $uaStartPage; $i <= $uaEndPage; $i++) {
                                            echo '<li class="page-item ' . ($i == $uaCurrentPage ? 'active' : '') . '"><a class="page-link" href="?ua_page=' . $i . '&date=' . urlencode($date) . '&filter=' . urlencode($additionalFilter) . '&page=' . $currentPage . '">' . $i . '</a></li>';
                                        }
                                        
                                        if ($uaEndPage < $uaTotalPages) {
                                            if ($uaEndPage < $uaTotalPages - 1) {
                                                echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                                            }
                                            echo '<li class="page-item"><a class="page-link" href="?ua_page=' . $uaTotalPages . '&date=' . urlencode($date) . '&filter=' . urlencode($additionalFilter) . '&page=' . $currentPage . '">' . $uaTotalPages . '</a></li>';
                                        }
                                        ?>
                                        
                                        <li class="page-item <?php echo ($uaCurrentPage >= $uaTotalPages) ? 'disabled' : ''; ?>">
                                            <a class="page-link" href="?ua_page=<?php echo $uaCurrentPage + 1; ?>&date=<?php echo urlencode($date); ?>&filter=<?php echo urlencode($additionalFilter); ?>&page=<?php echo $currentPage; ?>">Next</a>
                                        </li>
                                    </ul>
                                </nav>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Raw Log Entries with Pagination -->
                <div class="card mt-4">
                    <div class="card-header bg-light">
                        <h5><i class="fas fa-list me-2"></i>Raw Log Entries</h5>
                        <button type="button" class="toggle-btn" data-bs-toggle="collapse" data-bs-target="#rawLogEntries" aria-expanded="true" aria-controls="rawLogEntries">
                            <i class="fas fa-chevron-up"></i>
                        </button>
                    </div>
                    <div class="collapse show" id="rawLogEntries">
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped table-hover table-sm">
                                    <thead class="table-light">
                                        <tr>
                                            <th>#</th>
                                            <th>Log Entry</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php 
                                        $entryNumber = $offset + 1;
                                        foreach ($paginatedLines as $line): 
                                            // Extract and highlight the User Agent
                                            $highlightedLine = $line;
                                            if (preg_match('/"([^"]+)"$/', $line, $matches)) {
                                                $userAgent = $matches[1];
                                                // Determine User Agent type
                                                $uaType = 'default';
                                                $uaIcon = '';
                                                
                                                if (preg_match('/(bot|spider|crawl)/i', $userAgent)) {
                                                    $uaType = 'secondary'; // Bot
                                                    $uaIcon = '<i class="fas fa-robot me-1"></i>';
                                                } elseif (preg_match('/(mobile|android|iphone|ipad|ios)/i', $userAgent)) {
                                                    $uaType = 'primary'; // Mobile
                                                    $uaIcon = '<i class="fas fa-mobile-alt me-1"></i>';
                                                } else {
                                                    $uaType = 'success'; // Desktop
                                                    $uaIcon = '<i class="fas fa-desktop me-1"></i>';
                                                }
                                                
                                                // Replace the User Agent in the line with a highlighted version
                                                $highlightedUA = '<span class="badge bg-' . $uaType . ' text-white" 
                                                                      data-bs-toggle="tooltip" 
                                                                      title="' . htmlspecialchars($userAgent) . '">' 
                                                                      . $uaIcon . 'User Agent</span>';
                                                
                                                $highlightedLine = str_replace('"' . $userAgent . '"', '"' . $highlightedUA . '"', htmlspecialchars($line));
                                            } else {
                                                $highlightedLine = htmlspecialchars($line);
                                            }
                                        ?>
                                        <tr>
                                            <td><?php echo $entryNumber++; ?></td>
                                            <td><code class="small"><?php echo $highlightedLine; ?></code></td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                            
                            <!-- Pagination -->
                            <?php if ($totalPages > 1): ?>
                            <nav aria-label="Log entries pagination">
                                <ul class="pagination justify-content-center">
                                    <li class="page-item <?php echo ($currentPage <= 1) ? 'disabled' : ''; ?>">
                                        <a class="page-link" href="?page=<?php echo $currentPage - 1; ?>&date=<?php echo urlencode($date); ?>&filter=<?php echo urlencode($additionalFilter); ?>">Previous</a>
                                    </li>
                                    
                                    <?php
                                    $startPage = max(1, $currentPage - 2);
                                    $endPage = min($totalPages, $startPage + 4);
                                    
                                    if ($startPage > 1) {
                                        echo '<li class="page-item"><a class="page-link" href="?page=1&date=' . urlencode($date) . '&filter=' . urlencode($additionalFilter) . '">1</a></li>';
                                        if ($startPage > 2) {
                                            echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                                        }
                                    }
                                    
                                    for ($i = $startPage; $i <= $endPage; $i++) {
                                        echo '<li class="page-item ' . ($i == $currentPage ? 'active' : '') . '"><a class="page-link" href="?page=' . $i . '&date=' . urlencode($date) . '&filter=' . urlencode($additionalFilter) . '">' . $i . '</a></li>';
                                    }
                                    
                                    if ($endPage < $totalPages) {
                                        if ($endPage < $totalPages - 1) {
                                            echo '<li class="page-item disabled"><span class="page-link">...</span></li>';
                                        }
                                        echo '<li class="page-item"><a class="page-link" href="?page=' . $totalPages . '&date=' . urlencode($date) . '&filter=' . urlencode($additionalFilter) . '">' . $totalPages . '</a></li>';
                                    }
                                    ?>
                                    
                                    <li class="page-item <?php echo ($currentPage >= $totalPages) ? 'disabled' : ''; ?>">
                                        <a class="page-link" href="?page=<?php echo $currentPage + 1; ?>&date=<?php echo urlencode($date); ?>&filter=<?php echo urlencode($additionalFilter); ?>">Next</a>
                                    </li>
                                </ul>
                            </nav>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php else: ?>
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    No log entries found matching your criteria. Please try a different date or filter.
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>
    <!-- JavaScript Libraries -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Initialize date picker
        flatpickr("#date", {
            enableTime: true,
            dateFormat: "d/M/Y:H:i",
            time_24hr: true,
            allowInput: true,
            placeholder: "dd/Mmm/yyyy:hh:mm"
        });
        
        // Initialize tooltips for User Agents
        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl, {
            html: false,
            placement: 'top',
            boundary: 'window'
        }));
        
        // Toggle state persistence
        const toggleButtons = document.querySelectorAll('.toggle-btn');
        
        // Function to update toggle button icon based on collapse state
        function updateToggleIcon(button, isCollapsed) {
            const icon = button.querySelector('i');
            if (isCollapsed) {
                button.classList.add('collapsed');
            } else {
                button.classList.remove('collapsed');
            }
        }
        
        // Initialize toggle states from localStorage
        toggleButtons.forEach(button => {
            const targetId = button.getAttribute('data-bs-target').substring(1);
            const isCollapsed = localStorage.getItem('collapse_' + targetId) === 'true';
            const targetElement = document.getElementById(targetId);
            
            if (isCollapsed && targetElement) {
                targetElement.classList.remove('show');
                updateToggleIcon(button, true);
            }
            
            // Add event listener to save state on toggle
            button.addEventListener('click', function() {
                const target = button.getAttribute('data-bs-target').substring(1);
                const isCollapsed = !document.getElementById(target).classList.contains('show');
                localStorage.setItem('collapse_' + target, isCollapsed);
                updateToggleIcon(button, isCollapsed);
            });
        });
        
        // Show loading indicator when form is submitted
        const searchForm = document.getElementById('searchForm');
        const loadingIndicator = document.getElementById('loading');
        
        if (searchForm) {
            searchForm.addEventListener('submit', function() {
                loadingIndicator.style.display = 'block';
            });
        }
        
        // CSV Export functionality
        const exportBtn = document.getElementById('exportBtn');
        if (exportBtn) {
            exportBtn.addEventListener('click', function() {
                exportToCSV();
            });
        }
        
        // Function to export data to CSV - optimized for performance
        function exportToCSV() {
            // Use a string builder approach for better performance with large datasets
            const csvParts = ["data:text/csv;charset=utf-8,"];
            const tables = document.querySelectorAll('.stats-container table');
            
            // Process each table
            tables.forEach((table, tableIndex) => {
                // Add table title (from the card header)
                const cardHeader = table.closest('.card').querySelector('.card-header h5');
                if (cardHeader) {
                    csvParts.push(cardHeader.textContent.trim() + "\n");
                }
                
                // Get headers
                const headers = Array.from(table.querySelectorAll('thead th'))
                    .map(th => th.textContent.trim());
                csvParts.push(headers.join(',') + "\n");
                
                // Get rows - use DocumentFragment for better performance
                const rows = table.querySelectorAll('tbody tr');
                if (rows.length > 0) {
                    // Process in batches for large tables
                    const batchSize = 100;
                    for (let i = 0; i < rows.length; i += batchSize) {
                        const batch = Array.from(rows).slice(i, i + batchSize);
                        
                        batch.forEach(tr => {
                            const rowData = Array.from(tr.querySelectorAll('td')).map(td => {
                                // Remove HTML and clean the content
                                let content = td.textContent.trim();
                                // Escape commas and quotes
                                content = content.replace(/"/g, '""');
                                return content.includes(',') ? `"${content}"` : content;
                            });
                            csvParts.push(rowData.join(',') + "\n");
                        });
                    }
                }
                
                // Add a blank line between tables
                csvParts.push("\n");
            });
            
            // Join all parts at once for better performance
            const csvContent = csvParts.join('');
            
            // Create download link
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", "log_analysis_" + new Date().toISOString().slice(0, 10) + ".csv");
            
            // Append, click, and remove in one go
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
        
        // Initialize charts if data is available
        initializeCharts();
        
        // Optimized chart initialization
        function initializeCharts() {
            // Define chart configuration factory functions for reusability and performance
            const createPieChartConfig = (labels, data, colors) => ({
                type: 'pie',
                data: {
                    labels,
                    datasets: [{
                        data,
                        backgroundColor: colors,
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { boxWidth: 15 }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.raw || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = Math.round((value / total) * 100);
                                    return `${label}: ${value} (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
            
            const createBarChartConfig = (labels, data, colors) => ({
                type: 'bar',
                data: {
                    labels,
                    datasets: [{
                        label: 'HTTP Status Codes',
                        data,
                        backgroundColor: colors,
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.raw || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = Math.round((value / total) * 100);
                                    return `Status ${label}: ${value} requests (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
            
            // Function to extract data from table
            const extractTableData = (table) => {
                const data = [];
                const labels = [];
                const colors = [];
                
                if (table) {
                    // Use Array.from for better performance with map
                    const rows = Array.from(table.querySelectorAll('tbody tr'));
                    
                    rows.forEach((row, index) => {
                        const cells = row.querySelectorAll('td');
                        if (cells.length >= 2) {
                            const label = cells[0].textContent.trim();
                            const value = parseInt(cells[1].textContent.trim(), 10);
                            
                            if (value > 0) {
                                labels.push(label);
                                data.push(value);
                                
                                // Generate a color using golden ratio for good distribution
                                const hue = (index * 137) % 360;
                                colors.push(`hsl(${hue}, 70%, 60%)`);
                            }
                        }
                    });
                }
                
                return { data, labels, colors };
            };
            
            // Initialize Traffic Sources Chart
            const sourcesChartContainer = document.getElementById('sourcesChart');
            if (sourcesChartContainer) {
                const sourcesTable = document.querySelector('.card:has(#sourcesChart)').closest('.row').nextElementSibling.querySelector('table');
                const { data: sourcesData, labels: sourcesLabels, colors: sourcesColors } = extractTableData(sourcesTable);
                
                if (sourcesLabels.length > 0) {
                    const ctx = document.createElement('canvas');
                    sourcesChartContainer.appendChild(ctx);
                    
                    // Create chart with factory function
                    new Chart(ctx, createPieChartConfig(sourcesLabels, sourcesData, sourcesColors));
                } else {
                    sourcesChartContainer.innerHTML = '<div class="alert alert-info">No data available for chart</div>';
                }
            }
            
            // Initialize Status Codes Chart
            const statusChartContainer = document.getElementById('statusChart');
            if (statusChartContainer) {
                // Status code color mapping
                const statusColors = {
                    '200': 'rgba(40, 167, 69, 0.7)',   // Success (green)
                    '301': 'rgba(23, 162, 184, 0.7)',  // Redirect (cyan)
                    '302': 'rgba(23, 162, 184, 0.7)',  // Redirect (cyan)
                    '304': 'rgba(108, 117, 125, 0.7)', // Not Modified (gray)
                    '400': 'rgba(255, 193, 7, 0.7)',   // Client Error (yellow)
                    '401': 'rgba(255, 193, 7, 0.7)',   // Client Error (yellow)
                    '403': 'rgba(255, 193, 7, 0.7)',   // Client Error (yellow)
                    '404': 'rgba(255, 193, 7, 0.7)',   // Client Error (yellow)
                    '500': 'rgba(220, 53, 69, 0.7)',   // Server Error (red)
                    '502': 'rgba(220, 53, 69, 0.7)',   // Server Error (red)
                    '503': 'rgba(220, 53, 69, 0.7)',   // Server Error (red)
                    '504': 'rgba(220, 53, 69, 0.7)'    // Server Error (red)
                };
                
                const statusData = [];
                const statusLabels = [];
                const statusBackgroundColors = [];
                
                // Get status code data from PHP
                <?php if (isset($statusCodes) && !empty($statusCodes)): ?>
                <?php foreach ($statusCodes as $code => $count): ?>
                statusLabels.push('<?php echo $code; ?>');
                statusData.push(<?php echo $count; ?>);
                statusBackgroundColors.push(statusColors['<?php echo $code; ?>'] || 'rgba(0, 123, 255, 0.7)');
                <?php endforeach; ?>
                <?php endif; ?>
                
                if (statusLabels.length > 0) {
                    const ctx = document.createElement('canvas');
                    statusChartContainer.appendChild(ctx);
                    
                    // Create chart with factory function
                    new Chart(ctx, createBarChartConfig(statusLabels, statusData, statusBackgroundColors));
                } else {
                    statusChartContainer.innerHTML = '<div class="alert alert-info">No status code data available</div>';
                }
            }
        }
    });
    </script>
</body>
</html>
