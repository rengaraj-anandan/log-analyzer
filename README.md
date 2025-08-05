# 📊 Log Analyzer

[![PHP Version](https://img.shields.io/badge/PHP-8.2%2B-blue.svg)](https://www.php.net/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A powerful web-based tool for analyzing web server access logs with advanced filtering, visualization, and reporting capabilities.


## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [Technical Details](#-technical-details)
- [Performance](#-performance)
- [Browser Compatibility](#-browser-compatibility)
- [Future Enhancements](#-future-enhancements)
- [Contributing](#-contributing)
- [License](#-license)

## 🔍 Overview

Log Analyzer transforms complex web server logs into actionable insights through an intuitive interface. Quickly identify traffic patterns, detect issues, and generate reports without specialized knowledge.

**Key Benefits:**
- Instant visualization of log data
- Easy identification of traffic sources and patterns
- Detailed analysis of user agents and request patterns
- Secure upload and processing of custom log files

## ✨ Features

### User Interface
- Modern, responsive design with Bootstrap 5
- Intuitive navigation with clear section headers
- Interactive date picker and filtering options
- Mobile-friendly layout with collapsible sections
- Toggle state persistence across page refreshes

### Data Analysis & Visualization
- Comprehensive log parsing with key metrics extraction
- Interactive charts for traffic sources and status codes
- Statistical calculations with percentages and distributions
- Summary cards for quick metrics overview
- Enhanced User Agent detection and categorization
- Full User Agent reporting with pagination

### Data Management & Security
- Pagination for large result sets
- CSV export functionality
- Secure log file upload with:
  - File type validation
  - Size limits (10MB)
  - Secure naming and storage
  - CSRF protection
- Input sanitization and secure error handling

## 📋 Requirements

- PHP 8.2 or higher
- Web server (Apache, Nginx, etc.)
- Modern web browser

## 🚀 Installation

1. Download or clone the repository to your local machine

2. Place the files in your web server directory:
   ```bash
   # Example for Apache
   cp -r logger/ /var/www/html/
   ```

3. Ensure the `access_logs` directory is writable:
   ```bash
   chmod 755 /var/www/html/logger/access_logs
   ```

4. Access through your web browser:
   ```
   http://localhost/logger/
   ```

## 🏃‍♂️ Quick Start

1. Open the application in your browser
2. Enter a date/time in the format `dd/Mmm/yyyy:hh:mm` (e.g., `17/Apr/2025:00:00`)
3. Click "Search" to analyze logs
4. View visualizations and data tables
5. Use filters to refine results

![Logo](https://github.com/rengaraj-anandan/log-analyzer/blob/main/Log-Analyzer-Website-Statistics-08-05-2025_01_47_PM.png)

## 📖 Usage Guide

### Analyzing Log Files

1. Navigate to the search section
2. Enter a date and time in the format `dd/Mmm/yyyy:hh:mm`
3. Optionally add a filter term (IP, URL, or User Agent)
4. Click "Search" to analyze the logs
5. View results in the various sections:
   - Summary cards
   - Interactive charts
   - Detailed data tables
   - Raw log entries
6. Use pagination to navigate through large result sets
7. Export data to CSV for further analysis

### Uploading Custom Logs

1. Go to the "Upload Logs" section
2. Click "Choose File" to select a log file (max 10MB)
3. Click "Upload Log File"
4. Once uploaded, the file is moved to the access_logs folder
5. Analyze the uploaded file using the search functionality

### Viewing User Agent Details

1. After searching, find the "Top User Agents" section
2. Click "View All User Agents in Full"
3. Browse the categorized list (Desktop, Mobile, Bot)
4. Use pagination to navigate through all entries

## 🔧 Technical Details

- **Backend**: PHP 8.2+
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Libraries**:
  - Bootstrap 5.3.0 (UI components)
  - Flatpickr (date/time selection)
  - Chart.js (data visualization)
  - Font Awesome 6.0.0 (icons)
- **Architecture**: No database required - works directly with log files

## ⚡ Performance

- Extended execution time limit (300 seconds) for large log files
- Efficient pagination for handling large result sets
- Client-side processing for visualization to reduce server load
- Optimized log parsing with early filtering of non-matching entries

## 🌐 Browser Compatibility

Tested and working on:
- Chrome 90+
- Firefox 90+
- Safari 14+
- Edge 90+
- Mobile browsers (iOS Safari, Chrome for Android)

## 🔮 Future Enhancements

- Real-time log monitoring
- Advanced filtering with regular expressions
- User authentication system
- Saved searches and reports
- Automated scheduled reports
- Dark mode theme

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

