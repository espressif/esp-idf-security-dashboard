# ESP-IDF Security Vulnerability Dashboard

A comprehensive security vulnerability dashboard for ESP-IDF releases that tracks and displays security issues across different versions to help developers make informed decisions about updates and security patches.

## 🎯 Overview

This dashboard provides:
- **Automated vulnerability scanning** of ESP-IDF releases using `esp-idf-sbom`
- **Interactive web dashboard** with filtering and search capabilities
- **Daily automated updates** via GitHub Actions
- **Developer-friendly insights** for migration and security decisions

## 🌐 Live Dashboard

Visit the live dashboard at: **https://espressif.github.io/esp-idf-security-dashboard**

## 📊 Features

### Dashboard Features
- **Multi-version comparison** across ESP-IDF v5.0-v5.4 releases
- **Severity-based filtering** (Critical, High, Medium, Low)
- **Component analysis** showing affected third-party libraries
- **Search functionality** for CVE IDs and components
- **Export capabilities** for CI/CD integration
- **Mobile-responsive design**

### Automation Features
- **Daily vulnerability scans** using latest NVD database
- **GitHub Issues integration** for high-severity vulnerabilities
- **Matrix scanning** for parallel processing of multiple versions
- **Artifact storage** for historical scan data

## 🚀 Usage

Visit the [live dashboard](https://espressif.github.io/esp-idf-security-dashboard) to view the latest vulnerability information.

### Local Development
```bash
# Serve the dashboard locally
python -m http.server 8000

# Visit http://localhost:8000
```

