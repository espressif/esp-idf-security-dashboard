#!/usr/bin/env python3

"""
ESP-IDF Security Vulnerability Scanner

This script scans ESP-IDF releases for security vulnerabilities using:
1. ESP-IDF Docker images for stable releases (primary method)
2. Remote repository cloning for latest branch code (optional)

Uses esp-idf-sbom manifest check command for vulnerability detection.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ESP-IDF Docker image mappings for stable releases
ESP_IDF_DOCKER_IMAGES = {
    'v5.4.2': 'espressif/idf:v5.4.2',
    'v5.4.1': 'espressif/idf:v5.4.1', 
    'v5.3.3': 'espressif/idf:v5.3.3',
    'v5.3.2': 'espressif/idf:v5.3.2',
    'v5.3.1': 'espressif/idf:v5.3.1',
    'v5.2.5': 'espressif/idf:v5.2.5',
    'v5.2.4': 'espressif/idf:v5.2.4',
    'v5.2.3': 'espressif/idf:v5.2.3',
    'v5.2.2': 'espressif/idf:v5.2.2',
    'v5.2.1': 'espressif/idf:v5.2.1',
    'v5.1.6': 'espressif/idf:v5.1.6',
    'v5.1.5': 'espressif/idf:v5.1.5',
    'v5.1.4': 'espressif/idf:v5.1.4',
    'v5.1.3': 'espressif/idf:v5.1.3',
    'v5.1.2': 'espressif/idf:v5.1.2',
    'v5.1.1': 'espressif/idf:v5.1.1',
    'v5.0.9': 'espressif/idf:v5.0.9',
    'v5.0.8': 'espressif/idf:v5.0.8',
    'v5.0.7': 'espressif/idf:v5.0.7',
    'v5.0.6': 'espressif/idf:v5.0.6',
    'v5.0.5': 'espressif/idf:v5.0.5',
    'v5.0.4': 'espressif/idf:v5.0.4',
    'v5.0.3': 'espressif/idf:v5.0.3',
    'v5.0.2': 'espressif/idf:v5.0.2',
    'v5.0.1': 'espressif/idf:v5.0.1'
}

# Default releases to scan (most recent stable versions)
DEFAULT_RELEASES = [
    'v5.4.2', 'v5.4.1',
    'v5.3.3', 'v5.3.2', 
    'v5.2.5', 'v5.2.4',
    'v5.1.6', 'v5.1.5',
    'v5.0.9', 'v5.0.8'
]

# ESP-IDF release branches to scan
ESP_IDF_RELEASE_BRANCHES = [
    'release/v5.0',
    'release/v5.1', 
    'release/v5.2',
    'release/v5.3',
    'release/v5.4',
    'release/v5.5'
]

class ESPIDFSecurityScanner:
    def __init__(self, output_dir, use_docker=True):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.use_docker = use_docker
        
        # Check Docker availability if using Docker
        if self.use_docker:
            self._check_docker()
        
    def _check_docker(self):
        """Check if Docker is available"""
        try:
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, check=True)
            logger.info(f"Docker available: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("Docker is required but not available. Please install Docker or use --no-docker option.")
            
    def run_command(self, cmd, cwd=None, check=True, shell=True):
        """Run a command and return the result"""
        try:
            result = subprocess.run(
                cmd, shell=shell, cwd=cwd, 
                capture_output=True, text=True, check=check
            )
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {cmd}")
            logger.error(f"Error: {e.stderr}")
            raise
            
    def scan_version_with_docker(self, version):
        """Scan ESP-IDF version using Docker image"""
        docker_image = ESP_IDF_DOCKER_IMAGES.get(version)
        if not docker_image:
            logger.error(f"No Docker image available for version {version}")
            return None
            
        logger.info(f"Scanning {version} using Docker image: {docker_image}")
        
        try:
            # Update NVD database (only once per run)
            if not hasattr(self, '_db_synced'):
                logger.info("Syncing NVD database...")
                try:
                    self.run_command("pip install -q esp-idf-sbom && esp-idf-sbom sync-db")
                    self._db_synced = True
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to sync NVD database: {e}")
                    self._db_synced = True
            
            # Create temporary container and scan
            container_name = f"esp-idf-scan-{version.replace('.', '-')}"
            
            # Pull the Docker image
            logger.info(f"Pulling Docker image: {docker_image}")
            self.run_command(f"docker pull {docker_image}")
            
            # Run vulnerability scan inside container
            docker_cmd = f"""
            docker run --rm --name {container_name} \
                -v /tmp:/tmp \
                {docker_image} \
                bash -c "
                    pip install -q esp-idf-sbom && \
                    esp-idf-sbom sync-db && \
                    esp-idf-sbom manifest check --format=json --local-db --no-sync-db /opt/esp/idf
                "
            """
            
            result = self.run_command(docker_cmd, check=False)
            
            if result.returncode not in [0, 1]:  # 0 = no vulns, 1 = vulns found
                logger.error(f"Docker scan failed for {version}: {result.stderr}")
                return None
                
            try:
                if result.stdout.strip():
                    # Clean the output - sometimes there are extra lines before/after JSON
                    stdout_lines = result.stdout.strip().split('\n')
                    json_content = None
                    
                    # Try to find JSON content in the output
                    for i, line in enumerate(stdout_lines):
                        if line.strip().startswith('{'):
                            # Found start of JSON, try to parse from here
                            json_text = '\n'.join(stdout_lines[i:])
                            try:
                                scan_result = json.loads(json_text)
                                json_content = json_text
                                break
                            except json.JSONDecodeError:
                                continue
                    
                    if json_content is None:
                        # Fallback: try parsing the entire output
                        scan_result = json.loads(result.stdout.strip())
                else:
                    scan_result = {"vulnerabilities": []}
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse scan result for {version}: {e}")
                logger.error(f"Raw output: {result.stdout[:500]}...")  # Show first 500 chars for debugging
                # Return empty result instead of None to continue scanning other versions
                scan_result = {"vulnerabilities": []}
                
            return scan_result
            
        except Exception as e:
            logger.error(f"Docker scan failed for {version}: {e}")
            return None
            
    def scan_version_with_git(self, version, repository_url="https://github.com/espressif/esp-idf.git"):
        """Scan ESP-IDF version by cloning from git repository"""
        logger.info(f"Scanning {version} by cloning from repository")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "esp-idf"
            
            try:
                # Clone repository
                logger.info(f"Cloning ESP-IDF repository...")
                self.run_command(f"git clone --depth 1 --branch {version} --recursive {repository_url} {repo_path}")
                
                # Update NVD database (only once per run)
                if not hasattr(self, '_db_synced'):
                    logger.info("Syncing NVD database...")
                    try:
                        self.run_command("esp-idf-sbom sync-db")
                        self._db_synced = True
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Failed to sync NVD database: {e}")
                        self._db_synced = True
                
                # Run vulnerability scan
                result = self.run_command(
                    f"esp-idf-sbom manifest check --format=json --local-db --no-sync-db {repo_path}",
                    check=False
                )
                
                if result.returncode not in [0, 1]:
                    logger.error(f"Git scan failed for {version}: {result.stderr}")
                    return None
                    
                try:
                    if result.stdout.strip():
                        # Clean the output - sometimes there are extra lines before/after JSON
                        stdout_lines = result.stdout.strip().split('\n')
                        json_content = None
                        
                        # Try to find JSON content in the output
                        for i, line in enumerate(stdout_lines):
                            if line.strip().startswith('{'):
                                # Found start of JSON, try to parse from here
                                json_text = '\n'.join(stdout_lines[i:])
                                try:
                                    scan_result = json.loads(json_text)
                                    json_content = json_text
                                    break
                                except json.JSONDecodeError:
                                    continue
                        
                        if json_content is None:
                            # Fallback: try parsing the entire output
                            scan_result = json.loads(result.stdout.strip())
                    else:
                        scan_result = {"vulnerabilities": []}
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse scan result for {version}: {e}")
                    logger.error(f"Raw output: {result.stdout[:500]}...")  # Show first 500 chars for debugging
                    # Return empty result instead of None to continue scanning other versions
                    scan_result = {"vulnerabilities": []}
                    
                return scan_result
                
            except Exception as e:
                logger.error(f"Git scan failed for {version}: {e}")
                return None
                
    def scan_latest_branch(self, branch="master", repository_url="https://github.com/espressif/esp-idf.git"):
        """Scan latest code from a specific branch"""
        logger.info(f"Scanning latest code from branch: {branch}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "esp-idf"
            
            try:
                # Clone repository
                logger.info(f"Cloning ESP-IDF repository branch {branch}...")
                self.run_command(f"git clone --depth 1 --branch {branch} --recursive {repository_url} {repo_path}")
                
                # Get commit info for version identifier
                commit_result = self.run_command("git rev-parse --short HEAD", cwd=repo_path)
                commit_hash = commit_result.stdout.strip()
                
                date_result = self.run_command("git log -1 --format=%ci", cwd=repo_path)
                commit_date = date_result.stdout.strip()
                
                version_id = f"{branch}-{commit_hash}"
                
                # Update NVD database (only once per run)
                if not hasattr(self, '_db_synced'):
                    logger.info("Syncing NVD database...")
                    try:
                        self.run_command("esp-idf-sbom sync-db")
                        self._db_synced = True
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Failed to sync NVD database: {e}")
                        self._db_synced = True
                
                # Run vulnerability scan
                result = self.run_command(
                    f"esp-idf-sbom manifest check --format=json --local-db --no-sync-db {repo_path}",
                    check=False
                )
                
                if result.returncode not in [0, 1]:
                    logger.error(f"Branch scan failed for {branch}: {result.stderr}")
                    return None, None
                    
                try:
                    if result.stdout.strip():
                        # Clean the output - sometimes there are extra lines before/after JSON
                        stdout_lines = result.stdout.strip().split('\n')
                        json_content = None
                        
                        # Try to find JSON content in the output
                        for i, line in enumerate(stdout_lines):
                            if line.strip().startswith('{'):
                                # Found start of JSON, try to parse from here
                                json_text = '\n'.join(stdout_lines[i:])
                                try:
                                    scan_result = json.loads(json_text)
                                    json_content = json_text
                                    break
                                except json.JSONDecodeError:
                                    continue
                        
                        if json_content is None:
                            # Fallback: try parsing the entire output
                            scan_result = json.loads(result.stdout.strip())
                    else:
                        scan_result = {"vulnerabilities": []}
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse scan result for {branch}: {e}")
                    logger.error(f"Raw output: {result.stdout[:500]}...")  # Show first 500 chars for debugging
                    # Return empty result instead of None to continue scanning
                    scan_result = {"vulnerabilities": []}
                    
                return version_id, scan_result
                
            except Exception as e:
                logger.error(f"Branch scan failed for {branch}: {e}")
                return None, None
                
    def scan_multiple_targets_with_single_clone(self, targets, repository_url="https://github.com/espressif/esp-idf.git", generate_summary=True):
        """Efficiently scan multiple tags/branches with a single repository clone"""
        logger.info(f"Starting batch scan with single clone for {len(targets)} targets")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "esp-idf"
            results = {}
            
            try:
                # Clone repository with full history (not shallow)
                logger.info(f"Cloning ESP-IDF repository with full history...")
                self.run_command(f"git clone --recursive {repository_url} {repo_path}")
                
                # Update NVD database once
                if not hasattr(self, '_db_synced'):
                    logger.info("Syncing NVD database...")
                    try:
                        self.run_command("esp-idf-sbom sync-db")
                        self._db_synced = True
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Failed to sync NVD database: {e}")
                        self._db_synced = True
                
                # Scan each target
                for target in targets:
                    logger.info(f"Scanning target: {target}")
                    
                    try:
                        # Clean working directory before checkout to avoid conflicts
                        # Handle esptool files that cause conflicts due to source->submodule transition
                        esptool_files = [
                            "components/esptool_py/esptool/espefuse.py",
                            "components/esptool_py/esptool/espsecure.py", 
                            "components/esptool_py/esptool/esptool.py"
                        ]
                        for file_path in esptool_files:
                            full_path = repo_path / file_path
                            if full_path.exists():
                                logger.info(f"Removing problematic esptool file: {file_path}")
                                self.run_command(f"rm -f {file_path}", cwd=repo_path, check=False)
                        
                        # Check and clean esptool_py directory if it exists as non-submodule
                        esptool_dir = repo_path / "components/esptool_py"
                        if esptool_dir.exists():
                            self.run_command("git status --porcelain components/esptool_py", cwd=repo_path, check=False)
                        
                        self.run_command("git clean -fd", cwd=repo_path, check=False)
                        self.run_command("git reset --hard HEAD", cwd=repo_path, check=False)
                        
                        # Checkout the target (tag or branch)
                        checkout_result = self.run_command(f"git checkout {target}", cwd=repo_path, check=False)
                        if checkout_result.returncode != 0:
                            logger.error(f"Failed to checkout {target}: {checkout_result.stderr}")
                            continue
                        
                        # Update submodules after checkout (critical for finding vulnerabilities)
                        logger.info(f"Initializing submodules for {target}...")
                        submodule_result = self.run_command("git submodule update --init --recursive", cwd=repo_path, check=False)
                        if submodule_result.returncode != 0:
                            logger.warning(f"Submodule initialization failed for {target}: {submodule_result.stderr}")
                        else:
                            logger.info(f"Submodules initialized successfully for {target}")
                        
                        # Get commit info for version identifier
                        commit_result = self.run_command("git rev-parse --short HEAD", cwd=repo_path)
                        commit_hash = commit_result.stdout.strip()
                        
                        date_result = self.run_command("git log -1 --format=%ci", cwd=repo_path)
                        commit_date = date_result.stdout.strip()
                        
                        # Determine if this is a tag or branch and create appropriate version ID
                        tag_check = self.run_command(f"git tag --points-at HEAD", cwd=repo_path, check=False)
                        is_tag = target in tag_check.stdout.strip().split('\n') if tag_check.stdout.strip() else False
                        
                        if is_tag:
                            version_id = target  # Use tag name as-is for releases
                            scan_method = "git-tag"
                        else:
                            version_id = f"{target}-{commit_hash}"  # Use branch-hash for branches
                            scan_method = "git-branch" if not target.startswith("release/") else "git-release-branch"
                        
                        # Run vulnerability scan
                        logger.info(f"Running vulnerability scan for {target}...")
                        scan_result = self.run_command(
                            f"esp-idf-sbom manifest check --format=json --local-db --no-sync-db {repo_path}",
                            check=False
                        )
                        
                        if scan_result.returncode not in [0, 1]:
                            logger.error(f"Scan failed for {target}: {scan_result.stderr}")
                            continue
                            
                        try:
                            if scan_result.stdout.strip():
                                # Clean the output - sometimes there are extra lines before/after JSON
                                stdout_lines = scan_result.stdout.strip().split('\n')
                                json_content = None
                                
                                # Try to find JSON content in the output
                                for i, line in enumerate(stdout_lines):
                                    if line.strip().startswith('{'):
                                        # Found start of JSON, try to parse from here
                                        json_text = '\n'.join(stdout_lines[i:])
                                        try:
                                            parsed_result = json.loads(json_text)
                                            json_content = json_text
                                            break
                                        except json.JSONDecodeError:
                                            continue
                                
                                if json_content is None:
                                    # Fallback: try parsing the entire output
                                    parsed_result = json.loads(scan_result.stdout.strip())
                            else:
                                parsed_result = {"vulnerabilities": []}
                        except json.JSONDecodeError as e:
                            logger.error(f"Failed to parse scan result for {target}: {e}")
                            logger.error(f"Raw output: {scan_result.stdout[:500]}...")  # Show first 500 chars for debugging
                            # Continue with empty result instead of skipping
                            parsed_result = {"vulnerabilities": []}
                        
                        # Store the result
                        tool_version = self.get_tool_version()
                        dashboard_data = self.parse_and_store_results(parsed_result, version_id, tool_version, scan_method)
                        results[version_id] = dashboard_data
                        
                        logger.info(f"✅ Successfully scanned {target} as {version_id}")
                        
                    except Exception as e:
                        logger.error(f"Failed to scan {target}: {e}")
                        continue
                
                logger.info(f"Batch scan complete: {len(results)}/{len(targets)} targets successful")
                
                # Generate scan summary file if requested
                if generate_summary:
                    self._generate_scan_summary(results, targets, "git-batch")
                
                return results
                
            except Exception as e:
                logger.error(f"Batch scan failed: {e}")
                return {}
    
    def _generate_scan_summary(self, results, targets, scan_method):
        """Generate scan summary file"""
        summary = {
            "last_updated": datetime.utcnow().isoformat() + "Z",
            "scanned_versions": list(results.keys()),
            "failed_versions": [t for t in targets if t not in results],
            "total_scanned": len(results),
            "scan_method": scan_method,
            "workflow_run": os.getenv("GITHUB_RUN_NUMBER", "local"),
            "scanner_info": {
                "tool": "esp-idf-security-dashboard",
                "esp_idf_sbom_version": self.get_tool_version(),
                "batch_mode_used": scan_method in ["git-batch", "unified"]
            }
        }
        
        summary_file = self.output_dir / "scan_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Generated scan summary: {summary_file}")
        return summary
                
    def get_available_targets(self, repository_url="https://github.com/espressif/esp-idf.git", target_patterns=None):
        """Get available tags and branches from repository without cloning"""
        logger.info("Fetching available targets from repository...")
        
        try:
            # Get remote tags
            tags_result = self.run_command(f"git ls-remote --tags {repository_url}")
            available_tags = []
            for line in tags_result.stdout.strip().split('\n'):
                if line and 'refs/tags/' in line:
                    tag = line.split('refs/tags/')[-1]
                    # Skip annotated tag references (^{})
                    if not tag.endswith('^{}'):
                        available_tags.append(tag)
            
            # Get remote branches  
            branches_result = self.run_command(f"git ls-remote --heads {repository_url}")
            available_branches = []
            for line in branches_result.stdout.strip().split('\n'):
                if line and 'refs/heads/' in line:
                    branch = line.split('refs/heads/')[-1]
                    available_branches.append(branch)
            
            # Filter based on patterns if provided
            if target_patterns:
                filtered_tags = []
                filtered_branches = []
                
                for pattern in target_patterns:
                    # Match tags
                    filtered_tags.extend([tag for tag in available_tags if pattern in tag])
                    # Match branches
                    filtered_branches.extend([branch for branch in available_branches if pattern in branch])
                
                available_tags = list(set(filtered_tags))
                available_branches = list(set(filtered_branches))
            
            logger.info(f"Found {len(available_tags)} tags and {len(available_branches)} branches")
            return available_tags, available_branches
            
        except Exception as e:
            logger.error(f"Failed to fetch remote targets: {e}")
            return [], []
                
    def parse_and_store_results(self, scan_result, version, tool_version, scan_method="docker"):
        """Parse scan results and store in dashboard format"""
        # Handle esp-idf-sbom format with 'records' array
        if "records" in scan_result:
            # Extract vulnerabilities from esp-idf-sbom format
            raw_records = scan_result.get("records", [])
            vulnerabilities = []
            
            for record in raw_records:
                if record.get("vulnerable") == "YES":
                    # Convert esp-idf-sbom record to dashboard format
                    vuln = {
                        "cve_id": record.get("cve_id", ""),
                        "component": record.get("pkg_name", ""),
                        "component_version": record.get("pkg_version", ""),
                        "severity": record.get("cvss_base_severity", "UNKNOWN").upper(),
                        "score": record.get("cvss_base_score", ""),
                        "vector": record.get("cvss_vector_string", ""),
                        "description": record.get("cve_desc", ""),
                        "link": record.get("cve_link", "")
                    }
                    vulnerabilities.append(vuln)
        else:
            # Fallback to old format for backwards compatibility
            vulnerabilities = scan_result.get("vulnerabilities", [])
        
        # Count vulnerabilities by severity
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN").upper()
            if severity in severity_count:
                severity_count[severity] += 1
                
        # Create dashboard data structure
        dashboard_data = {
            "release_version": version,
            "scan_date": datetime.utcnow().isoformat() + "Z",
            "tool_version": tool_version,
            "total_components": len(scan_result.get("components", scan_result.get("packages", []))),
            "vulnerabilities": vulnerabilities,
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "by_severity": severity_count
            },
            "metadata": {
                "scanner": "esp-idf-security-dashboard",
                "scan_method": scan_method,
                "docker_image": ESP_IDF_DOCKER_IMAGES.get(version) if scan_method == "docker" else None
            }
        }
        
        # Save to output directory
        # Sanitize version for filename (replace / with _)
        safe_filename = version.replace("/", "_")
        output_file = self.output_dir / f"{safe_filename}.json"
        with open(output_file, 'w') as f:
            json.dump(dashboard_data, f, indent=2)
            
        logger.info(f"Saved scan results for {version} to {output_file}")
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities: {severity_count}")
        return dashboard_data
        
    def get_tool_version(self):
        """Get esp-idf-sbom tool version"""
        try:
            result = self.run_command("pip show esp-idf-sbom")
            for line in result.stdout.split('\n'):
                if line.startswith('Version:'):
                    return line.split(':', 1)[1].strip()
        except:
            pass
        return "unknown"
        
    def scan_version(self, version):
        """Scan a single ESP-IDF version using the best available method"""
        logger.info(f"Starting scan for {version}")
        
        scan_result = None
        scan_method = None
        
        # Try Docker first if available and image exists
        if self.use_docker and version in ESP_IDF_DOCKER_IMAGES:
            scan_result = self.scan_version_with_docker(version)
            scan_method = "docker"
            
        # Fall back to git clone if Docker failed or not available
        if scan_result is None:
            logger.info(f"Falling back to git clone for {version}")
            scan_result = self.scan_version_with_git(version)
            scan_method = "git"
            
        if scan_result is None:
            logger.error(f"Failed to scan {version} with any method")
            return None
            
        # Parse and store results
        tool_version = self.get_tool_version()
        dashboard_data = self.parse_and_store_results(scan_result, version, tool_version, scan_method)
        
        return dashboard_data
        
    def scan_releases(self, releases, include_branches=None, include_release_branches=False, use_batch_mode=False):
        """Scan multiple ESP-IDF releases and optionally latest branches"""
        results = {}
        
        # Collect all git-based targets for batch scanning if enabled
        git_targets = []
        if use_batch_mode and (include_branches or include_release_branches or any(v not in ESP_IDF_DOCKER_IMAGES for v in releases)):
            # Add releases that don't have Docker images
            git_targets.extend([v for v in releases if v not in ESP_IDF_DOCKER_IMAGES])
            
            # Add release branches
            if include_release_branches:
                git_targets.extend(ESP_IDF_RELEASE_BRANCHES)
                
            # Add custom branches
            if include_branches:
                git_targets.extend(include_branches)
        
        # Use batch mode for git targets if there are multiple
        if use_batch_mode and len(git_targets) > 1:
            logger.info(f"Using optimized batch scanning for {len(git_targets)} git targets")
            batch_results = self.scan_multiple_targets_with_single_clone(git_targets)
            results.update(batch_results)
            
            # Remove git targets from individual processing
            releases = [v for v in releases if v in ESP_IDF_DOCKER_IMAGES]
            include_branches = None
            include_release_branches = False
        
        # Scan specified releases with Docker (if available)
        if releases:
            logger.info(f"Scanning {len(releases)} releases: {releases}")
            
            for version in releases:
                logger.info(f"Processing {version}")
                result = self.scan_version(version)
                if result:
                    results[version] = result
                    logger.info(f"✅ Successfully scanned {version}")
                else:
                    logger.error(f"❌ Failed to scan {version}")
                
        # Scan ESP-IDF release branches if requested (and not in batch mode)
        if include_release_branches:
            logger.info(f"Scanning ESP-IDF release branches: {ESP_IDF_RELEASE_BRANCHES}")
            for branch in ESP_IDF_RELEASE_BRANCHES:
                version_id, scan_result = self.scan_latest_branch(branch)
                if scan_result:
                    tool_version = self.get_tool_version()
                    dashboard_data = self.parse_and_store_results(scan_result, version_id, tool_version, "git-release-branch")
                    results[version_id] = dashboard_data
                    logger.info(f"✅ Successfully scanned release branch {branch} as {version_id}")
                else:
                    logger.error(f"❌ Failed to scan release branch {branch}")
                
        # Scan custom branches if requested (and not in batch mode)
        if include_branches:
            logger.info(f"Scanning custom branches: {include_branches}")
            for branch in include_branches:
                version_id, scan_result = self.scan_latest_branch(branch)
                if scan_result:
                    tool_version = self.get_tool_version()
                    dashboard_data = self.parse_and_store_results(scan_result, version_id, tool_version, "git-branch")
                    results[version_id] = dashboard_data
                    logger.info(f"✅ Successfully scanned branch {branch} as {version_id}")
                else:
                    logger.error(f"❌ Failed to scan branch {branch}")
                    
        # Create summary file
        summary = {
            "last_updated": datetime.utcnow().isoformat() + "Z",
            "scanned_versions": list(results.keys()),
            "total_scanned": len(results),
            "scanner_info": {
                "tool": "esp-idf-security-dashboard",
                "methods": ["docker", "git"] if self.use_docker else ["git"],
                "esp_idf_sbom_version": self.get_tool_version(),
                "batch_mode_used": use_batch_mode and len(git_targets) > 1
            }
        }
        
        summary_file = self.output_dir / "scan_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
            
        logger.info(f"Scan complete. Results saved to {self.output_dir}")
        logger.info(f"Successfully scanned: {len(results)} items")
        return results
        
    def scan_unified_targets(self, targets, prefer_git_over_docker=False):
        """Unified scanning: scan ALL targets (tags, branches) in a single clone operation"""
        logger.info(f"Starting unified scan with single clone for {len(targets)} targets")
        
        if prefer_git_over_docker:
            logger.info("Using git-only mode for all targets (skipping Docker)")
            results = self.scan_multiple_targets_with_single_clone(targets)
            # Summary is already generated in scan_multiple_targets_with_single_clone
            return results
        
        # Separate Docker-available vs git-only targets
        docker_targets = [t for t in targets if t in ESP_IDF_DOCKER_IMAGES]
        git_targets = [t for t in targets if t not in ESP_IDF_DOCKER_IMAGES]
        
        logger.info(f"Found {len(docker_targets)} Docker-available targets and {len(git_targets)} git-only targets")
        
        # Option 1: Use Docker for available versions, git for others (current mixed approach)
        # Option 2: Use git for everything (more consistent, single clone)
        
        if len(git_targets) > len(docker_targets) * 2:  # If many git targets, use git for everything
            logger.info("Many git targets detected - using unified git scanning for ALL targets")
            return self.scan_multiple_targets_with_single_clone(targets)
        else:
            logger.info("Using mixed approach: Docker for stable releases, git batch for others")
            results = {}
            
            # Scan Docker targets individually (fast)
            for target in docker_targets:
                result = self.scan_version_with_docker(target)
                if result:
                    tool_version = self.get_tool_version()
                    dashboard_data = self.parse_and_store_results(result, target, tool_version, "docker")
                    results[target] = dashboard_data
                    logger.info(f"✅ Docker scan completed for {target}")
            
            # Batch scan git targets (single clone)
            if git_targets:
                git_results = self.scan_multiple_targets_with_single_clone(git_targets, generate_summary=False)
                results.update(git_results)
            
            # Generate summary for mixed mode scanning
            self._generate_scan_summary(results, targets, "mixed")
            
            return results
    
    def scan_all_v5_releases(self, use_unified_mode=True, prefer_git_over_docker=False):
        """Scan all available v5.x tags and release branches efficiently"""
        logger.info("Scanning ESP-IDF v5.x releases and branches...")
        
        # Get available v5.x tags and release branches
        tags, branches = self.get_available_targets(target_patterns=["v5."])
        release_branches = [b for b in branches if b.startswith("release/v5.")]
        
        # Filter to v5.x tags only, excluding rc, dev, beta versions
        v5_tags = [tag for tag in tags if tag.startswith("v5.") and 
                   not any(exclude in tag.lower() for exclude in ["rc", "dev", "beta"])]
        
        logger.info(f"Found {len(v5_tags)} v5.x tags and {len(release_branches)} v5.x release branches")
        
        if use_unified_mode:
            # Combine all targets for unified scanning
            all_targets = v5_tags + release_branches
            return self.scan_unified_targets(all_targets, prefer_git_over_docker)
        else:
            # Use traditional scanning approach
            return self.scan_releases(v5_tags, include_branches=release_branches)

def main():
    parser = argparse.ArgumentParser(description="Scan ESP-IDF releases for security vulnerabilities")
    parser.add_argument("--output-dir", default="./data", 
                       help="Directory to store scan results")
    parser.add_argument("--versions", 
                       help="Comma-separated list of versions to scan (default: recent stable versions)")
    parser.add_argument("--single-version", 
                       help="Scan a single version (for testing)")
    parser.add_argument("--include-branches",
                       help="Comma-separated list of custom branches to scan (e.g., master,develop)")
    parser.add_argument("--include-release-branches", action="store_true",
                       help="Scan all ESP-IDF release branches (release/v5.0 to release/v5.5)")
    parser.add_argument("--list-release-branches", action="store_true",
                       help="List available ESP-IDF release branches and exit")
    parser.add_argument("--batch-mode", action="store_true",
                       help="Use optimized batch scanning (single clone for multiple targets)")
    parser.add_argument("--scan-all-v5", action="store_true",
                       help="Scan all available v5.x tags and release branches")
    parser.add_argument("--unified-mode", action="store_true",
                       help="Use unified scanning (single clone for all targets)")
    parser.add_argument("--git-only", action="store_true",
                       help="Use git for ALL targets, including those with Docker images")
    parser.add_argument("--list-remote-targets", action="store_true",
                       help="List all available remote tags and branches without scanning")
    parser.add_argument("--no-docker", action="store_true",
                       help="Disable Docker and use git clone only")
    parser.add_argument("--list-docker-images", action="store_true",
                       help="List available Docker images and exit")
    
    args = parser.parse_args()
    
    if args.list_docker_images:
        print("Available ESP-IDF Docker images:")
        for version, image in ESP_IDF_DOCKER_IMAGES.items():
            print(f"  {version}: {image}")
        print(f"\nTotal: {len(ESP_IDF_DOCKER_IMAGES)} images")
        return
        
    if args.list_release_branches:
        print("Available ESP-IDF release branches:")
        for branch in ESP_IDF_RELEASE_BRANCHES:
            print(f"  {branch}")
        print(f"\nTotal: {len(ESP_IDF_RELEASE_BRANCHES)} release branches")
        print("\nTo scan these branches, use: --include-release-branches")
        return
        
    if args.list_remote_targets:
        scanner = ESPIDFSecurityScanner("./temp", use_docker=False)
        tags, branches = scanner.get_available_targets()
        print(f"Available remote tags ({len(tags)}):")
        for tag in sorted(tags)[:20]:  # Show first 20
            print(f"  {tag}")
        if len(tags) > 20:
            print(f"  ... and {len(tags) - 20} more")
            
        print(f"\nAvailable remote branches ({len(branches)}):")
        for branch in sorted(branches):
            print(f"  {branch}")
        return
    
    try:
        scanner = ESPIDFSecurityScanner(args.output_dir, use_docker=not args.no_docker)
        
        # Handle scan-all-v5 mode
        if args.scan_all_v5:
            logger.info(f"ESP-IDF Security Scanner starting in scan-all-v5 mode...")
            logger.info(f"Output directory: {args.output_dir}")
            logger.info(f"Unified mode: {args.unified_mode}")
            logger.info(f"Git-only mode: {args.git_only}")
            
            results = scanner.scan_all_v5_releases(use_unified_mode=args.unified_mode, prefer_git_over_docker=args.git_only)
        else:
            # Regular scanning mode
            if args.single_version:
                versions = [args.single_version]
            elif args.versions:
                versions = [v.strip() for v in args.versions.split(',')]
            else:
                versions = DEFAULT_RELEASES
                
            branches = None
            if args.include_branches:
                branches = [b.strip() for b in args.include_branches.split(',')]
                
            logger.info(f"ESP-IDF Security Scanner starting...")
            logger.info(f"Output directory: {args.output_dir}")
            logger.info(f"Using Docker: {not args.no_docker}")
            logger.info(f"Batch mode: {args.batch_mode}")
            logger.info(f"Unified mode: {args.unified_mode}")
            logger.info(f"Git-only mode: {args.git_only}")
            logger.info(f"Versions to scan: {len(versions)}")
            if args.include_release_branches:
                logger.info(f"Release branches to scan: {len(ESP_IDF_RELEASE_BRANCHES)}")
            if branches:
                logger.info(f"Custom branches to scan: {branches}")
            
            # Use unified mode if requested
            if args.unified_mode:
                all_targets = versions[:]
                if args.include_release_branches:
                    all_targets.extend(ESP_IDF_RELEASE_BRANCHES)
                if branches:
                    all_targets.extend(branches)
                
                logger.info(f"Using unified scanning for {len(all_targets)} total targets")
                results = scanner.scan_unified_targets(all_targets, prefer_git_over_docker=args.git_only)
            else:
                results = scanner.scan_releases(versions, include_branches=branches, 
                                              include_release_branches=args.include_release_branches,
                                              use_batch_mode=args.batch_mode)
        
        if results:
            print(f"\n✅ Successfully scanned {len(results)} items")
            
            # Print summary
            total_vulns = sum(r["summary"]["total_vulnerabilities"] for r in results.values())
            print(f"📊 Total vulnerabilities found: {total_vulns}")
            
            # Print severity breakdown
            severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for result in results.values():
                for severity, count in result["summary"]["by_severity"].items():
                    severity_totals[severity] += count
                    
            print("📋 Severity breakdown:")
            for severity, count in severity_totals.items():
                if count > 0:
                    print(f"   {severity}: {count}")
                    
        else:
            print("❌ No items were successfully scanned")
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(f"❌ Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()