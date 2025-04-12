<?php
/**
 * Plugin Name: Activity Logger
 * Plugin URI: https://yourwebsite.com
 * Description: Logs security alerts, user activities, theme and page changes in CSV file.
 * Version: 3.2
 * Author: Veer Saini
 * Author URI: https://viyog.com
 */

if (!defined('ABSPATH')) exit;

// Constants
define('LOG_FILE', __DIR__ . '/activity_logs.csv');
define('IP_LOG_FILE', __DIR__ . '/ip_access_logs.csv');
define('ADMIN_EMAIL', 'yogeshwarsaini321@gmail.com');
define('OFFICE_IPS', ['192.168.20.8']);
define('MAX_LOGIN_ATTEMPTS', 5);
define('TIME_WINDOW', 3600);
define('SECURITY_SCAN_INTERVAL', 86400);
date_default_timezone_set('Asia/Kolkata');

// Core functions
function get_user_ip() {
    foreach (['HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'] as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = trim(explode(',', $_SERVER[$key])[0]);
            return in_array($ip, OFFICE_IPS) ? "$ip (Office)" : "$ip (Home)";
        }
    }
    return 'UNKNOWN';
}

function log_activity($user_id, $username, $action) {
    $file = fopen(LOG_FILE, 'a');
    fputcsv($file, [$user_id, $username, $action, get_user_ip(), date('Y-m-d H:i:s')]);
    fclose($file);
}

function send_security_email($alert_name, $username, $action) {
    $subject = "!! Security Alert !! - " . get_bloginfo('name');
    $message = "User: $username\nIP Address: " . get_user_ip() . 
               "\nTime: " . date('Y-m-d H:i:s') . 
               "\nAction: $action\nWebsite: " . get_bloginfo('name');
    wp_mail(ADMIN_EMAIL, $subject, $message);
}

function track_activity($action) {
    $user = wp_get_current_user();
    log_activity($user->ID, $user->user_login, $action);
    return [$user->ID, $user->user_login, $action];
}

function track_and_alert($action) {
    $data = track_activity($action);
    send_security_email(trim(explode(':', $action)[0]), $data[1], $action);
}

// Hook setup helper
function add_hooks($hooks) {
    foreach ($hooks as $hook => $callback) {
        $params = isset($callback['params']) ? $callback['params'] : 1;
        add_action($hook, $callback['fn'], 10, $params);
    }
}

// User action hooks
add_hooks([
    'user_register' => [
        'fn' => function($user_id) {
            $user = get_userdata($user_id);
            log_activity($user_id, $user->user_login, 'User Created');
            send_security_email("User Created", $user->user_login, 'User Created');
        }
    ],
    'delete_user' => [
        'fn' => function($user_id) {
            $user = get_userdata($user_id);
            if ($user) {
                log_activity($user_id, $user->user_login, 'User Deleted');
                send_security_email("User Deleted", $user->user_login, 'User Deleted');
            }
        }
    ],
    'wp_login' => [
        'fn' => function($user_login, $user) {
            log_activity($user->ID, $user_login, 'Logged In');
            send_security_email("Successful Login Alert", $user_login, 'Logged In');
            log_ip_access($user_login);
        },
        'params' => 2
    ],
    'clear_auth_cookie' => [
        'fn' => function() {
            $user = wp_get_current_user();
            if ($user->ID) {
                log_activity($user->ID, $user->user_login, 'Logged Out');
                send_security_email("Logout Alert", $user->user_login, 'Logged Out');
            }
        }
    ],
    'wp_login_failed' => [
        'fn' => function($username) {
            log_activity(0, $username, 'Security Alert: Failed Login Attempt');
            send_security_email("Failed Login Attempt", $username, 'Failed Login Attempt');
            log_ip_access($username, 'failed');
        }
    ],
    'set_user_role' => [
        'fn' => function($user_id, $role, $old_roles) {
            $user = get_userdata($user_id);
            if ($user) {
                $action = 'Role Changed: ' . implode(', ', $old_roles) . ' → ' . $role;
                log_activity($user_id, $user->user_login, $action);
                send_security_email("User Role Changed", $user->user_login, $action);
            }
        },
        'params' => 3
    ]
]);

// Content change tracking
function track_page_post_changes($post_ID, $post_after, $post_before) {
    if (wp_is_post_revision($post_ID) || wp_is_post_autosave($post_ID)) return;
    
    $post_type = get_post_type($post_ID);
    $title = $post_after->post_title;
    $action = '';
    
    if ($post_before->post_status === 'auto-draft' && $post_after->post_status === 'publish')
        $action = ucfirst($post_type) . ' Created: ' . $title;
    elseif ($post_before->post_status !== 'trash' && $post_after->post_status === 'trash')
        $action = ucfirst($post_type) . ' Trashed: ' . $title;
    elseif ($post_before->post_status === 'trash' && $post_after->post_status === 'publish')
        $action = ucfirst($post_type) . ' Restored: ' . $title;
    elseif (($post_before->post_content !== $post_after->post_content ||
            $post_before->post_title !== $post_after->post_title ||
            $post_before->post_excerpt !== $post_after->post_excerpt) &&
            $post_before->post_status === 'publish' && $post_after->post_status === 'publish')
        $action = ucfirst($post_type) . ' Modified: ' . $title;
    
    if (!empty($action)) {
        $user = wp_get_current_user();
        log_activity($user->ID, $user->user_login, $action);
    }
}
add_action('post_updated', 'track_page_post_changes', 10, 3);

add_action('before_delete_post', function($post_id) {
    $post = get_post($post_id);
    if ($post && $post->post_status !== 'trash') {
        track_activity(ucfirst($post->post_type) . ' Deleted: ' . $post->post_title);
    }
});

// Theme and plugin changes
add_action('after_switch_theme', function() {
    track_and_alert('Theme Changed to: ' . wp_get_theme()->get('Name'));
});

// Plugin hooks
add_hooks([
    'upgrader_process_complete' => [
        'fn' => function($upgrader_object, $options) {
            if ($options['type'] == 'plugin' && $options['action'] == 'install' && !empty($options['plugins'])) {
                foreach ($options['plugins'] as $plugin) {
                    track_and_alert('Plugin Installed: ' . $plugin);
                }
            }
        },
        'params' => 2
    ],
    'activated_plugin' => ['fn' => function($plugin) { track_and_alert('Plugin Activated: ' . $plugin); }],
    'deactivated_plugin' => ['fn' => function($plugin) { track_and_alert('Plugin Deactivated: ' . $plugin); }],
    'deleted_plugin' => ['fn' => function($plugin) { track_and_alert('Plugin Deleted: ' . $plugin); }]
]);

// Options and meta changes
add_hooks([
    'added_option' => ['fn' => function($option) { track_activity("Option Added: $option"); }],
    'updated_option' => ['fn' => function($option) { track_activity("Option Updated: $option"); }],
    'deleted_option' => ['fn' => function($option) { track_activity("Option Deleted: $option"); }],
    'added_post_meta' => [
        'fn' => function($meta_id, $post_id, $meta_key) { track_activity("Meta Added to Post ID $post_id: $meta_key"); },
        'params' => 3
    ],
    'updated_post_meta' => [
        'fn' => function($meta_id, $post_id, $meta_key) { track_activity("Meta Updated in Post ID $post_id: $meta_key"); },
        'params' => 3
    ],
    'deleted_post_meta' => [
        'fn' => function($meta_ids, $post_id, $meta_key) { track_activity("Meta Deleted from Post ID $post_id: $meta_key"); },
        'params' => 3
    ],
    'wp_insert_comment' => [
        'fn' => function($comment_id) { track_activity("New Comment Added: ID $comment_id"); },
        'params' => 1
    ]
]);

// Admin interface
add_action('admin_menu', function() {
    add_menu_page('Activity Logs', 'Activity Logs', 'manage_options', 'activity-logs', 'display_activity_logs', 'dashicons-visibility', 20);
    add_submenu_page('activity-logs', 'Security Monitor', 'Security Monitor', 'manage_options', 'security-monitor', 'display_security_monitor');
    add_submenu_page('activity-logs', 'IP Access Logs', 'IP Access Logs', 'manage_options', 'ip-access-logs', 'display_ip_access_logs');
});

function display_activity_logs() {
    $categories = ['All', 'User Created', 'User Deleted', 'Role Changed', 'Logged In', 'Logged Out', 
                  'Security Alert', 'Page Created', 'Page Modified', 'Page Deleted', 'Post Created', 
                  'Post Modified', 'Post Deleted', 'Theme Changed', 'Plugin Installed', 'Plugin Activated', 
                  'Plugin Deactivated', 'Plugin Deleted'];
    $selected = isset($_GET['log_filter']) ? sanitize_text_field($_GET['log_filter']) : 'All';
    
    echo "<div class='wrap'><h1>Activity Logs</h1>";
    echo "<form method='GET'><input type='hidden' name='page' value='activity-logs'>";
    echo "<select name='log_filter' onchange='this.form.submit()'>";
    
    foreach ($categories as $category) {
        echo "<option value='$category' " . ($selected == $category ? 'selected' : '') . ">$category</option>";
    }
    
    echo "</select></form><table class='widefat fixed'><thead><tr>
          <th>#</th><th>User ID</th><th>User</th><th>Action</th>
          <th>IP Address</th><th>Timestamp</th></tr></thead><tbody>";
    
    if (file_exists(LOG_FILE) && ($handle = fopen(LOG_FILE, 'r')) !== false) {
        $rows = [];
        while (($data = fgetcsv($handle)) !== false) {
            if ($selected == 'All' || strpos($data[2], $selected) !== false) {
                $rows[] = $data;
            }
        }
        fclose($handle);
        
        $count = count($rows);
        foreach (array_reverse($rows) as $log) {
            echo "<tr><td>{$count}</td><td>{$log[0]}</td><td>{$log[1]}</td>
                 <td>{$log[2]}</td><td>{$log[3]}</td><td>{$log[4]}</td></tr>";
            $count--;
        }
    }
    echo "</tbody></table></div>";
}

// FUNCTIONALITY 1: Unusual Traffic Patterns/IP Access Monitoring
function log_ip_access($username, $status = 'success') {
    $ip = get_user_ip();
    $timestamp = time();
    
    // Ensure file exists with headers
    if (!file_exists(IP_LOG_FILE)) {
        $file = fopen(IP_LOG_FILE, 'w');
        fputcsv($file, ['IP', 'Username', 'Status', 'Timestamp']);
        fclose($file);
    }
    
    // Append new log entry
    $file = fopen(IP_LOG_FILE, 'a');
    fputcsv($file, [$ip, $username, $status, $timestamp]);
    fclose($file);
    
    // Check for unusual patterns
    check_for_unusual_traffic($ip);
}

function check_for_unusual_traffic($current_ip) {
    if (!file_exists(IP_LOG_FILE)) return;
    
    $file = fopen(IP_LOG_FILE, 'r');
    $header = fgetcsv($file); // Skip header
    
    $ip_counts = [];
    $failed_attempts = [];
    $current_time = time();
    
    // Count access attempts by IP within time window
    while (($data = fgetcsv($file)) !== false) {
        list($ip, $username, $status, $timestamp) = $data;
        
        if ($current_time - $timestamp <= TIME_WINDOW) {
            if (!isset($ip_counts[$ip])) $ip_counts[$ip] = 0;
            $ip_counts[$ip]++;
            
            if ($status === 'failed') {
                if (!isset($failed_attempts[$ip])) $failed_attempts[$ip] = 0;
                $failed_attempts[$ip]++;
            }
        }
    }
    fclose($file);
    
    // Check for rapid access from the current IP
    if (isset($ip_counts[$current_ip]) && $ip_counts[$current_ip] > 20) {
        $action = "Unusual Traffic Alert: High access frequency from IP $current_ip ({$ip_counts[$current_ip]} requests in " . (TIME_WINDOW/60) . " minutes)";
        track_and_alert($action);
    }
    
    // Check for multiple failed login attempts
    if (isset($failed_attempts[$current_ip]) && $failed_attempts[$current_ip] >= MAX_LOGIN_ATTEMPTS) {
        $action = "Unusual Traffic Alert: Multiple failed login attempts from IP $current_ip ({$failed_attempts[$current_ip]} attempts in " . (TIME_WINDOW/60) . " minutes)";
        track_and_alert($action);
    }
    
    // Check for access from new countries/regions
    if (strpos($current_ip, 'Office') === false && !in_array($current_ip, get_option('known_ips', []))) {
        $known_ips = get_option('known_ips', []);
        $known_ips[] = $current_ip;
        update_option('known_ips', $known_ips);
        
        $action = "New IP Access Alert: First time access from IP $current_ip";
        track_and_alert($action);
    }
}

function display_ip_access_logs() {
    echo "<div class='wrap'><h1>IP Access Logs</h1>";
    echo "<p>This page shows recent IP access patterns and highlights potential unusual traffic.</p>";
    
    echo "<table class='widefat fixed'><thead><tr>
          <th>IP Address</th><th>Username</th><th>Status</th>
          <th>Timestamp</th></tr></thead><tbody>";
    
    if (file_exists(IP_LOG_FILE) && ($handle = fopen(IP_LOG_FILE, 'r')) !== false) {
        $header = fgetcsv($handle); // Skip header
        $rows = [];
        
        while (($data = fgetcsv($handle)) !== false) {
            $rows[] = $data;
        }
        fclose($handle);
        
        foreach (array_reverse($rows) as $log) {
            $timestamp = date('Y-m-d H:i:s', $log[3]);
            $row_class = $log[2] === 'failed' ? 'style="background-color:#ffeeee;"' : '';
            
            echo "<tr $row_class>
                 <td>{$log[0]}</td>
                 <td>{$log[1]}</td>
                 <td>{$log[2]}</td>
                 <td>{$timestamp}</td>
                 </tr>";
        }
    }
    echo "</tbody></table></div>";
}

// FUNCTIONALITY 2: Security Changes Monitoring
function check_security_changes() {
    check_ssl_status();
    check_file_permissions();
    check_security_plugins();
    
    if (!wp_next_scheduled('security_scan_hook')) {
        wp_schedule_event(time(), 'daily', 'security_scan_hook');
    }
}

function check_ssl_status() {
    $is_ssl = is_ssl();
    $force_ssl_admin = defined('FORCE_SSL_ADMIN') && FORCE_SSL_ADMIN;
    $was_ssl = get_option('site_was_ssl', null);
    
    if ($was_ssl === null) {
        update_option('site_was_ssl', $is_ssl);
    } else if ($was_ssl && !$is_ssl) {
        track_and_alert("Security Alert: SSL has been disabled for the site");
    } else if (!$was_ssl && $is_ssl) {
        track_activity("Security Update: SSL has been enabled for the site");
    }
    
    $was_ssl_admin = get_option('ssl_admin_was_forced', null);
    if ($was_ssl_admin === null) {
        update_option('ssl_admin_was_forced', $force_ssl_admin);
    } else if ($was_ssl_admin && !$force_ssl_admin) {
        track_and_alert("Security Alert: Forced SSL for admin has been disabled");
    }
    
    update_option('site_was_ssl', $is_ssl);
    update_option('ssl_admin_was_forced', $force_ssl_admin);
}

function check_file_permissions() {
    $wp_config_path = ABSPATH . 'wp-config.php';
    
    if (file_exists($wp_config_path)) {
        $perms = substr(sprintf('%o', fileperms($wp_config_path)), -4);
        
        if ($perms[3] > 0) {
            track_and_alert("Security Alert: wp-config.php has unsafe permissions ($perms)");
        }
        
        update_option('wp_config_permissions', $perms);
    }
    
    $uploads_dir = wp_upload_dir();
    $upload_path = $uploads_dir['basedir'];
    
    if (file_exists($upload_path)) {
        $perms = substr(sprintf('%o', fileperms($upload_path)), -4);
        
        if ($perms[3] >= 6) {
            track_and_alert("Security Alert: Uploads directory has unsafe permissions ($perms)");
        }
    }
}

function check_security_plugins() {
    $security_plugins = [
        'wordfence/wordfence.php' => 'Wordfence',
        'sucuri-scanner/sucuri.php' => 'Sucuri',
        'better-wp-security/better-wp-security.php' => 'iThemes Security',
        'all-in-one-wp-security-and-firewall/wp-security.php' => 'All In One WP Security'
    ];
    
    $active_plugins = get_option('active_plugins');
    $active_security_plugins = array_intersect(array_keys($security_plugins), $active_plugins);
    
    $prev_active_security = get_option('active_security_plugins', []);
    $deactivated = array_diff($prev_active_security, $active_security_plugins);
    
    foreach ($deactivated as $plugin) {
        $plugin_name = isset($security_plugins[$plugin]) ? $security_plugins[$plugin] : basename($plugin);
        track_and_alert("Security Alert: Security plugin deactivated: $plugin_name");
    }
    
    update_option('active_security_plugins', $active_security_plugins);
}

function display_security_monitor() {
    echo "<div class='wrap'><h1>Security Monitor</h1>";
    
    if (isset($_POST['run_security_scan']) && current_user_can('manage_options')) {
        check_security_changes();
        echo "<div class='notice notice-success'><p>Security scan completed.</p></div>";
    }
    
    echo "<form method='post'>
          <input type='submit' name='run_security_scan' value='Run Security Scan Now' class='button button-primary'>
          </form><br>";
    
    $is_ssl = is_ssl();
    $force_ssl_admin = defined('FORCE_SSL_ADMIN') && FORCE_SSL_ADMIN;
    $ssl_status = $is_ssl ? '<span style="color:green;">✓ Enabled</span>' : '<span style="color:red;">✗ Disabled</span>';
    $admin_ssl_status = $force_ssl_admin ? '<span style="color:green;">✓ Forced</span>' : '<span style="color:red;">✗ Not Forced</span>';
    
    $wp_config_path = ABSPATH . 'wp-config.php';
    $perms = file_exists($wp_config_path) ? substr(sprintf('%o', fileperms($wp_config_path)), -4) : 'N/A';
    $perms_status = $perms != 'N/A' && $perms[3] == 0 ? '<span style="color:green;">✓ Secure</span>' : '<span style="color:red;">✗ Insecure</span>';
    
    $security_plugins = [
        'wordfence/wordfence.php' => 'Wordfence',
        'sucuri-scanner/sucuri.php' => 'Sucuri',
        'better-wp-security/better-wp-security.php' => 'iThemes Security',
        'all-in-one-wp-security-and-firewall/wp-security.php' => 'All In One WP Security'
    ];
    
    $active_plugins = get_option('active_plugins');
    $active_security = [];
    
    foreach ($security_plugins as $plugin_file => $plugin_name) {
        if (in_array($plugin_file, $active_plugins)) {
            $active_security[] = "$plugin_name <span style='color:green;'>✓</span>";
        } else {
            $active_security[] = "$plugin_name <span style='color:red;'>✗</span>";
        }
    }
    
    echo "<h2>Security Status</h2>";
    echo "<table class='widefat fixed'>";
    echo "<tr><th>SSL Status</th><td>$ssl_status</td></tr>";
    echo "<tr><th>Admin SSL</th><td>$admin_ssl_status</td></tr>";
    echo "<tr><th>wp-config.php Permissions</th><td>$perms ($perms_status)</td></tr>";
    echo "<tr><th>Security Plugins</th><td>" . implode(', ', $active_security) . "</td></tr>";
    echo "</table></div>";
}

// Register hooks for security scanning
add_action('security_scan_hook', 'check_security_changes');

// Plugin activation
register_activation_hook(__FILE__, function() {
    check_security_changes();
    
    foreach ([LOG_FILE, IP_LOG_FILE] as $file_path) {
        if (!file_exists($file_path)) {
            $file = fopen($file_path, 'w');
            $headers = $file_path == LOG_FILE ? 
                      ['User ID', 'Username', 'Action', 'IP Address', 'Timestamp'] : 
                      ['IP', 'Username', 'Status', 'Timestamp'];
            fputcsv($file, $headers);
            fclose($file);
        }
    }
});

// Plugin deactivation
register_deactivation_hook(__FILE__, function() {
    wp_clear_scheduled_hook('security_scan_hook');
});

// Run security check on init (limited to once per day)
add_action('admin_init', function() {
    $last_scan = get_option('last_security_scan', 0);
    if (time() - $last_scan > SECURITY_SCAN_INTERVAL) {
        check_security_changes();
        update_option('last_security_scan', time());
    }
});