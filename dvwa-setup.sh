#!/bin/bash

# Ethical Hacking Capstone - DVWA Setup Script
# This script sets up DVWA (Damn Vulnerable Web Application) for testing

echo "🔐 Ethical Hacking Capstone - DVWA Setup"
echo "========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root. Please use: sudo $0"
   exit 1
fi

echo "📦 Updating system packages..."
apt update && apt upgrade -y

echo "🛠️ Installing required packages..."
apt install -y \
    apache2 \
    mysql-server \
    php \
    php-mysql \
    php-gd \
    php-mbstring \
    php-xml \
    php-curl \
    git \
    unzip \
    curl \
    wget

echo "🔧 Starting and enabling services..."
systemctl start apache2 mysql
systemctl enable apache2 mysql

echo "🎯 Downloading DVWA..."
cd /var/www/html
git clone https://github.com/digininja/DVWA.git dvwa

echo "📋 Setting up permissions..."
chown -R www-data:www-data dvwa/
find dvwa/ -type d -exec chmod 755 {} \;
find dvwa/ -type f -exec chmod 644 {} \;

echo "🗃️ Setting up MySQL database..."
mysql -e "CREATE DATABASE dvwa;"
mysql -e "CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';"
mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

echo "⚙️ Configuring DVWA..."
cd /var/www/html/dvwa/config
cp config.inc.php.dist config.inc.php

# Update configuration file
cat > config.inc.php << 'EOF'
<?php

# Disable all errors and warnings
error_reporting(0);
ini_set('display_errors', 0);

# Database settings
$_DVWA['db_server'] = '127.0.0.1';
$_DVWA['db_database'] = 'dvwa';
$_DVWA['db_user'] = 'dvwa';
$_DVWA['db_password'] = 'p@ssw0rd';
$_DVWA['db_port'] = '3306';

# Only allow to configure the database settings
$_DVWA['disable_authentication'] = false;

# Default security level
$_DVWA['default_security_level'] = 'low';

# Security levels
$_DVWA['security_level'] = 'low';

# reCAPTCHA settings
$_DVWA['recaptcha_public_key'] = '';
$_DVWA['recaptcha_private_key'] = '';

# Change the following if using Docker
$_DVWA['base_url'] = 'http://localhost/dvwa';

?>
EOF

echo "📝 Creating writable directories..."
cd /var/www/html/dvwa
mkdir -p hackable/uploads
chmod 777 hackable/uploads
mkdir -p external/phpids/0.6/lib/IDS/tmp/phpids_log.txt
touch external/phpids/0.6/lib/IDS/tmp/phpids_log.txt
chmod 777 external/phpids/0.6/lib/IDS/tmp/phpids_log.txt

echo "🔧 Adjusting PHP settings..."
# Create a custom PHP config for DVWA
cat > /etc/apache2/sites-available/dvwa.conf << 'EOF'
<Directory /var/www/html/dvwa>
    AllowOverride All
    php_admin_value allow_url_fopen On
    php_admin_value allow_url_include On
    php_admin_flag magic_quotes_gpc Off
    php_admin_flag register_globals On
    Options +Indexes
</Directory>
EOF

a2ensite dvwa
systemctl restart apache2

echo "🔄 Restarting services..."
systemctl restart apache2 mysql

echo "✅ DVWA Installation Complete!"
echo ""
echo "🌐 Access DVWA at: http://localhost/dvwa/"
echo "👤 Default credentials: admin / password"
echo ""
echo "📝 Setup Instructions:"
echo "1. Go to http://localhost/dvwa/"
echo "2. Click 'Create / Reset Database'"
echo "3. Login with admin/password"
echo "4. Go to DVWA Security and set level to 'Low'"
echo "5. Start your ethical hacking assessment!"
echo ""
echo "⚠️  Important: This is a deliberately vulnerable application."
echo "    Only run this in an isolated environment for educational purposes!"

# Create a status check script
cat > /var/www/html/dvwa/check_status.sh << 'EOF'
#!/bin/bash
echo "🔍 DVWA Status Check"
echo "==================="

# Check Apache
if systemctl is-active --quiet apache2; then
    echo "✅ Apache2: Running"
else
    echo "❌ Apache2: Not running"
fi

# Check MySQL
if systemctl is-active --quiet mysql; then
    echo "✅ MySQL: Running"
else
    echo "❌ MySQL: Not running"
fi

# Check DVWA accessibility
if curl -s http://localhost/dvwa/ > /dev/null; then
    echo "✅ DVWA: Accessible at http://localhost/dvwa/"
else
    echo "❌ DVWA: Not accessible"
fi

# Check database connection
mysql -u dvwa -p'p@ssw0rd' -e "USE dvwa; SHOW TABLES;" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Database: Connected and tables exist"
else
    echo "❌ Database: Connection failed or tables missing"
fi

echo ""
echo "🎯 Ready for ethical hacking assessment!"
EOF

chmod +x /var/www/html/dvwa/check_status.sh

echo "🎉 Setup complete! Run './check_status.sh' to verify installation."