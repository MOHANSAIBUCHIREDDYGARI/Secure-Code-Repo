import pkg_resources

required_packages = [
    ("Flask", "3.0.0"),
    ("Flask-SQLAlchemy", "3.1.1"),
    ("cryptography", "41.0.7"),
    ("PyJWT", "2.8.0"),
    ("qrcode", "7.4.2"),
    ("Pillow", "10.1.0")
]

print("Checking required packages...\n")

all_installed = True
for package, expected_version in required_packages:
    try:
        installed_version = pkg_resources.get_distribution(package).version
        if installed_version == expected_version:
            print(f"✓ {package}=={installed_version} (correct version)")
        else:
            print(f"⚠ {package}=={installed_version} (expected: {expected_version})")
            all_installed = False
    except pkg_resources.DistributionNotFound:
        print(f"✗ {package} is NOT installed")
        all_installed = False

print(f"\nAll packages installed correctly: {'YES' if all_installed else 'NO'}")