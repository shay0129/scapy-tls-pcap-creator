from setuptools import setup, find_namespace_packages

def read_requirements():
    """Read requirements from requirements.txt file"""
    try:
        with open('requirements.txt', 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        # Fallback if requirements.txt is missing
        return [
            'pycryptodome==3.21.0',
            'cryptography==44.0.0',
            'pyOpenSSL==24.3.0',
            'scapy==2.6.1',
            'setuptools==75.6.0'
        ]

setup(
    name="tls-pcap-creator",
    version="1.0.0",
    description="TLS Protocol Simulator & Network Traffic Generator",
    author="Shay Mordechai",
    package_dir={"": "."},
    packages=find_namespace_packages(where="."),
    install_requires=read_requirements(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "tls-pcap-creator=tls.main:main",
        ],
    },
)
