from setuptools import setup, find_namespace_packages
from pathlib import Path

def read_requirements():
    """Read requirements from requirements.txt file"""
    try:
        requirements_path = Path(__file__).parent / "requirements.txt"
        with open(requirements_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        # Fallback to hardcoded requirements
        return [
            'pycryptodome==3.21.0',
            'cryptography==44.0.0',
            'pyOpenSSL==24.3.0',
            'scapy==2.6.1',
            'setuptools==75.6.0'
        ]

def read_long_description():
    """Read long description from README.md"""
    try:
        readme_path = Path(__file__).parent / "README.md"
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "TLS Protocol Simulator & Network Traffic Generator"

setup(
    name="tls-pcap-creator",
    version="1.0.0",
    description="TLS Protocol Simulator & Network Traffic Generator",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    author="Shay Mordechai",
    author_email="",  # Add your email if desired
    url="https://github.com/shay0129/scapy-tls-pcap-creator",  # Add your repo URL
    project_urls={
        "Bug Reports": "https://github.com/shay0129/scapy-tls-pcap-creator/issues",
        "Source": "https://github.com/shay0129/scapy-tls-pcap-creator",
    },    package_dir={"": "."},
    packages=find_namespace_packages(where="."),
    install_requires=read_requirements(),
    python_requires=">=3.8",
    keywords=["tls", "pcap", "network", "security", "scapy", "cryptography", "ctf"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Networking",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "tls-pcap-creator=tls.main:main",
        ],
    },
)