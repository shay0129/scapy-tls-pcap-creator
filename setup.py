from setuptools import setup, find_namespace_packages

setup(
    name="tls",
    version="0.1",
    package_dir={"": "."},
    packages=find_namespace_packages(where="."),
    install_requires=[
        'pycryptodome==3.21.0',
        'cryptography==44.0.0',
        'pyOpenSSL==24.3.0',
        'scapy==2.6.1',
        'setuptools==75.6.0'
    ],
)